# Copyright 2026 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Unit tests for the Analyzer class across all 3 migration analysis modes.

This test suite validates `analyzer.Analyzer`, which powers pre-migration
discovery (Phase 1a), post-provisioning verification (Phase 2a), and rollout
coverage tracking (Phase 3):
  1. **IAM & Project Normalization Helpers**: Predefined and custom IAM role
     resolution (`_get_principals_with_permission`) and bidirectional GCP
     Project ID <-> Project Number resolution (`_get_project_number`,
     `_get_project_id`).
  2. **Mode 1 (`static-taxonomy`)**: Taxonomy and Policy Tag discovery,
     concurrent IAM policy retrieval, V1 Data Policy attachment, Explicit vs.
     Implicit Access Control classification, and
     `generate_static_taxonomy_report`.
  3. **Mode 2 (`static-dgt`)**: Single-RPC $O(K)$ Tag Value hierarchy
     reconstruction, GAPIC-to-REST `/v2/` fallback, concurrent REST grantee
     hydration (including `*_default_deny` policies), cross-project Tag Key
     isolation, and `generate_static_dgt_report`.
  4. **Mode 3 (`column-binding`)**: Single-pass `INFORMATION_SCHEMA` metrics
     queries, automatic fallback when `data_policies` is unsupported, concurrent
     `get_policy_tag` display-name prefetching, and
     `generate_column_binding_report`.
"""

import contextlib
import json
import os
import sys
import types
import unittest
from unittest import mock
import urllib.error

from google.api_core import exceptions
from google.cloud import bigquery
from google.cloud import bigquery_datapolicies_v1
from google.cloud import iam_admin_v1
from google.cloud import resourcemanager_v3

# pylint: disable=g-import-not-at-top
try:
  from google.iam.v1 import iam_policy_pb2
  from google.iam.v1 import policy_pb2
except ImportError:
  from google.cloud.resourcemanager_v3.services.projects import (
      client as _projects_client,
  )

  iam_policy_pb2 = _projects_client.iam_policy_pb2
  policy_pb2 = _projects_client.policy_pb2
# pylint: enable=g-import-not-at-top


# === Section 1: Fake & Spec Test Doubles for Cloud Client Libraries ===
# These lightweight spec classes let `mock.create_autospec(..., spec_set=True)`
# enforce strict method-signature and attribute validation without requiring
# network credentials or live gRPC channels during unit test execution.


class FakePolicyTagManagerClient:
  """Spec class for Data Catalog `PolicyTagManagerClient` in unit tests."""

  def list_taxonomies(self, parent=None, retry=None):
    pass

  def list_policy_tags(self, parent=None, retry=None):
    pass

  def get_policy_tag(self, request=None, retry=None):
    pass

  def get_iam_policy(self, request=None, retry=None):
    pass


class FakeCredentials:
  """Spec class for `google.auth` credentials in REST fallback tests."""

  token: str | None = "fake-token"
  valid: bool = True

  def __init__(self, token="fake-token", valid=True):
    self.token = token
    self.valid = valid

  def refresh(self, request):
    pass


class FakeHttpResponse:
  """Spec class for `urllib` HTTP response context manager in REST tests."""

  def read(self) -> bytes:
    return b"{}"

  def __enter__(self):
    return self

  def __exit__(self, exc_type, exc_val, exc_tb):
    return False


class FakeDataMaskingPolicyV1:
  """Spec class for V1 `DataMaskingPolicy` protobuf messages in unit tests."""

  def __init__(self, predefined_expression=None, routine=""):
    self.predefined_expression = predefined_expression
    self.routine = routine


class FakeDataPolicyV1:
  """Spec class for V1 `DataPolicy` protobuf messages in unit tests."""

  def __init__(
      self,
      name="",
      data_policy_id="",
      data_policy_type=2,
      policy_tag="",
      data_masking_policy=None,
  ):
    self.name = name
    self.data_policy_id = data_policy_id
    self.data_policy_type = data_policy_type
    self.policy_tag = policy_tag
    self.data_masking_policy = data_masking_policy


class FakePolicyTag:
  """Fake representation of a Data Catalog `PolicyTag` for testing.

  Attributes:
    name: The full resource name of the policy tag.
    display_name: The human-readable display name of the policy tag.
    parent_policy_tag: The parent policy tag resource name, or `""` for roots.
  """

  def __init__(self, name, display_name=None, parent_policy_tag=""):
    self.name = name
    self.display_name = display_name
    self.parent_policy_tag = parent_policy_tag


class FakeTaxonomy:
  """Fake representation of a Data Catalog `Taxonomy` for testing.

  Attributes:
    PolicyType: Nested enum-like class representing policy types.
    name: The full resource name of the taxonomy.
    display_name: The human-readable display name of the taxonomy.
    policy_tag_count: The number of policy tags in the taxonomy.
    activated_policy_types: List of activated policy type enum values.
  """

  class PolicyType:
    FINE_GRAINED_ACCESS_CONTROL = 1

  def __init__(
      self,
      name,
      display_name=None,
      policy_tag_count=0,
      activated_policy_types=None,
  ):
    self.name = name
    self.display_name = display_name
    self.policy_tag_count = policy_tag_count
    self.activated_policy_types = activated_policy_types or []


# Inject a synthetic `google.cloud.datacatalog_v1` module before importing
# `analyzer` so tests remain hermetic even in environments without the optional
# Data Catalog client package installed.
mock_datacatalog_v1 = types.ModuleType("google.cloud.datacatalog_v1")
setattr(
    mock_datacatalog_v1,
    "PolicyTagManagerClient",
    FakePolicyTagManagerClient,
)
setattr(mock_datacatalog_v1, "PolicyTag", FakePolicyTag)
setattr(mock_datacatalog_v1, "Taxonomy", FakeTaxonomy)
sys.modules["google.cloud.datacatalog_v1"] = mock_datacatalog_v1
datacatalog_v1 = mock_datacatalog_v1


class FakeTagKey:
  """Fake representation of a Resource Manager `TagKey` for testing."""

  def __init__(
      self,
      name,
      short_name,
      namespaced_name=None,
      purpose="DATA_GOVERNANCE",
      description=None,
      parent=None,
  ):
    self.name = name
    self.short_name = short_name
    self.namespaced_name = namespaced_name
    self.purpose = purpose
    self.description = description
    self.parent = parent


class FakeTagValue:
  """Fake representation of a Resource Manager `TagValue` for testing."""

  def __init__(
      self,
      name,
      short_name,
      namespaced_name=None,
      parent=None,
      description=None,
  ):
    self.name = name
    self.short_name = short_name
    self.namespaced_name = namespaced_name
    self.parent = parent
    self.description = description


class FakeDataGovernanceTag:
  """Fake representation of `DataGovernanceTag` in a V2 `DataPolicy`."""

  def __init__(self, key=None, value=None):
    self.key = key
    self.value = value


class FakePredefinedExpression:
  """Fake representation of `PredefinedExpression` in `DataMaskingPolicy`."""

  def __init__(self, name):
    self.name = name


class FakeDataMaskingPolicy:
  """Fake representation of `DataMaskingPolicy` in a V2 `DataPolicy`."""

  def __init__(self, predefined_expression=None, routine=None):
    self.predefined_expression = (
        FakePredefinedExpression(predefined_expression)
        if isinstance(predefined_expression, str)
        else predefined_expression
    )
    self.routine = routine


class FakeDataPolicyV2:
  """Fake representation of a V2 `DataPolicy` resource for testing."""

  def __init__(
      self,
      name,
      data_policy_id=None,
      data_policy_type=None,
      data_governance_tag=None,
      data_masking_policy=None,
      grantees=None,
      matching_condition=None,
      data_governance_tag_condition=None,
  ):
    self.name = name
    self.data_policy_id = data_policy_id or name.split("/")[-1]
    self.data_policy_type = data_policy_type
    self.data_governance_tag = data_governance_tag
    self.data_masking_policy = data_masking_policy
    self.grantees = grantees or []
    self.matching_condition = matching_condition
    self.data_governance_tag_condition = data_governance_tag_condition


# Ensure local imports work in both package and standalone script execution.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# pylint: disable=g-import-not-at-top
# pylint: disable=g-bad-import-order
import constants
import analyzer

# pylint: enable=g-bad-import-order
# pylint: enable=g-import-not-at-top


class AnalyzerTest(unittest.TestCase):
  """Unit tests for `analyzer.Analyzer` across Modes 1, 2, 3, and 4."""

  def setUp(self):
    """Initializes strict `spec_set=True` mocks for all 8 Cloud API clients."""
    super().setUp()

    # Arrange: Construct strict autospec mocks for Data Catalog, Data Policy V1,
    # BigQuery, Resource Manager Projects, IAM Admin, Resource Manager Tag Keys
    # & Tag Values, and Data Policy V2 clients.
    self.mock_dc_client = mock.create_autospec(
        FakePolicyTagManagerClient, instance=True, spec_set=True
    )
    self.mock_bdp_client = mock.create_autospec(
        bigquery_datapolicies_v1.DataPolicyServiceClient,
        instance=True,
        spec_set=True,
    )
    self.mock_bq_client = mock.create_autospec(
        bigquery.Client, instance=True, spec_set=True
    )
    self.mock_crm_client = mock.create_autospec(
        resourcemanager_v3.ProjectsClient, instance=True, spec_set=True
    )
    self.mock_iam_client = mock.create_autospec(
        iam_admin_v1.IAMClient, instance=True, spec_set=True
    )
    self.mock_dg_tag_keys_client = mock.create_autospec(
        resourcemanager_v3.TagKeysClient, instance=True, spec_set=True
    )
    self.mock_dg_tag_values_client = mock.create_autospec(
        resourcemanager_v3.TagValuesClient, instance=True, spec_set=True
    )
    self.mock_data_policy_v2_client = mock.create_autospec(
        bigquery_datapolicies_v1.DataPolicyServiceClient,
        instance=True,
        spec_set=True,
    )
    self.analyzer = analyzer.Analyzer(
        data_catalog_client=self.mock_dc_client,
        data_policy_client=self.mock_bdp_client,
        bigquery_client=self.mock_bq_client,
        resourcemanager_client=self.mock_crm_client,
        iam_client=self.mock_iam_client,
        dg_tag_keys_client=self.mock_dg_tag_keys_client,
        dg_tag_values_client=self.mock_dg_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
    )

  # === Section 2: IAM Principal Extraction & Project Normalization Tests ===

  def test_get_principals_with_permission(self):
    """Scenario: Extract Fine-Grained Reader principals & cache custom roles.

    Verifies that `_get_principals_with_permission` resolves both predefined
    roles (from `_role_permission_cache`) and project/organization custom roles
    (via `iam_client.get_role`), excludes roles lacking the target permission,
    and caches custom role definitions so subsequent calls issue zero extra
    RPCs.
    """
    # Arrange: Seed the predefined role cache and construct an IAM policy with
    # 1 predefined role, 1 project custom role, 1 organization custom role, and
    # 1 unrelated role.
    self.analyzer._role_permission_cache = {
        constants.FINE_GRAINED_READER_ROLE: [
            constants.FINE_GRAINED_READER_PERMISSION
        ]
    }

    policy = policy_pb2.Policy(
        bindings=[
            policy_pb2.Binding(
                role=constants.FINE_GRAINED_READER_ROLE,
                members=["user:standard@example.com"],
            ),
            policy_pb2.Binding(
                role="projects/my-project/roles/customFineGrained",
                members=["user:custom_proj@example.com"],
            ),
            policy_pb2.Binding(
                role="organizations/123/roles/customFineGrainedOrg",
                members=["user:custom_org@example.com"],
            ),
            policy_pb2.Binding(
                role="roles/other.role", members=["user:other@example.com"]
            ),
        ]
    )

    def get_role_side_effect(request, retry=None):
      del retry  # Unused
      role = request["name"]
      if role == "projects/my-project/roles/customFineGrained":
        return iam_admin_v1.Role(
            included_permissions=[
                constants.FINE_GRAINED_READER_PERMISSION,
                "some.other.permission",
            ]
        )
      elif role == "organizations/123/roles/customFineGrainedOrg":
        return iam_admin_v1.Role(
            included_permissions=[constants.FINE_GRAINED_READER_PERMISSION]
        )
      else:
        return iam_admin_v1.Role(included_permissions=["some.other.permission"])

    self.mock_iam_client.get_role.side_effect = get_role_side_effect

    # Act: Resolve principals for the fine-grained reader permission twice.
    principals = self.analyzer._get_principals_with_permission(
        policy, constants.FINE_GRAINED_READER_PERMISSION
    )
    principals2 = self.analyzer._get_principals_with_permission(
        policy, constants.FINE_GRAINED_READER_PERMISSION
    )

    # Assert: Only roles granting fineGrainedGet are included, and custom roles
    # are fetched once and served from `_role_permission_cache` on the 2nd call.
    self.assertCountEqual(
        principals,
        [
            "user:standard@example.com",
            "user:custom_proj@example.com",
            "user:custom_org@example.com",
        ],
    )
    self.mock_iam_client.get_role.assert_has_calls(
        [
            mock.call(
                request={"name": "projects/my-project/roles/customFineGrained"},
                retry=mock.ANY,
            ),
            mock.call(
                request={
                    "name": "organizations/123/roles/customFineGrainedOrg"
                },
                retry=mock.ANY,
            ),
            mock.call(request={"name": "roles/other.role"}, retry=mock.ANY),
        ],
        any_order=True,
    )
    self.assertCountEqual(principals, principals2)
    self.assertEqual(self.mock_iam_client.get_role.call_count, 3)

  def test_get_principals_with_permission_masked(self):
    """Scenario: Extract Masked Reader principals from standard & custom roles.

    Verifies that `_get_principals_with_permission` resolves
    `bigquerydatapolicy.dataPolicies.maskedGet` across predefined, project-level
    custom, and organization-level custom IAM roles and caches custom role
    lookups.
    """
    # Arrange: Seed `_role_permission_cache` with `MASKED_READER_ROLE` and mock
    # `get_role` for custom roles.
    self.analyzer._role_permission_cache = {
        constants.MASKED_READER_ROLE: [constants.MASKED_READER_PERMISSION]
    }

    policy = policy_pb2.Policy(
        bindings=[
            policy_pb2.Binding(
                role=constants.MASKED_READER_ROLE,
                members=["user:standard_masked@example.com"],
            ),
            policy_pb2.Binding(
                role="projects/my-project/roles/customMasked",
                members=["user:custom_proj_masked@example.com"],
            ),
            policy_pb2.Binding(
                role="organizations/123/roles/customMaskedOrg",
                members=["user:custom_org_masked@example.com"],
            ),
            policy_pb2.Binding(
                role="roles/other.role", members=["user:other@example.com"]
            ),
        ]
    )

    def get_role_side_effect(request, retry=None):
      del retry  # Unused
      role = request["name"]
      if role == "projects/my-project/roles/customMasked":
        return iam_admin_v1.Role(
            included_permissions=[
                constants.MASKED_READER_PERMISSION,
                "some.other.permission",
            ]
        )
      elif role == "organizations/123/roles/customMaskedOrg":
        return iam_admin_v1.Role(
            included_permissions=[constants.MASKED_READER_PERMISSION]
        )
      else:
        return iam_admin_v1.Role(included_permissions=["some.other.permission"])

    self.mock_iam_client.get_role.side_effect = get_role_side_effect

    # Act: Extract principals for `MASKED_READER_PERMISSION` twice.
    principals = self.analyzer._get_principals_with_permission(
        policy, constants.MASKED_READER_PERMISSION
    )
    principals2 = self.analyzer._get_principals_with_permission(
        policy, constants.MASKED_READER_PERMISSION
    )

    # Assert: Principals from predefined and matching custom roles are returned
    # and cached on subsequent calls.
    self.assertCountEqual(
        principals,
        [
            "user:standard_masked@example.com",
            "user:custom_proj_masked@example.com",
            "user:custom_org_masked@example.com",
        ],
    )
    self.mock_iam_client.get_role.assert_has_calls(
        [
            mock.call(
                request={"name": "projects/my-project/roles/customMasked"},
                retry=mock.ANY,
            ),
            mock.call(
                request={"name": "organizations/123/roles/customMaskedOrg"},
                retry=mock.ANY,
            ),
            mock.call(request={"name": "roles/other.role"}, retry=mock.ANY),
        ],
        any_order=True,
    )
    self.assertCountEqual(principals, principals2)
    self.assertEqual(self.mock_iam_client.get_role.call_count, 3)

  def test_get_project_number(self):
    """Scenario: Resolve GCP Project ID to numeric Project Number with fallback.

    Verifies that `_get_project_number` extracts and caches the numeric project
    number from `projects/{number}` and returns `None` when the response format
    is non-numeric or when `get_project` raises `GoogleAPIError`.
    """
    # Arrange: Configure mock `ProjectsClient` to return `"projects/12345"`.
    mock_project = resourcemanager_v3.Project(name="projects/12345")
    self.mock_crm_client.get_project.return_value = mock_project

    # Act: Look up project number for `"test-project"`.
    project_number = self.analyzer._get_project_number("test-project")

    # Assert: Valid numeric ID `"12345"` is returned; invalid or error responses
    # return `None` after clearing the cache.
    self.assertEqual(project_number, "12345")
    self.mock_crm_client.get_project.assert_called_once_with(
        name="projects/test-project"
    )

    self.analyzer._project_id_to_number_cache.clear()
    mock_project.name = "projects/invalid"
    self.assertIsNone(self.analyzer._get_project_number("test-project"))

    self.mock_crm_client.get_project.side_effect = exceptions.GoogleAPIError(
        "Not Found"
    )
    self.assertIsNone(self.analyzer._get_project_number("test-project"))

  def test_get_project_id(self):
    """Scenario: Resolve numeric Project Number back to Project ID string.

    Verifies that `_get_project_id` resolves `"projects/12345"` to
    `"test-project"` and returns `None` when `project_id` is empty or when
    `get_project` raises `GoogleAPIError`.
    """
    # Arrange: Configure mock `ProjectsClient` with `project_id="test-project"`.
    mock_project = resourcemanager_v3.Project(project_id="test-project")
    self.mock_crm_client.get_project.return_value = mock_project

    # Act: Look up project ID for project number `"12345"`.
    project_id = self.analyzer._get_project_id("12345")

    # Assert: Valid project ID is returned; empty or failed responses return
    # `None`.
    self.assertEqual(project_id, "test-project")
    self.mock_crm_client.get_project.assert_called_once_with(
        name="projects/12345"
    )

    self.analyzer._project_number_to_id_cache.clear()
    mock_project.project_id = None
    self.assertIsNone(self.analyzer._get_project_id("12345"))

    self.mock_crm_client.get_project.side_effect = exceptions.GoogleAPIError(
        "Not Found"
    )
    self.assertIsNone(self.analyzer._get_project_id("12345"))

  # === Section 3: Mode 1 (`static-taxonomy`) Unit Tests ===

  def test_list_policy_tags_in_taxonomy(self):
    """Scenario: Enumerate Policy Tags, normalize project IDs, and fetch IAM.

    Verifies that `_list_policy_tags` normalizes both `name` and
    `parent_policy_tag` from `projects/{project_id}/...` to
    `projects/{project_number}/...` and concurrently retrieves each Policy Tag's
    Fine-Grained Reader principals in deterministic order.
    """
    # Arrange: Mock two hierarchical policy tags and their IAM policies.
    taxonomy_name = "projects/12345/locations/us/taxonomies/54321"
    self.mock_dc_client.list_policy_tags.return_value = [
        datacatalog_v1.PolicyTag(
            name=(
                "projects/test-project/locations/us/taxonomies/"
                "54321/policyTags/1"
            ),
            display_name="Tag 1",
        ),
        datacatalog_v1.PolicyTag(
            name=(
                "projects/test-project/locations/us/taxonomies/"
                "54321/policyTags/2"
            ),
            display_name="Tag 2 Child",
            parent_policy_tag=(
                "projects/test-project/locations/us/taxonomies/"
                "54321/policyTags/1"
            ),
        ),
    ]
    self.mock_dc_client.get_iam_policy.return_value = policy_pb2.Policy(
        bindings=[
            policy_pb2.Binding(
                role=constants.FINE_GRAINED_READER_ROLE,
                members=["user:user1@example.com"],
            )
        ]
    )

    # Act: List policy tags for the taxonomy.
    policy_tags = self.analyzer._list_policy_tags(
        taxonomy_name, "test-project", "12345"
    )

    # Assert: Both tags are normalized to project number `"12345"` and have
    # fine-grained readers populated in deterministic order.
    self.assertEqual(len(policy_tags), 2)
    self.assertEqual(
        policy_tags[0].name,
        "projects/12345/locations/us/taxonomies/54321/policyTags/1",
    )
    self.assertEqual(policy_tags[0].display_name, "Tag 1")
    self.assertEqual(policy_tags[0].parent_policy_tag, "")
    self.assertEqual(
        policy_tags[0].fine_grained_readers, ["user:user1@example.com"]
    )
    self.assertEqual(
        policy_tags[1].name,
        "projects/12345/locations/us/taxonomies/54321/policyTags/2",
    )
    self.assertEqual(policy_tags[1].display_name, "Tag 2 Child")
    self.assertEqual(
        policy_tags[1].parent_policy_tag,
        "projects/12345/locations/us/taxonomies/54321/policyTags/1",
    )
    self.assertEqual(
        policy_tags[1].fine_grained_readers, ["user:user1@example.com"]
    )

  def test_list_policy_tags_project_id_replacement_count_one(self):
    """Scenario: Bound project ID replacement to the leading prefix (`count=1`).

    Verifies that normalizing `projects/{project_id}/` to
    `projects/{project_number}/` replaces only the first occurrence (`count=1`)
    and does not corrupt a trailing resource segment containing the same
    substring.
    """
    # Arrange: Create a policy tag whose trailing ID segment repeats
    # `"projects/test-project/"`.
    taxonomy_name = "projects/12345/locations/us/taxonomies/54321"
    self.mock_dc_client.list_policy_tags.return_value = [
        datacatalog_v1.PolicyTag(
            name=(
                "projects/test-project/locations/us/taxonomies/54321/"
                "policyTags/projects/test-project/sub"
            ),
            display_name="Tag 1",
        ),
    ]
    self.mock_dc_client.get_iam_policy.return_value = policy_pb2.Policy()

    # Act: List policy tags and normalize the resource name.
    policy_tags = self.analyzer._list_policy_tags(
        taxonomy_name, "test-project", "12345"
    )

    # Assert: Only the leading project segment is replaced with `"12345"`.
    self.assertEqual(len(policy_tags), 1)
    self.assertEqual(
        policy_tags[0].name,
        (
            "projects/12345/locations/us/taxonomies/54321/"
            "policyTags/projects/test-project/sub"
        ),
    )

  @mock.patch.object(
      analyzer.Analyzer, "_get_project_id", autospec=True, spec_set=True
  )
  def test_list_data_policies_in_taxonomy(self, mock_get_project_id):
    """Scenario: Attach V1 Data Policies, resolve routines, & extract readers.

    Verifies that `_list_data_policies` matches V1 Data Policies to Policy Tags,
    marks `taxonomy_info.is_access_control = True` (Implicit Access Control),
    formats predefined expressions and custom masking routines (including
    `<unknown-project-{number}>` fallback when project number resolution fails),
    and extracts Masked Reader principals.
    """
    # Arrange: Configure 4 V1 Data Policies (2 predefined expressions, 1 custom
    # routine with resolvable project number, 1 with unresolvable number).
    mock_get_project_id.side_effect = ["routine-project", None]
    taxonomy_info = analyzer.TaxonomyInfo(
        name="projects/12345/locations/us/taxonomies/54321",
        display_name="Test Taxonomy",
        location="us",
        policy_tags=[
            analyzer.PolicyTagInfo(
                name=(
                    "projects/12345/locations/us/taxonomies/54321/policyTags/1"
                ),
                display_name="Tag 1",
                parent_policy_tag="",
            )
        ],
    )
    predefined_enum = (
        bigquery_datapolicies_v1.DataMaskingPolicy.PredefinedExpression
    )
    self.mock_bdp_client.list_data_policies.return_value = [
        FakeDataPolicyV1(
            name="projects/test-project/locations/us/dataPolicies/test_policy",
            data_policy_id="test_policy",
            data_policy_type=2,
            policy_tag=(
                "projects/12345/locations/us/taxonomies/54321/policyTags/1"
            ),
            data_masking_policy=FakeDataMaskingPolicyV1(
                predefined_expression=predefined_enum.ALWAYS_NULL
            ),
        ),
        FakeDataPolicyV1(
            name=(
                "projects/test-project/locations/us/dataPolicies/test_policy_2"
            ),
            data_policy_id="test_policy_2",
            data_policy_type=2,
            policy_tag=(
                "projects/12345/locations/us/taxonomies/54321/policyTags/1"
            ),
            data_masking_policy=FakeDataMaskingPolicyV1(
                predefined_expression=predefined_enum.SHA256,
                routine="",
            ),
        ),
        FakeDataPolicyV1(
            name=(
                "projects/test-project/locations/us/dataPolicies/test_policy_3"
            ),
            data_policy_id="test_policy_3",
            data_policy_type=2,
            policy_tag=(
                "projects/12345/locations/us/taxonomies/54321/policyTags/1"
            ),
            data_masking_policy=FakeDataMaskingPolicyV1(
                predefined_expression=(
                    predefined_enum.PREDEFINED_EXPRESSION_UNSPECIFIED
                ),
                routine=(
                    "projects/12345/datasets/my_dataset/routines/my_routine"
                ),
            ),
        ),
        FakeDataPolicyV1(
            name=(
                "projects/test-project/locations/us/dataPolicies/test_policy_4"
            ),
            data_policy_id="test_policy_4",
            data_policy_type=2,
            policy_tag=(
                "projects/12345/locations/us/taxonomies/54321/policyTags/1"
            ),
            data_masking_policy=FakeDataMaskingPolicyV1(
                predefined_expression=(
                    predefined_enum.PREDEFINED_EXPRESSION_UNSPECIFIED
                ),
                routine=(
                    "projects/9999/datasets/my_dataset/routines/"
                    "my_failed_routine"
                ),
            ),
        ),
    ]
    self.mock_bdp_client.get_iam_policy.return_value = policy_pb2.Policy(
        bindings=[
            policy_pb2.Binding(
                role=constants.MASKED_READER_ROLE,
                members=["user:user2@example.com"],
            )
        ]
    )

    # Act: Populate V1 data policies onto `taxonomy_info`.
    self.analyzer._list_data_policies("test-project", "us", taxonomy_info)

    # Assert: Implicit access control is enabled and all 4 masking rules and
    # readers are accurately populated.
    self.assertTrue(taxonomy_info.is_access_control)
    self.assertEqual(len(taxonomy_info.policy_tags[0].data_policies), 4)

    data_policy_info_1 = taxonomy_info.policy_tags[0].data_policies[0]
    self.assertEqual(
        data_policy_info_1.name,
        "projects/test-project/locations/us/dataPolicies/test_policy",
    )
    self.assertEqual(data_policy_info_1.masking_rule, "ALWAYS_NULL")
    self.assertEqual(
        data_policy_info_1.masked_readers, ["user:user2@example.com"]
    )

    data_policy_info_2 = taxonomy_info.policy_tags[0].data_policies[1]
    self.assertEqual(
        data_policy_info_2.name,
        "projects/test-project/locations/us/dataPolicies/test_policy_2",
    )
    self.assertEqual(data_policy_info_2.masking_rule, "SHA256")
    self.assertEqual(
        data_policy_info_2.masked_readers, ["user:user2@example.com"]
    )

    data_policy_info_3 = taxonomy_info.policy_tags[0].data_policies[2]
    self.assertEqual(
        data_policy_info_3.name,
        "projects/test-project/locations/us/dataPolicies/test_policy_3",
    )
    self.assertEqual(
        data_policy_info_3.masking_rule,
        "Custom Routine: routine-project.my_dataset.my_routine",
    )
    self.assertEqual(
        data_policy_info_3.masked_readers, ["user:user2@example.com"]
    )

    data_policy_info_4 = taxonomy_info.policy_tags[0].data_policies[3]
    self.assertEqual(
        data_policy_info_4.name,
        "projects/test-project/locations/us/dataPolicies/test_policy_4",
    )
    self.assertEqual(
        data_policy_info_4.masking_rule,
        "Custom Routine: <unknown-project-9999>.my_dataset.my_failed_routine",
    )
    self.assertEqual(
        data_policy_info_4.masked_readers, ["user:user2@example.com"]
    )

  @mock.patch.object(
      analyzer.Analyzer, "_get_project_id", autospec=True, spec_set=True
  )
  def test_list_data_policies_routine_project_id_and_malformed(
      self, mock_get_project_id
  ):
    """Scenario: Handle project-ID custom routines and malformed routine paths.

    Verifies that `_list_data_policies` skips `_get_project_id` RPCs when a
    custom masking routine path already embeds a non-numeric project ID, and
    records a descriptive warning on `DataPolicyInfo.warnings` when a routine
    path has fewer than 5 slash-separated segments.
    """
    # Arrange: Create one policy with a project-ID routine path and one with a
    # malformed routine path.
    taxonomy_info = analyzer.TaxonomyInfo(
        name="projects/12345/locations/us/taxonomies/54321",
        display_name="Test Taxonomy",
        location="us",
        policy_tags=[
            analyzer.PolicyTagInfo(
                name=(
                    "projects/12345/locations/us/taxonomies/54321/policyTags/1"
                ),
                display_name="Tag 1",
                parent_policy_tag="",
            )
        ],
    )
    predefined_enum = (
        bigquery_datapolicies_v1.DataMaskingPolicy.PredefinedExpression
    )
    policy_with_project_id = FakeDataPolicyV1(
        name="projects/test-project/locations/us/dataPolicies/udf_policy",
        data_policy_id="udf_policy",
        data_policy_type=2,
        policy_tag="projects/12345/locations/us/taxonomies/54321/policyTags/1",
        data_masking_policy=FakeDataMaskingPolicyV1(
            predefined_expression=(
                predefined_enum.PREDEFINED_EXPRESSION_UNSPECIFIED
            ),
            routine="projects/my-udf-proj/datasets/my_ds/routines/my_fn",
        ),
    )
    policy_malformed_routine = FakeDataPolicyV1(
        name=(
            "projects/test-project/locations/us/dataPolicies/bad_routine_policy"
        ),
        data_policy_id="bad_routine_policy",
        data_policy_type=2,
        policy_tag="projects/12345/locations/us/taxonomies/54321/policyTags/1",
        data_masking_policy=FakeDataMaskingPolicyV1(
            predefined_expression=(
                predefined_enum.PREDEFINED_EXPRESSION_UNSPECIFIED
            ),
            routine="projects/bad_routine",
        ),
    )
    self.mock_bdp_client.list_data_policies.return_value = [
        policy_with_project_id,
        policy_malformed_routine,
    ]
    self.mock_bdp_client.get_iam_policy.return_value = policy_pb2.Policy()

    # Act: List data policies for the taxonomy.
    self.analyzer._list_data_policies("test-project", "us", taxonomy_info)

    # Assert: `_get_project_id` is not called for non-numeric project tokens and
    # malformed routine paths record a warning.
    mock_get_project_id.assert_not_called()
    policies = taxonomy_info.policy_tags[0].data_policies
    self.assertEqual(len(policies), 2)
    self.assertEqual(
        policies[0].masking_rule,
        "Custom Routine: my-udf-proj.my_ds.my_fn",
    )
    self.assertEqual(policies[0].warnings, [])
    self.assertEqual(
        policies[1].masking_rule,
        "Custom Routine: projects/bad_routine",
    )
    self.assertEqual(len(policies[1].warnings), 1)
    self.assertIn(
        "Malformed custom masking routine resource name 'projects/bad_routine'",
        policies[1].warnings[0],
    )

  @mock.patch.object(
      analyzer.Analyzer, "_get_project_number", autospec=True, spec_set=True
  )
  @mock.patch.object(
      analyzer.Analyzer,
      "_list_policy_tags",
      autospec=True,
      spec_set=True,
  )
  @mock.patch.object(
      analyzer.Analyzer,
      "_list_data_policies",
      autospec=True,
      spec_set=True,
  )
  def test_analyze_static_taxonomy(
      self,
      mock_list_data_policies,
      mock_list_policy_tags,
      mock_get_project_number,
  ):
    """Scenario: Analyze a Classification-Only taxonomy in Mode 1.

    Verifies that `_analyze_static_taxonomy` normalizes the taxonomy resource
    name with the project number, delegates Policy Tag and V1 Data Policy
    enumeration, and leaves `is_access_control=False` when neither
    `FINE_GRAINED_ACCESS_CONTROL` nor any V1 Data Policy is present.
    """
    # Arrange: Configure one classification-only taxonomy in `test-project`.
    mock_get_project_number.return_value = "12345"
    self.mock_dc_client.list_taxonomies.return_value = [
        datacatalog_v1.Taxonomy(
            name="projects/test-project/locations/us/taxonomies/54321",
            display_name="Test Taxonomy",
        )
    ]
    mock_list_policy_tags.return_value = []

    # Act: Run static taxonomy analysis for `test-project` in `us`.
    taxonomies = self.analyzer._analyze_static_taxonomy("test-project", "us")

    # Assert: The taxonomy name uses project number `12345` and is not marked as
    # access control when neither `activated_policy_types` nor Data Policies
    # exist.
    self.assertEqual(len(taxonomies), 1)
    self.assertEqual(
        taxonomies[0].name, "projects/12345/locations/us/taxonomies/54321"
    )
    self.assertFalse(taxonomies[0].is_access_control)
    mock_list_policy_tags.assert_called_once()
    mock_list_data_policies.assert_called_once()

  @mock.patch.object(
      analyzer.Analyzer, "_get_project_number", autospec=True, spec_set=True
  )
  @mock.patch.object(
      analyzer.Analyzer,
      "_list_policy_tags",
      autospec=True,
      spec_set=True,
  )
  @mock.patch.object(
      analyzer.Analyzer,
      "_list_data_policies",
      autospec=True,
      spec_set=True,
  )
  def test_analyze_static_taxonomy_with_activated_policy_types(
      self,
      mock_list_data_policies,
      mock_list_policy_tags,
      mock_get_project_number,
  ):
    """Scenario: Detect Explicit Access Control via `activated_policy_types`.

    Verifies that `_analyze_static_taxonomy` sets `is_access_control=True` when
    `FINE_GRAINED_ACCESS_CONTROL` is present in `activated_policy_types`.
    """
    # Arrange: Configure a taxonomy with `FINE_GRAINED_ACCESS_CONTROL` enabled.
    mock_get_project_number.return_value = "12345"
    self.mock_dc_client.list_taxonomies.return_value = [
        datacatalog_v1.Taxonomy(
            name="projects/test-project/locations/us/taxonomies/54321",
            display_name="Test Taxonomy",
            activated_policy_types=[
                datacatalog_v1.Taxonomy.PolicyType.FINE_GRAINED_ACCESS_CONTROL
            ],
        )
    ]
    mock_list_policy_tags.return_value = []

    # Act: Run static taxonomy analysis.
    taxonomies = self.analyzer._analyze_static_taxonomy("test-project", "us")

    # Assert: `is_access_control` is `True`.
    self.assertEqual(len(taxonomies), 1)
    self.assertTrue(taxonomies[0].is_access_control)
    mock_list_data_policies.assert_called_once()

  @mock.patch.object(
      analyzer.Analyzer, "_get_project_number", autospec=True, spec_set=True
  )
  @mock.patch.object(
      analyzer.Analyzer,
      "_list_policy_tags",
      autospec=True,
      spec_set=True,
  )
  @mock.patch.object(
      analyzer.Analyzer,
      "_list_data_policies",
      autospec=True,
      spec_set=True,
  )
  def test_analyze_static_taxonomy_with_taxonomy_fine_grained_readers(
      self,
      mock_list_data_policies,
      mock_list_policy_tags,
      mock_get_project_number,
  ):
    """Scenario: Extract Taxonomy-level Fine-Grained Reader principals.

    Verifies that `_analyze_static_taxonomy` queries `get_iam_policy` on the
    Taxonomy resource itself and populates `TaxonomyInfo.fine_grained_readers`
    so `planner.py` can inherit those readers across all child Policy Tags.
    """
    # Arrange: Configure a taxonomy IAM policy granting
    # `FINE_GRAINED_READER_ROLE`.
    mock_get_project_number.return_value = "12345"
    self.mock_dc_client.list_taxonomies.return_value = [
        datacatalog_v1.Taxonomy(
            name="projects/test-project/locations/us/taxonomies/54321",
            display_name="Test Taxonomy",
            activated_policy_types=[
                datacatalog_v1.Taxonomy.PolicyType.FINE_GRAINED_ACCESS_CONTROL
            ],
        )
    ]
    mock_list_policy_tags.return_value = []
    self.mock_dc_client.get_iam_policy.return_value = policy_pb2.Policy(
        bindings=[
            policy_pb2.Binding(
                role=constants.FINE_GRAINED_READER_ROLE,
                members=["user:tax_reader@example.com"],
            )
        ]
    )

    # Act: Run static taxonomy analysis.
    taxonomies = self.analyzer._analyze_static_taxonomy("test-project", "us")

    # Assert: Taxonomy-level `fine_grained_readers` are populated on
    # `TaxonomyInfo`.
    self.assertEqual(len(taxonomies), 1)
    self.assertEqual(
        taxonomies[0].fine_grained_readers, ["user:tax_reader@example.com"]
    )
    mock_list_data_policies.assert_called_once()
    expected_request = iam_policy_pb2.GetIamPolicyRequest(
        resource="projects/12345/locations/us/taxonomies/54321"
    )
    expected_request.options.requested_policy_version = 3
    self.mock_dc_client.get_iam_policy.assert_called_with(
        request=expected_request,
        retry=analyzer.RETRY_CONFIG,
    )

  @mock.patch.object(
      analyzer.Analyzer, "_get_project_number", autospec=True, spec_set=True
  )
  @mock.patch.object(
      analyzer.Analyzer,
      "_list_policy_tags",
      autospec=True,
      spec_set=True,
  )
  @mock.patch.object(
      analyzer.Analyzer,
      "_list_data_policies",
      autospec=True,
      spec_set=True,
  )
  def test_analyze_static_taxonomy_iam_permission_denied(
      self,
      mock_list_data_policies,
      mock_list_policy_tags,
      mock_get_project_number,
  ):
    """Scenario: Fail-closed propagation of taxonomy IAM `PermissionDenied`.

    Verifies that `_analyze_static_taxonomy` re-raises `PermissionDenied` when
    `get_iam_policy` fails on a taxonomy rather than silently generating a
    migration plan with missing taxonomy-level readers.
    """
    # Arrange: Configure `get_iam_policy` to raise `PermissionDenied`.
    mock_get_project_number.return_value = "12345"
    self.mock_dc_client.list_taxonomies.return_value = [
        datacatalog_v1.Taxonomy(
            name="projects/test-project/locations/us/taxonomies/54321",
            display_name="Test Taxonomy",
        )
    ]
    mock_list_policy_tags.return_value = []
    self.mock_dc_client.get_iam_policy.side_effect = (
        analyzer.exceptions.PermissionDenied("Denied")
    )

    # Act & Assert: `PermissionDenied` is raised before `_list_data_policies`.
    with self.assertRaises(analyzer.exceptions.PermissionDenied):
      self.analyzer._analyze_static_taxonomy("test-project", "us")
    mock_list_data_policies.assert_not_called()

  def test_generate_static_taxonomy_report(self):
    """Scenario: Render Mode 1 ASCII report with taxonomy & tag permissions.

    Verifies that `generate_static_taxonomy_report` formats taxonomy metadata,
    taxonomy-level readers, policy tags, and attached V1 data policies into the
    expected 72-column ASCII hierarchy.
    """
    # Arrange: Build a `StaticTaxonomyAnalysisResult` with 1 tag and 2 policies.
    policy_tag_1 = "projects/12345/locations/us/taxonomies/54321/policyTags/1"
    results = [
        analyzer.StaticTaxonomyAnalysisResult(
            project_id="test-project",
            location="us",
            taxonomies=[
                analyzer.TaxonomyInfo(
                    name="projects/12345/locations/us/taxonomies/54321",
                    display_name="Test Taxonomy",
                    location="us",
                    is_access_control=True,
                    fine_grained_readers=["user:tax_reader@example.com"],
                    policy_tags=[
                        analyzer.PolicyTagInfo(
                            name=policy_tag_1,
                            display_name="Tag 1",
                            parent_policy_tag="",
                            fine_grained_readers=["user:fg@example.com"],
                            data_policies=[
                                analyzer.DataPolicyInfo(
                                    name=(
                                        "projects/test-project/locations/us/"
                                        "dataPolicies/dp1"
                                    ),
                                    policy_tag=policy_tag_1,
                                    masking_rule="SHA256",
                                    masked_readers=["user:mr@example.com"],
                                ),
                                analyzer.DataPolicyInfo(
                                    name=(
                                        "projects/test-project/locations/us/"
                                        "dataPolicies/dp2"
                                    ),
                                    policy_tag=policy_tag_1,
                                    masking_rule="ALWAYS_NULL",
                                    masked_readers=["user:mr2@example.com"],
                                ),
                            ],
                        )
                    ],
                )
            ],
        )
    ]

    # Act: Generate the human-readable static taxonomy report.
    report = self.analyzer.generate_static_taxonomy_report(results)

    # Assert: All expected headings, permissions, and principals are present,
    # wrapped in a Markdown report with a fenced `text` code block.
    self.assertTrue(
        report.startswith("# Static Taxonomy & Data Policy Analysis Report\n")
    )
    self.assertIn("```text\n", report)
    self.assertTrue(report.endswith("\n```"))
    self.assertIn("STATIC TAXONOMY ANALYSIS", report)
    self.assertIn('Taxonomy: "Test Taxonomy"', report)
    self.assertIn("Region:                 us", report)
    self.assertIn("Taxonomy Type:          Access Control", report)
    self.assertIn("Taxonomy-Level Readers: 1", report)
    self.assertIn(
        "Taxonomy Permission: Fine-Grained Reader (Raw Access)", report
    )
    self.assertIn("Principals: user:tax_reader@example.com", report)
    self.assertIn('> Policy Tag: "Tag 1"', report)
    self.assertIn("Permission: Fine-Grained Reader", report)
    self.assertIn("Principals: user:fg@example.com", report)
    self.assertIn('Data Policy: "dp1" (Rule: SHA256)', report)
    self.assertIn("Permission: Masked Reader", report)
    self.assertIn("Principals: user:mr@example.com", report)
    self.assertIn('Data Policy: "dp2" (Rule: ALWAYS_NULL)', report)
    self.assertIn("Principals: user:mr2@example.com", report)

  def test_generate_report_with_hierarchy(self):
    """Scenario: Render nested parent/child Policy Tag indentation in Mode 1.

    Verifies that `generate_static_taxonomy_report` reconstructs the
    parent-child tree from `parent_policy_tag` references and indents child
    policy tags beneath their parent.
    """
    # Arrange: Build a taxonomy with a parent policy tag and a child policy tag.
    parent_tag_name = (
        "projects/12345/locations/us/taxonomies/54321/policyTags/1"
    )
    child_tag_name = "projects/12345/locations/us/taxonomies/54321/policyTags/2"
    results = [
        analyzer.StaticTaxonomyAnalysisResult(
            project_id="test-project",
            location="us",
            taxonomies=[
                analyzer.TaxonomyInfo(
                    name="projects/12345/locations/us/taxonomies/54321",
                    display_name="Test Hierarchical Taxonomy",
                    location="us",
                    is_access_control=True,
                    policy_tags=[
                        analyzer.PolicyTagInfo(
                            name=parent_tag_name,
                            display_name="Parent Tag",
                            parent_policy_tag="",
                            fine_grained_readers=["user:parent@example.com"],
                            data_policies=[],
                        ),
                        analyzer.PolicyTagInfo(
                            name=child_tag_name,
                            display_name="Child Tag",
                            parent_policy_tag=parent_tag_name,
                            fine_grained_readers=["user:child@example.com"],
                            data_policies=[],
                        ),
                    ],
                )
            ],
        )
    ]

    # Act: Generate the static report.
    report = self.analyzer.generate_static_taxonomy_report(results)

    # Assert: `Parent Tag` is rendered at root level and `Child Tag` is
    # indented.
    self.assertIn("STATIC TAXONOMY ANALYSIS", report)
    self.assertIn('Taxonomy: "Test Hierarchical Taxonomy"', report)
    self.assertIn('> Policy Tag: "Parent Tag"', report)
    self.assertIn('  > Policy Tag: "Child Tag"', report)

  # === Section 4: Mode 2 (`column-binding`) Unit Tests ===

  def test_analyze_column_bindings(self):
    """Scenario: Execute the 4 regional `INFORMATION_SCHEMA` queries in Mode 2.

    Verifies that `_analyze_column_bindings` runs the aggregate metrics query
    plus the 3 binding breakdown queries (Policy Tags, Data Governance Tags, and
    direct Column Data Policies) and populates `ColumnBindingAnalysisResult`.
    """
    # Arrange: Mock the 4 BigQuery `QueryJob` results (metrics, policy tags,
    # DGTs, and column-level data policies).
    mock_metrics_job = mock.create_autospec(
        bigquery.QueryJob, instance=True, spec_set=True
    )
    mock_policy_tag_job = mock.create_autospec(
        bigquery.QueryJob, instance=True, spec_set=True
    )
    mock_dgt_job = mock.create_autospec(
        bigquery.QueryJob, instance=True, spec_set=True
    )
    mock_data_policy_job = mock.create_autospec(
        bigquery.QueryJob, instance=True, spec_set=True
    )
    self.mock_bq_client.query.side_effect = [
        mock_metrics_job,
        mock_policy_tag_job,
        mock_dgt_job,
        mock_data_policy_job,
    ]

    mock_metrics_row = bigquery.Row(
        (150, 1200, 12, 45, 10, 30, 4, 10, 20, 60),
        {
            "total_tables": 0,
            "total_columns": 1,
            "tables_with_policy_tags": 2,
            "columns_with_policy_tags": 3,
            "tables_with_dg_tags": 4,
            "columns_with_dg_tags": 5,
            "tables_with_data_policies": 6,
            "columns_with_data_policies": 7,
            "tables_with_any_cls": 8,
            "columns_with_any_cls": 9,
        },
    )
    mock_metrics_job.result.return_value = [mock_metrics_row]

    mock_policy_tag_row_1 = bigquery.Row(
        ("projects/12345/locations/us/taxonomies/111/policyTags/222", 15),
        {"policy_tag": 0, "bound_columns": 1},
    )
    mock_policy_tag_row_2 = bigquery.Row(
        ("projects/12345/locations/us/taxonomies/111/policyTags/333", 15),
        {"policy_tag": 0, "bound_columns": 1},
    )
    mock_policy_tag_job.result.return_value = [
        mock_policy_tag_row_1,
        mock_policy_tag_row_2,
    ]

    mock_dgt_row = bigquery.Row(
        ("projects/12345/tagKeys/key1", "val1", 20),
        {"dg_tag_key": 0, "dg_tag_value": 1, "bound_columns": 2},
    )
    mock_dgt_job.result.return_value = [mock_dgt_row]

    mock_data_policy_row = bigquery.Row(
        ("projects/my-data-project/locations/us/dataPolicies/dp1", 5),
        {"data_policy_name": 0, "bound_columns": 1},
    )
    mock_data_policy_job.result.return_value = [mock_data_policy_row]

    # Act: Run `_analyze_column_bindings` for `my-data-project` in `us`.
    with mock.patch.object(
        self.analyzer, "_get_project_id", return_value="my-taxonomy-project"
    ):
      result = self.analyzer._analyze_column_bindings("my-data-project", "us")

    # Assert: All 4 queries run under `my-data-project` and populate metrics and
    # grouped bindings accurately.
    self.assertEqual(self.mock_bq_client.query.call_count, 4)
    first_call_kwargs = self.mock_bq_client.query.call_args_list[0].kwargs
    self.assertEqual(first_call_kwargs["project"], "my-data-project")

    self.assertEqual(result.project_id, "my-data-project")
    self.assertEqual(result.location, "us")
    self.assertEqual(result.metrics.total_tables_scanned, 150)
    self.assertEqual(result.metrics.total_columns_scanned, 1200)
    self.assertEqual(result.metrics.tables_with_policy_tags, 12)
    self.assertEqual(result.metrics.columns_with_policy_tags, 45)
    self.assertEqual(result.metrics.active_policy_tags_bound, 2)
    self.assertEqual(result.metrics.tables_with_dg_tags, 10)
    self.assertEqual(result.metrics.columns_with_dg_tags, 30)
    self.assertEqual(result.metrics.active_dg_tags_bound, 1)
    self.assertEqual(result.metrics.tables_with_column_data_policies, 4)
    self.assertEqual(result.metrics.columns_with_column_data_policies, 10)
    self.assertEqual(result.metrics.active_column_data_policies_bound, 1)
    self.assertEqual(result.metrics.tables_with_any_cls, 20)
    self.assertEqual(result.metrics.columns_with_any_cls, 60)

    self.assertIn("my-taxonomy-project", result.bindings_by_taxonomy_project)
    self.assertEqual(
        len(result.bindings_by_taxonomy_project["my-taxonomy-project"]), 2
    )
    self.assertIn("projects/12345/tagKeys/key1", result.bindings_by_tag_key)
    self.assertEqual(len(result.column_data_policy_bindings), 1)
    self.assertEqual(
        result.column_data_policy_bindings[0].data_policy_id, "dp1"
    )

  def test_analyze_column_bindings_concurrent_display_name_prefetch(
      self,
  ):
    """Scenario: Concurrently prefetch Policy Tag display names.

    Verifies that `_analyze_column_bindings` pre-fetches uncached Policy Tag
    display names concurrently via `get_policy_tag` before row processing, skips
    RPCs for tags already in `_policy_tag_display_name_cache`, preserves
    deterministic row ordering, and falls back gracefully (`None`) when
    `get_policy_tag` raises `GoogleAPIError`.
    """
    # Arrange: Pre-seed 1 tag in `_policy_tag_display_name_cache` and configure
    # 3 bound tags in query results (1 pre-cached, 1 resolved via RPC, 1 failing
    # with `GoogleAPIError`).
    tag_cached = "projects/12345/locations/us/taxonomies/111/policyTags/cached"
    tag_uncached = (
        "projects/12345/locations/us/taxonomies/111/policyTags/uncached"
    )
    tag_failing = (
        "projects/12345/locations/us/taxonomies/111/policyTags/failing"
    )
    self.analyzer._policy_tag_display_name_cache[tag_cached] = "Cached Tag"

    def get_policy_tag_side_effect(request, retry=None):
      del retry  # Unused
      tag_name = request["name"]
      if tag_name == tag_uncached:
        return FakePolicyTag(name=tag_uncached, display_name="Fetched Tag")
      raise exceptions.GoogleAPIError("Permission denied on policy tag")

    self.mock_dc_client.get_policy_tag.side_effect = get_policy_tag_side_effect

    mock_metrics_job = mock.create_autospec(
        bigquery.QueryJob, instance=True, spec_set=True
    )
    mock_policy_tag_job = mock.create_autospec(
        bigquery.QueryJob, instance=True, spec_set=True
    )
    mock_dgt_job = mock.create_autospec(
        bigquery.QueryJob, instance=True, spec_set=True
    )
    mock_data_policy_job = mock.create_autospec(
        bigquery.QueryJob, instance=True, spec_set=True
    )
    self.mock_bq_client.query.side_effect = [
        mock_metrics_job,
        mock_policy_tag_job,
        mock_dgt_job,
        mock_data_policy_job,
    ]
    mock_metrics_job.result.return_value = []
    mock_policy_tag_job.result.return_value = [
        bigquery.Row((tag_cached, 5), {"policy_tag": 0, "bound_columns": 1}),
        bigquery.Row((tag_uncached, 10), {"policy_tag": 0, "bound_columns": 1}),
        bigquery.Row((tag_failing, 3), {"policy_tag": 0, "bound_columns": 1}),
    ]
    mock_dgt_job.result.return_value = []
    mock_data_policy_job.result.return_value = []

    # Act: Run `_analyze_column_bindings`.
    with mock.patch.object(
        self.analyzer, "_get_project_id", return_value="my-taxonomy-project"
    ):
      result = self.analyzer._analyze_column_bindings("my-data-project", "us")

    # Assert: Only the 2 uncached tags triggered `get_policy_tag` RPCs, and the
    # resulting `PolicyTagBindingDetails` preserve deterministic order with
    # `None` fallback for `tag_failing`.
    self.assertEqual(self.mock_dc_client.get_policy_tag.call_count, 2)
    bindings = result.bindings_by_taxonomy_project["my-taxonomy-project"]
    self.assertEqual(len(bindings), 3)
    self.assertEqual(bindings[0].policy_tag_name, tag_cached)
    self.assertEqual(bindings[0].policy_tag_display_name, "Cached Tag")
    self.assertEqual(bindings[1].policy_tag_name, tag_uncached)
    self.assertEqual(bindings[1].policy_tag_display_name, "Fetched Tag")
    self.assertEqual(bindings[2].policy_tag_name, tag_failing)
    self.assertIsNone(bindings[2].policy_tag_display_name)

  def test_analyze_column_bindings_excludes_and_guards_crr_placeholder_tags(
      self,
  ):
    """Excludes `/taxonomies/0/policyTags/` in SQL and skips get_policy_tag."""
    # Prime a synthetic Cross-Region Replication secondary-replica Policy Tag
    # URI (`/taxonomies/0/policyTags/`) alongside a real primary Policy Tag URI
    # to verify both SQL-level filtering and the Python `get_policy_tag` guard.
    crr_placeholder_tag = (
        "projects/12345/locations/us/taxonomies/0/policyTags/999"
    )
    primary_tag = "projects/12345/locations/us/taxonomies/111/policyTags/222"
    self.mock_dc_client.get_policy_tag.return_value = FakePolicyTag(
        name=primary_tag, display_name="Primary Tag"
    )

    mock_metrics_job = mock.create_autospec(
        bigquery.QueryJob, instance=True, spec_set=True
    )
    mock_policy_tag_job = mock.create_autospec(
        bigquery.QueryJob, instance=True, spec_set=True
    )
    mock_dgt_job = mock.create_autospec(
        bigquery.QueryJob, instance=True, spec_set=True
    )
    mock_data_policy_job = mock.create_autospec(
        bigquery.QueryJob, instance=True, spec_set=True
    )
    self.mock_bq_client.query.side_effect = [
        mock_metrics_job,
        mock_policy_tag_job,
        mock_dgt_job,
        mock_data_policy_job,
    ]
    mock_metrics_job.result.return_value = []
    mock_policy_tag_job.result.return_value = [
        bigquery.Row(
            (crr_placeholder_tag, 1), {"policy_tag": 0, "bound_columns": 1}
        ),
        bigquery.Row((primary_tag, 2), {"policy_tag": 0, "bound_columns": 1}),
    ]
    mock_dgt_job.result.return_value = []
    mock_data_policy_job.result.return_value = []

    # Execute `_analyze_column_bindings` so SQL generation and display-name
    # prefetch run against both tags.
    with mock.patch.object(
        self.analyzer, "_get_project_id", return_value="my-taxonomy-project"
    ):
      result = self.analyzer._analyze_column_bindings("my-data-project", "us")

    # Confirm SQL queries filter out `/taxonomies/0/policyTags/`, and confirm
    # Data Catalog `get_policy_tag` is called only for `primary_tag` while
    # `crr_placeholder_tag` receives the synthetic CRR placeholder label.
    metrics_sql = self.mock_bq_client.query.call_args_list[0].args[0]
    pt_bindings_sql = self.mock_bq_client.query.call_args_list[1].args[0]
    self.assertIn(
        constants.CRR_PLACEHOLDER_POLICY_TAG_SEGMENT,
        metrics_sql,
    )
    self.assertIn(
        constants.CRR_PLACEHOLDER_POLICY_TAG_SEGMENT,
        pt_bindings_sql,
    )
    self.mock_dc_client.get_policy_tag.assert_called_once_with(
        request={"name": primary_tag}, retry=analyzer.RETRY_CONFIG
    )
    bindings = result.bindings_by_taxonomy_project["my-taxonomy-project"]
    self.assertEqual(len(bindings), 2)
    self.assertEqual(
        bindings[0].policy_tag_display_name,
        constants.CRR_REPLICA_POLICY_TAG_DISPLAY_NAME,
    )
    self.assertEqual(bindings[1].policy_tag_display_name, "Primary Tag")

  def test_analyze_column_bindings_fallback_without_data_policies_column(self):
    """Scenario: Fallback when `data_policies` column is unsupported in region.

    Verifies that `_analyze_column_bindings` automatically retries the metrics
    query using `fallback_metrics_query` when the primary `INFORMATION_SCHEMA`
    query fails with an error mentioning `data_policies`, skips the unsupported
    `data_policy_bindings_query`, and still completes Policy Tag and DGT binding
    queries.
    """
    # Arrange: Configure the primary metrics query job to raise `BadRequest`
    # mentioning `data_policies`, and the fallback metrics query to succeed.
    mock_primary_metrics_job = mock.create_autospec(
        bigquery.QueryJob, instance=True, spec_set=True
    )
    mock_primary_error = exceptions.BadRequest(
        "Unrecognized name: data_policies at [12:9]"
    )
    mock_primary_metrics_job.result.side_effect = mock_primary_error

    mock_fallback_metrics_job = mock.create_autospec(
        bigquery.QueryJob, instance=True, spec_set=True
    )
    mock_fallback_row = bigquery.Row(
        (50, 400, 5, 20, 3, 10, 0, 0, 7, 25),
        {
            "total_tables": 0,
            "total_columns": 1,
            "tables_with_policy_tags": 2,
            "columns_with_policy_tags": 3,
            "tables_with_dg_tags": 4,
            "columns_with_dg_tags": 5,
            "tables_with_data_policies": 6,
            "columns_with_data_policies": 7,
            "tables_with_any_cls": 8,
            "columns_with_any_cls": 9,
        },
    )
    mock_fallback_metrics_job.result.return_value = [mock_fallback_row]

    mock_policy_tag_job = mock.create_autospec(
        bigquery.QueryJob, instance=True, spec_set=True
    )
    mock_policy_tag_job.result.return_value = []
    mock_dgt_job = mock.create_autospec(
        bigquery.QueryJob, instance=True, spec_set=True
    )
    mock_dgt_job.result.return_value = []

    self.mock_bq_client.query.side_effect = [
        mock_primary_metrics_job,
        mock_fallback_metrics_job,
        mock_policy_tag_job,
        mock_dgt_job,
    ]

    # Act: Run `_analyze_column_bindings`.
    result = self.analyzer._analyze_column_bindings("my-data-project", "us")

    # Assert: 4 queries were issued (primary metrics + fallback metrics + 2
    # supported binding queries, skipping `data_policy_bindings_query`) and
    # fallback metrics were populated cleanly.
    self.assertEqual(self.mock_bq_client.query.call_count, 4)
    self.assertEqual(result.metrics.total_tables_scanned, 50)
    self.assertEqual(result.metrics.tables_with_policy_tags, 5)
    self.assertEqual(result.metrics.tables_with_dg_tags, 3)
    self.assertEqual(result.metrics.tables_with_column_data_policies, 0)
    self.assertEqual(result.metrics.tables_with_any_cls, 7)

  def test_analyze_column_bindings_with_execution_project(self):
    """Scenario: Route BigQuery `INFORMATION_SCHEMA` jobs to billing project.

    Verifies that `_analyze_column_bindings` submits all 4 BigQuery query jobs
    under `self._execution_project` while still reading `INFORMATION_SCHEMA`
    from the target `my-data-project`.
    """
    # Arrange: Set `_execution_project` and mock empty query results.
    self.analyzer._execution_project = "my-billing-project"

    mock_metrics_job = mock.create_autospec(
        bigquery.QueryJob, instance=True, spec_set=True
    )
    mock_policy_tag_job = mock.create_autospec(
        bigquery.QueryJob, instance=True, spec_set=True
    )
    mock_dgt_job = mock.create_autospec(
        bigquery.QueryJob, instance=True, spec_set=True
    )
    mock_data_policy_job = mock.create_autospec(
        bigquery.QueryJob, instance=True, spec_set=True
    )
    self.mock_bq_client.query.side_effect = [
        mock_metrics_job,
        mock_policy_tag_job,
        mock_dgt_job,
        mock_data_policy_job,
    ]

    mock_metrics_job.result.return_value = []
    mock_policy_tag_job.result.return_value = []
    mock_dgt_job.result.return_value = []
    mock_data_policy_job.result.return_value = []

    # Act: Run `_analyze_column_bindings`.
    with mock.patch.object(
        self.analyzer, "_get_project_id", return_value="my-taxonomy-project"
    ):
      self.analyzer._analyze_column_bindings("my-data-project", "us")

    # Assert: Every BigQuery query job is submitted under `my-billing-project`.
    self.assertEqual(self.mock_bq_client.query.call_count, 4)
    for call_args in self.mock_bq_client.query.call_args_list:
      self.assertEqual(call_args.kwargs["project"], "my-billing-project")

  def test_analyze_column_bindings_verbose(self):
    """Scenario: Populate `bound_columns` in Mode 2 with `LIMIT 1000` cap.

    Verifies that `_analyze_column_bindings(..., verbose=True)` appends bounded
    `ARRAY_AGG(... LIMIT 1000)` clauses to all 3 binding breakdown queries and
    populates `bound_columns` on each returned binding detail object.
    """
    # Arrange: Mock `QueryJob` responses containing `bound_columns_list` arrays.
    mock_metrics_job = mock.create_autospec(
        bigquery.QueryJob, instance=True, spec_set=True
    )
    mock_policy_tag_job = mock.create_autospec(
        bigquery.QueryJob, instance=True, spec_set=True
    )
    mock_dgt_job = mock.create_autospec(
        bigquery.QueryJob, instance=True, spec_set=True
    )
    mock_data_policy_job = mock.create_autospec(
        bigquery.QueryJob, instance=True, spec_set=True
    )
    self.mock_bq_client.query.side_effect = [
        mock_metrics_job,
        mock_policy_tag_job,
        mock_dgt_job,
        mock_data_policy_job,
    ]

    mock_metrics_job.result.return_value = []

    mock_policy_tag_row = bigquery.Row(
        (
            "projects/12345/locations/us/taxonomies/111/policyTags/222",
            1,
            ["ds.tbl.c1"],
        ),
        {"policy_tag": 0, "bound_columns": 1, "bound_columns_list": 2},
    )
    mock_policy_tag_job.result.return_value = [mock_policy_tag_row]

    mock_dgt_row = bigquery.Row(
        ("projects/p/tagKeys/k1", "v1", 1, ["ds.tbl.c2"]),
        {
            "dg_tag_key": 0,
            "dg_tag_value": 1,
            "bound_columns": 2,
            "bound_columns_list": 3,
        },
    )
    mock_dgt_job.result.return_value = [mock_dgt_row]

    mock_data_policy_row = bigquery.Row(
        ("projects/p/locations/us/dataPolicies/dp1", 1, ["ds.tbl.c3"]),
        {
            "data_policy_name": 0,
            "bound_columns": 1,
            "bound_columns_list": 2,
        },
    )
    mock_data_policy_job.result.return_value = [mock_data_policy_row]

    # Act: Run `_analyze_column_bindings` with `verbose=True`.
    with mock.patch.object(
        self.analyzer, "_get_project_id", return_value="my-taxonomy-project"
    ):
      result = self.analyzer._analyze_column_bindings(
          "my-data-project", "us", verbose=True
      )

    # Assert: `bound_columns` lists are populated and SQL uses `LIMIT 1000`.
    self.assertEqual(self.mock_bq_client.query.call_count, 4)
    for query_call in self.mock_bq_client.query.call_args_list[1:]:
      self.assertIn("LIMIT 1000", query_call.args[0])
    policy_tag_bindings = result.bindings_by_taxonomy_project[
        "my-taxonomy-project"
    ]
    self.assertEqual(policy_tag_bindings[0].bound_columns, ["ds.tbl.c1"])
    dgt_bindings = result.bindings_by_tag_key["projects/p/tagKeys/k1"]
    self.assertEqual(dgt_bindings[0].bound_columns, ["ds.tbl.c2"])
    self.assertEqual(
        result.column_data_policy_bindings[0].bound_columns, ["ds.tbl.c3"]
    )

  def test_generate_column_binding_report(self):
    """Scenario: Render Mode 2 ASCII report with all 3 CLS binding sections.

    Verifies that `generate_column_binding_report` formats summary counts,
    coverage percentages, and all three binding sections
    (`[1. POLICY TAG BINDINGS]`, `[2. DATA GOVERNANCE TAG BINDINGS]`, and
    `[3. DATA POLICIES ON COLUMN]`).
    """
    # Arrange: Build a populated `ColumnBindingAnalysisResult`.
    result = analyzer.ColumnBindingAnalysisResult(
        project_id="my-data-project",
        location="us",
        metrics=analyzer.ColumnBindingMetrics(
            total_tables_scanned=150,
            tables_with_policy_tags=12,
            total_columns_scanned=1200,
            columns_with_policy_tags=45,
            active_policy_tags_bound=2,
            tables_with_dg_tags=8,
            columns_with_dg_tags=24,
            active_dg_tags_bound=1,
            tables_with_column_data_policies=2,
            columns_with_column_data_policies=5,
            active_column_data_policies_bound=1,
            tables_with_any_cls=15,
            columns_with_any_cls=55,
        ),
        bindings_by_taxonomy_project={
            "my-taxonomy-project": [
                analyzer.PolicyTagBindingDetails(
                    policy_tag_name=(
                        "projects/my-taxonomy-project/locations/us/taxonomies/"
                        "111/policyTags/222"
                    ),
                    bound_columns_count=15,
                ),
                analyzer.PolicyTagBindingDetails(
                    policy_tag_name=(
                        "projects/my-taxonomy-project/locations/us/taxonomies/"
                        "111/policyTags/333"
                    ),
                    bound_columns_count=15,
                ),
            ]
        },
        bindings_by_tag_key={
            "my-project/my-key": [
                analyzer.DGTagBindingDetails(
                    dg_tag_key="my-project/my-key",
                    dg_tag_value="my-val",
                    bound_columns_count=20,
                    bound_columns=["dataset.table.col_a"],
                )
            ]
        },
        column_data_policy_bindings=[
            analyzer.ColumnDataPolicyBindingDetails(
                data_policy_name="projects/p/locations/us/dataPolicies/dp_mask",
                bound_columns_count=5,
                data_policy_id="dp_mask",
                bound_columns=["dataset.table.col_b"],
            )
        ],
    )

    # Act: Generate the column binding report.
    report = self.analyzer.generate_column_binding_report([result])

    # Assert: Summary counts, percentages, and tree breakdowns match,
    # wrapped in a Markdown report with a fenced `text` code block.
    self.assertTrue(
        report.startswith(
            "# Column-Level Security (CLS) Binding Analysis Report\n"
        )
    )
    self.assertIn("```text\n", report)
    self.assertTrue(report.endswith("\n```"))
    self.assertIn("COLUMN BINDING ANALYSIS", report)
    self.assertIn("Project ID: my-data-project", report)
    self.assertIn("Total Tables Scanned:        150", report)
    self.assertIn("Tables with Policy Tags:     12  (8.0%)", report)
    self.assertIn("Total Columns/Fields:        1200", report)
    self.assertIn("Columns with Policy Tags:    45  (3.8%)", report)
    self.assertIn(
        "Active Policy Tags Bound:    2 (distinct tags in use)", report
    )
    self.assertIn("Tables with DG Tags:         8  (5.3%)", report)
    self.assertIn("Columns with DG Tags:        24  (2.0%)", report)
    self.assertIn(
        "Active DG Tags Bound:        1 (distinct tags in use)", report
    )
    self.assertIn("Tables with Data Policies:   2  (1.3%)", report)
    self.assertIn("Columns with Data Policies:  5  (0.4%)", report)
    self.assertIn(
        "Active Data Policies Bound:  1 (distinct policies in use)", report
    )
    self.assertIn("Tables with Any CLS:         15  (10.0%)", report)
    self.assertIn("Columns with Any CLS:        55  (4.6%)", report)

    self.assertIn("[1. POLICY TAG BINDINGS]", report)
    self.assertIn('> Taxonomy Project: "my-taxonomy-project" (Active)', report)
    self.assertIn(
        "├── Policy Tag: projects/my-taxonomy-project/locations/us/taxonomies/"
        "111/policyTags/222",
        report,
    )
    self.assertIn("└── Bound Columns: 15", report)

    self.assertIn("[2. DATA GOVERNANCE TAG BINDINGS]", report)
    self.assertIn('> Tag Key: "my-project/my-key"', report)
    self.assertIn('Tag Value: "my-val"', report)
    self.assertIn("Bound Columns: 20", report)

    self.assertIn("[3. DATA POLICIES ON COLUMN]", report)
    self.assertIn('Data Policy: "dp_mask"', report)
    self.assertIn("Bound Columns: 5", report)

  def test_generate_column_binding_report_zero_values(self):
    """Scenario: Render Mode 2 report for an empty region without divide-by-0.

    Verifies that `generate_column_binding_report` renders `[NOTE]: No tables
    found in this project in this region.` when `total_tables_scanned == 0`.
    """
    # Arrange: Build an empty `ColumnBindingAnalysisResult`.
    result = analyzer.ColumnBindingAnalysisResult(
        project_id="my-data-project",
        location="us",
        metrics=analyzer.ColumnBindingMetrics(
            total_tables_scanned=0,
            tables_with_policy_tags=0,
            total_columns_scanned=0,
            columns_with_policy_tags=0,
            active_policy_tags_bound=0,
        ),
        bindings_by_taxonomy_project={},
    )

    # Act: Generate the report.
    report = self.analyzer.generate_column_binding_report([result])

    # Assert: The empty-region note is rendered cleanly.
    self.assertIn(
        "[NOTE]: No tables found in this project in this region.", report
    )

  def test_analyze_static_taxonomies_batch(self):
    """Scenario: Isolate per-region failures in `analyze_static_taxonomies`.

    Verifies that `analyze_static_taxonomies` continues scanning remaining
    regions when one region raises `PermissionDenied`, storing the error in
    `StaticTaxonomyAnalysisResult.error`.
    """
    # Arrange: Configure `us` to succeed and `eu` to raise `PermissionDenied`.
    with mock.patch.object(
        self.analyzer, "_analyze_static_taxonomy", autospec=True, spec_set=True
    ) as mock_single:
      mock_single.side_effect = [
          [analyzer.TaxonomyInfo("tax1", "Tax 1", "us")],
          analyzer.exceptions.PermissionDenied("Denied"),
      ]

      # Act: Run batch static taxonomy analysis across `us` and `eu`.
      results = self.analyzer.analyze_static_taxonomies("p1", ["us", "eu"])

      # Assert: Both regions are returned with `eu` recording the error string.
      self.assertEqual(len(results), 2)
      self.assertEqual(results[0].project_id, "p1")
      self.assertEqual(results[0].location, "us")
      self.assertEqual(len(results[0].taxonomies), 1)

      self.assertEqual(results[1].project_id, "p1")
      self.assertEqual(results[1].location, "eu")
      self.assertIn("Denied", results[1].error)

  def test_analyze_column_bindings_batch(self):
    """Scenario: Isolate per-region failures in `analyze_column_bindings`.

    Verifies that `analyze_column_bindings` continues scanning remaining regions
    when one region raises `PermissionDenied`, storing the error in
    `ColumnBindingAnalysisResult.error`.
    """
    # Arrange: Configure `us` to succeed and `eu` to raise `PermissionDenied`.
    with mock.patch.object(
        self.analyzer, "_analyze_column_bindings", autospec=True, spec_set=True
    ) as mock_single:
      mock_single.side_effect = [
          analyzer.ColumnBindingAnalysisResult("p1", "us"),
          analyzer.exceptions.PermissionDenied("Denied"),
      ]

      # Act: Run batch column binding analysis across `us` and `eu`.
      results = self.analyzer.analyze_column_bindings("p1", ["us", "eu"])

      # Assert: Both regions are returned with `eu` recording the error string.
      self.assertEqual(len(results), 2)
      self.assertEqual(results[0].project_id, "p1")
      self.assertEqual(results[0].location, "us")

      self.assertEqual(results[1].project_id, "p1")
      self.assertEqual(results[1].location, "eu")
      self.assertIn("Denied", results[1].error)

  # === Section 5: Mode 3 (`static-dgt`) & REST Fallback Unit Tests ===

  def test_list_tag_values_recursive(self):
    """Scenario: Reconstruct Tag Value hierarchy in memory from 1 RPC.

    Verifies that `_list_tag_values_recursive` issues a single
    `list_tag_values(parent="tagKeys/1")` RPC and reconstructs the multi-level
    parent-child tree in memory ($O(K)$ RPCs instead of $O(V)$ recursive RPCs).
    """
    # Arrange: Configure `list_tag_values` to return root and descendant values
    # in a single flat response for `parent="tagKeys/1"`.
    tag_value_1 = FakeTagValue(
        name="tagValues/11",
        short_name="val1",
        namespaced_name="proj/key1/val1",
        parent="tagKeys/1",
    )
    tag_value_2 = FakeTagValue(
        name="tagValues/12",
        short_name="val2",
        namespaced_name="proj/key1/val2",
        parent="tagKeys/1",
    )
    child1 = FakeTagValue(
        name="tagValues/111",
        short_name="child1",
        namespaced_name="proj/key1/val1/child1",
        parent="tagValues/11",
    )

    self.mock_dg_tag_values_client.list_tag_values.return_value = [
        tag_value_1,
        tag_value_2,
        child1,
    ]

    # Act: Fetch the tag value hierarchy for `tagKeys/1`.
    values = self.analyzer._list_tag_values_recursive("tagKeys/1")

    # Assert: Only 1 RPC was issued and `child1` is nested under `val1`.
    self.mock_dg_tag_values_client.list_tag_values.assert_called_once_with(
        parent="tagKeys/1", retry=analyzer.RETRY_CONFIG
    )
    self.assertEqual(len(values), 2)
    self.assertEqual(values[0].short_name, "val1")
    self.assertEqual(len(values[0].child_values), 1)
    self.assertEqual(values[0].child_values[0].short_name, "child1")
    self.assertEqual(values[1].short_name, "val2")
    self.assertEqual(len(values[1].child_values), 0)

  def test_analyze_static_dgt_success(self):
    """Scenario: Filter `DATA_GOVERNANCE` Tag Keys and attach V2 Data Policies.

    Verifies that `analyze_static_dgt` filters out non-governance Tag Keys
    (`purpose != DATA_GOVERNANCE`) and attaches key-level, value-level, and
    unattached V2 Data Policies accurately.
    """
    # Arrange: Configure 3 tag keys (only `key1` has `DATA_GOVERNANCE` purpose),
    # 1 tag value, and 3 V2 Data Policies.
    key1 = FakeTagKey(
        name="tagKeys/1",
        short_name="security_tags",
        namespaced_name="my-proj/security_tags",
        purpose=2,
    )
    key2 = FakeTagKey(
        name="tagKeys/2",
        short_name="cost_center",
        namespaced_name="my-proj/cost_center",
        purpose="OTHER",
    )
    key3 = FakeTagKey(
        name="tagKeys/3",
        short_name="firewall_key",
        namespaced_name="my-proj/firewall_key",
        purpose=1,
    )
    self.mock_dg_tag_keys_client.list_tag_keys.return_value = [
        key1,
        key2,
        key3,
    ]

    tag_value_1 = FakeTagValue(
        name="tagValues/11",
        short_name="pii",
        namespaced_name="my-proj/security_tags/pii",
        parent="tagKeys/1",
    )
    self.mock_dg_tag_values_client.list_tag_values.return_value = [tag_value_1]

    policy1 = FakeDataPolicyV2(
        name="projects/my-proj/locations/us/dataPolicies/dp_raw",
        data_policy_type=2,
        data_governance_tag=FakeDataGovernanceTag(
            key="my-proj/security_tags", value="pii"
        ),
        grantees=["user:alice@example.com"],
    )
    policy2 = FakeDataPolicyV2(
        name="projects/my-proj/locations/us/dataPolicies/dp_key_level",
        data_policy_type=1,
        data_masking_policy=FakeDataMaskingPolicy(
            predefined_expression="SHA256"
        ),
        data_governance_tag=FakeDataGovernanceTag(
            key="my-proj/security_tags", value=None
        ),
        grantees=["group:security@example.com"],
    )
    policy3 = FakeDataPolicyV2(
        name="projects/my-proj/locations/us/dataPolicies/dp_unattached",
        data_policy_type=2,
        data_governance_tag=FakeDataGovernanceTag(
            key="other-proj/unknown_key", value="val"
        ),
        grantees=["user:bob@example.com"],
    )
    self.mock_data_policy_v2_client.list_data_policies.return_value = [
        policy1,
        policy2,
        policy3,
    ]

    # Act: Run `analyze_static_dgt` for `my-proj` in `us`.
    results = self.analyzer.analyze_static_dgt(["my-proj"], ["us"])

    # Assert: `key1` has `policy2` at key level, `tag_value_1` has `policy1`,
    # and `policy3` is classified as unattached.
    self.assertEqual(len(results), 1)
    result = results[0]
    self.assertEqual(result.project_id, "my-proj")
    self.assertEqual(result.location, "us")
    self.assertEqual(len(result.tag_keys), 1)

    tag_key = result.tag_keys[0]
    self.assertEqual(tag_key.short_name, "security_tags")
    self.assertEqual(tag_key.purpose, "DATA_GOVERNANCE")
    self.assertEqual(len(tag_key.tag_values), 1)
    self.assertEqual(len(tag_key.data_policies), 1)
    self.assertEqual(tag_key.data_policies[0].data_policy_id, "dp_key_level")
    self.assertEqual(tag_key.data_policies[0].masking_rule, "SHA256")

    tag_value = tag_key.tag_values[0]
    self.assertEqual(tag_value.short_name, "pii")
    self.assertEqual(len(tag_value.data_policies), 1)
    self.assertEqual(tag_value.data_policies[0].data_policy_id, "dp_raw")
    self.assertEqual(
        tag_value.data_policies[0].grantees, ["user:alice@example.com"]
    )

    self.assertEqual(len(result.unattached_data_policies), 1)
    self.assertEqual(
        result.unattached_data_policies[0].data_policy_id, "dp_unattached"
    )

  def test_analyze_static_dgt_hydrates_default_deny_and_isolates_cross_project(
      self,
  ):
    """Scenario: Hydrate `*_default_deny` grantees and isolate cross-project.

    Verifies that `_analyze_static_dgt`:
    1. Hydrates `grantees` via `_fetch_v2_data_policy_grantees` for
       `*_default_deny` seatbelt policies so out-of-band grantee tampering is
       surfaced in `static-dgt` audits.
    2. Does not mis-attach a V2 Data Policy referencing a cross-project Tag Key
       with the same `short_name` (`other-proj/security_tags`) to a local Tag
       Key (`my-proj/security_tags`).
    """
    # Configure local key `my-proj/security_tags`, a local `_default_deny`
    # policy with empty list-response grantees, and a cross-project policy.
    key1 = FakeTagKey(
        name="tagKeys/1",
        short_name="security_tags",
        namespaced_name="my-proj/security_tags",
        purpose=2,
    )
    self.mock_dg_tag_keys_client.list_tag_keys.return_value = [key1]
    tag_value_1 = FakeTagValue(
        name="tagValues/11",
        short_name="pii",
        namespaced_name="my-proj/security_tags/pii",
        parent="tagKeys/1",
    )
    self.mock_dg_tag_values_client.list_tag_values.return_value = [tag_value_1]

    default_deny_name = (
        "projects/my-proj/locations/us/dataPolicies/"
        "migrated_raw_security_tags_pii_default_deny"
    )
    default_deny_policy = FakeDataPolicyV2(
        name=default_deny_name,
        data_policy_id="migrated_raw_security_tags_pii_default_deny",
        data_policy_type=2,
        data_governance_tag=FakeDataGovernanceTag(
            key="my-proj/security_tags", value="pii"
        ),
        grantees=[],
    )
    cross_project_policy = FakeDataPolicyV2(
        name="projects/my-proj/locations/us/dataPolicies/dp_cross_proj",
        data_policy_id="dp_cross_proj",
        data_policy_type=2,
        data_governance_tag=FakeDataGovernanceTag(
            key="other-proj/security_tags", value="pii"
        ),
        grantees=["user:bob@example.com"],
    )
    self.mock_data_policy_v2_client.list_data_policies.return_value = [
        default_deny_policy,
        cross_project_policy,
    ]

    # Spy on `_fetch_v2_data_policy_grantees` returning an unexpected drifted
    # grantee on the `_default_deny` policy.
    with mock.patch.object(
        self.analyzer,
        "_fetch_v2_data_policy_grantees",
        autospec=True,
        spec_set=True,
        return_value={default_deny_name: ["user:tampered@example.com"]},
    ) as mock_fetch_grantees:
      results = self.analyzer.analyze_static_dgt(["my-proj"], ["us"])

    # Confirm `_default_deny` is hydrated and `cross_project_policy` stays in
    # `unattached_data_policies` rather than matching `my-proj/security_tags`.
    mock_fetch_grantees.assert_called_once_with(
        "my-proj",
        "us",
        [default_deny_name],
        warnings_by_policy=mock.ANY,
    )
    self.assertEqual(len(results), 1)
    result = results[0]
    tag_value = result.tag_keys[0].tag_values[0]
    self.assertEqual(len(tag_value.data_policies), 1)
    self.assertEqual(
        tag_value.data_policies[0].data_policy_id,
        "migrated_raw_security_tags_pii_default_deny",
    )
    self.assertEqual(
        tag_value.data_policies[0].grantees,
        ["user:tampered@example.com"],
    )
    self.assertEqual(len(result.unattached_data_policies), 1)
    self.assertEqual(
        result.unattached_data_policies[0].data_policy_id, "dp_cross_proj"
    )

  def test_analyze_static_dgt_empty_and_error(self):
    """Scenario: Handle empty Tag Key lists and `PermissionDenied` in Mode 3.

    Verifies that `analyze_static_dgt` returns an empty `tag_keys` list when a
    project has no Tag Keys and captures `PermissionDenied` into
    `StaticDgtAnalysisResult.error` without crashing.
    """
    # Arrange: First return empty lists, then raise `PermissionDenied`.
    self.mock_dg_tag_keys_client.list_tag_keys.return_value = []
    self.mock_data_policy_v2_client.list_data_policies.return_value = []

    # Act & Assert (Empty): Returns 0 `tag_keys` and no error.
    results = self.analyzer.analyze_static_dgt(["my-proj"], ["us"])
    self.assertEqual(len(results), 1)
    self.assertEqual(len(results[0].tag_keys), 0)
    self.assertIsNone(results[0].error)

    # Act & Assert (Error): Captures `PermissionDenied` in `result.error`.
    self.mock_dg_tag_keys_client.list_tag_keys.side_effect = (
        analyzer.exceptions.PermissionDenied("Permission Denied")
    )
    results = self.analyzer.analyze_static_dgt(["my-proj"], ["us"])
    self.assertEqual(len(results), 1)
    self.assertIn("Permission Denied", results[0].error)

  def test_analyze_static_dgt_rest_fallback(self):
    """Scenario: Fallback to REST `/v2/` when GAPIC drops `data_governance_tag`.

    Verifies that `_analyze_static_dgt` invokes `_list_data_policies_v2_rest`
    when GAPIC `list_data_policies` returns V2 policies with
    `data_governance_tag=None` (due to stale client proto descriptors), attaches
    DGT-backed policies, and ignores legacy V1 `policyTag` policies.
    """
    # Arrange: Configure GAPIC `list_data_policies` to return a policy with
    # `data_governance_tag=None` and mock `_list_data_policies_v2_rest`.
    key1 = FakeTagKey(
        name="tagKeys/1",
        short_name="security_tags",
        namespaced_name="my-proj/security_tags",
        purpose=2,
    )
    self.mock_dg_tag_keys_client.list_tag_keys.return_value = [key1]
    tag_value_1 = FakeTagValue(
        name="tagValues/11",
        short_name="pii",
        namespaced_name="my-proj/security_tags/pii",
        parent="tagKeys/1",
    )
    self.mock_dg_tag_values_client.list_tag_values.return_value = [tag_value_1]

    gapic_policy = FakeDataPolicyV2(
        name="projects/my-proj/locations/us/dataPolicies/dp_rest",
        data_policy_type=2,
        data_governance_tag=None,
    )
    self.mock_data_policy_v2_client.list_data_policies.return_value = [
        gapic_policy
    ]

    rest_policy = {
        "name": "projects/my-proj/locations/us/dataPolicies/dp_rest",
        "dataPolicyType": "RAW_DATA_ACCESS_POLICY",
        "dataGovernanceTag": {
            "key": "my-proj/security_tags",
            "value": "pii",
        },
        "grantees": ["user:alice@example.com"],
    }
    legacy_v1_policy = {
        "name": "projects/my-proj/locations/us/dataPolicies/dp_v1",
        "dataPolicyType": "DATA_MASKING_POLICY",
        "policyTag": "projects/my-proj/locations/us/taxonomies/1/policyTags/2",
    }

    # Act: Run `analyze_static_dgt` with the REST fallback patched.
    with mock.patch.object(
        self.analyzer,
        "_list_data_policies_v2_rest",
        return_value=[rest_policy, legacy_v1_policy],
    ) as mock_rest_call:
      results = self.analyzer.analyze_static_dgt(["my-proj"], ["us"])
      mock_rest_call.assert_called_once_with("my-proj", "us")

    # Assert: `rest_policy` is attached to `tag_value_1` and `legacy_v1_policy`
    # is ignored (not placed in `unattached_data_policies`).
    self.assertEqual(len(results), 1)
    tag_key = results[0].tag_keys[0]
    self.assertEqual(len(tag_key.tag_values), 1)
    tag_value = tag_key.tag_values[0]
    self.assertEqual(len(tag_value.data_policies), 1)
    self.assertEqual(tag_value.data_policies[0].data_policy_id, "dp_rest")
    self.assertEqual(len(results[0].unattached_data_policies), 0)

  @mock.patch("time.sleep", autospec=True)
  @mock.patch("urllib.request.urlopen", autospec=True)
  def test_urlopen_json_with_retry_transient_http_error(
      self, mock_urlopen, mock_sleep
  ):
    """Scenario: Retry transient HTTP 429/503 errors with exponential backoff.

    Verifies that `_urlopen_json_with_retry` retries transient HTTP 429 and 503
    errors before succeeding on the 3rd attempt, and immediately raises
    non-transient HTTP 404 errors without sleeping.
    """
    # Arrange: Configure `urlopen` to fail with HTTP 429, then HTTP 503, then
    # return valid JSON on the 3rd attempt.
    mock_response = mock.create_autospec(
        FakeHttpResponse, instance=True, spec_set=True
    )
    mock_response.read.return_value = b'{"grantees": ["user:ok@example.com"]}'
    mock_context = contextlib.nullcontext(mock_response)

    http_429 = urllib.error.HTTPError(
        url="https://example.com",
        code=429,
        msg="Too Many Requests",
        hdrs=None,
        fp=None,
    )
    http_503 = urllib.error.HTTPError(
        url="https://example.com",
        code=503,
        msg="Service Unavailable",
        hdrs=None,
        fp=None,
    )
    mock_urlopen.side_effect = [http_429, http_503, mock_context]

    # Act: Call `_urlopen_json_with_retry`.
    request = analyzer.urllib.request.Request("https://example.com")
    payload = self.analyzer._urlopen_json_with_retry(request)

    # Assert: Succeeded on attempt 3 after 2 exponential backoff sleeps; a
    # non-retryable HTTP 404 fails immediately without additional sleeps.
    self.assertEqual(payload, {"grantees": ["user:ok@example.com"]})
    self.assertEqual(mock_urlopen.call_count, 3)
    self.assertEqual(mock_sleep.call_count, 2)

    http_404 = urllib.error.HTTPError(
        url="https://example.com",
        code=404,
        msg="Not Found",
        hdrs=None,
        fp=None,
    )
    mock_urlopen.side_effect = [http_404]
    with self.assertRaises(urllib.error.HTTPError):
      self.analyzer._urlopen_json_with_retry(request)
    self.assertEqual(mock_sleep.call_count, 2)

  @mock.patch("google.auth.default", autospec=True)
  @mock.patch("urllib.request.urlopen", autospec=True)
  def test_list_data_policies_v2_rest(self, mock_urlopen, mock_auth_default):
    """Scenario: Authenticate with ADC and list V2 Data Policies via REST.

    Verifies that `_list_data_policies_v2_rest` obtains a Bearer token via
    `google.auth.default` and parses the `dataPolicies` array from the `/v2/`
    REST JSON response.
    """
    # Arrange: Mock `google.auth.default` credentials and
    # `urllib.request.urlopen`.
    mock_credentials = mock.create_autospec(
        FakeCredentials, instance=True, spec_set=True
    )
    mock_credentials.token = "fake-token"
    mock_auth_default.return_value = (mock_credentials, "my-proj")

    mock_response = mock.create_autospec(
        FakeHttpResponse, instance=True, spec_set=True
    )
    mock_response.read.return_value = json.dumps({
        "dataPolicies": [
            {
                "name": "projects/my-proj/locations/us/dataPolicies/dp_raw",
                "dataPolicyType": "RAW_DATA_ACCESS_POLICY",
                "dataGovernanceTag": {
                    "key": "my-proj/security_tags",
                    "value": "pii",
                },
                "grantees": ["user:alice@example.com"],
            },
            {
                "name": "projects/my-proj/locations/us/dataPolicies/dp_v1",
                "dataPolicyType": "DATA_MASKING_POLICY",
                "policyTag": (
                    "projects/my-proj/locations/us/taxonomies/1/policyTags/2"
                ),
            },
        ]
    }).encode("utf-8")
    mock_urlopen.return_value.__enter__.return_value = mock_response

    # Act: Call `_list_data_policies_v2_rest`.
    policies = self.analyzer._list_data_policies_v2_rest("my-proj", "us")

    # Assert: Both policy dictionaries are returned with intact fields.
    self.assertEqual(len(policies), 2)
    self.assertEqual(
        policies[0]["name"],
        "projects/my-proj/locations/us/dataPolicies/dp_raw",
    )
    self.assertEqual(
        policies[0]["dataGovernanceTag"]["key"], "my-proj/security_tags"
    )
    self.assertEqual(policies[0]["dataGovernanceTag"]["value"], "pii")
    self.assertEqual(policies[0]["grantees"], ["user:alice@example.com"])

  @mock.patch("google.auth.default", autospec=True)
  @mock.patch("urllib.request.urlopen", autospec=True)
  def test_fetch_v2_data_policy_grantees(self, mock_urlopen, mock_auth_default):
    """Scenario: Hydrate V2 Data Policy `grantees` via concurrent REST GETs.

    Verifies that `_fetch_v2_data_policy_grantees` queries `GET /v2/{name}` and
    returns a dictionary mapping each policy resource name to its `grantees`.
    """
    # Arrange: Mock ADC credentials and HTTP GET response containing `grantees`.
    mock_credentials = mock.create_autospec(
        FakeCredentials, instance=True, spec_set=True
    )
    mock_credentials.token = "fake-token"
    mock_auth_default.return_value = (mock_credentials, "my-proj")

    mock_response = mock.create_autospec(
        FakeHttpResponse, instance=True, spec_set=True
    )
    mock_response.read.return_value = json.dumps(
        {"grantees": ["user:alice@example.com"]}
    ).encode("utf-8")
    mock_urlopen.return_value.__enter__.return_value = mock_response

    # Act: Fetch grantees for `dp_raw`.
    policy_name = "projects/my-proj/locations/us/dataPolicies/dp_raw"
    grantees_map = self.analyzer._fetch_v2_data_policy_grantees(
        "my-proj", "us", [policy_name]
    )

    # Assert: The returned map associates `policy_name` with its grantees list.
    self.assertIn(policy_name, grantees_map)
    self.assertEqual(grantees_map[policy_name], ["user:alice@example.com"])

  @mock.patch("google.auth.default", autospec=True)
  @mock.patch("urllib.request.urlopen", autospec=True)
  def test_fetch_v2_data_policy_grantees_failure_warning_and_report(
      self, mock_urlopen, mock_auth_default
  ):
    """Scenario: Surface REST grantee hydration failures in Mode 3 warnings.

    Verifies that REST errors during `_fetch_v2_data_policy_grantees` are
    captured in `DataPolicyV2Info.warnings` (both in single-policy mode and
    batch mode) and rendered in the `WARNINGS` section of
    `generate_static_dgt_report`.
    """
    # Arrange 1: Configure `urlopen` to raise `RuntimeError`.
    mock_credentials = mock.create_autospec(
        FakeCredentials, instance=True, spec_set=True
    )
    mock_credentials.token = "fake-token"
    mock_auth_default.return_value = (mock_credentials, "my-proj")
    mock_urlopen.side_effect = RuntimeError("REST connection error")

    # Act 1: Call `_fetch_v2_data_policy_grantees` directly in single-policy
    # mode.
    policy_name = "projects/my-proj/locations/us/dataPolicies/dp_raw"
    single_warnings: list[str] = []
    single_grantees = self.analyzer._fetch_v2_data_policy_grantees(
        policy_name, single_warnings
    )

    # Assert 1: Empty grantees list and warning recorded.
    self.assertEqual(single_grantees, [])
    self.assertEqual(len(single_warnings), 1)
    self.assertIn(
        f"Failed to fetch V2 Data Policy grantees via REST for '{policy_name}'",
        single_warnings[0],
    )

    # Arrange 2: Configure `analyze_static_dgt` with a policy needing REST
    # grantee hydration.
    key1 = FakeTagKey(
        name="tagKeys/1",
        short_name="security_tags",
        namespaced_name="my-proj/security_tags",
        purpose=2,
    )
    self.mock_dg_tag_keys_client.list_tag_keys.return_value = [key1]
    tag_value_1 = FakeTagValue(
        name="tagValues/11",
        short_name="pii",
        namespaced_name="my-proj/security_tags/pii",
        parent="tagKeys/1",
    )
    self.mock_dg_tag_values_client.list_tag_values.return_value = [tag_value_1]
    policy1 = FakeDataPolicyV2(
        name=policy_name,
        data_policy_type=2,
        data_governance_tag=FakeDataGovernanceTag(
            key="my-proj/security_tags", value="pii"
        ),
        grantees=[],
    )
    self.mock_data_policy_v2_client.list_data_policies.return_value = [policy1]

    # Act 2: Run `analyze_static_dgt` and `generate_static_dgt_report`.
    results = self.analyzer.analyze_static_dgt(["my-proj"], ["us"])

    # Assert 2: Warning is attached to `DataPolicyV2Info` and rendered in the
    # report.
    self.assertEqual(len(results), 1)
    data_policy_v2 = results[0].tag_keys[0].tag_values[0].data_policies[0]
    self.assertEqual(len(data_policy_v2.warnings), 1)
    self.assertIn(
        f"Failed to fetch V2 Data Policy grantees via REST for '{policy_name}'",
        data_policy_v2.warnings[0],
    )

    report = self.analyzer.generate_static_dgt_report(results)
    self.assertIn("WARNINGS", report)
    self.assertIn(
        f"Failed to fetch V2 Data Policy grantees via REST for '{policy_name}'",
        report,
    )

  def test_generate_static_dgt_report(self):
    """Scenario: Render Mode 3 ASCII report for attached & unattached policies.

    Verifies that `generate_static_dgt_report` formats DG Tag Keys, key-level
    policies, recursive Tag Values, value-level policies, unattached V2 Data
    Policies, and empty project states.
    """
    # Arrange: Build a populated `StaticDgtAnalysisResult` and an empty result.
    key_info = analyzer.DGTagKeyInfo(
        name="tagKeys/1",
        short_name="security_tags",
        namespaced_name="my-proj/security_tags",
        purpose="DATA_GOVERNANCE",
        tag_values=[
            analyzer.DGTagValueInfo(
                name="tagValues/11",
                short_name="pii",
                namespaced_name="my-proj/security_tags/pii",
                data_policies=[
                    analyzer.DataPolicyV2Info(
                        name=(
                            "projects/my-proj/locations/us/dataPolicies/dp_raw"
                        ),
                        data_policy_id="dp_raw",
                        policy_type=constants.DATA_POLICY_TYPE_RAW,
                        grantees=["user:alice@example.com"],
                    )
                ],
            )
        ],
        data_policies=[
            analyzer.DataPolicyV2Info(
                name="projects/my-proj/locations/us/dataPolicies/dp_key",
                data_policy_id="dp_key",
                policy_type=constants.DATA_POLICY_TYPE_MASKING,
                masking_rule="SHA256",
                grantees=["group:sec@example.com"],
            )
        ],
    )
    unattached = analyzer.DataPolicyV2Info(
        name="projects/my-proj/locations/us/dataPolicies/dp_orphaned",
        data_policy_id="dp_orphaned",
        data_governance_tag_key="other/key",
    )
    result = analyzer.StaticDgtAnalysisResult(
        project_id="my-proj",
        location="us",
        tag_keys=[key_info],
        unattached_data_policies=[unattached],
    )

    # Act: Generate reports for populated and empty results.
    report = self.analyzer.generate_static_dgt_report([result])
    empty_result = analyzer.StaticDgtAnalysisResult(
        project_id="empty-proj", location="us"
    )
    empty_report = self.analyzer.generate_static_dgt_report([empty_result])

    # Assert: All sections and empty-state notes render accurately inside a
    # Markdown report with a fenced `text` code block.
    self.assertTrue(
        report.startswith(
            "# Static Data Governance Tag (DGT) Analysis Report\n"
        )
    )
    self.assertIn("```text\n", report)
    self.assertTrue(report.endswith("\n```"))
    self.assertIn("STATIC DGT ANALYSIS", report)
    self.assertIn('1. DG Tag Key: "security_tags" (tagKeys/1)', report)
    self.assertIn("Namespaced Name:     my-proj/security_tags", report)
    self.assertIn("Total DG Tag Values: 1", report)
    self.assertIn("Total Data Policies: 2", report)
    self.assertIn("[Key-Level Data Policies]", report)
    self.assertIn(
        '└── Data Policy: "dp_key" (Type: DATA_MASKING_POLICY, Rule: SHA256)',
        report,
    )
    self.assertIn("- group:sec@example.com", report)
    self.assertIn('> DG Tag Value: "pii" (tagValues/11)', report)
    self.assertIn(
        '└── Data Policy: "dp_raw" (Type: RAW_DATA_ACCESS_POLICY)', report
    )
    self.assertIn("- user:alice@example.com", report)
    self.assertIn("[DATA POLICIES (V2) ATTACHED TO OTHER DGT PROJECTS]", report)
    self.assertIn('> Data Policy: "dp_orphaned"', report)
    self.assertIn("└── Grantees: None", report)
    self.assertIn(
        "No Data Governance Tag keys found in this project.", empty_report
    )

  def test_analyze_static_dgt_batch(self):
    """Scenario: Isolate per-region failures in `analyze_static_dgt`.

    Verifies that `analyze_static_dgt` continues across regions when one region
    raises `PermissionDenied`, storing the error in
    `StaticDgtAnalysisResult.error`.
    """
    # Arrange: Configure `us` to succeed and `eu` to raise `PermissionDenied`.
    with mock.patch.object(
        self.analyzer, "_analyze_static_dgt", autospec=True, spec_set=True
    ) as mock_single:
      mock_single.side_effect = [
          ([analyzer.DGTagKeyInfo("tagKeys/1", "k1")], []),
          analyzer.exceptions.PermissionDenied("Denied"),
      ]

      # Act: Run `analyze_static_dgt` across `us` and `eu`.
      results = self.analyzer.analyze_static_dgt(["p1"], ["us", "eu"])

      # Assert: Both regions are returned with `eu` capturing the error.
      self.assertEqual(len(results), 2)
      self.assertEqual(results[0].project_id, "p1")
      self.assertEqual(results[0].location, "us")
      self.assertEqual(len(results[0].tag_keys), 1)
      self.assertEqual(results[1].project_id, "p1")
      self.assertEqual(results[1].location, "eu")
      self.assertIn("Denied", results[1].error)

  # Cross-project static-dgt scans fetch global DGT keys once from
  # dgt_project_id, isolate attached V2 policies per (policy_project, region),
  # place policies referencing another DGT project in unattached_data_policies,
  # and deduplicate global Tag Key totals in the Markdown report.
  def test_analyze_static_dgt_cross_project_joins_and_deduplicates_keys(self):
    """Verifies cross-project DGT discovery, policy isolation, and report."""
    # Omit namespaced_name on tag_key to exercise the
    # "{dgt_project_id}/{short_name}" fallback when matching V2 Data Policies.
    tag_key = FakeTagKey(
        name="tagKeys/1",
        short_name="security_tags",
        namespaced_name=None,
        purpose=2,
    )
    tag_value = FakeTagValue(
        name="tagValues/11",
        short_name="pii",
        namespaced_name="dgt-project/security_tags/pii",
        parent="tagKeys/1",
    )
    self.mock_dg_tag_keys_client.list_tag_keys.return_value = [tag_key]
    self.mock_dg_tag_values_client.list_tag_values.return_value = [tag_value]

    # Return distinct V2 Data Policies for policy-project-1 vs policy-project-2
    # referencing the shared global Tag Key in dgt-project, plus a policy in
    # policy-project-2 referencing a same-named Tag Key in another DGT project.
    policy_one = FakeDataPolicyV2(
        name="projects/policy-project-1/locations/us/dataPolicies/raw_one",
        data_policy_id="raw_one",
        data_policy_type=2,
        data_governance_tag=FakeDataGovernanceTag(
            key="dgt-project/security_tags", value="pii"
        ),
        grantees=["user:reader1@example.com"],
    )
    policy_two = FakeDataPolicyV2(
        name="projects/policy-project-2/locations/us/dataPolicies/raw_two",
        data_policy_id="raw_two",
        data_policy_type=2,
        data_governance_tag=FakeDataGovernanceTag(
            key="dgt-project/security_tags", value="pii"
        ),
        grantees=["user:reader2@example.com"],
    )
    policy_other_dgt_project = FakeDataPolicyV2(
        name="projects/policy-project-2/locations/us/dataPolicies/orphan_two",
        data_policy_id="orphan_two",
        data_policy_type=2,
        data_governance_tag=FakeDataGovernanceTag(
            key="other-dgt-project/security_tags", value="pii"
        ),
        grantees=["user:reader3@example.com"],
    )
    self.mock_data_policy_v2_client.list_data_policies.side_effect = [
        [policy_one],
        [policy_two, policy_other_dgt_project],
    ]

    # Execute cross-project static-dgt analysis across two policy projects.
    results = self.analyzer.analyze_static_dgt(
        "dgt-project",
        ["us"],
        data_policy_v2_project_ids=["policy-project-1", "policy-project-2"],
    )

    # Global Tag Keys/Values must be fetched once and deep-copied per section
    # so raw_one and raw_two do not bleed across policy-project-1 and 2, while
    # orphan_two (referencing other-dgt-project) stays unattached.
    self.mock_dg_tag_keys_client.list_tag_keys.assert_called_once()
    self.mock_dg_tag_values_client.list_tag_values.assert_called_once()
    self.assertEqual(len(results), 2)
    self.assertEqual(results[0].dgt_project_id, "dgt-project")
    self.assertEqual(results[0].project_id, "policy-project-1")
    first_policies = results[0].tag_keys[0].tag_values[0].data_policies
    second_policies = results[1].tag_keys[0].tag_values[0].data_policies
    self.assertEqual(
        [item.data_policy_id for item in first_policies], ["raw_one"]
    )
    self.assertEqual(
        [item.data_policy_id for item in second_policies], ["raw_two"]
    )
    self.assertEqual(
        [item.data_policy_id for item in results[1].unattached_data_policies],
        ["orphan_two"],
    )

    # Report header counts the single global Tag Key once rather than 2x and
    # renders the cross-project section banner.
    report = self.analyzer.generate_static_dgt_report(results)
    self.assertIn("Total DG Tag Keys Found: 1", report)
    self.assertIn(
        "Scan of DGT Project: dgt-project | Data Policy Project:"
        " policy-project-1 in Location: us",
        report,
    )

  # Unattached V2 Data Policies in a Data Policy project must still render when
  # the scanned DGT project currently contains zero Data Governance Tag Keys.
  def test_generate_static_dgt_report_keeps_unattached_when_tag_keys_empty(
      self,
  ):
    """Verifies unattached V2 Data Policies render when `tag_keys` is empty."""
    unattached_policy = analyzer.DataPolicyV2Info(
        name="projects/policy-project/locations/us/dataPolicies/orphan_policy",
        data_policy_id="orphan_policy",
        data_governance_tag_key="other-project/security_tags",
    )
    result = analyzer.StaticDgtAnalysisResult(
        project_id="policy-project",
        location="us",
        tag_keys=[],
        unattached_data_policies=[unattached_policy],
        dgt_project_id="empty-dgt-project",
    )

    report = self.analyzer.generate_static_dgt_report([result])

    # Confirm both the empty-key notice and the cross-project policy block
    # appear.
    self.assertIn("No Data Governance Tag keys found in this project.", report)
    self.assertIn("[DATA POLICIES (V2) ATTACHED TO OTHER DGT PROJECTS]", report)
    self.assertIn('> Data Policy: "orphan_policy"', report)

  def test_generate_column_binding_report_notifies_when_verbose_list_capped(
      self,
  ):
    """Notifies operators only when verbose column lists exceed the cap."""
    # Exact-limit (1,000 of 1,000) has zero omitted columns and must not emit a
    # false truncation notice.
    exact_limit_columns = [
        f"ds.tbl.col_{index}"
        for index in range(constants.VERBOSE_BINDINGS_LIMIT)
    ]
    exact_result = analyzer.ColumnBindingAnalysisResult(
        project_id="data-project",
        location="us",
        metrics=analyzer.ColumnBindingMetrics(
            total_tables_scanned=10,
            tables_with_policy_tags=1,
            total_columns_scanned=1000,
            columns_with_policy_tags=1000,
            active_policy_tags_bound=1,
            tables_with_any_cls=1,
            columns_with_any_cls=1000,
        ),
        bindings_by_taxonomy_project={
            "tax-project": [
                analyzer.PolicyTagBindingDetails(
                    policy_tag_name=(
                        "projects/tax-project/locations/us/"
                        "taxonomies/1/policyTags/2"
                    ),
                    bound_columns_count=1000,
                    policy_tag_display_name="Email",
                    bound_columns=exact_limit_columns,
                )
            ]
        },
    )

    # Render report at the exact 1,000 boundary and verify no truncation banner
    # or inline truncation marker appears.
    exact_report = self.analyzer.generate_column_binding_report([exact_result])
    self.assertNotIn("TRUNCATED:", exact_report)
    self.assertNotIn("capped at 1000 columns", exact_report)

    # Inject a binding with 1,250 total bound columns where `--verbose-bindings`
    # returned the first 1,000 paths (`ARRAY_AGG(... LIMIT 1000)`).
    capped_result = analyzer.ColumnBindingAnalysisResult(
        project_id="data-project",
        location="us",
        metrics=analyzer.ColumnBindingMetrics(
            total_tables_scanned=10,
            tables_with_policy_tags=1,
            total_columns_scanned=1250,
            columns_with_policy_tags=1250,
            active_policy_tags_bound=1,
            tables_with_any_cls=1,
            columns_with_any_cls=1250,
        ),
        bindings_by_taxonomy_project={
            "tax-project": [
                analyzer.PolicyTagBindingDetails(
                    policy_tag_name=(
                        "projects/tax-project/locations/us/"
                        "taxonomies/1/policyTags/2"
                    ),
                    bound_columns_count=1250,
                    policy_tag_display_name="Email",
                    bound_columns=exact_limit_columns,
                )
            ]
        },
    )

    # Render report above the 1,000 cap and verify both the top-level `[NOTE]`
    # and the inline truncation notice state exact shown/total/omitted counts.
    capped_report = self.analyzer.generate_column_binding_report(
        [capped_result]
    )
    self.assertIn("Bound Columns: 1250", capped_report)
    self.assertIn(
        "[NOTE]: One or more --verbose-bindings column lists below were capped"
        " at 1000 columns per tag/policy.",
        capped_report,
    )
    self.assertIn(
        "[TRUNCATED: showing 1000 of 1250 bound columns; 250 additional"
        " column(s) omitted due to 1000-column --verbose-bindings display cap]",
        capped_report,
    )

  # Priming the first uncached Policy Tag on the main thread before fanning out
  # remaining tags to ThreadPoolExecutor warms up Data Catalog OAuth2
  # credentials once instead of triggering concurrent oauth2.googleapis.com
  # token refreshes.
  def test_analyze_column_bindings_primes_first_tag_before_thread_pool(self):
    """Primes the first uncached Policy Tag synchronously before thread pool."""
    # Return three uncached Policy Tags from the binding query to exercise both
    # the synchronous warm-up call and the remaining-tags executor fan-out.
    mock_metrics_job = mock.create_autospec(
        bigquery.QueryJob, instance=True, spec_set=True
    )
    mock_policy_tag_job = mock.create_autospec(
        bigquery.QueryJob, instance=True, spec_set=True
    )
    mock_dgt_job = mock.create_autospec(
        bigquery.QueryJob, instance=True, spec_set=True
    )
    mock_data_policy_job = mock.create_autospec(
        bigquery.QueryJob, instance=True, spec_set=True
    )
    self.mock_bq_client.query.side_effect = [
        mock_metrics_job,
        mock_policy_tag_job,
        mock_dgt_job,
        mock_data_policy_job,
    ]
    mock_metrics_job.result.return_value = []
    tag_names = [
        "projects/tax-proj/locations/us/taxonomies/1/policyTags/101",
        "projects/tax-proj/locations/us/taxonomies/1/policyTags/102",
        "projects/tax-proj/locations/us/taxonomies/1/policyTags/103",
    ]
    mock_policy_tag_job.result.return_value = [
        bigquery.Row((tag_name, 1), {"policy_tag": 0, "bound_columns": 1})
        for tag_name in tag_names
    ]
    mock_dgt_job.result.return_value = []
    mock_data_policy_job.result.return_value = []

    call_events: list[str] = []

    def fake_get_policy_tag(request=None, **_):
      tag_name = request["name"]
      call_events.append(f"get:{tag_name}")
      return FakePolicyTag(name=tag_name, display_name=f"Display:{tag_name}")

    self.mock_dc_client.get_policy_tag.side_effect = fake_get_policy_tag

    # Wrap ThreadPoolExecutor to record when the pool is constructed relative to
    # the first get_policy_tag call and verify only the remaining 2 tags use it.
    real_executor_class = analyzer.concurrent.futures.ThreadPoolExecutor
    executor_max_workers: list[int] = []

    def tracking_executor(*args, **kwargs):
      call_events.append("executor_init")
      executor_max_workers.append(kwargs.get("max_workers", 0))
      return real_executor_class(*args, **kwargs)

    # Execute column-binding analysis and verify the first tag is fetched before
    # ThreadPoolExecutor initializes for the remaining two tags.
    with mock.patch.object(
        analyzer.concurrent.futures,
        "ThreadPoolExecutor",
        side_effect=tracking_executor,
    ):
      result = self.analyzer._analyze_column_bindings("data-proj", "us")

    # Confirm get_policy_tag for tag 101 completed before executor_init and all
    # three display names were cached and attached to the binding details.
    self.assertEqual(call_events[0], f"get:{tag_names[0]}")
    self.assertEqual(call_events[1], "executor_init")
    self.assertEqual(executor_max_workers, [2])
    bindings = result.bindings_by_taxonomy_project["tax-proj"]
    self.assertEqual(
        [item.policy_tag_display_name for item in bindings],
        [f"Display:{tag_name}" for tag_name in tag_names],
    )

  # Enabling halt_on_error stops regional loops immediately on the first failed
  # region across all three Analyzer modes so later regions are not queried.
  def test_analyze_modes_halt_on_error_stops_before_next_region(self):
    """Stops multi-region discovery immediately when `halt_on_error` is set."""
    self.analyzer._halt_on_error = True

    # Mode 1 (static-taxonomy): fail on us-bad and verify us is never scanned.
    with mock.patch.object(
        self.analyzer, "_analyze_static_taxonomy", autospec=True, spec_set=True
    ) as mock_taxonomy:
      mock_taxonomy.side_effect = [
          analyzer.exceptions.BadRequest("Unsupported location us-bad"),
          [analyzer.TaxonomyInfo("tax1", "Tax 1", "us")],
      ]
      taxonomy_results = self.analyzer.analyze_static_taxonomies(
          "p1", ["us-bad", "us"]
      )
      self.assertEqual(len(taxonomy_results), 1)
      self.assertEqual(taxonomy_results[0].location, "us-bad")
      self.assertIn("Unsupported location", taxonomy_results[0].error)
      mock_taxonomy.assert_called_once_with("p1", "us-bad")

    # Mode 2 (column-binding): fail on us-bad and verify us is never queried.
    with mock.patch.object(
        self.analyzer, "_analyze_column_bindings", autospec=True, spec_set=True
    ) as mock_bindings:
      mock_bindings.side_effect = [
          analyzer.exceptions.BadRequest("Unsupported location us-bad"),
          analyzer.ColumnBindingAnalysisResult("p1", "us"),
      ]
      binding_results = self.analyzer.analyze_column_bindings(
          "p1", ["us-bad", "us"]
      )
      self.assertEqual(len(binding_results), 1)
      self.assertEqual(binding_results[0].location, "us-bad")
      self.assertIn("Unsupported location", binding_results[0].error)
      mock_bindings.assert_called_once_with("p1", "us-bad", verbose=False)

    # Mode 3 (static-dgt): fail on us-bad across cross-project policy scan and
    # verify remaining regions/projects are skipped.
    with mock.patch.object(
        self.analyzer, "_analyze_static_dgt", autospec=True, spec_set=True
    ) as mock_dgt:
      mock_dgt.side_effect = [
          analyzer.exceptions.BadRequest("Unsupported location us-bad"),
          ([analyzer.DGTagKeyInfo("tagKeys/1", "k1")], []),
      ]
      dgt_results = self.analyzer.analyze_static_dgt(
          "dgt-proj",
          ["us-bad", "us"],
          data_policy_v2_project_ids=["dp-proj-1", "dp-proj-2"],
      )
      self.assertEqual(len(dgt_results), 1)
      self.assertEqual(dgt_results[0].location, "us-bad")
      self.assertIn("Unsupported location", dgt_results[0].error)
      mock_dgt.assert_called_once_with(
          "dgt-proj", "us-bad", data_policy_project_id="dp-proj-1"
      )

  # Classification-only taxonomies with Fine-Grained Reader bindings must flag
  # those bindings as dangling/unenforced, while taxonomies activated only via
  # attached V1 Data Policies must explicitly label implicit access control.
  def test_generate_static_taxonomy_report_dangling_fgr_and_implicit_ac(self):
    """Flags dangling Fine-Grained Readers and implicit access control."""
    # Construct a classification-only taxonomy carrying an unenforced FGR
    # binding alongside a taxonomy whose Data Catalog toggle is OFF
    # (is_explicit_access_control=False) but is promoted by a V1 Data Policy.
    class_only_taxonomy = analyzer.TaxonomyInfo(
        name="projects/p1/locations/us/taxonomies/t_class",
        display_name="mt_class_only_tax",
        location="us",
        is_access_control=False,
        is_explicit_access_control=False,
        policy_tags=[
            analyzer.PolicyTagInfo(
                name="projects/p1/locations/us/taxonomies/t_class/policyTags/1",
                display_name="Internal_Note_Tag",
                parent_policy_tag="",
                fine_grained_readers=["user:reader@example.com"],
            )
        ],
    )
    implicit_ac_taxonomy = analyzer.TaxonomyInfo(
        name="projects/p1/locations/us/taxonomies/t_implicit",
        display_name="mt_implicit_ac_tax",
        location="us",
        is_access_control=True,
        is_explicit_access_control=False,
        policy_tags=[
            analyzer.PolicyTagInfo(
                name=(
                    "projects/p1/locations/us/taxonomies/"
                    "t_implicit/policyTags/2"
                ),
                display_name="Implicit_Mask_Tag",
                parent_policy_tag="",
                data_policies=[
                    analyzer.DataPolicyInfo(
                        name="projects/p1/locations/us/dataPolicies/dp1",
                        policy_tag=(
                            "projects/p1/locations/us/taxonomies/"
                            "t_implicit/policyTags/2"
                        ),
                        policy_type="DATA_MASKING_POLICY",
                        masking_rule="DEFAULT_MASKING_VALUE",
                    )
                ],
            )
        ],
    )
    result = analyzer.StaticTaxonomyAnalysisResult(
        project_id="p1",
        location="us",
        taxonomies=[class_only_taxonomy, implicit_ac_taxonomy],
    )

    # Render the static taxonomy report for both taxonomies.
    report = self.analyzer.generate_static_taxonomy_report([result])

    # Confirm both inline annotations and bottom WARNINGS entries surface the
    # dangling FGR binding and implicit access-control state.
    self.assertIn(
        "[DANGLING - NOT ENFORCED (Enforce Access Control is OFF)]", report
    )
    self.assertIn(
        'Policy Tag "Internal_Note_Tag"'
        " (projects/p1/locations/us/taxonomies/t_class/policyTags/1) in"
        ' Classification-Only Taxonomy "mt_class_only_tax" has Fine-Grained'
        " Reader IAM bindings",
        report,
    )
    self.assertIn(
        "Enforce Access Control: ON (Implicit via attached V1 Data Policies;"
        " activated_policy_types=[] / Data Catalog toggle OFF)",
        report,
    )
    self.assertIn(
        'Taxonomy "mt_implicit_ac_tax"'
        " (projects/p1/locations/us/taxonomies/t_implicit) has empty"
        " activated_policy_types",
        report,
    )

  # Custom IAM role provenance and duplicate taxonomy display names across
  # regions must be surfaced in Mode 1 reports without altering the raw
  # fine_grained_readers list consumed by Phase 1b Planner.
  def test_generate_static_taxonomy_report_custom_roles_and_region_collision(
      self,
  ):
    """Renders custom role attribution and cross-region collision warnings."""
    # Populate custom_roles_by_principal on a Policy Tag and duplicate the
    # taxonomy display_name "mt_pii_tax" across us and eu results.
    us_taxonomy = analyzer.TaxonomyInfo(
        name="projects/p1/locations/us/taxonomies/1",
        display_name="mt_pii_tax",
        location="us",
        is_access_control=True,
        is_explicit_access_control=True,
        policy_tags=[
            analyzer.PolicyTagInfo(
                name="projects/p1/locations/us/taxonomies/1/policyTags/10",
                display_name="Contact_Mid",
                parent_policy_tag="",
                fine_grained_readers=[
                    "serviceAccount:sa@p1.iam.gserviceaccount.com"
                ],
                custom_roles_by_principal={
                    "serviceAccount:sa@p1.iam.gserviceaccount.com": [
                        "projects/p1/roles/mtCustomFineGrainedReader"
                    ]
                },
            )
        ],
    )
    eu_taxonomy = analyzer.TaxonomyInfo(
        name="projects/p1/locations/eu/taxonomies/2",
        display_name="mt_pii_tax",
        location="eu",
        is_access_control=True,
        is_explicit_access_control=True,
    )
    results = [
        analyzer.StaticTaxonomyAnalysisResult("p1", "us", [us_taxonomy]),
        analyzer.StaticTaxonomyAnalysisResult("p1", "eu", [eu_taxonomy]),
    ]

    # Render the multi-region static taxonomy report.
    report = self.analyzer.generate_static_taxonomy_report(results)

    # Verify custom role attribution, STATS collision indicator, and bottom
    # cross-region collision warning are all present.
    self.assertIn(
        "serviceAccount:sa@p1.iam.gserviceaccount.com (via custom role:"
        " projects/p1/roles/mtCustomFineGrainedReader)",
        report,
    )
    self.assertIn(
        'Global DGT Collision:   YES ("mt_pii_tax" appears in regions: us, eu;',
        report,
    )
    self.assertIn(
        'Cross-Region Taxonomy Name Collision: Taxonomy "mt_pii_tax" appears 2'
        " times across scanned regions",
        report,
    )

  # V2 Data Policy custom masking routines must resolve numeric project numbers
  # to project IDs, and direct column-level V2 policies without a DGT Tag Key
  # must label Tag Key: None (Direct Column-Level Data Policy...) in Mode 3.
  def test_analyze_and_generate_static_dgt_routine_and_direct_policy(self):
    """Resolves V2 custom routine project numbers and labels direct policies."""
    # Configure a direct column-level V2 Data Policy (no data_governance_tag)
    # whose custom masking routine uses a numeric project number.
    direct_policy = FakeDataPolicyV2(
        name="projects/my-proj/locations/us/dataPolicies/direct_cmr_policy",
        data_policy_id="direct_cmr_policy",
        data_policy_type=1,
        data_masking_policy=FakeDataMaskingPolicy(
            predefined_expression=0,
            routine="projects/593477869968/datasets/test/routines/customMask",
        ),
        data_governance_tag=FakeDataGovernanceTag(key="", value=""),
        grantees=["user:analyst@example.com"],
    )
    self.mock_dg_tag_keys_client.list_tag_keys.return_value = []
    self.mock_data_policy_v2_client.list_data_policies.return_value = [
        direct_policy
    ]

    # Run analyze_static_dgt with project number 593477869968 resolving to
    # my-proj, then generate the Mode 3 report.
    with mock.patch.object(
        self.analyzer, "_get_project_id", return_value="my-proj"
    ):
      results = self.analyzer.analyze_static_dgt(["my-proj"], ["us"])
    report = self.analyzer.generate_static_dgt_report(results)

    # Confirm the custom routine path uses my-proj.test.customMask and the
    # unattached section labels the policy as a Direct Column-Level Data Policy.
    self.assertEqual(len(results[0].unattached_data_policies), 1)
    self.assertEqual(
        results[0].unattached_data_policies[0].masking_rule,
        "Custom Routine: my-proj.test.customMask",
    )
    self.assertIn("Rule: Custom Routine: my-proj.test.customMask", report)
    self.assertIn(
        "├── Tag Key: None (Direct Column-Level Data Policy; no Data Governance"
        " Tag attached)",
        report,
    )

  # Cloud Resource Manager Tags v3 returns flat 3-segment `namespaced_name`
  # strings (`<project>/<key_short>/<value_short>`) even for nested child and
  # grandchild Tag Values; Mode 3 must reconstruct the full hierarchical path.
  def test_analyze_static_dgt_reconstructs_nested_tag_value_namespaced_paths(
      self,
  ):
    """Reconstructs hierarchical `namespaced_name` for nested DGT Tag Values."""
    # Configure a 3-level Tag Value tree whose raw `namespaced_name` fields are
    # flat 3-segment strings matching live Resource Manager v3 behavior.
    tag_key = FakeTagKey(
        name="tagKeys/100",
        short_name="mt_pii_tax",
        namespaced_name="my-proj/mt_pii_tax",
        description="PII key",
        purpose=2,
    )
    root_value = FakeTagValue(
        name="tagValues/101",
        short_name="PII_Root",
        namespaced_name="my-proj/mt_pii_tax/PII_Root",
        description="Root",
        parent="tagKeys/100",
    )
    mid_value = FakeTagValue(
        name="tagValues/102",
        short_name="Contact_Mid",
        namespaced_name="my-proj/mt_pii_tax/Contact_Mid",
        description="Mid",
        parent="tagValues/101",
    )
    leaf_value = FakeTagValue(
        name="tagValues/103",
        short_name="Email_Leaf",
        namespaced_name="my-proj/mt_pii_tax/Email_Leaf",
        description="Leaf",
        parent="tagValues/102",
    )
    leaf_policy = FakeDataPolicyV2(
        name="projects/my-proj/locations/us/dataPolicies/email_mask",
        data_policy_id="email_mask",
        data_policy_type=1,
        data_masking_policy=FakeDataMaskingPolicy(predefined_expression=1),
        data_governance_tag=FakeDataGovernanceTag(
            key="my-proj/mt_pii_tax",
            value="Email_Leaf",
        ),
        grantees=["user:reader@example.com"],
    )
    self.mock_dg_tag_keys_client.list_tag_keys.return_value = [tag_key]
    self.mock_dg_tag_values_client.list_tag_values.return_value = [
        root_value,
        mid_value,
        leaf_value,
    ]
    self.mock_data_policy_v2_client.list_data_policies.return_value = [
        leaf_policy
    ]

    # Run static-dgt analysis and render the Markdown hierarchy report.
    results = self.analyzer.analyze_static_dgt(["my-proj"], ["us"])
    report = self.analyzer.generate_static_dgt_report(results)

    # Verify nested child and grandchild nodes carry their full hierarchical
    # namespaced paths and the leaf V2 Data Policy attaches to Email_Leaf.
    parsed_root = results[0].tag_keys[0].tag_values[0]
    parsed_mid = parsed_root.child_values[0]
    parsed_leaf = parsed_mid.child_values[0]
    self.assertEqual(
        parsed_mid.namespaced_name,
        "my-proj/mt_pii_tax/PII_Root/Contact_Mid",
    )
    self.assertEqual(
        parsed_leaf.namespaced_name,
        "my-proj/mt_pii_tax/PII_Root/Contact_Mid/Email_Leaf",
    )
    self.assertEqual(len(parsed_leaf.data_policies), 1)
    self.assertIn(
        "Namespaced Name: my-proj/mt_pii_tax/PII_Root/Contact_Mid/Email_Leaf",
        report,
    )

  # Cloud IAM `GetRole` still populates `included_permissions` on `DISABLED` or
  # `deleted` custom roles; `_get_principals_with_permission` must skip them
  # with a warning on both uncached and cached lookups.
  def test_get_principals_skips_deleted_and_disabled_custom_roles(self):
    """Skips deleted and DISABLED custom roles while emitting warnings."""
    disabled_role = "projects/my-proj/roles/disabledFineGrainedReader"
    deleted_role = "projects/my-proj/roles/deletedFineGrainedReader"
    # Return real proto-plus `Role` objects with `included_permissions` set to
    # confirm inactive launch/deletion state overrides listed permissions.
    self.mock_iam_client.get_role.side_effect = [
        iam_admin_v1.Role(
            name=disabled_role,
            included_permissions=[constants.FINE_GRAINED_READER_PERMISSION],
            stage=iam_admin_v1.Role.RoleLaunchStage.DISABLED,
        ),
        iam_admin_v1.Role(
            name=deleted_role,
            included_permissions=[constants.FINE_GRAINED_READER_PERMISSION],
            deleted=True,
        ),
    ]
    policy = policy_pb2.Policy(
        bindings=[
            policy_pb2.Binding(
                role=disabled_role,
                members=["user:disabled_member@example.com"],
            ),
            policy_pb2.Binding(
                role=deleted_role,
                members=["user:deleted_member@example.com"],
            ),
            policy_pb2.Binding(
                role=constants.FINE_GRAINED_READER_ROLE,
                members=["user:active_member@example.com"],
            ),
        ]
    )
    first_warnings: list[str] = []
    custom_roles_by_principal: dict[str, list[str]] = {}

    # Evaluate bindings once (slow path) and a second time (cached fast path).
    principals = self.analyzer._get_principals_with_permission(
        policy,
        constants.FINE_GRAINED_READER_PERMISSION,
        first_warnings,
        custom_roles_by_principal,
    )
    second_warnings: list[str] = []
    cached_principals = self.analyzer._get_principals_with_permission(
        policy,
        constants.FINE_GRAINED_READER_PERMISSION,
        second_warnings,
        custom_roles_by_principal,
    )

    # Confirm only the active predefined binding is granted, `get_role` ran once
    # per custom role, and warnings appear on both first and cached evaluations.
    self.assertEqual(principals, ["user:active_member@example.com"])
    self.assertEqual(cached_principals, ["user:active_member@example.com"])
    self.assertEqual(custom_roles_by_principal, {})
    self.assertEqual(self.mock_iam_client.get_role.call_count, 2)
    self.assertTrue(any("DISABLED" in warning for warning in first_warnings))
    self.assertTrue(any("deleted" in warning for warning in first_warnings))
    self.assertEqual(second_warnings, first_warnings)

  # Failing both GAPIC `list_data_policies` and `/v2/` REST fallback in
  # `static-dgt` must record a regional `[ERROR]` and honor `halt_on_error`.
  def test_analyze_static_dgt_records_error_when_client_and_rest_both_fail(
      self,
  ):
    """Records `[ERROR]` and halts when both SDK and REST V2 listing fail."""
    self.mock_dg_tag_keys_client.list_tag_keys.return_value = []
    # Fail both V2 listing paths so policy state is unknown rather than empty.
    self.mock_data_policy_v2_client.list_data_policies.side_effect = (
        exceptions.PermissionDenied("Missing bigquery.dataPolicies.list")
    )
    with mock.patch.object(
        self.analyzer,
        "_list_data_policies_v2_rest",
        side_effect=RuntimeError("HTTP Error 403: Forbidden"),
    ):
      results = self.analyzer.analyze_static_dgt(
          ["my-proj"], ["us", "eu"], halt_on_error=True
      )
    report = self.analyzer.generate_static_dgt_report(results)

    # Confirm `us` records the error, `halt_on_error` skips `eu`, and the
    # rendered report surfaces `[ERROR]` instead of an empty clean scan.
    self.assertEqual(len(results), 1)
    self.assertEqual(results[0].location, "us")
    self.assertIn("Missing bigquery.dataPolicies.list", results[0].error or "")
    self.assertIn("[ERROR]", report)

  # Custom IAM role `get_role` failures must emit `[ACTION REQUIRED]` on both
  # initial and cached lookups, and raise immediately when `halt_on_error=True`.
  def test_custom_role_get_role_failure_emits_action_required_and_halts(self):
    org_role = "organizations/123/roles/customFineGrainedReader"
    policy = policy_pb2.Policy(
        bindings=[
            policy_pb2.Binding(role=org_role, members=["user:corp@example.com"])
        ]
    )
    self.mock_iam_client.get_role.side_effect = exceptions.PermissionDenied(
        "Missing iam.roles.get on organization"
    )

    first_warnings: list[str] = []
    principals = self.analyzer._get_principals_with_permission(
        policy, constants.FINE_GRAINED_READER_PERMISSION, first_warnings
    )
    second_warnings: list[str] = []
    cached_principals = self.analyzer._get_principals_with_permission(
        policy, constants.FINE_GRAINED_READER_PERMISSION, second_warnings
    )

    # Confirm fail-closed omission, single RPC, and `[ACTION REQUIRED]` alerts.
    self.assertEqual(principals, [])
    self.assertEqual(cached_principals, [])
    self.assertEqual(self.mock_iam_client.get_role.call_count, 1)
    self.assertIn("[ACTION REQUIRED]", first_warnings[0])
    self.assertIn(org_role, first_warnings[0])
    self.assertIn("[ACTION REQUIRED]", second_warnings[0])
    self.assertIn("Skipped custom role inspection", second_warnings[0])

    # Confirm `halt_on_error=True` raises RuntimeError instead of continuing.
    self.analyzer._halt_on_error = True
    with self.assertRaisesRegex(
        RuntimeError, f"Failed to get permissions for role {org_role}"
    ):
      self.analyzer._get_principals_with_permission(
          policy, constants.FINE_GRAINED_READER_PERMISSION, []
      )

  # When older GAPIC descriptors drop `data_governance_tag` (`None`) and the
  # `/v2/` REST fallback also fails, `analyze_static_dgt` must fail closed.
  def test_analyze_static_dgt_fails_closed_when_rest_fallback_errors(self):
    self.mock_dg_tag_keys_client.list_tag_keys.return_value = []
    stale_sdk_policy = FakeDataPolicyV2(
        name="projects/my-proj/locations/us/dataPolicies/dp_stale",
        data_policy_type=2,
        data_governance_tag=None,
    )
    self.mock_data_policy_v2_client.list_data_policies.return_value = [
        stale_sdk_policy
    ]
    with mock.patch.object(
        self.analyzer,
        "_list_data_policies_v2_rest",
        side_effect=RuntimeError("HTTP Error 403: REST denied"),
    ):
      results = self.analyzer.analyze_static_dgt(["my-proj"], ["us"])

    self.assertEqual(len(results), 1)
    self.assertIn("HTTP Error 403: REST denied", results[0].error or "")

  # Server-canonicalized numeric `<project_number>/<short_name>` Tag Keys on
  # live V2 Data Policies must match `<project_id>/<short_name>` Tag Keys.
  def test_analyze_static_dgt_matches_numeric_project_tag_key(self):
    self.mock_crm_client.get_project.return_value = resourcemanager_v3.Project(
        name="projects/987654321", project_id="my-proj"
    )
    key1 = FakeTagKey(
        name="tagKeys/1",
        short_name="security_tags",
        namespaced_name="my-proj/security_tags",
        purpose=2,
    )
    self.mock_dg_tag_keys_client.list_tag_keys.return_value = [key1]
    tag_value_1 = FakeTagValue(
        name="tagValues/11",
        short_name="pii",
        namespaced_name="my-proj/security_tags/pii",
        parent="tagKeys/1",
    )
    self.mock_dg_tag_values_client.list_tag_values.return_value = [tag_value_1]
    numeric_key_policy = FakeDataPolicyV2(
        name="projects/my-proj/locations/us/dataPolicies/dp_num",
        data_policy_id="dp_num",
        data_policy_type=2,
        data_governance_tag=FakeDataGovernanceTag(
            key="987654321/security_tags",
            value="987654321/security_tags/pii",
        ),
        grantees=["principal://goog/subject/alice@example.com"],
    )
    self.mock_data_policy_v2_client.list_data_policies.return_value = [
        numeric_key_policy
    ]

    results = self.analyzer.analyze_static_dgt(["my-proj"], ["us"])

    self.assertEqual(len(results[0].unattached_data_policies), 0)
    attached = results[0].tag_keys[0].tag_values[0].data_policies
    self.assertEqual([item.data_policy_id for item in attached], ["dp_num"])

  # Cloud API errors during `list_tag_values` must propagate to
  # `analyze_static_dgt` (`result.error` and `halt_on_error`) without caching a
  # partial empty tag tree across remaining regions.
  def test_analyze_static_dgt_propagates_list_tag_values_error_and_halts(self):
    key1 = FakeTagKey(
        name="tagKeys/1",
        short_name="security_tags",
        namespaced_name="my-proj/security_tags",
        purpose=2,
    )
    self.mock_dg_tag_keys_client.list_tag_keys.return_value = [key1]
    self.mock_dg_tag_values_client.list_tag_values.side_effect = (
        exceptions.PermissionDenied("403 tagValues.list denied")
    )

    # Verify `halt_on_error=True` stops on the first failing region (`us`).
    halted_results = self.analyzer.analyze_static_dgt(
        ["my-proj"], ["us", "eu"], halt_on_error=True
    )
    self.assertEqual(len(halted_results), 1)
    self.assertEqual(halted_results[0].location, "us")
    self.assertIn("403 tagValues.list denied", halted_results[0].error or "")
    self.assertEqual(
        self.mock_dg_tag_values_client.list_tag_values.call_count, 1
    )

    # Verify `halt_on_error=False` does not cache a partial tree from `us`,
    # retrying `list_tag_values` on `eu` and surfacing errors for both regions.
    self.mock_dg_tag_values_client.list_tag_values.reset_mock()
    all_results = self.analyzer.analyze_static_dgt(
        ["my-proj"], ["us", "eu"], halt_on_error=False
    )
    self.assertEqual(len(all_results), 2)
    self.assertEqual([item.location for item in all_results], ["us", "eu"])
    self.assertIn("403 tagValues.list denied", all_results[0].error or "")
    self.assertIn("403 tagValues.list denied", all_results[1].error or "")
    self.assertEqual(
        self.mock_dg_tag_values_client.list_tag_values.call_count, 2
    )
    self.assertEqual(self.analyzer._static_dgt_keys_cache, {})

  # Breakdown query errors in `_analyze_column_bindings` Steps 3 and 4 must
  # propagate to `analyze_column_bindings` (`result.error` and `halt_on_error`)
  # rather than returning contradictory summary counts with empty breakdowns.
  def test_analyze_column_bindings_propagates_dgt_and_dp_breakdown_errors(self):
    summary_row = bigquery.Row(
        (10, 50, 1, 2, 2, 4, 1, 3, 3, 7),
        {
            "total_tables": 0,
            "total_columns": 1,
            "tables_with_policy_tags": 2,
            "columns_with_policy_tags": 3,
            "tables_with_dg_tags": 4,
            "columns_with_dg_tags": 5,
            "tables_with_data_policies": 6,
            "columns_with_data_policies": 7,
            "tables_with_any_cls": 8,
            "columns_with_any_cls": 9,
        },
    )

    def make_ok_job(rows):
      job = mock.create_autospec(
          bigquery.QueryJob, instance=True, spec_set=True
      )
      job.result.return_value = rows
      return job

    def make_err_job(msg: str):
      job = mock.create_autospec(
          bigquery.QueryJob, instance=True, spec_set=True
      )
      job.result.side_effect = exceptions.ServiceUnavailable(msg)
      return job

    # Step 3 (`dgt_bindings_query`) raises ServiceUnavailable -> halts on `us`.
    self.mock_bq_client.query.side_effect = [
        make_ok_job([summary_row]),
        make_ok_job([]),
        make_err_job("503 DGT breakdown timeout"),
    ]
    step3_results = self.analyzer.analyze_column_bindings(
        "my-data-project", ["us", "eu"], halt_on_error=True
    )
    self.assertEqual(len(step3_results), 1)
    self.assertIn("503 DGT breakdown timeout", step3_results[0].error or "")

    # Step 4 (`data_policy_bindings_query`) raises ServiceUnavailable -> halts.
    self.mock_bq_client.query.side_effect = [
        make_ok_job([summary_row]),
        make_ok_job([]),
        make_ok_job([]),
        make_err_job("503 Data Policy breakdown timeout"),
    ]
    step4_results = self.analyzer.analyze_column_bindings(
        "my-data-project", ["us", "eu"], halt_on_error=True
    )
    self.assertEqual(len(step4_results), 1)
    self.assertIn(
        "503 Data Policy breakdown timeout", step4_results[0].error or ""
    )

  # All three source IAM policy lookups (Taxonomy, Policy Tag, and V1 Data
  # Policy) must send `requested_policy_version = 3` so conditional bindings
  # remain intact rather than being down-converted to `_withcond_` roles.
  def test_static_taxonomy_iam_lookups_request_policy_version_3(self):
    self.mock_crm_client.get_project.return_value = types.SimpleNamespace(
        name="projects/12345"
    )

    taxonomy = FakeTaxonomy(
        name="projects/test-proj/locations/us/taxonomies/100",
        display_name="Sensitive",
        activated_policy_types=[
            datacatalog_v1.Taxonomy.PolicyType.FINE_GRAINED_ACCESS_CONTROL
        ],
    )
    policy_tag = FakePolicyTag(
        name="projects/test-proj/locations/us/taxonomies/100/policyTags/200",
        display_name="SSN",
        parent_policy_tag="",
    )
    v1_policy = FakeDataPolicyV1(
        name="projects/test-proj/locations/us/dataPolicies/mask_ssn",
        policy_tag="projects/12345/locations/us/taxonomies/100/policyTags/200",
        data_policy_type=bigquery_datapolicies_v1.DataPolicy.DataPolicyType.DATA_MASKING_POLICY,
        data_masking_policy=FakeDataMaskingPolicyV1(
            predefined_expression=(
                bigquery_datapolicies_v1.DataMaskingPolicy.PredefinedExpression.SHA256
            )
        ),
    )
    self.mock_dc_client.list_taxonomies.return_value = [taxonomy]
    self.mock_dc_client.list_policy_tags.return_value = [policy_tag]
    self.mock_bdp_client.list_data_policies.return_value = [v1_policy]
    self.mock_dc_client.get_iam_policy.return_value = policy_pb2.Policy()
    self.mock_bdp_client.get_iam_policy.return_value = policy_pb2.Policy()

    self.analyzer._analyze_static_taxonomy("test-proj", "us")

    dc_requests = [
        call.kwargs["request"]
        for call in self.mock_dc_client.get_iam_policy.call_args_list
    ]
    dp_requests = [
        call.kwargs["request"]
        for call in self.mock_bdp_client.get_iam_policy.call_args_list
    ]
    self.assertEqual(len(dc_requests), 2)
    self.assertEqual(len(dp_requests), 1)
    for req in dc_requests + dp_requests:
      self.assertEqual(req.options.requested_policy_version, 3)

  # Conditional IAM bindings whose role grants the target permission must be
  # omitted fail-closed with an `[ACTION REQUIRED]` warning naming role,
  # members, and condition expression, while unrelated conditional roles do not
  # emit spurious warnings.
  def test_get_principals_omits_conditional_bindings_fail_closed(self):
    custom_reader_role = "projects/test-proj/roles/customFineReader"
    unrelated_role = "projects/test-proj/roles/customMetadataViewer"

    def get_role_side_effect(request, retry=None):
      del retry
      included = (
          [constants.FINE_GRAINED_READER_PERMISSION]
          if request["name"] == custom_reader_role
          else ["datacatalog.taxonomies.get"]
      )
      return types.SimpleNamespace(
          deleted=False,
          stage=iam_admin_v1.Role.RoleLaunchStage.GA,
          included_permissions=included,
      )

    self.mock_iam_client.get_role.side_effect = get_role_side_effect
    # Include (1) unconditional predefined grant, (2) conditional predefined
    # grant, (3) conditional custom-role grant, and (4) unrelated conditional
    # grant that does not include the target permission.
    policy = types.SimpleNamespace(
        bindings=[
            types.SimpleNamespace(
                role=constants.FINE_GRAINED_READER_ROLE,
                members=["user:permanent@example.com"],
                condition=None,
            ),
            types.SimpleNamespace(
                role=constants.FINE_GRAINED_READER_ROLE,
                members=["user:temp@example.com"],
                condition=types.SimpleNamespace(
                    expression=(
                        "request.time < timestamp('2026-01-01T00:00:00Z')"
                    )
                ),
            ),
            types.SimpleNamespace(
                role=custom_reader_role,
                members=["user:custom_temp@example.com"],
                condition=types.SimpleNamespace(
                    expression="resource.name.startsWith('projects/123')"
                ),
            ),
            types.SimpleNamespace(
                role=unrelated_role,
                members=["user:viewer@example.com"],
                condition=types.SimpleNamespace(
                    expression=(
                        "request.time < timestamp('2026-01-01T00:00:00Z')"
                    )
                ),
            ),
        ]
    )
    warnings_list: list[str] = []
    custom_roles_by_principal: dict[str, list[str]] = {}

    principals = self.analyzer._get_principals_with_permission(
        policy,
        constants.FINE_GRAINED_READER_PERMISSION,
        warnings_list,
        custom_roles_by_principal,
    )

    self.assertEqual(principals, ["user:permanent@example.com"])
    self.assertEqual(custom_roles_by_principal, {})
    self.assertEqual(len(warnings_list), 2)
    self.assertIn("[ACTION REQUIRED]", warnings_list[0])
    self.assertIn("user:temp@example.com", warnings_list[0])
    self.assertIn("2026-01-01T00:00:00Z", warnings_list[0])
    self.assertIn("[ACTION REQUIRED]", warnings_list[1])
    self.assertIn(custom_reader_role, warnings_list[1])
    self.assertIn("user:custom_temp@example.com", warnings_list[1])
    self.assertIn("resource.name.startsWith", warnings_list[1])

  # V1-aliased clients and intermediate SDK wheels lacking `matching_condition`
  # must adopt REST `/v2/` unconditionally so condition-bound V2 Data Policies
  # are retained and rendered with `Matching Condition:` in static DGT reports.
  def test_analyze_static_dgt_preserves_and_renders_conditional_v2_policies(
      self,
  ):
    key1 = FakeTagKey(
        name="tagKeys/1",
        short_name="security_tags",
        namespaced_name="my-proj/security_tags",
        purpose=2,
    )
    self.mock_dg_tag_keys_client.list_tag_keys.return_value = [key1]
    self.mock_dg_tag_values_client.list_tag_values.return_value = []

    # Case 1: V1-aliased client returning legacy V1 policy alongside a REST
    # condition-bound V2 policy (no `dataGovernanceTag` present in REST).
    v1_aliased_client = mock.create_autospec(
        bigquery_datapolicies_v1.DataPolicyServiceClient,
        instance=True,
        spec_set=True,
    )
    v1_aliased_client.list_data_policies.return_value = [
        FakeDataPolicyV1(
            name="projects/my-proj/locations/us/dataPolicies/legacy_v1",
            policy_tag="projects/123/locations/us/taxonomies/1/policyTags/2",
            data_policy_type=bigquery_datapolicies_v1.DataPolicy.DataPolicyType.DATA_MASKING_POLICY,
        )
    ]
    v1_analyzer = analyzer.Analyzer(
        data_catalog_client=self.mock_dc_client,
        data_policy_client=self.mock_bdp_client,
        bigquery_client=self.mock_bq_client,
        resourcemanager_client=self.mock_crm_client,
        iam_client=self.mock_iam_client,
        dg_tag_keys_client=self.mock_dg_tag_keys_client,
        dg_tag_values_client=self.mock_dg_tag_values_client,
        data_policy_v2_client=v1_aliased_client,
    )
    rest_conditional_policy = {
        "name": "projects/my-proj/locations/us/dataPolicies/cond_sql",
        "dataPolicyId": "cond_sql",
        "dataPolicyType": "RAW_DATA_ACCESS_POLICY",
        "matchingCondition": "COLUMN_HAS_TAG_KEY('my-proj/security_tags')",
        "grantees": ["user:cond_reader@example.com"],
    }
    with mock.patch.object(
        v1_analyzer,
        "_list_data_policies_v2_rest",
        return_value=[rest_conditional_policy],
    ) as mock_v1_rest:
      v1_results = v1_analyzer.analyze_static_dgt(["my-proj"], ["us"])

    mock_v1_rest.assert_called_once_with("my-proj", "us")
    self.assertEqual(len(v1_results[0].unattached_data_policies), 1)
    cond_info = v1_results[0].unattached_data_policies[0]
    self.assertEqual(cond_info.data_policy_id, "cond_sql")
    self.assertEqual(
        cond_info.matching_condition,
        "COLUMN_HAS_TAG_KEY('my-proj/security_tags')",
    )

    # Confirm the static DGT report labels condition-bound policies with
    # `Matching Condition:` rather than `Direct Column-Level Data Policy`.
    report = v1_analyzer.generate_static_dgt_report(v1_results)
    self.assertIn(
        "Matching Condition: COLUMN_HAS_TAG_KEY('my-proj/security_tags')",
        report,
    )
    self.assertNotIn("Direct Column-Level Data Policy", report)

    # Case 2: Intermediate SDK wheel defining `data_governance_tag` without
    # `matching_condition` must also fall back to REST `/v2/`.
    intermediate_sdk_policy = types.SimpleNamespace(
        name="projects/my-proj/locations/us/dataPolicies/dp_tag",
        data_policy_id="dp_tag",
        data_policy_type=2,
        data_governance_tag=FakeDataGovernanceTag(
            key="my-proj/security_tags", value=None
        ),
        data_masking_policy=None,
        grantees=["user:tag_reader@example.com"],
    )
    self.mock_data_policy_v2_client.list_data_policies.return_value = [
        intermediate_sdk_policy
    ]
    with mock.patch.object(
        self.analyzer,
        "_list_data_policies_v2_rest",
        return_value=[rest_conditional_policy],
    ) as mock_intermediate_rest:
      sdk_results = self.analyzer.analyze_static_dgt(["my-proj"], ["us"])

    mock_intermediate_rest.assert_called_once_with("my-proj", "us")
    self.assertEqual(
        [p.data_policy_id for p in sdk_results[0].unattached_data_policies],
        ["cond_sql"],
    )

    # Case 3: SDK wheel defining `matching_condition` without
    # `data_governance_tag_condition` must also fall back to REST `/v2/` so
    # CEL-condition policies are not dropped on the SDK path.
    sql_only_sdk_policy = types.SimpleNamespace(
        name="projects/my-proj/locations/us/dataPolicies/dp_tag",
        data_policy_id="dp_tag",
        data_policy_type=2,
        data_governance_tag=FakeDataGovernanceTag(
            key="my-proj/security_tags", value=None
        ),
        matching_condition=None,
        data_masking_policy=None,
        grantees=["user:tag_reader@example.com"],
    )
    self.mock_data_policy_v2_client.list_data_policies.return_value = [
        sql_only_sdk_policy
    ]
    rest_cel_policy = {
        "name": "projects/my-proj/locations/us/dataPolicies/cond_cel",
        "dataPolicyId": "cond_cel",
        "dataPolicyType": "RAW_DATA_ACCESS_POLICY",
        "dataGovernanceTagCondition": {
            "expression": "column.matchTag('my-proj/security_tags', 'high')"
        },
        "grantees": ["user:cel_reader@example.com"],
    }
    with mock.patch.object(
        self.analyzer,
        "_list_data_policies_v2_rest",
        return_value=[rest_cel_policy],
    ) as mock_cel_rest:
      cel_results = self.analyzer.analyze_static_dgt(["my-proj"], ["us"])

    mock_cel_rest.assert_called_once_with("my-proj", "us")
    self.assertEqual(
        [p.data_policy_id for p in cel_results[0].unattached_data_policies],
        ["cond_cel"],
    )
    self.assertEqual(
        cel_results[0].unattached_data_policies[0].matching_condition,
        "column.matchTag('my-proj/security_tags', 'high')",
    )

  # `analyze_static_dgt` must seed project numbers from `TagKey.parent` so
  # policies keyed by `<dgt_project_number>/<short_name>` attach without
  # calling `resourcemanager.projects.get`.
  def test_analyze_static_dgt_seeds_project_number_from_tag_key_parent(self):
    self.mock_crm_client.get_project.side_effect = exceptions.PermissionDenied(
        "403 resourcemanager.projects.get denied"
    )
    key1 = FakeTagKey(
        name="tagKeys/1",
        short_name="security_tags",
        namespaced_name="dgt-proj/security_tags",
        purpose=2,
        parent="projects/987654321",
    )
    val1 = FakeTagValue(
        name="tagValues/10",
        short_name="pii",
        namespaced_name="dgt-proj/security_tags/pii",
        parent="tagKeys/1",
    )
    self.mock_dg_tag_keys_client.list_tag_keys.return_value = [key1]
    self.mock_dg_tag_values_client.list_tag_values.return_value = [val1]
    self.mock_data_policy_v2_client.list_data_policies.return_value = [
        FakeDataPolicyV2(
            name="projects/dp-proj/locations/us/dataPolicies/pol_num",
            data_policy_id="pol_num",
            data_policy_type=2,
            data_governance_tag=FakeDataGovernanceTag(
                key="987654321/security_tags",
                value="987654321/security_tags/pii",
            ),
            grantees=["user:reader@example.com"],
        )
    ]

    results = self.analyzer.analyze_static_dgt(
        ["dgt-proj"], ["us"], data_policy_v2_project_ids=["dp-proj"]
    )

    self.mock_crm_client.get_project.assert_not_called()
    self.assertEqual(len(results), 1)
    self.assertEqual(results[0].unattached_data_policies, [])
    attached = results[0].tag_keys[0].tag_values[0].data_policies
    self.assertEqual([p.data_policy_id for p in attached], ["pol_num"])

  # Multi-project/multi-region `static-dgt` reports must reset Tag Key numbering
  # to `1..N` inside each scan section instead of counting past `Total`.
  def test_generate_static_dgt_report_resets_key_numbering_per_section(self):
    """Resets `1. DG Tag Key:` numbering per scan section."""
    key_alpha = analyzer.DGTagKeyInfo(
        name="tagKeys/1",
        short_name="alpha",
        namespaced_name="dgt-proj/alpha",
    )
    key_beta = analyzer.DGTagKeyInfo(
        name="tagKeys/2",
        short_name="beta",
        namespaced_name="dgt-proj/beta",
    )
    section_one = analyzer.StaticDgtAnalysisResult(
        project_id="data-proj-1",
        location="us",
        dgt_project_id="dgt-proj",
        tag_keys=[key_alpha, key_beta],
    )
    section_two = analyzer.StaticDgtAnalysisResult(
        project_id="data-proj-2",
        location="us",
        dgt_project_id="dgt-proj",
        tag_keys=[key_alpha, key_beta],
    )

    report = self.analyzer.generate_static_dgt_report(
        [section_one, section_two]
    )

    # Header shows 2 distinct global Tag Keys and each section numbers `1..2`.
    self.assertIn("Total DG Tag Keys Found: 2", report)
    self.assertEqual(report.count('1. DG Tag Key: "alpha" (tagKeys/1)'), 2)
    self.assertEqual(report.count('2. DG Tag Key: "beta" (tagKeys/2)'), 2)
    self.assertNotIn("3. DG Tag Key:", report)

  # Unmatched V2 Data Policies in `static-dgt` reports must be partitioned into
  # distinct sections so cross-project, direct-column, condition-bound, and
  # genuinely unattached policies are never conflated.
  def test_generate_static_dgt_report_partitions_unmatched_policy_categories(
      self,
  ):
    """Partitions cross-project, direct, condition, and unattached policies."""
    self.analyzer._project_number_to_id_cache["111111"] = "other-dgt-proj"
    self.analyzer._project_id_to_number_cache["dgt-proj"] = "222222"

    other_project_policy = analyzer.DataPolicyV2Info(
        name="projects/dp-proj/locations/us/dataPolicies/pol_other_proj",
        data_policy_id="pol_other_proj",
        data_governance_tag_key="other-dgt-proj/foreign_key",
    )
    other_numeric_policy = analyzer.DataPolicyV2Info(
        name="projects/dp-proj/locations/us/dataPolicies/pol_other_num",
        data_policy_id="pol_other_num",
        data_governance_tag_key="111111/foreign_num_key",
    )
    direct_column_policy = analyzer.DataPolicyV2Info(
        name="projects/dp-proj/locations/us/dataPolicies/pol_direct",
        data_policy_id="pol_direct",
        policy_type=constants.DATA_POLICY_TYPE_MASKING,
    )
    condition_policy = analyzer.DataPolicyV2Info(
        name="projects/dp-proj/locations/us/dataPolicies/pol_cond",
        data_policy_id="pol_cond",
        matching_condition="column.matchTag('dgt-proj/k', 'v')",
    )
    # Missing/deleted tag inside the *scanned* `dgt-proj` stays unattached and
    # must NOT be misclassified under OTHER DGT PROJECTS.
    same_project_missing_tag_policy = analyzer.DataPolicyV2Info(
        name="projects/dp-proj/locations/us/dataPolicies/pol_missing_local",
        data_policy_id="pol_missing_local",
        data_governance_tag_key="dgt-proj/deleted_key",
    )
    result = analyzer.StaticDgtAnalysisResult(
        project_id="dp-proj",
        location="us",
        dgt_project_id="dgt-proj",
        tag_keys=[],
        unattached_data_policies=[
            other_project_policy,
            other_numeric_policy,
            direct_column_policy,
            condition_policy,
            same_project_missing_tag_policy,
        ],
    )

    report = self.analyzer.generate_static_dgt_report([result])

    other_idx = report.index(
        "[DATA POLICIES (V2) ATTACHED TO OTHER DGT PROJECTS]"
    )
    direct_idx = report.index("[DIRECT COLUMN-LEVEL DATA POLICIES (V2)]")
    cond_idx = report.index("[CONDITION-BOUND DATA POLICIES (V2)]")
    unattached_idx = report.index("[UNATTACHED DATA POLICIES (V2)]")

    self.assertLess(other_idx, report.index('"pol_other_proj"'))
    self.assertLess(report.index('"pol_other_num"'), direct_idx)
    self.assertLess(direct_idx, report.index('"pol_direct"'))
    self.assertLess(report.index('"pol_direct"'), cond_idx)
    self.assertLess(cond_idx, report.index('"pol_cond"'))
    self.assertLess(report.index('"pol_cond"'), unattached_idx)
    self.assertLess(unattached_idx, report.index('"pol_missing_local"'))


if __name__ == "__main__":
  unittest.main()
