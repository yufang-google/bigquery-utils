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

"""Unit tests for the Phase 2a Creator class (`creator.py`).

What This Test Suite Verifies:
==============================
1. Tag Key & Tag Value Resolution (`_get_dg_tag_key_id`, `_get_dg_tag_value_id`,
   `_get_parent_id`):
   - In-memory positive caching (`_dg_tag_key_cache`, `_dg_tag_value_cache`) and
     per-project / per-parent negative-lookup sets (`_listed_tag_key_projects`,
     `_listed_tag_value_parents`).
   - Direct-child filtering when `list_tag_values` returns nested descendants
     sharing the same `short_name`.
   - Rejection of pre-existing Tag Keys that have a non-`DATA_GOVERNANCE`
     purpose.
2. Resource Creation & Idempotency (`create_dg_tag_key`, `create_dg_tag_value`,
   `create_data_policy_v2`):
   - Idempotent skip (`STATUS_SKIPPED`) when resources already exist or when
     concurrent creation raises `AlreadyExists` / HTTP 409.
   - Dual-transport V2 Data Policy existence check and creation,
     falling back from GAPIC `get_data_policy` / `create_data_policy` to raw
     `/v2/` REST endpoints (`_get_data_policy_v2_rest` /
     `_create_data_policy_v2_rest`) with exponential backoff on HTTP 503.
3. Batch & Individual Orchestration (`create_all_dgt_resources`,
   `create_individual_dgt_resource`):
   - Topological creation order (Tag Keys -> Tag Values by depth -> V2 Data
     Policies across all 3 manifest categories).
   - Cascading dependency failure tracking when a parent Tag Key or Tag Value
     fails creation.
   - Mode 2 (`TABLE_PARENT_PROJECTS`) cross-project `<policy_id>` ambiguity
     detection and `<target_project_id>/<policy_id>` disambiguation.
   - Dry-run read-only pre-flight inspection and Markdown report persistence
     (`--report-file`), including partial report writing on `halt_on_error`.
"""

import contextlib
import io
import os
import sys
import tempfile
import types
import unittest
from unittest import mock
import urllib.error

from google.api_core import exceptions
from google.api_core import operation as api_core_operation
from google.auth import credentials as auth_credentials
from google.cloud import bigquery_datapolicies_v1
from google.cloud import resourcemanager_v3
import proto

# Ensure local imports work in both package and standalone script execution.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# pylint: disable=g-import-not-at-top,g-bad-import-order
try:
  from google.cloud import bigquery_datapolicies_v2
except ImportError:
  bigquery_datapolicies_v2 = bigquery_datapolicies_v1

import constants
import creator

# pylint: enable=g-import-not-at-top,g-bad-import-order


__protobuf__ = proto.module(
    package="test.datapolicies.v2",
    manifest={"_ProtoTagRef", "_ProtoDataPolicyV2"},
)


class _ProtoTagRef(proto.Message):
  """Minimal proto-plus tag reference message for V2 drift tests."""

  key = proto.Field(proto.STRING, number=1)
  value = proto.Field(proto.STRING, number=2)


class _ProtoDataPolicyV2(proto.Message):
  """Minimal proto-plus V2 DataPolicy message exposing `Repeated` grantees."""

  name = proto.Field(proto.STRING, number=1)
  data_policy_type = proto.Field(proto.STRING, number=2)
  data_governance_tag = proto.Field(_ProtoTagRef, number=3)
  grantees = proto.RepeatedField(proto.STRING, number=4)


def _make_urlopen_response(body_bytes: bytes):
  """Returns a context-manager object whose read() returns body_bytes."""
  return contextlib.nullcontext(io.BytesIO(body_bytes))


class CreatorTest(unittest.TestCase):
  """Unit tests for Phase 2a `Creator` resource provisioning and dry-run."""

  def setUp(self):
    """Initializes strict autospecced GCP clients and a `Creator` instance."""
    super().setUp()

    self.mock_tag_keys_client = mock.create_autospec(
        resourcemanager_v3.TagKeysClient,
        instance=True,
        spec_set=True,
    )
    self.mock_tag_values_client = mock.create_autospec(
        resourcemanager_v3.TagValuesClient,
        instance=True,
        spec_set=True,
    )
    self.mock_data_policy_v2_client = mock.create_autospec(
        bigquery_datapolicies_v2.DataPolicyServiceClient,
        instance=True,
        spec_set=True,
    )

    self.creator = creator.Creator(
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
    )

  # =========================================================================
  # === Section 1: Tag Key & Tag Value Resolution and Caching Tests ===
  # =========================================================================

  def test_get_dg_tag_key_id_caching(self):
    """Verifies `_get_dg_tag_key_id` returns cached IDs without RPC calls."""
    # Arrange: Seed the Tag Key cache with a known namespaced name.
    self.creator._dg_tag_key_cache["my-project/my-key"] = "tagKeys/123"

    # Act: Look up the Tag Key ID.
    tag_id = self.creator._get_dg_tag_key_id("my-project/my-key")

    # Assert: The cached ID is returned and list_tag_keys is never called.
    self.assertEqual(tag_id, "tagKeys/123")
    self.mock_tag_keys_client.list_tag_keys.assert_not_called()

  def test_get_dg_tag_key_id_fetch(self):
    """Verifies `_get_dg_tag_key_id` lists project keys and populates cache."""
    # Arrange: Configure list_tag_keys to return one matching Tag Key.
    mock_key = types.SimpleNamespace(
        name="tagKeys/123", short_name="my-key", purpose=2
    )
    self.mock_tag_keys_client.list_tag_keys.return_value = [mock_key]

    # Act: Resolve the Tag Key ID by namespaced name.
    tag_id = self.creator._get_dg_tag_key_id("my-project/my-key")

    # Assert: The RPC is called with RETRY_CONFIG and the cache is populated.
    self.assertEqual(tag_id, "tagKeys/123")
    self.mock_tag_keys_client.list_tag_keys.assert_called_once_with(
        parent="projects/my-project", retry=creator.RETRY_CONFIG
    )
    self.assertEqual(
        self.creator._dg_tag_key_cache["my-project/my-key"], "tagKeys/123"
    )

  def test_get_dg_tag_key_id_not_found(self):
    """Verifies `_get_dg_tag_key_id` returns `None` when a key is absent."""
    # Arrange: Configure list_tag_keys to return an empty list.
    self.mock_tag_keys_client.list_tag_keys.return_value = []

    # Act: Look up a missing Tag Key.
    tag_id = self.creator._get_dg_tag_key_id("my-project/my-key")

    # Assert: None is returned.
    self.assertIsNone(tag_id)

  def test_get_dg_tag_value_id_caching(self):
    """Verifies `_get_dg_tag_value_id` serves cached Tag Value IDs in O(1)."""
    # Arrange: Seed the Tag Value cache.
    self.creator._dg_tag_value_cache["my-project/my-key/my-value"] = (
        "tagValues/456"
    )

    # Act: Look up the cached Tag Value ID.
    tag_id = self.creator._get_dg_tag_value_id("my-project/my-key/my-value")

    # Assert: The cached ID is returned and list_tag_values is not called.
    self.assertEqual(tag_id, "tagValues/456")
    self.mock_tag_values_client.list_tag_values.assert_not_called()

  def test_get_dg_tag_value_id_fetch(self):
    """Verifies `_get_dg_tag_value_id` lists child values under parent key."""
    # Arrange: Configure list_tag_keys and list_tag_values responses.
    mock_key = types.SimpleNamespace(
        name="tagKeys/123", short_name="my-key", purpose=2
    )
    self.mock_tag_keys_client.list_tag_keys.return_value = [mock_key]

    mock_value = types.SimpleNamespace(
        name="tagValues/456", short_name="my-value", parent="tagKeys/123"
    )
    self.mock_tag_values_client.list_tag_values.return_value = [mock_value]

    # Act: Resolve the Tag Value ID by namespaced name.
    tag_id = self.creator._get_dg_tag_value_id("my-project/my-key/my-value")

    # Assert: list_tag_values is called with parent="tagKeys/123" and cached.
    self.assertEqual(tag_id, "tagValues/456")
    self.mock_tag_values_client.list_tag_values.assert_called_once_with(
        parent="tagKeys/123", retry=creator.RETRY_CONFIG
    )
    self.assertEqual(
        self.creator._dg_tag_value_cache["my-project/my-key/my-value"],
        "tagValues/456",
    )

  def test_get_dg_tag_value_id_not_found(self):
    """Verifies `_get_dg_tag_value_id` returns `None` when value is absent."""
    # Arrange: Return a matching Tag Key and an empty Tag Value list.
    mock_key = types.SimpleNamespace(
        name="tagKeys/123", short_name="my-key", purpose=2
    )
    self.mock_tag_keys_client.list_tag_keys.return_value = [mock_key]
    self.mock_tag_values_client.list_tag_values.return_value = []

    # Act: Look up the missing Tag Value.
    tag_id = self.creator._get_dg_tag_value_id("my-project/my-key/my-value")

    # Assert: None is returned.
    self.assertIsNone(tag_id)

  def test_get_dg_tag_value_id_invalid_name(self):
    """Verifies `_get_dg_tag_value_id` raises `ValueError` on <3 segments."""
    # Arrange, Act & Assert: Assert ValueError on "invalid-name".
    with self.assertRaises(ValueError):
      self.creator._get_dg_tag_value_id("invalid-name")

  def test_get_parent_id_key(self):
    """Verifies `_get_parent_id` resolves a 2-segment name as a Tag Key ID."""
    # Arrange: Configure list_tag_keys to return tagKeys/123.
    mock_key = types.SimpleNamespace(
        name="tagKeys/123", short_name="my-key", purpose=2
    )
    self.mock_tag_keys_client.list_tag_keys.return_value = [mock_key]

    # Act: Resolve the 2-segment parent name.
    parent_id = self.creator._get_parent_id("my-project/my-key")

    # Assert: Returns the Tag Key resource name.
    self.assertEqual(parent_id, "tagKeys/123")

  def test_get_parent_id_value(self):
    """Verifies `_get_parent_id` resolves a >=3-segment name as a Tag Value."""
    # Arrange: Configure Tag Key and parent Tag Value responses.
    mock_key = types.SimpleNamespace(
        name="tagKeys/123", short_name="my-key", purpose=2
    )
    self.mock_tag_keys_client.list_tag_keys.return_value = [mock_key]

    mock_value = types.SimpleNamespace(
        name="tagValues/456", short_name="my-value", parent="tagKeys/123"
    )
    self.mock_tag_values_client.list_tag_values.return_value = [mock_value]

    # Act: Resolve the 3-segment parent name.
    parent_id = self.creator._get_parent_id("my-project/my-key/my-value")

    # Assert: Returns the parent Tag Value resource name.
    self.assertEqual(parent_id, "tagValues/456")

  # =========================================================================
  # === Section 2: Tag Key, Tag Value & V2 Data Policy Creation Tests ===
  # =========================================================================

  def test_create_dg_tag_key_exists(self):
    """Verifies `create_dg_tag_key` returns `STATUS_SKIPPED` if key exists."""
    # Arrange: Pre-populate the Tag Key cache.
    self.creator._dg_tag_key_cache["my-project/my-key"] = "tagKeys/123"
    action = {"namespaced_name": "my-project/my-key", "api_payload": {}}

    # Act: Call create_dg_tag_key.
    tag_id, status = self.creator.create_dg_tag_key(action)

    # Assert: Creation RPC is not called and status is SKIPPED.
    self.assertEqual(tag_id, "tagKeys/123")
    self.assertEqual(status, constants.STATUS_SKIPPED)
    self.mock_tag_keys_client.create_tag_key.assert_not_called()

  def test_create_dg_tag_key_creates(self):
    """Verifies `create_dg_tag_key` creates a missing key and caches its ID."""
    # Arrange: Mock empty list_tag_keys and an LRO returning tagKeys/123.
    self.mock_tag_keys_client.list_tag_keys.return_value = []
    mock_operation = mock.create_autospec(
        api_core_operation.Operation, instance=True, spec_set=True
    )
    mock_result = types.SimpleNamespace(name="tagKeys/123")
    mock_operation.result.return_value = mock_result
    self.mock_tag_keys_client.create_tag_key.return_value = mock_operation

    action = {
        "namespaced_name": "my-project/my-key",
        "api_payload": {"short_name": "my-key"},
    }

    # Act: Create the Tag Key.
    tag_id, status = self.creator.create_dg_tag_key(action)

    # Assert: create_tag_key was called with RETRY_CONFIG and status is CREATED.
    self.assertEqual(tag_id, "tagKeys/123")
    self.assertEqual(status, constants.STATUS_CREATED)
    self.mock_tag_keys_client.create_tag_key.assert_called_once_with(
        tag_key={"short_name": "my-key"}, retry=creator.RETRY_CONFIG
    )

  def test_create_dg_tag_value_exists(self):
    """Verifies `create_dg_tag_value` returns `STATUS_SKIPPED` if present."""
    # Arrange: Pre-populate the Tag Value cache.
    self.creator._dg_tag_value_cache["my-project/my-key/my-value"] = (
        "tagValues/456"
    )
    action = {
        "namespaced_name": "my-project/my-key/my-value",
        "api_payload": {},
    }

    # Act: Call create_dg_tag_value.
    tag_id, status = self.creator.create_dg_tag_value(action)

    # Assert: create_tag_value is not called and status is SKIPPED.
    self.assertEqual(tag_id, "tagValues/456")
    self.assertEqual(status, constants.STATUS_SKIPPED)
    self.mock_tag_values_client.create_tag_value.assert_not_called()

  def test_create_dg_tag_value_creates(self):
    """Verifies `create_dg_tag_value` resolves parent and creates the value."""
    # Arrange: Mock parent Tag Key lookup and LRO result for create_tag_value.
    mock_key = types.SimpleNamespace(
        name="tagKeys/123", short_name="my-key", purpose=2
    )
    self.mock_tag_keys_client.list_tag_keys.return_value = [mock_key]
    self.mock_tag_values_client.list_tag_values.return_value = []

    mock_operation = mock.create_autospec(
        api_core_operation.Operation, instance=True, spec_set=True
    )
    mock_result = types.SimpleNamespace(name="tagValues/456")
    mock_operation.result.return_value = mock_result
    self.mock_tag_values_client.create_tag_value.return_value = mock_operation

    action = {
        "namespaced_name": "my-project/my-key/my-value",
        "parent_namespaced_name": "my-project/my-key",
        "api_payload": {"short_name": "my-value"},
    }

    # Act: Create the Tag Value.
    tag_id, status = self.creator.create_dg_tag_value(action)

    # Assert: create_tag_value is called with resolved parent and RETRY_CONFIG.
    self.assertEqual(tag_id, "tagValues/456")
    self.assertEqual(status, constants.STATUS_CREATED)
    self.mock_tag_values_client.create_tag_value.assert_called_once_with(
        tag_value={"short_name": "my-value", "parent": "tagKeys/123"},
        retry=creator.RETRY_CONFIG,
    )

  def test_create_data_policy_v2_exists(self):
    """Verifies `create_data_policy_v2` skips creation when policy exists."""
    # Arrange: Prepare a Data Policy V2 action while get_data_policy succeeds.
    action = {
        "policy_id": "my-policy",
        "region": "us",
        "target_project_id": "my-project",
        "api_payload": {
            "data_governance_tag": {
                "key": "my-project/my-key",
                "value": "my-value",
            }
        },
    }

    # Act: Call create_data_policy_v2.
    policy_name, status = self.creator.create_data_policy_v2(action)

    # Assert: get_data_policy is called with RETRY_CONFIG and creation is
    # skipped.
    expected_name = "projects/my-project/locations/us/dataPolicies/my-policy"
    self.assertEqual(policy_name, expected_name)
    self.assertEqual(status, constants.STATUS_SKIPPED)
    self.mock_data_policy_v2_client.get_data_policy.assert_called_once_with(
        name=expected_name, retry=creator.RETRY_CONFIG
    )
    self.mock_data_policy_v2_client.create_data_policy.assert_not_called()

  def test_create_data_policy_v2_creates(self):
    """Verifies `create_data_policy_v2` creates policy on `NotFound`."""
    # Arrange: Configure get_data_policy to raise NotFound and mock creation.
    self.mock_data_policy_v2_client.get_data_policy.side_effect = (
        exceptions.NotFound("Not found")
    )

    mock_result = types.SimpleNamespace(
        name="projects/my-project/locations/us/dataPolicies/my-policy"
    )
    self.mock_data_policy_v2_client.create_data_policy.return_value = (
        mock_result
    )

    action = {
        "policy_id": "my-policy",
        "region": "us",
        "target_project_id": "my-project",
        "api_payload": {
            "data_governance_tag": {
                "key": "my-project/my-key",
                "value": "my-value",
            }
        },
    }

    # Act: Create the V2 Data Policy.
    policy_name, status = self.creator.create_data_policy_v2(action)

    # Assert: create_data_policy is called with request dict including
    # data_policy_id and retry=RETRY_CONFIG.
    expected_name = "projects/my-project/locations/us/dataPolicies/my-policy"
    self.assertEqual(policy_name, expected_name)
    self.assertEqual(status, constants.STATUS_CREATED)
    self.mock_data_policy_v2_client.create_data_policy.assert_called_once_with(
        request={
            "parent": "projects/my-project/locations/us",
            "data_policy_id": "my-policy",
            "data_policy": action["api_payload"],
        },
        retry=creator.RETRY_CONFIG,
    )

  def test_create_data_policy_v2_missing_target_project_id(self):
    """Verifies `create_data_policy_v2` raises `ValueError` without project."""
    # Arrange: Omit target_project_id from the action dict.
    action = {
        "policy_id": "my-policy",
        "region": "us",
        "api_payload": {
            "data_governance_tag": {
                "key": "my-project/my-key",
                "value": "my-value",
            }
        },
    }

    # Act & Assert: ValueError is raised.
    with self.assertRaises(ValueError):
      self.creator.create_data_policy_v2(action)

  # =========================================================================
  # === Section 3: Batch & Individual Orchestration and Reporting Tests ===
  # =========================================================================

  @mock.patch("builtins.input", return_value="y", autospec=True)
  def test_create_all_dgt_resources_success(self, mock_input):
    """Verifies `create_all_dgt_resources` provisions resources in order."""
    # Arrange: Build a migration plan with one Key, one Value, and one Policy.
    del mock_input  # Unused
    plan = {
        "phase_2_resource_manifest": {
            constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS: [
                {"namespaced_name": "my-project/my-key", "api_payload": {}}
            ],
            constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES: [{
                "namespaced_name": "my-project/my-key/my-value",
                "parent_namespaced_name": "my-project/my-key",
                "api_payload": {},
            }],
            constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2: [{
                "policy_id": "my-policy",
                "region": "us",
                "api_payload": {
                    "data_governance_tag": {
                        "key": "my-project/my-key",
                        "value": "my-value",
                    }
                },
            }],
        }
    }

    with (
        mock.patch.object(
            self.creator,
            "create_dg_tag_key",
            return_value=("tagKeys/123", constants.STATUS_CREATED),
            autospec=True,
        ) as mock_create_key,
        mock.patch.object(
            self.creator,
            "create_dg_tag_value",
            return_value=("tagValues/456", constants.STATUS_CREATED),
            autospec=True,
        ) as mock_create_value,
        mock.patch.object(
            self.creator,
            "create_data_policy_v2",
            return_value=(
                "projects/my-project/locations/us/dataPolicies/my-policy",
                constants.STATUS_CREATED,
            ),
            autospec=True,
        ) as mock_create_data_policy,
    ):
      # Act: Run batch resource creation.
      report = self.creator.create_all_dgt_resources(plan)

      # Assert: All three resource types were created and recorded in report.
      mock_create_key.assert_called_once()
      mock_create_value.assert_called_once()
      mock_create_data_policy.assert_called_once()
      self.assertIsNotNone(report)
      self.assertIn("Succeeded: 1", report)
      self.assertEqual(self.creator.last_summary["failed"], 0)
      self.assertEqual(self.creator.last_summary["succeeded"], 3)

  @mock.patch("builtins.input", return_value="y", autospec=True)
  def test_create_all_dgt_resources_separated_categories_success(
      self, mock_input
  ):
    """Verifies `create_all_dgt_resources` processes all 3 policy categories."""
    # Arrange: Build a plan with both Raw Reader and Default Deny policies.
    del mock_input  # Unused
    plan = {
        "phase_2_resource_manifest": {
            constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS: [
                {"namespaced_name": "my-project/my-key", "api_payload": {}}
            ],
            constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES: [{
                "namespaced_name": "my-project/my-key/my-value",
                "parent_namespaced_name": "my-project/my-key",
                "api_payload": {},
            }],
            constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2: [{
                "policy_id": "raw-policy",
                "region": "us",
                "note": constants.PARITY_RAW_READER,
                "api_payload": {
                    "data_governance_tag": {
                        "key": "my-project/my-key",
                        "value": "my-value",
                    }
                },
            }],
            constants.KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2: [{
                "policy_id": "deny-policy",
                "region": "us",
                "note": constants.PARITY_DEFAULT_DENY,
                "api_payload": {
                    "data_governance_tag": {
                        "key": "my-project/my-key",
                        "value": "my-value",
                    }
                },
            }],
            constants.KEY_DATA_POLICIES_V1_TO_DATA_POLICIES_V2: [],
        }
    }

    with (
        mock.patch.object(
            self.creator,
            "create_dg_tag_key",
            return_value=("tagKeys/123", constants.STATUS_CREATED),
            autospec=True,
        ) as mock_create_key,
        mock.patch.object(
            self.creator,
            "create_dg_tag_value",
            return_value=("tagValues/456", constants.STATUS_CREATED),
            autospec=True,
        ) as mock_create_value,
        mock.patch.object(
            self.creator,
            "create_data_policy_v2",
            return_value=(
                "projects/my-project/locations/us/dataPolicies/policy",
                constants.STATUS_CREATED,
            ),
            autospec=True,
        ) as mock_create_data_policy,
    ):
      # Act: Run batch creation.
      report = self.creator.create_all_dgt_resources(plan)

      # Assert: Both policy categories were created and aggregated.
      mock_create_key.assert_called_once()
      mock_create_value.assert_called_once()
      self.assertEqual(mock_create_data_policy.call_count, 2)
      self.assertIsNotNone(report)
      self.assertIn("Succeeded: 2", report)

  @mock.patch("builtins.input", return_value="n", autospec=True)
  def test_create_all_dgt_resources_aborted(self, mock_input):
    """Verifies declining confirmation aborts `create_all_dgt_resources`."""
    # Arrange: Mock input() to return "n".
    del mock_input  # Unused
    plan = {
        "phase_2_resource_manifest": {
            constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS: [
                {"namespaced_name": "my-project/my-key"}
            ]
        }
    }

    with mock.patch.object(
        self.creator,
        "create_dg_tag_key",
        autospec=True,
    ) as mock_create_key:
      # Act: Call create_all_dgt_resources.
      self.creator.create_all_dgt_resources(plan)

      # Assert: create_dg_tag_key was never invoked.
      mock_create_key.assert_not_called()

  def test_generate_report_section_order_and_headers(self):
    """Verifies `_generate_report` renders Succeeded, Skipped, Failed order."""
    # Arrange & Act: Generate a report with items in all three states.
    report = self.creator._generate_report(
        succeeded_dg_tag_keys={"key1"},
        skipped_dg_tag_keys={"key2"},
        failed_dg_tag_keys={"key3"},
        succeeded_dg_tag_values={"value1"},
        skipped_dg_tag_values={"value2"},
        failed_dg_tag_values={"value3"},
        succeeded_data_policies_v2={"policy1"},
        skipped_data_policies_v2={"policy2"},
        failed_data_policies_v2={"policy3"},
    )
    succeeded_index = report.find("### Succeeded Creations")
    skipped_index = report.find("### Skipped Creations (Already Existed)")
    failed_index = report.find("### Failed Creations")

    # Assert: Section headers exist and appear in Succeeded -> Skipped -> Failed
    # order.
    self.assertNotEqual(succeeded_index, -1)
    self.assertNotEqual(skipped_index, -1)
    self.assertNotEqual(failed_index, -1)
    self.assertLess(succeeded_index, skipped_index)
    self.assertLess(skipped_index, failed_index)

    self.assertIn("#### Data Policies V2", report)
    self.assertNotIn("#### Data Policies\n", report)

  @mock.patch("builtins.input", return_value="n", autospec=True)
  def test_create_individual_dgt_resource_aborted(self, mock_input):
    """Verifies declining confirmation aborts individual resource creation."""
    # Arrange: Mock input() to return "n".
    del mock_input  # Unused
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS: [{
                constants.FIELD_NAMESPACED_NAME: "my-project/my-key",
                constants.FIELD_API_PAYLOAD: {},
            }]
        }
    }
    with mock.patch.object(
        self.creator,
        "create_dg_tag_key",
        autospec=True,
    ) as mock_create_key:
      # Act: Attempt individual Tag Key creation.
      self.creator.create_individual_dgt_resource(
          plan, "my-project/my-key", constants.RESOURCE_TYPE_DG_TAG_KEY
      )

      # Assert: create_dg_tag_key is not called.
      mock_create_key.assert_not_called()

  @mock.patch("builtins.input", return_value="y", autospec=True)
  def test_create_individual_dgt_resource_key(self, mock_input):
    """Verifies `create_individual_dgt_resource` dispatches a DG Tag Key."""
    # Arrange: Prepare a plan with one Tag Key action.
    del mock_input  # Unused
    action = {
        constants.FIELD_NAMESPACED_NAME: "my-project/my-key",
        constants.FIELD_API_PAYLOAD: {},
    }
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS: [action]
        }
    }
    with mock.patch.object(
        self.creator,
        "create_dg_tag_key",
        autospec=True,
    ) as mock_create_key:
      # Act: Create the individual Tag Key.
      self.creator.create_individual_dgt_resource(
          plan, "my-project/my-key", constants.RESOURCE_TYPE_DG_TAG_KEY
      )

      # Assert: create_dg_tag_key was called with the action.
      mock_create_key.assert_called_once_with(action)

  @mock.patch("builtins.input", return_value="y", autospec=True)
  def test_create_individual_dgt_resource_value(self, mock_input):
    """Verifies `create_individual_dgt_resource` dispatches a DG Tag Value."""
    # Arrange: Prepare a plan with one Tag Value action.
    del mock_input  # Unused
    action = {
        constants.FIELD_NAMESPACED_NAME: "my-project/my-key/my-value",
        constants.FIELD_API_PAYLOAD: {},
    }
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES: [action]
        }
    }
    with mock.patch.object(
        self.creator,
        "create_dg_tag_value",
        autospec=True,
    ) as mock_create_value:
      # Act: Create the individual Tag Value.
      self.creator.create_individual_dgt_resource(
          plan,
          "my-project/my-key/my-value",
          constants.RESOURCE_TYPE_DG_TAG_VALUE,
      )

      # Assert: create_dg_tag_value was called with the action.
      mock_create_value.assert_called_once_with(action)

  @mock.patch("builtins.input", return_value="y", autospec=True)
  def test_create_individual_dgt_resource_policy(self, mock_input):
    """Verifies `create_individual_dgt_resource` dispatches a V2 Data Policy."""
    # Arrange: Prepare a plan with one project-qualified Data Policy V2 action.
    del mock_input  # Unused
    action = {
        constants.FIELD_POLICY_ID: "my-policy",
        constants.FIELD_TARGET_PROJECT_ID: "my-project",
        constants.FIELD_API_PAYLOAD: {},
    }
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2: [action]
        }
    }
    with mock.patch.object(
        self.creator,
        "create_data_policy_v2",
        autospec=True,
    ) as mock_create_data_policy:
      # Act: Create the individual V2 Data Policy using <project>/<policy_id>.
      self.creator.create_individual_dgt_resource(
          plan,
          "my-project/my-policy",
          constants.RESOURCE_TYPE_DATA_POLICY_V2,
      )

      # Assert: create_data_policy_v2 was called with the action.
      mock_create_data_policy.assert_called_once_with(action)

  @mock.patch("builtins.input", return_value="y", autospec=True)
  def test_create_individual_data_policy_v2_mode2_ambiguity_raises(
      self, mock_input
  ):
    """Verifies unqualified V2 Data Policy fails and `<project>/<id>` works."""
    action_project_1 = {
        constants.FIELD_POLICY_ID: "shared_policy",
        constants.FIELD_TARGET_PROJECT_ID: "data-project-1",
        constants.FIELD_REGION: "us",
        constants.FIELD_API_PAYLOAD: {},
    }
    action_project_2 = {
        constants.FIELD_POLICY_ID: "shared_policy",
        constants.FIELD_TARGET_PROJECT_ID: "data-project-2",
        constants.FIELD_REGION: "us",
        constants.FIELD_API_PAYLOAD: {},
    }
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2: [
                action_project_1,
                action_project_2,
            ]
        }
    }

    # Unqualified policy_id must fail fast before prompting, listing matching
    # '<target_project_id>/<data_policy_id>' examples.
    with self.assertRaisesRegex(
        ValueError,
        r"Invalid Data Policy V2 resource name 'shared_policy'.*"
        r"'data-project-1/shared_policy', 'data-project-2/shared_policy'",
    ):
      self.creator.create_individual_dgt_resource(
          plan, "shared_policy", constants.RESOURCE_TYPE_DATA_POLICY_V2
      )
    mock_input.assert_not_called()

    # Qualifying with 'data-project-2/shared_policy' selects action_project_2.
    with mock.patch.object(
        self.creator,
        "create_data_policy_v2",
        return_value=("policy-name", constants.STATUS_CREATED),
        autospec=True,
    ) as mock_create_data_policy:
      self.creator.create_individual_dgt_resource(
          plan,
          "data-project-2/shared_policy",
          constants.RESOURCE_TYPE_DATA_POLICY_V2,
      )
      mock_create_data_policy.assert_called_once_with(action_project_2)

  @mock.patch("builtins.input", return_value="y", autospec=True)
  def test_create_individual_dgt_resource_not_found(self, mock_input):
    """Verifies `create_individual_dgt_resource` raises when resource absent."""
    # Arrange: Empty manifest.
    del mock_input  # Unused
    plan = {constants.KEY_PHASE_2_RESOURCE_MANIFEST: {}}

    # Act & Assert: ValueError is raised.
    with self.assertRaises(ValueError):
      self.creator.create_individual_dgt_resource(
          plan, "nonexistent", constants.RESOURCE_TYPE_DG_TAG_KEY
      )

  @mock.patch("builtins.input", return_value="y", autospec=True)
  def test_create_all_dgt_resources_hierarchical_tag_value_failure_cascade(
      self, mock_input
  ):
    """Verifies leaf Tag Value creation failure cascades to V2 Data Policies."""
    # Arrange: Build a hierarchy where root-val succeeds but leaf-val fails.
    del mock_input  # Unused
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS: [{
                "namespaced_name": "my-project/my-key",
                "api_payload": {},
            }],
            constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES: [
                {
                    "namespaced_name": "my-project/my-key/root-val",
                    "parent_namespaced_name": "my-project/my-key",
                    "api_payload": {},
                },
                {
                    "namespaced_name": "my-project/my-key/root-val/leaf-val",
                    "parent_namespaced_name": "my-project/my-key/root-val",
                    "api_payload": {},
                },
            ],
            constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2: [{
                "policy_id": "policy-on-leaf",
                "region": "us",
                "api_payload": {
                    "data_governance_tag": {
                        "key": "my-project/my-key",
                        "value": "leaf-val",
                    }
                },
            }],
        }
    }

    def fake_create_value(action):
      if "leaf-val" in action["namespaced_name"]:
        raise exceptions.InternalServerError("Backend failure on leaf")
      return "tagValues/1", constants.STATUS_CREATED

    with (
        mock.patch.object(
            self.creator,
            "create_dg_tag_key",
            return_value=("tagKeys/1", constants.STATUS_CREATED),
            autospec=True,
        ),
        mock.patch.object(
            self.creator,
            "create_dg_tag_value",
            side_effect=fake_create_value,
            autospec=True,
        ),
        mock.patch.object(
            self.creator,
            "create_data_policy_v2",
            autospec=True,
        ) as mock_create_data_policy,
    ):
      # Act: Run create_all_dgt_resources.
      report = self.creator.create_all_dgt_resources(plan)

      # Assert: Data policy on the failed leaf tag value was skipped and logged
      # under Failed Creations.
      mock_create_data_policy.assert_not_called()
      self.assertIsNotNone(report)
      self.assertIn("policy-on-leaf", report)
      self.assertIn("Failed: 1", report)
      self.assertGreater(self.creator.last_summary["failed"], 0)

  @mock.patch("builtins.input", return_value="y", autospec=True)
  def test_create_all_dgt_resources_tag_key_failure_cascade(self, mock_input):
    """Verifies parent Tag Key failure cascades to child values and policies."""
    # Arrange: Configure create_dg_tag_key to raise PermissionDenied.
    del mock_input  # Unused
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS: [{
                "namespaced_name": "my-project/my-key",
                "api_payload": {},
            }],
            constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES: [{
                "namespaced_name": "my-project/my-key/root-val",
                "parent_namespaced_name": "my-project/my-key",
                "api_payload": {},
            }],
            constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2: [{
                "policy_id": "policy-on-root",
                "region": "us",
                "api_payload": {
                    "data_governance_tag": {
                        "key": "my-project/my-key",
                        "value": "root-val",
                    }
                },
            }],
        }
    }

    with (
        mock.patch.object(
            self.creator,
            "create_dg_tag_key",
            side_effect=exceptions.PermissionDenied("Denied"),
            autospec=True,
        ),
        mock.patch.object(
            self.creator,
            "create_dg_tag_value",
            autospec=True,
        ) as mock_create_value,
        mock.patch.object(
            self.creator,
            "create_data_policy_v2",
            autospec=True,
        ) as mock_create_data_policy,
    ):
      # Act: Run create_all_dgt_resources.
      report = self.creator.create_all_dgt_resources(plan)

      # Assert: Neither child Tag Values nor V2 Data Policies were called.
      mock_create_value.assert_not_called()
      mock_create_data_policy.assert_not_called()
      self.assertIsNotNone(report)
      self.assertIn("policy-on-root", report)

  # =========================================================================
  # === Section 4: V2 REST Transport Fallback & Retry Resilience Tests ===
  # =========================================================================

  @mock.patch("urllib.request.urlopen", autospec=True)
  @mock.patch("google.auth.default", autospec=True)
  def test_create_data_policy_v2_rest_fallback(self, mock_auth, mock_urlopen):
    """Verifies `create_data_policy_v2` falls back to `/v2/` REST POST."""
    # Arrange: Configure GAPIC create_data_policy to fail and mock REST 200.
    self.mock_data_policy_v2_client.get_data_policy.side_effect = (
        exceptions.NotFound("Not found")
    )
    self.mock_data_policy_v2_client.create_data_policy.side_effect = (
        exceptions.InvalidArgument(
            "Unknown field for DataPolicy: data_governance_tag"
        )
    )
    mock_credentials = mock.create_autospec(
        auth_credentials.Credentials, instance=True, spec_set=False
    )
    mock_credentials.token = "fake-token"
    mock_auth.return_value = (mock_credentials, "fake-project")

    mock_urlopen.return_value = _make_urlopen_response(
        b'{"name": "projects/my-project/locations/us/dataPolicies/my-policy"}'
    )

    action = {
        "policy_id": "my-policy",
        "region": "us",
        "target_project_id": "my-project",
        "api_payload": {
            "data_governance_tag": {
                "key": "my-project/my-key",
                "value": "my-value",
            },
            "data_policy_type": "RAW_DATA_ACCESS_POLICY",
        },
    }

    # Act: Call create_data_policy_v2.
    policy_name, status = self.creator.create_data_policy_v2(action)

    # Assert: REST fallback succeeded and returned STATUS_CREATED.
    self.assertEqual(
        policy_name,
        "projects/my-project/locations/us/dataPolicies/my-policy",
    )
    self.assertEqual(status, constants.STATUS_CREATED)
    mock_urlopen.assert_called_once()

  def test_generate_report_with_error_details(self):
    """Verifies `_generate_report` renders per-resource error strings."""
    # Arrange & Act: Pass failure dicts with error strings.
    report = self.creator._generate_report(
        succeeded_dg_tag_keys=set(),
        skipped_dg_tag_keys=set(),
        failed_dg_tag_keys={"my-key": "403 PermissionDenied"},
        succeeded_dg_tag_values=set(),
        skipped_dg_tag_values=set(),
        failed_dg_tag_values={"my-key/my-value": "Parent 'my-key' failed"},
        succeeded_data_policies_v2=set(),
        skipped_data_policies_v2=set(),
        failed_data_policies_v2={"my-policy": "400 InvalidArgument"},
    )

    # Assert: Each resource failure reason is rendered in the Markdown output.
    self.assertIn("- my-key: 403 PermissionDenied", report)
    self.assertIn("- my-key/my-value: Parent 'my-key' failed", report)
    self.assertIn("- my-policy: 400 InvalidArgument", report)

  @mock.patch("builtins.input", return_value="y", autospec=True)
  def test_create_all_dgt_resources_saves_report_file(self, mock_input):
    """Verifies `create_all_dgt_resources` writes Markdown report to disk."""
    # Arrange: Create a temporary directory and mock Tag Key creation.
    del mock_input  # Unused
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS: [{
                constants.FIELD_NAMESPACED_NAME: "my-project/my-key",
                constants.FIELD_API_PAYLOAD: {},
            }]
        }
    }
    with tempfile.TemporaryDirectory() as temp_dir:
      report_path = os.path.join(temp_dir, "report.md")
      with mock.patch.object(
          self.creator,
          "create_dg_tag_key",
          return_value=("tagKeys/123", constants.STATUS_CREATED),
          autospec=True,
      ):
        # Act: Run create_all_dgt_resources with report_file.
        report = self.creator.create_all_dgt_resources(
            plan, report_file=report_path
        )

      # Assert: The report file exists on disk and matches the returned report.
      self.assertIsNotNone(report)
      self.assertTrue(os.path.exists(report_path))
      with open(report_path, "r", encoding="utf-8") as file_handle:
        saved_content = file_handle.read()
      self.assertEqual(saved_content, report)
      self.assertIn("my-project/my-key", saved_content)

  @mock.patch("builtins.input", return_value="y", autospec=True)
  def test_create_all_dgt_resources_saves_report_file_on_halt(self, mock_input):
    """Verifies `create_all_dgt_resources` writes partial report on halt."""
    # Arrange: Instantiate Creator with halt_on_error=True and raise an error.
    del mock_input  # Unused
    creator_with_halt = creator.Creator(
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        halt_on_error=True,
    )
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS: [{
                constants.FIELD_NAMESPACED_NAME: "my-project/my-key",
                constants.FIELD_API_PAYLOAD: {},
            }]
        }
    }
    with tempfile.TemporaryDirectory() as temp_dir:
      report_path = os.path.join(temp_dir, "report.md")
      with mock.patch.object(
          creator_with_halt,
          "create_dg_tag_key",
          side_effect=exceptions.PermissionDenied("Access Denied"),
          autospec=True,
      ):
        # Act: Run creation expecting PermissionDenied to propagate.
        with self.assertRaises(exceptions.PermissionDenied):
          creator_with_halt.create_all_dgt_resources(
              plan, report_file=report_path
          )

      # Assert: The partial failure report was saved to report_path.
      self.assertTrue(os.path.exists(report_path))
      with open(report_path, "r", encoding="utf-8") as file_handle:
        saved_content = file_handle.read()
      self.assertIn("Failed Creations", saved_content)
      self.assertIn("my-project/my-key", saved_content)
      self.assertIn("Access Denied", saved_content)

  @mock.patch("builtins.input", return_value="y", autospec=True)
  def test_create_individual_dgt_resource_saves_report_file(self, mock_input):
    """Verifies `create_individual_dgt_resource` writes report to disk."""
    # Arrange: Prepare a single Tag Key plan and temporary report path.
    del mock_input  # Unused
    action = {
        constants.FIELD_NAMESPACED_NAME: "my-project/my-key",
        constants.FIELD_API_PAYLOAD: {},
    }
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS: [action]
        }
    }
    with tempfile.TemporaryDirectory() as temp_dir:
      report_path = os.path.join(temp_dir, "report.md")
      with mock.patch.object(
          self.creator,
          "create_dg_tag_key",
          return_value=("tagKeys/123", constants.STATUS_CREATED),
          autospec=True,
      ):
        # Act: Create the individual resource with report_file.
        self.creator.create_individual_dgt_resource(
            plan,
            "my-project/my-key",
            constants.RESOURCE_TYPE_DG_TAG_KEY,
            report_file=report_path,
        )

      # Assert: The individual creation report was saved with the resource ID.
      self.assertTrue(os.path.exists(report_path))
      with open(report_path, "r", encoding="utf-8") as file_handle:
        saved_content = file_handle.read()
      self.assertIn("my-project/my-key", saved_content)
      self.assertIn("tagKeys/123", saved_content)

  # =========================================================================
  # === Section 5: Dry-Run Pre-Flight Inspection & Edge Case Tests ===
  # =========================================================================

  @mock.patch("builtins.input", autospec=True)
  def test_dry_run_create_all_dgt_resources_does_not_mutate_and_reports_issues(
      self, mock_input
  ):
    """Verifies dry-run batch creation mutates nothing and reports warnings."""
    # Arrange: Configure dry_run Creator with one existing key and one new key.
    dry_run_creator = creator.Creator(
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        dry_run=True,
    )
    existing_key = types.SimpleNamespace(
        name="tagKeys/111", short_name="existing_key", purpose=2
    )
    self.mock_tag_keys_client.list_tag_keys.return_value = [existing_key]
    self.mock_tag_values_client.list_tag_values.return_value = []
    self.mock_data_policy_v2_client.get_data_policy.side_effect = (
        exceptions.NotFound("Not found")
    )

    plan = {
        "warnings": ["Plan-level multi-region warning."],
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS: [
                {
                    constants.FIELD_NAMESPACED_NAME: "my-project/existing_key",
                    constants.FIELD_API_PAYLOAD: {
                        "parent": "projects/my-project",
                        "short_name": "existing_key",
                    },
                },
                {
                    constants.FIELD_NAMESPACED_NAME: "my-project/new_key",
                    constants.FIELD_API_PAYLOAD: {
                        "parent": "projects/my-project",
                        "short_name": "new_key",
                    },
                },
            ],
            constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES: [
                {
                    constants.FIELD_NAMESPACED_NAME: (
                        "my-project/new_key/root_value"
                    ),
                    constants.FIELD_PARENT_NAMESPACED_NAME: (
                        "my-project/new_key"
                    ),
                    constants.FIELD_API_PAYLOAD: {
                        "short_name": "root_value",
                    },
                },
                {
                    constants.FIELD_NAMESPACED_NAME: (
                        "my-project/new_key/root_value/child_value"
                    ),
                    constants.FIELD_PARENT_NAMESPACED_NAME: (
                        "my-project/new_key/root_value"
                    ),
                    constants.FIELD_API_PAYLOAD: {
                        "short_name": "child_value",
                    },
                },
            ],
            constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2: [{
                constants.FIELD_POLICY_ID: "new_raw_policy",
                constants.FIELD_REGION: "us",
                constants.FIELD_TARGET_PROJECT_ID: "my-project",
                constants.FIELD_API_PAYLOAD: {
                    "data_governance_tag": {
                        "key": "my-project/new_key",
                        "value": "child_value",
                    },
                    "data_policy_type": "RAW_DATA_ACCESS_POLICY",
                },
            }],
        },
    }

    # Act: Run dry-run batch creation.
    report = dry_run_creator.create_all_dgt_resources(plan)

    # Assert: Zero mutation RPCs were called and all sections are populated.
    mock_input.assert_not_called()
    self.mock_tag_keys_client.create_tag_key.assert_not_called()
    self.mock_tag_values_client.create_tag_value.assert_not_called()
    self.mock_data_policy_v2_client.create_data_policy.assert_not_called()

    self.assertIsNotNone(report)
    self.assertIn("(DRY RUN)", report)
    self.assertIn("### Resources That Would Be Created", report)
    self.assertIn("my-project/new_key", report)
    self.assertIn("my-project/new_key/root_value", report)
    self.assertIn("my-project/new_key/root_value/child_value", report)
    self.assertIn("- my-project/new_raw_policy", report)
    self.assertIn("### Resources That Would Be Skipped (Already Exist)", report)
    self.assertIn("my-project/existing_key", report)
    self.assertIn("### Potential Issues & Warnings", report)
    self.assertIn("Plan-level multi-region warning.", report)

  @mock.patch("builtins.input", autospec=True)
  def test_dry_run_create_individual_value_missing_parent_reports_blocker(
      self, mock_input
  ):
    """Verifies dry-run individual value preview reports missing parent key."""
    # Arrange: Configure list_tag_keys to return empty list in dry-run mode.
    dry_run_creator = creator.Creator(
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        dry_run=True,
    )
    self.mock_tag_keys_client.list_tag_keys.return_value = []

    action = {
        constants.FIELD_NAMESPACED_NAME: "my-project/missing_key/my_value",
        constants.FIELD_PARENT_NAMESPACED_NAME: "my-project/missing_key",
        constants.FIELD_API_PAYLOAD: {"short_name": "my_value"},
    }
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES: [action]
        }
    }

    # Act: Run dry-run individual creation for the child Tag Value.
    report = dry_run_creator.create_individual_dgt_resource(
        plan,
        "my-project/missing_key/my_value",
        constants.RESOURCE_TYPE_DG_TAG_VALUE,
    )

    # Assert: The missing parent is reported under Failed Pre-Flight Checks.
    mock_input.assert_not_called()
    self.mock_tag_values_client.create_tag_value.assert_not_called()
    self.assertIsNotNone(report)
    self.assertIn("### Failed Pre-Flight Checks / Blockers", report)
    self.assertIn("my-project/missing_key", report)
    self.assertIn("### Potential Issues & Warnings", report)

  def test_create_dg_tag_key_rejects_existing_non_data_governance_purpose(self):
    """Verifies `create_dg_tag_key` rejects existing non-DG purpose Tag Keys."""
    # Arrange: Return a Tag Key with purpose=1 (GCE_FIREWALL).
    mock_key = types.SimpleNamespace(
        short_name="my_key", name="tagKeys/123", purpose=1
    )
    self.mock_tag_keys_client.list_tag_keys.return_value = [mock_key]

    action = {
        constants.FIELD_NAMESPACED_NAME: "my-project/my_key",
        constants.FIELD_API_PAYLOAD: {
            "parent": "projects/my-project",
            "short_name": "my_key",
            "purpose": "DATA_GOVERNANCE",
        },
    }

    # Act & Assert: ValueError is raised explaining the purpose mismatch.
    with self.assertRaisesRegex(ValueError, "non-DATA_GOVERNANCE purpose"):
      self.creator.create_dg_tag_key(action)

  def test_get_dg_tag_value_id_filters_nested_descendants(self):
    """Verifies `_get_dg_tag_value_id` ignores nested values with same name."""
    # Arrange: Return two Tag Values with identical short_name under different
    # parents.
    mock_key = types.SimpleNamespace(
        short_name="my_key", name="tagKeys/123", purpose=2
    )
    self.mock_tag_keys_client.list_tag_keys.return_value = [mock_key]

    root_value = types.SimpleNamespace(
        parent="tagKeys/123",
        short_name="shared_name",
        name="tagValues/root_100",
    )
    nested_value = types.SimpleNamespace(
        parent="tagValues/other_parent",
        short_name="shared_name",
        name="tagValues/nested_999",
    )
    self.mock_tag_values_client.list_tag_values.return_value = [
        root_value,
        nested_value,
    ]

    # Act: Look up the direct child Tag Value under my_key.
    resolved_id = self.creator._get_dg_tag_value_id(
        "my-project/my_key/shared_name"
    )

    # Assert: The direct child (tagValues/root_100) is selected.
    self.assertEqual(resolved_id, "tagValues/root_100")

  @mock.patch("builtins.input", autospec=True)
  def test_skip_confirmation_bypasses_prompts(self, mock_input):
    """Verifies `skip_confirmation=True` bypasses interactive `input()`."""
    # Arrange: Configure Creator with skip_confirmation=True.
    non_interactive_creator = creator.Creator(
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        skip_confirmation=True,
    )
    mock_key = types.SimpleNamespace(
        short_name="my_key", name="tagKeys/123", purpose=2
    )
    self.mock_tag_keys_client.list_tag_keys.return_value = [mock_key]

    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS: [{
                constants.FIELD_NAMESPACED_NAME: "my-project/my_key",
                constants.FIELD_API_PAYLOAD: {
                    "parent": "projects/my-project",
                    "short_name": "my_key",
                },
            }]
        }
    }

    # Act: Run create_all_dgt_resources.
    report = non_interactive_creator.create_all_dgt_resources(plan)

    # Assert: input() was never called.
    mock_input.assert_not_called()
    self.assertIsNotNone(report)

  def test_collect_action_validation_issues_warnings_and_unknown_project(self):
    """Verifies `_collect_action_validation_issues` catches routine markers."""
    # Arrange: Build an action with warnings and an unresolved routine path.
    action = {
        constants.FIELD_POLICY_ID: "masking_policy_1",
        constants.FIELD_WARNINGS: ["Warning [DR_WARN_03]: replicate routine."],
        constants.FIELD_WARNING: "Single legacy warning.",
        constants.FIELD_API_PAYLOAD: {
            "data_masking_policy": {
                "routine": (
                    "projects/<unknown-project-123>/datasets/d/routines/r"
                )
            }
        },
    }

    # Act: Collect validation issues for the action.
    issues = self.creator._collect_action_validation_issues(
        action, constants.RESOURCE_TYPE_DATA_POLICY_V2
    )

    # Assert: Both warnings and the placeholder error are returned with the
    # resource identifier prefixed so report readers can identify the policy.
    self.assertTrue(
        any(
            "[masking_policy_1] Plan warning: Warning [DR_WARN_03]" in issue
            for issue in issues
        )
    )
    self.assertTrue(
        any(
            "[masking_policy_1] Plan warning: Single legacy warning." in issue
            for issue in issues
        )
    )
    self.assertTrue(any("<unknown-project-...>" in issue for issue in issues))

  def test_dry_run_individual_data_policy_checks_dg_tag_value_existence(self):
    """Verifies dry-run policy preview warns when its DG Tag Value is absent."""
    # Arrange: Configure Tag Key to exist while Tag Value is missing.
    dry_run_creator = creator.Creator(
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        dry_run=True,
    )
    mock_key = types.SimpleNamespace(
        short_name="my_key", name="tagKeys/123", purpose=2
    )
    self.mock_tag_keys_client.list_tag_keys.return_value = [mock_key]
    self.mock_tag_values_client.list_tag_values.return_value = []
    self.mock_data_policy_v2_client.get_data_policy.side_effect = (
        exceptions.NotFound("Not found")
    )

    action = {
        constants.FIELD_POLICY_ID: "raw_policy_1",
        constants.FIELD_REGION: "us",
        constants.FIELD_TARGET_PROJECT_ID: "my-project",
        constants.FIELD_DG_TAG_VALUE_NAMESPACED_NAME: (
            "my-project/my_key/missing_value"
        ),
        constants.FIELD_API_PAYLOAD: {
            "data_governance_tag": {
                "key": "my-project/my_key",
                "value": "missing_value",
            }
        },
    }
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2: [action]
        }
    }

    # Act: Run dry-run creation for the individual Data Policy.
    report = dry_run_creator.create_individual_dgt_resource(
        plan,
        "my-project/raw_policy_1",
        constants.RESOURCE_TYPE_DATA_POLICY_V2,
    )

    # Assert: The report warns that the referenced Tag Value does not exist yet.
    self.assertIsNotNone(report)
    self.assertIn(
        "Referenced DG Tag Value 'my-project/my_key/missing_value' does not"
        " exist in GCP yet.",
        report,
    )

  @mock.patch("time.sleep", autospec=True)
  @mock.patch("urllib.request.urlopen", autospec=True)
  @mock.patch("google.auth.default", autospec=True)
  def test_create_data_policy_v2_rest_retries_transient_503(
      self, mock_auth, mock_urlopen, mock_sleep
  ):
    """Verifies `_create_data_policy_v2_rest` retries transient HTTP 503."""
    # Arrange: Configure urlopen to fail once with 503 and succeed on attempt 2.
    self.mock_data_policy_v2_client.get_data_policy.side_effect = (
        exceptions.NotFound("Not found")
    )
    self.mock_data_policy_v2_client.create_data_policy.side_effect = (
        exceptions.InvalidArgument(
            "Unknown field for DataPolicy: data_governance_tag"
        )
    )
    mock_credentials = mock.create_autospec(
        auth_credentials.Credentials, instance=True, spec_set=False
    )
    mock_credentials.token = "fake-token"
    mock_auth.return_value = (mock_credentials, "fake-project")

    http_503 = urllib.error.HTTPError(
        url="https://bigquerydatapolicy.googleapis.com/v2/...",
        code=503,
        msg="Service Unavailable",
        hdrs=None,
        fp=io.BytesIO(b"backend transient error"),
    )
    success_context_manager = _make_urlopen_response(
        b'{"name": "projects/my-project/locations/us/dataPolicies/my-policy"}'
    )
    mock_urlopen.side_effect = [http_503, success_context_manager]

    action = {
        "policy_id": "my-policy",
        "region": "us",
        "target_project_id": "my-project",
        "api_payload": {
            "data_governance_tag": {
                "key": "my-project/my-key",
                "value": "my-value",
            },
            "data_policy_type": "RAW_DATA_ACCESS_POLICY",
        },
    }

    # Act: Create the Data Policy via REST fallback.
    policy_name, status = self.creator.create_data_policy_v2(action)

    # Assert: Two HTTP attempts were made with a 1.0s backoff sleep.
    self.assertEqual(
        policy_name,
        "projects/my-project/locations/us/dataPolicies/my-policy",
    )
    self.assertEqual(status, constants.STATUS_CREATED)
    self.assertEqual(mock_urlopen.call_count, 2)
    mock_sleep.assert_called_once_with(1.0)

  @mock.patch("urllib.request.urlopen", autospec=True)
  @mock.patch("google.auth.default", autospec=True)
  def test_create_data_policy_v2_rest_409_returns_skipped(
      self, mock_auth, mock_urlopen
  ):
    """Verifies `_create_data_policy_v2_rest` maps HTTP 409 to SKIPPED."""
    # Arrange: Configure urlopen to raise HTTP 409.
    self.mock_data_policy_v2_client.get_data_policy.side_effect = (
        exceptions.NotFound("Not found")
    )
    self.mock_data_policy_v2_client.create_data_policy.side_effect = (
        exceptions.InvalidArgument(
            "Unknown field for DataPolicy: data_governance_tag"
        )
    )
    mock_credentials = mock.create_autospec(
        auth_credentials.Credentials, instance=True, spec_set=False
    )
    mock_credentials.token = "fake-token"
    mock_auth.return_value = (mock_credentials, "fake-project")

    http_409 = urllib.error.HTTPError(
        url="https://bigquerydatapolicy.googleapis.com/v2/...",
        code=409,
        msg="Conflict",
        hdrs=None,
        fp=io.BytesIO(b"Already exists"),
    )
    mock_urlopen.side_effect = http_409

    action = {
        "policy_id": "my-policy",
        "region": "us",
        "target_project_id": "my-project",
        "api_payload": {
            "data_governance_tag": {
                "key": "my-project/my-key",
                "value": "my-value",
            },
            "data_policy_type": "RAW_DATA_ACCESS_POLICY",
        },
    }

    # Act: Create the Data Policy via REST fallback.
    policy_name, status = self.creator.create_data_policy_v2(action)

    # Assert: Returns STATUS_SKIPPED on HTTP 409 Conflict.
    self.assertEqual(
        policy_name,
        "projects/my-project/locations/us/dataPolicies/my-policy",
    )
    self.assertEqual(status, constants.STATUS_SKIPPED)

  # =========================================================================
  # === Section 6: Negative-Lookup Caching & V2 GET REST Fallback Tests ===
  # =========================================================================

  def test_get_dg_tag_key_id_negative_lookup_skips_relisting_project(self):
    """Verifies `_listed_tag_key_projects` prevents repeated `list_tag_keys`."""
    # Arrange: Return one key in "my-project" so "missing-1" and "missing-2"
    # are both absent.
    existing_key = types.SimpleNamespace(
        name="tagKeys/100", short_name="existing-key", purpose=2
    )
    self.mock_tag_keys_client.list_tag_keys.return_value = [existing_key]

    # Act: Look up two different missing Tag Keys in the same project.
    first_lookup = self.creator._get_dg_tag_key_id("my-project/missing-1")
    second_lookup = self.creator._get_dg_tag_key_id("my-project/missing-2")

    # Assert: Both return None, my-project is recorded in
    # _listed_tag_key_projects, and list_tag_keys was called only once.
    self.assertIsNone(first_lookup)
    self.assertIsNone(second_lookup)
    self.assertIn("my-project", self.creator._listed_tag_key_projects)
    self.mock_tag_keys_client.list_tag_keys.assert_called_once_with(
        parent="projects/my-project", retry=creator.RETRY_CONFIG
    )

  def test_get_dg_tag_value_id_negative_lookup_and_post_create_cache(self):
    """Verifies `_listed_tag_value_parents` avoids redundant value list RPCs."""
    # Arrange: Configure create_tag_key and create_tag_value LROs for a brand
    # new Tag Key and two sibling Tag Values under it.
    self.mock_tag_keys_client.list_tag_keys.return_value = []
    key_operation = mock.create_autospec(
        api_core_operation.Operation, instance=True, spec_set=True
    )
    key_operation.result.return_value = types.SimpleNamespace(
        name="tagKeys/500"
    )
    self.mock_tag_keys_client.create_tag_key.return_value = key_operation

    val_operation_1 = mock.create_autospec(
        api_core_operation.Operation, instance=True, spec_set=True
    )
    val_operation_1.result.return_value = types.SimpleNamespace(
        name="tagValues/601"
    )
    val_operation_2 = mock.create_autospec(
        api_core_operation.Operation, instance=True, spec_set=True
    )
    val_operation_2.result.return_value = types.SimpleNamespace(
        name="tagValues/602"
    )
    self.mock_tag_values_client.create_tag_value.side_effect = [
        val_operation_1,
        val_operation_2,
    ]

    # Act: Create the parent Tag Key, then create two sibling child Tag Values
    # under that newly created Tag Key.
    key_id, key_status = self.creator.create_dg_tag_key({
        "namespaced_name": "my-project/new-key",
        "api_payload": {"short_name": "new-key"},
    })
    val_id_1, val_status_1 = self.creator.create_dg_tag_value({
        "namespaced_name": "my-project/new-key/val-1",
        "parent_namespaced_name": "my-project/new-key",
        "api_payload": {"short_name": "val-1"},
    })
    val_id_2, val_status_2 = self.creator.create_dg_tag_value({
        "namespaced_name": "my-project/new-key/val-2",
        "parent_namespaced_name": "my-project/new-key",
        "api_payload": {"short_name": "val-2"},
    })

    # Assert: All three creations succeeded, and list_tag_values was never
    # called because tagKeys/500 was added to _listed_tag_value_parents on
    # creation.
    self.assertEqual((key_id, key_status), ("tagKeys/500", "CREATED"))
    self.assertEqual((val_id_1, val_status_1), ("tagValues/601", "CREATED"))
    self.assertEqual((val_id_2, val_status_2), ("tagValues/602", "CREATED"))
    self.assertIn("tagKeys/500", self.creator._listed_tag_value_parents)
    self.assertIn("tagValues/601", self.creator._listed_tag_value_parents)
    self.assertIn("tagValues/602", self.creator._listed_tag_value_parents)
    self.mock_tag_values_client.list_tag_values.assert_not_called()

  @mock.patch("urllib.request.urlopen", autospec=True)
  @mock.patch("google.auth.default", autospec=True)
  def test_create_data_policy_v2_get_rest_fallback_skips_existing_policy(
      self, mock_auth, mock_urlopen
  ):
    """Verifies `create_data_policy_v2` falls back to `/v2/` REST GET."""
    # Arrange: Configure GAPIC get_data_policy to raise InvalidArgument and
    # mock REST GET returning HTTP 200 for an existing V2 Data Policy.
    self.mock_data_policy_v2_client.get_data_policy.side_effect = (
        exceptions.InvalidArgument("V2 policy requires /v2/ REST endpoint")
    )
    mock_credentials = mock.create_autospec(
        auth_credentials.Credentials, instance=True, spec_set=False
    )
    mock_credentials.token = "fake-token"
    mock_auth.return_value = (mock_credentials, "fake-project")
    mock_urlopen.return_value = _make_urlopen_response(
        b'{"name": "projects/my-project/locations/us/dataPolicies/my-policy"}'
    )

    action = {
        "policy_id": "my-policy",
        "region": "us",
        "target_project_id": "my-project",
        "api_payload": {
            "data_governance_tag": {
                "key": "my-project/my-key",
                "value": "my-value",
            }
        },
    }

    # Act: Call create_data_policy_v2.
    policy_name, status = self.creator.create_data_policy_v2(action)

    # Assert: Returns STATUS_SKIPPED without invoking create_data_policy.
    self.assertEqual(
        policy_name,
        "projects/my-project/locations/us/dataPolicies/my-policy",
    )
    self.assertEqual(status, constants.STATUS_SKIPPED)
    self.mock_data_policy_v2_client.create_data_policy.assert_not_called()
    mock_urlopen.assert_called_once()

  @mock.patch("urllib.request.urlopen", autospec=True)
  @mock.patch("google.auth.default", autospec=True)
  def test_create_data_policy_v2_get_rest_fallback_404_proceeds_to_create(
      self, mock_auth, mock_urlopen
  ):
    """Verifies REST GET 404 proceeds to REST POST creation."""
    # Arrange: Configure GAPIC get_data_policy to raise TypeError and GAPIC
    # create_data_policy to raise ValueError; mock REST GET 404 followed by
    # REST POST 200.
    self.mock_data_policy_v2_client.get_data_policy.side_effect = TypeError(
        "Incompatible proto descriptor"
    )
    self.mock_data_policy_v2_client.create_data_policy.side_effect = ValueError(
        "Unknown field data_governance_tag"
    )
    mock_credentials = mock.create_autospec(
        auth_credentials.Credentials, instance=True, spec_set=False
    )
    mock_credentials.token = "fake-token"
    mock_auth.return_value = (mock_credentials, "fake-project")

    http_404 = urllib.error.HTTPError(
        url="https://bigquerydatapolicy.googleapis.com/v2/...",
        code=404,
        msg="Not Found",
        hdrs=None,
        fp=io.BytesIO(b"Not found"),
    )
    post_200 = _make_urlopen_response(
        b'{"name": "projects/my-project/locations/us/dataPolicies/my-policy"}'
    )
    mock_urlopen.side_effect = [http_404, post_200]

    action = {
        "policy_id": "my-policy",
        "region": "us",
        "target_project_id": "my-project",
        "api_payload": {
            "data_governance_tag": {
                "key": "my-project/my-key",
                "value": "my-value",
            }
        },
    }

    # Act: Call create_data_policy_v2.
    policy_name, status = self.creator.create_data_policy_v2(action)

    # Assert: REST GET 404 triggered REST POST creation and returned CREATED.
    self.assertEqual(
        policy_name,
        "projects/my-project/locations/us/dataPolicies/my-policy",
    )
    self.assertEqual(status, constants.STATUS_CREATED)
    self.assertEqual(mock_urlopen.call_count, 2)

  def test_generate_report_renders_error_status_reference_on_failure(self):
    """Renders failure status explanations only when creation errors occur."""
    # Clean runs with zero failed resources omit the error reference section.
    clean_report = self.creator._generate_report(
        succeeded_dg_tag_keys={"my-project/key1"},
        skipped_dg_tag_keys=set(),
        failed_dg_tag_keys={},
        succeeded_dg_tag_values=set(),
        skipped_dg_tag_values=set(),
        failed_dg_tag_values={},
        succeeded_data_policies_v2=set(),
        skipped_data_policies_v2=set(),
        failed_data_policies_v2={},
    )
    self.assertNotIn("### Error & Failure Status Reference", clean_report)

    # Live failure runs explain the `Failed` status token in the report.
    live_failed_report = self.creator._generate_report(
        succeeded_dg_tag_keys=set(),
        skipped_dg_tag_keys=set(),
        failed_dg_tag_keys={"my-project/key1": "PermissionDenied"},
        succeeded_dg_tag_values=set(),
        skipped_dg_tag_values=set(),
        failed_dg_tag_values={},
        succeeded_data_policies_v2=set(),
        skipped_data_policies_v2=set(),
        failed_data_policies_v2={},
    )
    self.assertIn("### Error & Failure Status Reference", live_failed_report)
    self.assertIn("- **`Failed`:**", live_failed_report)

    # Dry-run blocker runs explain the `Failed / Blocked` status token.
    dry_run_creator = creator.Creator(
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        dry_run=True,
    )
    dry_run_failed_report = dry_run_creator._generate_report(
        succeeded_dg_tag_keys=set(),
        skipped_dg_tag_keys=set(),
        failed_dg_tag_keys={"my-project/key1": "Invalid short_name"},
        succeeded_dg_tag_values=set(),
        skipped_dg_tag_values=set(),
        failed_dg_tag_values={},
        succeeded_data_policies_v2=set(),
        skipped_data_policies_v2=set(),
        failed_data_policies_v2={},
    )
    self.assertIn("### Error & Failure Status Reference", dry_run_failed_report)
    self.assertIn("- **`Failed / Blocked`:**", dry_run_failed_report)

  @mock.patch("builtins.input", autospec=True)
  def test_create_individual_data_policy_v2_mode1_unqualified_raises(
      self, mock_input
  ):
    """Rejects bare `<data_policy_id>` in Mode 1 before prompting."""
    # Single centralized Mode 1 project still requires `<project>/<policy_id>`.
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2: [{
                constants.FIELD_POLICY_ID: "raw_policy",
                constants.FIELD_TARGET_PROJECT_ID: "gov-project",
                constants.FIELD_REGION: "us",
                constants.FIELD_API_PAYLOAD: {},
            }]
        }
    }

    # Format check runs prior to interactive prompt so invalid input fails fast.
    with self.assertRaisesRegex(
        ValueError,
        r"Invalid Data Policy V2 resource name 'raw_policy'.*"
        r"'gov-project/raw_policy'",
    ):
      self.creator.create_individual_dgt_resource(
          plan, "raw_policy", constants.RESOURCE_TYPE_DATA_POLICY_V2
      )

    # Confirm neither `input()` nor any Data Policy RPC was invoked.
    mock_input.assert_not_called()
    self.mock_data_policy_v2_client.create_data_policy.assert_not_called()

  @mock.patch("builtins.input", autospec=True)
  def test_create_all_blocks_on_unresolved_action_required_plan_warning(
      self, mock_input
  ):
    """Blocks `create_all_dgt_resources` when `[ACTION REQUIRED]` remains."""
    # Seed an unresolved `[ACTION REQUIRED]` warning on a planned Tag Key.
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS: [{
                constants.FIELD_NAMESPACED_NAME: "my-project/invalid_key",
                constants.FIELD_API_PAYLOAD: {"short_name": "invalid_key"},
                constants.FIELD_WARNINGS: [
                    "[ACTION REQUIRED] Tag Key short_name exceeds 63 chars."
                ],
            }]
        }
    }

    # Default fail-closed gate blocks before prompting or mutating cloud state.
    report = self.creator.create_all_dgt_resources(plan)

    # Summary records the blocking warning count as failed so CLI exits with 1.
    mock_input.assert_not_called()
    self.mock_tag_keys_client.create_tag_key.assert_not_called()
    self.assertEqual(self.creator.last_summary["failed"], 1)
    self.assertIsNotNone(report)
    self.assertIn(constants.STATUS_BLOCKED_UNRESOLVED_PLAN_WARNINGS, report)
    self.assertIn("Tag Key short_name exceeds 63 chars.", report)

  def test_create_all_allow_unresolved_plan_warnings_continues_valid_items(
      self,
  ):
    """Continues creating valid resources when plan warnings are overridden."""
    # Enable `allow_unresolved_plan_warnings` alongside `skip_confirmation` so
    # broken_key fails API creation while valid_key still provisions cleanly.
    override_creator = creator.Creator(
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        skip_confirmation=True,
        allow_unresolved_plan_warnings=True,
    )
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS: [
                {
                    constants.FIELD_NAMESPACED_NAME: "my-project/broken_key",
                    constants.FIELD_API_PAYLOAD: {"short_name": "broken_key"},
                    constants.FIELD_WARNINGS: [
                        "[ACTION REQUIRED] Invalid Tag Key short_name."
                    ],
                },
                {
                    constants.FIELD_NAMESPACED_NAME: "my-project/valid_key",
                    constants.FIELD_API_PAYLOAD: {"short_name": "valid_key"},
                },
            ]
        }
    }

    def fake_create_key(action):
      if action[constants.FIELD_NAMESPACED_NAME] == "my-project/broken_key":
        raise RuntimeError("Invalid short_name rejected by API")
      return ("tagKeys/200", constants.STATUS_CREATED)

    # Exercise batch creation with one failing broken_key and one valid_key.
    with mock.patch.object(
        override_creator,
        "create_dg_tag_key",
        side_effect=fake_create_key,
        autospec=True,
    ):
      report = override_creator.create_all_dgt_resources(plan)

    # Verify valid_key succeeded even though broken_key failed, and the
    # overridden `[ACTION REQUIRED]` warning is surfaced in the report.
    self.assertEqual(override_creator.last_summary["succeeded"], 1)
    self.assertEqual(override_creator.last_summary["failed"], 1)
    self.assertIn("my-project/valid_key", report)
    self.assertIn("Overridden Plan Warning:", report)

  # Pre-flight validation must flag custom masking routines whose project ID
  # differs from the V2 Data Policy's `target_project_id`.
  def test_collect_action_validation_issues_flags_cross_project_routine(self):
    """Flags V2 Data Policy actions whose custom routine is in another proj."""
    # Action targets `secondary-project` while its routine lives in
    # `primary-project`.
    cross_project_action = {
        constants.FIELD_POLICY_ID: "migrated_masking_phone",
        constants.FIELD_TARGET_PROJECT_ID: "secondary-project",
        constants.FIELD_API_PAYLOAD: {
            "data_masking_policy": {
                "routine": (
                    "projects/primary-project/datasets/gov_us/routines/mask_fn"
                )
            }
        },
    }

    # Evaluate validation issues for the cross-project and same-project actions.
    cross_issues = self.creator._collect_action_validation_issues(
        cross_project_action, constants.RESOURCE_TYPE_DATA_POLICY_V2
    )
    same_project_action = dict(
        cross_project_action,
        **{constants.FIELD_TARGET_PROJECT_ID: "primary-project"},
    )
    same_issues = self.creator._collect_action_validation_issues(
        same_project_action, constants.RESOURCE_TYPE_DATA_POLICY_V2
    )

    # Confirm the cross-project routine is flagged while the same-project
    # routine passes with zero issues.
    self.assertEqual(len(cross_issues), 1)
    self.assertIn("resides in project 'primary-project'", cross_issues[0])
    self.assertIn(
        "differs from target Data Policy project 'secondary-project'",
        cross_issues[0],
    )
    self.assertEqual(same_issues, [])

  # When `allow_unresolved_plan_warnings=True`, overridden `[ACTION REQUIRED]`
  # cross-project routine warnings must appear once in `### Potential Issues &
  # Warnings` instead of being triplicated by `_collect_potential_issues`.
  def test_collect_potential_issues_deduplicates_overridden_routine_warnings(
      self,
  ):
    """Deduplicates overridden `[ACTION REQUIRED]` cross-project warnings."""
    # Configure a dry-run Creator with `allow_unresolved_plan_warnings=True`
    # and a V2 Data Policy action carrying a Phase 1b cross-project routine
    # warning.
    dry_run_override_creator = creator.Creator(
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        dry_run=True,
        allow_unresolved_plan_warnings=True,
    )
    routine_path = "projects/primary-project/datasets/gov_us/routines/mask_fn"
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_DATA_POLICIES_V1_TO_DATA_POLICIES_V2: [{
                constants.FIELD_POLICY_ID: "migrated_masking_phone",
                constants.FIELD_REGION: "us",
                constants.FIELD_TARGET_PROJECT_ID: "secondary-project",
                constants.FIELD_WARNINGS: [
                    f"Custom masking routine '{routine_path}' resides in"
                    " project 'primary-project', whereas this V2 Data Policy"
                    " targets project 'secondary-project'. [ACTION REQUIRED:"
                    " Remap routine.]"
                ],
                constants.FIELD_API_PAYLOAD: {
                    "data_policy_type": "DATA_MASKING_POLICY",
                    "data_governance_tag": {
                        "key": "primary-project/my_key",
                        "value": "my_val",
                    },
                    "data_masking_policy": {"routine": routine_path},
                },
            }]
        }
    }
    self.mock_data_policy_v2_client.get_data_policy.side_effect = (
        exceptions.NotFound("Not found")
    )

    # Run dry-run batch creation with unresolved warnings overridden.
    report = dry_run_override_creator.create_all_dgt_resources(plan)

    # Verify the overridden plan warning is emitted exactly once without
    # duplicate `Plan warning:` or duplicate pre-flight routine bullets.
    self.assertEqual(report.count("Overridden Plan Warning:"), 1)
    self.assertNotIn("Plan warning: Custom masking routine", report)
    self.assertNotIn(
        "Data Policy V2 'secondary-project/migrated_masking_phone':"
        " data_masking_policy.routine",
        report,
    )

  # When `create_data_policy_v2` skips an existing V2 Data Policy in GCP whose
  # live `data_masking_policy.routine` differs from `plan.json`, it must surface
  # a configuration drift warning in `### Potential Issues & Warnings`.
  @mock.patch("builtins.input", return_value="y", autospec=True)
  def test_create_data_policy_v2_warns_on_skipped_existing_policy_drift(
      self, mock_input
  ):
    """Flags configuration drift when a skipped V2 Data Policy differs."""
    del mock_input  # Unused
    # Simulate a pre-existing V2 Data Policy in GCP pointing to a routine in
    # `secondary-project` while `plan.json` still specifies `primary-project`.
    existing_policy = types.SimpleNamespace(
        name=(
            "projects/secondary-project/locations/us/dataPolicies/"
            "migrated_masking_phone"
        ),
        data_policy_type="DATA_MASKING_POLICY",
        data_governance_tag=types.SimpleNamespace(
            key="primary-project/my_key",
            value="my_val",
        ),
        data_masking_policy=types.SimpleNamespace(
            predefined_expression=None,
            routine=(
                "projects/secondary-project/datasets/gov_us/routines/mask_fn"
            ),
        ),
        grantees=["user:analyst@example.com"],
    )
    self.mock_data_policy_v2_client.get_data_policy.return_value = (
        existing_policy
    )
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_DATA_POLICIES_V1_TO_DATA_POLICIES_V2: [{
                constants.FIELD_POLICY_ID: "migrated_masking_phone",
                constants.FIELD_REGION: "us",
                constants.FIELD_TARGET_PROJECT_ID: "secondary-project",
                constants.FIELD_API_PAYLOAD: {
                    "data_policy_type": "DATA_MASKING_POLICY",
                    "data_governance_tag": {
                        "key": "primary-project/my_key",
                        "value": "my_val",
                    },
                    "data_masking_policy": {
                        "routine": (
                            "projects/primary-project/datasets/gov_us/"
                            "routines/mask_fn"
                        )
                    },
                    "grantees": ["user:analyst@example.com"],
                },
            }]
        }
    }

    # Execute batch creation where the pre-existing policy is skipped.
    report = self.creator.create_all_dgt_resources(plan)

    # Confirm the policy is counted as skipped and the routine drift warning is
    # surfaced in `### Potential Issues & Warnings`.
    self.assertEqual(self.creator.last_summary["skipped"], 1)
    self.assertIn(
        "Skipped pre-existing Data Policy V2"
        " 'secondary-project/migrated_masking_phone' in Google Cloud differs"
        " from plan.json on: data_masking_policy.routine",
        report,
    )

  # Batch creation of multiple V2 Data Policies under an older SDK wheel must
  # log the REST `/v2/` fallback warning once at WARNING level and at DEBUG
  # thereafter so console logs are not spammed once per policy.
  def test_create_data_policy_v2_logs_rest_fallback_warning_once_per_instance(
      self,
  ):
    """Logs the V2 REST creation fallback warning once per Creator instance."""
    # Configure GAPIC `get_data_policy` to report NotFound and
    # `create_data_policy` to raise ValueError("Unknown field").
    self.mock_data_policy_v2_client.get_data_policy.side_effect = (
        exceptions.NotFound("Not found")
    )
    self.mock_data_policy_v2_client.create_data_policy.side_effect = ValueError(
        "Unknown field for DataPolicy: data_governance_tag"
    )
    action_one = {
        constants.FIELD_POLICY_ID: "policy_one",
        constants.FIELD_REGION: "us",
        constants.FIELD_TARGET_PROJECT_ID: "my-project",
        constants.FIELD_API_PAYLOAD: {
            "data_policy_type": "RAW_DATA_ACCESS_POLICY",
            "data_governance_tag": {"key": "my-project/k", "value": "v1"},
        },
    }
    action_two = {
        constants.FIELD_POLICY_ID: "policy_two",
        constants.FIELD_REGION: "us",
        constants.FIELD_TARGET_PROJECT_ID: "my-project",
        constants.FIELD_API_PAYLOAD: {
            "data_policy_type": "RAW_DATA_ACCESS_POLICY",
            "data_governance_tag": {"key": "my-project/k", "value": "v2"},
        },
    }

    # Create two V2 Data Policies back-to-back via the REST fallback.
    with (
        mock.patch.object(
            self.creator,
            "_create_data_policy_v2_rest",
            autospec=True,
            side_effect=[
                {"name": "projects/my-project/locations/us/dataPolicies/p1"},
                {"name": "projects/my-project/locations/us/dataPolicies/p2"},
            ],
        ),
        self.assertLogs(creator.logger, level="DEBUG") as log_context,
    ):
      self.creator.create_data_policy_v2(action_one)
      self.creator.create_data_policy_v2(action_two)

    # Confirm the SDK fallback warning was emitted once at WARNING level and the
    # second fallback was logged at DEBUG level.
    fallback_phrase = "Local client library lacks 'data_governance_tag' support"
    warning_records = [
        record
        for record in log_context.records
        if record.levelname == "WARNING"
        and fallback_phrase in record.getMessage()
    ]
    debug_records = [
        record
        for record in log_context.records
        if record.levelname == "DEBUG"
        and fallback_phrase in record.getMessage()
    ]
    self.assertEqual(len(warning_records), 1)
    self.assertEqual(len(debug_records), 1)

  # Proto-plus messages expose repeated fields as `Repeated` rather than Python
  # `list`/`tuple`, so drift inspection must still detect unexpected grantees.
  def test_create_data_policy_v2_detects_grantee_drift_on_proto_plus_repeated(
      self,
  ):
    """Detects grantee drift when `existing_policy.grantees` is `Repeated`."""
    # Return a real proto-plus message whose `grantees` attribute is `Repeated`.
    self.mock_data_policy_v2_client.get_data_policy.return_value = (
        _ProtoDataPolicyV2(
            name="projects/my-project/locations/us/dataPolicies/p_deny",
            data_policy_type="RAW_DATA_ACCESS_POLICY",
            data_governance_tag=_ProtoTagRef(
                key="my-project/my_key", value="my_val"
            ),
            grantees=["user:unexpected@example.com"],
        )
    )
    action = {
        constants.FIELD_POLICY_ID: "p_deny",
        constants.FIELD_REGION: "us",
        constants.FIELD_TARGET_PROJECT_ID: "my-project",
        constants.FIELD_API_PAYLOAD: {
            "data_policy_type": "RAW_DATA_ACCESS_POLICY",
            "data_governance_tag": {
                "key": "my-project/my_key",
                "value": "my_val",
            },
            "grantees": [],
        },
    }

    # Skip the existing policy and confirm `Repeated` grantee drift is recorded.
    _, status = self.creator.create_data_policy_v2(action)

    self.assertEqual(status, constants.STATUS_SKIPPED)
    self.assertEqual(len(self.creator._skipped_resource_drift_warnings), 1)
    self.assertIn(
        "grantees (extra_in_live (1)=['user:unexpected@example.com'];"
        " live_total=1, planned_total=0)",
        self.creator._skipped_resource_drift_warnings[0],
    )

  # When `bigquery_datapolicies_v2` is aliased to V1, `get_data_policy` returns
  # a V1 `DataPolicy` message lacking `grantees` and `data_governance_tag`;
  # `create_data_policy_v2` must fall back to `/v2/` REST GET to detect drift.
  def test_create_data_policy_v2_falls_back_to_rest_when_v1_proto_lacks_fields(
      self,
  ):
    """Falls back to REST GET when GAPIC response lacks V2 proto fields."""
    # Return a genuine V1 proto-plus `DataPolicy` lacking V2 attributes.
    self.mock_data_policy_v2_client.get_data_policy.return_value = (
        bigquery_datapolicies_v1.types.DataPolicy(
            name="projects/my-project/locations/us/dataPolicies/p_raw"
        )
    )
    action = {
        constants.FIELD_POLICY_ID: "p_raw",
        constants.FIELD_REGION: "us",
        constants.FIELD_TARGET_PROJECT_ID: "my-project",
        constants.FIELD_API_PAYLOAD: {
            "data_policy_type": "RAW_DATA_ACCESS_POLICY",
            "data_governance_tag": {
                "key": "my-project/my_key",
                "value": "my_val",
            },
            "grantees": ["user:expected@example.com"],
        },
    }

    # Provide full V2 JSON via REST with an extra live grantee.
    with mock.patch.object(
        self.creator,
        "_get_data_policy_v2_rest",
        return_value={
            "name": "projects/12345/locations/us/dataPolicies/p_raw",
            "dataPolicyType": "RAW_DATA_ACCESS_POLICY",
            "dataGovernanceTag": {
                "key": "my-project/my_key",
                "value": "my_val",
            },
            "grantees": [
                "user:expected@example.com",
                "user:extra@example.com",
            ],
        },
        autospec=True,
    ) as mock_rest_get:
      _, status = self.creator.create_data_policy_v2(action)

    # Confirm REST GET ran and flagged the extra grantee on the skipped policy.
    mock_rest_get.assert_called_once_with(
        "projects/my-project/locations/us/dataPolicies/p_raw"
    )
    self.assertEqual(status, constants.STATUS_SKIPPED)
    self.assertEqual(len(self.creator._skipped_resource_drift_warnings), 1)
    self.assertIn(
        "user:extra@example.com",
        self.creator._skipped_resource_drift_warnings[0],
    )

  # `GetDataPolicy` returns `data_masking_policy.routine` with a numeric project
  # number while `plan.json` uses the string project ID; re-runs must not emit
  # false routine drift warnings when `(dataset, routine)` and project match.
  def test_create_data_policy_v2_ignores_numeric_project_on_matching_routine(
      self,
  ):
    """Avoids false routine drift when GCP returns numeric project numbers."""
    existing_policy = types.SimpleNamespace(
        name=(
            "projects/123456789/locations/us/dataPolicies/"
            "migrated_masking_phone"
        ),
        data_policy_type="DATA_MASKING_POLICY",
        data_governance_tag=types.SimpleNamespace(
            key="my-project/my_key",
            value="my_val",
        ),
        data_masking_policy=types.SimpleNamespace(
            predefined_expression=None,
            routine="projects/123456789/datasets/gov_us/routines/mask_fn",
        ),
        grantees=["user:analyst@example.com"],
    )
    self.mock_data_policy_v2_client.get_data_policy.return_value = (
        existing_policy
    )
    action = {
        constants.FIELD_POLICY_ID: "migrated_masking_phone",
        constants.FIELD_REGION: "us",
        constants.FIELD_TARGET_PROJECT_ID: "my-project",
        constants.FIELD_API_PAYLOAD: {
            "data_policy_type": "DATA_MASKING_POLICY",
            "data_governance_tag": {
                "key": "my-project/my_key",
                "value": "my_val",
            },
            "data_masking_policy": {
                "routine": (
                    "projects/my-project/datasets/gov_us/routines/mask_fn"
                )
            },
            "grantees": ["user:analyst@example.com"],
        },
    }

    _, status = self.creator.create_data_policy_v2(action)

    self.assertEqual(status, constants.STATUS_SKIPPED)
    self.assertEqual(self.creator._skipped_resource_drift_warnings, [])

  # Resource Manager enforces Tag Value `short_name` uniqueness across the
  # entire Tag Key; if `AlreadyExists` occurs and `namespaced_name` is still
  # absent under `parent_id`, `create_dg_tag_value` must raise clearly.
  def test_create_dg_tag_value_raises_when_short_name_exists_under_other_parent(
      self,
  ):
    """Raises `AlreadyExists` when `short_name` collides under another node."""
    self.mock_tag_keys_client.list_tag_keys.return_value = [
        types.SimpleNamespace(name="tagKeys/100", short_name="my_key")
    ]
    self.mock_tag_values_client.list_tag_values.side_effect = [
        [
            types.SimpleNamespace(
                name="tagValues/200",
                short_name="branch_b",
                parent="tagKeys/100",
            )
        ],
        [],
        [],
    ]
    self.mock_tag_values_client.create_tag_value.side_effect = (
        exceptions.AlreadyExists("TagValue short_name already exists")
    )
    action = {
        "namespaced_name": "my-project/my_key/branch_b/shared_leaf",
        "parent_namespaced_name": "my-project/my_key/branch_b",
        "api_payload": {"short_name": "shared_leaf"},
    }

    # Colliding `short_name` under another parent must fail closed rather than
    # returning `(None, STATUS_SKIPPED)`.
    with self.assertRaisesRegex(
        exceptions.AlreadyExists,
        "unique across the entire Tag Key 'my-project/my_key'",
    ):
      self.creator.create_dg_tag_value(action)

  # Non-interactive `EOFError` on the batch creation prompt must raise instead
  # of returning `None` (which would cause the CLI to exit 0).
  @mock.patch("builtins.input", side_effect=EOFError, autospec=True)
  def test_create_all_dgt_resources_raises_on_eof_prompt_abort(
      self, mock_input
  ):
    """Raises `RuntimeError` when `input()` hits `EOFError` on batch create."""
    del mock_input  # Unused
    plan = {constants.KEY_PHASE_2_RESOURCE_MANIFEST: {}}

    with self.assertRaisesRegex(
        RuntimeError, "Interactive confirmation prompt aborted"
    ):
      self.creator.create_all_dgt_resources(plan)

  # Pre-flight validation must catch manual `plan.json` edits introducing
  # Authorized Routine grantees or exceeding 500 IAM principals / 100 groups.
  def test_collect_action_validation_issues_flags_routine_and_grantee_quotas(
      self,
  ):
    routine_grantee = (
        "principal://bigquery.googleapis.com/projects/my-project/"
        "datasets/gov_ds/routines/authorized_fn"
    )
    too_many_users = [
        f"principal://goog/subject/user-{index}@example.com"
        for index in range(constants.MAX_GRANTEES_PER_DATA_POLICY_V2 + 1)
    ]
    too_many_groups = [
        f"principalSet://goog/group/team-{index}@example.com"
        for index in range(constants.MAX_GROUP_GRANTEES_PER_DATA_POLICY_V2 + 1)
    ]
    action = {
        constants.FIELD_POLICY_ID: "manual_policy",
        constants.FIELD_TARGET_PROJECT_ID: "my-project",
        constants.FIELD_API_PAYLOAD: {
            "grantees": [routine_grantee] + too_many_users + too_many_groups
        },
    }

    # Validate the edited action so all three grantee rules are evaluated.
    issues = self.creator._collect_action_validation_issues(
        action, constants.RESOURCE_TYPE_DATA_POLICY_V2
    )
    joined_issues = " | ".join(issues)

    self.assertIn("BigQuery Authorized Routine principal", joined_issues)
    self.assertIn(routine_grantee, joined_issues)
    self.assertIn("exceeding BigQuery's limit of 500 IAM", joined_issues)
    self.assertIn("exceeding BigQuery's limit of 100 groups", joined_issues)

  # `_collect_potential_issues` must flag projects whose combined pre-existing
  # and planned Tag Keys exceed 1,000, and Tag Keys exceeding 1,000 Tag Values.
  def test_collect_potential_issues_flags_tag_key_and_tag_value_quotas(self):
    # Pre-populate `_dg_tag_key_cache` with 1,000 existing Tag Keys in
    # `my-project` so 1 new planned DG Tag Key pushes the total to 1,001.
    for index in range(constants.MAX_DG_TAG_KEYS_PER_PROJECT):
      self.creator._dg_tag_key_cache[f"my-project/existing_{index}"] = (
          f"tagKeys/{index}"
      )
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS: [{
                constants.FIELD_NAMESPACED_NAME: "my-project/new_dg_key",
                constants.FIELD_API_PAYLOAD: {"short_name": "new_dg_key"},
            }],
            constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES: [
                {
                    constants.FIELD_NAMESPACED_NAME: (
                        f"my-project/new_dg_key/val_{index}"
                    ),
                    constants.FIELD_API_PAYLOAD: {"short_name": f"val_{index}"},
                }
                for index in range(constants.MAX_DG_TAG_VALUES_PER_TAG_KEY + 1)
            ],
        }
    }

    # Collect pre-flight issues across both Tag Key and Tag Value manifests.
    issues = self.creator._collect_potential_issues(plan, set(), set(), set())
    joined_issues = " | ".join(issues)

    self.assertIn(
        "Project 'my-project' would contain 1001 total Tag Keys", joined_issues
    )
    self.assertIn(
        "DG Tag Key 'my-project/new_dg_key' has 1001 planned DG Tag Values",
        joined_issues,
    )

  # Organizationless GCP project failures must log an explicit Google Cloud
  # Organization requirement hint while re-raising the original exception.
  def test_create_logs_organization_requirement_hint_on_orgless_failure(self):
    self.mock_tag_keys_client.list_tag_keys.return_value = []
    self.mock_tag_keys_client.create_tag_key.side_effect = (
        exceptions.FailedPrecondition(
            "Project 'orgless-proj' must belong to an organization."
        )
    )
    key_action = {
        "namespaced_name": "orgless-proj/pii_key",
        "api_payload": {
            "parent": "projects/orgless-proj",
            "short_name": "pii_key",
            "purpose": "DATA_GOVERNANCE",
        },
    }

    with (
        self.assertLogs(creator.logger, level="ERROR") as log_context,
        self.assertRaisesRegex(
            exceptions.FailedPrecondition,
            "Project 'orgless-proj' must belong to an organization",
        ),
    ):
      self.creator.create_dg_tag_key(key_action)

    logged_messages = "\n".join(log_context.output)
    self.assertIn(
        "belong to a Google Cloud Organization resource", logged_messages
    )

  # Skipping a pre-existing column-bound V2 Data Policy that lacks
  # `dataGovernanceTag` must record `[DRIFT WARNING]`, whereas a server-side
  # numeric `<project_number>/<short>` key in the same project matches cleanly.
  @mock.patch("urllib.request.urlopen", autospec=True)
  @mock.patch("google.auth.default", autospec=True)
  def test_create_skipped_policy_flags_missing_dgt_and_accepts_same_proj_num(
      self, mock_auth, mock_urlopen
  ):
    self.mock_data_policy_v2_client.get_data_policy.side_effect = (
        exceptions.InvalidArgument("V2 policy requires /v2/ REST endpoint")
    )
    mock_credentials = mock.create_autospec(
        auth_credentials.Credentials, instance=True, spec_set=False
    )
    mock_credentials.token = "fake-token"
    mock_auth.return_value = (mock_credentials, "my-project")

    # First existing policy is column-bound (no `dataGovernanceTag`); second
    # existing policy stores a numeric project number in `dataGovernanceTag`.
    mock_urlopen.side_effect = [
        _make_urlopen_response(
            b'{"name": "projects/my-project/locations/us/dataPolicies/pol_col",'
            b' "dataPolicyType": "RAW_DATA_ACCESS_POLICY", "grantees": []}'
        ),
        _make_urlopen_response(
            b'{"name": "projects/123456/locations/us/dataPolicies/pol_num",'
            b' "dataPolicyType": "RAW_DATA_ACCESS_POLICY", "grantees": [],'
            b' "dataGovernanceTag": {"key": "123456/my-key",'
            b' "value": "123456/my-key/my-value"}}'
        ),
    ]

    col_bound_action = {
        "policy_id": "pol_col",
        "region": "us",
        "target_project_id": "my-project",
        "api_payload": {
            "data_policy_type": "RAW_DATA_ACCESS_POLICY",
            "data_governance_tag": {"key": "my-project/my-key", "value": "v1"},
            "grantees": [],
        },
    }
    same_proj_num_action = {
        "policy_id": "pol_num",
        "region": "us",
        "target_project_id": "my-project",
        "api_payload": {
            "data_policy_type": "RAW_DATA_ACCESS_POLICY",
            "data_governance_tag": {
                "key": "my-project/my-key",
                "value": "my-project/my-key/my-value",
            },
            "grantees": [],
        },
    }

    _, col_status = self.creator.create_data_policy_v2(col_bound_action)
    _, num_status = self.creator.create_data_policy_v2(same_proj_num_action)

    self.assertEqual(col_status, constants.STATUS_SKIPPED)
    self.assertEqual(num_status, constants.STATUS_SKIPPED)
    self.assertEqual(len(self.creator._skipped_resource_drift_warnings), 1)
    drift_msg = self.creator._skipped_resource_drift_warnings[0]
    self.assertIn("my-project/pol_col", drift_msg)
    self.assertIn(
        "data_governance_tag.key (live='<none>', planned='my-project/my-key')",
        drift_msg,
    )
    self.assertNotIn("pol_num", drift_msg)

  # Both batch and individual Phase 2a entrypoints must reject unsupported
  # `metadata.schema_version` values before prompting or calling GCP APIs.
  @mock.patch("builtins.input", autospec=True)
  def test_creator_entrypoints_reject_unsupported_plan_schema_version(
      self, mock_input
  ):
    future_plan = {
        "metadata": {"schema_version": 2},
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {},
    }

    with self.assertRaisesRegex(
        ValueError,
        r"Unsupported migration plan schema_version=2.*schema_version=1",
    ):
      self.creator.create_all_dgt_resources(future_plan)

    with self.assertRaisesRegex(
        ValueError,
        r"Unsupported migration plan schema_version=2.*schema_version=1",
    ):
      self.creator.create_individual_dgt_resource(
          future_plan,
          "my-project/my-key",
          constants.RESOURCE_TYPE_DG_TAG_KEY,
      )

    mock_input.assert_not_called()
    self.mock_tag_keys_client.create_tag_key.assert_not_called()

  # Batch `--dry-run` must classify deterministic GCP API violations and quota
  # breaches as `Failed / Blocked` rather than advisory-only warnings.
  def test_dry_run_batch_fails_on_hard_api_and_quota_violations(self):
    """Fails `--all --dry-run` on invalid names, grantees, routines, quotas."""
    dry_run_creator = creator.Creator(
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        dry_run=True,
    )
    # Seed 1,000 pre-existing live Tag Keys so planning 1 additional key
    # breaches the 1,000 Tag Keys per project limit.
    self.mock_tag_keys_client.list_tag_keys.return_value = [
        types.SimpleNamespace(
            name=f"tagKeys/{index}",
            short_name=f"existing_key_{index}",
            purpose=2,
        )
        for index in range(constants.MAX_DG_TAG_KEYS_PER_PROJECT)
    ]
    self.mock_tag_values_client.list_tag_values.return_value = []
    self.mock_data_policy_v2_client.get_data_policy.side_effect = (
        exceptions.NotFound("not found")
    )

    # Combine an invalid Tag Key `short_name` (`-bad_start`), a policy with
    # >500 IAM v3 principals + Authorized Routine grantee, and a cross-project
    # custom masking routine.
    oversized_grantees = [
        f"principal://goog/subject/reader_{index}@example.com"
        for index in range(constants.MAX_GRANTEES_PER_DATA_POLICY_V2 + 1)
    ] + ["//bigquery.googleapis.com/projects/p/datasets/d/routines/auth_fn"]
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS: [{
                constants.FIELD_NAMESPACED_NAME: "my-project/-bad_start",
                constants.FIELD_API_PAYLOAD: {
                    "parent": "projects/my-project",
                    "short_name": "-bad_start",
                    "description": "invalid start char",
                    "purpose": "DATA_GOVERNANCE",
                },
            }],
            constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES: [],
            constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2: [{
                constants.FIELD_POLICY_ID: "oversized_raw_policy",
                constants.FIELD_REGION: "us",
                constants.FIELD_TARGET_PROJECT_ID: "dp-project",
                constants.FIELD_API_PAYLOAD: {
                    "data_policy_type": constants.DATA_POLICY_TYPE_RAW,
                    "data_governance_tag": {
                        "key": "my-project/existing_key_0",
                        "value": "pii",
                    },
                    "grantees": oversized_grantees,
                },
            }],
            constants.KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2: [],
            constants.KEY_DATA_POLICIES_V1_TO_DATA_POLICIES_V2: [{
                constants.FIELD_POLICY_ID: "cross_project_mask",
                constants.FIELD_REGION: "us",
                constants.FIELD_TARGET_PROJECT_ID: "dp-project",
                constants.FIELD_API_PAYLOAD: {
                    "data_policy_type": constants.DATA_POLICY_TYPE_MASKING,
                    "data_governance_tag": {
                        "key": "my-project/existing_key_0",
                        "value": "pii",
                    },
                    "data_masking_policy": {
                        "routine": (
                            "projects/other-proj/datasets/ds/routines/mask_fn"
                        )
                    },
                    "grantees": ["user:analyst@example.com"],
                },
            }],
        }
    }

    with tempfile.TemporaryDirectory() as temp_dir:
      report_path = os.path.join(temp_dir, "dry_run_report.md")
      report = dry_run_creator.create_all_dgt_resources(
          plan, report_file=report_path
      )
      with open(report_path, "r", encoding="utf-8") as report_handle:
        disk_report = report_handle.read()

    # All 3 invalid resources plus the project Tag Key quota blocker must fail
    # pre-flight validation and land in `Failed Pre-Flight Checks / Blockers`.
    self.assertEqual(dry_run_creator.last_summary["succeeded"], 0)
    self.assertEqual(dry_run_creator.last_summary["failed"], 4)
    self.assertIn("### Failed Pre-Flight Checks / Blockers", report)
    self.assertIn("#### Plan & Quota Limits", report)
    self.assertIn("my-project/-bad_start", report)
    self.assertIn("dp-project/oversized_raw_policy", report)
    self.assertIn("exceeding BigQuery's limit of 500 IAM principals", report)
    self.assertIn("Authorized Routine principal", report)
    self.assertIn("dp-project/cross_project_mask", report)
    self.assertIn(
        "exceeding the Resource Manager limit of 1000 Tag Keys", report
    )
    self.assertNotIn("### Potential Issues & Warnings", report)
    self.assertTrue(disk_report.endswith("\n"))

  # Single-resource `--dry-run` must also fail pre-flight validation when the
  # target V2 Data Policy exceeds the 100-group principal limit.
  def test_dry_run_individual_resource_fails_on_hard_api_violation(self):
    """Fails individual `--dry-run` when policy exceeds 100 group grantees."""
    dry_run_creator = creator.Creator(
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        dry_run=True,
    )
    self.mock_data_policy_v2_client.get_data_policy.side_effect = (
        exceptions.NotFound("not found")
    )
    excess_groups = [
        f"principalSet://goog/group/g{index}@example.com"
        for index in range(constants.MAX_GROUP_GRANTEES_PER_DATA_POLICY_V2 + 1)
    ]
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2: [{
                constants.FIELD_POLICY_ID: "many_groups_policy",
                constants.FIELD_REGION: "us",
                constants.FIELD_TARGET_PROJECT_ID: "dp-project",
                constants.FIELD_API_PAYLOAD: {
                    "data_policy_type": constants.DATA_POLICY_TYPE_RAW,
                    "grantees": excess_groups,
                },
            }]
        }
    }

    report = dry_run_creator.create_individual_dgt_resource(
        plan,
        "dp-project/many_groups_policy",
        constants.RESOURCE_TYPE_DATA_POLICY_V2,
    )

    self.assertIsNotNone(report)
    self.assertIn("- **Status:** Failed", report)
    self.assertIn("### Failed Pre-Flight Checks / Blockers", report)
    self.assertIn("exceeding BigQuery's limit of 100 groups", report)

  # Grantee drift warnings on skipped pre-existing policies must emit compact
  # missing/extra set diffs capped at 5 items per list with full total counts.
  def test_skipped_grantee_drift_warning_uses_bounded_set_diff(self):
    """Formats large grantee drift as a bounded 5-item set diff."""
    shared_grantees = [
        f"user:shared_{index:03d}@example.com" for index in range(592)
    ]
    missing_in_live = [
        f"user:missing_{index:02d}@example.com" for index in range(8)
    ]
    extra_in_live = [
        f"user:extra_{index:02d}@example.com" for index in range(10)
    ]

    self.mock_data_policy_v2_client.get_data_policy.return_value = (
        _ProtoDataPolicyV2(
            name="projects/my-project/locations/us/dataPolicies/wide_policy",
            data_policy_type="RAW_DATA_ACCESS_POLICY",
            data_governance_tag=_ProtoTagRef(
                key="my-project/my_key", value="my_val"
            ),
            grantees=shared_grantees + extra_in_live,
        )
    )
    action = {
        constants.FIELD_POLICY_ID: "wide_policy",
        constants.FIELD_REGION: "us",
        constants.FIELD_TARGET_PROJECT_ID: "my-project",
        constants.FIELD_API_PAYLOAD: {
            "data_policy_type": "RAW_DATA_ACCESS_POLICY",
            "data_governance_tag": {
                "key": "my-project/my_key",
                "value": "my_val",
            },
            "grantees": shared_grantees + missing_in_live,
        },
    }

    _, status = self.creator.create_data_policy_v2(action)

    self.assertEqual(status, constants.STATUS_SKIPPED)
    self.assertEqual(len(self.creator._skipped_resource_drift_warnings), 1)
    warning_text = self.creator._skipped_resource_drift_warnings[0]
    # Shared principals must never be dumped; both diff sets are capped at 5
    # with explicit overflow counts and exact live/planned totals.
    self.assertNotIn("user:shared_000@example.com", warning_text)
    self.assertIn("missing_in_live (8)=", warning_text)
    self.assertIn("... (+3 more; showing 5 of 8)", warning_text)
    self.assertIn("extra_in_live (10)=", warning_text)
    self.assertIn("... (+5 more; showing 5 of 10)", warning_text)
    self.assertIn("live_total=602, planned_total=600", warning_text)

  # Aborting `create_individual_dgt_resource` at the interactive prompt via
  # `EOFError` must raise `RuntimeError` without writing a bogus failure report.
  @mock.patch("builtins.input", side_effect=EOFError, autospec=True)
  def test_create_individual_eof_prompt_abort_omits_report_file(
      self, mock_input
  ):
    """Leaves `last_report` as `None` and skips `report_file` on `EOFError`."""
    del mock_input  # Unused
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS: [{
                constants.FIELD_NAMESPACED_NAME: "my-project/my-key",
                constants.FIELD_API_PAYLOAD: {
                    "parent": "projects/my-project",
                    "short_name": "my-key",
                    "description": "test",
                    "purpose": "DATA_GOVERNANCE",
                },
            }]
        }
    }

    with tempfile.TemporaryDirectory() as temp_dir:
      report_path = os.path.join(temp_dir, "aborted_report.md")
      with self.assertRaisesRegex(
          RuntimeError, "Interactive confirmation prompt aborted"
      ):
        self.creator.create_individual_dgt_resource(
            plan,
            "my-project/my-key",
            constants.RESOURCE_TYPE_DG_TAG_KEY,
            report_file=report_path,
        )
      self.assertIsNone(self.creator.last_report)
      self.assertFalse(os.path.exists(report_path))

  # Non-`DATA_GOVERNANCE` existing Tag Keys with numeric protobuf enum values
  # (`0` or `1`) must report readable names rather than raw integers.
  def test_create_dg_tag_key_formats_numeric_purpose_enum_label(self):
    """Formats numeric `purpose=0` / `purpose=1` as readable enum names."""
    action = {
        constants.FIELD_NAMESPACED_NAME: "my-project/standard-key",
        constants.FIELD_API_PAYLOAD: {
            "parent": "projects/my-project",
            "short_name": "standard-key",
            "description": "test",
            "purpose": "DATA_GOVERNANCE",
        },
    }

    for raw_purpose, expected_label in (
        (0, "PURPOSE_UNSPECIFIED"),
        (1, "GCE_FIREWALL"),
    ):
      self.creator._dg_tag_key_cache.clear()
      self.creator._dg_tag_key_purpose_cache.clear()
      self.creator._listed_tag_key_projects.clear()
      self.mock_tag_keys_client.list_tag_keys.return_value = [
          types.SimpleNamespace(
              name="tagKeys/999",
              short_name="standard-key",
              purpose=raw_purpose,
          )
      ]
      with self.assertRaisesRegex(
          ValueError,
          f"non-DATA_GOVERNANCE purpose '{expected_label}'",
      ):
        self.creator.create_dg_tag_key(action)

  # Hand-edited plans with empty names, empty `data_masking_policy`, or
  # tombstoned/unsupported grantees must fail dry-run hard validation.
  def test_hard_validation_rejects_empty_names_masking_and_bad_grantees(self):
    """Rejects empty short_name/policy_id, empty masking, and bad grantees."""
    empty_short_name_errors = (
        self.creator._collect_action_hard_validation_errors(
            {
                constants.FIELD_NAMESPACED_NAME: "my-project/",
                constants.FIELD_API_PAYLOAD: {"short_name": ""},
            },
            constants.RESOURCE_TYPE_DG_TAG_KEY,
        )
    )
    self.assertTrue(
        any("short_name ''" in msg for msg in empty_short_name_errors)
    )

    bad_policy_errors = self.creator._collect_action_hard_validation_errors(
        {
            constants.FIELD_POLICY_ID: "",
            constants.FIELD_TARGET_PROJECT_ID: "dp-project",
            constants.FIELD_API_PAYLOAD: {
                "data_policy_type": constants.DATA_POLICY_TYPE_MASKING,
                "data_masking_policy": {},
                "grantees": [
                    "deleted:user:old@example.com?uid=123",
                    "domain:example.com",
                    "allUsers",
                ],
            },
        },
        constants.RESOURCE_TYPE_DATA_POLICY_V2,
    )
    joined_errors = "\n".join(bad_policy_errors)
    self.assertIn("policy_id must contain only", joined_errors)
    self.assertIn("requires a non-empty data_masking_policy", joined_errors)
    self.assertIn("deleted principal tombstone", joined_errors)
    self.assertIn("unsupported Workspace 'domain:' notation", joined_errors)
    self.assertIn("is a public principal", joined_errors)


if __name__ == "__main__":
  unittest.main()
