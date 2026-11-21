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

"""Unit tests for the Phase 2b Deleter class (`deleter.py`).

What This Test Suite Verifies:
==============================
1. Tag Key & Tag Value Resolution and Caching (`_get_dg_tag_key_id`,
   `_get_dg_tag_value_id`):
   - In-memory positive caching (`_dg_tag_key_cache`, `_dg_tag_value_cache`) and
     per-project / per-parent negative-lookup sets (`_listed_tag_key_projects`,
     `_listed_tag_value_parents`).
   - Direct-child filtering when `list_tag_values` returns nested descendants
     sharing the same `short_name`.
2. Individual Resource Deletion & Idempotency (`delete_dg_tag_key`,
   `delete_dg_tag_value`, `delete_data_policy_v2`):
   - Synchronous LRO completion (`operation.result()`), cache eviction upon
     deletion, and idempotent `DELETE_STATUS_SKIPPED` handling when resources
     are already absent in GCP.
   - Dual-transport V2 Data Policy inspection and deletion, falling back from
     GAPIC `get_data_policy` / `delete_data_policy` to raw `/v2/` REST endpoints
     (`_get_data_policy_v2_rest` / `_delete_data_policy_v2_rest`).
3. Pre-Delete Safety Warnings, Dry-Run & Failure Reporting
   (`delete_individual_dgt_resource`):
   - Fail-Open warnings when deleting Default-Deny or standard V2 Data Policies.
   - Live-mode and dry-run plan dependency warnings when deleting a DG Tag Value
     that still has child Tag Values (`parent_namespaced_name`) or referencing
     V2 Data Policies (`dg_tag_value_namespaced_name`) in `plan.json`.
   - Mode 2 (`TABLE_PARENT_PROJECTS`) `<policy_id>` ambiguity detection and
     `<target_project_id>/<policy_id>` disambiguation.
   - Persistence of a `FAILED` Markdown report to `report_file` when live
     deletion raises an exception.
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

# Ensure local imports work in both package and standalone script execution.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# pylint: disable=g-import-not-at-top,g-bad-import-order
try:
  from google.cloud import bigquery_datapolicies_v2
except ImportError:
  bigquery_datapolicies_v2 = bigquery_datapolicies_v1

import constants
import deleter

# pylint: enable=g-import-not-at-top,g-bad-import-order


def _make_urlopen_response(body_bytes: bytes):
  """Returns a context-manager object whose read() returns body_bytes."""
  return contextlib.nullcontext(io.BytesIO(body_bytes))


class DeleterTest(unittest.TestCase):
  """Unit tests for Phase 2b `Deleter` resource deletion and dry-run checks."""

  def setUp(self):
    """Initializes strict autospecced GCP clients and a `Deleter` instance."""
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

    self.deleter = deleter.Deleter(
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
    )

  # =========================================================================
  # === Section 1: Tag Key, Tag Value & V2 Data Policy Deletion Tests ===
  # =========================================================================

  def test_get_dg_tag_key_id_fetch_and_cache(self):
    """Verifies `_get_dg_tag_key_id` lists project keys once and caches them."""
    # Arrange: Configure list_tag_keys to return one matching Tag Key.
    mock_key = types.SimpleNamespace(name="tagKeys/123", short_name="my-key")
    self.mock_tag_keys_client.list_tag_keys.return_value = [mock_key]

    # Act: Resolve the Tag Key ID twice.
    first_tag_id = self.deleter._get_dg_tag_key_id("my-project/my-key")
    second_tag_id = self.deleter._get_dg_tag_key_id("my-project/my-key")

    # Assert: Both lookups return tagKeys/123 and list_tag_keys is called once.
    self.assertEqual(first_tag_id, "tagKeys/123")
    self.assertEqual(second_tag_id, "tagKeys/123")
    self.mock_tag_keys_client.list_tag_keys.assert_called_once_with(
        parent="projects/my-project", retry=deleter.RETRY_CONFIG
    )

  def test_get_dg_tag_key_id_not_found(self):
    """Verifies `_get_dg_tag_key_id` returns `None` when the key is absent."""
    # Arrange: Configure list_tag_keys to return an empty list.
    self.mock_tag_keys_client.list_tag_keys.return_value = []

    # Act: Look up the missing Tag Key.
    tag_id = self.deleter._get_dg_tag_key_id("my-project/my-key")

    # Assert: Returns None.
    self.assertIsNone(tag_id)

  @mock.patch("time.sleep", autospec=True)
  def test_delete_dg_tag_key_exists(self, mock_sleep):
    """Verifies `delete_dg_tag_key` waits for LRO and evicts cache entry."""
    # Arrange: Configure list_tag_keys and delete_tag_key LRO mock.
    del mock_sleep  # Unused
    mock_key = types.SimpleNamespace(name="tagKeys/123", short_name="my-key")
    self.mock_tag_keys_client.list_tag_keys.return_value = [mock_key]
    mock_operation = mock.create_autospec(
        api_core_operation.Operation, instance=True, spec_set=True
    )
    self.mock_tag_keys_client.delete_tag_key.return_value = mock_operation

    # Act: Delete the Tag Key.
    status = self.deleter.delete_dg_tag_key("my-project/my-key")

    # Assert: delete_tag_key was called with RETRY_CONFIG and LRO completed.
    self.assertEqual(status, constants.DELETE_STATUS_DELETED)
    self.mock_tag_keys_client.delete_tag_key.assert_called_once_with(
        name="tagKeys/123", retry=deleter.RETRY_CONFIG
    )
    mock_operation.result.assert_called_once_with()
    self.assertNotIn("my-project/my-key", self.deleter._dg_tag_key_cache)

  def test_delete_dg_tag_key_not_found(self):
    """Verifies `delete_dg_tag_key` returns `SKIPPED` when key is absent."""
    # Arrange: Configure list_tag_keys to return an empty list.
    self.mock_tag_keys_client.list_tag_keys.return_value = []

    # Act: Attempt to delete the missing Tag Key.
    status = self.deleter.delete_dg_tag_key("my-project/my-key")

    # Assert: Returns SKIPPED and never calls delete_tag_key.
    self.assertEqual(status, constants.DELETE_STATUS_SKIPPED)
    self.mock_tag_keys_client.delete_tag_key.assert_not_called()

  @mock.patch("time.sleep", autospec=True)
  def test_delete_dg_tag_value_exists(self, mock_sleep):
    """Verifies `delete_dg_tag_value` resolves ID, deletes, and evicts cache."""
    # Arrange: Configure parent Tag Key, child Tag Value, and delete LRO mock.
    del mock_sleep  # Unused
    mock_key = types.SimpleNamespace(name="tagKeys/123", short_name="my-key")
    self.mock_tag_keys_client.list_tag_keys.return_value = [mock_key]

    mock_value = types.SimpleNamespace(
        name="tagValues/456", short_name="my-value", parent="tagKeys/123"
    )
    self.mock_tag_values_client.list_tag_values.return_value = [mock_value]
    mock_operation = mock.create_autospec(
        api_core_operation.Operation, instance=True, spec_set=True
    )
    self.mock_tag_values_client.delete_tag_value.return_value = mock_operation

    # Act: Delete the Tag Value.
    status = self.deleter.delete_dg_tag_value("my-project/my-key/my-value")

    # Assert: delete_tag_value was called with RETRY_CONFIG and LRO completed.
    self.assertEqual(status, constants.DELETE_STATUS_DELETED)
    self.mock_tag_values_client.delete_tag_value.assert_called_once_with(
        name="tagValues/456", retry=deleter.RETRY_CONFIG
    )
    mock_operation.result.assert_called_once_with()

  def test_delete_data_policy_v2_exists(self):
    """Verifies `delete_data_policy_v2` calls `delete_data_policy` with name."""
    # Arrange: Prepare a Data Policy V2 action.
    action = {
        "policy_id": "my-policy",
        "region": "us",
        "target_project_id": "my-project",
        "api_payload": {
            "dataGovernanceTag": {
                "key": "my-project/my-key",
                "value": "my-value",
            }
        },
    }

    # Act: Delete the V2 Data Policy.
    status = self.deleter.delete_data_policy_v2(action)

    # Assert: delete_data_policy was called with expected resource name and
    # RETRY_CONFIG.
    expected_name = "projects/my-project/locations/us/dataPolicies/my-policy"
    self.assertEqual(status, constants.DELETE_STATUS_DELETED)
    self.mock_data_policy_v2_client.delete_data_policy.assert_called_once_with(
        name=expected_name, retry=deleter.RETRY_CONFIG
    )

  def test_delete_data_policy_v2_not_found(self):
    """Verifies `delete_data_policy_v2` returns `SKIPPED` on `NotFound`."""
    # Arrange: Configure delete_data_policy to raise NotFound.
    self.mock_data_policy_v2_client.delete_data_policy.side_effect = (
        exceptions.NotFound("Not found")
    )

    action = {
        "policy_id": "my-policy",
        "region": "us",
        "target_project_id": "my-project",
        "api_payload": {
            "dataGovernanceTag": {
                "key": "my-project/my-key",
                "value": "my-value",
            }
        },
    }

    # Act: Call delete_data_policy_v2.
    status = self.deleter.delete_data_policy_v2(action)

    # Assert: Returns SKIPPED without raising an exception.
    expected_name = "projects/my-project/locations/us/dataPolicies/my-policy"
    self.assertEqual(status, constants.DELETE_STATUS_SKIPPED)
    self.mock_data_policy_v2_client.delete_data_policy.assert_called_once_with(
        name=expected_name, retry=deleter.RETRY_CONFIG
    )

  # =========================================================================
  # === Section 2: Individual Resource Orchestration & Safety Warnings ===
  # =========================================================================

  @mock.patch("builtins.input", return_value="y", autospec=True)
  def test_delete_individual_dgt_resource_success(self, mock_input):
    """Verifies `delete_individual_dgt_resource` deletes confirmed Tag Key."""
    # Arrange: Prepare a plan with one Tag Key action.
    del mock_input  # Unused
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS: [
                {constants.FIELD_NAMESPACED_NAME: "my-project/my-key"}
            ]
        }
    }

    with mock.patch.object(
        self.deleter,
        "delete_dg_tag_key",
        return_value=constants.DELETE_STATUS_DELETED,
        autospec=True,
    ) as mock_delete:
      # Act: Delete the individual Tag Key.
      report = self.deleter.delete_individual_dgt_resource(
          plan, "my-project/my-key", constants.RESOURCE_TYPE_DG_TAG_KEY
      )

      # Assert: delete_dg_tag_key was called once and report shows DELETED.
      mock_delete.assert_called_once_with("my-project/my-key")
      self.assertIsNotNone(report)
      self.assertIn("**DELETED**", report)

  @mock.patch("builtins.input", return_value="n", autospec=True)
  def test_delete_individual_dgt_resource_aborted(self, mock_input):
    """Verifies declining confirmation aborts individual resource deletion."""
    # Arrange: Mock input() to return "n".
    del mock_input  # Unused
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS: [
                {constants.FIELD_NAMESPACED_NAME: "my-project/my-key"}
            ]
        }
    }

    with mock.patch.object(
        self.deleter, "delete_dg_tag_key", autospec=True
    ) as mock_delete:
      # Act: Attempt individual deletion.
      result = self.deleter.delete_individual_dgt_resource(
          plan, "my-project/my-key", constants.RESOURCE_TYPE_DG_TAG_KEY
      )

      # Assert: delete_dg_tag_key was never called and None was returned.
      self.assertIsNone(result)
      mock_delete.assert_not_called()

  @mock.patch("builtins.input", return_value="y", autospec=True)
  def test_delete_individual_raw_reader_policy_success(self, mock_input):
    """Verifies `delete_individual_dgt_resource` dispatches V2 Data Policy."""
    # Arrange: Prepare a plan with one Raw Reader V2 Data Policy action.
    del mock_input  # Unused
    action = {
        constants.FIELD_POLICY_ID: "raw-policy",
        "region": "us",
        "target_project_id": "my-project",
        "api_payload": {},
    }
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2: [action]
        }
    }

    override_deleter = deleter.Deleter(
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        allow_fail_open_policy_delete=True,
    )
    with mock.patch.object(
        override_deleter,
        "delete_data_policy_v2",
        return_value=constants.DELETE_STATUS_DELETED,
        autospec=True,
    ) as mock_delete:
      # Act: Delete the Raw Reader policy using `<project>/<policy_id>`.
      override_deleter.delete_individual_dgt_resource(
          plan,
          "my-project/raw-policy",
          constants.RESOURCE_TYPE_DATA_POLICY_V2,
      )

      # Assert: delete_data_policy_v2 was called with the action.
      mock_delete.assert_called_once_with(action)

  @mock.patch("builtins.input", return_value="y", autospec=True)
  def test_delete_individual_default_deny_policy_emits_fail_open_warning(
      self, mock_input
  ):
    """Verifies deleting a Default-Deny policy emits Fail-Open warning."""
    # Arrange: Prepare a Default-Deny policy action in the manifest.
    del mock_input  # Unused
    action = {
        constants.FIELD_POLICY_ID: "deny_policy_default_deny",
        constants.FIELD_REGION: "us",
        constants.FIELD_TARGET_PROJECT_ID: "my-project",
        constants.FIELD_DG_TAG_VALUE_NAMESPACED_NAME: (
            "my-project/my-key/my-value"
        ),
        constants.FIELD_API_PAYLOAD: {},
    }
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2: [action]
        }
    }

    override_deleter = deleter.Deleter(
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        allow_fail_open_policy_delete=True,
    )
    with mock.patch.object(
        override_deleter,
        "delete_data_policy_v2",
        return_value=constants.DELETE_STATUS_DELETED,
        autospec=True,
    ) as mock_delete:
      # Act: Delete the Default-Deny policy in live mode with explicit override.
      report = override_deleter.delete_individual_dgt_resource(
          plan,
          "my-project/deny_policy_default_deny",
          constants.RESOURCE_TYPE_DATA_POLICY_V2,
      )

      # Assert: The policy is deleted and the report contains the Fail-Open
      # warning.
      mock_delete.assert_called_once_with(action)
      self.assertIsNotNone(report)
      self.assertIn("[WARNING - FAIL-OPEN RISK]", report)
      self.assertIn("Fail-Open", report)

  @mock.patch("builtins.input", return_value="y", autospec=True)
  def test_delete_individual_policy_with_project_prefix_and_mode2_ambiguity(
      self, mock_input
  ):
    """Verifies Mode 2 ambiguity check and `<project>/<policy_id>` selection."""
    # Arrange: Build a Mode 2 manifest with shared-policy in two data projects.
    del mock_input  # Unused
    action_project_1 = {
        constants.FIELD_POLICY_ID: "shared-policy",
        "region": "us",
        "target_project_id": "data-project-1",
        "api_payload": {},
    }
    action_project_2 = {
        constants.FIELD_POLICY_ID: "shared-policy",
        "region": "us",
        "target_project_id": "data-project-2",
        "api_payload": {},
    }
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2: [
                action_project_1,
                action_project_2,
            ]
        }
    }

    # Unqualified name raises ValueError before prompting, listing matching
    # `<target_project_id>/<data_policy_id>` examples.
    with self.assertRaisesRegex(
        ValueError,
        r"Invalid Data Policy V2 resource name 'shared-policy'.*"
        r"'data-project-1/shared-policy', 'data-project-2/shared-policy'",
    ):
      self.deleter.delete_individual_dgt_resource(
          plan, "shared-policy", constants.RESOURCE_TYPE_DATA_POLICY_V2
      )

    # Act & Assert 2: Project-prefixed name disambiguates and deletes
    # action_project_2 when `allow_fail_open_policy_delete=True`.
    override_deleter = deleter.Deleter(
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        allow_fail_open_policy_delete=True,
    )
    with mock.patch.object(
        override_deleter,
        "delete_data_policy_v2",
        return_value=constants.DELETE_STATUS_DELETED,
        autospec=True,
    ) as mock_delete:
      override_deleter.delete_individual_dgt_resource(
          plan,
          "data-project-2/shared-policy",
          constants.RESOURCE_TYPE_DATA_POLICY_V2,
      )
      mock_delete.assert_called_once_with(action_project_2)

  # =========================================================================
  # === Section 3: Dry-Run Inspection & V2 REST Fallback Tests ===
  # =========================================================================

  @mock.patch("builtins.input", autospec=True)
  def test_dry_run_delete_dg_tag_key_blocked_by_child_values(self, mock_input):
    """Verifies dry-run Tag Key deletion reports `BLOCKED` on live children."""
    # Arrange: Configure list_tag_keys and list_tag_values with a live child.
    dry_run_deleter = deleter.Deleter(
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        dry_run=True,
    )
    mock_key = types.SimpleNamespace(name="tagKeys/123", short_name="my-key")
    self.mock_tag_keys_client.list_tag_keys.return_value = [mock_key]

    mock_child = types.SimpleNamespace(
        name="tagValues/456", short_name="child-value", parent="tagKeys/123"
    )
    self.mock_tag_values_client.list_tag_values.return_value = [mock_child]

    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS: [
                {constants.FIELD_NAMESPACED_NAME: "my-project/my-key"}
            ]
        }
    }

    # Act: Preview deletion of the Tag Key.
    report = dry_run_deleter.delete_individual_dgt_resource(
        plan, "my-project/my-key", constants.RESOURCE_TYPE_DG_TAG_KEY
    )

    # Assert: Status is BLOCKED and zero mutations occurred.
    mock_input.assert_not_called()
    self.mock_tag_keys_client.delete_tag_key.assert_not_called()
    self.assertIsNotNone(report)
    self.assertIn("**BLOCKED**", report)
    self.assertIn("live child DG Tag Value(s)", report)

  @mock.patch("builtins.input", autospec=True)
  def test_dry_run_delete_dg_tag_value_would_delete_with_policy_warning(
      self, mock_input
  ):
    """Verifies dry-run leaf Tag Value deletion warns of plan Data Policies."""
    # Arrange: Configure a leaf Tag Value with no child values and one
    # referencing Data Policy in plan.json.
    dry_run_deleter = deleter.Deleter(
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        dry_run=True,
    )
    mock_key = types.SimpleNamespace(name="tagKeys/123", short_name="my-key")
    self.mock_tag_keys_client.list_tag_keys.return_value = [mock_key]

    mock_value = types.SimpleNamespace(
        name="tagValues/456", short_name="my-value", parent="tagKeys/123"
    )

    def list_tag_values_side_effect(parent, retry=None):
      del retry
      if parent == "tagKeys/123":
        return [mock_value]
      return []

    self.mock_tag_values_client.list_tag_values.side_effect = (
        list_tag_values_side_effect
    )

    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES: [
                {constants.FIELD_NAMESPACED_NAME: "my-project/my-key/my-value"}
            ],
            constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2: [{
                constants.FIELD_POLICY_ID: "raw-policy",
                constants.FIELD_DG_TAG_VALUE_NAMESPACED_NAME: (
                    "my-project/my-key/my-value"
                ),
            }],
        }
    }

    # Act: Preview deletion of the leaf Tag Value.
    report = dry_run_deleter.delete_individual_dgt_resource(
        plan,
        "my-project/my-key/my-value",
        constants.RESOURCE_TYPE_DG_TAG_VALUE,
    )

    # Assert: Report shows WOULD_DELETE and warns about raw-policy.
    mock_input.assert_not_called()
    self.mock_tag_values_client.delete_tag_value.assert_not_called()
    self.assertIsNotNone(report)
    self.assertIn("**WOULD_DELETE**", report)
    self.assertIn("raw-policy", report)

  @mock.patch("builtins.input", autospec=True)
  def test_dry_run_delete_default_deny_data_policy_warns_fail_open(
      self, mock_input
  ):
    """Verifies dry-run Default-Deny policy preview emits Fail-Open warning."""
    # Arrange: Configure get_data_policy to return a live policy object.
    dry_run_deleter = deleter.Deleter(
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        dry_run=True,
    )
    self.mock_data_policy_v2_client.get_data_policy.return_value = (
        types.SimpleNamespace(
            name="projects/my-project/locations/us/dataPolicies/deny-policy"
        )
    )

    action = {
        constants.FIELD_POLICY_ID: "deny-policy",
        constants.FIELD_REGION: "us",
        constants.FIELD_TARGET_PROJECT_ID: "my-project",
        constants.FIELD_DG_TAG_VALUE_NAMESPACED_NAME: (
            "my-project/my-key/my-value"
        ),
    }
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2: [action]
        }
    }

    # Act: Preview deletion of the Default-Deny Data Policy.
    report = dry_run_deleter.delete_individual_dgt_resource(
        plan,
        "my-project/deny-policy",
        constants.RESOURCE_TYPE_DATA_POLICY_V2,
    )

    # Assert: Report shows WOULD_DELETE and warns about Fail-Open risk.
    mock_input.assert_not_called()
    self.mock_data_policy_v2_client.delete_data_policy.assert_not_called()
    self.assertIsNotNone(report)
    self.assertIn("**WOULD_DELETE**", report)
    self.assertIn("Fail-Open", report)

  @mock.patch("builtins.input", autospec=True)
  def test_skip_confirmation_deletes_without_prompt(self, mock_input):
    """Verifies `skip_confirmation=True` deletes without calling `input()`."""
    # Configure Deleter with both skip_confirmation=True and
    # allow_fail_open_policy_delete=True (since skip_confirmation alone never
    # overrides the live V2 Data Policy Fail-Open deletion block).
    non_interactive_deleter = deleter.Deleter(
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        skip_confirmation=True,
        allow_fail_open_policy_delete=True,
    )
    action = {
        constants.FIELD_POLICY_ID: "raw-policy",
        constants.FIELD_REGION: "us",
        constants.FIELD_TARGET_PROJECT_ID: "my-project",
    }
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2: [action]
        }
    }
    with tempfile.TemporaryDirectory() as temp_dir:
      report_path = os.path.join(temp_dir, "delete_report.md")
      # Act: Delete the policy with report_file.
      report = non_interactive_deleter.delete_individual_dgt_resource(
          plan,
          "my-project/raw-policy",
          constants.RESOURCE_TYPE_DATA_POLICY_V2,
          report_file=report_path,
      )
      self.assertTrue(os.path.exists(report_path))

    # Assert: input() was not called and status is DELETED.
    mock_input.assert_not_called()
    self.mock_data_policy_v2_client.delete_data_policy.assert_called_once()
    self.assertIsNotNone(report)
    self.assertIn("**DELETED**", report)

  def test_get_dg_tag_value_id_filters_nested_descendants(self):
    """Verifies `_get_dg_tag_value_id` ignores nested values with same name."""
    # Arrange: Configure root and nested Tag Values with identical short_name.
    mock_key = types.SimpleNamespace(short_name="my_key", name="tagKeys/123")
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

    # Act: Resolve the direct child Tag Value ID.
    resolved_id = self.deleter._get_dg_tag_value_id(
        "my-project/my_key/shared_name"
    )

    # Assert: Returns tagValues/root_100.
    self.assertEqual(resolved_id, "tagValues/root_100")

  @mock.patch("urllib.request.urlopen", autospec=True)
  @mock.patch("google.auth.default", autospec=True)
  def test_delete_data_policy_v2_rest_fallback_and_404_not_found(
      self, mock_auth, mock_urlopen
  ):
    """Verifies `delete_data_policy_v2` falls back to `/v2/` REST DELETE."""
    # Arrange: Configure delete_data_policy to raise InvalidArgument and mock
    # REST responses.
    self.mock_data_policy_v2_client.delete_data_policy.side_effect = (
        exceptions.InvalidArgument("V2 policy requires v2 endpoint")
    )
    mock_credentials = mock.create_autospec(
        auth_credentials.Credentials, instance=True, spec_set=False
    )
    mock_credentials.token = "fake-token"
    mock_auth.return_value = (mock_credentials, "fake-project")

    mock_urlopen.return_value = _make_urlopen_response(b"{}")

    action = {
        constants.FIELD_POLICY_ID: "my-policy",
        constants.FIELD_REGION: "us",
        constants.FIELD_TARGET_PROJECT_ID: "my-project",
    }

    # Act 1: Delete via REST fallback when policy exists.
    status = self.deleter.delete_data_policy_v2(action)

    # Assert 1: Returns DELETE_STATUS_DELETED.
    self.assertEqual(status, constants.DELETE_STATUS_DELETED)
    mock_urlopen.assert_called_once()

    # Act 2: Delete via REST fallback when HTTP 404 is returned.
    http_404 = urllib.error.HTTPError(
        url="https://bigquerydatapolicy.googleapis.com/v2/...",
        code=404,
        msg="Not Found",
        hdrs=None,
        fp=io.BytesIO(b"Not found"),
    )
    mock_urlopen.side_effect = http_404
    status_404 = self.deleter.delete_data_policy_v2(action)

    # Assert 2: HTTP 404 translates to DELETE_STATUS_SKIPPED.
    self.assertEqual(status_404, constants.DELETE_STATUS_SKIPPED)

  @mock.patch("urllib.request.urlopen", autospec=True)
  @mock.patch("google.auth.default", autospec=True)
  def test_dry_run_get_data_policy_v2_rest_fallback(
      self, mock_auth, mock_urlopen
  ):
    """Verifies dry-run inspection falls back to `/v2/` REST GET."""
    # Arrange: Configure dry-run Deleter with GAPIC failure and REST 200.
    dry_run_deleter = deleter.Deleter(
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        dry_run=True,
    )
    self.mock_data_policy_v2_client.get_data_policy.side_effect = (
        exceptions.InvalidArgument("V2 policy requires v2 endpoint")
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
        constants.FIELD_POLICY_ID: "my-policy",
        constants.FIELD_REGION: "us",
        constants.FIELD_TARGET_PROJECT_ID: "my-project",
    }
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2: [action]
        }
    }

    # Act: Preview deletion of the V2 Data Policy.
    report = dry_run_deleter.delete_individual_dgt_resource(
        plan,
        "my-project/my-policy",
        constants.RESOURCE_TYPE_DATA_POLICY_V2,
    )

    # Assert: Report shows WOULD_DELETE.
    self.assertIsNotNone(report)
    self.assertIn("**WOULD_DELETE**", report)

  # =========================================================================
  # === Section 4: Negative-Lookup Caching & Live Failure Report Tests ===
  # =========================================================================

  def test_get_dg_tag_key_id_negative_lookup_skips_relisting_project(self):
    """Verifies `_listed_tag_key_projects` prevents repeated `list_tag_keys`."""
    # Arrange: Return one key in "my-project" so "missing-1" and "missing-2"
    # are both absent.
    existing_key = types.SimpleNamespace(
        name="tagKeys/100", short_name="existing-key"
    )
    self.mock_tag_keys_client.list_tag_keys.return_value = [existing_key]

    # Act: Look up two different missing Tag Keys in the same project.
    first_lookup = self.deleter._get_dg_tag_key_id("my-project/missing-1")
    second_lookup = self.deleter._get_dg_tag_key_id("my-project/missing-2")

    # Assert: Both return None, my-project is recorded in
    # _listed_tag_key_projects, and list_tag_keys was called only once.
    self.assertIsNone(first_lookup)
    self.assertIsNone(second_lookup)
    self.assertIn("my-project", self.deleter._listed_tag_key_projects)
    self.mock_tag_keys_client.list_tag_keys.assert_called_once_with(
        parent="projects/my-project", retry=deleter.RETRY_CONFIG
    )

  def test_get_dg_tag_value_id_negative_lookup_skips_relisting_parent(self):
    """Verifies `_listed_tag_value_parents` avoids repeated value list RPCs."""
    # Arrange: Configure parent Tag Key tagKeys/123 with zero child values.
    mock_key = types.SimpleNamespace(name="tagKeys/123", short_name="my-key")
    self.mock_tag_keys_client.list_tag_keys.return_value = [mock_key]
    self.mock_tag_values_client.list_tag_values.return_value = []

    # Act: Look up two missing sibling Tag Values under my-project/my-key.
    first_val = self.deleter._get_dg_tag_value_id(
        "my-project/my-key/missing-val-1"
    )
    second_val = self.deleter._get_dg_tag_value_id(
        "my-project/my-key/missing-val-2"
    )

    # Assert: Both return None, tagKeys/123 is recorded in
    # _listed_tag_value_parents, and list_tag_values was called only once.
    self.assertIsNone(first_val)
    self.assertIsNone(second_val)
    self.assertIn("tagKeys/123", self.deleter._listed_tag_value_parents)
    self.mock_tag_values_client.list_tag_values.assert_called_once_with(
        parent="tagKeys/123", retry=deleter.RETRY_CONFIG
    )

  @mock.patch("builtins.input", return_value="y", autospec=True)
  def test_delete_individual_dg_tag_value_live_mode_warns_plan_dependents(
      self, mock_input
  ):
    """Verifies live Tag Value deletion warns of child values & policies."""
    # Arrange: Build a plan where parent-val has a child Tag Value with
    # parent_namespaced_name == "my-project/my-key/parent-val" and a V2 Data
    # Policy with dg_tag_value_namespaced_name ==
    # "my-project/my-key/parent-val".
    del mock_input  # Unused
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES: [
                {
                    constants.FIELD_NAMESPACED_NAME: (
                        "my-project/my-key/parent-val"
                    ),
                    constants.FIELD_PARENT_NAMESPACED_NAME: "my-project/my-key",
                },
                {
                    constants.FIELD_NAMESPACED_NAME: (
                        "my-project/my-key/parent-val/child-val"
                    ),
                    constants.FIELD_PARENT_NAMESPACED_NAME: (
                        "my-project/my-key/parent-val"
                    ),
                },
            ],
            constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2: [{
                constants.FIELD_POLICY_ID: "dependent-policy",
                constants.FIELD_DG_TAG_VALUE_NAMESPACED_NAME: (
                    "my-project/my-key/parent-val"
                ),
            }],
        }
    }

    with mock.patch.object(
        self.deleter,
        "delete_dg_tag_value",
        return_value=constants.DELETE_STATUS_DELETED,
        autospec=True,
    ) as mock_delete:
      # Act: Delete parent-val in live mode.
      report = self.deleter.delete_individual_dgt_resource(
          plan,
          "my-project/my-key/parent-val",
          constants.RESOURCE_TYPE_DG_TAG_VALUE,
      )

    # Assert: Both the child Tag Value warning and referencing V2 Data Policy
    # warning are included in the deletion report.
    mock_delete.assert_called_once_with("my-project/my-key/parent-val")
    self.assertIsNotNone(report)
    self.assertIn("my-project/my-key/parent-val/child-val", report)
    self.assertIn("dependent-policy", report)

  @mock.patch("builtins.input", return_value="y", autospec=True)
  def test_delete_individual_dgt_resource_writes_failed_report_on_exception(
      self, mock_input
  ):
    """Verifies live deletion error writes `FAILED` report."""
    # Arrange: Configure delete_dg_tag_value to raise FailedPrecondition while
    # report_file is specified.
    del mock_input  # Unused
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES: [{
                constants.FIELD_NAMESPACED_NAME: "my-project/my-key/my-val",
                constants.FIELD_PARENT_NAMESPACED_NAME: "my-project/my-key",
            }],
            constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2: [{
                constants.FIELD_POLICY_ID: "active-policy",
                constants.FIELD_DG_TAG_VALUE_NAMESPACED_NAME: (
                    "my-project/my-key/my-val"
                ),
            }],
        }
    }

    with tempfile.TemporaryDirectory() as temp_dir:
      report_path = os.path.join(temp_dir, "failed_delete_report.md")
      with mock.patch.object(
          self.deleter,
          "delete_dg_tag_value",
          side_effect=exceptions.FailedPrecondition(
              "TagValue is still bound to a DataPolicy"
          ),
          autospec=True,
      ):
        # Act: Attempt deletion expecting FailedPrecondition to be re-raised.
        with self.assertRaises(exceptions.FailedPrecondition):
          self.deleter.delete_individual_dgt_resource(
              plan,
              "my-project/my-key/my-val",
              constants.RESOURCE_TYPE_DG_TAG_VALUE,
              report_file=report_path,
          )

      # Assert: The FAILED report was persisted to report_path with both the
      # pre-delete warning and the exception message.
      self.assertTrue(os.path.exists(report_path))
      with open(report_path, "r", encoding="utf-8") as file_handle:
        saved_report = file_handle.read()
      self.assertIn("**FAILED**", saved_report)
      self.assertIn(
          f"Failed to delete {constants.RESOURCE_TYPE_DG_TAG_VALUE}"
          " 'my-project/my-key/my-val'",
          saved_report,
      )
      self.assertIn("active-policy", saved_report)
      self.assertIn("TagValue is still bound to a DataPolicy", saved_report)
      self.assertIn("## Error & Block Status Reference", saved_report)
      self.assertIn("- **`FAILED`**:", saved_report)

  def test_generate_delete_report_renders_error_reference_only_on_block_or_fail(
      self,
  ):
    """Renders deletion error/block enum definitions on block or failure."""
    # Successful deletion omits the error/block reference section.
    deleted_report = self.deleter._generate_delete_report(
        resource_name="my-project/my-key",
        resource_type=constants.RESOURCE_TYPE_DG_TAG_KEY,
        status=constants.DELETE_STATUS_DELETED,
        detail="Deleted DG Tag Key.",
        potential_issues=[],
    )
    self.assertNotIn("## Error & Block Status Reference", deleted_report)

    # Dry-run `BLOCKED` deletion includes the `BLOCKED` enum explanation.
    blocked_report = self.deleter._generate_delete_report(
        resource_name="my-project/my-key",
        resource_type=constants.RESOURCE_TYPE_DG_TAG_KEY,
        status=constants.DELETE_STATUS_BLOCKED,
        detail="Child Tag Values still exist.",
        potential_issues=["Delete child Tag Values first."],
    )
    self.assertIn("## Error & Block Status Reference", blocked_report)
    self.assertIn(f"- **`{constants.DELETE_STATUS_BLOCKED}`**:", blocked_report)

  @mock.patch("builtins.input", autospec=True)
  def test_delete_individual_data_policy_v2_mode1_unqualified_raises(
      self, mock_input
  ):
    """Rejects bare `<data_policy_id>` in Mode 1 before prompting."""
    # Single centralized Mode 1 project still requires `<project>/<policy_id>`.
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2: [{
                constants.FIELD_POLICY_ID: "raw-policy",
                constants.FIELD_REGION: "us",
                constants.FIELD_TARGET_PROJECT_ID: "gov-project",
                constants.FIELD_API_PAYLOAD: {},
            }]
        }
    }

    # Format validation rejects the bare policy ID before calling `input()`.
    with self.assertRaisesRegex(
        ValueError,
        r"Invalid Data Policy V2 resource name 'raw-policy'.*"
        r"'gov-project/raw-policy'",
    ):
      self.deleter.delete_individual_dgt_resource(
          plan, "raw-policy", constants.RESOURCE_TYPE_DATA_POLICY_V2
      )

    # Confirm no user prompt or delete RPC occurred.
    mock_input.assert_not_called()
    self.mock_data_policy_v2_client.delete_data_policy.assert_not_called()

  # Nested DG Tag Values can be addressed in `--phase delete` using either their
  # full hierarchical path in `plan.json` or their 3-segment Resource Manager
  # namespaced name (`<project>/<key_short>/<value_short>`).
  @mock.patch("builtins.input", return_value="y", autospec=True)
  def test_delete_individual_dg_tag_value_matches_three_segment_namespaced_name(
      self, mock_input
  ):
    """Resolves 3-segment `<proj>/<key>/<val>` to a unique nested Tag Value."""
    del mock_input  # Unused
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES: [
                {
                    constants.FIELD_NAMESPACED_NAME: (
                        "my-project/my-key/parent-val"
                    ),
                    constants.FIELD_PARENT_NAMESPACED_NAME: "my-project/my-key",
                },
                {
                    constants.FIELD_NAMESPACED_NAME: (
                        "my-project/my-key/parent-val/leaf-val"
                    ),
                    constants.FIELD_PARENT_NAMESPACED_NAME: (
                        "my-project/my-key/parent-val"
                    ),
                },
            ]
        }
    }

    # Delete the nested leaf Tag Value using its 3-segment Resource Manager
    # namespaced name.
    with mock.patch.object(
        self.deleter,
        "delete_dg_tag_value",
        return_value=constants.DELETE_STATUS_DELETED,
        autospec=True,
    ) as mock_delete:
      report = self.deleter.delete_individual_dgt_resource(
          plan,
          "my-project/my-key/leaf-val",
          constants.RESOURCE_TYPE_DG_TAG_VALUE,
      )

    # Confirm `delete_dg_tag_value` received the full hierarchical path from
    # `plan.json` so parent traversal resolves `parent-val` first.
    mock_delete.assert_called_once_with("my-project/my-key/parent-val/leaf-val")
    self.assertIsNotNone(report)
    self.assertIn("**DELETED**", report)

  # Dry-run Tag Value inspection probes planned V2 Data Policies that include
  # regional metadata (`target_project_id` and `region`), returning `BLOCKED`
  # when the policy still exists in GCP and `WOULD_DELETE` once it returns 404.
  @mock.patch("builtins.input", autospec=True)
  def test_dry_run_delete_dg_tag_value_blocked_by_live_v2_data_policy(
      self, mock_input
  ):
    """Reports `BLOCKED` when a planned V2 Data Policy still exists in GCP."""
    del mock_input  # Unused
    dry_run_deleter = deleter.Deleter(
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        dry_run=True,
    )
    mock_key = types.SimpleNamespace(name="tagKeys/123", short_name="my-key")
    self.mock_tag_keys_client.list_tag_keys.return_value = [mock_key]
    mock_value = types.SimpleNamespace(
        name="tagValues/456", short_name="my-value", parent="tagKeys/123"
    )
    self.mock_tag_values_client.list_tag_values.side_effect = (
        lambda parent, retry=None: [mock_value]
        if parent == "tagKeys/123"
        else []
    )

    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES: [
                {constants.FIELD_NAMESPACED_NAME: "my-project/my-key/my-value"}
            ],
            constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2: [{
                constants.FIELD_POLICY_ID: "raw-policy",
                constants.FIELD_REGION: "us",
                constants.FIELD_TARGET_PROJECT_ID: "data-proj",
                constants.FIELD_DG_TAG_VALUE_NAMESPACED_NAME: (
                    "my-project/my-key/my-value"
                ),
            }],
        }
    }

    # Case 1: The referencing V2 Data Policy exists in GCP (`get_data_policy`
    # succeeds), so dry-run reports `BLOCKED` with `<project>/<policy_id>`.
    self.mock_data_policy_v2_client.get_data_policy.return_value = (
        types.SimpleNamespace(
            name="projects/data-proj/locations/us/dataPolicies/raw-policy"
        )
    )
    blocked_report = dry_run_deleter.delete_individual_dgt_resource(
        plan,
        "my-project/my-key/my-value",
        constants.RESOURCE_TYPE_DG_TAG_VALUE,
    )
    self.assertIsNotNone(blocked_report)
    self.assertIn("**BLOCKED**", blocked_report)
    self.assertIn("data-proj/raw-policy", blocked_report)

    # Case 2: Once the V2 Data Policy is deleted in GCP (`NotFound`), dry-run
    # reports `WOULD_DELETE` with zero potential issues.
    self.mock_data_policy_v2_client.get_data_policy.side_effect = (
        exceptions.NotFound("Data policy already deleted")
    )
    would_delete_report = dry_run_deleter.delete_individual_dgt_resource(
        plan,
        "my-project/my-key/my-value",
        constants.RESOURCE_TYPE_DG_TAG_VALUE,
    )
    self.assertIsNotNone(would_delete_report)
    self.assertIn("**WOULD_DELETE**", would_delete_report)
    self.assertIn("- **Potential Issues Detected**: 0", would_delete_report)

  # Skipping an already-deleted resource (`DELETE_STATUS_SKIPPED`) has zero
  # Fail-Open or dependency risk, so the report must record 0 potential issues
  # even without `allow_fail_open_policy_delete=True`.
  def test_delete_skipped_resource_omits_spurious_potential_issues(self):
    """Omits Fail-Open warnings when a V2 Data Policy is already `SKIPPED`."""
    non_interactive_deleter = deleter.Deleter(
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        skip_confirmation=True,
    )
    self.mock_data_policy_v2_client.get_data_policy.side_effect = (
        exceptions.NotFound("Already deleted")
    )
    self.mock_data_policy_v2_client.delete_data_policy.side_effect = (
        exceptions.NotFound("Already deleted")
    )
    action = {
        constants.FIELD_POLICY_ID: "deny_policy_default_deny",
        constants.FIELD_REGION: "us",
        constants.FIELD_TARGET_PROJECT_ID: "my-project",
        constants.FIELD_DG_TAG_VALUE_NAMESPACED_NAME: (
            "my-project/my-key/my-value"
        ),
    }
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2: [action]
        }
    }

    # Deleting an already-absent Default-Deny policy returns `SKIPPED` without
    # attaching a false Fail-Open warning.
    report = non_interactive_deleter.delete_individual_dgt_resource(
        plan,
        "my-project/deny_policy_default_deny",
        constants.RESOURCE_TYPE_DATA_POLICY_V2,
    )
    self.assertIsNotNone(report)
    self.assertIn("**SKIPPED**", report)
    self.assertIn("- **Potential Issues Detected**: 0", report)
    self.assertNotIn("## Potential Issues & Warnings", report)

  # Cloud Resource Manager LRO exceptions repeat their error message after a
  # gRPC status code (`"400 <msg> 9: <msg>"`); `_clean_exception_message` strips
  # the duplicate suffix.
  def test_clean_exception_message_deduplicates_lro_grpc_status_suffix(self):
    """Strips repeated `<code_num>: <same_message>` suffix from LRO errors."""
    raw_error = exceptions.FailedPrecondition(
        "Cannot delete tag value [tagValues/123]: Existing bindings"
        " referenced by the tag value must be deleted. 9: Cannot delete tag"
        " value [tagValues/123]: Existing bindings referenced by the tag value"
        " must be deleted."
    )
    cleaned = deleter._clean_exception_message(raw_error)
    self.assertEqual(
        cleaned,
        "400 Cannot delete tag value [tagValues/123]: Existing bindings"
        " referenced by the tag value must be deleted.",
    )

  # V1-aliased `DataPolicyServiceClient` rejects V2 Data Policies with
  # `FailedPrecondition`; both dry-run and live deletion must fall back to REST.
  def test_delete_data_policy_v2_falls_back_to_rest_on_failed_precondition(
      self,
  ):
    """Falls back to `/v2/` REST when GAPIC raises `FailedPrecondition`."""
    action = {
        constants.FIELD_POLICY_ID: "v2_policy",
        constants.FIELD_REGION: "us",
        constants.FIELD_TARGET_PROJECT_ID: "my-project",
    }
    v1_error = exceptions.FailedPrecondition(
        "Only V1 data policies can be deleted using V1 api"
    )
    self.mock_data_policy_v2_client.delete_data_policy.side_effect = v1_error
    self.mock_data_policy_v2_client.get_data_policy.side_effect = v1_error

    # Verify live delete falls back to `_delete_data_policy_v2_rest`.
    with mock.patch.object(
        self.deleter,
        "_delete_data_policy_v2_rest",
        autospec=True,
    ) as mock_rest_delete:
      live_status = self.deleter.delete_data_policy_v2(action)
    mock_rest_delete.assert_called_once_with(
        "projects/my-project/locations/us/dataPolicies/v2_policy"
    )
    self.assertEqual(live_status, constants.DELETE_STATUS_DELETED)

    # Verify dry-run inspect falls back to `_get_data_policy_v2_rest`.
    dry_run_deleter = deleter.Deleter(
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        dry_run=True,
    )
    with mock.patch.object(
        dry_run_deleter,
        "_get_data_policy_v2_rest",
        return_value={
            "name": "projects/123/locations/us/dataPolicies/v2_policy"
        },
        autospec=True,
    ) as mock_rest_get:
      dry_status = dry_run_deleter.delete_data_policy_v2(action)
    mock_rest_get.assert_called_once_with(
        "projects/my-project/locations/us/dataPolicies/v2_policy"
    )
    self.assertEqual(dry_status, constants.DELETE_STATUS_WOULD_DELETE)

  # Non-interactive `EOFError` during the deletion confirmation prompt must
  # raise `RuntimeError` rather than returning `None`.
  @mock.patch("builtins.input", side_effect=EOFError, autospec=True)
  def test_delete_individual_dgt_resource_raises_on_eof_prompt_abort(
      self, mock_input
  ):
    """Raises `RuntimeError` when `input()` hits `EOFError` during delete."""
    del mock_input  # Unused
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS: [
                {constants.FIELD_NAMESPACED_NAME: "my-project/my-key"}
            ]
        }
    }

    with self.assertRaisesRegex(
        RuntimeError, "Interactive confirmation prompt aborted"
    ):
      self.deleter.delete_individual_dgt_resource(
          plan, "my-project/my-key", constants.RESOURCE_TYPE_DG_TAG_KEY
      )

  # Live V2 Data Policy deletion must be blocked by default—even when
  # `skip_confirmation=True`—unless `allow_fail_open_policy_delete=True` is set.
  @mock.patch("builtins.input", autospec=True)
  def test_live_delete_data_policy_v2_blocks_without_explicit_override(
      self, mock_input
  ):
    """Refuses live `data-policy-v2` delete unless override flag is enabled."""
    # Even with `skip_confirmation=True`, `allow_fail_open_policy_delete`
    # defaults to `False` so automated scripts cannot accidentally strip a
    # `_default_deny` policy while its DG Tag Value is still bound to columns.
    non_interactive_deleter = deleter.Deleter(
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        skip_confirmation=True,
    )
    self.mock_data_policy_v2_client.get_data_policy.return_value = (
        types.SimpleNamespace(
            name="projects/my-project/locations/us/dataPolicies/deny_policy"
        )
    )
    action = {
        constants.FIELD_POLICY_ID: "deny_policy_default_deny",
        constants.FIELD_REGION: "us",
        constants.FIELD_TARGET_PROJECT_ID: "my-project",
        constants.FIELD_DG_TAG_VALUE_NAMESPACED_NAME: (
            "my-project/my-key/my-value"
        ),
    }
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2: [action]
        }
    }

    # Execute live delete without `--allow-fail-open-policy-delete`; the gate
    # must block before calling `input()` or `delete_data_policy`.
    report = non_interactive_deleter.delete_individual_dgt_resource(
        plan,
        "my-project/deny_policy_default_deny",
        constants.RESOURCE_TYPE_DATA_POLICY_V2,
    )

    mock_input.assert_not_called()
    self.mock_data_policy_v2_client.delete_data_policy.assert_not_called()
    self.assertIsNotNone(report)
    self.assertIn(
        f"- **Status**: **{constants.DELETE_STATUS_BLOCKED}**", report
    )
    self.assertIn("--allow-fail-open-policy-delete", report)

  # Domain-scoped project IDs containing ':' in `--resource-name` are rejected.
  def test_delete_individual_rejects_domain_scoped_resource_name(self):
    """Raises `ValueError` when `--resource-name` uses a domain-scoped ID."""
    plan = {constants.KEY_PHASE_2_RESOURCE_MANIFEST: {}}
    with self.assertRaises(ValueError) as ctx:
      self.deleter.delete_individual_dgt_resource(
          plan,
          "example.com:my-project/my-key",
          constants.RESOURCE_TYPE_DG_TAG_KEY,
      )
    self.assertIn(
        constants.UNSUPPORTED_DOMAIN_SCOPED_PROJECT_MSG, str(ctx.exception)
    )

  # `delete_individual_dgt_resource` rejects unsupported `schema_version` before
  # prompting or issuing Resource Manager / Data Policy API calls.
  def test_delete_individual_rejects_unsupported_plan_schema_version(self):
    future_plan = {
        "metadata": {"schema_version": 2},
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {},
    }
    with self.assertRaisesRegex(
        ValueError,
        r"Unsupported migration plan schema_version=2.*schema_version=1",
    ):
      self.deleter.delete_individual_dgt_resource(
          future_plan,
          "my-project/my-key",
          constants.RESOURCE_TYPE_DG_TAG_KEY,
      )
    self.mock_tag_keys_client.list_tag_keys.assert_not_called()

  # Under `--skip-confirmation`, Fail-Open warnings must be logged *before* the
  # live delete RPC when the target exists, and omitted when already `SKIPPED`.
  def test_skip_confirmation_logs_fail_open_warning_before_live_delete(self):
    """Logs Fail-Open warning before live delete and omits it on `SKIPPED`."""
    non_interactive_deleter = deleter.Deleter(
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        skip_confirmation=True,
        allow_fail_open_policy_delete=True,
    )
    action = {
        constants.FIELD_POLICY_ID: "deny_policy_default_deny",
        constants.FIELD_REGION: "us",
        constants.FIELD_TARGET_PROJECT_ID: "my-project",
        constants.FIELD_DG_TAG_VALUE_NAMESPACED_NAME: (
            "my-project/my-key/my-value"
        ),
    }
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2: [action]
        }
    }

    # Case 1: Live policy exists -> Fail-Open warning precedes delete log entry.
    live_policy = types.SimpleNamespace(
        name=(
            "projects/my-project/locations/us/dataPolicies/"
            "deny_policy_default_deny"
        )
    )
    self.mock_data_policy_v2_client.get_data_policy.return_value = live_policy
    with self.assertLogs(deleter.logger, level="INFO") as existing_logs:
      non_interactive_deleter.delete_individual_dgt_resource(
          plan,
          "my-project/deny_policy_default_deny",
          constants.RESOURCE_TYPE_DATA_POLICY_V2,
      )
    warning_indices = [
        index
        for index, message in enumerate(existing_logs.output)
        if "[WARNING - FAIL-OPEN RISK]" in message
    ]
    delete_indices = [
        index
        for index, message in enumerate(existing_logs.output)
        if "Deleting Data Policy V2:" in message
    ]
    self.assertEqual(len(warning_indices), 1)
    self.assertEqual(len(delete_indices), 1)
    self.assertLess(warning_indices[0], delete_indices[0])

    # Case 2: Policy is already absent (404) -> `SKIPPED` with zero warnings.
    self.mock_data_policy_v2_client.get_data_policy.side_effect = (
        exceptions.NotFound("already deleted")
    )
    self.mock_data_policy_v2_client.delete_data_policy.side_effect = (
        exceptions.NotFound("already deleted")
    )
    with self.assertLogs(deleter.logger, level="INFO") as skipped_logs:
      skipped_report = non_interactive_deleter.delete_individual_dgt_resource(
          plan,
          "my-project/deny_policy_default_deny",
          constants.RESOURCE_TYPE_DATA_POLICY_V2,
      )
    self.assertIn("**SKIPPED**", skipped_report)
    self.assertFalse(
        any(
            "[WARNING - FAIL-OPEN RISK]" in message
            for message in skipped_logs.output
        )
    )

  # Interactive confirmation suppresses duplicate `print()` when the logger
  # already emits warnings to the same console, and prints when redirected.
  @mock.patch("builtins.input", return_value="n", autospec=True)
  def test_interactive_mode_suppresses_duplicate_stdout_warning(
      self, mock_input
  ):
    """Avoids printing Fail-Open warning twice when console logger is active."""
    del mock_input  # Unused
    override_deleter = deleter.Deleter(
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        allow_fail_open_policy_delete=True,
    )
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2: [{
                constants.FIELD_POLICY_ID: "deny_policy_default_deny",
                constants.FIELD_REGION: "us",
                constants.FIELD_TARGET_PROJECT_ID: "my-project",
                constants.FIELD_DG_TAG_VALUE_NAMESPACED_NAME: (
                    "my-project/my-key/my-value"
                ),
            }]
        }
    }

    # When console logging is already visible, stdout skips duplicate `print()`.
    shared_stdout = io.StringIO()
    with (
        mock.patch.object(
            deleter, "_logger_emits_to_console", return_value=True
        ),
        mock.patch.object(sys, "stdout", shared_stdout),
        self.assertLogs(deleter.logger, level="WARNING") as shared_logs,
    ):
      override_deleter.delete_individual_dgt_resource(
          plan,
          "my-project/deny_policy_default_deny",
          constants.RESOURCE_TYPE_DATA_POLICY_V2,
      )
    self.assertEqual(
        sum("[WARNING - FAIL-OPEN RISK]" in msg for msg in shared_logs.output),
        1,
    )
    self.assertNotIn("[WARNING - FAIL-OPEN RISK]", shared_stdout.getvalue())

    # When logger output is redirected away from the console, stdout mirrors it.
    split_stdout = io.StringIO()
    with (
        mock.patch.object(
            deleter, "_logger_emits_to_console", return_value=False
        ),
        mock.patch.object(sys, "stdout", split_stdout),
        self.assertLogs(deleter.logger, level="WARNING"),
    ):
      override_deleter.delete_individual_dgt_resource(
          plan,
          "my-project/deny_policy_default_deny",
          constants.RESOURCE_TYPE_DATA_POLICY_V2,
      )
    self.assertIn("[WARNING - FAIL-OPEN RISK]", split_stdout.getvalue())

  # Dry-run `BLOCKED` reports on Tag Keys and nested parent Tag Values must
  # reconstruct full hierarchical child paths despite flat CRM namespaced names.
  def test_dry_run_blocked_reconstructs_nested_child_tag_value_paths(self):
    """Displays full hierarchical child Tag Value paths in dry-run reports."""
    dry_run_deleter = deleter.Deleter(
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        dry_run=True,
    )
    mock_key = types.SimpleNamespace(name="tagKeys/100", short_name="my-key")
    self.mock_tag_keys_client.list_tag_keys.return_value = [mock_key]

    # CRM returns flat 3-segment `namespaced_name` even for nested child values.
    parent_value = types.SimpleNamespace(
        name="tagValues/200",
        short_name="parent_val",
        namespaced_name="my-project/my-key/parent_val",
        parent="tagKeys/100",
    )
    nested_child = types.SimpleNamespace(
        name="tagValues/300",
        short_name="child_val",
        namespaced_name="my-project/my-key/child_val",
        parent="tagValues/200",
    )

    def list_values_by_parent(parent, retry=None):
      del retry
      if parent == "tagKeys/100":
        return [parent_value, nested_child]
      if parent == "tagValues/200":
        return [nested_child]
      return []

    self.mock_tag_values_client.list_tag_values.side_effect = (
        list_values_by_parent
    )
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS: [
                {constants.FIELD_NAMESPACED_NAME: "my-project/my-key"}
            ],
            constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES: [
                {
                    constants.FIELD_NAMESPACED_NAME: (
                        "my-project/my-key/parent_val"
                    )
                },
                {
                    constants.FIELD_NAMESPACED_NAME: (
                        "my-project/my-key/parent_val/child_val"
                    ),
                    constants.FIELD_PARENT_NAMESPACED_NAME: (
                        "my-project/my-key/parent_val"
                    ),
                },
            ],
        }
    }

    with tempfile.TemporaryDirectory() as temp_dir:
      key_report_path = os.path.join(temp_dir, "key_blocked.md")
      key_report = dry_run_deleter.delete_individual_dgt_resource(
          plan,
          "my-project/my-key",
          constants.RESOURCE_TYPE_DG_TAG_KEY,
          report_file=key_report_path,
      )
      value_report = dry_run_deleter.delete_individual_dgt_resource(
          plan,
          "my-project/my-key/parent_val",
          constants.RESOURCE_TYPE_DG_TAG_VALUE,
      )
      with open(key_report_path, "r", encoding="utf-8") as report_handle:
        saved_key_report = report_handle.read()

    # Both Tag Key and parent Tag Value reports show full hierarchical path
    # rather than flat CRM `my-project/my-key/child_val`, and file ends in `\n`.
    self.assertIn("**BLOCKED**", key_report)
    self.assertIn("my-project/my-key/parent_val/child_val", key_report)
    self.assertNotIn("`my-project/my-key/child_val`", key_report)
    self.assertIn("**BLOCKED**", value_report)
    self.assertIn("my-project/my-key/parent_val/child_val", value_report)
    self.assertTrue(saved_key_report.endswith("\n"))


if __name__ == "__main__":
  unittest.main()
