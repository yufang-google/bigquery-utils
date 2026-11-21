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

"""Unit tests for the Phase 3 Swapper module (`swapper.py`).

Tests the full Phase 3 forward migration (`--swap-mode pt-to-dgt`) and automated
rollback (`--swap-mode dgt-to-pt`) lifecycle across 7 functional sections:
  - Section 1: Scope Resolution (`--table-project-ids`, `--dataset-ids`,
    `--table-ids`, `--regions`, and `VIEW` / `SNAPSHOT` skipping).
  - Section 2: Schema Transformation (top-level columns, nested `RECORD` /
    `STRUCT` fields, and numeric GCP project-number Policy Tag normalization).
  - Section 3: Strict Schema Integrity Safeguard (`verify_schema_swap_integrity`
    and `SchemaCorruptionError` abort gates).
  - Section 4: Pre-Swap Enforcement Parity Verification
    (`verify_enforcement_parity` across `ACCESS_LEAKAGE_RISK`,
    `ACCESS_BLOCKAGE_RISK`, and `RESOURCE_DISCREPANCY_RISK`, hierarchical tag
    inheritance, and REST fallback).
  - Section 5: Backup, Unified Diff Logging, Interactive Confirmation, and
    Dry-Run Orchestration (`swap_table_schema` and `swap_schemas`).
  - Section 6: Mode 2 DGT-to-PT Automated Rollback (`--swap-mode dgt-to-pt`
    round-trip fidelity, multi-DGT rejection, and parity bypass).
  - Section 7: Scale, Seatbelt, and Strict Tag-Matching Regressions
    (`INFORMATION_SCHEMA.COLUMN_FIELD_PATHS` pre-filtering in both `pt-to-dgt`
    and `dgt-to-pt` modes, `_default_deny` REST GET drift detection, and strict
    cross-project/sibling tag matching).
"""

from __future__ import annotations

import copy
import json
import logging
import os
import sys
import tempfile
import types
import unittest
from unittest import mock

import google.api_core.exceptions
import google.auth.exceptions
from google.cloud import bigquery
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
import swapper

# pylint: enable=g-import-not-at-top,g-bad-import-order


class _FakeCredentials:
  """Hermetic test double for `google.auth` credentials in REST fallback tests.

  Simulates an active OAuth2 bearer token (`"fake-token"`) so REST helper
  methods (`_list_data_policies_v2_rest` and `_fetch_v2_data_policy_grantees`)
  can be exercised without network access.
  """

  token: str | None = "fake-token"
  valid: bool = True

  def refresh(self, request: object) -> None:
    pass


class _RecordingPromptCallback:
  """Callable test double that records interactive confirmation prompts.

  Captures every prompt string passed to `confirmation_callback` and returns a
  pre-configured operator response (`"y"` or `"n"`).
  """

  def __init__(self, response: str):
    self._response = response
    self.prompts: list[str] = []

  def __call__(self, prompt: str) -> str:
    self.prompts.append(prompt)
    return self._response


class _FakeTable:
  """Lightweight BigQuery `Table` double holding raw wire schema dictionaries.

  Mirrors `google.cloud.bigquery.Table`'s `_properties["schema"]["fields"]` and
  `to_api_repr()` behavior so `_extract_raw_schema_fields` and
  `_apply_raw_schema_fields_to_table` can be tested with exact wire-format JSON
  dictionaries (including columns that intentionally omit `"mode"`).
  """

  def __init__(self, fields: list[dict[str, object]], location: str = "US"):
    self.location = location
    self._properties = {"schema": {"fields": copy.deepcopy(fields)}}

  def to_api_repr(self) -> dict[str, object]:
    return copy.deepcopy(self._properties)


def _make_sample_plan() -> dict[str, object]:
  """Builds a sample migration plan covering all 6 Policy Tag archetypes.

  The returned plan exercises every enforcement pattern encountered in Phase 3:
    1. `policyTags/201` -> `Email_Mask_Root`: Masked column (`EMAIL_MASK`) +
       mandatory `_default_deny` raw seatbelt.
    2. `policyTags/202` -> `Sha256_Mask_Root`: Masked column (`SHA256`) +
       mandatory `_default_deny` raw seatbelt.
    3. `policyTags/203` -> `Raw_Root`: Access-controlled root tag with direct
       Fine-Grained Reader (`raw_reader@example.com`).
    4. `policyTags/204` -> `Deny_Default_Root`: Access-controlled tag with zero
       readers and zero masking policies (protected by `_default_deny`).
    5. `policyTags/205` -> `Raw_Child`: Child tag under `Raw_Root` that inherits
       `raw_reader@example.com` from `Raw_Root` and has its own `_default_deny`
       seatbelt.
    6. `policyTags/901` -> `Public_Info`: Classification-only tag
       (`is_access_control: False`) that must have zero V2 Data Policies.

  Returns:
    A dictionary matching the `plan.json` schema consumed by `Swapper`.
  """
  policy_tag_email = (
      "projects/source-proj/locations/us/taxonomies/100/policyTags/201"
  )
  policy_tag_sha256 = (
      "projects/source-proj/locations/us/taxonomies/100/policyTags/202"
  )
  policy_tag_raw = (
      "projects/source-proj/locations/us/taxonomies/100/policyTags/203"
  )
  policy_tag_deny = (
      "projects/source-proj/locations/us/taxonomies/100/policyTags/204"
  )
  policy_tag_child = (
      "projects/source-proj/locations/us/taxonomies/100/policyTags/205"
  )
  policy_tag_classification = (
      "projects/source-proj/locations/us/taxonomies/999/policyTags/901"
  )

  dg_key_access = "target-dgt-proj/manual_migration_taxonomy"
  dg_key_class = "target-dgt-proj/classification_only_taxonomy"

  dg_value_email = f"{dg_key_access}/Email_Mask_Root"
  dg_value_sha256 = f"{dg_key_access}/Sha256_Mask_Root"
  dg_value_raw = f"{dg_key_access}/Raw_Root"
  dg_value_deny = f"{dg_key_access}/Deny_Default_Root"
  dg_value_child = f"{dg_key_access}/Raw_Child"
  dg_value_class = f"{dg_key_class}/Public_Info"

  return {
      "metadata": {
          "source_project_id": "source-proj",
          "target_dgt_project_id": "target-dgt-proj",
          "target_data_policy_mode": (
              constants.TARGET_DATA_POLICY_MODE_TABLE_PROJECTS
          ),
          "target_data_policy_project_ids": ["data-proj"],
      },
      "phase_2_resource_manifest": {
          "create_dg_tag_keys": [
              {
                  "action": constants.ACTION_CREATE_DG_TAG_KEY,
                  "namespaced_name": dg_key_access,
                  "source_taxonomy": (
                      "projects/source-proj/locations/us/taxonomies/100"
                  ),
                  "is_access_control": True,
              },
              {
                  "action": constants.ACTION_CREATE_DG_TAG_KEY,
                  "namespaced_name": dg_key_class,
                  "source_taxonomy": (
                      "projects/source-proj/locations/us/taxonomies/999"
                  ),
                  "is_access_control": False,
              },
          ],
          "create_dg_tag_values": [
              {
                  "action": constants.ACTION_CREATE_DG_TAG_VALUE,
                  "namespaced_name": dg_value_email,
                  "parent_namespaced_name": dg_key_access,
                  "source_policy_tag": policy_tag_email,
              },
              {
                  "action": constants.ACTION_CREATE_DG_TAG_VALUE,
                  "namespaced_name": dg_value_sha256,
                  "parent_namespaced_name": dg_key_access,
                  "source_policy_tag": policy_tag_sha256,
              },
              {
                  "action": constants.ACTION_CREATE_DG_TAG_VALUE,
                  "namespaced_name": dg_value_raw,
                  "parent_namespaced_name": dg_key_access,
                  "source_policy_tag": policy_tag_raw,
              },
              {
                  "action": constants.ACTION_CREATE_DG_TAG_VALUE,
                  "namespaced_name": dg_value_deny,
                  "parent_namespaced_name": dg_key_access,
                  "source_policy_tag": policy_tag_deny,
              },
              {
                  "action": constants.ACTION_CREATE_DG_TAG_VALUE,
                  "namespaced_name": dg_value_child,
                  "parent_namespaced_name": dg_value_raw,
                  "source_policy_tag": policy_tag_child,
              },
              {
                  "action": constants.ACTION_CREATE_DG_TAG_VALUE,
                  "namespaced_name": dg_value_class,
                  "parent_namespaced_name": dg_key_class,
                  "source_policy_tag": policy_tag_classification,
              },
          ],
          "create_data_policies_v2": [
              {
                  "action": constants.ACTION_CREATE_DATA_POLICY_V2,
                  "target_project_id": "data-proj",
                  "region": "us",
                  "policy_id": "migrated_masking_email_mask_policy",
                  "source_entity": (
                      "projects/source-proj/locations/us/dataPolicies/"
                      "email_mask_policy"
                  ),
                  "policy_origin": constants.POLICY_ORIGIN_MIGRATED_V1,
                  "grantees": ["user:masked_reader@example.com"],
                  "api_payload": {
                      "data_policy_id": "migrated_masking_email_mask_policy",
                      "data_policy_type": constants.DATA_POLICY_TYPE_MASKING,
                      "data_governance_tag": {
                          "key": dg_key_access,
                          "value": dg_value_email,
                      },
                      "data_masking_policy": {
                          "predefined_expression": "EMAIL_MASK",
                      },
                  },
              },
              {
                  "action": constants.ACTION_CREATE_DATA_POLICY_V2,
                  "target_project_id": "data-proj",
                  "region": "us",
                  "policy_id": "migrated_raw_email_mask_root_default_deny",
                  "source_entity": policy_tag_email,
                  "policy_origin": (
                      constants.POLICY_ORIGIN_SYNTHETIC_DEFAULT_DENY
                  ),
                  "grantees": [],
                  "api_payload": {
                      "data_policy_id": (
                          "migrated_raw_email_mask_root_default_deny"
                      ),
                      "data_policy_type": constants.DATA_POLICY_TYPE_RAW,
                      "data_governance_tag": {
                          "key": dg_key_access,
                          "value": dg_value_email,
                      },
                  },
              },
              {
                  "action": constants.ACTION_CREATE_DATA_POLICY_V2,
                  "target_project_id": "data-proj",
                  "region": "us",
                  "policy_id": "migrated_masking_sha256_mask_policy",
                  "source_entity": (
                      "projects/source-proj/locations/us/dataPolicies/"
                      "sha256_mask_policy"
                  ),
                  "policy_origin": constants.POLICY_ORIGIN_MIGRATED_V1,
                  "grantees": ["user:masked_reader@example.com"],
                  "api_payload": {
                      "data_policy_id": "migrated_masking_sha256_mask_policy",
                      "data_policy_type": constants.DATA_POLICY_TYPE_MASKING,
                      "data_governance_tag": {
                          "key": dg_key_access,
                          "value": dg_value_sha256,
                      },
                      "data_masking_policy": {
                          "predefined_expression": "SHA256",
                      },
                  },
              },
              {
                  "action": constants.ACTION_CREATE_DATA_POLICY_V2,
                  "target_project_id": "data-proj",
                  "region": "us",
                  "policy_id": "migrated_raw_sha256_mask_root_default_deny",
                  "source_entity": policy_tag_sha256,
                  "policy_origin": (
                      constants.POLICY_ORIGIN_SYNTHETIC_DEFAULT_DENY
                  ),
                  "grantees": [],
                  "api_payload": {
                      "data_policy_id": (
                          "migrated_raw_sha256_mask_root_default_deny"
                      ),
                      "data_policy_type": constants.DATA_POLICY_TYPE_RAW,
                      "data_governance_tag": {
                          "key": dg_key_access,
                          "value": dg_value_sha256,
                      },
                  },
              },
              {
                  "action": constants.ACTION_CREATE_DATA_POLICY_V2,
                  "target_project_id": "data-proj",
                  "region": "us",
                  "policy_id": "migrated_raw_raw_root",
                  "source_entity": policy_tag_raw,
                  "policy_origin": constants.POLICY_ORIGIN_SYNTHETIC_RAW_READER,
                  "grantees": ["user:raw_reader@example.com"],
                  "api_payload": {
                      "data_policy_id": "migrated_raw_raw_root",
                      "data_policy_type": constants.DATA_POLICY_TYPE_RAW,
                      "data_governance_tag": {
                          "key": dg_key_access,
                          "value": dg_value_raw,
                      },
                  },
              },
              {
                  "action": constants.ACTION_CREATE_DATA_POLICY_V2,
                  "target_project_id": "data-proj",
                  "region": "us",
                  "policy_id": "migrated_raw_deny_default_root_default_deny",
                  "source_entity": policy_tag_deny,
                  "policy_origin": (
                      constants.POLICY_ORIGIN_SYNTHETIC_DEFAULT_DENY
                  ),
                  "grantees": [],
                  "api_payload": {
                      "data_policy_id": (
                          "migrated_raw_deny_default_root_default_deny"
                      ),
                      "data_policy_type": constants.DATA_POLICY_TYPE_RAW,
                      "data_governance_tag": {
                          "key": dg_key_access,
                          "value": dg_value_deny,
                      },
                  },
              },
              {
                  "action": constants.ACTION_CREATE_DATA_POLICY_V2,
                  "target_project_id": "data-proj",
                  "region": "us",
                  "policy_id": "migrated_raw_raw_child_default_deny",
                  "source_entity": policy_tag_child,
                  "policy_origin": (
                      constants.POLICY_ORIGIN_SYNTHETIC_DEFAULT_DENY
                  ),
                  "grantees": [],
                  "api_payload": {
                      "data_policy_id": "migrated_raw_raw_child_default_deny",
                      "data_policy_type": constants.DATA_POLICY_TYPE_RAW,
                      "data_governance_tag": {
                          "key": dg_key_access,
                          "value": dg_value_child,
                      },
                  },
              },
          ],
      },
      "phase_3_binding_map": {
          "policy_tags_to_dg_tag_values": {
              policy_tag_email: {
                  "dg_tag_key": dg_key_access,
                  "dg_tag_value": dg_value_email,
              },
              policy_tag_sha256: {
                  "dg_tag_key": dg_key_access,
                  "dg_tag_value": dg_value_sha256,
              },
              policy_tag_raw: {
                  "dg_tag_key": dg_key_access,
                  "dg_tag_value": dg_value_raw,
              },
              policy_tag_deny: {
                  "dg_tag_key": dg_key_access,
                  "dg_tag_value": dg_value_deny,
              },
              policy_tag_child: {
                  "dg_tag_key": dg_key_access,
                  "dg_tag_value": dg_value_child,
              },
              policy_tag_classification: {
                  "dg_tag_key": dg_key_class,
                  "dg_tag_value": dg_value_class,
              },
          }
      },
  }


def _make_sample_table_schema_fields() -> list[dict[str, object]]:
  """Returns a sample BigQuery table schema with top-level and nested PTs.

  Includes:
    - `id` (untagged top-level `INTEGER` without an explicit `mode` field).
    - `contact_info` (`RECORD` containing tagged `contact_info.email` and
      untagged `contact_info.phone`).
    - `ssn_hash`, `credit_card`, and `secret_notes` (tagged top-level columns).
  """
  return [
      {"name": "id", "type": "INTEGER"},
      {
          "name": "contact_info",
          "type": "RECORD",
          "fields": [
              {
                  "name": "email",
                  "type": "STRING",
                  "policyTags": {
                      "names": [
                          "projects/source-proj/locations/us/"
                          "taxonomies/100/policyTags/201"
                      ]
                  },
              },
              {"name": "phone", "type": "STRING"},
          ],
      },
      {
          "name": "ssn_hash",
          "type": "STRING",
          "policyTags": {
              "names": [
                  "projects/source-proj/locations/us/"
                  "taxonomies/100/policyTags/202"
              ]
          },
      },
      {
          "name": "credit_card",
          "type": "STRING",
          "policyTags": {
              "names": [
                  "projects/source-proj/locations/us/"
                  "taxonomies/100/policyTags/203"
              ]
          },
      },
      {
          "name": "secret_notes",
          "type": "STRING",
          "policyTags": {
              "names": [
                  "projects/source-proj/locations/us/"
                  "taxonomies/100/policyTags/204"
              ]
          },
      },
  ]


def _make_mock_v2_policy(
    policy_id: str,
    policy_type: str,
    dg_tag_key: str,
    dg_tag_value: str,
    grantees: list[str] | None = None,
    predefined_expression: str | None = None,
    routine: str | None = None,
    matching_condition: str | None = None,
    data_governance_tag_condition: object | None = None,
) -> types.SimpleNamespace:
  """Creates a stub V2 `DataPolicy` object returned by `list_data_policies`."""
  type_enum = types.SimpleNamespace(name=policy_type)
  dgt_field = types.SimpleNamespace(key=dg_tag_key, value=dg_tag_value)

  if predefined_expression or routine:
    if predefined_expression:
      expression_enum = types.SimpleNamespace(name=predefined_expression)
      masking = types.SimpleNamespace(
          predefined_expression=expression_enum, routine=None
      )
    else:
      masking = types.SimpleNamespace(
          predefined_expression=None, routine=routine
      )
  else:
    masking = None

  # BigQuery V2 `ListDataPolicies` omits `grantees` on the wire for all listed
  # policies (`grantees` is only returned by per-policy `GET /v2/{name}`). Keep
  # `.grantees = []` on the list stub and store the fixture grantees on a
  # test-only attribute served by `self.mock_urlopen` during REST GET calls.
  return types.SimpleNamespace(
      name=f"projects/data-proj/locations/us/dataPolicies/{policy_id}",
      data_policy_id=policy_id,
      policy_tag=None,
      data_policy_type=type_enum,
      data_governance_tag=dgt_field,
      matching_condition=matching_condition,
      data_governance_tag_condition=data_governance_tag_condition,
      grantees=[],
      _fixture_rest_grantees=list(grantees or []),
      data_masking_policy=masking,
  )


class _FakeHttpResponse:
  """Context-manager HTTP response double for `urllib.request.urlopen`."""

  def __init__(self, payload: dict[str, object]):
    self._raw_bytes = json.dumps(payload).encode("utf-8")

  def read(self) -> bytes:
    return self._raw_bytes

  def __enter__(self) -> _FakeHttpResponse:
    return self

  def __exit__(self, exc_type: object, exc: object, tb: object) -> bool:
    return False


class SwapperTest(unittest.TestCase):
  """Comprehensive unit tests for `swapper.Swapper`."""

  def setUp(self):
    super().setUp()
    self.temp_dir = tempfile.TemporaryDirectory()
    self.addCleanup(self.temp_dir.cleanup)

    # Provide hermetic fake credentials and a local `urlopen` responder so REST
    # `GET /v2/{name}` grantee lookups never touch ambient credentials or the
    # network while matching real `ListDataPolicies` (which omits `grantees`).
    auth_patcher = mock.patch(
        "google.auth.default",
        return_value=(_FakeCredentials(), "data-proj"),
    )
    self.mock_auth_default = auth_patcher.start()
    self.addCleanup(auth_patcher.stop)

    self._rest_grantees_override: dict[str, list[str]] = {}

    def urlopen_side_effect(request, timeout=30.0):
      del timeout
      url = getattr(request, "full_url", str(request))
      path_without_query = url.split("?")[0].rstrip("/")
      path_parts = path_without_query.split("/")
      # Auto-serve only individual `GET /v2/.../dataPolicies/<policy_id>` calls;
      # list endpoints (`.../dataPolicies`) raise unless explicitly stubbed.
      if len(path_parts) < 2 or path_parts[-2] != "dataPolicies":
        raise OSError(f"Unexpected unstubbed REST URL in test: {url}")
      policy_id = path_parts[-1]
      if policy_id in self._rest_grantees_override:
        return _FakeHttpResponse(
            {"grantees": list(self._rest_grantees_override[policy_id])}
        )
      listed = self.mock_data_policy_v2_client.list_data_policies.return_value
      if isinstance(listed, list):
        for candidate in listed:
          if getattr(candidate, "data_policy_id", None) == policy_id:
            fixture_grantees = getattr(candidate, "_fixture_rest_grantees", [])
            return _FakeHttpResponse({"grantees": list(fixture_grantees)})
      return _FakeHttpResponse({"grantees": []})

    urlopen_patcher = mock.patch(
        "urllib.request.urlopen",
        autospec=True,
        side_effect=urlopen_side_effect,
    )
    self.mock_urlopen = urlopen_patcher.start()
    self.addCleanup(urlopen_patcher.stop)

    self.mock_bigquery_client = mock.create_autospec(
        bigquery.Client, instance=True, spec_set=True
    )
    self.mock_bigquery_client.get_dataset.return_value = types.SimpleNamespace(
        location="US"
    )
    self.mock_bigquery_client.update_table.side_effect = (
        lambda tbl, *_args, **_kwargs: tbl
    )
    self.mock_tag_keys_client = mock.create_autospec(
        resourcemanager_v3.TagKeysClient, instance=True, spec_set=True
    )
    self.mock_tag_values_client = mock.create_autospec(
        resourcemanager_v3.TagValuesClient, instance=True, spec_set=True
    )
    self.mock_data_policy_v2_client = mock.create_autospec(
        bigquery_datapolicies_v2.DataPolicyServiceClient,
        instance=True,
        spec_set=True,
    )
    self.mock_projects_client = mock.create_autospec(
        resourcemanager_v3.ProjectsClient, instance=True, spec_set=True
    )

    mock_tag_key_access = types.SimpleNamespace(
        name="tagKeys/111",
        short_name="manual_migration_taxonomy",
        namespaced_name="target-dgt-proj/manual_migration_taxonomy",
        purpose=2,  # DATA_GOVERNANCE
    )
    mock_tag_key_class = types.SimpleNamespace(
        name="tagKeys/999",
        short_name="classification_only_taxonomy",
        namespaced_name="target-dgt-proj/classification_only_taxonomy",
        purpose=2,  # DATA_GOVERNANCE
    )
    self.mock_tag_keys_client.list_tag_keys.return_value = [
        mock_tag_key_access,
        mock_tag_key_class,
    ]

    def list_tag_values_side_effect(parent: str):
      access_prefix = "target-dgt-proj/manual_migration_taxonomy"
      class_prefix = "target-dgt-proj/classification_only_taxonomy"
      if parent == "tagKeys/111":
        values = []
        for index, short_name in enumerate([
            "Email_Mask_Root",
            "Sha256_Mask_Root",
            "Raw_Root",
            "Deny_Default_Root",
            "Raw_Child",
        ]):
          values.append(
              types.SimpleNamespace(
                  name=f"tagValues/20{index}",
                  parent="tagKeys/111",
                  short_name=short_name,
                  namespaced_name=f"{access_prefix}/{short_name}",
              )
          )
        return values
      if parent == "tagValues/202":
        return [
            types.SimpleNamespace(
                name="tagValues/205",
                parent="tagValues/202",
                short_name="Raw_Child",
                namespaced_name=f"{access_prefix}/Raw_Root/Raw_Child",
            )
        ]
      if parent == "tagKeys/999":
        return [
            types.SimpleNamespace(
                name="tagValues/901",
                parent="tagKeys/999",
                short_name="Public_Info",
                namespaced_name=f"{class_prefix}/Public_Info",
            )
        ]
      return []

    self.mock_tag_values_client.list_tag_values.side_effect = (
        list_tag_values_side_effect
    )

    self.plan = _make_sample_plan()
    self.swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        resourcemanager_client=self.mock_projects_client,
        backup_dir=self.temp_dir.name,
        skip_confirmation=True,
    )

  def _configure_matching_live_v2_policies(self) -> None:
    """Configures mock_data_policy_v2_client with full parity V2 policies."""
    dg_key = "target-dgt-proj/manual_migration_taxonomy"
    self.mock_data_policy_v2_client.list_data_policies.return_value = [
        _make_mock_v2_policy(
            policy_id="migrated_masking_email_mask_policy",
            policy_type=constants.DATA_POLICY_TYPE_MASKING,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Email_Mask_Root",
            grantees=["user:masked_reader@example.com"],
            predefined_expression="EMAIL_MASK",
        ),
        _make_mock_v2_policy(
            policy_id="migrated_raw_email_mask_root_default_deny",
            policy_type=constants.DATA_POLICY_TYPE_RAW,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Email_Mask_Root",
            grantees=[],
        ),
        _make_mock_v2_policy(
            policy_id="migrated_masking_sha256_mask_policy",
            policy_type=constants.DATA_POLICY_TYPE_MASKING,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Sha256_Mask_Root",
            grantees=["user:masked_reader@example.com"],
            predefined_expression="SHA256",
        ),
        _make_mock_v2_policy(
            policy_id="migrated_raw_sha256_mask_root_default_deny",
            policy_type=constants.DATA_POLICY_TYPE_RAW,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Sha256_Mask_Root",
            grantees=[],
        ),
        _make_mock_v2_policy(
            policy_id="migrated_raw_raw_root",
            policy_type=constants.DATA_POLICY_TYPE_RAW,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Raw_Root",
            grantees=["user:raw_reader@example.com"],
        ),
        _make_mock_v2_policy(
            policy_id="migrated_raw_deny_default_root_default_deny",
            policy_type=constants.DATA_POLICY_TYPE_RAW,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Deny_Default_Root",
            grantees=[],
        ),
        _make_mock_v2_policy(
            policy_id="migrated_raw_raw_child_default_deny",
            policy_type=constants.DATA_POLICY_TYPE_RAW,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Raw_Child",
            grantees=[],
        ),
    ]

  def _make_mock_table(
      self,
      fields: list[dict[str, object]],
      location: str = "US",
  ) -> _FakeTable:
    """Creates a stub BigQuery Table object holding raw schema fields."""
    return _FakeTable(fields=fields, location=location)

  # =========================================================================
  # === Section 1: Scope Resolution Tests (--table-project-ids / --dataset-ids)
  # =========================================================================

  def test_resolve_target_tables_combines_and_deduplicates_scopes(self):
    """Scenario: Combining scope flags deduplicates tables and skips views."""
    # Arrange: Configure list_datasets and list_tables across projects,
    # including a VIEW resource that must be skipped before get_table.
    dataset_item_1 = types.SimpleNamespace(dataset_id="dataset_a")
    self.mock_bigquery_client.list_datasets.return_value = [dataset_item_1]

    table_item_1 = types.SimpleNamespace(table_id="table_1", table_type="TABLE")
    view_item = types.SimpleNamespace(table_id="view_1", table_type="VIEW")
    table_item_2 = types.SimpleNamespace(table_id="table_2", table_type="TABLE")

    def list_tables_side_effect(dataset_reference: str):
      if dataset_reference == "proj-1.dataset_a":
        return [table_item_1, view_item]
      if dataset_reference == "proj-2.dataset_b":
        return [table_item_2]
      return []

    self.mock_bigquery_client.list_tables.side_effect = list_tables_side_effect

    # Act: Resolve target tables across all three scope flags.
    resolved_tables, failures = self.swapper.resolve_target_tables(
        table_project_ids=["proj-1"],
        dataset_ids=["proj-2.dataset_b", "proj-1.dataset_a"],
        table_ids=[
            "proj-1.dataset_a.table_1",  # Duplicate, should be deduplicated
            "proj-3.dataset_c.table_3, proj-3.dataset_c.table_4",
        ],
        regions=["us"],
    )

    # Assert: Duplicate tables and views are excluded in discovery order.
    self.assertEqual(failures, [])
    self.assertEqual(
        resolved_tables,
        [
            ("proj-1", "dataset_a", "table_1"),
            ("proj-2", "dataset_b", "table_2"),
            ("proj-3", "dataset_c", "table_3"),
            ("proj-3", "dataset_c", "table_4"),
        ],
    )

  def test_resolve_target_tables_rejects_colon_separated_identifiers(self):
    """Scenario: Colon-separated dataset and table identifiers are rejected."""
    # Colon-separated BigQuery CLI syntax must suggest dot-separated notation,
    # while legacy domain-scoped project IDs emit the domain-scoped error.
    resolved_tables, failures = self.swapper.resolve_target_tables(
        dataset_ids=["proj-2:dataset_b", "example.com:proj.dataset_d"],
        table_ids=["proj-3:dataset_c.table_3"],
        regions=["us"],
    )
    self.assertEqual(resolved_tables, [])
    self.assertEqual(len(failures), 3)
    self.assertEqual(failures[0].table_identifier, "proj-2:dataset_b")
    self.assertIn(
        "Colon-separated BigQuery CLI notation is not supported; use"
        " dot-separated '<project_id>.<dataset_id>' instead (for example,"
        " 'proj-2.dataset_b')",
        failures[0].error_message,
    )
    self.assertEqual(failures[1].table_identifier, "example.com:proj.dataset_d")
    self.assertIn(
        constants.UNSUPPORTED_DOMAIN_SCOPED_PROJECT_MSG,
        failures[1].error_message,
    )
    self.assertEqual(failures[2].table_identifier, "proj-3:dataset_c.table_3")
    self.assertIn(
        "Colon-separated BigQuery CLI notation is not supported; use"
        " dot-separated '<project_id>.<dataset_id>.<table_id>' instead (for"
        " example, 'proj-3.dataset_c.table_3')",
        failures[2].error_message,
    )

  def test_resolve_target_tables_filters_by_regions(self):
    """Scenario: Passing --regions filters datasets by location."""
    # Arrange: Configure one US dataset and one EU dataset.
    dataset_us = types.SimpleNamespace(location="US")
    dataset_eu = types.SimpleNamespace(location="EU")

    def get_dataset_side_effect(dataset_reference: str):
      if dataset_reference == "proj-1.ds_us":
        return dataset_us
      return dataset_eu

    self.mock_bigquery_client.get_dataset.side_effect = get_dataset_side_effect
    table_us = types.SimpleNamespace(table_id="users_us", table_type="TABLE")
    self.mock_bigquery_client.list_tables.return_value = [table_us]

    # Act: Resolve target tables with regions=["us"].
    resolved_tables, failures = self.swapper.resolve_target_tables(
        dataset_ids=["proj-1.ds_us", "proj-1.ds_eu"],
        regions=["us"],
    )

    # Assert: Only the US dataset's table is included.
    self.assertEqual(failures, [])
    self.assertEqual(resolved_tables, [("proj-1", "ds_us", "users_us")])

  def test_resolve_target_tables_raises_when_no_scope_specified(self):
    """Scenario: Omitting --regions or all scope flags raises ValueError."""
    # Omitting --regions raises ValueError before scope evaluation.
    with self.assertRaisesRegex(
        ValueError, "At least one region must be specified via --regions"
    ):
      self.swapper.resolve_target_tables(table_ids=["proj-1.ds.tbl"])

    # Omitting all scope flags when --regions is set raises ValueError.
    with self.assertRaisesRegex(
        ValueError, "At least one of --table-project-ids"
    ):
      self.swapper.resolve_target_tables(regions=["us"])

  # =========================================================================
  # === Section 2: Schema Transformation Tests (Top-Level & Nested Fields) ===
  # =========================================================================

  def test_transform_schema_fields_swaps_top_level_and_nested_record_fields(
      self,
  ):
    """Scenario: PT-to-DGT swap transforms top-level and nested RECORDs."""
    # Arrange: Build sample schema with nested RECORD and top-level PT columns.
    original_fields = _make_sample_table_schema_fields()

    # Act: Transform schema fields using the sample plan.
    updated_fields, swapped_columns, unmapped_columns = (
        self.swapper.transform_schema_fields(original_fields, self.plan)
    )

    # Assert: All 4 PT columns are swapped and non-swapped columns are
    # untouched.
    self.assertEqual(unmapped_columns, [])
    self.assertEqual(len(swapped_columns), 4)
    self.assertEqual(
        [column.field_path for column in swapped_columns],
        ["contact_info.email", "ssn_hash", "credit_card", "secret_notes"],
    )

    # Assert: id column is completely unchanged (no mode: NULLABLE injected).
    self.assertEqual(updated_fields[0], {"name": "id", "type": "INTEGER"})

    # Assert: Nested RECORD field contact_info.email has PT cleared to [] and
    # DGT attached, while sibling contact_info.phone is untouched.
    email_field = updated_fields[1]["fields"][0]
    self.assertEqual(email_field["policyTags"], {"names": []})
    self.assertEqual(
        email_field["dataGovernanceTagsInfo"],
        {
            "dataGovernanceTags": {
                "target-dgt-proj/manual_migration_taxonomy": (
                    "target-dgt-proj/manual_migration_taxonomy/Email_Mask_Root"
                )
            }
        },
    )
    phone_field = updated_fields[1]["fields"][1]
    self.assertEqual(phone_field, {"name": "phone", "type": "STRING"})

    # Assert: Top-level columns have policyTags={"names": []} and DGT set.
    for index, expected_value_short in [
        (2, "Sha256_Mask_Root"),
        (3, "Raw_Root"),
        (4, "Deny_Default_Root"),
    ]:
      field_dict = updated_fields[index]
      self.assertEqual(field_dict["policyTags"], {"names": []})
      self.assertEqual(
          field_dict["dataGovernanceTagsInfo"],
          {
              "dataGovernanceTags": {
                  "target-dgt-proj/manual_migration_taxonomy": (
                      "target-dgt-proj/manual_migration_taxonomy/"
                      f"{expected_value_short}"
                  )
              }
          },
      )

  def test_transform_schema_fields_matches_numeric_project_number_policy_tags(
      self,
  ):
    """Scenario: Policy Tag URIs with project numbers match via suffix."""
    # Arrange: Build schema with numeric project number PT and unmapped PT.
    original_fields = [
        {
            "name": "email",
            "type": "STRING",
            "policyTags": {
                "names": [
                    "projects/987654321/locations/us/"
                    "taxonomies/100/policyTags/201"
                ]
            },
        },
        {
            "name": "other_tagged_col",
            "type": "STRING",
            "policyTags": {
                "names": [
                    "projects/other-proj/locations/us/"
                    "taxonomies/555/policyTags/666"
                ]
            },
        },
    ]

    # Act: Transform schema fields.
    updated_fields, swapped_columns, unmapped_columns = (
        self.swapper.transform_schema_fields(original_fields, self.plan)
    )

    # Assert: Numeric project PT is matched and unmapped PT is untouched.
    self.assertEqual(len(swapped_columns), 1)
    self.assertEqual(swapped_columns[0].field_path, "email")
    self.assertEqual(updated_fields[0]["policyTags"], {"names": []})

    self.assertEqual(len(unmapped_columns), 1)
    self.assertEqual(unmapped_columns[0].field_path, "other_tagged_col")
    self.assertEqual(updated_fields[1], original_fields[1])

  # =========================================================================
  # === Section 3: Strict Schema Integrity Safeguard (Anti-Corruption) Tests
  # =========================================================================

  def test_verify_schema_swap_integrity_passes_for_valid_swap(self):
    """Scenario: Valid PT-to-DGT swap passes verify_schema_swap_integrity."""
    # Arrange: Transform sample schema fields.
    original_fields = _make_sample_table_schema_fields()
    updated_fields, swapped_columns, _ = self.swapper.transform_schema_fields(
        original_fields, self.plan
    )

    # Act / Assert: Integrity check succeeds without raising.
    self.swapper.verify_schema_swap_integrity(
        original_fields, updated_fields, swapped_columns
    )

  def test_verify_schema_swap_integrity_rejects_dropped_column(self):
    """Scenario: Dropping a column raises SchemaCorruptionError."""
    # Arrange: Remove the last column from updated_fields.
    original_fields = _make_sample_table_schema_fields()
    updated_fields, swapped_columns, _ = self.swapper.transform_schema_fields(
        original_fields, self.plan
    )
    corrupted_fields = updated_fields[:-1]

    # Act / Assert: Field count mismatch raises SchemaCorruptionError.
    with self.assertRaisesRegex(
        swapper.SchemaCorruptionError, "Field count mismatch"
    ):
      self.swapper.verify_schema_swap_integrity(
          original_fields, corrupted_fields, swapped_columns
      )

  def test_verify_schema_swap_integrity_rejects_type_or_mode_mutation(self):
    """Scenario: Injecting mode='NULLABLE' on an untouched column raises."""
    # Arrange: Mutate mode on non-swapped column 'id'.
    original_fields = _make_sample_table_schema_fields()
    updated_fields, swapped_columns, _ = self.swapper.transform_schema_fields(
        original_fields, self.plan
    )
    corrupted_fields = copy.deepcopy(updated_fields)
    corrupted_fields[0]["mode"] = "NULLABLE"

    # Act / Assert: Non-swapped field mutation raises SchemaCorruptionError.
    with self.assertRaisesRegex(
        swapper.SchemaCorruptionError,
        "Unintended modification on non-swapped field 'id'",
    ):
      self.swapper.verify_schema_swap_integrity(
          original_fields, corrupted_fields, swapped_columns
      )

  def test_verify_schema_swap_integrity_rejects_mutation_on_swapped_column(
      self,
  ):
    """Scenario: Modifying type on a swapped column raises corruption error."""
    # Arrange: Mutate type on swapped nested column 'contact_info.email'.
    original_fields = _make_sample_table_schema_fields()
    updated_fields, swapped_columns, _ = self.swapper.transform_schema_fields(
        original_fields, self.plan
    )
    corrupted_fields = copy.deepcopy(updated_fields)
    corrupted_fields[1]["fields"][0]["type"] = "BYTES"

    # Act / Assert: Swapped field attribute mutation raises
    # SchemaCorruptionError.
    with self.assertRaisesRegex(
        swapper.SchemaCorruptionError,
        "Unintended attribute modification on swapped field"
        " 'contact_info.email'",
    ):
      self.swapper.verify_schema_swap_integrity(
          original_fields, corrupted_fields, swapped_columns
      )

  def test_verify_schema_swap_integrity_rejects_uncleared_policy_tags(self):
    """Scenario: Omitting policyTags={'names': []} raises corruption error."""
    # Arrange: Pop policyTags from swapped column 'ssn_hash'.
    original_fields = _make_sample_table_schema_fields()
    updated_fields, swapped_columns, _ = self.swapper.transform_schema_fields(
        original_fields, self.plan
    )
    corrupted_fields = copy.deepcopy(updated_fields)
    corrupted_fields[2].pop("policyTags")

    # Act / Assert: Missing policyTags={"names": []} raises
    # SchemaCorruptionError.
    with self.assertRaisesRegex(
        swapper.SchemaCorruptionError,
        "must have policyTags set to \\{'names': \\[\\]\\}",
    ):
      self.swapper.verify_schema_swap_integrity(
          original_fields, corrupted_fields, swapped_columns
      )

  def test_swap_table_schema_aborts_when_corruption_detected(self):
    """Scenario: swap_table_schema aborts without patching on corruption."""
    # Arrange: Patch transform_schema_fields to corrupt non-swapped column 'id'.
    table = self._make_mock_table(_make_sample_table_schema_fields())
    self.mock_bigquery_client.get_table.return_value = table
    original_transform = self.swapper.transform_schema_fields

    def corrupted_transform(original_fields, plan):
      updated_fields, swapped_columns, unmapped_columns = original_transform(
          original_fields, plan
      )
      updated_fields[0]["type"] = "STRING"
      return updated_fields, swapped_columns, unmapped_columns

    # Act: Run swap_table_schema with corrupted transformation.
    with mock.patch.object(
        self.swapper,
        "transform_schema_fields",
        side_effect=corrupted_transform,
    ):
      result = self.swapper.swap_table_schema(
          "data-proj", "demo_ds", "sensitive_customers", self.plan
      )

    # Assert: Table swap is aborted and update_table is never called.
    self.assertEqual(
        result.status, constants.SWAP_STATUS_ABORTED_SCHEMA_CORRUPTION
    )
    self.assertIn("Unintended modification", result.error_message)
    self.mock_bigquery_client.update_table.assert_not_called()

  # =========================================================================
  # === Section 4: Pre-Swap Enforcement Parity Verification Tests ===
  # =========================================================================

  def test_verify_enforcement_parity_passes_when_all_policies_match(self):
    """Scenario: verify_enforcement_parity passes when live state matches."""
    # Arrange: Configure matching live V2 Data Policies.
    self._configure_matching_live_v2_policies()
    original_fields = _make_sample_table_schema_fields()
    _, swapped_columns, _ = self.swapper.transform_schema_fields(
        original_fields, self.plan
    )

    # Act: Verify enforcement parity.
    discrepancies = self.swapper.verify_enforcement_parity(
        swapped_columns=swapped_columns,
        plan=self.plan,
        table_project_id="data-proj",
        table_location="us",
    )

    # Assert: Zero discrepancies are returned.
    self.assertEqual(discrepancies, [])

  def test_verify_enforcement_parity_supports_root_tag_hierarchy_inheritance(
      self,
  ):
    """Scenario: Child Tag Value inherits parent readers and keeps seatbelt."""
    # Arrange: Configure matching live V2 policies and a column bound to
    # Raw_Child.
    self._configure_matching_live_v2_policies()
    child_schema = [{
        "name": "child_col",
        "type": "STRING",
        "policyTags": {
            "names": [
                "projects/source-proj/locations/us/"
                "taxonomies/100/policyTags/205"
            ]
        },
    }]
    _, swapped_columns, _ = self.swapper.transform_schema_fields(
        child_schema, self.plan
    )

    # Act: Verify enforcement parity on the child column.
    discrepancies = self.swapper.verify_enforcement_parity(
        swapped_columns=swapped_columns,
        plan=self.plan,
        table_project_id="data-proj",
        table_location="us",
    )

    # Assert: Hierarchy inheritance satisfies parity with zero discrepancies.
    self.assertEqual(discrepancies, [])

  def test_verify_enforcement_parity_detects_missing_v2_policy_leakage_risk(
      self,
  ):
    """Scenario: Missing live V2 policies are flagged as ACCESS_LEAKAGE_RISK."""
    # Arrange: Return empty list of live V2 policies.
    self.mock_data_policy_v2_client.list_data_policies.return_value = []
    original_fields = _make_sample_table_schema_fields()
    _, swapped_columns, _ = self.swapper.transform_schema_fields(
        original_fields, self.plan
    )

    # Act: Verify enforcement parity.
    discrepancies = self.swapper.verify_enforcement_parity(
        swapped_columns=swapped_columns,
        plan=self.plan,
        table_project_id="data-proj",
        table_location="us",
    )

    # Assert: All 4 swapped columns report ACCESS_LEAKAGE_RISK.
    self.assertEqual(len(discrepancies), 4)
    for discrepancy in discrepancies:
      self.assertEqual(
          discrepancy.risk_category, constants.PARITY_RISK_ACCESS_LEAKAGE
      )
      self.assertIn("Fail-Open", discrepancy.description)

  def test_verify_enforcement_parity_detects_missing_and_extra_grantees(self):
    """Scenario: Grantee/rule mismatches map to exact risk categories."""
    # Arrange: Configure live V2 policies with an intruder masked reader, wrong
    # masking rule, missing raw reader, and leaked default-deny reader.
    dg_key = "target-dgt-proj/manual_migration_taxonomy"
    self.mock_data_policy_v2_client.list_data_policies.return_value = [
        _make_mock_v2_policy(
            policy_id="migrated_masking_email_mask_policy",
            policy_type=constants.DATA_POLICY_TYPE_MASKING,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Email_Mask_Root",
            grantees=[
                "user:masked_reader@example.com",
                "user:intruder@example.com",
            ],
            predefined_expression="EMAIL_MASK",
        ),
        _make_mock_v2_policy(
            policy_id="migrated_raw_email_mask_root_default_deny",
            policy_type=constants.DATA_POLICY_TYPE_RAW,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Email_Mask_Root",
            grantees=[],
        ),
        _make_mock_v2_policy(
            policy_id="migrated_masking_sha256_mask_policy",
            policy_type=constants.DATA_POLICY_TYPE_MASKING,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Sha256_Mask_Root",
            grantees=["user:masked_reader@example.com"],
            predefined_expression="DEFAULT_MASKING_VALUE",
        ),
        _make_mock_v2_policy(
            policy_id="migrated_raw_sha256_mask_root_default_deny",
            policy_type=constants.DATA_POLICY_TYPE_RAW,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Sha256_Mask_Root",
            grantees=[],
        ),
        _make_mock_v2_policy(
            policy_id="migrated_raw_raw_root",
            policy_type=constants.DATA_POLICY_TYPE_RAW,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Raw_Root",
            grantees=[],
        ),
        _make_mock_v2_policy(
            policy_id="migrated_raw_deny_default_root_default_deny",
            policy_type=constants.DATA_POLICY_TYPE_RAW,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Deny_Default_Root",
            grantees=[],
        ),
        _make_mock_v2_policy(
            policy_id="migrated_raw_deny_default_root_stale",
            policy_type=constants.DATA_POLICY_TYPE_RAW,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Deny_Default_Root",
            grantees=["user:leaked_reader@example.com"],
        ),
    ]

    original_fields = _make_sample_table_schema_fields()
    _, swapped_columns, _ = self.swapper.transform_schema_fields(
        original_fields, self.plan
    )

    # Act: Verify enforcement parity across all 4 columns.
    discrepancies = self.swapper.verify_enforcement_parity(
        swapped_columns=swapped_columns,
        plan=self.plan,
        table_project_id="data-proj",
        table_location="us",
    )

    # Assert: Each column reports the expected discrepancy category and detail.
    by_column = {
        discrepancy.field_path: discrepancy for discrepancy in discrepancies
    }
    self.assertEqual(len(by_column), 4)

    self.assertEqual(
        by_column["contact_info.email"].risk_category,
        constants.PARITY_RISK_ACCESS_LEAKAGE,
    )
    self.assertIn(
        "user:intruder@example.com",
        by_column["contact_info.email"].description,
    )

    self.assertEqual(
        by_column["ssn_hash"].risk_category,
        constants.PARITY_RISK_RESOURCE_DISCREPANCY,
    )
    self.assertIn("Masking rule mismatch", by_column["ssn_hash"].description)

    self.assertEqual(
        by_column["credit_card"].risk_category,
        constants.PARITY_RISK_ACCESS_BLOCKAGE,
    )
    self.assertIn(
        "user:raw_reader@example.com", by_column["credit_card"].description
    )

    self.assertEqual(
        by_column["secret_notes"].risk_category,
        constants.PARITY_RISK_ACCESS_LEAKAGE,
    )
    self.assertIn(
        "user:leaked_reader@example.com",
        by_column["secret_notes"].description,
    )

  def test_verify_enforcement_parity_detects_policy_on_classification_tag(self):
    """Scenario: V2 policy on a Classification-Only tag flags blockage risk."""
    # Arrange: Attach an unexpected V2 Data Policy to Public_Info.
    dg_key_class = "target-dgt-proj/classification_only_taxonomy"
    self.mock_data_policy_v2_client.list_data_policies.return_value = [
        _make_mock_v2_policy(
            policy_id="unexpected_deny_policy",
            policy_type=constants.DATA_POLICY_TYPE_RAW,
            dg_tag_key=dg_key_class,
            dg_tag_value=f"{dg_key_class}/Public_Info",
            grantees=[],
        )
    ]

    fields = [{
        "name": "public_col",
        "type": "STRING",
        "policyTags": {
            "names": [
                "projects/source-proj/locations/us/"
                "taxonomies/999/policyTags/901"
            ]
        },
    }]
    _, swapped_columns, _ = self.swapper.transform_schema_fields(
        fields, self.plan
    )

    # Act: Verify enforcement parity.
    discrepancies = self.swapper.verify_enforcement_parity(
        swapped_columns=swapped_columns,
        plan=self.plan,
        table_project_id="data-proj",
        table_location="us",
    )

    # Assert: ACCESS_BLOCKAGE_RISK is reported.
    self.assertEqual(len(discrepancies), 1)
    self.assertEqual(
        discrepancies[0].risk_category, constants.PARITY_RISK_ACCESS_BLOCKAGE
    )
    self.assertIn("Classification-Only", discrepancies[0].description)

  def test_verify_enforcement_parity_detects_missing_tag_key_and_value(self):
    """Scenario: Missing DG Tag Key in Resource Manager flags leakage risk."""
    # Arrange: Return empty list of Tag Keys.
    self.mock_tag_keys_client.list_tag_keys.return_value = []
    fields = [_make_sample_table_schema_fields()[2]]  # ssn_hash
    _, swapped_columns, _ = self.swapper.transform_schema_fields(
        fields, self.plan
    )

    # Act: Verify enforcement parity.
    discrepancies = self.swapper.verify_enforcement_parity(
        swapped_columns=swapped_columns,
        plan=self.plan,
        table_project_id="data-proj",
        table_location="us",
    )

    # Assert: Missing Tag Key is reported as ACCESS_LEAKAGE_RISK.
    self.assertEqual(len(discrepancies), 1)
    self.assertEqual(
        discrepancies[0].risk_category, constants.PARITY_RISK_ACCESS_LEAKAGE
    )
    self.assertIn("does not exist", discrepancies[0].description)

  def test_verify_enforcement_parity_normalizes_custom_routine_project_number(
      self,
  ):
    """Canonicalized numeric project number in V2 custom UDF routine matches."""
    dg_key = "target-dgt-proj/manual_migration_taxonomy"
    dg_value = f"{dg_key}/Email_Mask_Root"
    # Phase 1b plan.json records the custom masking UDF routine with its
    # human-readable project ID ('source-proj'), while BigQuery Data Policy
    # Service V2 returns the server-canonicalized numeric project number
    # ('466393599270') on list_data_policies.
    routine_plan = copy.deepcopy(self.plan)
    routine_plan["phase_2_resource_manifest"]["create_data_policies_v2"][0][
        "api_payload"
    ]["data_masking_policy"] = {
        "routine": (
            "projects/source-proj/datasets/mt_gov_us/routines/mask_phone_last4"
        )
    }
    self.mock_projects_client.get_project.return_value = types.SimpleNamespace(
        project_id="source-proj"
    )
    self.mock_data_policy_v2_client.list_data_policies.return_value = [
        _make_mock_v2_policy(
            policy_id="migrated_masking_email_mask_policy",
            policy_type=constants.DATA_POLICY_TYPE_MASKING,
            dg_tag_key=dg_key,
            dg_tag_value=dg_value,
            grantees=["user:masked_reader@example.com"],
            routine=(
                "projects/466393599270/datasets/mt_gov_us/"
                "routines/mask_phone_last4"
            ),
        ),
        _make_mock_v2_policy(
            policy_id="migrated_raw_email_mask_root_default_deny",
            policy_type=constants.DATA_POLICY_TYPE_RAW,
            dg_tag_key=dg_key,
            dg_tag_value=dg_value,
            grantees=[],
        ),
    ]
    email_column_only = [_make_sample_table_schema_fields()[1]]
    _, swapped_columns, _ = self.swapper.transform_schema_fields(
        email_column_only, routine_plan
    )

    # _normalize_routine_path resolves 'projects/466393599270/...' to
    # 'projects/source-proj/...' so _masking_rule_matches compares identical
    # canonical routine paths.
    discrepancies = self.swapper.verify_enforcement_parity(
        swapped_columns=swapped_columns,
        plan=routine_plan,
        table_project_id="data-proj",
        table_location="us",
    )

    # Confirm zero false-positive RESOURCE_DISCREPANCY errors are raised for
    # server-canonicalized custom UDF routine project numbers.
    self.assertEqual(discrepancies, [])

  def test_swap_table_schema_blocks_on_discrepancy_by_default(self):
    """Scenario: swap_table_schema blocks by default on parity discrepancy."""
    # Arrange: Return empty live V2 policies to trigger parity discrepancies.
    self.mock_data_policy_v2_client.list_data_policies.return_value = []
    table = self._make_mock_table(_make_sample_table_schema_fields())
    self.mock_bigquery_client.get_table.return_value = table

    # Act: Attempt to swap table schema.
    result = self.swapper.swap_table_schema(
        "data-proj", "demo_ds", "sensitive_customers", self.plan
    )

    # Assert: Table status is BLOCKED_PARITY_DISCREPANCY and update_table is
    # not called.
    self.assertEqual(
        result.status, constants.SWAP_STATUS_BLOCKED_PARITY_DISCREPANCY
    )
    self.assertEqual(len(result.parity_discrepancies), 4)
    self.mock_bigquery_client.update_table.assert_not_called()

  def test_swap_table_schema_proceeds_when_allow_parity_discrepancy_enabled(
      self,
  ):
    """Scenario: allow_parity_discrepancy=True allows swap_table_schema."""
    # Arrange: Configure Swapper with allow_parity_discrepancy=True.
    self.mock_data_policy_v2_client.list_data_policies.return_value = []
    table = self._make_mock_table(_make_sample_table_schema_fields())
    self.mock_bigquery_client.get_table.return_value = table

    override_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        backup_dir=self.temp_dir.name,
        skip_confirmation=True,
        allow_parity_discrepancy=True,
    )

    # Act: Swap table schema with override enabled.
    result = override_swapper.swap_table_schema(
        "data-proj", "demo_ds", "sensitive_customers", self.plan
    )

    # Assert: Table is swapped while preserving discrepancy records.
    self.assertEqual(result.status, constants.SWAP_STATUS_SWAPPED)
    self.assertEqual(len(result.parity_discrepancies), 4)
    self.mock_bigquery_client.update_table.assert_called_once_with(
        table, ["schema"]
    )

  # =========================================================================
  # === Section 5: Backup, Diff Logging, & Interactive Confirmation Tests ===
  # =========================================================================

  def test_swap_table_schema_creates_backup_and_patches_schema_on_approval(
      self,
  ):
    """Scenario: Approving prompt writes schema backup and patches table."""
    # Arrange: Configure matching live V2 policies and a 'y' confirmation
    # callback.
    self._configure_matching_live_v2_policies()
    original_fields = _make_sample_table_schema_fields()
    table = self._make_mock_table(original_fields)
    self.mock_bigquery_client.get_table.return_value = table

    prompt_callback = _RecordingPromptCallback("y")
    interactive_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        backup_dir=self.temp_dir.name,
        skip_confirmation=False,
        confirmation_callback=prompt_callback,
    )

    # Act: Run swap_table_schema interactively.
    result = interactive_swapper.swap_table_schema(
        "data-proj", "demo_ds", "sensitive_customers", self.plan
    )

    # Assert: Backup file is written and update_table is called with ["schema"].
    self.assertEqual(result.status, constants.SWAP_STATUS_SWAPPED)
    self.assertEqual(len(prompt_callback.prompts), 1)
    self.assertIsNotNone(result.backup_file_path)
    self.assertTrue(os.path.exists(result.backup_file_path))

    with open(result.backup_file_path, "r", encoding="utf-8") as backup_file:
      saved_backup = json.load(backup_file)
    # Forward backup JSON injects empty `dataGovernanceTagsInfo` onto swapped
    # leaf columns so `bq update` clears attached DGTs while restoring PTs,
    # without mutating `original_fields` in memory or touching untagged columns.
    expected_backup = copy.deepcopy(original_fields)
    expected_backup[1]["fields"][0]["dataGovernanceTagsInfo"] = {
        "dataGovernanceTags": {}
    }
    for swapped_index in (2, 3, 4):
      expected_backup[swapped_index]["dataGovernanceTagsInfo"] = {
          "dataGovernanceTags": {}
      }
    self.assertEqual(saved_backup, expected_backup)
    self.assertNotIn("dataGovernanceTagsInfo", original_fields[2])

    self.assertIn("dataGovernanceTagsInfo", result.schema_diff)
    self.mock_bigquery_client.update_table.assert_called_once_with(
        table, ["schema"]
    )
    patched_fields = table._properties["schema"]["fields"]
    self.assertEqual(
        patched_fields[1]["fields"][0]["policyTags"], {"names": []}
    )

  def test_swap_table_schema_skips_when_user_declines_confirmation(self):
    """Scenario: Declining confirmation skips table without backup or patch."""
    # Arrange: Configure a 'n' confirmation callback.
    self._configure_matching_live_v2_policies()
    table = self._make_mock_table(_make_sample_table_schema_fields())
    self.mock_bigquery_client.get_table.return_value = table

    prompt_callback = _RecordingPromptCallback("n")
    interactive_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        backup_dir=self.temp_dir.name,
        skip_confirmation=False,
        confirmation_callback=prompt_callback,
    )

    # Act: Run swap_table_schema and decline confirmation.
    result = interactive_swapper.swap_table_schema(
        "data-proj", "demo_ds", "sensitive_customers", self.plan
    )

    # Assert: Status is SKIPPED_USER_DECLINED with an explanatory error_message
    # and no schema mutation or backup occurs.
    self.assertEqual(result.status, constants.SWAP_STATUS_SKIPPED_USER_DECLINED)
    self.assertEqual(
        result.error_message,
        "User declined schema swap at interactive confirmation prompt.",
    )
    self.assertIsNone(result.backup_file_path)
    self.mock_bigquery_client.update_table.assert_not_called()

  def test_swap_schemas_end_to_end_and_report_generation(self):
    """Scenario: End-to-end swap_schemas swaps tables and writes report."""
    # Arrange: Configure one table with Policy Tags and one plain table.
    self._configure_matching_live_v2_policies()
    table_with_policy_tags = self._make_mock_table(
        _make_sample_table_schema_fields()
    )
    table_without_policy_tags = self._make_mock_table(
        [{"name": "id", "type": "INTEGER"}]
    )

    def get_table_side_effect(table_identifier: str):
      if table_identifier == "data-proj.demo_ds.sensitive_customers":
        return table_with_policy_tags
      return table_without_policy_tags

    self.mock_bigquery_client.get_table.side_effect = get_table_side_effect

    # Act: Run swap_schemas and write report_file.
    report_path = os.path.join(self.temp_dir.name, "swap_report.md")
    results, report = self.swapper.swap_schemas(
        plan=self.plan,
        table_ids=[
            "data-proj.demo_ds.sensitive_customers",
            "data-proj.demo_ds.plain_table",
        ],
        regions=["us"],
        report_file=report_path,
    )

    # Assert: Both tables are processed and the report contains rollback CLI
    # commands.
    self.assertEqual(len(results), 2)
    self.assertEqual(results[0].status, constants.SWAP_STATUS_SWAPPED)
    self.assertEqual(
        results[1].status, constants.SWAP_STATUS_SKIPPED_NO_POLICY_TAGS
    )
    self.assertTrue(os.path.exists(report_path))
    self.assertIn("# Phase 3: Policy Tag to DG Tag Schema Swap Report", report)
    self.assertIn("<!-- mdformat off -->", report)
    self.assertIn("`data-proj.demo_ds.sensitive_customers`", report)
    # Forward swap reports render both the recommended surgical dgt-to-pt
    # rollback command and the point-in-time bq update snapshot restore command.
    self.assertIn(
        "python main.py --phase swap --swap-mode dgt-to-pt"
        " --plan-file plan.json"
        " --table-ids data-proj.demo_ds.sensitive_customers"
        " --regions us",
        report,
    )
    self.assertIn("bq update data-proj:demo_ds.sensitive_customers", report)

  def test_swap_with_canonical_planner_manifest_and_short_tag_values(self):
    """Scenario: Canonical manifest keys and short Tag Values swap cleanly."""
    # Arrange: Build a plan using canonical planner manifest keys and short Tag
    # Value names.
    self._configure_matching_live_v2_policies()
    policy_tag_email = (
        "projects/source-proj/locations/us/taxonomies/100/policyTags/201"
    )
    dg_key_access = "target-dgt-proj/manual_migration_taxonomy"
    dg_value_email_full = f"{dg_key_access}/Email_Mask_Root"

    canonical_plan = {
        "metadata": {
            "source_project_id": "source-proj",
            "target_dgt_project_id": "target-dgt-proj",
            "target_data_policy_mode": (
                constants.TARGET_DATA_POLICY_MODE_TABLE_PROJECTS
            ),
            "target_data_policy_project_ids": ["data-proj"],
        },
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS: [{
                "action": constants.ACTION_CREATE_DG_TAG_KEY,
                "namespaced_name": dg_key_access,
                "source_resource_name": (
                    "projects/source-proj/locations/us/taxonomies/100"
                ),
            }],
            constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES: [{
                "action": constants.ACTION_CREATE_DG_TAG_VALUE,
                "namespaced_name": dg_value_email_full,
                "parent_namespaced_name": dg_key_access,
                "source_resource_name": policy_tag_email,
            }],
            constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2: [],
            constants.KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2: [{
                "action": constants.ACTION_CREATE_DATA_POLICY_V2,
                "target_project_id": "data-proj",
                "region": "us",
                "api_payload": {
                    "data_policy_id": (
                        "migrated_raw_email_mask_root_default_deny"
                    ),
                    "data_policy_type": constants.DATA_POLICY_TYPE_RAW,
                    "data_governance_tag": {
                        "key": dg_key_access,
                        "value": "Email_Mask_Root",
                    },
                    "grantees": [],
                },
            }],
            constants.KEY_DATA_POLICIES_V1_TO_DATA_POLICIES_V2: [{
                "action": constants.ACTION_CREATE_DATA_POLICY_V2,
                "target_project_id": "data-proj",
                "region": "us",
                "api_payload": {
                    "data_policy_id": "migrated_masking_email_mask_policy",
                    "data_policy_type": constants.DATA_POLICY_TYPE_MASKING,
                    "data_governance_tag": {
                        "key": dg_key_access,
                        "value": "Email_Mask_Root",
                    },
                    "data_masking_policy": {
                        "predefined_expression": "EMAIL_MASK",
                    },
                    "grantees": ["user:masked_reader@example.com"],
                },
            }],
        },
        "phase_3_binding_map": {
            constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES: {
                policy_tag_email: {
                    "dg_tag_key": dg_key_access,
                    "dg_tag_value": "Email_Mask_Root",
                }
            }
        },
    }

    fields = [{
        "name": "email",
        "type": "STRING",
        "policyTags": {"names": [policy_tag_email]},
    }]
    table = self._make_mock_table(fields)
    self.mock_bigquery_client.get_table.return_value = table

    # Act: Swap table schema using the canonical plan.
    result = self.swapper.swap_table_schema(
        "data-proj", "demo_ds", "users", canonical_plan
    )

    # Assert: Table is swapped with zero parity discrepancies.
    self.assertEqual(result.status, constants.SWAP_STATUS_SWAPPED)
    self.assertEqual(result.parity_discrepancies, [])
    patched_fields = table._properties["schema"]["fields"]
    self.assertEqual(patched_fields[0]["policyTags"], {"names": []})
    self.assertEqual(
        patched_fields[0]["dataGovernanceTagsInfo"],
        {"dataGovernanceTags": {dg_key_access: "Email_Mask_Root"}},
    )

  def test_swap_schemas_enforces_regions_filter_on_direct_table_ids(self):
    """Scenario: Passing --regions with --table-ids skips non-region tables."""
    # Arrange: Configure one US table and one EU table.
    self._configure_matching_live_v2_policies()
    us_fields = _make_sample_table_schema_fields()
    eu_fields = _make_sample_table_schema_fields()
    us_table = self._make_mock_table(us_fields, location="US")
    eu_table = self._make_mock_table(eu_fields, location="EU")

    def get_table_side_effect(table_identifier):
      if table_identifier == "data-proj.us_ds.us_table":
        return us_table
      return eu_table

    self.mock_bigquery_client.get_table.side_effect = get_table_side_effect

    # Act: Run swap_schemas with regions=["us"].
    results, report = self.swapper.swap_schemas(
        plan=self.plan,
        table_ids=[
            "data-proj.us_ds.us_table,data-proj.eu_ds.eu_table",
        ],
        regions=["us"],
    )

    # Assert: US table is swapped and EU table is skipped with region mismatch.
    self.assertEqual(len(results), 2)
    self.assertEqual(results[0].status, constants.SWAP_STATUS_SWAPPED)
    self.assertEqual(
        results[1].status, constants.SWAP_STATUS_SKIPPED_REGION_MISMATCH
    )
    self.assertIn("Tables Skipped (Region Mismatch):** 1", report)
    self.mock_bigquery_client.update_table.assert_called_once_with(
        us_table, ["schema"]
    )

  def test_dry_run_swap_schemas_previews_diff_without_mutating_or_backing_up(
      self,
  ):
    """Scenario: Dry-run mode previews diffs without prompting or mutating."""
    # Arrange: Configure dry_run=True Swapper.
    self._configure_matching_live_v2_policies()
    original_fields = _make_sample_table_schema_fields()
    table = self._make_mock_table(original_fields)
    self.mock_bigquery_client.get_table.return_value = table

    prompt_callback = _RecordingPromptCallback("n")
    dry_run_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        backup_dir=self.temp_dir.name,
        skip_confirmation=False,
        confirmation_callback=prompt_callback,
        dry_run=True,
    )

    # Act: Run swap_schemas in dry-run mode.
    results, report = dry_run_swapper.swap_schemas(
        plan=self.plan,
        table_ids=["data-proj.demo_ds.sensitive_customers"],
        regions=["us"],
    )

    # Assert: DRY_RUN_READY is returned without backups, prompts, or patches.
    self.assertEqual(len(results), 1)
    self.assertEqual(results[0].status, constants.SWAP_STATUS_DRY_RUN_READY)
    self.assertIsNone(results[0].backup_file_path)
    self.assertEqual(os.listdir(self.temp_dir.name), [])
    self.assertEqual(prompt_callback.prompts, [])
    self.mock_bigquery_client.update_table.assert_not_called()
    self.assertIn("dataGovernanceTagsInfo", results[0].schema_diff)
    self.assertIn(
        "# Phase 3: Policy Tag to DG Tag Schema Swap Report (DRY RUN)", report
    )
    self.assertIn("Tables Ready to Swap (Dry Run):** 1", report)
    self.assertIn("Total Columns That Would Be Swapped:** 4", report)

  def test_dry_run_swap_schemas_detects_parity_discrepancies_without_mutating(
      self,
  ):
    """Scenario: Dry-run mode runs parity checks and flags discrepancies."""
    # Arrange: Configure empty live V2 policies and dry_run=True.
    self.mock_data_policy_v2_client.list_data_policies.return_value = []
    table = self._make_mock_table(_make_sample_table_schema_fields())
    self.mock_bigquery_client.get_table.return_value = table

    dry_run_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        backup_dir=self.temp_dir.name,
        dry_run=True,
    )

    # Act: Run swap_schemas in dry-run mode.
    results, report = dry_run_swapper.swap_schemas(
        plan=self.plan,
        table_ids=["data-proj.demo_ds.sensitive_customers"],
        regions=["us"],
    )

    # Assert: BLOCKED_PARITY_DISCREPANCY is reported in dry-run mode.
    self.assertEqual(len(results), 1)
    self.assertEqual(
        results[0].status, constants.SWAP_STATUS_BLOCKED_PARITY_DISCREPANCY
    )
    self.assertEqual(len(results[0].parity_discrepancies), 4)
    self.mock_bigquery_client.update_table.assert_not_called()
    self.assertIn("Pre-Swap Enforcement Parity Discrepancies", report)

  # =========================================================================
  # === Section 6: Mode 2 DGT-to-PT Rollback (--swap-mode dgt-to-pt) Tests ===
  # =========================================================================

  def test_invalid_swap_mode_raises_value_error(self):
    """Scenario: Unsupported swap_mode in Swapper raises ValueError."""
    # Arrange / Act / Assert: Invalid swap_mode raises ValueError.
    with self.assertRaisesRegex(ValueError, "Invalid swap_mode"):
      swapper.Swapper(
          bigquery_client=self.mock_bigquery_client,
          dg_tag_keys_client=self.mock_tag_keys_client,
          dg_tag_values_client=self.mock_tag_values_client,
          data_policy_v2_client=self.mock_data_policy_v2_client,
          swap_mode="invalid-mode",
      )

  def test_dgt_to_pt_rollback_transforms_top_level_and_nested_record_fields(
      self,
  ):
    """Scenario: Rollback restores Policy Tags and clears DGTs recursively."""
    # Arrange: Build a DGT-tagged schema with both short and full Tag Value
    # formats.
    dg_key = "target-dgt-proj/manual_migration_taxonomy"
    dgt_fields = [
        {"name": "id", "type": "INTEGER"},
        {
            "name": "contact_info",
            "type": "RECORD",
            "fields": [
                {
                    "name": "email",
                    "type": "STRING",
                    "dataGovernanceTagsInfo": {
                        "dataGovernanceTags": {
                            dg_key: "Email_Mask_Root",
                        }
                    },
                },
                {"name": "phone", "type": "STRING"},
            ],
        },
        {
            "name": "ssn_hash",
            "type": "STRING",
            "dataGovernanceTagsInfo": {
                "dataGovernanceTags": {
                    dg_key: f"{dg_key}/Sha256_Mask_Root",
                }
            },
        },
        {
            "name": "credit_card",
            "type": "STRING",
            "dataGovernanceTagsInfo": {
                "dataGovernanceTags": {
                    dg_key: "Raw_Root",
                }
            },
        },
        {
            "name": "secret_notes",
            "type": "STRING",
            "dataGovernanceTagsInfo": {
                "dataGovernanceTags": {
                    dg_key: f"{dg_key}/Deny_Default_Root",
                }
            },
        },
    ]

    rollback_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        swap_mode=constants.SWAP_MODE_DGT_TO_PT,
    )

    # Act: Transform DGT fields back to Policy Tags and verify integrity.
    updated_fields, swapped_columns, unmapped_columns = (
        rollback_swapper.transform_schema_fields(dgt_fields, self.plan)
    )

    # Assert: All 4 columns restore their original Policy Tags and clear DGTs.
    self.assertEqual(unmapped_columns, [])
    self.assertEqual(len(swapped_columns), 4)
    rollback_swapper.verify_schema_swap_integrity(
        dgt_fields, updated_fields, swapped_columns
    )

    self.assertEqual(updated_fields[0], {"name": "id", "type": "INTEGER"})
    self.assertEqual(
        updated_fields[1]["fields"][1], {"name": "phone", "type": "STRING"}
    )

    email_field = updated_fields[1]["fields"][0]
    self.assertEqual(
        email_field["policyTags"],
        {
            "names": [
                "projects/source-proj/locations/us/"
                "taxonomies/100/policyTags/201"
            ]
        },
    )
    self.assertEqual(
        email_field["dataGovernanceTagsInfo"], {"dataGovernanceTags": {}}
    )

    for index, expected_tag_id in [
        (2, "202"),
        (3, "203"),
        (4, "204"),
    ]:
      field_dict = updated_fields[index]
      self.assertEqual(
          field_dict["policyTags"],
          {
              "names": [
                  "projects/source-proj/locations/us/"
                  f"taxonomies/100/policyTags/{expected_tag_id}"
              ]
          },
      )
      self.assertEqual(
          field_dict["dataGovernanceTagsInfo"], {"dataGovernanceTags": {}}
      )

  def test_round_trip_pt_to_dgt_then_dgt_to_pt_restores_original_policy_tags(
      self,
  ):
    """Scenario: Forward swap then rollback restores exact Policy Tags."""
    # Arrange: Start with original Policy Tag schema fields.
    original_policy_tag_fields = _make_sample_table_schema_fields()

    # Act: Run forward PT-to-DGT swap followed by DGT-to-PT rollback.
    dgt_fields, forward_swapped, forward_unmapped = (
        self.swapper.transform_schema_fields(
            original_policy_tag_fields, self.plan
        )
    )
    self.assertEqual(forward_unmapped, [])
    self.assertEqual(len(forward_swapped), 4)
    self.swapper.verify_schema_swap_integrity(
        original_policy_tag_fields, dgt_fields, forward_swapped
    )

    rollback_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        swap_mode=constants.SWAP_MODE_DGT_TO_PT,
    )
    restored_fields, rollback_swapped, rollback_unmapped = (
        rollback_swapper.transform_schema_fields(dgt_fields, self.plan)
    )

    # Assert: Restored fields pass integrity checks and match original PTs.
    self.assertEqual(rollback_unmapped, [])
    self.assertEqual(len(rollback_swapped), 4)
    rollback_swapper.verify_schema_swap_integrity(
        dgt_fields, restored_fields, rollback_swapped
    )

    self.assertEqual(
        restored_fields[1]["fields"][0]["policyTags"],
        original_policy_tag_fields[1]["fields"][0]["policyTags"],
    )
    self.assertEqual(
        restored_fields[1]["fields"][0]["dataGovernanceTagsInfo"],
        {"dataGovernanceTags": {}},
    )
    for index in (2, 3, 4):
      self.assertEqual(
          restored_fields[index]["policyTags"],
          original_policy_tag_fields[index]["policyTags"],
      )
      self.assertEqual(
          restored_fields[index]["dataGovernanceTagsInfo"],
          {"dataGovernanceTags": {}},
      )

  def test_dgt_to_pt_skips_unmapped_dgt_and_tables_with_no_dg_tags(self):
    """Scenario: Rollback skips tables with unmapped DGTs or no DGTs."""
    # Arrange: Configure one table with an unmapped DGT and one plain table.
    rollback_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        backup_dir=self.temp_dir.name,
        skip_confirmation=True,
        swap_mode=constants.SWAP_MODE_DGT_TO_PT,
    )

    unmapped_dgt_table = self._make_mock_table([{
        "name": "unrelated_col",
        "type": "STRING",
        "dataGovernanceTagsInfo": {
            "dataGovernanceTags": {
                "other-proj/unrelated_key": "Unrelated_Value",
            }
        },
    }])
    plain_table = self._make_mock_table([{"name": "id", "type": "INTEGER"}])

    def get_table_side_effect(table_identifier: str):
      if table_identifier == "data-proj.demo_ds.unmapped_dgt_table":
        return unmapped_dgt_table
      return plain_table

    self.mock_bigquery_client.get_table.side_effect = get_table_side_effect

    # Act: Run swap_schemas in rollback mode.
    results, report = rollback_swapper.swap_schemas(
        plan=self.plan,
        table_ids=[
            "data-proj.demo_ds.unmapped_dgt_table",
            "data-proj.demo_ds.plain_table",
        ],
        regions=["us"],
    )

    # Assert: Both tables are skipped with appropriate statuses.
    self.assertEqual(len(results), 2)
    self.assertEqual(results[0].status, constants.SWAP_STATUS_SKIPPED_UNMAPPED)
    self.assertEqual(len(results[0].unmapped_columns), 1)
    self.assertEqual(
        results[0].unmapped_columns[0].source_policy_tag,
        "key='other-proj/unrelated_key', value='Unrelated_Value'",
    )
    self.assertEqual(
        results[1].status, constants.SWAP_STATUS_SKIPPED_NO_DG_TAGS
    )
    self.assertIn("Tables Skipped (Unmapped DG Tags Only):** 1", report)
    self.assertIn("Tables Skipped (No DG Tags):** 1", report)
    self.mock_bigquery_client.update_table.assert_not_called()

  def test_dgt_to_pt_rejects_column_with_multiple_dg_tags(self):
    """Scenario: Rollback aborts if a column has multiple DG Tags attached."""
    # Arrange: Configure a table column with two DG Tags attached.
    dg_key = "target-dgt-proj/manual_migration_taxonomy"
    rollback_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        backup_dir=self.temp_dir.name,
        skip_confirmation=True,
        swap_mode=constants.SWAP_MODE_DGT_TO_PT,
    )

    multi_dgt_fields = [{
        "name": "email",
        "type": "STRING",
        "dataGovernanceTagsInfo": {
            "dataGovernanceTags": {
                dg_key: "Email_Mask_Root",
                "other-proj/extra_key": "Extra_Value",
            }
        },
    }]
    table = self._make_mock_table(multi_dgt_fields)
    self.mock_bigquery_client.get_table.return_value = table

    # Act: Attempt rollback on the multi-DGT table.
    result = rollback_swapper.swap_table_schema(
        "data-proj", "demo_ds", "multi_dgt_table", self.plan
    )

    # Assert: Rollback is aborted to prevent dropping the extra DGT.
    self.assertEqual(
        result.status, constants.SWAP_STATUS_ABORTED_SCHEMA_CORRUPTION
    )
    self.assertIn("multiple Data Governance Tags", result.error_message)
    self.mock_bigquery_client.update_table.assert_not_called()

  def test_dgt_to_pt_rejects_ambiguous_same_region_rollback_mapping(self):
    """Aborts rollback when two same-region Policy Tags map to one DGT."""
    # Map a second `us` Policy Tag in `plan.json` to the same DGT Tag Key/Value
    # so regional disambiguation cannot pick a unique source Policy Tag.
    dg_key = "target-dgt-proj/manual_migration_taxonomy"
    ambiguous_plan = copy.deepcopy(self.plan)
    ambiguous_plan["phase_3_binding_map"]["policy_tags_to_dg_tag_values"][
        "projects/source-proj/locations/us/taxonomies/999/policyTags/999"
    ] = {
        "dg_tag_key": dg_key,
        "dg_tag_value": f"{dg_key}/Email_Mask_Root",
    }

    rollback_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        backup_dir=self.temp_dir.name,
        skip_confirmation=True,
        swap_mode=constants.SWAP_MODE_DGT_TO_PT,
    )
    table = self._make_mock_table([{
        "name": "dual_governed_col",
        "type": "STRING",
        "dataGovernanceTagsInfo": {
            "dataGovernanceTags": {
                dg_key: "Email_Mask_Root",
            }
        },
    }])
    self.mock_bigquery_client.get_table.return_value = table

    # Exercise `swap_table_schema` in `dgt-to-pt` mode;
    # `_resolve_dg_tag_mapping` must raise `SchemaCorruptionError` naming
    # `dual_governed_col`.
    result = rollback_swapper.swap_table_schema(
        "data-proj", "demo_ds", "ambiguous_dgt_table", ambiguous_plan
    )

    # Confirm the table aborts with `ABORTED_SCHEMA_CORRUPTION` and reports the
    # column name without patching BigQuery.
    self.assertEqual(
        result.status, constants.SWAP_STATUS_ABORTED_SCHEMA_CORRUPTION
    )
    self.assertIn("Ambiguous rollback mapping", result.error_message)
    self.assertIn(
        "(key='target-dgt-proj/manual_migration_taxonomy',"
        " value='Email_Mask_Root')",
        result.error_message,
    )
    self.assertIn("on column 'dual_governed_col'", result.error_message)
    self.mock_bigquery_client.update_table.assert_not_called()

  def test_dgt_to_pt_verify_schema_swap_integrity_rejects_corruptions(self):
    """Scenario: Rollback integrity check rejects uncleared DGTs/mutations."""
    # Arrange: Transform a valid DGT schema in rollback mode.
    dg_key = "target-dgt-proj/manual_migration_taxonomy"
    rollback_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        swap_mode=constants.SWAP_MODE_DGT_TO_PT,
    )

    original_dgt_fields = [
        {"name": "id", "type": "INTEGER"},
        {
            "name": "ssn_hash",
            "type": "STRING",
            "dataGovernanceTagsInfo": {
                "dataGovernanceTags": {dg_key: "Sha256_Mask_Root"}
            },
        },
    ]
    updated_fields, swapped_columns, _ = (
        rollback_swapper.transform_schema_fields(original_dgt_fields, self.plan)
    )

    # Act / Assert 1: Uncleared dataGovernanceTagsInfo is rejected.
    corrupted_uncleared_dgt = copy.deepcopy(updated_fields)
    corrupted_uncleared_dgt[1]["dataGovernanceTagsInfo"] = {
        "dataGovernanceTags": {dg_key: "Sha256_Mask_Root"}
    }
    with self.assertRaisesRegex(
        swapper.SchemaCorruptionError,
        "must have dataGovernanceTagsInfo set to \\{'dataGovernanceTags':"
        " \\{\\}\\}",
    ):
      rollback_swapper.verify_schema_swap_integrity(
          original_dgt_fields, corrupted_uncleared_dgt, swapped_columns
      )

    # Act / Assert 2: Missing or mismatched policyTags is rejected.
    corrupted_wrong_policy_tag = copy.deepcopy(updated_fields)
    corrupted_wrong_policy_tag[1]["policyTags"] = {"names": []}
    with self.assertRaisesRegex(
        swapper.SchemaCorruptionError,
        "Rolled-back field 'ssn_hash' must have policyTags set to",
    ):
      rollback_swapper.verify_schema_swap_integrity(
          original_dgt_fields, corrupted_wrong_policy_tag, swapped_columns
      )

    # Act / Assert 3: Unintended attribute modification is rejected.
    corrupted_type = copy.deepcopy(updated_fields)
    corrupted_type[1]["type"] = "BYTES"
    with self.assertRaisesRegex(
        swapper.SchemaCorruptionError,
        "Unintended attribute modification on swapped field 'ssn_hash'",
    ):
      rollback_swapper.verify_schema_swap_integrity(
          original_dgt_fields, corrupted_type, swapped_columns
      )

  def test_dgt_to_pt_end_to_end_rollback_with_confirmation_backup_and_report(
      self,
  ):
    """Scenario: End-to-end rollback backs up DGT schema and writes report."""
    # Arrange: Build a DGT-swapped table schema and a 'y' confirmation callback.
    self._configure_matching_live_v2_policies()
    dgt_fields, _, _ = self.swapper.transform_schema_fields(
        _make_sample_table_schema_fields(), self.plan
    )
    dgt_fields[1]["fields"][0].pop("policyTags", None)
    for index in (2, 3, 4):
      dgt_fields[index].pop("policyTags", None)

    table = self._make_mock_table(dgt_fields)
    self.mock_bigquery_client.get_table.return_value = table

    prompt_callback = _RecordingPromptCallback("y")
    rollback_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        backup_dir=self.temp_dir.name,
        skip_confirmation=False,
        swap_mode=constants.SWAP_MODE_DGT_TO_PT,
        confirmation_callback=prompt_callback,
    )

    # Act: Run swap_schemas in rollback mode.
    report_path = os.path.join(self.temp_dir.name, "rollback_report.md")
    results, report = rollback_swapper.swap_schemas(
        plan=self.plan,
        table_ids=["data-proj.demo_ds.sensitive_customers"],
        regions=["us"],
        report_file=report_path,
    )

    # Assert: Table is rolled back, backed up, and reported accurately.
    # Prompt 1 is the pre-swap README.md review & risk acknowledgment;
    # Prompt 2 is the per-table schema rollback confirmation.
    self.assertEqual(len(results), 1)
    result = results[0]
    self.assertEqual(result.status, constants.SWAP_STATUS_SWAPPED)
    self.assertEqual(len(result.swapped_columns), 4)
    self.assertEqual(len(prompt_callback.prompts), 2)
    self.assertIn(
        "Have you thoroughly read and understood README.md and the risks of"
        " proceeding?",
        prompt_callback.prompts[0],
    )
    self.assertIsNotNone(result.backup_file_path)
    self.assertTrue(os.path.exists(result.backup_file_path))

    self.mock_bigquery_client.update_table.assert_called_once_with(
        table, ["schema"]
    )
    patched_fields = table._properties["schema"]["fields"]
    self.assertEqual(
        patched_fields[1]["fields"][0]["policyTags"],
        {
            "names": [
                "projects/source-proj/locations/us/"
                "taxonomies/100/policyTags/201"
            ]
        },
    )
    self.assertEqual(
        patched_fields[1]["fields"][0]["dataGovernanceTagsInfo"],
        {"dataGovernanceTags": {}},
    )
    self.assertIn(
        "# Phase 3: DG Tag to Policy Tag Schema Rollback Report", report
    )
    # Rollback reports render both the forward re-cutover command (pt-to-dgt)
    # and the pre-rollback bq update snapshot restore command.
    self.assertIn(
        "python main.py --phase swap --swap-mode pt-to-dgt"
        " --plan-file plan.json"
        " --table-ids data-proj.demo_ds.sensitive_customers"
        " --regions us",
        report,
    )
    self.assertIn("bq update data-proj:demo_ds.sensitive_customers", report)
    self.assertIn("rolled back PT schema", result.schema_diff)

  def test_dgt_to_pt_rollback_succeeds_even_when_v2_data_policies_missing(
      self,
  ):
    """Scenario: Rollback succeeds even when live V2 policies are missing."""
    # Arrange: Return empty live V2 Data Policies and a DGT-swapped table.
    self.mock_data_policy_v2_client.list_data_policies.return_value = []
    dgt_fields, _, _ = self.swapper.transform_schema_fields(
        _make_sample_table_schema_fields(), self.plan
    )
    table = self._make_mock_table(dgt_fields)
    self.mock_bigquery_client.get_table.return_value = table

    rollback_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        backup_dir=self.temp_dir.name,
        skip_confirmation=True,
        swap_mode=constants.SWAP_MODE_DGT_TO_PT,
    )

    # Act: Run swap_table_schema in rollback mode.
    result = rollback_swapper.swap_table_schema(
        "data-proj", "demo_ds", "sensitive_customers", self.plan
    )

    # Assert: Rollback succeeds without parity discrepancies.
    self.assertEqual(result.status, constants.SWAP_STATUS_SWAPPED)
    self.assertEqual(result.parity_discrepancies, [])
    self.mock_bigquery_client.update_table.assert_called_once_with(
        table, ["schema"]
    )

  def test_pt_to_dgt_rejects_column_with_conflicting_preexisting_dgt(self):
    """Scenario: Forward swap aborts if column has conflicting pre-DGT."""
    # Arrange: Build a column with both a Policy Tag and an unrelated DGT.
    conflicting_fields = [{
        "name": "email",
        "type": "STRING",
        "policyTags": {
            "names": [
                "projects/source-proj/locations/us/"
                "taxonomies/100/policyTags/201"
            ]
        },
        "dataGovernanceTagsInfo": {
            "dataGovernanceTags": {
                "other-proj/unrelated_key": "Unrelated_Value",
            }
        },
    }]
    table = self._make_mock_table(conflicting_fields)
    self.mock_bigquery_client.get_table.return_value = table

    # Act: Attempt forward swap on the conflicting table.
    result = self.swapper.swap_table_schema(
        "data-proj", "demo_ds", "conflicting_table", self.plan
    )

    # Assert: Swap is aborted with ABORTED_SCHEMA_CORRUPTION.
    self.assertEqual(
        result.status, constants.SWAP_STATUS_ABORTED_SCHEMA_CORRUPTION
    )
    self.assertIn(
        "conflicting pre-existing Data Governance Tag", result.error_message
    )
    self.mock_bigquery_client.update_table.assert_not_called()

  def test_verify_enforcement_parity_reports_rest_grantee_fetch_error(self):
    """Scenario: REST grantee hydration failure reports a discrepancy."""
    # Arrange: Configure REST GET to fail with HTTP 500 when hydrating grantees
    # for a Raw Reader policy whose expected grantees are non-empty.
    mock_credentials = mock.create_autospec(
        _FakeCredentials, instance=True, spec_set=True
    )
    mock_credentials.token = "fake-token"
    self.mock_auth_default.side_effect = None
    self.mock_auth_default.return_value = (mock_credentials, "data-proj")
    self.mock_urlopen.side_effect = OSError("HTTP 500 Internal Server Error")

    dg_key = "target-dgt-proj/manual_migration_taxonomy"
    self.mock_data_policy_v2_client.list_data_policies.return_value = [
        _make_mock_v2_policy(
            policy_id="migrated_raw_raw_root",
            policy_type=constants.DATA_POLICY_TYPE_RAW,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Raw_Root",
            grantees=[],  # Triggers REST grantee lookup because planned != []
        )
    ]

    fields = [_make_sample_table_schema_fields()[3]]  # credit_card
    _, swapped_columns, _ = self.swapper.transform_schema_fields(
        fields, self.plan
    )

    # Act: Verify enforcement parity.
    discrepancies = self.swapper.verify_enforcement_parity(
        swapped_columns=swapped_columns,
        plan=self.plan,
        table_project_id="data-proj",
        table_location="us",
    )

    # Assert: REST grantee fetch failure is reported as a discrepancy.
    self.assertTrue(
        any(
            discrepancy.risk_category
            == constants.PARITY_RISK_RESOURCE_DISCREPANCY
            and "Failed to verify grantees via REST" in discrepancy.description
            for discrepancy in discrepancies
        )
    )

  def test_verify_enforcement_parity_no_fail_open_on_classification_list_error(
      self,
  ):
    """Scenario: PermissionDenied listing V2 policies does not fail open."""
    # Arrange: Configure list_data_policies to raise PermissionDenied.
    self.mock_data_policy_v2_client.list_data_policies.side_effect = (
        google.api_core.exceptions.PermissionDenied(
            "403 Permission Denied listing data policies"
        )
    )
    fields = [{
        "name": "public_col",
        "type": "STRING",
        "policyTags": {
            "names": [
                "projects/source-proj/locations/us/"
                "taxonomies/999/policyTags/901"
            ]
        },
    }]
    _, swapped_columns, _ = self.swapper.transform_schema_fields(
        fields, self.plan
    )

    # Act: Verify enforcement parity.
    discrepancies = self.swapper.verify_enforcement_parity(
        swapped_columns=swapped_columns,
        plan=self.plan,
        table_project_id="data-proj",
        table_location="us",
    )

    # Assert: Discrepancy is recorded instead of failing open.
    self.assertEqual(len(discrepancies), 1)
    self.assertEqual(
        discrepancies[0].risk_category,
        constants.PARITY_RISK_RESOURCE_DISCREPANCY,
    )
    self.assertIn(
        "Failed to list live V2 Data Policies", discrepancies[0].description
    )

  def test_verify_enforcement_parity_does_not_fail_open_on_rest_fallback_error(
      self,
  ):
    """Scenario: REST fallback failure does not fail open."""
    # Arrange: Return a legacy SDK policy without data_governance_tag and make
    # REST auth fail.
    legacy_sdk_policy = types.SimpleNamespace(
        name="projects/data-proj/locations/us/dataPolicies/v1_policy",
        data_governance_tag=None,
    )
    self.mock_data_policy_v2_client.list_data_policies.return_value = [
        legacy_sdk_policy
    ]
    self.mock_auth_default.side_effect = (
        google.api_core.exceptions.PermissionDenied(
            "403 Permission Denied on REST fallback"
        )
    )

    fields = [{
        "name": "public_col",
        "type": "STRING",
        "policyTags": {
            "names": [
                "projects/source-proj/locations/us/"
                "taxonomies/999/policyTags/901"
            ]
        },
    }]
    _, swapped_columns, _ = self.swapper.transform_schema_fields(
        fields, self.plan
    )

    # Act: Verify enforcement parity.
    discrepancies = self.swapper.verify_enforcement_parity(
        swapped_columns=swapped_columns,
        plan=self.plan,
        table_project_id="data-proj",
        table_location="us",
    )

    # Assert: REST fallback failure is reported as a discrepancy.
    self.assertEqual(len(discrepancies), 1)
    self.assertEqual(
        discrepancies[0].risk_category,
        constants.PARITY_RISK_RESOURCE_DISCREPANCY,
    )
    self.assertIn(
        "Failed to list live V2 Data Policies", discrepancies[0].description
    )

  def test_verify_enforcement_parity_detects_inherited_ancestor_masking_policy(
      self,
  ):
    """Scenario: Unexpected ancestor masking policy on Raw_Root is flagged."""
    # Arrange: Attach an unexpected masking policy to ancestor Raw_Root.
    dg_key = "target-dgt-proj/manual_migration_taxonomy"
    self.mock_data_policy_v2_client.list_data_policies.return_value = [
        _make_mock_v2_policy(
            policy_id="migrated_raw_raw_root",
            policy_type=constants.DATA_POLICY_TYPE_RAW,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Raw_Root",
            grantees=["user:raw_reader@example.com"],
        ),
        _make_mock_v2_policy(
            policy_id="unexpected_ancestor_masking_on_raw_root",
            policy_type=constants.DATA_POLICY_TYPE_MASKING,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Raw_Root",
            grantees=["user:unexpected_masked_reader@example.com"],
            predefined_expression="DEFAULT_MASKING_VALUE",
        ),
        _make_mock_v2_policy(
            policy_id="migrated_raw_raw_child_default_deny",
            policy_type=constants.DATA_POLICY_TYPE_RAW,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Raw_Child",
            grantees=[],
        ),
    ]

    child_schema = [{
        "name": "child_col",
        "type": "STRING",
        "policyTags": {
            "names": [
                "projects/source-proj/locations/us/"
                "taxonomies/100/policyTags/205"
            ]
        },
    }]
    _, swapped_columns, _ = self.swapper.transform_schema_fields(
        child_schema, self.plan
    )

    # Act: Verify enforcement parity on the child column.
    discrepancies = self.swapper.verify_enforcement_parity(
        swapped_columns=swapped_columns,
        plan=self.plan,
        table_project_id="data-proj",
        table_location="us",
    )

    # Assert: Inherited ancestor masking policy is flagged as
    # ACCESS_LEAKAGE_RISK.
    self.assertEqual(len(discrepancies), 1)
    self.assertEqual(
        discrepancies[0].risk_category, constants.PARITY_RISK_ACCESS_LEAKAGE
    )
    self.assertIn(
        "unexpected_ancestor_masking_on_raw_root",
        discrepancies[0].description,
    )

  def test_backup_table_schema_isolates_subdirectories_and_rejects_domain_proj(
      self,
  ):
    """Writes backups under `<mode>/<project>/<dataset>/<table>.json`."""
    # Mode/project/dataset subdirectories keep forward and rollback backups plus
    # `__` / `_rollback` identifier pairs strictly non-colliding.
    project_id = "data-proj"
    policy_tag_fields = [
        {"name": "id", "type": "INTEGER", "policyTags": {"names": []}}
    ]
    dgt_fields = [
        {"name": "id", "type": "INTEGER", "dataGovernanceTagsInfo": {}}
    ]

    forward_backup_path = self.swapper.backup_table_schema(
        project_id, "demo_ds", "sensitive_customers", policy_tag_fields
    )
    rollback_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        backup_dir=self.temp_dir.name,
        swap_mode=constants.SWAP_MODE_DGT_TO_PT,
    )
    rollback_backup_path = rollback_swapper.backup_table_schema(
        project_id, "demo_ds", "sensitive_customers", dgt_fields
    )

    self.assertEqual(
        forward_backup_path,
        os.path.join(
            self.temp_dir.name,
            constants.BACKUP_SUBDIR_PT_TO_DGT,
            "data-proj",
            "demo_ds",
            "sensitive_customers.json",
        ),
    )
    self.assertEqual(
        rollback_backup_path,
        os.path.join(
            self.temp_dir.name,
            constants.BACKUP_SUBDIR_DGT_TO_PT,
            "data-proj",
            "demo_ds",
            "sensitive_customers.json",
        ),
    )
    with open(forward_backup_path, "r", encoding="utf-8") as forward_file:
      self.assertEqual(json.load(forward_file), policy_tag_fields)
    with open(rollback_backup_path, "r", encoding="utf-8") as rollback_file:
      self.assertEqual(json.load(rollback_file), dgt_fields)

    # Confirm pairs that previously collided in flat filenames map to 4 distinct
    # subdirectory paths, and domain-scoped project IDs raise ValueError.
    distinct_paths = {
        self.swapper._get_backup_file_path("data-proj", "a__b", "c"),
        self.swapper._get_backup_file_path("data-proj", "a", "b__c"),
        self.swapper._get_backup_file_path("data-proj", "ds", "t_rollback"),
        rollback_swapper._get_backup_file_path("data-proj", "ds", "t"),
    }
    self.assertEqual(len(distinct_paths), 4)
    with self.assertRaises(ValueError) as ctx:
      self.swapper.backup_table_schema(
          "example.com:data-proj", "demo_ds", "tbl", policy_tag_fields
      )
    self.assertIn(
        constants.UNSUPPORTED_DOMAIN_SCOPED_PROJECT_MSG, str(ctx.exception)
    )

  def test_backup_table_schema_enforces_overwrite_and_skip_confirmation(self):
    """Scenario: Existing schema backup requires overwrite=True to replace."""
    project_id = "data-proj"
    dataset_id = "demo_ds"
    table_id = "sensitive_customers"
    initial_fields = [{"name": "id", "type": "INTEGER"}]
    updated_fields = [{"name": "id", "type": "STRING"}]

    # First backup writes cleanly to an empty directory.
    backup_path = self.swapper.backup_table_schema(
        project_id, dataset_id, table_id, initial_fields
    )
    self.assertTrue(os.path.exists(backup_path))

    # With overwrite=False (default on self.swapper even though
    # skip_confirmation=True), a second backup to the same path raises
    # FileExistsError and preserves the original backup file.
    with self.assertRaisesRegex(FileExistsError, "Pass --overwrite"):
      self.swapper.backup_table_schema(
          project_id, dataset_id, table_id, updated_fields
      )
    with open(backup_path, "r", encoding="utf-8") as backup_file:
      self.assertEqual(json.load(backup_file), initial_fields)

    # With overwrite=True and skip_confirmation=False, declining ("n") raises
    # FileExistsError without overwriting the file.
    decline_callback = _RecordingPromptCallback("n")
    prompt_swapper_decline = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        backup_dir=self.temp_dir.name,
        skip_confirmation=False,
        overwrite=True,
        confirmation_callback=decline_callback,
    )
    with self.assertRaisesRegex(FileExistsError, "User declined overwriting"):
      prompt_swapper_decline.backup_table_schema(
          project_id, dataset_id, table_id, updated_fields
      )
    self.assertEqual(len(decline_callback.prompts), 1)

    # With overwrite=True and skip_confirmation=False, approving ("y")
    # overwrites the existing backup file.
    approve_callback = _RecordingPromptCallback("y")
    prompt_swapper_approve = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        backup_dir=self.temp_dir.name,
        skip_confirmation=False,
        overwrite=True,
        confirmation_callback=approve_callback,
    )
    prompt_swapper_approve.backup_table_schema(
        project_id, dataset_id, table_id, updated_fields
    )
    self.assertEqual(len(approve_callback.prompts), 1)
    with open(backup_path, "r", encoding="utf-8") as backup_file:
      self.assertEqual(json.load(backup_file), updated_fields)

    # With both overwrite=True and skip_confirmation=True, the backup file is
    # overwritten without prompting.
    silent_callback = _RecordingPromptCallback("n")
    silent_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        backup_dir=self.temp_dir.name,
        skip_confirmation=True,
        overwrite=True,
        confirmation_callback=silent_callback,
    )
    silent_swapper.backup_table_schema(
        project_id, dataset_id, table_id, initial_fields
    )
    self.assertEqual(silent_callback.prompts, [])
    with open(backup_path, "r", encoding="utf-8") as backup_file:
      self.assertEqual(json.load(backup_file), initial_fields)

  # =========================================================================
  # === Section 7: Scale, Seatbelt, and Strict Tag-Matching Regressions ===
  # =========================================================================

  def test_verify_enforcement_parity_hydrates_default_deny_and_catches_drift(
      self,
  ):
    """Scenario: _default_deny policies hydrate grantees and block drift."""
    # `ListDataPolicies` omits `grantees` on all 7 DGT policies (3 populated
    # policies + 4 `*_default_deny` seatbelts), so REST `GET /v2/{name}` runs
    # once per policy for the `(project, location)` cache entry.
    self._configure_matching_live_v2_policies()
    self.mock_urlopen.reset_mock()

    original_fields = _make_sample_table_schema_fields()
    _, swapped_columns, _ = self.swapper.transform_schema_fields(
        original_fields, self.plan
    )

    discrepancies = self.swapper.verify_enforcement_parity(
        swapped_columns=swapped_columns,
        plan=self.plan,
        table_project_id="data-proj",
        table_location="us",
    )

    # Confirm zero discrepancies when `_default_deny` grantees are empty and
    # all 7 DGT policies were hydrated once via REST GET.
    self.assertEqual(discrepancies, [])
    requested_urls = [
        call.args[0].full_url for call in self.mock_urlopen.call_args_list
    ]
    self.assertEqual(len(requested_urls), 7)
    self.assertTrue(any("_default_deny" in url for url in requested_urls))

    # Inject an unauthorized grantee onto a live `_default_deny` policy and
    # confirm pre-swap parity blocks with `ACCESS_LEAKAGE_RISK`.
    self.swapper._live_v2_policies_cache.clear()
    self._rest_grantees_override[
        "migrated_raw_deny_default_root_default_deny"
    ] = ["user:rogue_reader@example.com"]
    drifted_discrepancies = self.swapper.verify_enforcement_parity(
        swapped_columns=swapped_columns,
        plan=self.plan,
        table_project_id="data-proj",
        table_location="us",
    )
    self.assertEqual(len(drifted_discrepancies), 1)
    self.assertEqual(
        drifted_discrepancies[0].risk_category,
        constants.PARITY_RISK_ACCESS_LEAKAGE,
    )
    self.assertIn(
        "user:rogue_reader@example.com", drifted_discrepancies[0].description
    )

  def test_resolve_target_tables_prefilters_info_schema_and_skips_snapshots(
      self,
  ):
    """Scenario: Project scope pre-filters via INFO_SCHEMA and skips snaps."""
    # Arrange: Configure query() to return 1 tagged table for proj-info, and
    # configure dataset scanning on proj-list to return a TABLE and a SNAPSHOT.
    query_job = types.SimpleNamespace(
        result=lambda: [
            types.SimpleNamespace(
                table_catalog="proj-info",
                table_schema="ds_1",
                table_name="tagged_table",
            )
        ]
    )
    self.mock_bigquery_client.query.return_value = query_job

    table_item = types.SimpleNamespace(
        table_id="real_table", table_type="TABLE"
    )
    snapshot_item = types.SimpleNamespace(
        table_id="snap_table", table_type="SNAPSHOT"
    )
    self.mock_bigquery_client.list_tables.return_value = [
        table_item,
        snapshot_item,
    ]
    self.mock_bigquery_client.get_dataset.return_value = types.SimpleNamespace(
        location="US"
    )

    # Act: Resolve target tables with regions=["us"].
    resolved_tables, failures = self.swapper.resolve_target_tables(
        table_project_ids=["proj-info"],
        dataset_ids=["proj-list.ds_2"],
        regions=["us"],
    )

    # Assert: proj-info uses INFORMATION_SCHEMA (excluding CRR `/taxonomies/0/`
    # secondary-replica placeholders) without calling list_datasets, and
    # proj-list skips the SNAPSHOT table.
    self.assertEqual(failures, [])
    self.mock_bigquery_client.list_datasets.assert_not_called()
    executed_sql = self.mock_bigquery_client.query.call_args[0][0]
    self.assertIn("ARRAY_LENGTH(policy_tags) > 0", executed_sql)
    self.assertIn(
        constants.CRR_PLACEHOLDER_POLICY_TAG_SEGMENT,
        executed_sql,
    )
    self.assertEqual(
        resolved_tables,
        [
            ("proj-info", "ds_1", "tagged_table"),
            ("proj-list", "ds_2", "real_table"),
        ],
    )

  def test_resolve_target_tables_dgt_to_pt_prefilters_via_info_schema(self):
    """Scenario: Rollback mode pre-filters project tables via INFO_SCHEMA."""
    # Arrange: Create a rollback Swapper and configure query() to return a
    # DGT-tagged table from INFORMATION_SCHEMA.COLUMN_FIELD_PATHS.
    rollback_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        backup_dir=self.temp_dir.name,
        skip_confirmation=True,
        swap_mode=constants.SWAP_MODE_DGT_TO_PT,
    )
    query_job = types.SimpleNamespace(
        result=lambda: [{
            "table_catalog": "proj-rollback",
            "table_schema": "ds_dgt",
            "table_name": "dgt_tagged_table",
        }]
    )
    self.mock_bigquery_client.query.return_value = query_job

    # Act: Resolve target tables in rollback mode using explicit regions.
    resolved_tables, failures = rollback_swapper.resolve_target_tables(
        table_project_ids=["proj-rollback"],
        regions=["us"],
    )

    # Assert: INFORMATION_SCHEMA was queried with data_governance_tags filter
    # and list_datasets was not called.
    self.assertEqual(failures, [])
    self.assertEqual(
        resolved_tables, [("proj-rollback", "ds_dgt", "dgt_tagged_table")]
    )
    self.mock_bigquery_client.list_datasets.assert_not_called()
    executed_sql = self.mock_bigquery_client.query.call_args[0][0]
    self.assertIn("ARRAY_LENGTH(data_governance_tags) > 0", executed_sql)

  def test_resolve_target_tables_dgt_to_pt_falls_back_on_info_schema_error(
      self,
  ):
    """Scenario: Rollback falls back to list_datasets on INFO_SCHEMA error."""
    # Arrange: Create a rollback Swapper where bigquery_client.query raises an
    # exception (e.g., data_governance_tags column unavailable in region).
    rollback_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        backup_dir=self.temp_dir.name,
        skip_confirmation=True,
        swap_mode=constants.SWAP_MODE_DGT_TO_PT,
    )
    self.mock_bigquery_client.query.side_effect = RuntimeError(
        "Unrecognized name: data_governance_tags"
    )
    self.mock_bigquery_client.list_datasets.return_value = [
        types.SimpleNamespace(dataset_id="fallback_ds")
    ]
    self.mock_bigquery_client.list_tables.return_value = [
        types.SimpleNamespace(table_id="fallback_table", table_type="TABLE")
    ]

    # Act: Resolve target tables in rollback mode.
    resolved_tables, failures = rollback_swapper.resolve_target_tables(
        table_project_ids=["proj-fallback"],
        regions=["us"],
    )

    # Assert: Query failure falls back cleanly to list_datasets/list_tables.
    self.assertEqual(failures, [])
    self.assertEqual(
        resolved_tables,
        [("proj-fallback", "fallback_ds", "fallback_table")],
    )
    self.mock_bigquery_client.list_datasets.assert_called_once_with(
        project="proj-fallback"
    )

  def test_verify_parity_detects_missing_raw_default_deny_when_masking_present(
      self,
  ):
    """Scenario: Missing direct RAW_DATA_ACCESS_POLICY seatbelt flags leak."""
    # Arrange: Configure Email_Mask_Root with its DATA_MASKING_POLICY but omit
    # its mandatory _default_deny RAW_DATA_ACCESS_POLICY seatbelt.
    dg_key = "target-dgt-proj/manual_migration_taxonomy"
    self.mock_data_policy_v2_client.list_data_policies.return_value = [
        _make_mock_v2_policy(
            policy_id="migrated_masking_email_mask_policy",
            policy_type=constants.DATA_POLICY_TYPE_MASKING,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Email_Mask_Root",
            grantees=["user:masked_reader@example.com"],
            predefined_expression="EMAIL_MASK",
        )
    ]

    email_only_schema = [_make_sample_table_schema_fields()[1]]  # contact_info
    _, swapped_columns, _ = self.swapper.transform_schema_fields(
        email_only_schema, self.plan
    )

    # Act: Verify enforcement parity.
    discrepancies = self.swapper.verify_enforcement_parity(
        swapped_columns=swapped_columns,
        plan=self.plan,
        table_project_id="data-proj",
        table_location="us",
    )

    # Assert: Missing direct RAW_DATA_ACCESS_POLICY is flagged as
    # ACCESS_LEAKAGE_RISK without internal "seatbelt" terminology.
    self.assertEqual(len(discrepancies), 1)
    self.assertEqual(
        discrepancies[0].risk_category, constants.PARITY_RISK_ACCESS_LEAKAGE
    )
    self.assertIn("_default_deny", discrepancies[0].description)
    self.assertNotIn("seatbelt", discrepancies[0].description)

  def test_policy_matches_tag_rejects_cross_project_and_sibling_suffix_matches(
      self,
  ):
    """Scenario: _policy_matches_tag rejects cross-project & sibling tags."""
    # Arrange: Build a live policy summary from another project or sibling
    # branch.
    cross_project_policy = swapper.LiveDataPolicyV2Summary(
        name="projects/data-proj/locations/us/dataPolicies/p1",
        data_policy_id="p1",
        data_policy_type=constants.DATA_POLICY_TYPE_RAW,
        dg_tag_key="other-proj/manual_migration_taxonomy",
        dg_tag_value="other-proj/manual_migration_taxonomy/Raw_Child",
        grantees=[],
    )
    sibling_branch_policy = swapper.LiveDataPolicyV2Summary(
        name="projects/data-proj/locations/us/dataPolicies/p2",
        data_policy_id="p2",
        data_policy_type=constants.DATA_POLICY_TYPE_RAW,
        dg_tag_key="target-dgt-proj/manual_migration_taxonomy",
        dg_tag_value=(
            "target-dgt-proj/manual_migration_taxonomy/Other_Branch/Raw_Child"
        ),
        grantees=[],
    )
    exact_match_policy = swapper.LiveDataPolicyV2Summary(
        name="projects/data-proj/locations/us/dataPolicies/p3",
        data_policy_id="p3",
        data_policy_type=constants.DATA_POLICY_TYPE_RAW,
        dg_tag_key="target-dgt-proj/manual_migration_taxonomy",
        dg_tag_value="Raw_Root/Raw_Child",
        grantees=[],
    )

    # Act / Assert: Cross-project and sibling branch policies are rejected,
    # while exact relative path within the verified Tag Key matches.
    target_key = "target-dgt-proj/manual_migration_taxonomy"
    target_value = (
        "target-dgt-proj/manual_migration_taxonomy/Raw_Root/Raw_Child"
    )
    self.assertFalse(
        self.swapper._policy_matches_tag(
            cross_project_policy,
            dg_tag_key=target_key,
            dg_tag_value=target_value,
        )
    )
    self.assertFalse(
        self.swapper._policy_matches_tag(
            sibling_branch_policy,
            dg_tag_key=target_key,
            dg_tag_value=target_value,
        )
    )
    self.assertTrue(
        self.swapper._policy_matches_tag(
            exact_match_policy,
            dg_tag_key=target_key,
            dg_tag_value=target_value,
        )
    )

  def test_swap_schemas_rejects_unqualified_dataset_and_mode2_missing_project(
      self,
  ):
    """Scenario: Unqualified datasets & unplanned Mode 2 projects fail."""
    # Arrange / Act / Assert 1: Unqualified dataset ID in swap_schemas records a
    # FAILED TableSwapResult instead of falling back to
    # metadata.source_project_id.
    results, _ = self.swapper.swap_schemas(
        plan=self.plan,
        dataset_ids=["unqualified_ds"],
        regions=["us"],
    )
    self.assertEqual(len(results), 1)
    self.assertEqual(results[0].status, constants.SWAP_STATUS_FAILED)
    self.assertEqual(results[0].table_identifier, "unqualified_ds")
    self.assertIn(
        "Invalid dataset identifier 'unqualified_ds'",
        results[0].error_message,
    )

    # Arrange 2: Configure matching live V2 policies in 'unplanned-table-proj',
    # which is not in plan.json's Mode 2 target_project_id actions.
    self._configure_matching_live_v2_policies()
    email_only_schema = [_make_sample_table_schema_fields()[1]]
    _, swapped_columns, _ = self.swapper.transform_schema_fields(
        email_only_schema, self.plan
    )

    # Act 2: Verify enforcement parity for 'unplanned-table-proj'.
    discrepancies = self.swapper.verify_enforcement_parity(
        swapped_columns=swapped_columns,
        plan=self.plan,
        table_project_id="unplanned-table-proj",
        table_location="us",
    )

    # Assert 2: Mode 2 missing project discrepancy is reported with the
    # --target-table-dp-project-ids remediation hint instead of silently
    # comparing against 'data-proj' planned policies.
    self.assertEqual(len(discrepancies), 1)
    self.assertEqual(
        discrepancies[0].risk_category,
        constants.PARITY_RISK_RESOURCE_DISCREPANCY,
    )
    self.assertIn(
        "Table project 'unplanned-table-proj' has no planned V2 Data Policies",
        discrepancies[0].description,
    )
    self.assertIn(
        "--target-table-dp-project-ids unplanned-table-proj",
        discrepancies[0].description,
    )

  def test_swap_schemas_aborts_when_pre_swap_checklist_ack_declined(self):
    """Declining the pre-swap README.md ack aborts before get_table."""
    prompt_callback = _RecordingPromptCallback("n")
    interactive_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        backup_dir=self.temp_dir.name,
        skip_confirmation=False,
        confirmation_callback=prompt_callback,
    )

    # Declining ("n") the pre-swap acknowledgment prompt exits swap_schemas
    # immediately without calling get_table or update_table.
    results, report = interactive_swapper.swap_schemas(
        plan=self.plan,
        table_ids=["data-proj.demo_ds.sensitive_customers"],
        regions=["us"],
    )
    self.assertEqual(results, [])
    self.assertEqual(len(prompt_callback.prompts), 1)
    self.assertIn(
        "Have you thoroughly read and understood README.md and the risks of"
        " proceeding?",
        prompt_callback.prompts[0],
    )
    self.assertIn(
        "Swap phase aborted by user at the pre-swap README.md risk"
        " acknowledgment prompt before inspecting or modifying any tables.",
        report,
    )
    self.mock_bigquery_client.get_table.assert_not_called()
    self.mock_bigquery_client.update_table.assert_not_called()

  def test_swap_schemas_verifies_backup_dir_writability_before_inspection(self):
    """Unwritable backup_dir fails before resolving or inspecting tables."""
    # Point backup_dir at an existing regular file so
    # _verify_backup_dir_writable fails immediately when swap_schemas starts.
    blocking_file_path = os.path.join(self.temp_dir.name, "not_a_directory")
    with open(blocking_file_path, "w", encoding="utf-8") as blocking_file:
      blocking_file.write("file blocking directory creation")

    bad_backup_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        backup_dir=blocking_file_path,
        skip_confirmation=True,
    )

    with self.assertRaises(OSError):
      bad_backup_swapper.swap_schemas(
          plan=self.plan,
          table_ids=["data-proj.demo_ds.sensitive_customers"],
          regions=["us"],
      )
    self.mock_bigquery_client.get_table.assert_not_called()

  def test_generate_swap_report_renders_error_and_block_status_reference(
      self,
  ):
    """Renders swap status and risk enum definitions when errors occur."""
    # Clean swap runs omit the error/block reference section completely.
    clean_result = swapper.TableSwapResult(
        project_id="data-proj",
        dataset_id="demo_ds",
        table_id="clean_table",
        status=constants.SWAP_STATUS_SWAPPED,
    )
    clean_report = self.swapper.generate_swap_report([clean_result])
    self.assertNotIn("## Error & Block Status Reference", clean_report)

    # Error/blocked table outcomes include explanations only for the status and
    # parity risk enums actually encountered in the run.
    blocked_result = swapper.TableSwapResult(
        project_id="data-proj",
        dataset_id="demo_ds",
        table_id="blocked_table",
        status=constants.SWAP_STATUS_BLOCKED_PARITY_DISCREPANCY,
        parity_discrepancies=[
            swapper.ParityDiscrepancy(
                field_path="email",
                source_policy_tag=(
                    "projects/p/locations/us/taxonomies/1/policyTags/2"
                ),
                dg_tag_key="gov-proj/pii",
                dg_tag_value="email",
                risk_category=constants.PARITY_RISK_ACCESS_LEAKAGE,
                description="Missing _default_deny policy.",
            )
        ],
    )
    aborted_result = swapper.TableSwapResult(
        project_id="data-proj",
        dataset_id="demo_ds",
        table_id="aborted_table",
        status=constants.SWAP_STATUS_ABORTED_SCHEMA_CORRUPTION,
        error_message="Conflicting pre-existing Data Governance Tag.",
    )

    error_report = self.swapper.generate_swap_report(
        [blocked_result, aborted_result]
    )

    self.assertIn("## Error & Block Status Reference", error_report)
    self.assertIn(
        f"- **`{constants.SWAP_STATUS_BLOCKED_PARITY_DISCREPANCY}`:**",
        error_report,
    )
    self.assertIn(
        f"- **`{constants.SWAP_STATUS_ABORTED_SCHEMA_CORRUPTION}`:**",
        error_report,
    )
    self.assertIn(
        f"- **`{constants.PARITY_RISK_ACCESS_LEAKAGE}`:**",
        error_report,
    )
    self.assertNotIn(
        f"- **`{constants.SWAP_STATUS_FAILED}`:**",
        error_report,
    )

  def test_swap_schemas_blocks_on_unresolved_action_required_plan_warning(self):
    """Blocks forward `pt-to-dgt` swap when `[ACTION REQUIRED]` remains."""
    # Inject an unresolved `[ACTION REQUIRED]` warning on a planned V2 policy
    # and configure a prompt spy to prove blocking occurs before prompting.
    prompt_spy = mock.MagicMock(return_value="y")
    live_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        confirmation_callback=prompt_spy,
    )
    plan = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_DATA_POLICIES_V1_TO_DATA_POLICIES_V2: [{
                constants.FIELD_POLICY_ID: "mask_email",
                constants.FIELD_TARGET_PROJECT_ID: "data-proj",
                constants.FIELD_WARNINGS: [
                    "[ACTION REQUIRED] Unsupported domain:example.com grantee."
                ],
            }]
        }
    }

    # Forward `swap_schemas` must halt before backup-dir creation, README
    # acknowledgment prompt, or BigQuery table discovery.
    with mock.patch.object(
        live_swapper, "resolve_target_tables"
    ) as mock_resolve:
      results, report = live_swapper.swap_schemas(
          plan=plan,
          table_ids=["data-proj.demo_ds.users"],
          regions=["us"],
      )

    # Verify a single plan-level `BLOCKED_UNRESOLVED_PLAN_WARNINGS` result is
    # returned and documented in the Markdown report.
    prompt_spy.assert_not_called()
    mock_resolve.assert_not_called()
    self.assertEqual(len(results), 1)
    self.assertEqual(
        results[0].status,
        constants.SWAP_STATUS_BLOCKED_UNRESOLVED_PLAN_WARNINGS,
    )
    self.assertIn(
        "## Blocked by Unresolved Plan Warnings ([ACTION REQUIRED])", report
    )
    self.assertIn("Unsupported domain:example.com grantee.", report)
    self.assertIn(
        f"- **`{constants.SWAP_STATUS_BLOCKED_UNRESOLVED_PLAN_WARNINGS}`:**",
        report,
    )

  def test_swap_schemas_allow_unresolved_plan_warnings_proceeds(self):
    """Proceeds with forward swap when `allow_unresolved_plan_warnings=True`."""
    # Enabling `allow_unresolved_plan_warnings` overrides the upfront gate while
    # recording the overridden warning in the generated swap report.
    override_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        allow_unresolved_plan_warnings=True,
        dry_run=True,
    )
    plan = {
        "warnings": ["[ACTION REQUIRED] Custom routine project unresolved."],
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {},
    }
    skipped_table = swapper.TableSwapResult(
        project_id="data-proj",
        dataset_id="demo_ds",
        table_id="clean_table",
        status=constants.SWAP_STATUS_SKIPPED_NO_POLICY_TAGS,
    )

    # Exercise dry-run `swap_schemas` with a mocked table discovery result.
    with (
        mock.patch.object(
            override_swapper,
            "resolve_target_tables",
            return_value=([("data-proj", "demo_ds", "clean_table")], []),
        ) as mock_resolve,
        mock.patch.object(
            override_swapper,
            "swap_table_schema",
            return_value=skipped_table,
        ),
    ):
      results, report = override_swapper.swap_schemas(
          plan=plan,
          table_ids=["data-proj.demo_ds.clean_table"],
          regions=["us"],
      )

    # Confirm table discovery ran and the overridden warning was surfaced.
    mock_resolve.assert_called_once()
    self.assertEqual(len(results), 1)
    self.assertEqual(
        results[0].status, constants.SWAP_STATUS_SKIPPED_NO_POLICY_TAGS
    )
    self.assertIn(
        "## Overridden Unresolved Plan Warnings ([ACTION REQUIRED])", report
    )

  def test_swap_schemas_rollback_ignores_unresolved_plan_warnings(self):
    """Exempts `dgt-to-pt` rollback from `[ACTION REQUIRED]` plan blocking."""
    # Emergency `dgt-to-pt` rollback must remain available even if `plan.json`
    # still contains unresolved `[ACTION REQUIRED]` warnings.
    rollback_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        swap_mode=constants.SWAP_MODE_DGT_TO_PT,
        dry_run=True,
    )
    plan = {
        "warnings": ["[ACTION REQUIRED] Overlong V2 Data Policy ID."],
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {},
    }

    # Exercise rollback `swap_schemas` without `allow_unresolved_plan_warnings`.
    with mock.patch.object(
        rollback_swapper,
        "resolve_target_tables",
        return_value=([], []),
    ) as mock_resolve:
      results, report = rollback_swapper.swap_schemas(
          plan=plan,
          table_ids=["data-proj.demo_ds.users"],
          regions=["us"],
      )

    # Confirm rollback was not blocked and proceeded into table resolution.
    mock_resolve.assert_called_once()
    self.assertEqual(results, [])
    self.assertNotIn(
        constants.SWAP_STATUS_BLOCKED_UNRESOLVED_PLAN_WARNINGS, report
    )

  # Direct --table-ids targeting a non-table resource (VIEW/SNAPSHOT) skips
  # schema tag transformation with an explicit table_type explanation.
  def test_swap_table_schema_skips_non_table_resources(self):
    """Skips VIEW and SNAPSHOT resources before schema transformation."""
    # Attach table_type='VIEW' to a table resource even when its schema contains
    # a mapped Policy Tag so we verify the non-table barrier fires first.
    view_resource = self._make_mock_table(_make_sample_table_schema_fields())
    view_resource.table_type = "VIEW"
    self.mock_bigquery_client.get_table.return_value = view_resource

    # Execute swap_table_schema on the VIEW resource.
    result = self.swapper.swap_table_schema(
        "data-proj", "demo_ds", "customers_view", self.plan
    )

    # Confirm the VIEW is skipped with `SKIPPED_NON_TABLE`, an explicit
    # `table_type=VIEW` note, a non-table summary line, and zero mutations.
    self.assertEqual(result.status, constants.SWAP_STATUS_SKIPPED_NON_TABLE)
    self.assertEqual(result.swapped_columns, [])
    self.assertIn(
        "Skipped non-table resource (table_type=VIEW)",
        result.error_message,
    )
    report = self.swapper.generate_swap_report([result])
    self.assertIn("- **Tables Skipped (Non-Table Resource):** 1", report)
    self.mock_bigquery_client.update_table.assert_not_called()

  # Blocked, declined, or failed tables that were never patched in BigQuery
  # must show 'None' in Swapped Columns and omit rollback commands in diffs.
  def test_generate_swap_report_omits_rollback_cmds_for_unswapped_tables(self):
    """Omits Swapped Columns and rollback commands when status != SWAPPED."""
    # Construct a blocked result that carries candidate swapped_columns and a
    # schema_diff from pre-swap inspection but was never patched in BigQuery.
    candidate_column = swapper.ColumnSwapDetail(
        field_path="email",
        source_policy_tag="projects/p/locations/us/taxonomies/1/policyTags/2",
        matched_plan_policy_tag=(
            "projects/p/locations/us/taxonomies/1/policyTags/2"
        ),
        dg_tag_key="gov-proj/pii",
        dg_tag_value="email_mask",
    )
    blocked_result = swapper.TableSwapResult(
        project_id="data-proj",
        dataset_id="demo_ds",
        table_id="blocked_table",
        location="us",
        status=constants.SWAP_STATUS_BLOCKED_PARITY_DISCREPANCY,
        swapped_columns=[candidate_column],
        schema_diff="--- a/schema\n+++ b/schema\n@@ -1 +1 @@\n-old\n+new\n",
        error_message="Blocked schema swap due to parity discrepancy.",
    )

    # Render the swap report for the blocked table.
    report = self.swapper.generate_swap_report([blocked_result])

    # Confirm Table Details shows 'None' in Swapped Columns and Schema Diffs
    # includes the unified diff without printing rollback CLI commands.
    self.assertIn(
        "| `data-proj.demo_ds.blocked_table` | `BLOCKED_PARITY_DISCREPANCY` |"
        " None | N/A | Blocked schema swap due to parity discrepancy. |",
        report,
    )
    self.assertIn("```diff", report)
    self.assertNotIn("Surgical Rollback Command", report)
    self.assertNotIn("Snapshot Rollback Command", report)

  # Interactive confirmation mode emits the INFO schema diff record to file
  # handlers while avoiding duplicate INFO console output before the banner.
  def test_swap_table_schema_interactive_logs_diff_to_file_handler_only(self):
    """Writes INFO schema diff to FileHandler without console INFO duplicate."""
    self._configure_matching_live_v2_policies()
    table = self._make_mock_table(_make_sample_table_schema_fields())
    self.mock_bigquery_client.get_table.return_value = table
    log_file_path = os.path.join(self.temp_dir.name, "interactive_swap.log")
    file_handler = logging.FileHandler(log_file_path, encoding="utf-8")
    file_handler.setLevel(logging.INFO)
    swapper.logger.addHandler(file_handler)
    self.addCleanup(swapper.logger.removeHandler, file_handler)
    self.addCleanup(file_handler.close)

    interactive_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        backup_dir=self.temp_dir.name,
        skip_confirmation=False,
        confirmation_callback=_RecordingPromptCallback("n"),
    )

    # Run interactive swap_table_schema and inspect logger.info calls vs file.
    with mock.patch.object(
        swapper.logger, "info", wraps=swapper.logger.info
    ) as spy_logger_info:
      interactive_swapper.swap_table_schema(
          "data-proj", "demo_ds", "sensitive_customers", self.plan
      )
    file_handler.flush()

    # Confirm logger.info was not called with 'Proposed schema diff', while the
    # FileHandler log file recorded the full proposed schema diff.
    info_messages = [call.args[0] for call in spy_logger_info.call_args_list]
    self.assertFalse(
        any("Proposed schema diff" in str(msg) for msg in info_messages)
    )
    with open(log_file_path, "r", encoding="utf-8") as log_file:
      log_contents = log_file.read()
    self.assertIn(
        "Proposed schema diff for data-proj.demo_ds.sensitive_customers:",
        log_contents,
    )

  # When `--halt-on-error` raises on a later table after an earlier table has
  # already swapped, `swap_schemas` must still write the partial report so
  # rollback commands for the swapped table are preserved on disk.
  def test_swap_schemas_writes_partial_report_when_halt_on_error_raises(self):
    """Writes partial swap report to `report_file` when a later table raises."""
    self._configure_matching_live_v2_policies()
    first_table = self._make_mock_table(_make_sample_table_schema_fields())
    second_table = self._make_mock_table(_make_sample_table_schema_fields())
    self.mock_bigquery_client.get_table.side_effect = [
        first_table,
        second_table,
    ]
    # Succeed on the first table's `update_table`, then fail on the second.
    self.mock_bigquery_client.update_table.side_effect = [
        first_table,
        RuntimeError("412 Precondition Failed"),
    ]
    report_path = os.path.join(self.temp_dir.name, "partial_swap_report.md")
    halting_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        backup_dir=self.temp_dir.name,
        skip_confirmation=True,
        halt_on_error=True,
    )

    with self.assertRaisesRegex(RuntimeError, "412 Precondition Failed"):
      halting_swapper.swap_schemas(
          plan=self.plan,
          table_ids=["data-proj.demo_ds.t1", "data-proj.demo_ds.t2"],
          regions=["us"],
          report_file=report_path,
      )

    # Confirm the report file and `last_report` contain `t1` and its rollback
    # command despite the exception on `t2`.
    self.assertTrue(os.path.exists(report_path))
    with open(report_path, "r", encoding="utf-8") as report_file:
      saved_report = report_file.read()
    self.assertIn("`data-proj.demo_ds.t1` | `SWAPPED`", saved_report)
    self.assertIn("Surgical Rollback Command", saved_report)
    self.assertEqual(halting_swapper.last_report, saved_report)

  # Non-interactive `EOFError` at the pre-swap `README.md` acknowledgment prompt
  # must raise `_PromptAbortedError` (`RuntimeError`) rather than silently
  # returning an empty `0`-exit result.
  def test_swap_schemas_raises_on_eof_at_readme_prompt(self):
    """Raises `RuntimeError` when `EOFError` aborts the README prompt."""

    def _raise_eof(_: str) -> str:
      raise EOFError()

    interactive_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        backup_dir=self.temp_dir.name,
        skip_confirmation=False,
        confirmation_callback=_raise_eof,
    )

    with self.assertRaisesRegex(
        RuntimeError, "Interactive confirmation prompt aborted"
    ):
      interactive_swapper.swap_schemas(
          plan=self.plan,
          table_ids=["data-proj.demo_ds.sensitive_customers"],
          regions=["us"],
      )

  # If BigQuery `tables.patch` returns HTTP 200 after clearing Policy Tags while
  # silently dropping `dataGovernanceTagsInfo` (e.g., unsupported federated
  # table format), `swap_table_schema` must restore `original_fields` and return
  # `FAILED`.
  def test_swap_table_schema_restores_tags_and_fails_when_patch_drops_dgt(self):
    """Restores original Policy Tags when `update_table` drops target DGTs."""
    self._configure_matching_live_v2_policies()
    original_fields = [_make_sample_table_schema_fields()[2]]  # ssn_hash
    table = self._make_mock_table(original_fields)
    self.mock_bigquery_client.get_table.return_value = table
    patch_payloads: list[list[dict[str, object]]] = []

    def dropping_update_table(tbl, *_args, **_kwargs):
      sent_fields = copy.deepcopy(tbl._properties["schema"]["fields"])
      patch_payloads.append(sent_fields)
      if len(patch_payloads) == 1:
        # Simulate server clearing `policyTags` while dropping DGTs.
        stripped = copy.deepcopy(sent_fields)
        stripped[0].pop("dataGovernanceTagsInfo", None)
        return self._make_mock_table(stripped)
      return tbl

    self.mock_bigquery_client.update_table.side_effect = dropping_update_table

    # Execute `swap_table_schema`; Step 6 must detect the missing DGT on the
    # returned table and issue a compensating `update_table` restoring the PT.
    result = self.swapper.swap_table_schema(
        "data-proj", "demo_ds", "iceberg_customers", self.plan
    )

    self.assertEqual(result.status, constants.SWAP_STATUS_FAILED)
    self.assertIn("Post-patch schema verification failed", result.error_message)
    self.assertIn(
        "(key='target-dgt-proj/manual_migration_taxonomy',"
        " value='target-dgt-proj/manual_migration_taxonomy/Sha256_Mask_Root')",
        result.error_message,
    )
    self.assertIn(
        "Automatically restored original column tags", result.error_message
    )
    self.assertEqual(len(patch_payloads), 2)
    self.assertEqual(
        patch_payloads[1][0]["policyTags"],
        original_fields[0]["policyTags"],
    )

  # Credential errors during REST `GET /v2/{name}` grantee lookup must record
  # `_grantee_fetch_errors` on every policy rather than treating unknown
  # grantees as empty.
  def test_verify_enforcement_parity_blocks_on_rest_credential_error(self):
    """Blocks parity check when ADC credential lookup fails for REST GET."""
    self._configure_matching_live_v2_policies()
    self.mock_auth_default.side_effect = (
        google.auth.exceptions.DefaultCredentialsError("ADC unavailable")
    )
    fields = [_make_sample_table_schema_fields()[3]]  # credit_card (Raw_Root)
    _, swapped_columns, _ = self.swapper.transform_schema_fields(
        fields, self.plan
    )

    discrepancies = self.swapper.verify_enforcement_parity(
        swapped_columns=swapped_columns,
        plan=self.plan,
        table_project_id="data-proj",
        table_location="us",
    )

    self.assertTrue(
        any(
            item.risk_category == constants.PARITY_RISK_RESOURCE_DISCREPANCY
            and "Failed to verify grantees via REST" in item.description
            for item in discrepancies
        )
    )

  # A non-`_default_deny` policy planned in `plan.json` with `grantees: []`
  # (e.g., re-planned to zero readers) must still fetch `GET /v2/{name}` so
  # stale grantees on an existing live policy are caught as leakage.
  def test_verify_enforcement_parity_hydrates_planned_empty_non_default_deny(
      self,
  ):
    """Fetches grantees via REST GET for planned-empty non-default-deny IDs."""
    dg_key = "target-dgt-proj/manual_migration_taxonomy"
    replanned_plan = copy.deepcopy(self.plan)
    # Re-plan `migrated_raw_raw_root` to `grantees: []` while the live server
    # policy still retains `stale_reader@example.com`.
    for item in replanned_plan["phase_2_resource_manifest"][
        "create_data_policies_v2"
    ]:
      if item["policy_id"] == "migrated_raw_raw_root":
        item["grantees"] = []

    self.mock_data_policy_v2_client.list_data_policies.return_value = [
        _make_mock_v2_policy(
            policy_id="migrated_raw_raw_root",
            policy_type=constants.DATA_POLICY_TYPE_RAW,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Raw_Root",
            grantees=["user:stale_reader@example.com"],
        )
    ]
    fields = [_make_sample_table_schema_fields()[3]]  # credit_card
    _, swapped_columns, _ = self.swapper.transform_schema_fields(
        fields, replanned_plan
    )

    discrepancies = self.swapper.verify_enforcement_parity(
        swapped_columns=swapped_columns,
        plan=replanned_plan,
        table_project_id="data-proj",
        table_location="us",
    )

    self.assertEqual(len(discrepancies), 1)
    self.assertEqual(
        discrepancies[0].risk_category, constants.PARITY_RISK_ACCESS_LEAKAGE
    )
    self.assertIn("user:stale_reader@example.com", discrepancies[0].description)

  # Mode 1 (`DEFAULT_DATA_POLICY_PROJECT`) must verify that the central project
  # is registered in `INFORMATION_SCHEMA.EFFECTIVE_PROJECT_OPTIONS` unless
  # `skip_default_dp_org_check=True` is set.
  def test_verify_enforcement_parity_mode1_checks_effective_project_options(
      self,
  ):
    """Verifies Mode 1 org `default_data_policy_projects` and skip override."""
    mode1_plan = copy.deepcopy(self.plan)
    mode1_plan["metadata"][
        "target_data_policy_mode"
    ] = constants.TARGET_DATA_POLICY_MODE_DEFAULT_PROJECT
    mode1_plan["metadata"]["target_data_policy_project_ids"] = [
        "central-dp-proj"
    ]
    for item in mode1_plan["phase_2_resource_manifest"][
        "create_data_policies_v2"
    ]:
      item["target_project_id"] = "central-dp-proj"

    dg_key = "target-dgt-proj/manual_migration_taxonomy"
    central_policies = [
        _make_mock_v2_policy(
            policy_id="migrated_raw_deny_default_root_default_deny",
            policy_type=constants.DATA_POLICY_TYPE_RAW,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Deny_Default_Root",
            grantees=[],
        )
    ]

    def list_policies_side_effect(parent: str):
      if parent == "projects/central-dp-proj/locations/us":
        return central_policies
      return []

    self.mock_data_policy_v2_client.list_data_policies.side_effect = (
        list_policies_side_effect
    )
    fields = [_make_sample_table_schema_fields()[4]]  # secret_notes
    _, swapped_columns, _ = self.swapper.transform_schema_fields(
        fields, mode1_plan
    )

    # Unregistered central project (`[]` in EFFECTIVE_PROJECT_OPTIONS) blocks
    # with ACCESS_LEAKAGE_RISK.
    self.mock_bigquery_client.query.return_value = types.SimpleNamespace(
        result=lambda: []
    )
    missing_org_discrepancies = self.swapper.verify_enforcement_parity(
        swapped_columns=swapped_columns,
        plan=mode1_plan,
        table_project_id="data-proj",
        table_location="us",
    )
    self.assertEqual(len(missing_org_discrepancies), 1)
    self.assertEqual(
        missing_org_discrepancies[0].risk_category,
        constants.PARITY_RISK_ACCESS_LEAKAGE,
    )
    self.assertIn("central-dp-proj", missing_org_discrepancies[0].description)

    # `skip_default_dp_org_check=True` bypasses `EFFECTIVE_PROJECT_OPTIONS` when
    # the operator verified Organization configuration manually.
    skip_org_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        skip_default_dp_org_check=True,
    )
    self.assertEqual(
        skip_org_swapper.verify_enforcement_parity(
            swapped_columns=swapped_columns,
            plan=mode1_plan,
            table_project_id="data-proj",
            table_location="us",
        ),
        [],
    )

    # Registered `[central-dp-proj]` in EFFECTIVE_PROJECT_OPTIONS passes.
    registered_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
    )
    self.mock_bigquery_client.query.return_value = types.SimpleNamespace(
        result=lambda: [
            types.SimpleNamespace(option_value="[central-dp-proj, other-proj]")
        ]
    )
    self.assertEqual(
        registered_swapper.verify_enforcement_parity(
            swapped_columns=swapped_columns,
            plan=mode1_plan,
            table_project_id="data-proj",
            table_location="us",
        ),
        [],
    )

  # Mode 1 must also inspect `table_project_id` and block if a conflicting V2
  # Data Policy in the table project would override the central project.
  def test_verify_enforcement_parity_mode1_blocks_table_project_policy(self):
    """Flags conflicting V2 Data Policies in `table_project_id` under Mode 1."""
    mode1_plan = copy.deepcopy(self.plan)
    mode1_plan["metadata"][
        "target_data_policy_mode"
    ] = constants.TARGET_DATA_POLICY_MODE_DEFAULT_PROJECT
    mode1_plan["metadata"]["target_data_policy_project_ids"] = [
        "central-dp-proj"
    ]
    for item in mode1_plan["phase_2_resource_manifest"][
        "create_data_policies_v2"
    ]:
      item["target_project_id"] = "central-dp-proj"

    dg_key = "target-dgt-proj/manual_migration_taxonomy"
    central_policy = _make_mock_v2_policy(
        policy_id="migrated_raw_deny_default_root_default_deny",
        policy_type=constants.DATA_POLICY_TYPE_RAW,
        dg_tag_key=dg_key,
        dg_tag_value=f"{dg_key}/Deny_Default_Root",
        grantees=[],
    )
    shadow_table_policy = _make_mock_v2_policy(
        policy_id="shadow_table_raw_policy",
        policy_type=constants.DATA_POLICY_TYPE_RAW,
        dg_tag_key=dg_key,
        dg_tag_value=f"{dg_key}/Deny_Default_Root",
        grantees=["user:override_reader@example.com"],
    )
    self._rest_grantees_override["shadow_table_raw_policy"] = [
        "user:override_reader@example.com"
    ]

    def list_policies_side_effect(parent: str):
      if parent == "projects/central-dp-proj/locations/us":
        return [central_policy]
      if parent == "projects/data-proj/locations/us":
        return [shadow_table_policy]
      return []

    self.mock_data_policy_v2_client.list_data_policies.side_effect = (
        list_policies_side_effect
    )
    self.mock_bigquery_client.query.return_value = types.SimpleNamespace(
        result=lambda: [types.SimpleNamespace(option_value="[central-dp-proj]")]
    )
    fields = [_make_sample_table_schema_fields()[4]]  # secret_notes
    _, swapped_columns, _ = self.swapper.transform_schema_fields(
        fields, mode1_plan
    )

    discrepancies = self.swapper.verify_enforcement_parity(
        swapped_columns=swapped_columns,
        plan=mode1_plan,
        table_project_id="data-proj",
        table_location="us",
    )

    self.assertEqual(len(discrepancies), 1)
    self.assertEqual(
        discrepancies[0].risk_category, constants.PARITY_RISK_ACCESS_LEAKAGE
    )
    self.assertIn("shadow_table_raw_policy", discrepancies[0].description)

  # Unmasked child tags under a masked parent tag inherit the parent's planned
  # masking policy in both Policy Tags and DGT without false leakage errors.
  def test_verify_enforcement_parity_passes_unmasked_child_under_masked_parent(
      self,
  ):
    """Allows planned ancestor masking policy on an unmasked child Tag Value."""
    dg_key = "target-dgt-proj/manual_migration_taxonomy"
    masked_parent_plan = copy.deepcopy(self.plan)
    masked_parent_plan["phase_2_resource_manifest"][
        "create_data_policies_v2"
    ].append({
        "action": constants.ACTION_CREATE_DATA_POLICY_V2,
        "target_project_id": "data-proj",
        "region": "us",
        "policy_id": "migrated_masking_raw_root_mask",
        "policy_origin": constants.POLICY_ORIGIN_MIGRATED_V1,
        "grantees": ["user:masked_reader@example.com"],
        "api_payload": {
            "data_policy_id": "migrated_masking_raw_root_mask",
            "data_policy_type": constants.DATA_POLICY_TYPE_MASKING,
            "data_governance_tag": {
                "key": dg_key,
                "value": f"{dg_key}/Raw_Root",
            },
            "data_masking_policy": {
                "predefined_expression": "DEFAULT_MASKING_VALUE",
            },
        },
    })
    self.mock_data_policy_v2_client.list_data_policies.return_value = [
        _make_mock_v2_policy(
            policy_id="migrated_raw_raw_root",
            policy_type=constants.DATA_POLICY_TYPE_RAW,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Raw_Root",
            grantees=["user:raw_reader@example.com"],
        ),
        _make_mock_v2_policy(
            policy_id="migrated_masking_raw_root_mask",
            policy_type=constants.DATA_POLICY_TYPE_MASKING,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Raw_Root",
            grantees=["user:masked_reader@example.com"],
            predefined_expression="DEFAULT_MASKING_VALUE",
        ),
        _make_mock_v2_policy(
            policy_id="migrated_raw_raw_child_default_deny",
            policy_type=constants.DATA_POLICY_TYPE_RAW,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Raw_Child",
            grantees=[],
        ),
    ]
    child_schema = [{
        "name": "child_col",
        "type": "STRING",
        "policyTags": {
            "names": [
                "projects/source-proj/locations/us/"
                "taxonomies/100/policyTags/205"
            ]
        },
    }]
    _, swapped_columns, _ = self.swapper.transform_schema_fields(
        child_schema, masked_parent_plan
    )

    discrepancies = self.swapper.verify_enforcement_parity(
        swapped_columns=swapped_columns,
        plan=masked_parent_plan,
        table_project_id="data-proj",
        table_location="us",
    )

    self.assertEqual(discrepancies, [])

  # When a masked child tag has a planned direct `RAW_DATA_ACCESS_POLICY` (from
  # copied taxonomy-level readers), omitting that child raw policy in GCP must
  # flag `ACCESS_BLOCKAGE_RISK` even when the Root Tag Value still grants it.
  def test_verify_parity_blocks_masked_child_missing_copied_taxonomy_raw_grant(
      self,
  ):
    """Flags missing direct raw policy on masked child despite root grant."""
    dg_key = "target-dgt-proj/manual_migration_taxonomy"
    child_masked_plan = copy.deepcopy(self.plan)
    child_masked_plan["phase_2_resource_manifest"][
        "create_data_policies_v2"
    ].extend([
        {
            "action": constants.ACTION_CREATE_DATA_POLICY_V2,
            "target_project_id": "data-proj",
            "region": "us",
            "policy_id": "migrated_raw_raw_child",
            "policy_origin": constants.POLICY_ORIGIN_SYNTHETIC_RAW_READER,
            "grantees": ["user:raw_reader@example.com"],
            "api_payload": {
                "data_policy_id": "migrated_raw_raw_child",
                "data_policy_type": constants.DATA_POLICY_TYPE_RAW,
                "data_governance_tag": {
                    "key": dg_key,
                    "value": f"{dg_key}/Raw_Child",
                },
            },
        },
        {
            "action": constants.ACTION_CREATE_DATA_POLICY_V2,
            "target_project_id": "data-proj",
            "region": "us",
            "policy_id": "migrated_masking_raw_child_mask",
            "policy_origin": constants.POLICY_ORIGIN_MIGRATED_V1,
            "grantees": ["user:raw_reader@example.com"],
            "api_payload": {
                "data_policy_id": "migrated_masking_raw_child_mask",
                "data_policy_type": constants.DATA_POLICY_TYPE_MASKING,
                "data_governance_tag": {
                    "key": dg_key,
                    "value": f"{dg_key}/Raw_Child",
                },
                "data_masking_policy": {"predefined_expression": "EMAIL_MASK"},
            },
        },
    ])
    # Live GCP has Root raw policy + Child masking + Child default-deny, but is
    # missing `migrated_raw_raw_child` at depth 2.
    self.mock_data_policy_v2_client.list_data_policies.return_value = [
        _make_mock_v2_policy(
            policy_id="migrated_raw_raw_root",
            policy_type=constants.DATA_POLICY_TYPE_RAW,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Raw_Root",
            grantees=["user:raw_reader@example.com"],
        ),
        _make_mock_v2_policy(
            policy_id="migrated_masking_raw_child_mask",
            policy_type=constants.DATA_POLICY_TYPE_MASKING,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Raw_Child",
            grantees=["user:raw_reader@example.com"],
            predefined_expression="EMAIL_MASK",
        ),
        _make_mock_v2_policy(
            policy_id="migrated_raw_raw_child_default_deny",
            policy_type=constants.DATA_POLICY_TYPE_RAW,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Raw_Child",
            grantees=[],
        ),
    ]
    child_schema = [{
        "name": "child_col",
        "type": "STRING",
        "policyTags": {
            "names": [
                "projects/source-proj/locations/us/"
                "taxonomies/100/policyTags/205"
            ]
        },
    }]
    _, swapped_columns, _ = self.swapper.transform_schema_fields(
        child_schema, child_masked_plan
    )

    discrepancies = self.swapper.verify_enforcement_parity(
        swapped_columns=swapped_columns,
        plan=child_masked_plan,
        table_project_id="data-proj",
        table_location="us",
    )

    self.assertEqual(len(discrepancies), 1)
    self.assertEqual(
        discrepancies[0].risk_category, constants.PARITY_RISK_ACCESS_BLOCKAGE
    )
    self.assertIn("deepest matching tag", discrepancies[0].description)

  # Forward schema backups must inject empty `dataGovernanceTagsInfo` strictly
  # onto swapped leaf columns so `bq update` clears newly attached DGTs without
  # touching unmapped columns, pre-existing unrelated DGTs, or RECORD fields.
  def test_forward_backup_injects_empty_dgt_only_on_swapped_leaf_columns(self):
    """Writes restore-ready empty DGT map only on swapped forward leaf cols."""
    self._configure_matching_live_v2_policies()
    # Mix mapped top-level and nested RECORD leaf PTs with an unmapped PT, an
    # unrelated pre-existing DGT column, and an untagged column.
    mixed_fields = [
        {
            "name": "email",
            "type": "STRING",
            "policyTags": {
                "names": [
                    "projects/source-proj/locations/us/"
                    "taxonomies/100/policyTags/201"
                ]
            },
        },
        {
            "name": "profile",
            "type": "RECORD",
            "fields": [
                {
                    "name": "ssn",
                    "type": "STRING",
                    "policyTags": {
                        "names": [
                            "projects/source-proj/locations/us/"
                            "taxonomies/100/policyTags/202"
                        ]
                    },
                },
                {"name": "bio", "type": "STRING"},
            ],
        },
        {
            "name": "legacy_unmapped",
            "type": "STRING",
            "policyTags": {
                "names": [
                    "projects/other-proj/locations/us/"
                    "taxonomies/888/policyTags/801"
                ]
            },
        },
        {
            "name": "existing_dgt_col",
            "type": "STRING",
            "dataGovernanceTagsInfo": {
                "dataGovernanceTags": {"other-proj/other_key": "Keep_Value"}
            },
        },
        {"name": "plain_col", "type": "INTEGER"},
    ]
    table = self._make_mock_table(mixed_fields)
    self.mock_bigquery_client.get_table.return_value = table

    # Execute forward swap so Step 5 writes the `pt_to_dgt` schema backup file.
    result = self.swapper.swap_table_schema(
        "data-proj", "demo_ds", "mixed_customers", self.plan
    )

    self.assertEqual(result.status, constants.SWAP_STATUS_SWAPPED)
    assert result.backup_file_path is not None
    with open(result.backup_file_path, "r", encoding="utf-8") as backup_file:
      saved_backup = json.load(backup_file)

    # Swapped top-level and nested leaf columns carry explicit empty DGT maps
    # alongside their original Policy Tags for `bq update` exclusivity safety.
    self.assertEqual(
        saved_backup[0]["dataGovernanceTagsInfo"], {"dataGovernanceTags": {}}
    )
    self.assertEqual(
        saved_backup[0]["policyTags"], mixed_fields[0]["policyTags"]
    )
    self.assertEqual(
        saved_backup[1]["fields"][0]["dataGovernanceTagsInfo"],
        {"dataGovernanceTags": {}},
    )
    # Parent RECORD container, untagged fields, unmapped PT, and unrelated DGT
    # column remain completely untouched.
    self.assertNotIn("dataGovernanceTagsInfo", saved_backup[1])
    self.assertNotIn("dataGovernanceTagsInfo", saved_backup[1]["fields"][1])
    self.assertNotIn("dataGovernanceTagsInfo", saved_backup[2])
    self.assertEqual(
        saved_backup[3]["dataGovernanceTagsInfo"],
        {"dataGovernanceTags": {"other-proj/other_key": "Keep_Value"}},
    )
    self.assertNotIn("dataGovernanceTagsInfo", saved_backup[4])

  # Pre-rollback `dgt_to_pt` backups must symmetrically inject empty
  # `policyTags` onto swapped leaf columns because BigQuery omits `policyTags`
  # on DGT-only schemas and `bq update` otherwise keeps restored Policy Tags.
  def test_rollback_backup_injects_empty_policy_tags_on_swapped_leaf_columns(
      self,
  ):
    """Writes restore-ready empty policyTags only on swapped rollback cols."""
    dg_key = "target-dgt-proj/manual_migration_taxonomy"
    # Simulate live BigQuery wire state where `policyTags` is omitted on DGT
    # columns before `dgt-to-pt` rollback runs.
    dgt_wire_fields = [
        {
            "name": "email",
            "type": "STRING",
            "dataGovernanceTagsInfo": {
                "dataGovernanceTags": {dg_key: f"{dg_key}/Email_Mask_Root"}
            },
        },
        {
            "name": "profile",
            "type": "RECORD",
            "fields": [
                {
                    "name": "ssn",
                    "type": "STRING",
                    "dataGovernanceTagsInfo": {
                        "dataGovernanceTags": {
                            dg_key: f"{dg_key}/Sha256_Mask_Root"
                        }
                    },
                },
                {"name": "bio", "type": "STRING"},
            ],
        },
        {
            "name": "unmapped_dgt_col",
            "type": "STRING",
            "dataGovernanceTagsInfo": {
                "dataGovernanceTags": {"other-proj/other_key": "Keep_Value"}
            },
        },
    ]
    table = self._make_mock_table(dgt_wire_fields)
    self.mock_bigquery_client.get_table.return_value = table
    rollback_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        backup_dir=self.temp_dir.name,
        skip_confirmation=True,
        swap_mode=constants.SWAP_MODE_DGT_TO_PT,
    )

    # Execute `dgt-to-pt` rollback so Step 5 writes the `dgt_to_pt` backup.
    result = rollback_swapper.swap_table_schema(
        "data-proj", "demo_ds", "dgt_customers", self.plan
    )

    self.assertEqual(result.status, constants.SWAP_STATUS_SWAPPED)
    assert result.backup_file_path is not None
    with open(result.backup_file_path, "r", encoding="utf-8") as backup_file:
      saved_backup = json.load(backup_file)

    # Swapped leaf columns carry explicit empty `policyTags` while unmapped DGT,
    # untagged leaf, and RECORD container fields stay unchanged.
    self.assertEqual(saved_backup[0]["policyTags"], {"names": []})
    self.assertEqual(
        saved_backup[0]["dataGovernanceTagsInfo"],
        dgt_wire_fields[0]["dataGovernanceTagsInfo"],
    )
    self.assertEqual(saved_backup[1]["fields"][0]["policyTags"], {"names": []})
    self.assertNotIn("policyTags", saved_backup[1])
    self.assertNotIn("policyTags", saved_backup[1]["fields"][1])
    self.assertNotIn("policyTags", saved_backup[2])

  # If `tables.patch` attaches a DGT on one column while dropping the DGT on a
  # sibling column, Step 6 compensating restore must clear the partial DGT on
  # the first column while restoring Policy Tags on both columns.
  def test_compensating_restore_clears_partial_dgt_when_sibling_drops_tag(self):
    """Clears partially persisted DGTs during Step 6 compensating restore."""
    self._configure_matching_live_v2_policies()
    sample = _make_sample_table_schema_fields()
    two_col_fields = [sample[2], sample[3]]  # ssn_hash, credit_card
    table = self._make_mock_table(two_col_fields)
    self.mock_bigquery_client.get_table.return_value = table
    patch_payloads: list[list[dict[str, object]]] = []

    def partial_drop_update_table(tbl, *_args, **_kwargs):
      sent_fields = copy.deepcopy(tbl._properties["schema"]["fields"])
      patch_payloads.append(sent_fields)
      if len(patch_payloads) == 1:
        # Simulate column 0 keeping its new DGT while column 1 drops its DGT.
        partial = copy.deepcopy(sent_fields)
        partial[1].pop("dataGovernanceTagsInfo", None)
        return self._make_mock_table(partial)
      return tbl

    self.mock_bigquery_client.update_table.side_effect = (
        partial_drop_update_table
    )

    # Execute `swap_table_schema` so partial post-patch mismatch triggers
    # compensating `update_table`.
    result = self.swapper.swap_table_schema(
        "data-proj", "demo_ds", "partial_drop_table", self.plan
    )

    self.assertEqual(result.status, constants.SWAP_STATUS_FAILED)
    self.assertEqual(len(patch_payloads), 2)
    # Column 0 retained a live DGT on the server response, so compensating
    # restore explicitly clears `dataGovernanceTagsInfo` on column 0 while
    # omitting `dataGovernanceTagsInfo` on column 1 where no DGT persisted.
    self.assertEqual(
        patch_payloads[1][0]["dataGovernanceTagsInfo"],
        {"dataGovernanceTags": {}},
    )
    self.assertEqual(
        patch_payloads[1][0]["policyTags"], two_col_fields[0]["policyTags"]
    )
    self.assertNotIn("dataGovernanceTagsInfo", patch_payloads[1][1])
    self.assertEqual(
        patch_payloads[1][1]["policyTags"], two_col_fields[1]["policyTags"]
    )

  # BigQuery Omni (`aws-*`, `azure-*`) tables carrying mapped Policy Tags must
  # abort with SWAP_STATUS_ABORTED_SCHEMA_CORRUPTION in both dry-run and live
  # modes, whereas untagged Omni tables skip with SKIPPED_NO_POLICY_TAGS.
  def test_swap_table_schema_aborts_bigquery_omni_tables_with_mapped_tags(self):
    for omni_location in ("aws-us-east-1", "azure-eastus2"):
      for dry_run_flag in (True, False):
        with self.subTest(location=omni_location, dry_run=dry_run_flag):
          omni_swapper = swapper.Swapper(
              bigquery_client=self.mock_bigquery_client,
              dg_tag_keys_client=self.mock_tag_keys_client,
              dg_tag_values_client=self.mock_tag_values_client,
              data_policy_v2_client=self.mock_data_policy_v2_client,
              resourcemanager_client=self.mock_projects_client,
              backup_dir=self.temp_dir.name,
              dry_run=dry_run_flag,
              skip_confirmation=True,
          )
          omni_table = self._make_mock_table(
              _make_sample_table_schema_fields(), location=omni_location
          )
          self.mock_bigquery_client.get_table.return_value = omni_table

          # Execute swap_table_schema on the PT-tagged BigQuery Omni table.
          result = omni_swapper.swap_table_schema(
              "data-proj", "omni_ds", "omni_customers", self.plan
          )

          # Confirm the table aborts fail-closed without calling update_table.
          self.assertEqual(
              result.status, constants.SWAP_STATUS_ABORTED_SCHEMA_CORRUPTION
          )
          self.assertIn(omni_location, result.error_message)
          self.assertIn(
              "Data governance tags cannot be attached in BigQuery Omni.",
              result.error_message,
          )
          self.mock_bigquery_client.update_table.assert_not_called()

    # Untagged Omni tables skip cleanly without raising a corruption alarm.
    untagged_omni_table = self._make_mock_table(
        [{"name": "id", "type": "INTEGER"}], location="aws-us-east-1"
    )
    self.mock_bigquery_client.get_table.return_value = untagged_omni_table
    untagged_result = self.swapper.swap_table_schema(
        "data-proj", "omni_ds", "untagged_omni", self.plan
    )
    self.assertEqual(
        untagged_result.status, constants.SWAP_STATUS_SKIPPED_NO_POLICY_TAGS
    )

  # Non-leaf RECORD or STRUCT parent columns carrying mapped Policy Tags cannot
  # accept Data Governance Tags and must raise SchemaCorruptionError.
  def test_transform_schema_fields_rejects_non_leaf_record_policy_tag(self):
    mapped_policy_tag = (
        "projects/source-proj/locations/us/taxonomies/100/policyTags/201"
    )
    for record_type in ("RECORD", "STRUCT"):
      with self.subTest(field_type=record_type):
        non_leaf_fields = [{
            "name": "customer_profile",
            "type": record_type,
            "policyTags": {"names": [mapped_policy_tag]},
            "fields": [{"name": "email", "type": "STRING"}],
        }]
        with self.assertRaisesRegex(
            swapper.SchemaCorruptionError,
            "Column 'customer_profile'.*can only be attached to leaf columns",
        ):
          self.swapper.transform_schema_fields(non_leaf_fields, self.plan)

  # Columns carrying both a mapped Policy Tag and direct column-level Data
  # Policies (`dataPolicies`) must fail closed before mutating the schema.
  def test_transform_schema_fields_rejects_coexisting_direct_column_policies(
      self,
  ):
    mapped_policy_tag = (
        "projects/source-proj/locations/us/taxonomies/100/policyTags/201"
    )
    dual_governed_fields = [{
        "name": "email",
        "type": "STRING",
        "policyTags": {"names": [mapped_policy_tag]},
        "dataPolicies": [
            {"name": "projects/data-proj/locations/us/dataPolicies/col_mask"}
        ],
    }]

    with self.assertRaises(swapper.SchemaCorruptionError) as exc_context:
      self.swapper.transform_schema_fields(dual_governed_fields, self.plan)
    error_text = str(exc_context.exception)
    self.assertIn("Column 'email'", error_text)
    self.assertIn(
        "direct column-level Data Policy binding(s)"
        " ['projects/data-proj/locations/us/dataPolicies/col_mask']",
        error_text,
    )
    self.assertNotIn("{'name':", error_text)

  # `tables.patch` allows at most 1,000 unique Data Governance Tags per table,
  # while allowing > 1,000 columns when unique Data Governance Tags <= 1,000.
  def test_transform_schema_fields_rejects_exceeding_max_dg_tags_per_table(
      self,
  ):
    large_binding_map = {}
    for index in range(constants.MAX_DG_TAGS_PER_TABLE + 1):
      policy_tag_name = (
          f"projects/source-proj/locations/us/taxonomies/1/policyTags/{index}"
      )
      large_binding_map[policy_tag_name] = {
          "dg_tag_key": "target-dgt-proj/wide_taxonomy",
          "dg_tag_value": f"value_{index}",
          "dg_tag_value_namespaced_name": (
              f"target-dgt-proj/wide_taxonomy/value_{index}"
          ),
      }
    wide_plan = {
        "phase_3_binding_map": {
            "policy_tags_to_dg_tag_values": large_binding_map
        }
    }

    # 1,005 columns reusing a single unique Data Governance Tag stays within
    # BigQuery's 1,000-unique-tags-per-table limit on `tables.patch`.
    reused_tag_fields = [
        {
            "name": f"column_{index}",
            "type": "STRING",
            "policyTags": {
                "names": [
                    "projects/source-proj/locations/us/taxonomies/1/"
                    "policyTags/0"
                ]
            },
        }
        for index in range(constants.MAX_DG_TAGS_PER_TABLE + 5)
    ]
    _, reused_swapped, _ = self.swapper.transform_schema_fields(
        reused_tag_fields, wide_plan
    )
    self.assertEqual(len(reused_swapped), constants.MAX_DG_TAGS_PER_TABLE + 5)

    # 1,001 columns with 1,001 distinct Data Governance Tags exceeds the limit.
    excess_unique_fields = [
        {
            "name": f"column_{index}",
            "type": "STRING",
            "policyTags": {
                "names": [
                    "projects/source-proj/locations/us/taxonomies/1/"
                    f"policyTags/{index}"
                ]
            },
        }
        for index in range(constants.MAX_DG_TAGS_PER_TABLE + 1)
    ]
    with self.assertRaisesRegex(
        swapper.SchemaCorruptionError,
        "1001 unique Data Governance Tags after swapping",
    ):
      self.swapper.transform_schema_fields(excess_unique_fields, wide_plan)

  # Legacy top-level `field["dataGovernanceTags"]` schema payloads and numeric
  # `<project_number>/<short>` Tag Keys must roll back and match parity cleanly.
  def test_rollback_and_parity_support_legacy_field_dgt_and_numeric_key(self):
    self.mock_projects_client.get_project.return_value = types.SimpleNamespace(
        name="projects/777888999", project_id="target-dgt-proj"
    )
    rollback_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        resourcemanager_client=self.mock_projects_client,
        backup_dir=self.temp_dir.name,
        swap_mode=constants.SWAP_MODE_DGT_TO_PT,
        skip_confirmation=True,
    )
    legacy_fields = [{
        "name": "secret_notes",
        "type": "STRING",
        "dataGovernanceTags": [{
            "key": "777888999/manual_migration_taxonomy",
            "value": "777888999/manual_migration_taxonomy/Deny_Default_Root",
        }],
    }]

    updated_fields, swapped, _ = rollback_swapper.transform_schema_fields(
        legacy_fields, self.plan
    )
    rollback_swapper.verify_schema_swap_integrity(
        legacy_fields, updated_fields, swapped
    )
    self.assertEqual(len(swapped), 1)
    self.assertNotIn("dataGovernanceTags", updated_fields[0])
    self.assertEqual(
        updated_fields[0]["dataGovernanceTagsInfo"],
        {"dataGovernanceTags": {}},
    )

    # Confirm `_policy_matches_tag` also resolves `<project_number>/<short>`.
    live_numeric_policy = swapper.LiveDataPolicyV2Summary(
        name="projects/data-proj/locations/us/dataPolicies/pol_num",
        data_policy_id="pol_num",
        data_policy_type=constants.DATA_POLICY_TYPE_RAW,
        dg_tag_key="777888999/manual_migration_taxonomy",
        dg_tag_value="777888999/manual_migration_taxonomy/Deny_Default_Root",
        masking_expression=None,
        masking_routine=None,
        grantees=[],
    )
    self.assertTrue(
        self.swapper._policy_matches_tag(
            live_numeric_policy,
            "target-dgt-proj/manual_migration_taxonomy",
            "target-dgt-proj/manual_migration_taxonomy/Deny_Default_Root",
        )
    )

  # Federated external catalog (`externalCatalogTableOptions`) and BigLake
  # catalog (`catalog.namespace`) tables must abort forward `pt-to-dgt` swaps
  # before mutating schemas (`ABORTED_SCHEMA_CORRUPTION`).
  def test_swap_table_schema_aborts_external_catalog_table_in_forward_mode(
      self,
  ):
    self._configure_matching_live_v2_policies()
    catalog_table = self._make_mock_table(
        fields=_make_sample_table_schema_fields(), location="US"
    )
    catalog_table._properties["externalCatalogTableOptions"] = {
        "connectionId": "projects/p/locations/us/connections/c",
        "storageDescriptor": {"locationUri": "gs://bucket/iceberg"},
    }
    self.mock_bigquery_client.get_table.return_value = catalog_table

    result = self.swapper.swap_table_schema(
        project_id="data-proj",
        dataset_id="ds",
        table_id="iceberg_tbl",
        plan=self.plan,
    )

    self.assertEqual(
        result.status, constants.SWAP_STATUS_ABORTED_SCHEMA_CORRUPTION
    )
    self.assertIn("federated external catalog", result.error_message or "")
    self.mock_bigquery_client.update_table.assert_not_called()

  # `backup_table_schema` must reject pre-existing symlinks at the backup path.
  def test_backup_table_schema_rejects_symlink_target(self):
    backup_path = self.swapper._get_backup_file_path("data-proj", "ds", "tbl")
    os.makedirs(os.path.dirname(backup_path), exist_ok=True)
    target_file = os.path.join(self.temp_dir.name, "real_target.json")
    with open(target_file, "w", encoding="utf-8") as handle:
      handle.write("keep")
    os.symlink(target_file, backup_path)

    with self.assertRaisesRegex(
        OSError, f"Refusing to write schema backup to symlink '{backup_path}'"
    ):
      self.swapper.backup_table_schema(
          "data-proj", "ds", "tbl", [{"name": "c", "type": "STRING"}]
      )

  # Both `swap_schemas` and `swap_table_schema` reject unsupported
  # `metadata.schema_version` values before fetching or mutating tables.
  def test_swapper_entrypoints_reject_unsupported_plan_schema_version(self):
    future_plan = copy.deepcopy(self.plan)
    future_plan["metadata"]["schema_version"] = 2

    with self.assertRaisesRegex(
        ValueError,
        r"Unsupported migration plan schema_version=2.*schema_version=1",
    ):
      self.swapper.swap_schemas(
          plan=future_plan,
          table_ids=["data-proj.ds.tbl"],
          regions=["us"],
      )

    with self.assertRaisesRegex(
        ValueError,
        r"Unsupported migration plan schema_version=2.*schema_version=1",
    ):
      self.swapper.swap_table_schema("data-proj", "ds", "tbl", future_plan)

    self.mock_bigquery_client.get_table.assert_not_called()
    self.mock_bigquery_client.update_table.assert_not_called()

  # `Swapped Columns` and `Target DG Tag` cells render explicit `PT -> DGT` /
  # `DGT -> PT` transitions and `key` / `value` labels without `=` ambiguity.
  def test_generate_swap_report_renders_pt_dgt_transitions(self):
    """Renders `<br>`-separated PT <-> DGT transitions and `key`/`value`."""
    # Populate `source_display_path` (including a `|` character to verify
    # Markdown table-cell escaping) on the first planned Tag Value while leaving
    # the second planned Tag Value without `source_display_path` to exercise URI
    # fallback.
    plan_with_display_paths = copy.deepcopy(self.plan)
    dg_tag_key_name = "target-dgt-proj/manual_migration_taxonomy"
    email_policy_tag = (
        "projects/source-proj/locations/us/taxonomies/100/policyTags/201"
    )
    sha256_policy_tag = (
        "projects/source-proj/locations/us/taxonomies/100/policyTags/202"
    )
    plan_with_display_paths["phase_3_binding_map"][
        "policy_tags_to_dg_tag_values"
    ][email_policy_tag]["dg_tag_value"] = "Email_Mask_Root"
    plan_with_display_paths["phase_3_binding_map"][
        "policy_tags_to_dg_tag_values"
    ][sha256_policy_tag]["dg_tag_value"] = "Sha256_Mask_Root"
    plan_with_display_paths["phase_2_resource_manifest"][
        "create_dg_tag_values"
    ][0]["source_display_path"] = "Customer_PII | US > Email_Mask"

    two_column_policy_tag_fields = [
        _make_sample_table_schema_fields()[1],
        _make_sample_table_schema_fields()[2],
    ]
    dgt_fields, forward_swapped, _ = self.swapper.transform_schema_fields(
        two_column_policy_tag_fields, plan_with_display_paths
    )
    forward_result = swapper.TableSwapResult(
        project_id="data-proj",
        dataset_id="demo_ds",
        table_id="customers",
        status=constants.SWAP_STATUS_SWAPPED,
        swapped_columns=forward_swapped,
    )
    blocked_result = swapper.TableSwapResult(
        project_id="data-proj",
        dataset_id="demo_ds",
        table_id="blocked_customers",
        status=constants.SWAP_STATUS_BLOCKED_PARITY_DISCREPANCY,
        parity_discrepancies=[
            swapper.ParityDiscrepancy(
                field_path="contact_info.email",
                source_policy_tag=email_policy_tag,
                dg_tag_key=dg_tag_key_name,
                dg_tag_value="Email_Mask_Root",
                risk_category=constants.PARITY_RISK_ACCESS_LEAKAGE,
                description="Missing _default_deny safety-net policy.",
            )
        ],
    )

    # Render the forward `pt-to-dgt` swap report and verify both `Swapped
    # Columns` and `Pre-Swap Enforcement Parity Discrepancies`.
    forward_report = self.swapper.generate_swap_report(
        [forward_result, blocked_result]
    )

    expected_forward_swapped_cell = (
        "`contact_info.email`: PT `Customer_PII \\| US > Email_Mask` ->"
        f" DGT (key: `{dg_tag_key_name}`, value: `Email_Mask_Root`)"
        "<br>"
        f"`ssn_hash`: PT `{sha256_policy_tag}` ->"
        f" DGT (key: `{dg_tag_key_name}`, value: `Sha256_Mask_Root`)"
    )
    self.assertIn(expected_forward_swapped_cell, forward_report)
    self.assertIn(
        f"| key: `{dg_tag_key_name}`, value: `Email_Mask_Root` |",
        forward_report,
    )
    self.assertNotIn(f"{dg_tag_key_name}=", forward_report)
    self.assertNotIn(f"`{dg_tag_key_name}`=", forward_report)

    # Transform the DGT schema back to Policy Tags in `dgt-to-pt` rollback mode
    # and verify symmetric `DGT (...) -> PT ...` rendering.
    rollback_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        swap_mode=constants.SWAP_MODE_DGT_TO_PT,
    )
    _, rollback_swapped, _ = rollback_swapper.transform_schema_fields(
        dgt_fields, plan_with_display_paths
    )
    rollback_result = swapper.TableSwapResult(
        project_id="data-proj",
        dataset_id="demo_ds",
        table_id="customers",
        status=constants.SWAP_STATUS_SWAPPED,
        swapped_columns=rollback_swapped,
    )
    rollback_report = rollback_swapper.generate_swap_report([rollback_result])

    expected_rollback_swapped_cell = (
        f"`contact_info.email`: DGT (key: `{dg_tag_key_name}`,"
        " value: `Email_Mask_Root`) -> PT `Customer_PII \\| US > Email_Mask`"
        "<br>"
        f"`ssn_hash`: DGT (key: `{dg_tag_key_name}`,"
        f" value: `Sha256_Mask_Root`) -> PT `{sha256_policy_tag}`"
    )
    self.assertIn(expected_rollback_swapped_cell, rollback_report)
    self.assertNotIn(f"{dg_tag_key_name}=", rollback_report)
    self.assertNotIn(f"`{dg_tag_key_name}`=", rollback_report)

  # When `main.py` aliases `bigquery_datapolicies_v2` to V1, V1
  # `ListDataPolicies` omits DGT-backed V2 policies and can return `[]`;
  # `_list_live_v2_data_policies` must still query `_list_data_policies_v2_rest`
  # so hidden live V2 policies cannot bypass parity checks.
  def test_v1_aliased_client_empty_list_falls_back_to_v2_rest(self):
    v1_client_cls = type(
        "_FakeV1DataPolicyServiceClient",
        (),
        {
            "__module__": (
                "google.cloud.bigquery_datapolicies_v1.services"
                ".data_policy_service.client"
            ),
            "list_data_policies": staticmethod(lambda parent: []),
        },
    )
    v1_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=v1_client_cls(),
        resourcemanager_client=self.mock_projects_client,
        backup_dir=self.temp_dir.name,
        skip_confirmation=True,
    )
    # Inspect only the Classification-Only column (`public_note` ->
    # `Public_Info`), which requires zero live V2 Data Policies; an aliased V1
    # client returning `[]` would falsely pass if REST `/v2/` were skipped.
    classification_only_fields = [{
        "name": "public_note",
        "type": "STRING",
        "policyTags": {
            "names": [
                "projects/source-proj/locations/us/"
                "taxonomies/999/policyTags/901"
            ]
        },
    }]
    _, swapped_columns, _ = v1_swapper.transform_schema_fields(
        classification_only_fields, self.plan
    )
    hidden_v2_policy = {
        "name": "projects/data-proj/locations/us/dataPolicies/hidden_dgt_deny",
        "dataPolicyId": "hidden_dgt_deny",
        "dataPolicyType": constants.DATA_POLICY_TYPE_RAW,
        "dataGovernanceTag": {
            "key": "target-dgt-proj/classification_only_taxonomy",
            "value": "Public_Info",
        },
        "grantees": [],
    }

    with mock.patch.object(
        v1_swapper,
        "_list_data_policies_v2_rest",
        return_value=[hidden_v2_policy],
    ) as mock_rest_list:
      discrepancies = v1_swapper.verify_enforcement_parity(
          swapped_columns=swapped_columns,
          plan=self.plan,
          table_project_id="data-proj",
          table_location="us",
      )

    # Confirm REST `/v2/` ran despite the empty V1 SDK list and caught the
    # unexpected live V2 policy on `Public_Info`.
    mock_rest_list.assert_called_once_with("data-proj", "us")
    self.assertEqual(len(discrepancies), 1)
    self.assertEqual(
        discrepancies[0].risk_category,
        constants.PARITY_RISK_ACCESS_BLOCKAGE,
    )
    self.assertIn("hidden_dgt_deny", discrepancies[0].description)

  # An empty `data_masking_policy: {}` in `plan.json` must fail closed in
  # `_masking_rule_matches` rather than matching arbitrary live masking rules.
  def test_verify_parity_unspecified_planned_masking_rule_fails_closed(self):
    self._configure_matching_live_v2_policies()
    plan_with_empty_masking = copy.deepcopy(self.plan)
    email_mask_action = plan_with_empty_masking["phase_2_resource_manifest"][
        "create_data_policies_v2"
    ][0]
    email_mask_action["api_payload"]["data_masking_policy"] = {}

    email_only_fields = [_make_sample_table_schema_fields()[1]]
    _, swapped_columns, _ = self.swapper.transform_schema_fields(
        email_only_fields, plan_with_empty_masking
    )

    # Execute parity verification against live `EMAIL_MASK`; unspecified
    # planned rule must report `<unspecified>` mismatch instead of matching.
    discrepancies = self.swapper.verify_enforcement_parity(
        swapped_columns=swapped_columns,
        plan=plan_with_empty_masking,
        table_project_id="data-proj",
        table_location="us",
    )

    descriptions = " | ".join(item.description for item in discrepancies)
    self.assertIn("expected masking rule '<unspecified>'", descriptions)
    self.assertIn("EMAIL_MASK", descriptions)

  # BigQuery groups matching DGT policies by tag depth first (`max_depth` wins)
  # before breaking `RAW > MASKING` ties. Per-depth raw grantee comparison must
  # catch both out-of-band raw tampering on a masked child's `_default_deny`
  # policy (`ACCESS_LEAKAGE_RISK`) and upward raw-grant shifts above a masked
  # intermediate tag (`ACCESS_BLOCKAGE_RISK`).
  def test_verify_parity_per_depth_raw_grantees_catches_depth_shifts(self):
    dg_key = "target-dgt-proj/manual_migration_taxonomy"
    # Subcase A: `Raw_Root` grants Policy-Tag-level raw access to `raw_reader`,
    # while child `Raw_Child` masks `raw_reader` (`EMAIL_MASK`) with empty
    # `_default_deny` (`planned_raw_by_ancestor[Raw_Child] == set()`). Tampering
    # with `Raw_Child`'s `_default_deny` to add `raw_reader` leaks raw data.
    masked_child_plan = copy.deepcopy(self.plan)
    masked_child_plan["phase_2_resource_manifest"][
        "create_data_policies_v2"
    ].append({
        "action": constants.ACTION_CREATE_DATA_POLICY_V2,
        "target_project_id": "data-proj",
        "region": "us",
        "policy_id": "migrated_masking_raw_child_mask",
        "policy_origin": constants.POLICY_ORIGIN_MIGRATED_V1,
        "grantees": ["user:raw_reader@example.com"],
        "api_payload": {
            "data_policy_id": "migrated_masking_raw_child_mask",
            "data_policy_type": constants.DATA_POLICY_TYPE_MASKING,
            "data_governance_tag": {
                "key": dg_key,
                "value": f"{dg_key}/Raw_Child",
            },
            "data_masking_policy": {"predefined_expression": "EMAIL_MASK"},
        },
    })
    self.mock_data_policy_v2_client.list_data_policies.return_value = [
        _make_mock_v2_policy(
            policy_id="migrated_raw_raw_root",
            policy_type=constants.DATA_POLICY_TYPE_RAW,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Raw_Root",
            grantees=["user:raw_reader@example.com"],
        ),
        _make_mock_v2_policy(
            policy_id="migrated_masking_raw_child_mask",
            policy_type=constants.DATA_POLICY_TYPE_MASKING,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Raw_Child",
            grantees=["user:raw_reader@example.com"],
            predefined_expression="EMAIL_MASK",
        ),
        _make_mock_v2_policy(
            policy_id="migrated_raw_raw_child_default_deny",
            policy_type=constants.DATA_POLICY_TYPE_RAW,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Raw_Child",
            grantees=["user:raw_reader@example.com"],
        ),
    ]
    child_schema = [{
        "name": "child_col",
        "type": "STRING",
        "policyTags": {
            "names": [
                "projects/source-proj/locations/us/"
                "taxonomies/100/policyTags/205"
            ]
        },
    }]
    _, swapped_columns, _ = self.swapper.transform_schema_fields(
        child_schema, masked_child_plan
    )

    tampered_discrepancies = self.swapper.verify_enforcement_parity(
        swapped_columns=swapped_columns,
        plan=masked_child_plan,
        table_project_id="data-proj",
        table_location="us",
    )

    self.assertEqual(len(tampered_discrepancies), 1)
    self.assertEqual(
        tampered_discrepancies[0].risk_category,
        constants.PARITY_RISK_ACCESS_LEAKAGE,
    )
    self.assertIn(
        "user:raw_reader@example.com", tampered_discrepancies[0].description
    )

    # Subcase B: 3-level hierarchy `Raw_Root -> Raw_Child (masked) ->
    # Raw_Grandchild (unmasked)` where `leaf_reader` was planned directly on
    # `Raw_Grandchild` but moved up to `Raw_Root` in GCP above masked
    # `Raw_Child`, causing `Raw_Child` masking to override `Raw_Root` raw read.
    grandchild_pt = (
        "projects/source-proj/locations/us/taxonomies/100/policyTags/206"
    )
    grandchild_val = f"{dg_key}/Raw_Grandchild"
    three_level_plan = copy.deepcopy(masked_child_plan)
    three_level_plan["phase_2_resource_manifest"][
        "create_dg_tag_values"
    ].append({
        "action": constants.ACTION_CREATE_DG_TAG_VALUE,
        "namespaced_name": grandchild_val,
        "parent_namespaced_name": f"{dg_key}/Raw_Child",
        "source_policy_tag": grandchild_pt,
    })
    three_level_plan["phase_3_binding_map"]["policy_tags_to_dg_tag_values"][
        grandchild_pt
    ] = {"dg_tag_key": dg_key, "dg_tag_value": grandchild_val}
    three_level_plan["phase_2_resource_manifest"][
        "create_data_policies_v2"
    ].append({
        "action": constants.ACTION_CREATE_DATA_POLICY_V2,
        "target_project_id": "data-proj",
        "region": "us",
        "policy_id": "migrated_raw_raw_grandchild",
        "policy_origin": constants.POLICY_ORIGIN_SYNTHETIC_RAW_READER,
        "grantees": ["user:leaf_reader@example.com"],
        "api_payload": {
            "data_policy_id": "migrated_raw_raw_grandchild",
            "data_policy_type": constants.DATA_POLICY_TYPE_RAW,
            "data_governance_tag": {"key": dg_key, "value": grandchild_val},
        },
    })

    grandchild_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
    )
    grandchild_swapper._live_tag_values_cache[grandchild_val] = (
        types.SimpleNamespace(
            name="tagValues/206",
            parent="tagValues/205",
            short_name="Raw_Grandchild",
            namespaced_name=grandchild_val,
        )
    )
    self.mock_data_policy_v2_client.list_data_policies.return_value = [
        _make_mock_v2_policy(
            policy_id="migrated_raw_raw_root",
            policy_type=constants.DATA_POLICY_TYPE_RAW,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Raw_Root",
            grantees=[
                "user:raw_reader@example.com",
                "user:leaf_reader@example.com",
            ],
        ),
        _make_mock_v2_policy(
            policy_id="migrated_masking_raw_child_mask",
            policy_type=constants.DATA_POLICY_TYPE_MASKING,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Raw_Child",
            grantees=["user:raw_reader@example.com"],
            predefined_expression="EMAIL_MASK",
        ),
        _make_mock_v2_policy(
            policy_id="migrated_raw_raw_child_default_deny",
            policy_type=constants.DATA_POLICY_TYPE_RAW,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Raw_Child",
            grantees=[],
        ),
        _make_mock_v2_policy(
            policy_id="migrated_raw_raw_grandchild_default_deny",
            policy_type=constants.DATA_POLICY_TYPE_RAW,
            dg_tag_key=dg_key,
            dg_tag_value=grandchild_val,
            grantees=[],
        ),
    ]
    _, gc_swapped, _ = grandchild_swapper.transform_schema_fields(
        [{
            "name": "gc_col",
            "type": "STRING",
            "policyTags": {"names": [grandchild_pt]},
        }],
        three_level_plan,
    )

    shifted_discrepancies = grandchild_swapper.verify_enforcement_parity(
        swapped_columns=gc_swapped,
        plan=three_level_plan,
        table_project_id="data-proj",
        table_location="us",
    )

    risk_categories = {item.risk_category for item in shifted_discrepancies}
    self.assertIn(constants.PARITY_RISK_ACCESS_BLOCKAGE, risk_categories)
    self.assertIn(constants.PARITY_RISK_ACCESS_LEAKAGE, risk_categories)

  # Condition-bound V2 Data Policies (`matching_condition` and
  # `data_governance_tag_condition.expression`) must be retained, have grantees
  # hydrated via REST GET, flag matching Tag Keys, ignore disjoint Tag Keys, and
  # fail closed on unparseable CEL predicates.
  def test_verify_parity_detects_condition_bound_policies_and_fails_closed(
      self,
  ):
    self._configure_matching_live_v2_policies()
    base_policies = list(
        self.mock_data_policy_v2_client.list_data_policies.return_value
    )
    dg_key_access = "target-dgt-proj/manual_migration_taxonomy"

    # 1. Disjoint condition-bound policy targeting another Tag Key produces zero
    # false-positive discrepancies.
    disjoint_cond_policy = types.SimpleNamespace(
        name="projects/data-proj/locations/us/dataPolicies/cond_other_key",
        data_policy_id="cond_other_key",
        policy_tag=None,
        data_policy_type=types.SimpleNamespace(
            name=constants.DATA_POLICY_TYPE_RAW
        ),
        data_governance_tag=None,
        matching_condition="COLUMN_HAS_TAG_KEY('other-proj/unrelated_key')",
        data_governance_tag_condition=None,
        grantees=[],
        _fixture_rest_grantees=["user:other@example.com"],
        data_masking_policy=None,
    )
    self.mock_data_policy_v2_client.list_data_policies.return_value = (
        base_policies + [disjoint_cond_policy]
    )
    raw_fields = [_make_sample_table_schema_fields()[3]]  # credit_card
    _, swapped_raw, _ = self.swapper.transform_schema_fields(
        raw_fields, self.plan
    )
    self.assertEqual(
        self.swapper.verify_enforcement_parity(
            swapped_columns=swapped_raw,
            plan=self.plan,
            table_project_id="data-proj",
            table_location="us",
        ),
        [],
    )

    # 2. CEL `data_governance_tag_condition.expression` referencing
    # `tagKeys/111` hydrates grantees via REST GET and flags
    # `ACCESS_LEAKAGE_RISK`.
    cel_cond_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
    )
    matching_cel_policy = types.SimpleNamespace(
        name="projects/data-proj/locations/us/dataPolicies/cond_cel_leak",
        data_policy_id="cond_cel_leak",
        policy_tag=None,
        data_policy_type=types.SimpleNamespace(
            name=constants.DATA_POLICY_TYPE_RAW
        ),
        data_governance_tag=None,
        matching_condition=None,
        data_governance_tag_condition=types.SimpleNamespace(
            expression="column.matchTagHierarchy('tagKeys/111', 'Raw_Root')"
        ),
        grantees=[],
        _fixture_rest_grantees=["user:cond_reader@example.com"],
        data_masking_policy=None,
    )
    self.mock_data_policy_v2_client.list_data_policies.return_value = (
        base_policies + [matching_cel_policy]
    )
    cel_discrepancies = cel_cond_swapper.verify_enforcement_parity(
        swapped_columns=swapped_raw,
        plan=self.plan,
        table_project_id="data-proj",
        table_location="us",
    )
    self.assertEqual(len(cel_discrepancies), 1)
    self.assertEqual(
        cel_discrepancies[0].risk_category, constants.PARITY_RISK_ACCESS_LEAKAGE
    )
    self.assertIn("cond_cel_leak", cel_discrepancies[0].description)

    # 3. Unparseable condition expression fails closed (`True`) rather than
    # silently allowing an unrecognized CEL predicate.
    self.assertTrue(
        self.swapper._policy_condition_matches_tag_key(
            "customPredicate(column.tags)", dg_key_access, "tagKeys/111"
        )
    )

  # Any V2 Data Policy referencing a Classification-Only Tag Key—even on a
  # sibling Tag Value—activates Tag-Key-wide Default Deny in BigQuery and must
  # block with `ACCESS_BLOCKAGE_RISK`.
  def test_verify_parity_blocks_classification_only_on_sibling_tag_policy(self):
    dg_key_class = "target-dgt-proj/classification_only_taxonomy"
    self.mock_data_policy_v2_client.list_data_policies.return_value = [
        _make_mock_v2_policy(
            policy_id="sibling_tag_policy",
            policy_type=constants.DATA_POLICY_TYPE_RAW,
            dg_tag_key=dg_key_class,
            dg_tag_value=f"{dg_key_class}/Other_Sibling_Value",
            grantees=[],
        )
    ]
    class_fields = [{
        "name": "public_note",
        "type": "STRING",
        "policyTags": {
            "names": [
                "projects/source-proj/locations/us/"
                "taxonomies/999/policyTags/901"
            ]
        },
    }]
    _, swapped_columns, _ = self.swapper.transform_schema_fields(
        class_fields, self.plan
    )

    discrepancies = self.swapper.verify_enforcement_parity(
        swapped_columns=swapped_columns,
        plan=self.plan,
        table_project_id="data-proj",
        table_location="us",
    )

    self.assertEqual(len(discrepancies), 1)
    self.assertEqual(
        discrepancies[0].risk_category, constants.PARITY_RISK_ACCESS_BLOCKAGE
    )
    self.assertIn("Classification-Only", discrepancies[0].description)
    self.assertIn("sibling_tag_policy", discrepancies[0].description)

  # Mode 2 (`TABLE_PROJECTS`) must also inspect projects registered in the
  # Organization's `default_data_policy_projects` setting because BigQuery
  # evaluates Organization default projects alongside table-project policies.
  def test_verify_parity_mode2_checks_org_default_data_policy_projects(self):
    self._configure_matching_live_v2_policies()
    table_policies = list(
        self.mock_data_policy_v2_client.list_data_policies.return_value
    )
    dg_key = "target-dgt-proj/manual_migration_taxonomy"
    org_shadow_policy = _make_mock_v2_policy(
        policy_id="org_default_leak_policy",
        policy_type=constants.DATA_POLICY_TYPE_RAW,
        dg_tag_key=dg_key,
        dg_tag_value=f"{dg_key}/Deny_Default_Root",
        grantees=["user:org_override@example.com"],
    )
    self._rest_grantees_override["org_default_leak_policy"] = [
        "user:org_override@example.com"
    ]

    def list_policies_by_parent(parent: str):
      if parent == "projects/data-proj/locations/us":
        return table_policies
      if parent == "projects/org-central-dp/locations/us":
        return [org_shadow_policy]
      return []

    self.mock_data_policy_v2_client.list_data_policies.side_effect = (
        list_policies_by_parent
    )
    self.mock_bigquery_client.query.return_value = types.SimpleNamespace(
        result=lambda: [types.SimpleNamespace(option_value="[org-central-dp]")]
    )
    fields = [_make_sample_table_schema_fields()[4]]  # secret_notes
    _, swapped_columns, _ = self.swapper.transform_schema_fields(
        fields, self.plan
    )

    discrepancies = self.swapper.verify_enforcement_parity(
        swapped_columns=swapped_columns,
        plan=self.plan,
        table_project_id="data-proj",
        table_location="us",
    )

    self.assertEqual(len(discrepancies), 1)
    self.assertEqual(
        discrepancies[0].risk_category, constants.PARITY_RISK_ACCESS_LEAKAGE
    )
    self.assertIn("org-central-dp", discrepancies[0].description)
    self.assertIn("org_default_leak_policy", discrepancies[0].description)

    # `skip_default_dp_org_check=True` skips the Organization query in Mode 2.
    skip_org_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        skip_default_dp_org_check=True,
    )
    self.assertEqual(
        skip_org_swapper.verify_enforcement_parity(
            swapped_columns=swapped_columns,
            plan=self.plan,
            table_project_id="data-proj",
            table_location="us",
        ),
        [],
    )

  # `Swapper(..., execution_project=...)` must forward explicit `project=` and
  # `location=` arguments to both `COLUMN_FIELD_PATHS` and
  # `EFFECTIVE_PROJECT_OPTIONS` BigQuery jobs.
  def test_swapper_forwards_execution_project_and_location_to_bq_queries(self):
    self._configure_matching_live_v2_policies()
    exec_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        execution_project="central-billing-proj",
    )
    self.mock_bigquery_client.query.return_value = types.SimpleNamespace(
        result=lambda: [{
            "table_catalog": "data-proj",
            "table_schema": "demo_ds",
            "table_name": "tagged_tbl",
        }]
    )
    exec_swapper.resolve_target_tables(
        table_project_ids=["data-proj"], regions=["US"]
    )
    prefilter_kwargs = self.mock_bigquery_client.query.call_args.kwargs
    self.assertEqual(prefilter_kwargs["project"], "central-billing-proj")
    self.assertEqual(prefilter_kwargs["location"], "us")

    self.mock_bigquery_client.query.reset_mock()
    self.mock_bigquery_client.query.return_value = types.SimpleNamespace(
        result=lambda: []
    )
    fields = [_make_sample_table_schema_fields()[4]]
    _, swapped_columns, _ = exec_swapper.transform_schema_fields(
        fields, self.plan
    )
    exec_swapper.verify_enforcement_parity(
        swapped_columns=swapped_columns,
        plan=self.plan,
        table_project_id="data-proj",
        table_location="US",
    )
    org_check_kwargs = self.mock_bigquery_client.query.call_args.kwargs
    self.assertEqual(org_check_kwargs["project"], "central-billing-proj")
    self.assertEqual(org_check_kwargs["location"], "us")

  # `generate_swap_report` must escape pipe characters and newlines in error
  # notes, unmapped column paths, and parity discrepancy descriptions without
  # double-escaping, and rollback unmapped warnings must avoid nested quotes.
  def test_report_markdown_cell_escaping_and_rollback_unmapped_log(self):
    failed_result = swapper.TableSwapResult(
        project_id="data-proj",
        dataset_id="demo_ds",
        table_id="failed_tbl",
        status=constants.SWAP_STATUS_FAILED,
        error_message="400 Invalid field: a | b\ndetails on line 2",
    )
    unmapped_result = swapper.TableSwapResult(
        project_id="data-proj",
        dataset_id="demo_ds",
        table_id="unmapped_tbl",
        status=constants.SWAP_STATUS_SKIPPED_UNMAPPED,
        unmapped_columns=[
            swapper.UnmappedColumnDetail(
                field_path="col|pipe",
                source_policy_tag=(
                    "projects/p/locations/us/taxonomies/1/policyTags/9"
                ),
            )
        ],
    )
    parity_result = swapper.TableSwapResult(
        project_id="data-proj",
        dataset_id="demo_ds",
        table_id="parity_tbl",
        status=constants.SWAP_STATUS_BLOCKED_PARITY_DISCREPANCY,
        parity_discrepancies=[
            swapper.ParityDiscrepancy(
                field_path="nested|col",
                source_policy_tag=(
                    "projects/p/locations/us/taxonomies/1/policyTags/2"
                ),
                dg_tag_key="gov/key",
                dg_tag_value="val",
                risk_category=constants.PARITY_RISK_ACCESS_BLOCKAGE,
                description="Mismatch: expected A | got B\nnext line",
            )
        ],
    )
    report = self.swapper.generate_swap_report(
        [failed_result, unmapped_result, parity_result]
    )
    self.assertIn(
        "400 Invalid field: a \\| b details on line 2 |",
        report,
    )
    self.assertIn(
        "Unmapped Policy Tags left untouched on: `col\\|pipe` |",
        report,
    )
    self.assertNotIn("\\\\|", report)
    self.assertIn(
        "| `data-proj.demo_ds.parity_tbl` | `nested\\|col` |"
        " `ACCESS_BLOCKAGE_RISK` | key: `gov/key`, value: `val` |"
        " Mismatch: expected A \\| got B next line |",
        report,
    )

    # Verify rollback warning log wraps `key='...', value='...'` in parentheses.
    rollback_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        swap_mode=constants.SWAP_MODE_DGT_TO_PT,
        dry_run=True,
    )
    self.mock_bigquery_client.get_table.return_value = self._make_mock_table([{
        "name": "unmapped_col",
        "type": "STRING",
        "dataGovernanceTagsInfo": {
            "dataGovernanceTags": {"other-proj/other_key": "Keep_Value"}
        },
    }])
    with self.assertLogs(swapper.logger, level="WARNING") as log_ctx:
      rollback_swapper.swap_table_schema(
          "data-proj", "demo_ds", "unmapped_dgt_tbl", self.plan
      )
    self.assertTrue(
        any(
            "Data Governance Tag (key='other-proj/other_key',"
            " value='Keep_Value')"
            in msg
            for msg in log_ctx.output
        )
    )

  # Numeric project numbers and `projects/` prefixes in Organization
  # `default_data_policy_projects` match zero V2 Data Policies at query time and
  # must be flagged as `ACCESS_LEAKAGE_RISK` without scanning numeric tokens as
  # companion projects (preventing Mode 1 false passes and Mode 2 self-conflict
  # false positives).
  def test_verify_parity_flags_numeric_default_data_policy_projects(self):
    self.mock_projects_client.get_project.return_value = types.SimpleNamespace(
        project_id="central-dp-proj"
    )
    dg_key = "target-dgt-proj/manual_migration_taxonomy"
    central_policy = _make_mock_v2_policy(
        policy_id="migrated_raw_deny_default_root_default_deny",
        policy_type=constants.DATA_POLICY_TYPE_RAW,
        dg_tag_key=dg_key,
        dg_tag_value=f"{dg_key}/Deny_Default_Root",
        grantees=[],
    )

    mode1_plan = copy.deepcopy(self.plan)
    mode1_plan["metadata"][
        "target_data_policy_mode"
    ] = constants.TARGET_DATA_POLICY_MODE_DEFAULT_PROJECT
    mode1_plan["metadata"]["target_data_policy_project_ids"] = [
        "central-dp-proj"
    ]
    for item in mode1_plan["phase_2_resource_manifest"][
        "create_data_policies_v2"
    ]:
      item["target_project_id"] = "central-dp-proj"

    listed_parents: list[str] = []

    def list_mode1_policies(parent: str):
      listed_parents.append(parent)
      if parent == "projects/central-dp-proj/locations/us":
        return [central_policy]
      return []

    self.mock_data_policy_v2_client.list_data_policies.side_effect = (
        list_mode1_policies
    )
    self.mock_bigquery_client.query.return_value = types.SimpleNamespace(
        result=lambda: [types.SimpleNamespace(option_value="[123456789]")]
    )
    fields = [_make_sample_table_schema_fields()[4]]  # secret_notes
    _, swapped_columns, _ = self.swapper.transform_schema_fields(
        fields, mode1_plan
    )

    mode1_discrepancies = self.swapper.verify_enforcement_parity(
        swapped_columns=swapped_columns,
        plan=mode1_plan,
        table_project_id="data-proj",
        table_location="us",
    )
    self.assertTrue(mode1_discrepancies)
    self.assertTrue(
        all(
            d.risk_category == constants.PARITY_RISK_ACCESS_LEAKAGE
            for d in mode1_discrepancies
        )
    )
    self.assertTrue(
        any(
            "123456789" in d.description
            and "`region-us.default_data_policy_projects`" in d.description
            for d in mode1_discrepancies
        )
    )
    self.assertNotIn("projects/123456789/locations/us", listed_parents)

    # Mode 2: numeric org entry is flagged as ACCESS_LEAKAGE_RISK without
    # scanning `projects/987654321` as a companion project.
    mode2_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        resourcemanager_client=self.mock_projects_client,
    )
    self._configure_matching_live_v2_policies()
    table_policies = list(
        self.mock_data_policy_v2_client.list_data_policies.return_value
    )
    mode2_parents: list[str] = []

    def list_mode2_policies(parent: str):
      mode2_parents.append(parent)
      if parent == "projects/data-proj/locations/us":
        return table_policies
      return table_policies

    self.mock_data_policy_v2_client.list_data_policies.side_effect = (
        list_mode2_policies
    )
    self.mock_bigquery_client.query.return_value = types.SimpleNamespace(
        result=lambda: [types.SimpleNamespace(option_value="[987654321]")]
    )
    _, swapped_mode2, _ = mode2_swapper.transform_schema_fields(
        fields, self.plan
    )
    mode2_discrepancies = mode2_swapper.verify_enforcement_parity(
        swapped_columns=swapped_mode2,
        plan=self.plan,
        table_project_id="data-proj",
        table_location="us",
    )
    self.assertEqual(len(mode2_discrepancies), 1)
    self.assertEqual(
        mode2_discrepancies[0].risk_category,
        constants.PARITY_RISK_ACCESS_LEAKAGE,
    )
    self.assertIn("987654321", mode2_discrepancies[0].description)
    self.assertNotIn("projects/987654321/locations/us", mode2_parents)

  # High-fan-out masking policies sharded across multiple V2 policies sharing
  # the same masking rule on one tag must union planned grantees rather than
  # cross-reporting sibling grantees as unauthorized extras.
  def test_verify_parity_merges_sharded_masking_policies_sharing_rule(self):
    dg_key = "target-dgt-proj/manual_migration_taxonomy"
    sharded_plan = copy.deepcopy(self.plan)
    sharded_plan["phase_2_resource_manifest"]["create_data_policies_v2"][0][
        "grantees"
    ] = ["group:readers_shard_1@example.com"]
    sharded_plan["phase_2_resource_manifest"][
        "create_data_policies_v2"
    ].append({
        "action": constants.ACTION_CREATE_DATA_POLICY_V2,
        "target_project_id": "data-proj",
        "region": "us",
        "policy_id": "migrated_masking_email_mask_policy_shard_2",
        "policy_origin": constants.POLICY_ORIGIN_MIGRATED_V1,
        "grantees": ["group:readers_shard_2@example.com"],
        "api_payload": {
            "data_policy_id": "migrated_masking_email_mask_policy_shard_2",
            "data_policy_type": constants.DATA_POLICY_TYPE_MASKING,
            "data_governance_tag": {
                "key": dg_key,
                "value": f"{dg_key}/Email_Mask_Root",
            },
            "data_masking_policy": {
                "predefined_expression": "EMAIL_MASK",
            },
        },
    })

    self.mock_data_policy_v2_client.list_data_policies.return_value = [
        _make_mock_v2_policy(
            policy_id="migrated_masking_email_mask_policy",
            policy_type=constants.DATA_POLICY_TYPE_MASKING,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Email_Mask_Root",
            grantees=["group:readers_shard_1@example.com"],
            predefined_expression="EMAIL_MASK",
        ),
        _make_mock_v2_policy(
            policy_id="migrated_masking_email_mask_policy_shard_2",
            policy_type=constants.DATA_POLICY_TYPE_MASKING,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Email_Mask_Root",
            grantees=["group:readers_shard_2@example.com"],
            predefined_expression="EMAIL_MASK",
        ),
        _make_mock_v2_policy(
            policy_id="migrated_raw_email_mask_root_default_deny",
            policy_type=constants.DATA_POLICY_TYPE_RAW,
            dg_tag_key=dg_key,
            dg_tag_value=f"{dg_key}/Email_Mask_Root",
            grantees=[],
        ),
    ]
    self.mock_bigquery_client.query.return_value = types.SimpleNamespace(
        result=lambda: []
    )
    fields = [_make_sample_table_schema_fields()[1]]  # email
    _, swapped_columns, _ = self.swapper.transform_schema_fields(
        fields, sharded_plan
    )
    self.assertEqual(
        self.swapper.verify_enforcement_parity(
            swapped_columns=swapped_columns,
            plan=sharded_plan,
            table_project_id="data-proj",
            table_location="us",
        ),
        [],
    )

  # Negated CEL/SQL tag predicates (`!column.hasTagKey('other-proj/k')`) can
  # match columns lacking that key and must fail closed; intermediate SDK wheels
  # lacking `matching_condition` must fall back to REST so condition-bound
  # policies are not dropped as label-less entries.
  def test_intermediate_sdk_without_matching_condition_and_negated_cel(self):
    dg_key = "target-dgt-proj/manual_migration_taxonomy"
    self.assertTrue(
        self.swapper._policy_condition_matches_tag_key(
            "!column.hasTagKey('other-proj/other_key')", dg_key
        )
    )
    self.assertTrue(
        self.swapper._policy_condition_matches_tag_key(
            "NOT COLUMN_HAS_TAG_KEY('other-proj/other_key')", dg_key
        )
    )

    # Simulate an intermediate wheel whose `DataPolicy` defines
    # `data_governance_tag` but omits `matching_condition`, causing a
    # condition-bound policy to arrive label-less in `sdk_policies`.
    sdk_dgt_policy = types.SimpleNamespace(
        name="projects/data-proj/locations/us/dataPolicies/raw_root_sdk",
        data_policy_id="migrated_raw_raw_root",
        policy_tag=None,
        data_policy_type=types.SimpleNamespace(
            name=constants.DATA_POLICY_TYPE_RAW
        ),
        data_governance_tag=types.SimpleNamespace(
            key=dg_key, value=f"{dg_key}/Raw_Root"
        ),
        grantees=[],
        data_masking_policy=None,
    )
    stripped_cond_policy = types.SimpleNamespace(
        name="projects/data-proj/locations/us/dataPolicies/cond_leak",
        data_policy_id="cond_leak",
        policy_tag=None,
        data_policy_type=types.SimpleNamespace(
            name=constants.DATA_POLICY_TYPE_RAW
        ),
        data_governance_tag=None,
        grantees=[],
        data_masking_policy=None,
    )
    self.mock_data_policy_v2_client.list_data_policies.return_value = [
        sdk_dgt_policy,
        stripped_cond_policy,
    ]
    self.mock_bigquery_client.query.return_value = types.SimpleNamespace(
        result=lambda: []
    )
    rest_payloads = [
        {
            "name": (
                "projects/data-proj/locations/us/dataPolicies/"
                "migrated_raw_raw_root"
            ),
            "dataPolicyId": "migrated_raw_raw_root",
            "dataPolicyType": constants.DATA_POLICY_TYPE_RAW,
            "dataGovernanceTag": {
                "key": dg_key,
                "value": f"{dg_key}/Raw_Root",
            },
            "grantees": ["user:raw_reader@example.com"],
        },
        {
            "name": "projects/data-proj/locations/us/dataPolicies/cond_leak",
            "dataPolicyId": "cond_leak",
            "dataPolicyType": constants.DATA_POLICY_TYPE_RAW,
            "matchingCondition": f"COLUMN_HAS_TAG_KEY('{dg_key}')",
            "grantees": ["user:unexpected@example.com"],
        },
    ]
    fields = [_make_sample_table_schema_fields()[3]]  # credit_card
    _, swapped_columns, _ = self.swapper.transform_schema_fields(
        fields, self.plan
    )
    with mock.patch.object(
        self.swapper,
        "_list_data_policies_v2_rest",
        return_value=rest_payloads,
    ) as mock_rest_list:
      discrepancies = self.swapper.verify_enforcement_parity(
          swapped_columns=swapped_columns,
          plan=self.plan,
          table_project_id="data-proj",
          table_location="us",
      )
    mock_rest_list.assert_called_once_with("data-proj", "us")
    self.assertEqual(len(discrepancies), 1)
    self.assertEqual(
        discrepancies[0].risk_category, constants.PARITY_RISK_ACCESS_LEAKAGE
    )
    self.assertIn("cond_leak", discrepancies[0].description)

  # Intermediate SDK wheels defining `data_governance_tag_condition` without
  # `matching_condition` must still fall back to REST `/v2/` because the server
  # returns SQL conditions only in `matching_condition`.
  def test_intermediate_sdk_with_cel_field_only_falls_back_to_rest(self):
    dg_key = "target-dgt-proj/manual_migration_taxonomy"
    cel_only_wheel_policy = types.SimpleNamespace(
        name="projects/data-proj/locations/us/dataPolicies/raw_root_sdk",
        data_policy_id="migrated_raw_raw_root",
        policy_tag=None,
        data_policy_type=types.SimpleNamespace(
            name=constants.DATA_POLICY_TYPE_RAW
        ),
        data_governance_tag=types.SimpleNamespace(
            key=dg_key, value=f"{dg_key}/Raw_Root"
        ),
        data_governance_tag_condition=None,
        grantees=["user:raw_reader@example.com"],
        data_masking_policy=None,
    )
    self.mock_data_policy_v2_client.list_data_policies.return_value = [
        cel_only_wheel_policy
    ]
    rest_payloads = [{
        "name": "projects/data-proj/locations/us/dataPolicies/sql_cond_dp",
        "dataPolicyId": "sql_cond_dp",
        "dataPolicyType": constants.DATA_POLICY_TYPE_RAW,
        "matchingCondition": f"COLUMN_HAS_TAG_KEY('{dg_key}')",
        "grantees": ["user:extra@example.com"],
    }]
    with mock.patch.object(
        self.swapper,
        "_list_data_policies_v2_rest",
        return_value=rest_payloads,
    ) as mock_rest_list:
      summaries = self.swapper._list_live_v2_data_policies("data-proj", "us")

    mock_rest_list.assert_called_once_with("data-proj", "us")
    self.assertEqual([s.data_policy_id for s in summaries], ["sql_cond_dp"])
    self.assertEqual(
        summaries[0].matching_condition, f"COLUMN_HAS_TAG_KEY('{dg_key}')"
    )

    # SDK wheels defining `matching_condition` without
    # `data_governance_tag_condition` must also fall back to REST `/v2/` so
    # CEL-condition policies are not dropped on the SDK path.
    self.swapper._live_v2_policies_cache.clear()
    sql_only_wheel_policy = types.SimpleNamespace(
        name="projects/data-proj/locations/us/dataPolicies/raw_root_sdk",
        data_policy_id="migrated_raw_raw_root",
        policy_tag=None,
        data_policy_type=types.SimpleNamespace(
            name=constants.DATA_POLICY_TYPE_RAW
        ),
        data_governance_tag=types.SimpleNamespace(
            key=dg_key, value=f"{dg_key}/Raw_Root"
        ),
        matching_condition=None,
        grantees=["user:raw_reader@example.com"],
        data_masking_policy=None,
    )
    self.mock_data_policy_v2_client.list_data_policies.return_value = [
        sql_only_wheel_policy
    ]
    cel_rest_payloads = [{
        "name": "projects/data-proj/locations/us/dataPolicies/cel_cond_dp",
        "dataPolicyId": "cel_cond_dp",
        "dataPolicyType": constants.DATA_POLICY_TYPE_RAW,
        "dataGovernanceTagCondition": {
            "expression": f"column.matchTagKey('{dg_key}')"
        },
        "grantees": ["user:cel_reader@example.com"],
    }]
    with mock.patch.object(
        self.swapper,
        "_list_data_policies_v2_rest",
        return_value=cel_rest_payloads,
    ) as mock_cel_rest_list:
      cel_summaries = self.swapper._list_live_v2_data_policies(
          "data-proj", "us"
      )

    mock_cel_rest_list.assert_called_once_with("data-proj", "us")
    self.assertEqual([s.data_policy_id for s in cel_summaries], ["cel_cond_dp"])
    self.assertEqual(
        cel_summaries[0].matching_condition, f"column.matchTagKey('{dg_key}')"
    )

  # `_get_live_dg_tag_key` must seed `_project_number_to_id_cache` from
  # `tag_key.parent` without requiring `resourcemanager.projects.get`, and any
  # remaining unresolved `<digits>/<key_short>` policy must fail closed rather
  # than passing parity or falsely satisfying `_default_deny`.
  def test_numeric_tag_key_resolution_via_tag_key_parent_and_fail_closed(self):
    self.mock_projects_client.get_project.side_effect = (
        google.api_core.exceptions.PermissionDenied(
            "403 resourcemanager.projects.get denied"
        )
    )
    self.mock_bigquery_client.query.return_value = types.SimpleNamespace(
        result=lambda: []
    )
    # Seed `parent="projects/987654321"` on the live Tag Key so numeric
    # `987654321/manual_migration_taxonomy` resolves without `get_project`.
    key_with_parent = types.SimpleNamespace(
        name="tagKeys/111",
        parent="projects/987654321",
        short_name="manual_migration_taxonomy",
        namespaced_name="target-dgt-proj/manual_migration_taxonomy",
        purpose=2,
    )
    class_key_with_parent = types.SimpleNamespace(
        name="tagKeys/999",
        parent="projects/987654321",
        short_name="classification_only_taxonomy",
        namespaced_name="target-dgt-proj/classification_only_taxonomy",
        purpose=2,
    )
    self.mock_tag_keys_client.list_tag_keys.return_value = [
        key_with_parent,
        class_key_with_parent,
    ]
    self.mock_data_policy_v2_client.list_data_policies.return_value = [
        _make_mock_v2_policy(
            policy_id="migrated_raw_deny_default_root_default_deny",
            policy_type=constants.DATA_POLICY_TYPE_RAW,
            dg_tag_key="987654321/manual_migration_taxonomy",
            dg_tag_value=(
                "987654321/manual_migration_taxonomy/Deny_Default_Root"
            ),
            grantees=[],
        )
    ]
    fields = [_make_sample_table_schema_fields()[4]]  # secret_notes
    _, swapped_columns, _ = self.swapper.transform_schema_fields(
        fields, self.plan
    )

    # Case 1: Known DGT project number resolves via `tag_key.parent` cleanly.
    resolved_discrepancies = self.swapper.verify_enforcement_parity(
        swapped_columns=swapped_columns,
        plan=self.plan,
        table_project_id="data-proj",
        table_location="us",
    )
    self.assertEqual(resolved_discrepancies, [])
    self.mock_projects_client.get_project.assert_not_called()

    # Case 2: Unresolved `<999999>/<short_name>` policy fails closed in
    # Access-Control mode (cannot satisfy `_default_deny` AND flags leakage).
    self.swapper._live_v2_policies_cache.clear()
    self.mock_data_policy_v2_client.list_data_policies.return_value = [
        _make_mock_v2_policy(
            policy_id="unknown_proj_policy",
            policy_type=constants.DATA_POLICY_TYPE_RAW,
            dg_tag_key="999999/manual_migration_taxonomy",
            dg_tag_value="999999/manual_migration_taxonomy/Deny_Default_Root",
            grantees=[],
        )
    ]
    unresolved_discrepancies = self.swapper.verify_enforcement_parity(
        swapped_columns=swapped_columns,
        plan=self.plan,
        table_project_id="data-proj",
        table_location="us",
    )
    self.assertTrue(
        any(
            d.risk_category == constants.PARITY_RISK_ACCESS_LEAKAGE
            and "unknown_proj_policy" in d.description
            and "999999/manual_migration_taxonomy" in d.description
            for d in unresolved_discrepancies
        )
    )
    self.assertTrue(
        any(
            d.risk_category == constants.PARITY_RISK_ACCESS_LEAKAGE
            and "has NO live V2 Data Policy attached" in d.description
            for d in unresolved_discrepancies
        )
    )

    # Case 3: Unresolved `<999999>/<short_name>` also fails closed in
    # Classification-Only mode (`ACCESS_BLOCKAGE_RISK`).
    self.swapper._live_v2_policies_cache.clear()
    self.mock_data_policy_v2_client.list_data_policies.return_value = [
        _make_mock_v2_policy(
            policy_id="unknown_class_policy",
            policy_type=constants.DATA_POLICY_TYPE_RAW,
            dg_tag_key="999999/classification_only_taxonomy",
            dg_tag_value="999999/classification_only_taxonomy/Public_Info",
            grantees=[],
        )
    ]
    class_fields = [{
        "name": "marketing_tier",
        "type": "STRING",
        "policyTags": {
            "names": [
                "projects/source-proj/locations/us/"
                "taxonomies/999/policyTags/901"
            ]
        },
    }]
    _, class_swapped, _ = self.swapper.transform_schema_fields(
        class_fields, self.plan
    )
    class_discrepancies = self.swapper.verify_enforcement_parity(
        swapped_columns=class_swapped,
        plan=self.plan,
        table_project_id="data-proj",
        table_location="us",
    )
    self.assertTrue(
        any(
            d.risk_category == constants.PARITY_RISK_ACCESS_BLOCKAGE
            and "unknown_class_policy" in d.description
            for d in class_discrepancies
        )
    )

  # When `update_table` raises an ambiguous error (such as retry 412 or timeout)
  # after an initial PATCH committed, `swap_table_schema` must re-read live
  # column tags: restoring dropped tags, preserving concurrent unrelated DDL on
  # genuine 412s, and flagging `live_schema_possibly_modified` for report
  # rollback commands whenever live state changed or could not be re-verified.
  def test_ambiguous_update_table_exception_rechecks_live_schema(self):
    self._configure_matching_live_v2_policies()
    original_fields = [_make_sample_table_schema_fields()[2]]  # ssn_hash
    swapped_fields, _, _ = self.swapper.transform_schema_fields(
        original_fields, self.plan
    )

    # Case 1: First PATCH cleared PT while dropping DGT, then retry raised 412;
    # re-read detects dropped DGT and triggers compensating restore.
    with self.subTest(case="dropped_dgt_triggers_compensating_restore"):
      initial_table = self._make_mock_table(copy.deepcopy(original_fields))
      dropped_dgt_fields = copy.deepcopy(swapped_fields)
      dropped_dgt_fields[0].pop("dataGovernanceTagsInfo", None)
      live_after_error = self._make_mock_table(dropped_dgt_fields)
      self.mock_bigquery_client.get_table.side_effect = [
          initial_table,
          live_after_error,
      ]
      patch_calls: list[list[dict[str, object]]] = []

      def update_side_effect(tbl, *_args, **_kwargs):
        patch_calls.append(copy.deepcopy(tbl._properties["schema"]["fields"]))
        if len(patch_calls) == 1:
          raise google.api_core.exceptions.PreconditionFailed(
              "412 retry after commit"
          )
        return tbl

      self.mock_bigquery_client.update_table.side_effect = update_side_effect
      result = self.swapper.swap_table_schema(
          "data-proj", "demo_ds", "ambiguous_drop_tbl", self.plan
      )
      self.assertEqual(result.status, constants.SWAP_STATUS_FAILED)
      self.assertFalse(result.live_schema_possibly_modified)
      self.assertEqual(len(patch_calls), 2)
      self.assertEqual(
          patch_calls[1][0]["policyTags"], original_fields[0]["policyTags"]
      )
      self.assertIn(
          "Automatically restored original column tags", result.error_message
      )

    # Case 2: Genuine 412 caused by concurrent unrelated `ALTER TABLE` adding a
    # new column while swapped column retains its original PT must NOT trigger
    # destructive compensating restore.
    with self.subTest(case="genuine_412_unrelated_ddl_skips_restore"):
      initial_table = self._make_mock_table(copy.deepcopy(original_fields))
      concurrent_fields = copy.deepcopy(original_fields) + [
          {"name": "concurrent_col", "type": "STRING", "mode": "NULLABLE"}
      ]
      live_after_412 = self._make_mock_table(concurrent_fields)
      self.mock_bigquery_client.get_table.side_effect = [
          initial_table,
          live_after_412,
      ]
      self.mock_bigquery_client.update_table.reset_mock()
      self.mock_bigquery_client.update_table.side_effect = (
          google.api_core.exceptions.PreconditionFailed(
              "412 concurrent ALTER TABLE"
          )
      )
      result = self.swapper.swap_table_schema(
          "data-proj", "demo_ds", "concurrent_ddl_tbl", self.plan
      )
      self.assertEqual(result.status, constants.SWAP_STATUS_FAILED)
      self.assertFalse(result.live_schema_possibly_modified)
      self.assertEqual(self.mock_bigquery_client.update_table.call_count, 1)
      self.assertIn(
          "swapped column tags remain unchanged", result.error_message
      )
      report = self.swapper.generate_swap_report([result])
      self.assertNotIn("Surgical Rollback Command", report)

    # Case 3: Initial PATCH actually committed valid target DGTs before timeout;
    # re-read confirms live schema changed -> `live_schema_possibly_modified` is
    # True and `generate_swap_report` surfaces rollback commands.
    with self.subTest(case="committed_target_tags_surfaces_rollback_in_report"):
      initial_table = self._make_mock_table(copy.deepcopy(original_fields))
      live_committed = self._make_mock_table(copy.deepcopy(swapped_fields))
      self.mock_bigquery_client.get_table.side_effect = [
          initial_table,
          live_committed,
      ]
      self.mock_bigquery_client.update_table.reset_mock()
      self.mock_bigquery_client.update_table.side_effect = (
          google.api_core.exceptions.DeadlineExceeded(
              "504 timeout after commit"
          )
      )
      result = self.swapper.swap_table_schema(
          "data-proj", "demo_ds", "committed_timeout_tbl", self.plan
      )
      self.assertEqual(result.status, constants.SWAP_STATUS_FAILED)
      self.assertTrue(result.live_schema_possibly_modified)
      self.assertIn("ARE persisted on BigQuery", result.error_message)
      report = self.swapper.generate_swap_report([result])
      self.assertIn("(live state modified/unverified)", report)
      self.assertIn("Surgical Rollback Command", report)
      self.assertIn("Snapshot Rollback Command", report)

    # Case 4: `get_table` re-read itself fails after `update_table` error ->
    # fail closed with `live_schema_possibly_modified=True` and rollback hints.
    with self.subTest(case="recheck_get_table_failure_fails_closed"):
      initial_table = self._make_mock_table(copy.deepcopy(original_fields))
      self.mock_bigquery_client.get_table.side_effect = [
          initial_table,
          google.api_core.exceptions.ServiceUnavailable(
              "503 re-read unavailable"
          ),
      ]
      self.mock_bigquery_client.update_table.reset_mock()
      self.mock_bigquery_client.update_table.side_effect = (
          google.api_core.exceptions.DeadlineExceeded("504 timeout")
      )
      result = self.swapper.swap_table_schema(
          "data-proj", "demo_ds", "unverified_state_tbl", self.plan
      )
      self.assertEqual(result.status, constants.SWAP_STATUS_FAILED)
      self.assertTrue(result.live_schema_possibly_modified)
      self.assertIn("Could not re-read live table schema", result.error_message)
      report = self.swapper.generate_swap_report([result])
      self.assertIn("Snapshot Rollback Command", report)

    # Case 5: Genuine 412 where an admin concurrently moved `ssn_hash` to a
    # stricter Policy Tag must NOT revert that concurrent tag change.
    with self.subTest(
        case="genuine_412_concurrent_policy_tag_edit_not_reverted"
    ):
      initial_table = self._make_mock_table(copy.deepcopy(original_fields))
      tightened_fields = copy.deepcopy(original_fields)
      tightened_fields[0]["policyTags"] = {
          "names": [
              "projects/source-proj/locations/us/"
              "taxonomies/100/policyTags/stricter_pt"
          ]
      }
      live_after_412 = self._make_mock_table(tightened_fields)
      self.mock_bigquery_client.get_table.side_effect = [
          initial_table,
          live_after_412,
      ]
      self.mock_bigquery_client.update_table.reset_mock()
      self.mock_bigquery_client.update_table.side_effect = (
          google.api_core.exceptions.PreconditionFailed(
              "412 concurrent policy tag tightening"
          )
      )
      result = self.swapper.swap_table_schema(
          "data-proj", "demo_ds", "concurrent_pt_edit_tbl", self.plan
      )
      self.assertEqual(result.status, constants.SWAP_STATUS_FAILED)
      self.assertTrue(result.live_schema_possibly_modified)
      self.assertEqual(self.mock_bigquery_client.update_table.call_count, 1)
      self.assertIn(
          "skipped automatic compensating restore to avoid reverting"
          " concurrent edits",
          result.error_message,
      )

    # Case 6: Genuine 412 where a swapped column was concurrently dropped must
    # skip restore (never attempt to re-add it) and mark possibly modified.
    with self.subTest(case="genuine_412_dropped_swapped_column_skips_restore"):
      initial_table = self._make_mock_table(copy.deepcopy(original_fields))
      live_dropped = self._make_mock_table(
          [{"name": "other_col", "type": "STRING", "mode": "NULLABLE"}]
      )
      self.mock_bigquery_client.get_table.side_effect = [
          initial_table,
          live_dropped,
      ]
      self.mock_bigquery_client.update_table.reset_mock()
      self.mock_bigquery_client.update_table.side_effect = (
          google.api_core.exceptions.PreconditionFailed("412 column dropped")
      )
      result = self.swapper.swap_table_schema(
          "data-proj", "demo_ds", "concurrent_drop_tbl", self.plan
      )
      self.assertEqual(result.status, constants.SWAP_STATUS_FAILED)
      self.assertTrue(result.live_schema_possibly_modified)
      self.assertEqual(self.mock_bigquery_client.update_table.call_count, 1)
      self.assertIn("concurrently removed", result.error_message)

    # Case 7: Partial write (PT cleared, DGT dropped) alongside a concurrently
    # added column restores ONLY the partial-write column onto a copy of
    # `live_fields`, preserving the concurrently added column.
    with self.subTest(case="partial_write_restore_preserves_concurrent_column"):
      initial_table = self._make_mock_table(copy.deepcopy(original_fields))
      partial_live_fields = copy.deepcopy(swapped_fields) + [
          {"name": "added_concurrently", "type": "STRING", "mode": "NULLABLE"}
      ]
      partial_live_fields[0].pop("dataGovernanceTagsInfo", None)
      live_after_error = self._make_mock_table(partial_live_fields)
      self.mock_bigquery_client.get_table.side_effect = [
          initial_table,
          live_after_error,
      ]
      patch_calls: list[list[dict[str, object]]] = []

      def restore_on_live_side_effect(tbl, *_args, **_kwargs):
        patch_calls.append(copy.deepcopy(tbl._properties["schema"]["fields"]))
        if len(patch_calls) == 1:
          raise google.api_core.exceptions.PreconditionFailed("412 retry")
        return tbl

      self.mock_bigquery_client.update_table.reset_mock()
      self.mock_bigquery_client.update_table.side_effect = (
          restore_on_live_side_effect
      )
      result = self.swapper.swap_table_schema(
          "data-proj", "demo_ds", "partial_preserve_col_tbl", self.plan
      )
      self.assertEqual(result.status, constants.SWAP_STATUS_FAILED)
      self.assertFalse(result.live_schema_possibly_modified)
      self.assertEqual(len(patch_calls), 2)
      restored_names = [col["name"] for col in patch_calls[1]]
      self.assertEqual(restored_names, ["ssn_hash", "added_concurrently"])
      self.assertEqual(
          patch_calls[1][0]["policyTags"], original_fields[0]["policyTags"]
      )

    # Case 8: Partial-write compensating restore ALSO raises -> fail closed
    # with `live_schema_possibly_modified=True` and rollback commands in report.
    with self.subTest(case="ambiguous_error_failed_compensating_restore"):
      initial_table = self._make_mock_table(copy.deepcopy(original_fields))
      dropped_dgt_fields = copy.deepcopy(swapped_fields)
      dropped_dgt_fields[0].pop("dataGovernanceTagsInfo", None)
      live_after_error = self._make_mock_table(dropped_dgt_fields)
      self.mock_bigquery_client.get_table.side_effect = [
          initial_table,
          live_after_error,
      ]
      self.mock_bigquery_client.update_table.reset_mock()
      self.mock_bigquery_client.update_table.side_effect = [
          google.api_core.exceptions.PreconditionFailed("412 retry"),
          google.api_core.exceptions.ServiceUnavailable("503 restore failed"),
      ]
      result = self.swapper.swap_table_schema(
          "data-proj", "demo_ds", "ambiguous_restore_fail_tbl", self.plan
      )
      self.assertEqual(result.status, constants.SWAP_STATUS_FAILED)
      self.assertTrue(result.live_schema_possibly_modified)
      self.assertIn(
          "automatic compensating schema restore ALSO failed",
          result.error_message,
      )
      report = self.swapper.generate_swap_report([result])
      self.assertIn("Snapshot Rollback Command", report)

  # HTTP 200 post-patch silent tag drop whose compensating restore ALSO raises
  # must set `live_schema_possibly_modified=True` (and preserve the failed
  # result with rollback commands in `swap_schemas` even with `halt_on_error`).
  def test_failed_post_patch_restore_and_halt_on_error_report_rollback(self):
    self._configure_matching_live_v2_policies()
    original_fields = [_make_sample_table_schema_fields()[2]]  # ssn_hash
    swapped_fields, _, _ = self.swapper.transform_schema_fields(
        original_fields, self.plan
    )
    dropped_dgt_fields = copy.deepcopy(swapped_fields)
    dropped_dgt_fields[0].pop("dataGovernanceTagsInfo", None)

    # 1. Non-halting path: compensating restore failure flags
    # `live_schema_possibly_modified=True` and surfaces rollback commands.
    initial_table = self._make_mock_table(copy.deepcopy(original_fields))
    patched_dropped_table = self._make_mock_table(
        copy.deepcopy(dropped_dgt_fields)
    )
    self.mock_bigquery_client.get_table.side_effect = [initial_table]
    self.mock_bigquery_client.update_table.side_effect = [
        patched_dropped_table,
        google.api_core.exceptions.ServiceUnavailable("503 restore boom"),
    ]
    result = self.swapper.swap_table_schema(
        "data-proj", "demo_ds", "post_patch_restore_fail_tbl", self.plan
    )
    self.assertEqual(result.status, constants.SWAP_STATUS_FAILED)
    self.assertTrue(result.live_schema_possibly_modified)
    self.assertIn(
        "Automatic compensating schema restore ALSO failed",
        result.error_message,
    )
    report = self.swapper.generate_swap_report([result])
    self.assertIn("Snapshot Rollback Command", report)

    # 2. `--halt-on-error` path: `swap_schemas` still records the failed table
    # result (with rollback commands) in `last_report` before re-raising.
    halting_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        resourcemanager_client=self.mock_projects_client,
        backup_dir=self.temp_dir.name,
        skip_confirmation=True,
        halt_on_error=True,
        overwrite=True,
    )
    initial_table_halt = self._make_mock_table(copy.deepcopy(original_fields))
    patched_dropped_halt = self._make_mock_table(
        copy.deepcopy(dropped_dgt_fields)
    )
    self.mock_bigquery_client.get_table.side_effect = [initial_table_halt]
    self.mock_bigquery_client.update_table.side_effect = [
        patched_dropped_halt,
        google.api_core.exceptions.ServiceUnavailable("503 halt restore boom"),
    ]
    with self.assertRaisesRegex(
        RuntimeError, "Automatic compensating schema restore ALSO failed"
    ):
      halting_swapper.swap_schemas(
          plan=self.plan,
          table_ids=["data-proj.demo_ds.halt_post_patch_tbl"],
          regions=["us"],
      )
    self.assertIsNotNone(halting_swapper.last_report)
    self.assertIn("halt_post_patch_tbl", halting_swapper.last_report)
    self.assertIn("Snapshot Rollback Command", halting_swapper.last_report)

    # 3. `--halt-on-error` on ambiguous `update_table` error where live re-read
    # confirms target tags committed also preserves rollback commands in report.
    initial_table_ambig = self._make_mock_table(copy.deepcopy(original_fields))
    live_committed = self._make_mock_table(copy.deepcopy(swapped_fields))
    self.mock_bigquery_client.get_table.side_effect = [
        initial_table_ambig,
        live_committed,
    ]
    self.mock_bigquery_client.update_table.side_effect = (
        google.api_core.exceptions.DeadlineExceeded("504 timeout after commit")
    )
    with self.assertRaises(google.api_core.exceptions.DeadlineExceeded):
      halting_swapper.swap_schemas(
          plan=self.plan,
          table_ids=["data-proj.demo_ds.halt_ambiguous_tbl"],
          regions=["us"],
      )
    self.assertIsNotNone(halting_swapper.last_report)
    self.assertIn("halt_ambiguous_tbl", halting_swapper.last_report)
    self.assertIn("Surgical Rollback Command", halting_swapper.last_report)
    self.assertIn("Snapshot Rollback Command", halting_swapper.last_report)

  # Companion project containing an unresolved numeric `<digits>/<short_name>`
  # V2 Data Policy must fail closed with `PARITY_RISK_ACCESS_LEAKAGE`.
  def test_companion_project_unresolved_numeric_tag_key_fails_closed(self):
    self._configure_matching_live_v2_policies()
    self.mock_projects_client.get_project.side_effect = (
        google.api_core.exceptions.PermissionDenied(
            "403 resourcemanager.projects.get denied"
        )
    )
    # Configure org `default_data_policy_projects` to point to a companion
    # governance project (`org-default-dp-proj`) while `plan` is Mode 2
    # (`data-proj`), and place an unresolved numeric Tag Key policy there.
    self.mock_bigquery_client.query.return_value = types.SimpleNamespace(
        result=lambda: [
            types.SimpleNamespace(
                option_name="default_data_policy_projects",
                option_value='["org-default-dp-proj"]',
            )
        ]
    )
    primary_policies = list(
        self.mock_data_policy_v2_client.list_data_policies.return_value
    )
    companion_unresolved = _make_mock_v2_policy(
        policy_id="companion_unknown_num_policy",
        policy_type=constants.DATA_POLICY_TYPE_RAW,
        dg_tag_key="777777/manual_migration_taxonomy",
        dg_tag_value="777777/manual_migration_taxonomy/Deny_Default_Root",
        grantees=["user:mystery@example.com"],
    )
    companion_unresolved.name = (
        "projects/org-default-dp-proj/locations/us/dataPolicies/"
        "companion_unknown_num_policy"
    )

    def list_policies_by_project(parent: str):
      if parent.startswith("projects/org-default-dp-proj/"):
        return [companion_unresolved]
      return primary_policies

    self.mock_data_policy_v2_client.list_data_policies.side_effect = (
        list_policies_by_project
    )
    fields = [_make_sample_table_schema_fields()[4]]  # secret_notes
    _, swapped_columns, _ = self.swapper.transform_schema_fields(
        fields, self.plan
    )
    discrepancies = self.swapper.verify_enforcement_parity(
        swapped_columns=swapped_columns,
        plan=self.plan,
        table_project_id="data-proj",
        table_location="us",
    )
    self.assertTrue(
        any(
            d.risk_category == constants.PARITY_RISK_ACCESS_LEAKAGE
            and "org-default-dp-proj" in d.description
            and "companion_unknown_num_policy" in d.description
            and "777777/manual_migration_taxonomy" in d.description
            for d in discrepancies
        )
    )

  # Schema backup JSON files and Phase 3 swap Markdown reports written to disk
  # must end with a POSIX trailing newline.
  def test_backup_and_swap_report_files_end_with_trailing_newline(self):
    """Terminates saved schema backup JSON and swap report files with LF."""
    backup_path = self.swapper.backup_table_schema(
        project_id="data-proj",
        dataset_id="demo_ds",
        table_id="customers",
        original_fields=_make_sample_table_schema_fields(),
    )
    with open(backup_path, "r", encoding="utf-8") as backup_handle:
      backup_text = backup_handle.read()
    self.assertTrue(backup_text.endswith("\n"))

    dry_run_swapper = swapper.Swapper(
        bigquery_client=self.mock_bigquery_client,
        dg_tag_keys_client=self.mock_tag_keys_client,
        dg_tag_values_client=self.mock_tag_values_client,
        data_policy_v2_client=self.mock_data_policy_v2_client,
        resourcemanager_client=self.mock_projects_client,
        backup_dir=self.temp_dir.name,
        dry_run=True,
    )
    self.mock_bigquery_client.get_table.return_value = self._make_mock_table(
        [{"name": "id", "type": "INTEGER"}]
    )
    report_path = os.path.join(self.temp_dir.name, "swap_report.md")
    dry_run_swapper.swap_schemas(
        plan=self.plan,
        table_ids=["data-proj.demo_ds.no_tags_tbl"],
        regions=["us"],
        report_file=report_path,
    )
    with open(report_path, "r", encoding="utf-8") as report_handle:
      report_text = report_handle.read()
    self.assertTrue(report_text.endswith("\n"))


if __name__ == "__main__":
  unittest.main()
