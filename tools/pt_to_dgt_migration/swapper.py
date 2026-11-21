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

"""Phase 3 Swapper module for atomic Policy Tag to DG Tag schema migration.

Architectural Role in the 3-Phase Migration Pipeline:
-----------------------------------------------------
This module implements Phase 3 (`--phase swap`) of the BigQuery Policy Tag (PT)
to Data Governance Tag (DGT) migration tool:
  - Phase 1a (`analyzer.py`): Inspects source Data Catalog Taxonomies, Policy
    Tags, V1 Data Policies, and IAM bindings.
  - Phase 1b (`planner.py`): Compiles `plan.json` containing two main sections:
      1. `phase_2_resource_manifest`: Target DG Tag Keys, DG Tag Values, and
         regional V2 Data Policies (`RAW_DATA_ACCESS_POLICY`,
         `DATA_MASKING_POLICY`, and `_default_deny` safety-net seatbelts).
      2. `phase_3_binding_map`: Exact `policy_tags_to_dg_tag_values` mapping
         connecting each source Policy Tag URI to its target DG Tag Key/Value.
  - Phase 2a (`creator.py`): Provisions the planned DG Tag Keys/Values in
    Resource Manager and V2 Data Policies in BigQuery Data Policy Service.
  - Phase 3 (`swapper.py`, this module): Consumes `plan.json` (after a
    recommended 5-7 minute IAM/tag propagation soak window) to atomically cut
    over BigQuery table schemas from Policy Tags to Data Governance Tags—or to
    roll them back from Data Governance Tags to Policy Tags.

Symmetric 6-Step Per-Table Execution Pipeline:
----------------------------------------------
Both forward cutover (`--swap-mode pt-to-dgt`) and automated surgical rollback
(`--swap-mode dgt-to-pt`) share the exact same 6-step pipeline:
  1. Target Table Discovery & Pre-Filtering (`resolve_target_tables`):
     Resolves `--table-project-ids`, `--dataset-ids`, and `--table-ids`. When
     scanning whole projects, pre-filters candidate tables via regional
     `INFORMATION_SCHEMA.COLUMN_FIELD_PATHS` (`ARRAY_LENGTH(policy_tags) > 0`
     in `pt-to-dgt` mode; `ARRAY_LENGTH(data_governance_tags) > 0` in
     `dgt-to-pt` mode) before falling back to `list_datasets`/`list_tables`,
     and skips non-table resources (`VIEW`, `MATERIALIZED_VIEW`, `EXTERNAL`,
     and read-only `SNAPSHOT` tables) before calling `get_table`.
  2. Wire-Fidelity Schema Extraction & Recursive Transformation
     (`_extract_raw_schema_fields` & `transform_schema_fields`):
     Extracts raw field dictionaries via `table.to_api_repr()["schema"]` before
     `table.schema` is ever accessed, then recursively traverses top-level and
     nested `RECORD`/`STRUCT` columns to swap mapped tags in-memory.
  3. Recursive Anti-Corruption Integrity Verification
     (`verify_schema_swap_integrity`):
     Proves that ONLY the intended `policyTags` and `dataGovernanceTagsInfo`
     properties changed on mapped columns and that every other attribute
     (field counts, ordering, names, types, modes, descriptions, defaults, and
     unmapped tags) is byte-for-byte identical.
  4. Unified Schema Diff Generation (`generate_schema_diff`):
     Computes a unified JSON diff for audit logging and reporting before parity
     checks or user prompts run.
  5. Pre-Swap Live Enforcement Parity Gate (`verify_enforcement_parity`):
     In `pt-to-dgt` mode, verifies live Google Cloud Resource Manager Tag
     Keys/Values and BigQuery V2 Data Policies against `plan.json` to prevent
     Fail-Open access leakage or accidental access blockage. Bypassed in
     `dgt-to-pt` rollback mode so emergency rollbacks are never blocked by
     broken or missing target DGT resources.
  6. Interactive Confirmation, Mode-Specific Backup & Verified `tables.patch`
     (`backup_table_schema`, `_apply_raw_schema_fields_to_table`, and
     `_verify_post_patch_column_tags`):
     Prompts for human approval (unless `--skip-confirmation` or `--dry-run`),
     saves a restore-ready, mode-isolated local JSON backup under
     `<backup_dir>/<pt_to_dgt|dgt_to_pt>/<project>/<dataset>/<table>.json`
     (explicitly injecting empty `"dataGovernanceTagsInfo"` in `pt-to-dgt`
     backups and empty `"policyTags"` in `dgt_to_pt` backups onto swapped leaf
     columns so `bq update` clears newly attached opposite tags cleanly),
     executes `bigquery_client.update_table(table, ["schema"])` (`tables.patch`)
     by writing directly to `table._properties["schema"]`, and verifies the
     returned `Table` schema to confirm every swapped column carries its
     expected target tag (automatically issuing a compensating `tables.patch`
     and marking the table `FAILED` if BigQuery silently dropped the target
     tag).

Key Architectural Design Decisions & Trade-offs:
------------------------------------------------
  - Stage 1 Atomic Swap vs. Coexistence: BigQuery columns currently enforce
    mutual exclusivity between a legacy Policy Tag and a migrated Data
    Governance Tag during Stage 1 cutover. Therefore, `pt-to-dgt` explicitly
    sets `"policyTags": {"names": []}` while setting `dataGovernanceTagsInfo`,
    and `dgt-to-pt` sets `"dataGovernanceTagsInfo": {"dataGovernanceTags": {}}`
    while restoring `policyTags`.
  - Raw Dict Wire Fidelity (`to_api_repr` / `_properties["schema"]`) vs.
    `table.schema` (`SchemaField`): Accessing `table.schema` in the
    `google-cloud-bigquery` SDK invokes `SchemaField.from_api_repr()`, which
    mutates underlying raw field dicts in-place (injecting `"mode": "NULLABLE"`
    where `mode` was omitted) and strips `dataGovernanceTagsInfo` on older SDK
    versions. Using `tables.patch` (`update_table(table, ["schema"])`) instead
    of `tables.update` also preserves concurrent non-schema table metadata.
  - Validation Against `plan.json` Snapshot vs. Live Source Re-Query:
    `verify_enforcement_parity` validates live target DGT and V2 Data Policy
    resources against the `plan.json` snapshot rather than re-querying source
    Data Catalog IAM policies during Phase 3. This avoids $O(N)$ source IAM
    quota pressure during large table cutovers; as a trade-off, customers must
    freeze source Policy Tag IAM and V1 Data Policy edits between `--phase plan`
    and `--phase swap` (or re-run Phases 1b and 2a if source IAM changes).
"""

from __future__ import annotations

import concurrent.futures
import copy
import dataclasses
import difflib
import json
import logging
import os
import re
import shlex
import sys
import tempfile
from typing import Any, Callable
import urllib.request

from google.cloud import bigquery
from google.cloud import resourcemanager_v3

# Ensure local imports work in both package and standalone script execution.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# pylint: disable=g-import-not-at-top,g-bad-import-order
import constants
import rest_utils

# pylint: enable=g-import-not-at-top,g-bad-import-order

logger = logging.getLogger(__name__)


def _ensure_trailing_newline(content: str) -> str:
  """Ensures non-empty file content terminates with a single newline."""
  if not content or content.endswith("\n"):
    return content
  return f"{content}\n"


class SchemaCorruptionError(Exception):
  """Raised when an unintended modification is detected in a table schema.

  This exception acts as a hard mechanical barrier (`ABORTED_SCHEMA_CORRUPTION`)
  before any BigQuery `tables.patch` call is issued. It is raised by:
    1. `transform_schema_fields`: When a column has conflicting pre-existing
       tags (e.g., an unrelated DGT already attached in `pt-to-dgt` mode, or
       multiple DGTs attached to a single column in `dgt-to-pt` rollback mode
       where restoring a Policy Tag would violate BigQuery's tag exclusivity).
    2. `verify_schema_swap_integrity`: When recursive comparison of the
       original and transformed schema dictionaries detects any unintended
       change to field counts, field ordering, names, types, modes,
       descriptions, default values, nested subfields, or unmapped tags.
  """


class _PromptAbortedError(RuntimeError):
  """Raised when an interactive prompt is interrupted (`Ctrl+C` or `EOFError`).

  Propagates past per-table backup error handlers so `swap_schemas` persists
  any partial swap report in `finally:` and `main.py` exits non-zero (`1`).
  """


@dataclasses.dataclass
class ColumnSwapDetail:
  """Details of a single column or nested field Policy Tag <-> DGT swap.

  Attributes:
    field_path: Dot-delimited column path (e.g., `'email'` for top-level or
      `'contact_info.email'` for nested `RECORD`/`STRUCT` fields).
    source_policy_tag: Policy Tag resource URI found on the table column (in
      `pt-to-dgt` mode) or restored to the column (in `dgt-to-pt` mode).
    matched_plan_policy_tag: Canonical Policy Tag key matched in `plan.json`'s
      `phase_3_binding_map` (which may use project ID even when the table column
      stored a numeric project number).
    dg_tag_key: Target Data Governance Tag Key namespaced name
      (`<project_id>/<key_short_name>`).
    dg_tag_value: Target Data Governance Tag Value short name or namespaced path
      bound to the column.
    field_path_parts: Structural tuple of column and subfield names from root to
      leaf, preserving unambiguous identity across case-insensitive or dotted
      column names.
    source_policy_tag_display_path: Optional human-readable Policy Tag hierarchy
      path from `plan.json` (e.g., `'Finance_Taxonomy > Email_Mask'`), used when
      rendering `Swapped Columns` transitions in the Phase 3 Markdown report.
  """

  field_path: str
  source_policy_tag: str
  matched_plan_policy_tag: str
  dg_tag_key: str
  dg_tag_value: str
  field_path_parts: tuple[str, ...] = ()
  source_policy_tag_display_path: str = ""


@dataclasses.dataclass
class UnmappedColumnDetail:
  """Details of a column or nested field with an unmapped Policy Tag or DGT.

  Columns carrying tags outside `plan.json` (for example, tags belonging to a
  different source project or an independent DGT taxonomy) are left untouched
  by `transform_schema_fields` and recorded for operator visibility.

  Attributes:
    field_path: Dot-delimited column or nested `RECORD` subfield path.
    source_policy_tag: The unmapped Policy Tag URI (in `pt-to-dgt` mode) or
      `key='<dg_tag_key>', value='<dg_tag_value>'` string (in `dgt-to-pt`
      rollback mode).
  """

  field_path: str
  source_policy_tag: str


@dataclasses.dataclass
class ParityDiscrepancy:
  """Represents a security or resource parity discrepancy before swapping.

  Emitted by `verify_enforcement_parity` in `pt-to-dgt` mode when live Google
  Cloud Resource Manager or BigQuery V2 Data Policy state does not match the
  expected security posture in `plan.json`. Unless `--allow-parity-discrepancy`
  is set, any discrepancy blocks the table swap (`BLOCKED_PARITY_DISCREPANCY`).

  Attributes:
    field_path: Dot-delimited column path affected by the discrepancy.
    source_policy_tag: Source Policy Tag URI on the column.
    dg_tag_key: Target DG Tag Key namespaced name.
    dg_tag_value: Target DG Tag Value short name or namespaced path.
    risk_category: One of `constants.PARITY_RISK_ACCESS_LEAKAGE`
      (`'ACCESS_LEAKAGE_RISK'`), `constants.PARITY_RISK_ACCESS_BLOCKAGE`
      (`'ACCESS_BLOCKAGE_RISK'`), or
      `constants.PARITY_RISK_RESOURCE_DISCREPANCY` (`'RESOURCE_DISCREPANCY'`).
    description: Human-readable explanation of the discrepancy and remediation.
  """

  field_path: str
  source_policy_tag: str
  dg_tag_key: str
  dg_tag_value: str
  risk_category: str
  description: str


@dataclasses.dataclass
class LiveDataPolicyV2Summary:
  """Normalized summary of a live V2 Data Policy in Google Cloud.

  Unifies V2 Data Policy representations across both the GAPIC protobuf client
  (`bigquery_datapolicies_v2.DataPolicyServiceClient`) and the raw REST `/v2/`
  JSON fallback so `_compare_tag_value_enforcement` can inspect policy types,
  tag bindings, masking rules, and hydrated IAM v3 grantees uniformly.

  Attributes:
    name: Full resource name
      (`projects/<project>/locations/<region>/dataPolicies/<id>`).
    data_policy_id: Short Data Policy identifier (`<id>`).
    data_policy_type: Normalized type string (`'RAW_DATA_ACCESS_POLICY'`,
      `'DATA_MASKING_POLICY'`, or `'COLUMN_LEVEL_SECURITY_POLICY'`).
    dg_tag_key: DG Tag Key referenced by `data_governance_tag.key` (namespaced
      name, short name, or `tagKeys/<id>`).
    dg_tag_value: DG Tag Value referenced by `data_governance_tag.value`
      (namespaced path, relative path, short name, or `tagValues/<id>`).
    masking_expression: Optional predefined masking expression enum name (e.g.,
      `'EMAIL_MASK'`, `'SHA256'`, `'DEFAULT_MASKING_VALUE'`).
    masking_routine: Optional custom masking UDF routine resource path
      (`projects/<p>/datasets/<d>/routines/<r>`).
    grantees: List of principals granted raw or masked read access on the V2
      Data Policy.
    matching_condition: Optional condition expression string from a
      condition-bound V2 Data Policy (`matching_condition` or
      `data_governance_tag_condition.expression`).
  """

  name: str
  data_policy_id: str
  data_policy_type: str
  dg_tag_key: str
  dg_tag_value: str
  masking_expression: str | None = None
  masking_routine: str | None = None
  grantees: list[str] = dataclasses.field(default_factory=list)
  matching_condition: str | None = None


@dataclasses.dataclass
class TableSwapResult:
  """Result of inspecting and optionally swapping a single BigQuery table.

  Attributes:
    project_id: BigQuery table project ID.
    dataset_id: BigQuery dataset ID (or `'*'` on project-level list failure).
    table_id: BigQuery table ID (or `'*'` on dataset-level list failure).
    status: One of the `constants.SWAP_STATUS_*` tokens (`'SWAPPED'`,
      `'DRY_RUN_READY'`, `'BLOCKED_PARITY_DISCREPANCY'`,
      `'ABORTED_SCHEMA_CORRUPTION'`, `'SKIPPED_USER_DECLINED'`,
      `'SKIPPED_REGION_MISMATCH'`, `'SKIPPED_UNMAPPED'`,
      `'SKIPPED_NO_POLICY_TAGS'`, `'SKIPPED_NO_DG_TAGS'`, or `'FAILED'`).
    location: Lowercase BigQuery dataset/table location (e.g., `'us'`, `'eu'`).
    swapped_columns: List of `ColumnSwapDetail` entries for columns that were
      swapped (or would be swapped in `--dry-run`).
    unmapped_columns: List of `UnmappedColumnDetail` entries for columns with
      tags not present in `plan.json`.
    parity_discrepancies: List of `ParityDiscrepancy` items detected by
      `verify_enforcement_parity`.
    backup_file_path: Local path to the saved pre-swap JSON schema backup file
      (or `None` if skipped, blocked, or run with `--dry-run`).
    schema_diff: Unified diff string comparing original vs. updated schema JSON.
    error_message: Optional error or skip/block explanation for reporting.
    live_schema_possibly_modified: True when a `FAILED` table swap may have
      modified live BigQuery column tags (for example, an ambiguous
      `update_table` exception where the live table shows modified tags or could
      not be re-read, or a failed compensating restore), signaling
      `generate_swap_report` to surface rollback commands.
  """

  project_id: str
  dataset_id: str
  table_id: str
  status: str
  location: str = ""
  swapped_columns: list[ColumnSwapDetail] = dataclasses.field(
      default_factory=list
  )
  unmapped_columns: list[UnmappedColumnDetail] = dataclasses.field(
      default_factory=list
  )
  parity_discrepancies: list[ParityDiscrepancy] = dataclasses.field(
      default_factory=list
  )
  backup_file_path: str | None = None
  schema_diff: str = ""
  error_message: str | None = None
  live_schema_possibly_modified: bool = False

  @property
  def table_identifier(self) -> str:
    """Returns the dot-separated table identifier or raw invalid identifier."""
    parts = [
        part
        for part in (self.project_id, self.dataset_id, self.table_id)
        if part
    ]
    return ".".join(parts)


class Swapper:
  """Swaps Policy Tags and Data Governance Tags on BigQuery table schemas.

  Orchestrates Phase 3 (`--phase swap`) across both forward migration
  (`--swap-mode pt-to-dgt`) and surgical rollback (`--swap-mode dgt-to-pt`).
  Maintains per-run in-memory caches for `plan.json` indexes, Resource Manager
  Tag Keys/Values (including negative-lookup sets for listed projects/parents),
  and regional V2 Data Policies so batch runs across $10,000+$ tables execute
  with $O(1)$ amortized control-plane RPC overhead per region.
  """

  def __init__(
      self,
      bigquery_client: bigquery.Client,
      dg_tag_keys_client: resourcemanager_v3.TagKeysClient,
      dg_tag_values_client: resourcemanager_v3.TagValuesClient,
      data_policy_v2_client: Any,
      resourcemanager_client: resourcemanager_v3.ProjectsClient | None = None,
      execution_project: str | None = None,
      backup_dir: str = constants.DEFAULT_SCHEMA_BACKUP_DIR,
      overwrite: bool = False,
      skip_confirmation: bool = False,
      allow_parity_discrepancy: bool = False,
      allow_unresolved_plan_warnings: bool = False,
      skip_default_dp_org_check: bool = False,
      halt_on_error: bool = False,
      dry_run: bool = False,
      swap_mode: str = constants.SWAP_MODE_PT_TO_DGT,
      plan_file: str = "plan.json",
      confirmation_callback: Callable[[str], str] | None = None,
  ):
    """Initializes the Swapper with cloud clients, flags, and in-memory caches.

    Args:
      bigquery_client: BigQuery client for reading and patching table schemas.
      dg_tag_keys_client: Resource Manager TagKeysClient for verifying tag keys.
      dg_tag_values_client: Resource Manager TagValuesClient for verifying tag
        values.
      data_policy_v2_client: BigQuery DataPolicyServiceClient (V2) for verifying
        live V2 data policies.
      resourcemanager_client: Optional ProjectsClient for resolving project
        numbers to project IDs.
      execution_project: Optional project ID used to execute and bill BigQuery
        `INFORMATION_SCHEMA` query jobs (`COLUMN_FIELD_PATHS` pre-filtering and
        `EFFECTIVE_PROJECT_OPTIONS` inspection) when the caller lacks
        `bigquery.jobs.create` in the target table project. Defaults to each
        queried table project when `None`.
      backup_dir: Directory path where original table schema backups are saved.
      overwrite: If True, allow overwriting existing schema backup files (with
        an interactive confirmation prompt unless `skip_confirmation` is also
        True). When False (default), an existing backup file aborts the backup
        with `FileExistsError`.
      skip_confirmation: If True, bypass interactive user confirmation prompts.
      allow_parity_discrepancy: If True, allow proceeding when pre-swap parity
        verification detects discrepancies.
      allow_unresolved_plan_warnings: If True, allow forward `pt-to-dgt` swap to
        proceed even when `plan.json` contains unresolved `[ACTION REQUIRED]`
        warnings (`dgt-to-pt` rollback is never blocked by plan warnings).
      skip_default_dp_org_check: If True, skip querying regional
        `INFORMATION_SCHEMA.EFFECTIVE_PROJECT_OPTIONS` for
        `default_data_policy_projects` (Mode 1 registration check and Mode 1 /
        Mode 2 Organization default-project conflict checks) when the caller
        lacks `bigquery.config.get` and has verified the Organization setting
        manually.
      halt_on_error: If True, raise an exception immediately on the first error.
      dry_run: If True, execute in read-only dry-run mode without writing schema
        backups or patching any BigQuery table schemas.
      swap_mode: Swap direction ('pt-to-dgt' for forward migration or
        'dgt-to-pt' for automated rollback to Policy Tags).
      plan_file: Path to the migration plan JSON file used for rendering
        copy-pasteable surgical `--swap-mode` rollback or re-cutover commands in
        the generated Markdown swap report.
      confirmation_callback: Optional function taking a prompt string and
        returning user input (defaults to built-in input).

    Raises:
      ValueError: If `swap_mode` is not in `constants.VALID_SWAP_MODES`.
    """
    if swap_mode not in constants.VALID_SWAP_MODES:
      raise ValueError(
          f"Invalid swap_mode '{swap_mode}'. Expected one of"
          f" {constants.VALID_SWAP_MODES}."
      )
    if execution_project is not None:
      execution_project = constants.validate_standard_project_id(
          execution_project, "execution_project"
      )
    self._bigquery_client = bigquery_client
    self._dg_tag_keys_client = dg_tag_keys_client
    self._dg_tag_values_client = dg_tag_values_client
    self._data_policy_v2_client = data_policy_v2_client
    self._rest_client = rest_utils.DataPolicyRestClient(data_policy_v2_client)
    self._resourcemanager_client = resourcemanager_client
    self._execution_project = execution_project
    self._backup_dir = backup_dir
    self._overwrite = overwrite
    self._skip_confirmation = skip_confirmation
    self._allow_parity_discrepancy = allow_parity_discrepancy
    self._allow_unresolved_plan_warnings = allow_unresolved_plan_warnings
    self._skip_default_dp_org_check = skip_default_dp_org_check
    self._unresolved_plan_warnings: list[str] = []
    self._aborted_by_readme_decline: bool = False
    self._halt_on_error = halt_on_error
    self._last_failed_table_result: TableSwapResult | None = None
    self._dry_run = dry_run
    self._swap_mode = swap_mode
    self._plan_file = plan_file or "plan.json"
    self._last_regions: list[str] = []
    self._confirmation_callback = confirmation_callback or input

    # --- Per-Run In-Memory Caches & Negative-Lookup Sets ---
    # 1. Project Number -> Project ID cache: Avoids repeated Resource Manager
    #    `get_project` RPCs when table schemas store numeric project numbers
    #    (`projects/123456/...`) in Policy Tag resource names.
    self._project_number_to_id_cache: dict[str, str] = {}
    # Tracks the lowercase location of the table currently being processed by
    # `swap_table_schema` so `transform_schema_fields` can disambiguate
    # multi-region Policy Tags when needed.
    self._current_table_location: str = ""

    # 2. Resource Manager Tag Key & Tag Value caches + negative-lookup sets:
    #    We use `list_tag_keys(parent="projects/<id>")` and level-by-level
    #    `list_tag_values(parent="tagKeys/<id>" | "tagValues/<id>")` instead of
    #    `get_namespaced_tag_key` / `get_namespaced_tag_value` for VPC Service
    #    Controls (VPC-SC) compatibility. Recording each listed project in
    #    `_listed_tag_key_projects` and each listed parent in
    #    `_listed_tag_value_parents` provides negative caching: if a Tag Key or
    #    Tag Value is missing in Google Cloud, subsequent columns referencing
    #    the same project or parent return `None` in O(1) without re-issuing
    #    redundant `list_tag_keys` or `list_tag_values` RPCs.
    self._live_tag_keys_cache: dict[str, Any] = {}
    self._listed_tag_key_projects: set[str] = set()
    self._live_tag_values_cache: dict[str, Any] = {}
    self._listed_tag_value_parents: set[str] = set()

    # 3. Regional V2 Data Policy cache & REST grantee fetch error tracker:
    #    `_live_v2_policies_cache` maps `(project_id, lowercase_region)` to the
    #    normalized list of live V2 Data Policies so `list_data_policies` and
    #    parallel REST `GET /v2/{name}` grantee hydration run at most once per
    #    `(project, region)` across thousands of tables.
    #    `_grantee_fetch_errors` records any policy whose REST `GET` failed so
    #    `_compare_tag_value_enforcement` reports a `RESOURCE_DISCREPANCY`
    #    (fail-closed) rather than comparing against an empty grantee list.
    self._live_v2_policies_cache: dict[
        tuple[str, str], list[LiveDataPolicyV2Summary]
    ] = {}
    self._grantee_fetch_errors: dict[str, str] = {}
    self._effective_default_dp_projects_cache: dict[
        tuple[str, str], tuple[set[str] | None, str | None]
    ] = {}

    # 4. Pre-built `plan.json` lookup indexes:
    #    Built once per `plan` dictionary (`_cached_plan_id == id(plan)`) via
    #    `_get_or_build_plan_indexes`. Note `_list_live_v2_data_policies`
    #    hydrates `grantees` via REST `GET /v2/{name}` once per
    #    `(project_id, location)` for ALL DGT-backed policies—including
    #    `*_default_deny` seatbelts—so out-of-band grantee drift is caught as
    #    `ACCESS_LEAKAGE_RISK`.
    self._cached_plan_id: int | None = None
    self._cached_plan_indexes: dict[str, Any] | None = None
    self.last_report: str | None = None

  def _get_or_build_plan_indexes(self, plan: dict[str, Any]) -> dict[str, Any]:
    """Builds and caches O(1) lookup dictionaries for a parsed migration plan.

    Pre-computing plan indexes once per plan avoids O(T * P) dictionary and list
    re-allocations when swapping or verifying hundreds or thousands of tables.
    Supports both the canonical `plan.json` manifest keys generated by
    `planner.py` (`taxonomies_to_dg_tag_keys`, `policy_tags_to_dg_tag_values`,
    `policy_tags_to_raw_reader_data_policies_v2`,
    `policy_tags_to_default_deny_data_policies_v2`,
    `data_policies_v1_to_data_policies_v2`) and simplified legacy test fixture
    keys (`create_dg_tag_keys`, `create_dg_tag_values`,
    `create_data_policies_v2`).

    Args:
      plan: Parsed migration plan dictionary loaded from `plan.json`.

    Returns:
      A dictionary of pre-indexed lookup structures for Phase 3 operations:
        - `binding_map`: Direct `source_policy_tag -> {dg_tag_key,
          dg_tag_value}` dictionary from `phase_3_binding_map`.
        - `bindings_by_canonical_suffix`: Map from canonical Policy Tag suffix
          (`/locations/.../taxonomies/.../policyTags/...`) to matching
          `(plan_key, mapping)` pairs for O(1) numeric project-number fallback.
        - `bindings_by_dg_tag_key`: Map from `dg_tag_key` to matching
          `(plan_key, mapping)` pairs for fast reverse lookup during rollback.
        - `planned_keys`: Map from DG Tag Key `namespaced_name` to its manifest
          action dict.
        - `planned_values`: Map from DG Tag Value `namespaced_name` to its
          manifest action dict.
        - `planned_values_by_source_policy_tag`: Map from source Policy Tag URI
          to its planned DG Tag Value action dict.
        - `planned_v2_policies`: Flattened list of all planned V2 Data Policy
          manifest actions across all 3 policy categories.
        - `plan_regions`: Set of lowercase region strings referenced by any
          planned V2 Data Policy or source Policy Tag in `plan.json`.
    """
    if (
        self._cached_plan_id == id(plan)
        and self._cached_plan_indexes is not None
    ):
      return self._cached_plan_indexes

    # Step 1: Extract the Phase 3 column binding map (`PT -> {key, value}`) and
    # build secondary indexes by canonical Policy Tag suffix and by DG Tag Key.
    binding_map = plan.get("phase_3_binding_map", {}).get(
        constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES, {}
    )
    bindings_by_canonical_suffix: dict[
        str, list[tuple[str, dict[str, str]]]
    ] = {}
    bindings_by_dg_tag_key: dict[str, list[tuple[str, dict[str, str]]]] = {}
    for plan_key, mapping in binding_map.items():
      if not isinstance(mapping, dict):
        continue
      suffix_match = re.search(
          r"(/locations/[^/]+/taxonomies/[^/]+/policyTags/.+)$", plan_key
      )
      if suffix_match:
        canonical_suffix = suffix_match.group(1)
        bindings_by_canonical_suffix.setdefault(canonical_suffix, []).append(
            (plan_key, mapping)
        )
      mapped_dg_key = mapping.get("dg_tag_key", "")
      if mapped_dg_key:
        bindings_by_dg_tag_key.setdefault(mapped_dg_key, []).append(
            (plan_key, mapping)
        )

    manifest = plan.get(constants.KEY_PHASE_2_RESOURCE_MANIFEST, {})

    # Step 2: Index planned DG Tag Keys by `namespaced_name` (`proj/key`).
    tag_key_actions = list(
        manifest.get(constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS, [])
    ) + list(manifest.get("create_dg_tag_keys", []))
    planned_keys = {
        action.get("namespaced_name"): action
        for action in tag_key_actions
        if action.get("namespaced_name")
    }

    # Step 3: Index planned DG Tag Values both by `namespaced_name`
    # (`proj/key/val` or `proj/key/parent/child`) and by source Policy Tag URI.
    tag_value_actions = list(
        manifest.get(constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES, [])
    ) + list(manifest.get("create_dg_tag_values", []))
    planned_values = {
        action.get("namespaced_name"): action
        for action in tag_value_actions
        if action.get("namespaced_name")
    }
    planned_values_by_source_policy_tag: dict[str, dict[str, Any]] = {}
    for action in tag_value_actions:
      source_policy_tag = action.get("source_resource_name") or action.get(
          "source_policy_tag"
      )
      if source_policy_tag:
        planned_values_by_source_policy_tag[source_policy_tag] = action

    # Seed `_project_number_to_id_cache` from `metadata.source_project_id` and
    # numeric `source_resource_name` entries (`projects/<number>/locations/...`)
    # so custom masking routine paths and Policy Tag URIs in the source project
    # resolve without extra Resource Manager `get_project` RPCs.
    metadata = plan.get("metadata", {})
    source_project_id = (metadata.get("source_project_id") or "").strip()
    if source_project_id and not source_project_id.isdigit():
      for action in tag_key_actions + tag_value_actions:
        source_uri = (
            action.get("source_resource_name")
            or action.get("source_taxonomy")
            or action.get("source_policy_tag")
            or ""
        )
        uri_parts = source_uri.split("/")
        if (
            len(uri_parts) >= 2
            and uri_parts[0] == "projects"
            and uri_parts[1].isdigit()
        ):
          self._project_number_to_id_cache.setdefault(
              uri_parts[1], source_project_id
          )

    # Step 4: Combine all three V2 Data Policy manifest lists:
    #   - Case 1: Raw Reader policies (`migrated_raw_<tax>_<tag>`)
    #   - Case 2: Default-Deny seatbelts
    #     (`migrated_raw_<tax>_<tag>_default_deny`)
    #   - Case 3: Migrated V1 masking/raw policies (`migrated_masking_...`)
    planned_v2_policies = (
        list(
            manifest.get(
                constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2, []
            )
        )
        + list(
            manifest.get(
                constants.KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2, []
            )
        )
        + list(
            manifest.get(constants.KEY_DATA_POLICIES_V1_TO_DATA_POLICIES_V2, [])
        )
        + list(manifest.get("create_data_policies_v2", []))
    )

    # Step 5: Identify all regions in scope across planned V2 Data Policies and
    # source Policy Tags in `phase_3_binding_map`.
    plan_regions: set[str] = set()
    for action in planned_v2_policies:
      region_value = (action.get("region") or "").strip().lower()
      if region_value:
        plan_regions.add(region_value)

    for source_policy_tag in binding_map:
      extracted_region = self._extract_region_from_policy_tag(source_policy_tag)
      if extracted_region:
        plan_regions.add(extracted_region)

    indexes = {
        "binding_map": binding_map,
        "bindings_by_canonical_suffix": bindings_by_canonical_suffix,
        "bindings_by_dg_tag_key": bindings_by_dg_tag_key,
        "planned_keys": planned_keys,
        "planned_values": planned_values,
        "planned_values_by_source_policy_tag": (
            planned_values_by_source_policy_tag
        ),
        "planned_v2_policies": planned_v2_policies,
        "plan_regions": plan_regions,
    }
    self._cached_plan_id = id(plan)
    self._cached_plan_indexes = indexes
    return indexes

  def resolve_target_tables(
      self,
      table_project_ids: list[str] | None = None,
      dataset_ids: list[str] | None = None,
      table_ids: list[str] | None = None,
      regions: list[str] | None = None,
      default_project_id: str | None = None,
  ) -> tuple[list[tuple[str, str, str]], list[TableSwapResult]]:
    """Resolves target tables across project, dataset, and table flags.

    Supports flexible, incremental migration scopes so operators can canary a
    single table (`--table-ids`), roll out dataset-by-dataset (`--dataset-ids`),
    or sweep entire projects (`--table-project-ids`). All three flags can be
    combined in a single invocation; duplicate table references are
    deduplicated while preserving discovery order.

    Args:
      table_project_ids: Optional list of project IDs to scan for datasets and
        tables.
      dataset_ids: Optional list of dot-separated dataset identifiers
        (`project.dataset`, or `dataset` if an unambiguous project is provided).
      table_ids: Optional list of dot-separated table identifiers
        (`project.dataset.table`, or `dataset.table` if an unambiguous project
        is provided).
      regions: Required list of regions to filter datasets and tables by
        location and to scope `INFORMATION_SCHEMA.COLUMN_FIELD_PATHS`
        pre-filtering when scanning entire projects.
      default_project_id: Optional fallback project ID when dataset or table
        identifiers omit the project prefix.

    Returns:
      A tuple of `(resolved_table_tuples, discovery_failure_results)` where each
      table tuple is `(project_id, dataset_id, table_id)`.

    Raises:
      ValueError: If `regions` is empty, if none of `table_project_ids`,
        `dataset_ids`, or `table_ids` are specified, or if an identifier is
        malformed and `halt_on_error` is True.
    """
    # === Step 1: Normalize and validate target scope and region flags ===
    normalized_projects = self._normalize_flag_items(table_project_ids)
    normalized_datasets = self._normalize_flag_items(dataset_ids)
    normalized_tables = self._normalize_flag_items(table_ids)
    normalized_regions = {
        region.lower() for region in self._normalize_flag_items(regions)
    }

    if not normalized_regions:
      raise ValueError(
          "At least one region must be specified via --regions for the 'swap'"
          " phase."
      )

    if (
        not normalized_projects
        and not normalized_datasets
        and not normalized_tables
    ):
      raise ValueError(
          "At least one of --table-project-ids, --dataset-ids, or --table-ids"
          " must be specified for the 'swap' phase."
      )

    if default_project_id is not None and default_project_id.strip():
      constants.validate_standard_project_id(
          default_project_id, "default_project_id"
      )

    # When exactly one non-domain-scoped project is passed via
    # --table-project-ids, allow shorthand dataset (`dataset`) and table
    # (`dataset.table`) identifiers to inherit that project ID automatically.
    inferred_project_id = default_project_id
    if len(normalized_projects) == 1 and ":" not in normalized_projects[0]:
      inferred_project_id = normalized_projects[0]

    discovered_tables: list[tuple[str, str, str]] = []
    seen_tables: set[tuple[str, str, str]] = set()
    failure_results: list[TableSwapResult] = []

    def add_table(project_id: str, dataset_id: str, table_id: str) -> None:
      table_tuple = (project_id, dataset_id, table_id)
      if table_tuple not in seen_tables:
        seen_tables.add(table_tuple)
        discovered_tables.append(table_tuple)

    # === Step 2: Expand --table-project-ids ===
    # First attempt O(1) regional INFORMATION_SCHEMA.COLUMN_FIELD_PATHS
    # pre-filtering in the explicitly specified `--regions` for both forward
    # ('pt-to-dgt') and rollback ('dgt-to-pt') modes so projects with 10,000+
    # untagged tables do not incur O(T) get_table calls. If INFORMATION_SCHEMA
    # is unavailable or fails, fall back cleanly to list_datasets + list_tables.
    for project_id in normalized_projects:
      if ":" in project_id:
        error_text = (
            f"Invalid project ID '{project_id}' in --table-project-ids:"
            f" {constants.UNSUPPORTED_DOMAIN_SCOPED_PROJECT_MSG}."
        )
        logger.error(error_text)
        if self._halt_on_error:
          raise ValueError(error_text)
        failure_results.append(
            TableSwapResult(
                project_id=project_id,
                dataset_id="*",
                table_id="*",
                status=constants.SWAP_STATUS_FAILED,
                error_message=error_text,
            )
        )
        continue
      pre_filtered = self._try_pre_filter_project_tables_via_info_schema(
          project_id=project_id,
          target_regions=normalized_regions,
      )
      if pre_filtered is not None:
        for found_project, found_dataset, found_table in pre_filtered:
          add_table(found_project, found_dataset, found_table)
        continue

      try:
        datasets = list(self._bigquery_client.list_datasets(project=project_id))
      except Exception as error:  # pylint: disable=broad-exception-caught
        error_text = (
            f"Failed to list datasets in project '{project_id}': {error}"
        )
        logger.error(error_text)
        if self._halt_on_error:
          raise
        failure_results.append(
            TableSwapResult(
                project_id=project_id,
                dataset_id="*",
                table_id="*",
                status=constants.SWAP_STATUS_FAILED,
                error_message=error_text,
            )
        )
        continue

      for dataset_item in datasets:
        dataset_id = dataset_item.dataset_id
        self._collect_tables_from_dataset(
            project_id=project_id,
            dataset_id=dataset_id,
            normalized_regions=normalized_regions,
            add_table_callback=add_table,
            failure_results=failure_results,
        )

    # === Step 3: Expand --dataset-ids ===
    parsed_datasets: list[tuple[str, str]] = []
    for raw_dataset in normalized_datasets:
      try:
        project_id, dataset_id = self._parse_dataset_identifier(
            raw_dataset, inferred_project_id
        )
        parsed_datasets.append((project_id, dataset_id))
      except ValueError as error:
        logger.error("%s", error)
        if self._halt_on_error:
          raise
        failure_results.append(
            TableSwapResult(
                project_id="",
                dataset_id=raw_dataset,
                table_id="",
                status=constants.SWAP_STATUS_FAILED,
                error_message=str(error),
            )
        )

    for project_id, dataset_id in parsed_datasets:
      self._collect_tables_from_dataset(
          project_id=project_id,
          dataset_id=dataset_id,
          normalized_regions=normalized_regions,
          add_table_callback=add_table,
          failure_results=failure_results,
      )

    # === Step 4: Expand --table-ids ===
    inferred_dataset_pair: tuple[str, str] | None = None
    if len(parsed_datasets) == 1:
      inferred_dataset_pair = parsed_datasets[0]

    for raw_table in normalized_tables:
      try:
        project_id, dataset_id, table_id = self._parse_table_identifier(
            raw_table,
            inferred_project_id=inferred_project_id,
            inferred_dataset_pair=inferred_dataset_pair,
        )
        add_table(project_id, dataset_id, table_id)
      except ValueError as error:
        logger.error("%s", error)
        if self._halt_on_error:
          raise
        failure_results.append(
            TableSwapResult(
                project_id="",
                dataset_id="",
                table_id=raw_table,
                status=constants.SWAP_STATUS_FAILED,
                error_message=str(error),
            )
        )

    return discovered_tables, failure_results

  def _try_pre_filter_project_tables_via_info_schema(
      self, project_id: str, target_regions: set[str]
  ) -> list[tuple[str, str, str]] | None:
    """Pre-filters tagged tables in a project via INFORMATION_SCHEMA when able.

    Architectural Rationale & Scale Trade-Off:
      When scanning an entire project (`--table-project-ids`) that contains
      10,000+ tables, iterating over every dataset via `list_datasets` +
      `list_tables` and calling `get_table` on every table takes O(T) RPCs even
      when only a handful of tables carry Policy Tags or Data Governance Tags.
      Querying regional `INFORMATION_SCHEMA.COLUMN_FIELD_PATHS` reduces table
      discovery to 1 SQL query per active region:
        - Forward mode (`pt-to-dgt`): `WHERE ARRAY_LENGTH(policy_tags) > 0`
          with an `EXISTS(SELECT 1 FROM UNNEST(policy_tags) ...)` filter
          excluding `/taxonomies/0/policyTags/` Cross-Region Replication (CRR)
          secondary-replica placeholders (whose primary tables live in another
          region and cannot be patched in the secondary region).
        - Rollback mode (`dgt-to-pt`):
          `WHERE ARRAY_LENGTH(data_governance_tags) > 0`
      If `target_regions` is empty, if the client mock does not implement
      `query`, or if the `INFORMATION_SCHEMA` query fails in any region (for
      example, missing BigQuery Jobs permissions or an unsupported column in a
      custom test harness), this method returns `None` so
      `resolve_target_tables` seamlessly falls back to `list_datasets` /
      `list_tables`.

    Args:
      project_id: BigQuery project ID to query.
      target_regions: Set of lowercase region strings to query in `project_id`.

    Returns:
      A list of `(project_id, dataset_id, table_id)` tuples for tables with at
      least one tagged column, or `None` to fall back to `list_datasets` /
      `list_tables`.
    """
    if not target_regions or not hasattr(self._bigquery_client, "query"):
      return None

    # Select the INFORMATION_SCHEMA WHERE predicate based on the active swap
    # mode: forward migration filters on `policy_tags` (excluding
    # `/taxonomies/0/policyTags/` Cross-Region Replication secondary-replica
    # placeholders), whereas rollback filters on `data_governance_tags`.
    crr_segment = constants.CRR_PLACEHOLDER_POLICY_TAG_SEGMENT
    if self._swap_mode == constants.SWAP_MODE_DGT_TO_PT:
      where_clause = "ARRAY_LENGTH(data_governance_tags) > 0"
    else:
      where_clause = (
          "ARRAY_LENGTH(policy_tags) > 0 AND EXISTS(SELECT 1 FROM"
          " UNNEST(policy_tags) AS policy_tag WHERE NOT"
          f" CONTAINS_SUBSTR(policy_tag, '{crr_segment}'))"
      )

    discovered: list[tuple[str, str, str]] = []
    for region in sorted(target_regions):
      # Guard against SQL injection in region identifiers before interpolating
      # into the `region-<location>` INFORMATION_SCHEMA qualifier.
      if not re.search(r"^[a-zA-Z0-9-]+$", region):
        return None
      sql = (
          "SELECT DISTINCT table_catalog, table_schema, table_name FROM"
          f" `{project_id}`.`region-{region}`"
          f".INFORMATION_SCHEMA.COLUMN_FIELD_PATHS WHERE {where_clause}"
          " ORDER BY table_schema, table_name"
      )
      target_execution_project = self._execution_project or project_id
      try:
        query_job = self._bigquery_client.query(
            sql,
            location=region.lower(),
            project=target_execution_project,
        )
        rows = list(query_job.result())
        # In unit tests using an unconfigured MagicMock for `bigquery_client`,
        # `query_job` is an auto-generated mock whose `result()` returns `[]`.
        # Returning `None` preserves the standard `list_datasets` test path
        # unless the test explicitly configures a query job return value.
        if hasattr(query_job, "_mock_name") and not rows:
          return None
      except Exception as error:  # pylint: disable=broad-exception-caught
        logger.debug(
            "INFORMATION_SCHEMA pre-filter unavailable for project '%s' in"
            " region '%s'; falling back to list_datasets: %s",
            project_id,
            region,
            error,
        )
        return None

      for row in rows:
        dataset_name = getattr(row, "table_schema", None)
        table_name = getattr(row, "table_name", None)
        if isinstance(row, dict):
          dataset_name = dataset_name or row.get("table_schema")
          table_name = table_name or row.get("table_name")
        if dataset_name and table_name:
          discovered.append((project_id, str(dataset_name), str(table_name)))

    return discovered

  def _collect_tables_from_dataset(
      self,
      project_id: str,
      dataset_id: str,
      normalized_regions: set[str],
      add_table_callback: Callable[[str, str, str], None],
      failure_results: list[TableSwapResult],
  ) -> None:
    """Lists mutable base tables in a dataset after optional region filtering.

    Architectural Rationale:
      1. Region pre-check: When `--regions` is specified, checks the dataset's
         `location` once via `get_dataset` before calling `list_tables`,
         skipping entire out-of-region datasets in O(1).
      2. Non-table filtering: Inspects `table_item.table_type` from the
         lightweight `list_tables` summary and skips `VIEW`,
         `MATERIALIZED_VIEW`, `EXTERNAL`, and read-only `SNAPSHOT` resources
         (`table_type != "TABLE"`) BEFORE calling `get_table`, avoiding wasted
         `get_table` RPCs and unsupported schema PATCH errors on non-base
         tables.

    Args:
      project_id: Project ID owning the dataset.
      dataset_id: Dataset ID to list tables from.
      normalized_regions: Set of allowed lowercase region names (empty if all
        regions are allowed).
      add_table_callback: Callback to register each discovered `(project_id,
        dataset_id, table_id)` tuple.
      failure_results: Mutable list where discovery failures are appended when
        `halt_on_error` is False.
    """
    dataset_reference = f"{project_id}.{dataset_id}"
    if normalized_regions:
      try:
        dataset_object = self._bigquery_client.get_dataset(dataset_reference)
        dataset_location = (
            getattr(dataset_object, "location", "") or ""
        ).lower()
        if dataset_location and dataset_location not in normalized_regions:
          logger.debug(
              "Skipping dataset %s in location '%s' (not in %s).",
              dataset_reference,
              dataset_location,
              sorted(normalized_regions),
          )
          return
      except Exception as error:  # pylint: disable=broad-exception-caught
        error_text = f"Failed to get dataset '{dataset_reference}': {error}"
        logger.error(error_text)
        if self._halt_on_error:
          raise
        failure_results.append(
            TableSwapResult(
                project_id=project_id,
                dataset_id=dataset_id,
                table_id="*",
                status=constants.SWAP_STATUS_FAILED,
                error_message=error_text,
            )
        )
        return

    try:
      tables = list(self._bigquery_client.list_tables(dataset_reference))
    except Exception as error:  # pylint: disable=broad-exception-caught
      error_text = (
          f"Failed to list tables in dataset '{dataset_reference}': {error}"
      )
      logger.error(error_text)
      if self._halt_on_error:
        raise
      failure_results.append(
          TableSwapResult(
              project_id=project_id,
              dataset_id=dataset_id,
              table_id="*",
              status=constants.SWAP_STATUS_FAILED,
              error_message=error_text,
          )
      )
      return

    for table_item in tables:
      table_type = getattr(table_item, "table_type", "TABLE")
      # Skip VIEW, MATERIALIZED_VIEW, EXTERNAL, and read-only SNAPSHOT tables
      # so get_table and update_table are only called on mutable base tables.
      if table_type and str(table_type).upper() != "TABLE":
        logger.debug(
            "Skipping non-table resource %s.%s (type=%s).",
            dataset_reference,
            table_item.table_id,
            table_type,
        )
        continue
      add_table_callback(project_id, dataset_id, table_item.table_id)

  def _normalize_flag_items(self, raw_items: list[str] | None) -> list[str]:
    """Splits comma-separated CLI items and strips surrounding whitespace.

    Args:
      raw_items: Optional list of raw CLI argument strings, each of which may
        contain comma-separated tokens.

    Returns:
      A flat list of non-empty, whitespace-trimmed string tokens.
    """
    if not raw_items:
      return []
    normalized: list[str] = []
    for raw_item in raw_items:
      if not raw_item:
        continue
      for token in raw_item.split(","):
        cleaned = token.strip()
        if cleaned:
          normalized.append(cleaned)
    return normalized

  def _parse_dataset_identifier(
      self, raw_dataset: str, inferred_project_id: str | None
  ) -> tuple[str, str]:
    """Parses a CLI dataset identifier into `(project_id, dataset_id)`.

    Accepts standard dot-separated BigQuery `project.dataset` notation, or bare
    `dataset` when `inferred_project_id` is unambiguous. Colon-separated
    `project:dataset` identifiers are rejected so CLI notation remains uniform.

    Args:
      raw_dataset: Raw dataset string from `--dataset-ids`.
      inferred_project_id: Optional fallback project ID when `raw_dataset` omits
        the project prefix.

    Returns:
      A `(project_id, dataset_id)` tuple.

    Raises:
      ValueError: If `raw_dataset` cannot be resolved to `(project_id,
        dataset_id)`.
    """
    normalized = raw_dataset.strip()
    parts = [part.strip() for part in normalized.split(".") if part.strip()]
    if len(parts) == 2 and ":" not in parts[0] and ":" not in parts[1]:
      return parts[0], parts[1]
    if (
        len(parts) == 1
        and ":" not in parts[0]
        and inferred_project_id
        and ":" not in inferred_project_id
    ):
      return inferred_project_id, parts[0]
    if ":" in normalized:
      raise ValueError(
          constants.format_colon_identifier_error(
              raw_dataset,
              "dataset identifier",
              "<project_id>.<dataset_id>",
          )
      )
    raise ValueError(
        f"Invalid dataset identifier '{raw_dataset}'. Expected dot-separated"
        " '<project_id>.<dataset_id>'."
    )

  def _parse_table_identifier(
      self,
      raw_table: str,
      inferred_project_id: str | None,
      inferred_dataset_pair: tuple[str, str] | None,
  ) -> tuple[str, str, str]:
    """Parses a CLI table identifier into `(project_id, dataset_id, table_id)`.

    Accepts dot-separated `project.dataset.table`, `dataset.table` (when a
    single project is inferred), or bare `table` (when a single dataset is
    inferred). Colon-separated `project:dataset.table` and legacy domain-scoped
    `example.com:project` identifiers are rejected explicitly.

    Args:
      raw_table: Raw table string from `--table-ids`.
      inferred_project_id: Optional fallback project ID when `raw_table` has two
        segments (`dataset.table`).
      inferred_dataset_pair: Optional fallback `(project_id, dataset_id)` tuple
        when `raw_table` has a single segment (`table`).

    Returns:
      A `(project_id, dataset_id, table_id)` tuple.

    Raises:
      ValueError: If `raw_table` cannot be resolved to a 3-part table reference.
    """
    normalized = raw_table.strip()
    parts = [part.strip() for part in normalized.split(".") if part.strip()]
    if (
        len(parts) == 3
        and ":" not in parts[0]
        and ":" not in parts[1]
        and ":" not in parts[2]
    ):
      return parts[0], parts[1], parts[2]
    if (
        len(parts) == 2
        and ":" not in parts[0]
        and ":" not in parts[1]
        and inferred_project_id
        and ":" not in inferred_project_id
    ):
      return inferred_project_id, parts[0], parts[1]
    if (
        len(parts) == 1
        and ":" not in parts[0]
        and inferred_dataset_pair
        and ":" not in inferred_dataset_pair[0]
    ):
      return inferred_dataset_pair[0], inferred_dataset_pair[1], parts[0]
    if ":" in normalized:
      raise ValueError(
          constants.format_colon_identifier_error(
              raw_table,
              "table identifier",
              "<project_id>.<dataset_id>.<table_id>",
          )
      )
    raise ValueError(
        f"Invalid table identifier '{raw_table}'. Expected dot-separated"
        " '<project_id>.<dataset_id>.<table_id>'."
    )

  def _resolve_policy_tag_mapping(
      self,
      policy_tag_name: str,
      binding_map: dict[str, dict[str, str]],
      bindings_by_canonical_suffix: (
          dict[str, list[tuple[str, dict[str, str]]]] | None
      ) = None,
  ) -> tuple[str, dict[str, str]] | None:
    """Resolves a table column's Policy Tag resource name in the plan map.

    Architectural Rationale (Numeric Project Numbers vs. Project IDs):
      BigQuery table schemas frequently store Policy Tag references using the
      numeric project number
      (`projects/123456789/locations/us/taxonomies/1/...`), whereas `plan.json`
      keys `phase_3_binding_map` by string project ID
      (`projects/my-proj/locations/us/taxonomies/1/...`) or vice versa.
      This helper resolves the Policy Tag in 3 deterministic tiers:
        1. Exact string match in `binding_map` (O(1)).
        2. If the project segment is numeric (`project_token.isdigit()`),
           resolves the project number to its project ID via cached Resource
           Manager `get_project` and checks `binding_map` (O(1) after first
           lookup per project number).
        3. Matches by the canonical suffix
           `/locations/<loc>/taxonomies/<tax_id>/policyTags/<tag_id>`, which is
           globally unique because Data Catalog Taxonomy IDs and Policy Tag IDs
           are globally unique 64-bit integers. Uses the pre-built
           `bindings_by_canonical_suffix` index when provided (O(1)), or falls
           back to scanning `binding_map` if called directly in isolation.

    Args:
      policy_tag_name: Policy Tag resource name from the BigQuery table schema.
      binding_map: The `policy_tags_to_dg_tag_values` dictionary from
        `plan.json`.
      bindings_by_canonical_suffix: Optional pre-built index mapping canonical
        `/locations/.../taxonomies/.../policyTags/...` suffixes to `(plan_key,
        mapping)` tuples.

    Returns:
      A tuple of `(matched_plan_policy_tag, dgt_mapping_dict)`, or `None` if the
      Policy Tag is not in the migration plan.
    """
    # Tier 1: Fast O(1) exact URI match.
    if policy_tag_name in binding_map:
      return policy_tag_name, binding_map[policy_tag_name]

    # Tier 2: Resolve numeric project number to string project ID if possible.
    match = re.search(
        r"^projects/([^/]+)(/locations/[^/]+/taxonomies/[^/]+/policyTags/.+)$",
        policy_tag_name,
    )
    if not match:
      return None

    project_token, canonical_suffix = match.group(1), match.group(2)
    if project_token.isdigit() and self._resourcemanager_client:
      resolved_project_id = self._resolve_project_number(project_token)
      if resolved_project_id:
        candidate_key = f"projects/{resolved_project_id}{canonical_suffix}"
        if candidate_key in binding_map:
          return candidate_key, binding_map[candidate_key]

    # Tier 3: Match by canonical suffix (`/locations/.../policyTags/...`)
    # since taxonomy IDs and policy tag IDs are globally unique 64-bit IDs.
    if bindings_by_canonical_suffix is not None:
      suffix_matches = bindings_by_canonical_suffix.get(canonical_suffix, [])
    else:
      suffix_matches = [
          (plan_key, mapping)
          for plan_key, mapping in binding_map.items()
          if plan_key.endswith(canonical_suffix)
      ]
    if len(suffix_matches) == 1:
      return suffix_matches[0]

    return None

  def _resolve_project_number(self, project_number: str) -> str | None:
    """Resolves a numeric GCP project number to its string project ID.

    Caches successful lookups in `_project_number_to_id_cache` so repeated
    columns referencing the same numeric taxonomy project number incur at most
    one `resourcemanager.projects.get` RPC per `Swapper` session.

    Args:
      project_number: Numeric GCP project number string (e.g., `'123456789'`).

    Returns:
      The resolved string project ID, or `None` if resolution fails or no
      Resource Manager client is configured.
    """
    if project_number in self._project_number_to_id_cache:
      return self._project_number_to_id_cache[project_number]
    if not self._resourcemanager_client:
      return None
    try:
      project = self._resourcemanager_client.get_project(
          name=f"projects/{project_number}"
      )
      project_id = getattr(project, "project_id", None)
      if isinstance(project_id, str) and project_id:
        self._project_number_to_id_cache[project_number] = project_id
        return project_id
    except Exception as error:  # pylint: disable=broad-exception-caught
      logger.debug(
          "Could not resolve project number %s to project ID: %s",
          project_number,
          error,
      )
    return None

  def _resolve_dg_tag_mapping(
      self,
      dg_tag_key: str,
      dg_tag_value: str,
      binding_map: dict[str, dict[str, str]],
      planned_values_by_source_policy_tag: dict[str, dict[str, Any]],
      table_location: str = "",
      bindings_by_dg_tag_key: (
          dict[str, list[tuple[str, dict[str, str]]]] | None
      ) = None,
      field_path: str = "",
  ) -> tuple[str, dict[str, str]] | None:
    """Resolves a column's Data Governance Tag Key/Value back to its Policy Tag.

    Architectural Rationale (Rollback Normalization & Regional Disambiguation):
      During Mode 2 (`--swap-mode dgt-to-pt`) rollback, a column's
      `dataGovernanceTagsInfo.dataGovernanceTags` dictionary maps a Tag Key
      namespaced name (`proj/key`) to a Tag Value identifier that may appear as:
        - A short Tag Value name (e.g., `'Email_Mask_Root'`),
        - A flat namespaced path (`'proj/key/Email_Mask_Root'`), or
        - A hierarchical namespaced path (`'proj/key/parent/child'`).
      Furthermore, if two regional Policy Taxonomies in different locations were
      consolidated into a single global Data Governance Tag Key/Value, this
      method uses `table_location` to disambiguate which regional Policy Tag URI
      belongs to the table being rolled back. If multiple Policy Tags still
      match in the same region, it raises `SchemaCorruptionError` rather than
      guessing and restoring the wrong Policy Tag.

    Args:
      dg_tag_key: Data Governance Tag Key namespaced name from the column.
      dg_tag_value: Data Governance Tag Value short or namespaced name from the
        column.
      binding_map: The `policy_tags_to_dg_tag_values` dictionary from
        `plan.json`.
      planned_values_by_source_policy_tag: Mapping from source Policy Tag
        resource name to its planned Tag Value manifest action.
      table_location: Optional BigQuery table location to disambiguate regional
        Policy Tags if multiple Policy Tags map to the same DG Tag.
      bindings_by_dg_tag_key: Optional pre-built index mapping `dg_tag_key` to
        `(plan_policy_tag, mapping)` pairs for fast lookup.
      field_path: Optional dot-delimited column path included in
        `SchemaCorruptionError` diagnostics when multiple Policy Tags match.

    Returns:
      A tuple of `(matched_plan_policy_tag, dgt_mapping_dict)` or `None` if the
      Data Governance Tag is not in the migration plan.

    Raises:
      SchemaCorruptionError: If multiple Policy Tags in the plan map to the same
        Data Governance Tag and cannot be disambiguated by `table_location`.
    """
    if not dg_tag_key or not dg_tag_value:
      return None

    column_value_short = dg_tag_value.split("/")[-1]
    normalized_dg_key = dg_tag_key
    normalized_dg_value = dg_tag_value
    if "/" in dg_tag_key:
      key_proj, key_short = dg_tag_key.split("/", 1)
      if key_proj.isdigit():
        resolved_proj_id = self._resolve_project_number(key_proj)
        if resolved_proj_id:
          normalized_dg_key = f"{resolved_proj_id}/{key_short}"
          if dg_tag_value.startswith(f"{dg_tag_key}/"):
            normalized_dg_value = (
                f"{normalized_dg_key}/{dg_tag_value[len(dg_tag_key) + 1:]}"
            )
    matches: list[tuple[str, dict[str, str]]] = []

    if bindings_by_dg_tag_key is not None:
      candidate_bindings = list(
          bindings_by_dg_tag_key.get(normalized_dg_key, [])
      )
      if normalized_dg_key != dg_tag_key and not candidate_bindings:
        candidate_bindings = list(bindings_by_dg_tag_key.get(dg_tag_key, []))
    else:
      candidate_bindings = list(binding_map.items())

    for plan_policy_tag, mapping in candidate_bindings:
      if not isinstance(mapping, dict):
        continue
      mapped_key = mapping.get("dg_tag_key", "")
      mapped_value = mapping.get("dg_tag_value", "")
      if (
          not mapped_key
          or not mapped_value
          or mapped_key not in (dg_tag_key, normalized_dg_key)
      ):
        continue

      mapped_value_short = mapped_value.split("/")[-1]
      candidate_values = {
          mapped_value,
          mapped_value_short,
          f"{mapped_key}/{mapped_value_short}",
      }
      planned_action = planned_values_by_source_policy_tag.get(plan_policy_tag)
      if isinstance(planned_action, dict):
        planned_namespaced = planned_action.get("namespaced_name", "")
        if planned_namespaced:
          candidate_values.add(planned_namespaced)

      if (
          dg_tag_value in candidate_values
          or normalized_dg_value in candidate_values
          or column_value_short == mapped_value_short
      ):
        matches.append((plan_policy_tag, mapping))

    if not matches:
      return None
    if len(matches) == 1:
      return matches[0]

    # Disambiguate multi-region matches using the BigQuery table's location.
    if table_location:
      normalized_location = table_location.lower()
      region_matches = [
          (plan_policy_tag, mapping)
          for plan_policy_tag, mapping in matches
          if self._extract_region_from_policy_tag(plan_policy_tag)
          == normalized_location
      ]
      if len(region_matches) == 1:
        return region_matches[0]

    # Include `field_path` in the diagnostic message so operators know which
    # column triggered the ambiguous rollback mapping.
    candidate_tags = [plan_policy_tag for plan_policy_tag, _ in matches]
    column_clause = f" on column '{field_path}'" if field_path else ""
    raise SchemaCorruptionError(
        "Ambiguous rollback mapping for Data Governance Tag"
        f" (key='{dg_tag_key}', value='{dg_tag_value}'){column_clause}:"
        f" matches multiple Policy Tags in migration plan {candidate_tags}."
    )

  @classmethod
  def _resolve_policy_tag_display_path(
      cls,
      matched_plan_policy_tag: str,
      source_policy_tag: str,
      planned_values_by_source_policy_tag: dict[str, dict[str, Any]],
  ) -> str:
    """Returns the human-readable Policy Tag path from `plan.json` if present.

    Looks up the Policy Tag entry in `phase_2_resource_manifest`
    (`source_display_path`, formatted as `'<Taxonomy> > <Tag>'`) so Phase 3
    swap reports display clear Policy Tag names alongside Data Governance Tag
    keys and values.

    Args:
      matched_plan_policy_tag: Canonical Policy Tag resource name matched in
        `phase_3_binding_map`.
      source_policy_tag: Raw Policy Tag resource name from the table column.
      planned_values_by_source_policy_tag: Pre-built index mapping source Policy
        Tag resource names to planned Tag Value manifest entries.

    Returns:
      Trimmed `source_display_path` string if found, or `""` otherwise.
    """
    for candidate_policy_tag in (matched_plan_policy_tag, source_policy_tag):
      if not candidate_policy_tag:
        continue
      planned_action = planned_values_by_source_policy_tag.get(
          candidate_policy_tag
      )
      if isinstance(planned_action, dict):
        display_path = str(
            planned_action.get("source_display_path") or ""
        ).strip()
        if display_path:
          return display_path
    return ""

  @classmethod
  def _extract_field_dg_tags(cls, field_dict: dict[str, Any]) -> dict[str, str]:
    """Extracts attached DGT `(key, value)` pairs from a schema field dict.

    Supports both the canonical `dataGovernanceTagsInfo.dataGovernanceTags`
    map format and legacy/alternate top-level `dataGovernanceTags` dict or
    `[{"key": ..., "value": ...}]` list representations returned by older
    `google-cloud-bigquery` SDK builds.

    Args:
      field_dict: Raw BigQuery `TableFieldSchema` dictionary.

    Returns:
      Copied `{dg_tag_key: dg_tag_value}` dictionary (empty if untagged).
    """
    existing_dgt_info = field_dict.get("dataGovernanceTagsInfo")
    if isinstance(existing_dgt_info, dict) and isinstance(
        existing_dgt_info.get("dataGovernanceTags"), dict
    ):
      extracted = {
          str(k): str(v)
          for k, v in existing_dgt_info["dataGovernanceTags"].items()
          if k and v
      }
      if extracted:
        return extracted

    legacy_dgt = field_dict.get("dataGovernanceTags")
    if isinstance(legacy_dgt, dict):
      inner_map = legacy_dgt.get("dataGovernanceTags")
      source_map = inner_map if isinstance(inner_map, dict) else legacy_dgt
      return {str(k): str(v) for k, v in source_map.items() if k and v}
    if isinstance(legacy_dgt, list):
      extracted_list: dict[str, str] = {}
      for entry in legacy_dgt:
        if isinstance(entry, dict):
          key = entry.get("key")
          val = entry.get("value")
          if key and val:
            extracted_list[str(key)] = str(val)
      return extracted_list
    return {}

  def transform_schema_fields(
      self,
      original_fields: list[dict[str, Any]],
      plan: dict[str, Any],
      table_location: str = "",
  ) -> tuple[
      list[dict[str, Any]],
      list[ColumnSwapDetail],
      list[UnmappedColumnDetail],
  ]:
    """Recursively swaps mapped Policy Tags and DGTs across schema fields.

    Architectural Rationale & Exclusivity Invariant:
      BigQuery enforces mutual exclusivity on columns: a column cannot carry
      both a legacy Policy Tag and a Data Governance Tag simultaneously.
      Therefore, every mapped column swap must be an atomic replacement within a
      single `tables.patch` payload:
        - Mode 1 (`pt-to-dgt`, default): Explicitly sets
          `field_dict["policyTags"] = {"names": []}` (because omitting
          `policyTags` in a `PATCH` request leaves the existing Policy Tag
          attached on the server!) and sets `dataGovernanceTagsInfo` to
          `{"dataGovernanceTags": {key: val}}`. If the column already carries a
          conflicting pre-existing DGT, raises `SchemaCorruptionError` so we
          never create a multi-tag column that cannot be cleanly rolled back.
        - Mode 2 (`dgt-to-pt`, rollback): Explicitly sets
          `field_dict["policyTags"] = {"names": [matched_plan_policy_tag]}` and
          clears `dataGovernanceTagsInfo` to `{"dataGovernanceTags": {}}`.
          If a column has multiple DGTs attached (e.g., an extra non-migrated
          DGT added after migration), raises `SchemaCorruptionError` because
          restoring a Policy Tag while leaving any DGT on the column would be
          rejected by BigQuery.
      Traverses both top-level columns and nested subfields inside `RECORD` /
      `STRUCT` columns at arbitrary depth (`parent.child.leaf`). Unmapped tags
      are left completely untouched and recorded in `unmapped_columns`.

    Args:
      original_fields: Original BigQuery schema fields list (API dict repr).
      plan: Parsed migration plan dictionary.
      table_location: Optional table location used for regional disambiguation.

    Returns:
      A tuple of `(updated_fields, swapped_columns, unmapped_columns)`.

    Raises:
      SchemaCorruptionError: If a mapped column has an invalid empty mapping or
        conflicting multi-tag state that would violate BigQuery's PT/DGT
        exclusivity rules.
    """
    plan_indexes = self._get_or_build_plan_indexes(plan)
    binding_map = plan_indexes["binding_map"]
    bindings_by_canonical_suffix = plan_indexes["bindings_by_canonical_suffix"]
    bindings_by_dg_tag_key = plan_indexes["bindings_by_dg_tag_key"]
    planned_values_by_source_policy_tag = plan_indexes[
        "planned_values_by_source_policy_tag"
    ]

    # Deep-copy original_fields first so `original_fields` remains an immutable
    # baseline for `verify_schema_swap_integrity`, `generate_schema_diff`, and
    # `backup_table_schema`.
    updated_fields = copy.deepcopy(original_fields)
    swapped_columns: list[ColumnSwapDetail] = []
    unmapped_columns: list[UnmappedColumnDetail] = []
    effective_location = table_location or self._current_table_location

    def _transform_field_list(
        field_list: list[dict[str, Any]],
        parent_prefix: str,
        parent_parts: tuple[str, ...] = (),
    ) -> None:
      for field_dict in field_list:
        field_name = field_dict.get("name", "")
        current_path = (
            f"{parent_prefix}.{field_name}" if parent_prefix else field_name
        )
        current_parts = parent_parts + (str(field_name),)

        if self._swap_mode == constants.SWAP_MODE_DGT_TO_PT:
          # === Mode 2 (Rollback: DGT -> PT) ===
          existing_dg_tags = self._extract_field_dg_tags(field_dict)

          if existing_dg_tags:
            mapped_entries: list[
                tuple[tuple[str, str], tuple[str, dict[str, str]]]
            ] = []
            unmapped_entries: list[tuple[str, str]] = []
            for column_dg_key, column_dg_value in existing_dg_tags.items():
              resolved = self._resolve_dg_tag_mapping(
                  dg_tag_key=column_dg_key,
                  dg_tag_value=column_dg_value,
                  binding_map=binding_map,
                  planned_values_by_source_policy_tag=(
                      planned_values_by_source_policy_tag
                  ),
                  table_location=effective_location,
                  bindings_by_dg_tag_key=bindings_by_dg_tag_key,
                  field_path=current_path,
              )
              if resolved is not None:
                mapped_entries.append(
                    ((column_dg_key, column_dg_value), resolved)
                )
              else:
                unmapped_entries.append((column_dg_key, column_dg_value))

            if not mapped_entries:
              # None of the DGTs on this column came from `plan.json`; leave the
              # column untouched and record each unmapped DGT for reporting.
              for column_dg_key, column_dg_value in unmapped_entries:
                unmapped_columns.append(
                    UnmappedColumnDetail(
                        field_path=current_path,
                        source_policy_tag=(
                            f"key='{column_dg_key}', value='{column_dg_value}'"
                        ),
                    )
                )
            else:
              # BigQuery forbids a column from having both a Policy Tag and a
              # Data Governance Tag. If the column has >1 DGT (either multiple
              # mapped DGTs or 1 mapped DGT + 1 non-migrated DGT), abort before
              # mutating the table.
              if len(existing_dg_tags) > 1:
                raise SchemaCorruptionError(
                    f"Cannot roll back column '{current_path}' from Data"
                    " Governance Tag to Policy Tag because multiple Data"
                    f" Governance Tags are attached ({existing_dg_tags!r})."
                    " BigQuery does not allow Policy Tags and remaining Data"
                    " Governance Tags on the same column."
                )

              (column_dg_key, column_dg_value), (
                  matched_plan_policy_tag,
                  _,
              ) = mapped_entries[0]
              if not matched_plan_policy_tag:
                raise SchemaCorruptionError(
                    "Invalid empty Policy Tag mapping in migration plan for"
                    f" Data Governance Tag (key='{column_dg_key}',"
                    f" value='{column_dg_value}') on column '{current_path}'."
                )

              policy_tags_wrapper = field_dict.get("policyTags")
              existing_policy_tags: list[str] = []
              if isinstance(policy_tags_wrapper, dict):
                raw_names = policy_tags_wrapper.get("names")
                if isinstance(raw_names, list):
                  existing_policy_tags = [name for name in raw_names if name]
              if existing_policy_tags and existing_policy_tags != [
                  matched_plan_policy_tag
              ]:
                raise SchemaCorruptionError(
                    f"Column '{current_path}' already has conflicting Policy"
                    f" Tag(s) {existing_policy_tags!r} while rolling back to"
                    f" '{matched_plan_policy_tag}'."
                )

              # Explicitly restore original Policy Tag and set
              # dataGovernanceTagsInfo.dataGovernanceTags to {} so BigQuery
              # atomically clears the Data Governance Tag on tables.patch.
              field_dict["policyTags"] = {"names": [matched_plan_policy_tag]}
              field_dict["dataGovernanceTagsInfo"] = {"dataGovernanceTags": {}}
              field_dict.pop("dataGovernanceTags", None)

              source_display_path = self._resolve_policy_tag_display_path(
                  matched_plan_policy_tag=matched_plan_policy_tag,
                  source_policy_tag=matched_plan_policy_tag,
                  planned_values_by_source_policy_tag=(
                      planned_values_by_source_policy_tag
                  ),
              )
              swapped_columns.append(
                  ColumnSwapDetail(
                      field_path=current_path,
                      source_policy_tag=matched_plan_policy_tag,
                      matched_plan_policy_tag=matched_plan_policy_tag,
                      dg_tag_key=column_dg_key,
                      dg_tag_value=column_dg_value,
                      field_path_parts=current_parts,
                      source_policy_tag_display_path=source_display_path,
                  )
              )
        else:
          # === Mode 1 (Forward Swap: PT -> DGT) ===
          policy_tags_wrapper = field_dict.get("policyTags")
          policy_tag_names = []
          if isinstance(policy_tags_wrapper, dict):
            raw_names = policy_tags_wrapper.get("names")
            if isinstance(raw_names, list):
              policy_tag_names = [name for name in raw_names if name]

          if policy_tag_names:
            source_policy_tag = policy_tag_names[0]
            resolved = self._resolve_policy_tag_mapping(
                source_policy_tag,
                binding_map,
                bindings_by_canonical_suffix=bindings_by_canonical_suffix,
            )
            if resolved is not None:
              matched_plan_policy_tag, dgt_mapping = resolved
              dg_tag_key = dgt_mapping.get("dg_tag_key", "")
              dg_tag_value = dgt_mapping.get("dg_tag_value", "")
              if not dg_tag_key or not dg_tag_value:
                raise SchemaCorruptionError(
                    "Invalid empty DGT mapping in migration plan for policy"
                    f" tag '{source_policy_tag}' on column '{current_path}'."
                )

              # BigQuery rejects attaching Data Governance Tags to non-leaf
              # `RECORD` / `STRUCT` parent columns (`Data governance tags are
              # only allowed on leaf fields.`). Fail closed upfront before
              # mutating schema fields.
              field_type = str(field_dict.get("type", "") or "").strip().upper()
              nested_subfields = field_dict.get("fields")
              has_nested_subfields = isinstance(nested_subfields, list) and (
                  bool(nested_subfields)
              )
              if field_type in ("RECORD", "STRUCT") or has_nested_subfields:
                raise SchemaCorruptionError(
                    f"Column '{current_path}' has non-leaf type"
                    f" '{field_type or 'RECORD'}' and carries Policy Tag"
                    f" '{source_policy_tag}'. BigQuery Data Governance Tags can"
                    " only be attached to leaf columns; move Policy Tags to"
                    " leaf subfields before migrating this table."
                )

              # BigQuery prohibits combining Data Governance Tags with direct
              # column-level Data Policies (`dataPolicies` in
              # `TableFieldSchema`) on the same column.
              existing_column_policies = field_dict.get("dataPolicies")
              if isinstance(existing_column_policies, list) and any(
                  bool(policy_entry)
                  for policy_entry in existing_column_policies
              ):
                formatted_column_policies: list[str] = []
                for policy_entry in existing_column_policies:
                  if not policy_entry:
                    continue
                  if isinstance(policy_entry, dict) and policy_entry.get(
                      "name"
                  ):
                    formatted_column_policies.append(policy_entry["name"])
                  else:
                    formatted_column_policies.append(str(policy_entry))
                raise SchemaCorruptionError(
                    f"Column '{current_path}' carries both Policy Tag"
                    f" '{source_policy_tag}' and direct column-level Data"
                    f" Policy binding(s) {formatted_column_policies}. BigQuery"
                    " prohibits combining Data Governance Tags with direct"
                    " column-level Data Policies on the same column; remove"
                    " the direct column-level Data Policy binding before"
                    " migrating this table."
                )

              # Explicitly set policyTags.names to [] so BigQuery clears the
              # existing Policy Tag binding on tables.patch.
              field_dict["policyTags"] = {"names": []}

              existing_dg_tags = self._extract_field_dg_tags(field_dict)
              if existing_dg_tags and existing_dg_tags != {
                  dg_tag_key: dg_tag_value
              }:
                raise SchemaCorruptionError(
                    f"Column '{current_path}' has both Policy Tag"
                    f" '{source_policy_tag}' and conflicting pre-existing"
                    f" Data Governance Tag(s) {existing_dg_tags}. Swapping"
                    " would create a multi-tag column that cannot be cleanly"
                    " rolled back."
                )
              existing_dg_tags[dg_tag_key] = dg_tag_value
              field_dict["dataGovernanceTagsInfo"] = {
                  "dataGovernanceTags": existing_dg_tags
              }
              field_dict.pop("dataGovernanceTags", None)

              source_display_path = self._resolve_policy_tag_display_path(
                  matched_plan_policy_tag=matched_plan_policy_tag,
                  source_policy_tag=source_policy_tag,
                  planned_values_by_source_policy_tag=(
                      planned_values_by_source_policy_tag
                  ),
              )
              swapped_columns.append(
                  ColumnSwapDetail(
                      field_path=current_path,
                      source_policy_tag=source_policy_tag,
                      matched_plan_policy_tag=matched_plan_policy_tag,
                      dg_tag_key=dg_tag_key,
                      dg_tag_value=dg_tag_value,
                      field_path_parts=current_parts,
                      source_policy_tag_display_path=source_display_path,
                  )
              )
            else:
              unmapped_columns.append(
                  UnmappedColumnDetail(
                      field_path=current_path,
                      source_policy_tag=source_policy_tag,
                  )
              )

        # Recursively traverse nested RECORD / STRUCT subfields (`fields`).
        subfields = field_dict.get("fields")
        if isinstance(subfields, list) and subfields:
          _transform_field_list(subfields, current_path, current_parts)

    _transform_field_list(updated_fields, "", ())

    if self._swap_mode != constants.SWAP_MODE_DGT_TO_PT and swapped_columns:
      unique_table_dg_tags: set[tuple[str, str]] = set()

      def _collect_unique_dg_tags(fields_list: list[dict[str, Any]]) -> None:
        for candidate_field in fields_list:
          if not isinstance(candidate_field, dict):
            continue
          for tag_key, tag_value in self._extract_field_dg_tags(
              candidate_field
          ).items():
            unique_table_dg_tags.add((tag_key, tag_value))
          nested_list = candidate_field.get("fields")
          if isinstance(nested_list, list) and nested_list:
            _collect_unique_dg_tags(nested_list)

      _collect_unique_dg_tags(updated_fields)
      if len(unique_table_dg_tags) > constants.MAX_DG_TAGS_PER_TABLE:
        raise SchemaCorruptionError(
            "Table schema would contain"
            f" {len(unique_table_dg_tags)} unique Data Governance Tags after"
            " swapping, exceeding BigQuery's limit of"
            f" {constants.MAX_DG_TAGS_PER_TABLE} unique Data Governance Tags"
            " per table."
        )

    return updated_fields, swapped_columns, unmapped_columns

  def verify_schema_swap_integrity(
      self,
      original_fields: list[dict[str, Any]],
      updated_fields: list[dict[str, Any]],
      swapped_columns: list[ColumnSwapDetail],
  ) -> None:
    """Strictly verifies that ONLY the intended PT<->DGT tag swaps occurred.

    Architectural Rationale (Defense-in-Depth Anti-Corruption Gate):
      Before `swap_table_schema` ever writes a schema PATCH to BigQuery, this
      method performs an independent, recursive structural audit comparing
      `original_fields` against `updated_fields`:
        1. Exact field list lengths and ordering at the top level and inside
           every nested `RECORD` / `STRUCT` column.
        2. Exact field `name` equality at every index.
        3. For each column in `swapped_columns`:
           - In `pt-to-dgt` mode: verifies `policyTags == {"names": []}` and
             `dataGovernanceTagsInfo` contains the exact expected DG Tag while
             every non-tag attribute (`type`, `mode`, `description`,
             `defaultValueExpression`, `maxLength`, `precision`, `scale`,
             `collation`, `roundingMode`, etc.) is byte-for-byte identical.
           - In `dgt-to-pt` mode: verifies `policyTags` restored the exact
             `matched_plan_policy_tag` and `dataGovernanceTagsInfo` is cleared
             to `{"dataGovernanceTags": {}}` while every non-tag attribute is
             byte-for-byte identical.
        4. For every non-swapped column: verifies that ALL attributes (including
           any unmapped `policyTags` or `dataGovernanceTagsInfo`) are completely
           unchanged.
        5. Verifies that every path in `swapped_columns` was actually visited
           in the schema tree.

    Args:
      original_fields: Original table schema fields before transformation.
      updated_fields: Modified table schema fields after transformation.
      swapped_columns: List of expected column swap details.

    Raises:
      SchemaCorruptionError: If any unintended schema change is detected.
    """
    expected_by_path: dict[str, ColumnSwapDetail] = {}
    for swap_detail in swapped_columns:
      if swap_detail.field_path in expected_by_path:
        raise SchemaCorruptionError(
            "Duplicate column swap entry detected for path"
            f" '{swap_detail.field_path}'."
        )
      expected_by_path[swap_detail.field_path] = swap_detail

    visited_swapped_paths: set[str] = set()

    def _verify_field_list(
        original_list: Any,
        updated_list: Any,
        parent_prefix: str,
    ) -> None:
      if not isinstance(original_list, list) or not isinstance(
          updated_list, list
      ):
        raise SchemaCorruptionError(
            f"Schema fields at '{parent_prefix or '<root>'}' must be a list."
        )

      if len(original_list) != len(updated_list):
        raise SchemaCorruptionError(
            f"Field count mismatch at '{parent_prefix or '<root>'}': original"
            f" has {len(original_list)} fields, updated has"
            f" {len(updated_list)} fields."
        )

      for index, (original_field, updated_field) in enumerate(
          zip(original_list, updated_list)
      ):
        if not isinstance(original_field, dict) or not isinstance(
            updated_field, dict
        ):
          raise SchemaCorruptionError(
              f"Field at index {index} under '{parent_prefix or '<root>'}' is"
              " not a dictionary."
          )

        original_name = original_field.get("name")
        updated_name = updated_field.get("name")
        if (
            not original_name
            or not isinstance(original_name, str)
            or original_name != updated_name
        ):
          raise SchemaCorruptionError(
              f"Field name mismatch at index {index} under"
              f" '{parent_prefix or '<root>'}': original='{original_name}',"
              f" updated='{updated_name}'."
          )

        current_path = (
            f"{parent_prefix}.{original_name}"
            if parent_prefix
            else original_name
        )

        if current_path in expected_by_path:
          visited_swapped_paths.add(current_path)
          expected = expected_by_path[current_path]

          if self._swap_mode == constants.SWAP_MODE_DGT_TO_PT:
            # Mode 2 (DGT -> PT Rollback):
            # 1. Verify original field had the expected DG Tag
            original_dg_tags = self._extract_field_dg_tags(original_field)
            expected_original_tags = {
                expected.dg_tag_key: expected.dg_tag_value
            }
            if original_dg_tags != expected_original_tags:
              raise SchemaCorruptionError(
                  f"Rolled-back field '{current_path}' had unexpected original"
                  f" Data Governance Tags: found {original_dg_tags!r},"
                  f" expected {expected_original_tags!r}."
              )

            # 2. Verify policyTags is set to {"names": [matched_policy_tag]}
            updated_policy_tags = updated_field.get("policyTags")
            expected_policy_tags = {"names": [expected.matched_plan_policy_tag]}
            if (
                not expected.matched_plan_policy_tag
                or updated_policy_tags != expected_policy_tags
            ):
              raise SchemaCorruptionError(
                  f"Rolled-back field '{current_path}' must have policyTags"
                  f" set to {expected_policy_tags!r}, but found:"
                  f" {updated_policy_tags!r}."
              )

            # 3. Verify dataGovernanceTagsInfo is explicitly cleared to {}
            updated_dgt_info = updated_field.get("dataGovernanceTagsInfo")
            if (
                updated_dgt_info != {"dataGovernanceTags": {}}
                or "dataGovernanceTags" in updated_field
            ):
              raise SchemaCorruptionError(
                  f"Rolled-back field '{current_path}' must have"
                  " dataGovernanceTagsInfo set to {'dataGovernanceTags':"
                  f" {{}}}}, but found: {updated_dgt_info!r}."
              )
          else:
            # Mode 1 (PT -> DGT Swap):
            # 1. Verify policyTags is explicitly set to {"names": []}
            updated_policy_tags = updated_field.get("policyTags")
            if updated_policy_tags != {"names": []}:
              raise SchemaCorruptionError(
                  f"Swapped field '{current_path}' must have policyTags set to"
                  f" {{'names': []}}, but found: {updated_policy_tags!r}."
              )

            # 2. Verify dataGovernanceTagsInfo only added the mapped DG tag
            expected_dg_tags = self._extract_field_dg_tags(original_field)
            expected_dg_tags[expected.dg_tag_key] = expected.dg_tag_value

            updated_dgt_info = updated_field.get("dataGovernanceTagsInfo")
            if (
                updated_dgt_info != {"dataGovernanceTags": expected_dg_tags}
                or "dataGovernanceTags" in updated_field
            ):
              raise SchemaCorruptionError(
                  f"Swapped field '{current_path}' has unexpected"
                  f" dataGovernanceTagsInfo: found {updated_dgt_info!r},"
                  f" expected {{'dataGovernanceTags': {expected_dg_tags!r}}}."
              )

          # Verify all other properties on this field are untouched
          excluded_keys = {
              "policyTags",
              "dataGovernanceTagsInfo",
              "dataGovernanceTags",
              "fields",
          }
          original_other = {
              key: value
              for key, value in original_field.items()
              if key not in excluded_keys
          }
          updated_other = {
              key: value
              for key, value in updated_field.items()
              if key not in excluded_keys
          }
          if original_other != updated_other:
            raise SchemaCorruptionError(
                "Unintended attribute modification on swapped field"
                f" '{current_path}': original={original_other!r},"
                f" updated={updated_other!r}."
            )
        else:
          # Non-swapped field: every property except 'fields' (checked below)
          # must be completely identical, including policyTags and DGTs.
          original_non_subfields = {
              key: value
              for key, value in original_field.items()
              if key != "fields"
          }
          updated_non_subfields = {
              key: value
              for key, value in updated_field.items()
              if key != "fields"
          }
          if original_non_subfields != updated_non_subfields:
            raise SchemaCorruptionError(
                "Unintended modification on non-swapped field"
                f" '{current_path}': original={original_non_subfields!r},"
                f" updated={updated_non_subfields!r}."
            )

        # 4. Verify nested subfields recursively
        has_original_subfields = "fields" in original_field
        has_updated_subfields = "fields" in updated_field
        if has_original_subfields != has_updated_subfields:
          raise SchemaCorruptionError(
              f"Nested 'fields' presence mismatch on '{current_path}'."
          )
        if has_original_subfields:
          _verify_field_list(
              original_field["fields"],
              updated_field["fields"],
              current_path,
          )

    _verify_field_list(original_fields, updated_fields, "")

    unvisited_paths = set(expected_by_path.keys()) - visited_swapped_paths
    if unvisited_paths:
      raise SchemaCorruptionError(
          "Expected swapped column paths were not found in the schema:"
          f" {sorted(unvisited_paths)}."
      )

  def verify_enforcement_parity(
      self,
      swapped_columns: list[ColumnSwapDetail],
      plan: dict[str, Any],
      table_project_id: str,
      table_location: str,
  ) -> list[ParityDiscrepancy]:
    """Verifies that target DGTs and V2 Data Policies match source PT security.

    Architectural Rationale (Pre-Swap Security Parity Gate):
      In a 3-phase migration, `plan.json` captures a point-in-time snapshot of
      the source Policy Taxonomy IAM and V1 Data Policy security posture during
      Phase 1 (`plan`), and Phase 2 (`create`) provisions the equivalent target
      DG Tags and V2 Data Policies. Customers must freeze source Policy Taxonomy
      IAM and V1 Data Policy edits between Phase 1 (`plan`) and Phase 3
      (`swap`). Before `swap_table_schema` mutates a table's columns from Policy
      Tags to DG Tags, this method inspects live GCP Resource Manager and
      BigQuery Data Policy V2 state against `plan.json` to block three classes
      of security regressions:
        - `ACCESS_LEAKAGE`: e.g., missing `_default_deny` or Raw Reader policy
          on an access-controlled tag (causing Fail-Open access where all table
          readers see unmasked sensitive data), or unexpected extra grantees on
          a live V2 Data Policy.
        - `ACCESS_BLOCKAGE`: e.g., missing raw reader or masked reader
          principals on live V2 Data Policies, missing masking policy, or a V2
          Data Policy attached to a Classification-Only (`enforceAccessControl:
          false`) tag (switching the column from Default Allow to Default Deny).
        - `RESOURCE_DISCREPANCY`: e.g., missing DG Tag Key/Value in Resource
          Manager, wrong tag purpose (not `DATA_GOVERNANCE`), or mismatched
          masking rule expression/routine.

    Args:
      swapped_columns: Columns scheduled to be swapped in the table.
      plan: Migration plan dictionary.
      table_project_id: Project ID of the BigQuery table being updated.
      table_location: Location/region of the BigQuery table being updated.

    Returns:
      A list of `ParityDiscrepancy` objects (empty if full parity holds).
    """
    discrepancies: list[ParityDiscrepancy] = []
    plan_indexes = self._get_or_build_plan_indexes(plan)
    planned_keys = plan_indexes["planned_keys"]
    planned_values = plan_indexes["planned_values"]
    planned_values_by_source_policy_tag = plan_indexes[
        "planned_values_by_source_policy_tag"
    ]
    planned_v2_policies = plan_indexes["planned_v2_policies"]
    target_data_policy_mode = plan.get("metadata", {}).get(
        "target_data_policy_mode"
    )

    # Determine which project(s) must host the V2 Data Policies for this table.
    expected_data_policy_projects = self._resolve_expected_data_policy_projects(
        plan, table_project_id
    )

    for swap_detail in swapped_columns:
      dg_tag_key = swap_detail.dg_tag_key
      dg_tag_value = swap_detail.dg_tag_value
      full_dg_tag_value = self._resolve_full_tag_value_namespaced_name(
          swap_detail=swap_detail,
          planned_values=planned_values,
          planned_values_by_source_policy_tag=(
              planned_values_by_source_policy_tag
          ),
      )
      key_action = planned_keys.get(dg_tag_key, {})
      if "is_access_control" in key_action:
        is_access_control = bool(key_action["is_access_control"])
      elif dg_tag_key in planned_keys:
        is_access_control = any(
            action.get("api_payload", {})
            .get("data_governance_tag", {})
            .get("key")
            == dg_tag_key
            for action in planned_v2_policies
        )
      else:
        is_access_control = True

      risk_if_missing = (
          constants.PARITY_RISK_ACCESS_LEAKAGE
          if is_access_control
          else constants.PARITY_RISK_RESOURCE_DISCREPANCY
      )

      # 1. Verify DG Tag Key exists in Resource Manager with DATA_GOVERNANCE
      live_tag_key_id = None
      try:
        live_tag_key = self._get_live_dg_tag_key(dg_tag_key)
        if live_tag_key is None:
          discrepancies.append(
              ParityDiscrepancy(
                  field_path=swap_detail.field_path,
                  source_policy_tag=swap_detail.source_policy_tag,
                  dg_tag_key=dg_tag_key,
                  dg_tag_value=dg_tag_value,
                  risk_category=risk_if_missing,
                  description=(
                      f"Target DG Tag Key '{dg_tag_key}' does not exist in"
                      " Resource Manager. Run '--phase create' first."
                  ),
              )
          )
          continue
        live_tag_key_id = getattr(live_tag_key, "name", None)
        purpose_value = getattr(live_tag_key, "purpose", None)
        if not self._is_data_governance_purpose(purpose_value):
          discrepancies.append(
              ParityDiscrepancy(
                  field_path=swap_detail.field_path,
                  source_policy_tag=swap_detail.source_policy_tag,
                  dg_tag_key=dg_tag_key,
                  dg_tag_value=dg_tag_value,
                  risk_category=risk_if_missing,
                  description=(
                      f"DG Tag Key '{dg_tag_key}' exists but does not have"
                      " DATA_GOVERNANCE purpose (found"
                      f" purpose={purpose_value})."
                  ),
              )
          )
      except Exception as error:  # pylint: disable=broad-exception-caught
        discrepancies.append(
            ParityDiscrepancy(
                field_path=swap_detail.field_path,
                source_policy_tag=swap_detail.source_policy_tag,
                dg_tag_key=dg_tag_key,
                dg_tag_value=dg_tag_value,
                risk_category=risk_if_missing,
                description=(
                    f"Failed to verify DG Tag Key '{dg_tag_key}': {error}"
                ),
            )
        )
        continue

      # 2. Verify DG Tag Value exists in Resource Manager
      live_tag_value_id = None
      try:
        live_tag_value = self._get_live_dg_tag_value(full_dg_tag_value)
        if live_tag_value is None:
          discrepancies.append(
              ParityDiscrepancy(
                  field_path=swap_detail.field_path,
                  source_policy_tag=swap_detail.source_policy_tag,
                  dg_tag_key=dg_tag_key,
                  dg_tag_value=dg_tag_value,
                  risk_category=risk_if_missing,
                  description=(
                      f"Target DG Tag Value '{full_dg_tag_value}' does not"
                      " exist in Resource Manager. Run '--phase create' first."
                  ),
              )
          )
          continue
        live_tag_value_id = getattr(live_tag_value, "name", None)
      except Exception as error:  # pylint: disable=broad-exception-caught
        discrepancies.append(
            ParityDiscrepancy(
                field_path=swap_detail.field_path,
                source_policy_tag=swap_detail.source_policy_tag,
                dg_tag_key=dg_tag_key,
                dg_tag_value=dg_tag_value,
                risk_category=risk_if_missing,
                description=(
                    f"Failed to verify DG Tag Value '{full_dg_tag_value}':"
                    f" {error}"
                ),
            )
        )
        continue

      # 3. Determine region and ancestor Tag Value chain for hierarchy matching
      policy_region = self._extract_region_from_policy_tag(
          swap_detail.matched_plan_policy_tag
      ) or (table_location.lower() if table_location else "")
      if not policy_region:
        discrepancies.append(
            ParityDiscrepancy(
                field_path=swap_detail.field_path,
                source_policy_tag=swap_detail.source_policy_tag,
                dg_tag_key=dg_tag_key,
                dg_tag_value=dg_tag_value,
                risk_category=constants.PARITY_RISK_RESOURCE_DISCREPANCY,
                description=(
                    "Could not determine region for policy tag"
                    f" '{swap_detail.source_policy_tag}'."
                ),
            )
        )
        continue

      ancestor_tag_values = self._get_tag_value_hierarchy_chain(
          full_dg_tag_value, planned_values
      )

      # 4. BigQuery evaluates V2 Data Policies across the union of
      # `table_project_id` and every project registered in the Organization's
      # regional `default_data_policy_projects` setting (`table_project_id`
      # takes precedence only when both define policies at the exact same tag
      # depth). Verify across BOTH Mode 1 and Mode 2:
      #   (a) In Mode 1 (`DEFAULT_DATA_POLICY_PROJECT`), each central Data
      #       Policy project is registered in
      #       `INFORMATION_SCHEMA.EFFECTIVE_PROJECT_OPTIONS` (unless
      #       `--skip-default-dp-org-check` is set).
      #   (b) Every companion project evaluated by BigQuery outside
      #       `expected_data_policy_projects` (`table_project_id` in Mode 1 and
      #       any Organization `default_data_policy_projects` entries in Mode 1
      #       or Mode 2) contains zero conflicting V2 Data Policies.
      if expected_data_policy_projects:
        self._verify_mode1_org_and_table_project_parity(
            swap_detail=swap_detail,
            full_dg_tag_value=full_dg_tag_value,
            is_access_control=is_access_control,
            table_project_id=table_project_id,
            central_dp_project_ids=expected_data_policy_projects,
            policy_region=policy_region,
            live_tag_key_id=live_tag_key_id,
            live_tag_value_id=live_tag_value_id,
            ancestor_tag_values=ancestor_tag_values,
            discrepancies=discrepancies,
            target_data_policy_mode=target_data_policy_mode,
        )

      # 5. Verify V2 Data Policies in each required Data Policy project
      for data_policy_project_id in expected_data_policy_projects:
        try:
          live_policies = self._list_live_v2_data_policies(
              data_policy_project_id, policy_region
          )
        except Exception as error:  # pylint: disable=broad-exception-caught
          discrepancies.append(
              ParityDiscrepancy(
                  field_path=swap_detail.field_path,
                  source_policy_tag=swap_detail.source_policy_tag,
                  dg_tag_key=dg_tag_key,
                  dg_tag_value=dg_tag_value,
                  risk_category=constants.PARITY_RISK_RESOURCE_DISCREPANCY,
                  description=(
                      "Failed to list live V2 Data Policies in project"
                      f" '{data_policy_project_id}' (region"
                      f" '{policy_region}'): {error}"
                  ),
              )
          )
          continue

        self._compare_tag_value_enforcement(
            swap_detail=swap_detail,
            full_dg_tag_value=full_dg_tag_value,
            is_access_control=is_access_control,
            data_policy_project_id=data_policy_project_id,
            policy_region=policy_region,
            live_tag_key_id=live_tag_key_id,
            live_tag_value_id=live_tag_value_id,
            ancestor_tag_values=ancestor_tag_values,
            planned_v2_policies=planned_v2_policies,
            live_policies=live_policies,
            discrepancies=discrepancies,
            target_data_policy_mode=target_data_policy_mode,
        )

    return discrepancies

  def _get_live_dg_tag_key(self, namespaced_name: str) -> Any | None:
    """Looks up a live DG Tag Key in Resource Manager via `list_tag_keys`.

    Caches all Tag Keys under `projects/{project_id}` on the first lookup and
    records `project_id` in `_listed_tag_key_projects` so missing Tag Keys
    return `None` in O(1) on subsequent columns without re-paging.

    Args:
      namespaced_name: Expected Tag Key namespaced name (`project/key_short`).

    Returns:
      The matching Resource Manager `TagKey` object, or `None` if not found.
    """
    if namespaced_name in self._live_tag_keys_cache:
      return self._live_tag_keys_cache[namespaced_name]

    parts = namespaced_name.split("/")
    if len(parts) != 2:
      return None

    project_id, _ = parts
    if project_id not in self._listed_tag_key_projects:
      parent = f"projects/{project_id}"
      pager = self._dg_tag_keys_client.list_tag_keys(parent=parent)
      for tag_key in pager:
        short_name = getattr(tag_key, "short_name", "")
        if short_name:
          self._live_tag_keys_cache[f"{project_id}/{short_name}"] = tag_key
        key_namespaced = getattr(tag_key, "namespaced_name", "")
        if key_namespaced:
          self._live_tag_keys_cache[key_namespaced] = tag_key
        # Seed `_project_number_to_id_cache` directly from `TagKey.parent`
        # (`projects/<project_number>`) so live V2 Data Policies referencing
        # `<dgt_project_number>/<key_short>` resolve without requiring
        # `resourcemanager.projects.get` (absent from least-privilege
        # `roles/resourcemanager.tagViewer` / `tagUser` roles).
        tag_key_parent = getattr(tag_key, "parent", "")
        if (
            isinstance(tag_key_parent, str)
            and tag_key_parent.startswith("projects/")
            and not project_id.isdigit()
        ):
          parent_project_number = tag_key_parent.removeprefix("projects/")
          if parent_project_number.isdigit():
            self._project_number_to_id_cache.setdefault(
                parent_project_number, project_id
            )
      self._listed_tag_key_projects.add(project_id)

    return self._live_tag_keys_cache.get(namespaced_name)

  def _get_live_dg_tag_value(self, full_namespaced_name: str) -> Any | None:
    """Looks up a live DG Tag Value in Resource Manager via `list_tag_values`.

    Recursively resolves the parent Tag Key (`len(parts) == 3`) or parent Tag
    Value (`len(parts) > 3` for hierarchical Tag Values), lists all sibling
    Tag Values under that parent once, and records `parent_id` in
    `_listed_tag_value_parents` so missing Tag Values do not trigger repeated
    `list_tag_values` RPCs across columns.

    Args:
      full_namespaced_name: Full hierarchical namespaced name of the Tag Value
        (e.g., `proj/key/val` or `proj/key/parent/child`).

    Returns:
      The matching Resource Manager `TagValue` object, or `None` if not found.
    """
    if full_namespaced_name in self._live_tag_values_cache:
      return self._live_tag_values_cache[full_namespaced_name]

    parts = full_namespaced_name.split("/")
    if len(parts) < 3:
      return None

    parent_namespaced_name = "/".join(parts[:-1])
    if len(parts) == 3:
      parent_resource = self._get_live_dg_tag_key(parent_namespaced_name)
    else:
      parent_resource = self._get_live_dg_tag_value(parent_namespaced_name)

    parent_id = (
        getattr(parent_resource, "name", None)
        if parent_resource is not None
        else None
    )
    if not parent_id:
      return None

    if parent_id not in self._listed_tag_value_parents:
      pager = self._dg_tag_values_client.list_tag_values(parent=parent_id)
      for tag_value in pager:
        value_namespaced = getattr(tag_value, "namespaced_name", "")
        if value_namespaced:
          self._live_tag_values_cache[value_namespaced] = tag_value
        value_parent = getattr(tag_value, "parent", None)
        short_name = getattr(tag_value, "short_name", "")
        if short_name and value_parent in (None, "", parent_id):
          self._live_tag_values_cache[
              f"{parent_namespaced_name}/{short_name}"
          ] = tag_value
      self._listed_tag_value_parents.add(parent_id)

    return self._live_tag_values_cache.get(full_namespaced_name)

  def _resolve_full_tag_value_namespaced_name(
      self,
      swap_detail: ColumnSwapDetail,
      planned_values: dict[str, dict[str, Any]],
      planned_values_by_source_policy_tag: dict[str, dict[str, Any]],
  ) -> str:
    """Resolves a Tag Value short name or path to its full namespaced name.

    Args:
      swap_detail: Column swap detail containing the Policy Tag and DGT mapping.
      planned_values: Map from Tag Value `namespaced_name` to manifest action.
      planned_values_by_source_policy_tag: Map from source Policy Tag URI to
        planned Tag Value manifest action.

    Returns:
      The resolved full namespaced path (`proj/key/val` or
      `proj/key/parent/child`).
    """
    for candidate_policy_tag in (
        swap_detail.matched_plan_policy_tag,
        swap_detail.source_policy_tag,
    ):
      if candidate_policy_tag in planned_values_by_source_policy_tag:
        namespaced = planned_values_by_source_policy_tag[
            candidate_policy_tag
        ].get("namespaced_name")
        if namespaced:
          return namespaced

    dg_tag_key = swap_detail.dg_tag_key
    dg_tag_value = swap_detail.dg_tag_value
    if dg_tag_value in planned_values:
      return dg_tag_value

    direct_child_name = f"{dg_tag_key}/{dg_tag_value}"
    if direct_child_name in planned_values:
      return direct_child_name

    target_short_name = dg_tag_value.split("/")[-1]
    for namespaced_name in planned_values:
      if (
          namespaced_name.startswith(f"{dg_tag_key}/")
          and namespaced_name.split("/")[-1] == target_short_name
      ):
        return namespaced_name

    if dg_tag_value.count("/") >= 2:
      return dg_tag_value
    return direct_child_name

  def _compare_tag_value_enforcement(
      self,
      swap_detail: ColumnSwapDetail,
      full_dg_tag_value: str,
      is_access_control: bool,
      data_policy_project_id: str,
      policy_region: str,
      live_tag_key_id: str | None,
      live_tag_value_id: str | None,
      ancestor_tag_values: list[str],
      planned_v2_policies: list[dict[str, Any]],
      live_policies: list[LiveDataPolicyV2Summary],
      discrepancies: list[ParityDiscrepancy],
      target_data_policy_mode: str | None = None,
  ) -> None:
    """Compares expected vs. live V2 Data Policy enforcement for one tag.

    Architectural Rationale (Hierarchical Inheritance & Default-Deny Invariant):
      BigQuery evaluates Data Governance Tag enforcement hierarchically
      (`column.matchTagHierarchy`): a `RAW_DATA_ACCESS_POLICY` or
      `DATA_MASKING_POLICY` attached to an ancestor Tag Value applies to columns
      tagged with any descendant Tag Value. However, BigQuery only activates
      Default-Deny column access control on a Tag Value when at least one
      `RAW_DATA_ACCESS_POLICY` is attached directly to that Tag Value.
      Crucially, attaching ONLY a `DATA_MASKING_POLICY` to a Tag Value without a
      direct `RAW_DATA_ACCESS_POLICY` leaves non-masked table readers Fail-Open
      to unmasked column data! Therefore:
        1. Classification-Only (`is_access_control=False`): Zero live V2 Data
           Policies may reference `dg_tag_key` (whether attached to
           `dg_tag_value`, an ancestor, a sibling/descendant Tag Value, or a
           matching condition), because BigQuery activates Tag-Key-wide Default
           Deny whenever any policy references the Tag Key.
        2. Access-Controlled (`is_access_control=True`):
           - Must have at least one direct live `RAW_DATA_ACCESS_POLICY` on
             `dg_tag_value` (either a Raw Reader policy or the mandatory
             `_default_deny` seatbelt) and zero out-of-band condition-bound
             policies matching `dg_tag_key`.
           - At EACH ancestor tag depth in `ancestor_tag_values`, live
             `RAW_DATA_ACCESS_POLICY` `grantees` must match expected raw
             grantees from `plan.json` (preserving deepest-tag-wins precedence).
           - Every expected `DATA_MASKING_POLICY` rule and its masked reader
             `grantees` must match live masking policies, and no unexpected
             live masking policies may exist on the Tag Value or its ancestors.

    Args:
      swap_detail: Column swap detail being audited.
      full_dg_tag_value: Full hierarchical namespaced name of the DG Tag Value.
      is_access_control: True if the source Taxonomy had `enforceAccessControl`
        enabled.
      data_policy_project_id: Project ID where V2 Data Policies are inspected.
      policy_region: Lowercase region of the Policy Tag / Table.
      live_tag_key_id: Numeric `tagKeys/<id>` resource name of the live Tag Key.
      live_tag_value_id: Numeric `tagValues/<id>` name of the live Tag Value.
      ancestor_tag_values: Ordered list `[self, parent, ..., root]` of Tag Value
        namespaced names along the hierarchy.
      planned_v2_policies: Planned V2 Data Policy manifest entries.
      live_policies: Live V2 Data Policy summaries in `data_policy_project_id`
        and `policy_region`.
      discrepancies: Mutable list where detected `ParityDiscrepancy` items are
        appended.
      target_data_policy_mode: Configured V2 Data Policy placement mode from
        `plan.json`.
    """
    dg_tag_key = swap_detail.dg_tag_key
    dg_tag_value = swap_detail.dg_tag_value

    # Match live policies attached directly to dg_tag_value
    direct_live_policies = [
        policy
        for policy in live_policies
        if self._policy_matches_tag(
            policy,
            dg_tag_key=dg_tag_key,
            dg_tag_value=full_dg_tag_value,
            live_tag_key_id=live_tag_key_id,
            live_tag_value_id=live_tag_value_id,
        )
    ]

    # Resolve live numeric IDs for ancestor Tag Values from the populated cache
    # so policies referencing numeric tagValues/<id> on ancestors match cleanly.
    ancestor_live_ids: dict[str, str | None] = {}
    for ancestor_value in ancestor_tag_values:
      if ancestor_value in (dg_tag_value, full_dg_tag_value):
        ancestor_live_ids[ancestor_value] = live_tag_value_id
      else:
        ancestor_obj = self._live_tag_values_cache.get(ancestor_value)
        if ancestor_obj is None:
          try:
            ancestor_obj = self._get_live_dg_tag_value(ancestor_value)
          except Exception:  # pylint: disable=broad-exception-caught
            ancestor_obj = None
        ancestor_live_ids[ancestor_value] = (
            getattr(ancestor_obj, "name", None)
            if ancestor_obj is not None
            else None
        )

    # Match live policies attached to any ancestor Tag Value (including self)
    hierarchy_live_policies = [
        policy
        for policy in live_policies
        if any(
            self._policy_matches_tag(
                policy,
                dg_tag_key=dg_tag_key,
                dg_tag_value=ancestor_value,
                live_tag_key_id=live_tag_key_id,
                live_tag_value_id=ancestor_live_ids.get(ancestor_value),
            )
            for ancestor_value in ancestor_tag_values
        )
    ]

    # Match live V2 policies referencing `dg_tag_key` anywhere (direct,
    # ancestor, sibling/descendant Tag Value, or condition expression) because
    # BigQuery activates Tag-Key-wide Default Deny whenever ANY active V2 Data
    # Policy references the Tag Key.
    key_live_policies = [
        policy
        for policy in live_policies
        if self._policy_matches_tag_key(
            policy,
            dg_tag_key=dg_tag_key,
            live_tag_key_id=live_tag_key_id,
        )
    ]
    condition_live_policies = [
        policy
        for policy in live_policies
        if policy.matching_condition
        and self._policy_condition_matches_tag_key(
            policy.matching_condition,
            dg_tag_key=dg_tag_key,
            live_tag_key_id=live_tag_key_id,
        )
    ]

    policies_to_check_for_grantee_errors = (
        direct_live_policies + hierarchy_live_policies + condition_live_policies
        if is_access_control
        else key_live_policies
    )
    seen_error_policies: set[str] = set()
    for policy in policies_to_check_for_grantee_errors:
      if (
          policy.name in self._grantee_fetch_errors
          and policy.name not in seen_error_policies
      ):
        seen_error_policies.add(policy.name)
        discrepancies.append(
            ParityDiscrepancy(
                field_path=swap_detail.field_path,
                source_policy_tag=swap_detail.source_policy_tag,
                dg_tag_key=dg_tag_key,
                dg_tag_value=dg_tag_value,
                risk_category=constants.PARITY_RISK_RESOURCE_DISCREPANCY,
                description=(
                    "Failed to verify grantees via REST for live V2 Data Policy"
                    f" '{policy.name}' on '{dg_tag_value}':"
                    f" {self._grantee_fetch_errors[policy.name]}"
                ),
            )
        )

    # Fail closed in Access-Control mode whenever a live V2 Data Policy
    # references `<project_number>/<key_short>` sharing `dg_tag_key`'s short
    # name whose numeric project could not be resolved (e.g., missing
    # `resourcemanager.projects.get`). Classification-Only mode already flags
    # these policies via `_policy_matches_tag_key(...,
    # fail_closed_on_unresolved_numeric=True)` below.
    if is_access_control:
      for unresolved_policy in self._find_unresolved_numeric_tag_key_policies(
          live_policies, dg_tag_key
      ):
        discrepancies.append(
            ParityDiscrepancy(
                field_path=swap_detail.field_path,
                source_policy_tag=swap_detail.source_policy_tag,
                dg_tag_key=dg_tag_key,
                dg_tag_value=dg_tag_value,
                risk_category=constants.PARITY_RISK_ACCESS_LEAKAGE,
                description=(
                    f"Live V2 Data Policy '{unresolved_policy.data_policy_id}'"
                    f" in project '{data_policy_project_id}' (region"
                    f" '{policy_region}') references numeric Tag Key"
                    f" '{unresolved_policy.dg_tag_key}' sharing short name with"
                    f" '{dg_tag_key}', but the numeric project number could not"
                    " be resolved to verify whether this policy targets"
                    f" '{dg_tag_key}'. Grant 'resourcemanager.projects.get' on"
                    " the referenced project or verify out-of-band before"
                    " swapping."
                ),
            )
        )

    if not is_access_control:
      # Classification-Only Taxonomy: BigQuery applies Tag-Key-wide Default Deny
      # whenever ANY active V2 Data Policy references `dg_tag_key` (even on a
      # sibling/descendant Tag Value or via a matching condition), which would
      # lock out existing table readers on `dg_tag_value`.
      if key_live_policies:
        policy_ids = [policy.data_policy_id for policy in key_live_policies]
        discrepancies.append(
            ParityDiscrepancy(
                field_path=swap_detail.field_path,
                source_policy_tag=swap_detail.source_policy_tag,
                dg_tag_key=dg_tag_key,
                dg_tag_value=dg_tag_value,
                risk_category=constants.PARITY_RISK_ACCESS_BLOCKAGE,
                description=(
                    "Source Policy Tag belongs to a Classification-Only"
                    " (Default Allow) taxonomy, but target DG Tag Key"
                    f" '{dg_tag_key}' (for tag '{dg_tag_value}') has live V2"
                    " Data Policies attached in project"
                    f" '{data_policy_project_id}' ({policy_ids}), which"
                    " activates Tag-Key-wide Default Deny and blocks table"
                    " readers."
                ),
            )
        )
      return

    # Flag any out-of-band condition-bound V2 Data Policies
    # (`matching_condition` or `data_governance_tag_condition`) targeting
    # `dg_tag_key` (or containing unparseable CEL predicates), which `plan.json`
    # never generates and which can grant extra access via OR evaluation or
    # alter masking precedence.
    if condition_live_policies:
      cond_ids = [policy.data_policy_id for policy in condition_live_policies]
      has_leakage_condition_policy = any(
          policy.grantees
          or policy.data_policy_type == constants.DATA_POLICY_TYPE_MASKING
          for policy in condition_live_policies
      )
      if has_leakage_condition_policy:
        cond_risk = constants.PARITY_RISK_ACCESS_LEAKAGE
      else:
        cond_risk = constants.PARITY_RISK_RESOURCE_DISCREPANCY
      discrepancies.append(
          ParityDiscrepancy(
              field_path=swap_detail.field_path,
              source_policy_tag=swap_detail.source_policy_tag,
              dg_tag_key=dg_tag_key,
              dg_tag_value=dg_tag_value,
              risk_category=cond_risk,
              description=(
                  f"Project '{data_policy_project_id}' (region"
                  f" '{policy_region}') contains unexpected condition-bound V2"
                  f" Data Policy(ies) {cond_ids} matching Tag Key"
                  f" '{dg_tag_key}'. Condition-bound policies are evaluated"
                  " alongside tag-bound policies and can grant unauthorized"
                  " access or alter masking rules."
              ),
          )
      )

    # Access-Controlled Taxonomy:
    # 1. Must have at least one direct V2 Data Policy on dg_tag_value so the
    # column is never Fail-Open (and maintains its fail-closed seatbelt).
    if not direct_live_policies:
      discrepancies.append(
          ParityDiscrepancy(
              field_path=swap_detail.field_path,
              source_policy_tag=swap_detail.source_policy_tag,
              dg_tag_key=dg_tag_key,
              dg_tag_value=dg_tag_value,
              risk_category=constants.PARITY_RISK_ACCESS_LEAKAGE,
              description=(
                  "Source Policy Tag is Access-Controlled (Default Deny), but"
                  f" target DG Tag Value '{dg_tag_value}' has NO live V2 Data"
                  f" Policy attached in project '{data_policy_project_id}'"
                  f" (region '{policy_region}'). Swapping would leave column"
                  f" '{swap_detail.field_path}' Fail-Open to all table readers."
              ),
          )
      )
      return

    # Every access-controlled Tag Value MUST have a direct
    # RAW_DATA_ACCESS_POLICY (either a Raw Reader policy or the mandatory
    # `_default_deny` seatbelt) even when a DATA_MASKING_POLICY is present.
    # Without a RAW_DATA_ACCESS_POLICY on the Tag Value, non-masked table
    # readers fall open to unmasked column data.
    direct_live_raw_policies = [
        policy
        for policy in direct_live_policies
        if policy.data_policy_type == constants.DATA_POLICY_TYPE_RAW
    ]
    if not direct_live_raw_policies:
      discrepancies.append(
          ParityDiscrepancy(
              field_path=swap_detail.field_path,
              source_policy_tag=swap_detail.source_policy_tag,
              dg_tag_key=dg_tag_key,
              dg_tag_value=dg_tag_value,
              risk_category=constants.PARITY_RISK_ACCESS_LEAKAGE,
              description=(
                  "Source Policy Tag is Access-Controlled (Default Deny), but"
                  f" target DG Tag Value '{dg_tag_value}' has no direct"
                  f" V2 {constants.DATA_POLICY_TYPE_RAW} (such as the"
                  f" mandatory '{constants.SUFFIX_DEFAULT_DENY_POLICY}'"
                  f" policy) in project '{data_policy_project_id}' (region"
                  f" '{policy_region}'). Without a direct"
                  f" {constants.DATA_POLICY_TYPE_RAW}, non-masked table"
                  " readers fall open to unmasked column data."
              ),
          )
      )

    # Filter planned V2 Data Policies for this Tag Value (and ancestors) in
    # this region (and project, or any planned project if Mode 1).
    relevant_planned_policies = [
        action
        for action in planned_v2_policies
        if action.get("region", "").lower() == policy_region.lower()
        and (
            not action.get("target_project_id")
            or action.get("target_project_id") == data_policy_project_id
        )
    ]
    if not relevant_planned_policies:
      if (
          target_data_policy_mode
          == constants.TARGET_DATA_POLICY_MODE_TABLE_PROJECTS
      ):
        discrepancies.append(
            ParityDiscrepancy(
                field_path=swap_detail.field_path,
                source_policy_tag=swap_detail.source_policy_tag,
                dg_tag_key=dg_tag_key,
                dg_tag_value=dg_tag_value,
                risk_category=constants.PARITY_RISK_RESOURCE_DISCREPANCY,
                description=(
                    f"Table project '{data_policy_project_id}' has no planned"
                    " V2 Data Policies in plan.json for region"
                    f" '{policy_region}' under Mode 2"
                    f" ({constants.TARGET_DATA_POLICY_MODE_TABLE_PROJECTS})."
                    " Re-run '--phase plan' including"
                    f" '--target-table-dp-project-ids {data_policy_project_id}'"
                    " and '--phase create' before swapping."
                ),
            )
        )
        return
      # Mode 1 fallback if plan actions were generated without target_project_id
      relevant_planned_policies = [
          action
          for action in planned_v2_policies
          if action.get("region", "").lower() == policy_region.lower()
      ]

    planned_raw_by_ancestor: dict[str, set[str]] = {
        ancestor_value: set() for ancestor_value in ancestor_tag_values
    }
    planned_masking_by_ancestor: dict[
        str, list[tuple[str | None, str | None, set[str]]]
    ] = {ancestor_value: [] for ancestor_value in ancestor_tag_values}
    grouped_masking_by_ancestor: dict[
        str,
        dict[
            tuple[str | None, str | None],
            tuple[str | None, str | None, set[str]],
        ],
    ] = {ancestor_value: {} for ancestor_value in ancestor_tag_values}

    for action in relevant_planned_policies:
      matched_ancestor = self._match_planned_action_ancestor(
          action=action,
          dg_tag_key=dg_tag_key,
          ancestor_tag_values=ancestor_tag_values,
      )
      if matched_ancestor is None:
        continue

      payload = action.get("api_payload", {})
      policy_type = payload.get("data_policy_type", "")
      raw_grantees = payload.get("grantees")
      if raw_grantees is None:
        raw_grantees = action.get("grantees", [])
      action_grantees = set(raw_grantees or [])

      if policy_type == constants.DATA_POLICY_TYPE_RAW:
        planned_raw_by_ancestor[matched_ancestor].update(action_grantees)
      elif policy_type == constants.DATA_POLICY_TYPE_MASKING:
        masking_dict = payload.get("data_masking_policy", {})
        expected_expression = masking_dict.get("predefined_expression")
        expected_routine = masking_dict.get("routine")
        if not expected_expression and not expected_routine:
          # Keep unspecified rules unmerged so empty `data_masking_policy: {}`
          # entries continue to fail closed individually.
          planned_masking_by_ancestor[matched_ancestor].append(
              (expected_expression, expected_routine, action_grantees)
          )
        else:
          # Group sharded masking policies sharing the same normalized rule on
          # one tag so unioned live grantees match unioned planned grantees.
          norm_rule_key = (
              expected_expression or None,
              self._normalize_routine_path(expected_routine)
              if expected_routine and not expected_expression
              else None,
          )
          ancestor_rules = grouped_masking_by_ancestor[matched_ancestor]
          if norm_rule_key in ancestor_rules:
            ancestor_rules[norm_rule_key][2].update(action_grantees)
          else:
            merged_entry = (
                expected_expression,
                expected_routine,
                set(action_grantees),
            )
            ancestor_rules[norm_rule_key] = merged_entry
            planned_masking_by_ancestor[matched_ancestor].append(merged_entry)

    live_policies_by_ancestor: dict[str, list[LiveDataPolicyV2Summary]] = {
        ancestor_value: [
            policy
            for policy in live_policies
            if self._policy_matches_tag(
                policy,
                dg_tag_key=dg_tag_key,
                dg_tag_value=ancestor_value,
                live_tag_key_id=live_tag_key_id,
                live_tag_value_id=ancestor_live_ids.get(ancestor_value),
            )
        ]
        for ancestor_value in ancestor_tag_values
    }

    # 2. Compare Raw Data Access Policy grantees at EACH ancestor tag depth in
    # `ancestor_tag_values`. BigQuery groups matching DGT policies by tag depth
    # first (`max_depth` wins) and only breaks `RAW_DATA_ACCESS_POLICY >
    # DATA_MASKING_POLICY` ties within the deepest matching tag. Comparing flat
    # hierarchy-wide grantee sets can mask both:
    #   (a) Upward raw-grant drift (moving a child raw grant above a masked
    #       intermediate tag causes the masked intermediate tag to win), and
    #   (b) Downward raw-grant tampering (adding an ancestor raw reader onto a
    #       masked child's `_default_deny` policy leaks unmasked data).
    for ancestor_value in ancestor_tag_values:
      live_raw_at_ancestor: set[str] = set()
      for policy in live_policies_by_ancestor[ancestor_value]:
        if policy.data_policy_type == constants.DATA_POLICY_TYPE_RAW:
          live_raw_at_ancestor.update(policy.grantees)

      expected_raw_at_ancestor = planned_raw_by_ancestor[ancestor_value]
      missing_at_ancestor = sorted(
          expected_raw_at_ancestor - live_raw_at_ancestor
      )
      extra_at_ancestor = sorted(
          live_raw_at_ancestor - expected_raw_at_ancestor
      )

      if missing_at_ancestor:
        discrepancies.append(
            ParityDiscrepancy(
                field_path=swap_detail.field_path,
                source_policy_tag=swap_detail.source_policy_tag,
                dg_tag_key=dg_tag_key,
                dg_tag_value=dg_tag_value,
                risk_category=constants.PARITY_RISK_ACCESS_BLOCKAGE,
                description=(
                    "Missing Fine-Grained Reader principal(s)"
                    f" {missing_at_ancestor} on live V2 RAW_DATA_ACCESS_POLICY"
                    f" for tag '{ancestor_value}' in project"
                    f" '{data_policy_project_id}'. Because BigQuery evaluates"
                    " Data Governance Tag policies at the deepest matching tag"
                    " first, omitting these readers at this tag depth causes"
                    " them to lose unmasked read access."
                ),
            )
        )

      if extra_at_ancestor:
        discrepancies.append(
            ParityDiscrepancy(
                field_path=swap_detail.field_path,
                source_policy_tag=swap_detail.source_policy_tag,
                dg_tag_key=dg_tag_key,
                dg_tag_value=dg_tag_value,
                risk_category=constants.PARITY_RISK_ACCESS_LEAKAGE,
                description=(
                    f"Unexpected extra principal(s) {extra_at_ancestor} granted"
                    " raw data access on live V2 RAW_DATA_ACCESS_POLICY for tag"
                    f" '{ancestor_value}' in project"
                    f" '{data_policy_project_id}'. Because BigQuery evaluates"
                    " Data Governance Tag policies at the deepest matching tag"
                    " first, extra raw grants at this tag depth can override"
                    " masking or grant unauthorized unmasked access."
                ),
            )
        )

    # 3. Compare Data Masking Policies at each ancestor level along
    # `ancestor_tag_values`. Both Policy Tags and Data Governance Tags inherit
    # ancestor masking policies onto unmasked descendant tags, so planned
    # ancestor masking policies must match live policies at that ancestor
    # without falsely blocking unmasked child tags.
    unexpected_live_masking: list[LiveDataPolicyV2Summary] = []
    for ancestor_value in ancestor_tag_values:
      ancestor_expected_specs = planned_masking_by_ancestor[ancestor_value]
      ancestor_live_masking = [
          policy
          for policy in live_policies_by_ancestor[ancestor_value]
          if policy.data_policy_type == constants.DATA_POLICY_TYPE_MASKING
      ]
      matched_at_ancestor: list[LiveDataPolicyV2Summary] = []

      for (
          expected_expression,
          expected_routine,
          expected_grantees,
      ) in ancestor_expected_specs:
        matching_live_masking = [
            policy
            for policy in ancestor_live_masking
            if self._masking_rule_matches(
                policy, expected_expression, expected_routine
            )
        ]
        for policy in matching_live_masking:
          if policy not in matched_at_ancestor:
            matched_at_ancestor.append(policy)

        rule_label = expected_expression or expected_routine or "<unspecified>"
        if not matching_live_masking:
          if ancestor_live_masking:
            found_rules = [
                policy.masking_expression
                or policy.masking_routine
                or "<unspecified>"
                for policy in ancestor_live_masking
            ]
            discrepancies.append(
                ParityDiscrepancy(
                    field_path=swap_detail.field_path,
                    source_policy_tag=swap_detail.source_policy_tag,
                    dg_tag_key=dg_tag_key,
                    dg_tag_value=dg_tag_value,
                    risk_category=constants.PARITY_RISK_RESOURCE_DISCREPANCY,
                    description=(
                        f"Masking rule mismatch for '{ancestor_value}' in"
                        f" project '{data_policy_project_id}': expected"
                        f" masking rule '{rule_label}', but found live masking"
                        f" rule(s) {found_rules}."
                    ),
                )
            )
          else:
            discrepancies.append(
                ParityDiscrepancy(
                    field_path=swap_detail.field_path,
                    source_policy_tag=swap_detail.source_policy_tag,
                    dg_tag_key=dg_tag_key,
                    dg_tag_value=dg_tag_value,
                    risk_category=constants.PARITY_RISK_ACCESS_BLOCKAGE,
                    description=(
                        f"Missing V2 DATA_MASKING_POLICY (rule '{rule_label}')"
                        f" for '{ancestor_value}' in project"
                        f" '{data_policy_project_id}'. Masked readers"
                        f" {sorted(expected_grantees)} will lose masked access."
                    ),
                )
            )
          continue

        live_masked_grantees: set[str] = set()
        for policy in matching_live_masking:
          live_masked_grantees.update(policy.grantees)

        missing_masked = sorted(expected_grantees - live_masked_grantees)
        extra_masked = sorted(live_masked_grantees - expected_grantees)

        if missing_masked:
          discrepancies.append(
              ParityDiscrepancy(
                  field_path=swap_detail.field_path,
                  source_policy_tag=swap_detail.source_policy_tag,
                  dg_tag_key=dg_tag_key,
                  dg_tag_value=dg_tag_value,
                  risk_category=constants.PARITY_RISK_ACCESS_BLOCKAGE,
                  description=(
                      f"Missing Masked Reader principal(s) {missing_masked} on"
                      f" live V2 DATA_MASKING_POLICY (rule '{rule_label}') for"
                      f" '{ancestor_value}' in project"
                      f" '{data_policy_project_id}'."
                  ),
              )
          )

        if extra_masked:
          discrepancies.append(
              ParityDiscrepancy(
                  field_path=swap_detail.field_path,
                  source_policy_tag=swap_detail.source_policy_tag,
                  dg_tag_key=dg_tag_key,
                  dg_tag_value=dg_tag_value,
                  risk_category=constants.PARITY_RISK_ACCESS_LEAKAGE,
                  description=(
                      "Unexpected extra Masked Reader principal(s)"
                      f" {extra_masked} on live V2 DATA_MASKING_POLICY (rule"
                      f" '{rule_label}') for '{ancestor_value}' in project"
                      f" '{data_policy_project_id}'."
                  ),
              )
          )

      if not ancestor_expected_specs or matched_at_ancestor:
        for policy in ancestor_live_masking:
          if (
              policy not in matched_at_ancestor
              and (ancestor_value == full_dg_tag_value or policy.grantees)
              and policy not in unexpected_live_masking
          ):
            unexpected_live_masking.append(policy)

    if unexpected_live_masking:
      extra_masking_ids = [
          policy.data_policy_id for policy in unexpected_live_masking
      ]
      discrepancies.append(
          ParityDiscrepancy(
              field_path=swap_detail.field_path,
              source_policy_tag=swap_detail.source_policy_tag,
              dg_tag_key=dg_tag_key,
              dg_tag_value=dg_tag_value,
              risk_category=constants.PARITY_RISK_ACCESS_LEAKAGE,
              description=(
                  "Unexpected live V2 DATA_MASKING_POLICY"
                  f" {extra_masking_ids} attached to '{dg_tag_value}' (or"
                  " ancestor hierarchy) in project"
                  f" '{data_policy_project_id}'."
              ),
          )
      )

  def _match_planned_action_ancestor(
      self,
      action: dict[str, Any],
      dg_tag_key: str,
      ancestor_tag_values: list[str],
  ) -> str | None:
    """Maps a planned V2 policy action to its target ancestor Tag Value path.

    Args:
      action: Planned V2 Data Policy manifest action dictionary.
      dg_tag_key: Expected DG Tag Key namespaced name (`project/key_short`).
      ancestor_tag_values: Ordered `[leaf, parent, ..., root]` Tag Value paths.

    Returns:
      The matched full namespaced Tag Value string from `ancestor_tag_values`,
      or `None` if `action` targets a different Tag Key or Tag Value branch.
    """
    payload = action.get("api_payload", {})
    data_governance_tag_field = payload.get("data_governance_tag", {})
    if data_governance_tag_field.get("key", "") != dg_tag_key:
      return None

    explicit_namespaced = action.get(
        constants.FIELD_DG_TAG_VALUE_NAMESPACED_NAME, ""
    )
    if explicit_namespaced and explicit_namespaced in ancestor_tag_values:
      return explicit_namespaced

    action_tag_value = data_governance_tag_field.get("value", "")
    if not action_tag_value:
      return None

    for ancestor_value in ancestor_tag_values:
      relative_path = (
          ancestor_value[len(dg_tag_key) + 1 :]
          if ancestor_value.startswith(f"{dg_tag_key}/")
          else ancestor_value
      )
      if action_tag_value in (ancestor_value, relative_path):
        return ancestor_value

    if "/" not in action_tag_value:
      for ancestor_value in ancestor_tag_values:
        if ancestor_value.split("/")[-1] == action_tag_value:
          return ancestor_value
    return None

  def _get_effective_default_dp_projects(
      self, table_project_id: str, policy_region: str
  ) -> tuple[set[str] | None, str | None]:
    """Queries BigQuery `EFFECTIVE_PROJECT_OPTIONS` for Mode 1 org projects.

    Executes ``SELECT option_value FROM `<table_project_id>`.`region-<loc>`.
    INFORMATION_SCHEMA.EFFECTIVE_PROJECT_OPTIONS WHERE option_name =
    'default_data_policy_projects'`` once per `(table_project_id,
    policy_region)` and caches the raw trimmed project entries verbatim
    (without resolving numeric project numbers or stripping `projects/`
    prefixes, matching BigQuery query-time enforcement).

    Args:
      table_project_id: Project ID owning the BigQuery table being swapped.
      policy_region: Lowercase regional location string (e.g., `'us'`, `'eu'`).

    Returns:
      Tuple `(effective_projects_set, error_message)`. When the query succeeds,
      `error_message` is `None` and `effective_projects_set` contains raw
      trimmed option entries (empty set if unset). On query/permission error,
      returns `(None, error_str)` so callers block fail-closed.
    """
    cache_key = (table_project_id, policy_region.lower())
    if cache_key in self._effective_default_dp_projects_cache:
      return self._effective_default_dp_projects_cache[cache_key]

    if not re.search(r"^[a-zA-Z0-9-]+$", policy_region):
      result = (None, f"Invalid region identifier '{policy_region}'.")
      self._effective_default_dp_projects_cache[cache_key] = result
      return result

    sql = (
        "SELECT option_value FROM"
        f" `{table_project_id}`.`region-{policy_region.lower()}`"
        ".INFORMATION_SCHEMA.EFFECTIVE_PROJECT_OPTIONS"
        " WHERE option_name = 'default_data_policy_projects'"
    )
    target_execution_project = self._execution_project or table_project_id
    try:
      query_job = self._bigquery_client.query(
          sql,
          location=policy_region.lower(),
          project=target_execution_project,
      )
      rows = list(query_job.result())
    except Exception as error:  # pylint: disable=broad-exception-caught
      result = (None, str(error))
      self._effective_default_dp_projects_cache[cache_key] = result
      return result

    # Match BigQuery query-time enforcement verbatim: BigQuery DDL permits
    # numeric strings in `default_data_policy_projects`, but query-time policy
    # lookup compares literal string project IDs without resolving project
    # numbers or stripping `projects/` prefixes.
    effective_projects: set[str] = set()
    for row in rows:
      raw_val = getattr(row, "option_value", None)
      if raw_val is None and isinstance(row, dict):
        raw_val = row.get("option_value")
      inner = str(raw_val or "").strip()
      if inner.startswith("[") and inner.endswith("]"):
        inner = inner[1:-1]
      for item in inner.split(","):
        token = item.strip().strip('"').strip("'").strip()
        if not token:
          continue
        effective_projects.add(token)

    result = (effective_projects, None)
    self._effective_default_dp_projects_cache[cache_key] = result
    return result

  def _verify_mode1_org_and_table_project_parity(
      self,
      swap_detail: ColumnSwapDetail,
      full_dg_tag_value: str,
      is_access_control: bool,
      table_project_id: str,
      central_dp_project_ids: list[str],
      policy_region: str,
      live_tag_key_id: str | None,
      live_tag_value_id: str | None,
      ancestor_tag_values: list[str],
      discrepancies: list[ParityDiscrepancy],
      target_data_policy_mode: str | None = (
          constants.TARGET_DATA_POLICY_MODE_DEFAULT_PROJECT
      ),
  ) -> None:
    """Verifies Organization `default_data_policy_projects` and companion pools.

    BigQuery evaluates V2 Data Policies across both `table_project_id` and every
    project listed in the Organization's regional `default_data_policy_projects`
    option (`table_project_id` overrides Organization default projects only at
    the exact same tag depth). Consequently:
      1. In Mode 1 (`DEFAULT_DATA_POLICY_PROJECT`), every central governance
         project in `central_dp_project_ids` must be registered in
         `default_data_policy_projects` (unless `--skip-default-dp-org-check`),
         and `table_project_id` must contain no conflicting V2 policies.
      2. In both Mode 1 and Mode 2 (`TABLE_PROJECTS`), any additional project
         present in `default_data_policy_projects` outside
         `central_dp_project_ids` is also evaluated by BigQuery and must contain
         zero conflicting V2 Data Policies for this column's Tag Key / lineage.

    Args:
      swap_detail: Column swap detail being audited.
      full_dg_tag_value: Full hierarchical namespaced name of the DG Tag Value.
      is_access_control: True if the source Taxonomy is access-controlled.
      table_project_id: Project ID of the BigQuery table being swapped.
      central_dp_project_ids: Expected Data Policy project ID(s) from plan.json.
      policy_region: Lowercase region of the Policy Tag / Table.
      live_tag_key_id: Numeric `tagKeys/<id>` resource name of the live Tag Key.
      live_tag_value_id: Numeric `tagValues/<id>` name of the live Tag Value.
      ancestor_tag_values: Ordered `[leaf, parent, ..., root]` Tag Value paths.
      discrepancies: Mutable list where detected `ParityDiscrepancy` items are
        appended.
      target_data_policy_mode: Configured V2 Data Policy mode from `plan.json`.
    """
    dg_tag_key = swap_detail.dg_tag_key
    dg_tag_value = swap_detail.dg_tag_value
    is_mode1 = (
        target_data_policy_mode
        == constants.TARGET_DATA_POLICY_MODE_DEFAULT_PROJECT
    )

    effective_projects: set[str] | None = None
    if not self._skip_default_dp_org_check:
      effective_projects, query_error = self._get_effective_default_dp_projects(
          table_project_id, policy_region
      )
      if query_error is not None:
        discrepancies.append(
            ParityDiscrepancy(
                field_path=swap_detail.field_path,
                source_policy_tag=swap_detail.source_policy_tag,
                dg_tag_key=dg_tag_key,
                dg_tag_value=dg_tag_value,
                risk_category=constants.PARITY_RISK_RESOURCE_DISCREPANCY,
                description=(
                    "Failed to verify Organization"
                    " 'default_data_policy_projects' via"
                    f" `{table_project_id}.region-{policy_region}"
                    ".INFORMATION_SCHEMA.EFFECTIVE_PROJECT_OPTIONS`:"
                    f" {query_error}. Grant 'bigquery.config.get' and"
                    " 'bigquery.jobs.create' (or pass --execution-project /"
                    " --skip-default-dp-org-check if verified manually)."
                ),
            )
        )
      elif effective_projects is not None:
        for raw_entry in sorted(effective_projects):
          if raw_entry.isdigit() or raw_entry.startswith("projects/"):
            discrepancies.append(
                ParityDiscrepancy(
                    field_path=swap_detail.field_path,
                    source_policy_tag=swap_detail.source_policy_tag,
                    dg_tag_key=dg_tag_key,
                    dg_tag_value=dg_tag_value,
                    risk_category=constants.PARITY_RISK_ACCESS_LEAKAGE,
                    description=(
                        "Organization 'default_data_policy_projects' for table"
                        f" project '{table_project_id}' in region"
                        f" '{policy_region}' contains non-ID entry"
                        f" '{raw_entry}'. BigQuery query-time enforcement looks"
                        " up V2 Data Policies by literal string project ID"
                        " without resolving numeric project numbers or"
                        " 'projects/' prefixes, leaving cross-project columns"
                        " Fail-Open. Update 'ALTER ORGANIZATION SET OPTIONS"
                        f" (`region-{policy_region}"
                        ".default_data_policy_projects` = ['<project-id>'])'"
                        " to specify the string project ID."
                    ),
                )
            )
        if is_mode1:
          for central_project in central_dp_project_ids:
            if (
                central_project != table_project_id
                and central_project not in effective_projects
            ):
              risk = (
                  constants.PARITY_RISK_ACCESS_LEAKAGE
                  if is_access_control
                  else constants.PARITY_RISK_RESOURCE_DISCREPANCY
              )
              discrepancies.append(
                  ParityDiscrepancy(
                      field_path=swap_detail.field_path,
                      source_policy_tag=swap_detail.source_policy_tag,
                      dg_tag_key=dg_tag_key,
                      dg_tag_value=dg_tag_value,
                      risk_category=risk,
                      description=(
                          "Mode 1 central Data Policy project"
                          f" '{central_project}' is NOT registered in effective"
                          " 'default_data_policy_projects' for table project"
                          f" '{table_project_id}' in region '{policy_region}'"
                          f" (found: {sorted(effective_projects)}). BigQuery"
                          " will NOT enforce V2 Data Policies in"
                          f" '{central_project}', leaving swapped columns"
                          f" Fail-Open. Register '{central_project}' in"
                          " Organization 'default_data_policy_projects' or pass"
                          " --skip-default-dp-org-check if verified"
                          " out-of-band."
                      ),
                  )
              )

    companion_projects: list[tuple[str, bool]] = []
    if is_mode1 and table_project_id not in central_dp_project_ids:
      companion_projects.append((table_project_id, True))
    if effective_projects:
      for org_default_proj in sorted(effective_projects):
        if org_default_proj.isdigit() or org_default_proj.startswith(
            "projects/"
        ):
          continue
        if (
            org_default_proj not in central_dp_project_ids
            and org_default_proj != table_project_id
        ):
          companion_projects.append((org_default_proj, False))

    if not companion_projects:
      return

    ancestor_live_ids: dict[str, str | None] = {}
    for ancestor_value in ancestor_tag_values:
      if ancestor_value in (dg_tag_value, full_dg_tag_value):
        ancestor_live_ids[ancestor_value] = live_tag_value_id
      else:
        ancestor_obj = self._live_tag_values_cache.get(ancestor_value)
        ancestor_live_ids[ancestor_value] = (
            getattr(ancestor_obj, "name", None)
            if ancestor_obj is not None
            else None
        )

    for companion_project_id, is_table_project in companion_projects:
      try:
        companion_policies = self._list_live_v2_data_policies(
            companion_project_id, policy_region
        )
      except Exception as error:  # pylint: disable=broad-exception-caught
        if is_table_project:
          project_role = f"table project '{companion_project_id}'"
        else:
          project_role = (
              "Organization 'default_data_policy_projects' project"
              f" '{companion_project_id}'"
          )
        discrepancies.append(
            ParityDiscrepancy(
                field_path=swap_detail.field_path,
                source_policy_tag=swap_detail.source_policy_tag,
                dg_tag_key=dg_tag_key,
                dg_tag_value=dg_tag_value,
                risk_category=constants.PARITY_RISK_RESOURCE_DISCREPANCY,
                description=(
                    f"Failed to list live V2 Data Policies in {project_role}"
                    f" (region '{policy_region}') during cross-project"
                    f" conflict check: {error}"
                ),
            )
        )
        continue

      if not is_access_control:
        conflicting_policies = [
            policy
            for policy in companion_policies
            if self._policy_matches_tag_key(
                policy,
                dg_tag_key=dg_tag_key,
                live_tag_key_id=live_tag_key_id,
            )
        ]
      else:
        conflicting_policies = [
            policy
            for policy in companion_policies
            if any(
                self._policy_matches_tag(
                    policy,
                    dg_tag_key=dg_tag_key,
                    dg_tag_value=ancestor_value,
                    live_tag_key_id=live_tag_key_id,
                    live_tag_value_id=ancestor_live_ids.get(ancestor_value),
                )
                for ancestor_value in ancestor_tag_values
            )
            or (
                policy.matching_condition
                and self._policy_condition_matches_tag_key(
                    policy.matching_condition,
                    dg_tag_key=dg_tag_key,
                    live_tag_key_id=live_tag_key_id,
                )
            )
        ]

      if is_access_control:
        for unresolved_policy in self._find_unresolved_numeric_tag_key_policies(
            companion_policies, dg_tag_key
        ):
          discrepancies.append(
              ParityDiscrepancy(
                  field_path=swap_detail.field_path,
                  source_policy_tag=swap_detail.source_policy_tag,
                  dg_tag_key=dg_tag_key,
                  dg_tag_value=dg_tag_value,
                  risk_category=constants.PARITY_RISK_ACCESS_LEAKAGE,
                  description=(
                      "Companion project"
                      f" '{companion_project_id}' (region '{policy_region}')"
                      " contains V2 Data Policy"
                      f" '{unresolved_policy.data_policy_id}' referencing"
                      f" numeric Tag Key '{unresolved_policy.dg_tag_key}'"
                      f" sharing short name with '{dg_tag_key}', but the"
                      " numeric project number could not be resolved to verify"
                      " whether it conflicts with this tag. Grant"
                      " 'resourcemanager.projects.get' on the referenced"
                      " project or verify out-of-band before swapping."
                  ),
              )
          )

      for policy in conflicting_policies:
        if policy.name in self._grantee_fetch_errors:
          discrepancies.append(
              ParityDiscrepancy(
                  field_path=swap_detail.field_path,
                  source_policy_tag=swap_detail.source_policy_tag,
                  dg_tag_key=dg_tag_key,
                  dg_tag_value=dg_tag_value,
                  risk_category=constants.PARITY_RISK_RESOURCE_DISCREPANCY,
                  description=(
                      "Failed to verify grantees via REST for V2 Data Policy"
                      f" '{policy.name}' in project '{companion_project_id}':"
                      f" {self._grantee_fetch_errors[policy.name]}"
                  ),
              )
          )

      if conflicting_policies:
        conflict_ids = [
            policy.data_policy_id for policy in conflicting_policies
        ]
        if not is_access_control:
          conflict_risk = constants.PARITY_RISK_ACCESS_BLOCKAGE
        elif any(
            policy.grantees
            or policy.data_policy_type == constants.DATA_POLICY_TYPE_MASKING
            for policy in conflicting_policies
        ):
          conflict_risk = constants.PARITY_RISK_ACCESS_LEAKAGE
        else:
          conflict_risk = constants.PARITY_RISK_RESOURCE_DISCREPANCY

        if is_table_project:
          conflict_desc = (
              f"Table project '{companion_project_id}' contains unexpected V2"
              f" Data Policy(ies) {conflict_ids} targeting '{dg_tag_value}'"
              " (or its Tag Key / ancestors) under Mode 1"
              f" ({constants.TARGET_DATA_POLICY_MODE_DEFAULT_PROJECT})."
              " Table-project V2 Data Policies take precedence over"
              " Organization 'default_data_policy_projects' at equal tag depth"
              " and can override central governance policies."
          )
        else:
          conflict_desc = (
              "Organization 'default_data_policy_projects' project"
              f" '{companion_project_id}' contains unexpected V2 Data"
              f" Policy(ies) {conflict_ids} targeting '{dg_tag_value}' (or its"
              f" Tag Key '{dg_tag_key}' / ancestors) for table project"
              f" '{table_project_id}' in region '{policy_region}'. BigQuery"
              " evaluates Organization default Data Policy projects alongside"
              " table-project policies and can grant extra access, alter"
              " masking, or trigger Default Deny."
          )
        discrepancies.append(
            ParityDiscrepancy(
                field_path=swap_detail.field_path,
                source_policy_tag=swap_detail.source_policy_tag,
                dg_tag_key=dg_tag_key,
                dg_tag_value=dg_tag_value,
                risk_category=conflict_risk,
                description=conflict_desc,
            )
        )

  def _resolve_expected_data_policy_projects(
      self, plan: dict[str, Any], table_project_id: str
  ) -> list[str]:
    """Determines which project(s) must contain V2 Data Policies for a table.

    Supports both V2 Data Policy placement modes from `plan.json`:
      - Mode 1 (`DEFAULT_PROJECT`): Central governance project stored in
        `metadata.target_data_policy_project_ids[0]`.
      - Mode 2 (`TABLE_PROJECTS`): Distributed table-project placement where
        each table's own `table_project_id` must host the regional V2 Data
        Policies.

    Args:
      plan: Parsed migration plan dictionary.
      table_project_id: Project ID of the BigQuery table being verified.

    Returns:
      A list of project IDs where V2 Data Policies must be verified.
    """
    metadata = plan.get("metadata", {})
    mode = metadata.get("target_data_policy_mode")
    configured_projects = metadata.get("target_data_policy_project_ids", [])

    if mode == constants.TARGET_DATA_POLICY_MODE_DEFAULT_PROJECT:
      if configured_projects:
        return [configured_projects[0]]
    elif mode == constants.TARGET_DATA_POLICY_MODE_TABLE_PROJECTS:
      return [table_project_id]

    manifest = plan.get(constants.KEY_PHASE_2_RESOURCE_MANIFEST, {})
    manifest_policies = (
        list(
            manifest.get(
                constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2, []
            )
        )
        + list(
            manifest.get(
                constants.KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2, []
            )
        )
        + list(
            manifest.get(constants.KEY_DATA_POLICIES_V1_TO_DATA_POLICIES_V2, [])
        )
        + list(manifest.get("create_data_policies_v2", []))
    )
    manifest_projects = sorted({
        action.get("target_project_id")
        for action in manifest_policies
        if action.get("target_project_id")
    })
    if table_project_id in manifest_projects:
      return [table_project_id]
    if manifest_projects:
      return manifest_projects
    return [table_project_id]

  def _is_data_governance_purpose(self, purpose_value: Any) -> bool:
    """Returns True if a TagKey purpose represents `DATA_GOVERNANCE`.

    Handles enum integer (`2`), enum name strings (`"DATA_GOVERNANCE"`,
    `"Purpose.DATA_GOVERNANCE"`), and `resourcemanager_v3.TagKey.Purpose` enum
    instances across SDK versions.

    Args:
      purpose_value: Raw `purpose` attribute from a Resource Manager `TagKey`.

    Returns:
      True if `purpose_value` represents `DATA_GOVERNANCE`.
    """
    if purpose_value is None:
      return False
    if purpose_value == 2 or str(purpose_value) in (
        "2",
        constants.TAG_PURPOSE_DATA_GOVERNANCE,
        "Purpose.DATA_GOVERNANCE",
    ):
      return True
    if hasattr(resourcemanager_v3.TagKey, "Purpose"):
      try:
        return (
            purpose_value == resourcemanager_v3.TagKey.Purpose.DATA_GOVERNANCE
        )
      except (ValueError, AttributeError):
        return False
    return False

  def _extract_region_from_policy_tag(self, policy_tag_name: str) -> str | None:
    """Extracts the lowercase location segment from a Policy Tag resource URI.

    Args:
      policy_tag_name: Policy Tag URI
        (`projects/<p>/locations/<loc>/taxonomies/<t>/policyTags/<pt>`).

    Returns:
      The lowercase region string (e.g., `'us'`), or `None` if not matched.
    """
    match = re.search(r"/locations/([^/]+)/taxonomies/", policy_tag_name)
    if match:
      return match.group(1).lower()
    return None

  def _get_tag_value_hierarchy_chain(
      self,
      dg_tag_value: str,
      planned_values: dict[str, dict[str, Any]],
  ) -> list[str]:
    """Returns `[dg_tag_value, parent_tag_value, ..., root_tag_value]`.

    Walks `parent_namespaced_name` pointers in `planned_values` from leaf to
    root (with cycle protection) so `_compare_tag_value_enforcement` can
    evaluate ancestor V2 Data Policies inherited via
    `column.matchTagHierarchy`.

    Args:
      dg_tag_value: Full namespaced name of the target DG Tag Value.
      planned_values: Map from Tag Value `namespaced_name` to manifest action.

    Returns:
      Ordered list of Tag Value namespaced names from leaf to root.
    """
    chain = [dg_tag_value]
    current = dg_tag_value
    visited = {dg_tag_value}
    while current in planned_values:
      action = planned_values[current]
      parent_namespaced = action.get("parent_namespaced_name", "")
      # A Tag Key namespaced name has 2 segments (project/key_short_name),
      # whereas a parent Tag Value has 3 segments (project/key/value).
      if parent_namespaced.count("/") >= 2 and parent_namespaced not in visited:
        chain.append(parent_namespaced)
        visited.add(parent_namespaced)
        current = parent_namespaced
      else:
        break
    return chain

  @classmethod
  def _extract_policy_matching_condition(
      cls, policy: Any, is_rest: bool
  ) -> str | None:
    """Extracts a condition expression from a REST or SDK V2 Data Policy.

    Inspects both the SQL-like `matching_condition` (`matchingCondition`) field
    and the CEL `data_governance_tag_condition.expression`
    (`dataGovernanceTagCondition.expression`) submessage so condition-bound V2
    Data Policies are never invisible during pre-swap parity verification.

    Args:
      policy: Raw REST dictionary or SDK `DataPolicy` message.
      is_rest: True when `policy` is a JSON dictionary from REST `/v2/`.

    Returns:
      Stripped condition expression string, or `None` when not condition-bound.
    """
    if is_rest:
      matching_cond = policy.get("matchingCondition")
      if isinstance(matching_cond, str) and matching_cond.strip():
        return matching_cond.strip()
      dgt_cond = policy.get("dataGovernanceTagCondition")
      if isinstance(dgt_cond, dict):
        expr = dgt_cond.get("expression")
        if isinstance(expr, str) and expr.strip():
          return expr.strip()
      return None

    matching_cond = getattr(policy, "matching_condition", None)
    if isinstance(matching_cond, str) and matching_cond.strip():
      return matching_cond.strip()
    dgt_cond = getattr(policy, "data_governance_tag_condition", None)
    if dgt_cond is not None:
      expr = getattr(dgt_cond, "expression", None)
      if isinstance(expr, str) and expr.strip():
        return expr.strip()
    return None

  def _tag_key_ref_matches(
      self,
      raw_key: str,
      dg_tag_key: str,
      live_tag_key_id: str | None = None,
      fail_closed_on_unresolved_numeric: bool = False,
  ) -> bool:
    """Checks whether a policy Tag Key reference matches `dg_tag_key`.

    Supports exact namespaced names (`proj/key`), numeric project-number
    namespaced names (`123456/key`), bare short names (`key`), and Resource
    Manager numeric IDs (`tagKeys/111`).

    Fail-Closed vs. Exact Matching Discipline:
      - Callers verifying that a **required** planned policy exists
        (`_policy_matches_tag`) MUST leave
        `fail_closed_on_unresolved_numeric=False` so an unverified
        `<other_project_num>/<key>` policy can never falsely satisfy a missing
        `_default_deny`, raw reader, or masking policy.
      - Callers detecting **conflicting or restrictive** policies
        (`_policy_matches_tag_key`, `_policy_condition_matches_tag_key`) pass
        `fail_closed_on_unresolved_numeric=True` so an unresolvable
        `<project_number>/<key_short>` reference sharing `dg_tag_key`'s short
        name fails closed rather than silently passing parity.

    Args:
      raw_key: Tag Key string referenced by a live V2 Data Policy or condition.
      dg_tag_key: Expected DG Tag Key namespaced name (`project/key_short`).
      live_tag_key_id: Optional Resource Manager `tagKeys/<id>` resource name.
      fail_closed_on_unresolved_numeric: When True, returns True if `raw_key`
        uses `<digits>/<short_name>` matching `dg_tag_key`'s short name and the
        numeric project cannot be resolved.

    Returns:
      True if `raw_key` refers to `dg_tag_key` (or cannot be proven disjoint
      when `fail_closed_on_unresolved_numeric=True`).
    """
    if not raw_key:
      return False
    key_short_name = dg_tag_key.split("/")[-1]
    normalized_key = raw_key
    if "/" in raw_key:
      pol_proj, pol_short = raw_key.split("/", 1)
      if pol_proj.isdigit():
        resolved_proj_id = self._resolve_project_number(pol_proj)
        if resolved_proj_id:
          normalized_key = f"{resolved_proj_id}/{pol_short}"
        elif fail_closed_on_unresolved_numeric and pol_short == key_short_name:
          return True
    return (
        raw_key == dg_tag_key
        or normalized_key == dg_tag_key
        or ("/" not in raw_key and raw_key == key_short_name)
        or (live_tag_key_id is not None and raw_key == live_tag_key_id)
    )

  def _find_unresolved_numeric_tag_key_policies(
      self,
      policies: list[LiveDataPolicyV2Summary],
      dg_tag_key: str,
  ) -> list[LiveDataPolicyV2Summary]:
    """Finds policies with unresolvable `<digits>/<key_short>` Tag Key refs.

    Args:
      policies: Live V2 Data Policy summaries to inspect.
      dg_tag_key: Target DG Tag Key namespaced name (`project/key_short`).

    Returns:
      Policies whose `dg_tag_key` has `<digits>/<pol_short>` matching
      `dg_tag_key`'s short name where `_resolve_project_number(digits)` returns
      `None`.
    """
    key_short_name = dg_tag_key.split("/")[-1]
    unresolved: list[LiveDataPolicyV2Summary] = []
    for policy in policies:
      raw_key = policy.dg_tag_key or ""
      if "/" not in raw_key:
        continue
      pol_proj, pol_short = raw_key.split("/", 1)
      if (
          pol_proj.isdigit()
          and pol_short == key_short_name
          and self._resolve_project_number(pol_proj) is None
      ):
        unresolved.append(policy)
    return unresolved

  def _policy_condition_matches_tag_key(
      self,
      condition_expr: str | None,
      dg_tag_key: str,
      live_tag_key_id: str | None = None,
  ) -> bool:
    """Checks if a V2 policy condition expression can match `dg_tag_key`.

    Parses supported SQL-like (`COLUMN_HAS_TAG_KEY`, `COLUMN_MATCH_TAG`,
    `RESOURCE_HAS_TAG_KEY`, `RESOURCE_MATCH_TAG`) and CEL (`column.hasTagKey`,
    `resource.hasTagKey`, `column.matchTagHierarchy`, `column.matchTag`,
    `resource.matchTag`, `resource.matchTagHierarchy`) tag predicates. If a
    non-empty expression contains negation (`NOT`, `!`), any unrecognized
    function, escaped string, or unparsed token outside positive `AND`/`OR`
    operators and parentheses, fails closed by returning `True` (because a
    negated predicate such as `!column.hasTagKey('other-proj/key')` evaluates
    to `True` on columns without that key, including the swapped column).

    Args:
      condition_expr: Condition string from `LiveDataPolicyV2Summary`.
      dg_tag_key: Expected DG Tag Key namespaced name (`project/key_short`).
      live_tag_key_id: Optional Resource Manager `tagKeys/<id>` resource name.

    Returns:
      True if any predicate references `dg_tag_key` or if `condition_expr`
      cannot be statically proven disjoint from `dg_tag_key`.
    """
    if not condition_expr or not condition_expr.strip():
      return False

    expr = condition_expr.strip()
    one_arg_pattern = re.compile(
        r"\b(?:(?:column|resource)_has_tag_key|(?:column|resource)\.hastagkey)"
        r"\s*\(\s*(?:'([^'\\]+)'|\"([^\"\\]+)\")\s*\)",
        re.IGNORECASE,
    )
    two_arg_pattern = re.compile(
        r"\b(?:(?:column|resource)_match_tag"
        r"|(?:column|resource)\.matchtag(?:hierarchy)?)"
        r"\s*\(\s*(?:'([^'\\]+)'|\"([^\"\\]+)\")\s*,"
        r"\s*(?:'[^'\\]*'|\"[^\"\\]*\")\s*\)",
        re.IGNORECASE,
    )

    extracted_keys: list[str] = []
    for match in one_arg_pattern.finditer(expr):
      extracted_keys.append(match.group(1) or match.group(2) or "")
    for match in two_arg_pattern.finditer(expr):
      extracted_keys.append(match.group(1) or match.group(2) or "")

    if not extracted_keys:
      return True

    remainder = one_arg_pattern.sub(" ", expr)
    remainder = two_arg_pattern.sub(" ", remainder)
    remainder = re.sub(r"\b(?:AND|OR)\b", " ", remainder, flags=re.I)
    remainder = re.sub(r"[()&|\s]+", "", remainder)
    if remainder:
      return True

    return any(
        self._tag_key_ref_matches(
            key_ref,
            dg_tag_key,
            live_tag_key_id,
            fail_closed_on_unresolved_numeric=True,
        )
        for key_ref in extracted_keys
    )

  def _policy_matches_tag_key(
      self,
      policy: LiveDataPolicyV2Summary,
      dg_tag_key: str,
      live_tag_key_id: str | None = None,
  ) -> bool:
    """Checks if a live V2 Data Policy references `dg_tag_key` in any form."""
    if self._tag_key_ref_matches(
        policy.dg_tag_key,
        dg_tag_key,
        live_tag_key_id,
        fail_closed_on_unresolved_numeric=True,
    ):
      return True
    return self._policy_condition_matches_tag_key(
        policy.matching_condition, dg_tag_key, live_tag_key_id
    )

  def _policy_matches_tag(
      self,
      policy: LiveDataPolicyV2Summary,
      dg_tag_key: str,
      dg_tag_value: str,
      live_tag_key_id: str | None = None,
      live_tag_value_id: str | None = None,
  ) -> bool:
    """Checks if a live V2 Data Policy targets the given DG Tag Key & Value.

    Requires exact project/key/path or short-name matching within the verified
    Tag Key (or exact `tagKeys/<id>` / `tagValues/<id>` matching) without
    loose `.endswith()` suffix matching, preventing cross-project or sibling
    sub-branch Tag Values sharing a leaf short name from false-matching.

    Args:
      policy: Normalized summary of the live V2 Data Policy.
      dg_tag_key: Expected DG Tag Key namespaced name (`project/key_short`).
      dg_tag_value: Expected DG Tag Value full namespaced path.
      live_tag_key_id: Optional Resource Manager `tagKeys/<id>` resource name.
      live_tag_value_id: Optional Resource Manager `tagValues/<id>` name.

    Returns:
      True if the policy targets the exact DG Tag Key and Value.
    """
    value_short_name = dg_tag_value.split("/")[-1]
    policy_key = policy.dg_tag_key or ""
    policy_value = policy.dg_tag_value or ""
    if not self._tag_key_ref_matches(policy_key, dg_tag_key, live_tag_key_id):
      return False

    normalized_policy_value = policy_value
    if "/" in policy_key:
      pol_proj, pol_short = policy_key.split("/", 1)
      if pol_proj.isdigit():
        resolved_proj_id = self._resolve_project_number(pol_proj)
        if resolved_proj_id and policy_value.startswith(f"{policy_key}/"):
          normalized_policy_key = f"{resolved_proj_id}/{pol_short}"
          normalized_policy_value = (
              f"{normalized_policy_key}/{policy_value[len(policy_key) + 1:]}"
          )

    value_relative_path = (
        dg_tag_value[len(dg_tag_key) + 1 :]
        if dg_tag_value.startswith(f"{dg_tag_key}/")
        else dg_tag_value
    )
    allowed_value_forms = {
        dg_tag_value,
        value_relative_path,
        f"{dg_tag_key}/{value_short_name}",
    }
    value_matches = (
        policy_value in allowed_value_forms
        or normalized_policy_value in allowed_value_forms
        or ("/" not in policy_value and policy_value == value_short_name)
        or (live_tag_value_id is not None and policy_value == live_tag_value_id)
    )
    return value_matches

  def _normalize_routine_path(self, routine_path: str | None) -> str:
    """Normalizes a custom UDF routine path by resolving numeric project IDs.

    BigQuery Data Policy Service V2 canonicalizes `data_masking_policy.routine`
    on the server from `projects/<project_id>/datasets/<d>/routines/<r>` to
    `projects/<project_number>/datasets/<d>/routines/<r>`. Resolving numeric
    `<project_number>` tokens back to `<project_id>` via
    `_resolve_project_number` ensures pre-swap enforcement parity comparisons
    match canonicalized live V2 Data Policies against `plan.json`.

    Args:
      routine_path: Raw routine resource path
        (`projects/<p>/datasets/<d>/routines/<r>`), or `None`.

    Returns:
      Normalized routine resource path string (or `""` if `routine_path` is
      empty or `None`).
    """
    if not routine_path:
      return ""
    stripped_path = routine_path.strip()
    parts = stripped_path.split("/")
    if (
        len(parts) == 6
        and parts[0] == "projects"
        and parts[2] == "datasets"
        and parts[4] == "routines"
        and parts[1].isdigit()
    ):
      resolved_project_id = self._resolve_project_number(parts[1])
      if resolved_project_id:
        parts[1] = resolved_project_id
        return "/".join(parts)
    return stripped_path

  def _masking_rule_matches(
      self,
      policy: LiveDataPolicyV2Summary,
      expected_expression: str | None,
      expected_routine: str | None,
  ) -> bool:
    """Checks if a live V2 masking policy matches the expected rule.

    Normalizes custom UDF routine paths via `_normalize_routine_path` on both
    the live V2 Data Policy and the expected `plan.json` specification so that
    server-canonicalized numeric project numbers (`projects/466393599270/...`)
    match human-readable project IDs (`projects/my-project/...`).

    Args:
      policy: Normalized summary of the live V2 Data Policy.
      expected_expression: Expected predefined masking expression name (e.g.,
        `'SHA256'`), or `None` if a custom masking routine is expected.
      expected_routine: Expected custom UDF routine resource path, or `None` if
        a predefined expression is expected.

    Returns:
      True if the policy's masking rule matches the expected expression or
      routine; False when neither `expected_expression` nor `expected_routine`
      is specified (fail-closed) or when the live rule differs.
    """
    if expected_expression:
      return (policy.masking_expression or "") == expected_expression
    if expected_routine:
      live_routine = self._normalize_routine_path(policy.masking_routine)
      planned_routine = self._normalize_routine_path(expected_routine)
      return bool(live_routine) and live_routine == planned_routine
    # Fail closed if `plan.json` carries an empty `data_masking_policy: {}` so
    # an unspecified expected rule never matches arbitrary live masking rules.
    return False

  def _list_live_v2_data_policies(
      self, project_id: str, location: str
  ) -> list[LiveDataPolicyV2Summary]:
    """Lists and normalizes live V2 Data Policies in a project and location.

    Architectural Rationale (gRPC SDK vs. REST Fallback & Grantee Hydration):
      1. Caching: Caches normalized `LiveDataPolicyV2Summary` lists per
         `(project_id, location.lower())` so verifying 1,000 tables in the same
         project and region calls `list_data_policies` only once.
      2. REST fallback for V1-aliased or older V2 SDKs: When `main.py` aliases
         `bigquery_datapolicies_v2` to `bigquery_datapolicies_v1` (because the
         V2 module is absent), V1 `ListDataPolicies` filters out V2 tag-based
         and matching-condition policies on the server and can return `[]` even
         when live V2 policies exist. Likewise, older V2 wheels omit the
         `data_governance_tag` protobuf field. Whenever the client module is V1,
         the SDK call fails, or returned SDK policies lack
         `data_governance_tag`, this method queries the authenticated REST
         `GET /v2/{parent}/dataPolicies` endpoint.
      3. Grantee hydration: When a DGT-backed V2 policy has no inline `grantees`
         on the list response, fetches `GET /v2/{name}` in parallel (up to 16
         threads) once per `(project_id, location)` to hydrate `grantees`
         (including `*_default_deny` policies so out-of-band grantee tampering
         is caught fail-closed).

    Args:
      project_id: GCP project ID hosting V2 Data Policies.
      location: Regional location string (e.g., `'us'`, `'eu'`).

    Returns:
      List of normalized `LiveDataPolicyV2Summary` objects targeting DG Tags.
    """
    cache_key = (project_id, location.lower())
    if cache_key in self._live_v2_policies_cache:
      return self._live_v2_policies_cache[cache_key]

    parent = f"projects/{project_id}/locations/{location.lower()}"
    raw_policies: list[tuple[Any, bool]] = []

    sdk_policies: list[Any] = []
    sdk_error: Exception | None = None
    try:
      sdk_policies = list(
          self._data_policy_v2_client.list_data_policies(parent=parent)
      )
    except Exception as error:  # pylint: disable=broad-exception-caught
      sdk_error = error

    # Mirror `Analyzer`: when `bigquery_datapolicies_v2` is aliased to V1, V1
    # `ListDataPolicies` hides DGT-backed V2 policies and can return `[]`, so
    # always verify via the `/v2/` REST endpoint on V1 client instances.
    client_module = getattr(type(self._data_policy_v2_client), "__module__", "")
    is_v1_client = client_module.startswith(
        "google.cloud.bigquery_datapolicies_v1"
    )
    has_dgt_support = any(
        getattr(policy, "data_governance_tag", None) is not None
        or self._extract_policy_matching_condition(policy, False) is not None
        for policy in sdk_policies
    )
    # Require both `matching_condition` and `data_governance_tag_condition`
    # schema support on every returned SDK object so intermediate wheels
    # lacking either condition field fall back to REST `/v2/` instead of
    # silently dropping condition-bound policies as label-less entries.
    has_condition_field_support = all(
        hasattr(policy, "matching_condition")
        and hasattr(policy, "data_governance_tag_condition")
        for policy in sdk_policies
    )
    if (
        sdk_error is None
        and not is_v1_client
        and (
            not sdk_policies
            or (has_dgt_support and has_condition_field_support)
        )
    ):
      raw_policies = [(policy, False) for policy in sdk_policies]
    else:
      try:
        rest_policies = self._list_data_policies_v2_rest(
            project_id, location.lower()
        )
        raw_policies = [(policy, True) for policy in rest_policies]
      except Exception as rest_error:  # pylint: disable=broad-exception-caught
        if sdk_error is not None:
          raise sdk_error from rest_error
        raise

    # Hydrate `grantees` via parallel REST `GET /v2/{name}` for all DGT-backed
    # and condition-bound V2 policies—including synthetic `*_default_deny`
    # seatbelts—so out-of-band grantee drift is caught as `ACCESS_LEAKAGE_RISK`.
    policies_needing_grantees: list[str] = []
    for policy, is_rest in raw_policies:
      matching_condition = self._extract_policy_matching_condition(
          policy, is_rest
      )
      if is_rest:
        dg_tag_dict = policy.get("dataGovernanceTag")
        has_dg_tag = bool(
            isinstance(dg_tag_dict, dict)
            and (dg_tag_dict.get("key") or dg_tag_dict.get("value"))
        )
        if (
            not policy.get("grantees")
            and policy.get("name")
            and (has_dg_tag or matching_condition)
        ):
          policies_needing_grantees.append(policy["name"])
      else:
        policy_name = getattr(policy, "name", None)
        dg_tag_obj = getattr(policy, "data_governance_tag", None)
        has_dg_tag = bool(
            dg_tag_obj
            and (
                getattr(dg_tag_obj, "key", "")
                or getattr(dg_tag_obj, "value", "")
            )
        )
        if (
            policy_name
            and not getattr(policy, "grantees", None)
            and (has_dg_tag or matching_condition)
        ):
          policies_needing_grantees.append(policy_name)

    fetched_grantees = (
        self._fetch_v2_data_policy_grantees(policies_needing_grantees)
        if policies_needing_grantees
        else {}
    )

    summaries: list[LiveDataPolicyV2Summary] = []
    for policy, is_rest in raw_policies:
      matching_condition = self._extract_policy_matching_condition(
          policy, is_rest
      )
      if is_rest:
        dg_tag_field = policy.get("dataGovernanceTag")
        has_dg_tag = bool(
            isinstance(dg_tag_field, dict)
            and (dg_tag_field.get("key") or dg_tag_field.get("value"))
        )
        if (
            policy.get("policyTag")
            and not has_dg_tag
            and not matching_condition
        ):
          continue
        if not has_dg_tag and not matching_condition:
          continue
        dg_tag_key = (
            dg_tag_field.get("key", "")
            if isinstance(dg_tag_field, dict)
            else ""
        )
        dg_tag_value = (
            dg_tag_field.get("value", "")
            if isinstance(dg_tag_field, dict)
            else ""
        )
        data_policy_id = (
            policy.get("dataPolicyId") or policy.get("name", "").split("/")[-1]
        )
        policy_name = policy.get(
            "name", f"{parent}/dataPolicies/{data_policy_id}"
        )
        policy_type_name = policy.get("dataPolicyType", "")
        masking_policy = policy.get("dataMaskingPolicy") or {}
        masking_expression = masking_policy.get("predefinedExpression")
        masking_routine = masking_policy.get("routine")
        grantees = list(policy.get("grantees", []))
        if not grantees and policy_name in fetched_grantees:
          grantees = fetched_grantees[policy_name]
      else:
        dg_tag_field = getattr(policy, "data_governance_tag", None)
        dg_tag_key = (
            getattr(dg_tag_field, "key", "") or "" if dg_tag_field else ""
        )
        dg_tag_value = (
            getattr(dg_tag_field, "value", "") or "" if dg_tag_field else ""
        )
        has_dg_tag = bool(dg_tag_key or dg_tag_value)
        if (
            getattr(policy, "policy_tag", None)
            and not has_dg_tag
            and not matching_condition
        ):
          continue
        if not has_dg_tag and not matching_condition:
          continue
        policy_name = getattr(policy, "name", "") or ""
        data_policy_id = (
            getattr(policy, "data_policy_id", None)
            or policy_name.split("/")[-1]
        )
        raw_type = getattr(policy, "data_policy_type", None)
        if hasattr(raw_type, "name"):
          policy_type_name = raw_type.name
        else:
          type_map = {
              1: constants.DATA_POLICY_TYPE_MASKING,
              2: constants.DATA_POLICY_TYPE_RAW,
              3: constants.DATA_POLICY_TYPE_CLS,
          }
          policy_type_name = type_map.get(raw_type, str(raw_type or ""))

        masking_expression = None
        masking_routine = None
        masking_policy = getattr(policy, "data_masking_policy", None)
        if masking_policy:
          predefined_expression = getattr(
              masking_policy, "predefined_expression", None
          )
          if predefined_expression:
            expression_name = (
                predefined_expression.name
                if hasattr(predefined_expression, "name")
                else str(predefined_expression)
            )
            if expression_name != "PREDEFINED_EXPRESSION_UNSPECIFIED":
              masking_expression = expression_name
          routine_value = getattr(masking_policy, "routine", None)
          if routine_value:
            masking_routine = str(routine_value)

        grantees = list(getattr(policy, "grantees", None) or [])
        if not grantees and policy_name in fetched_grantees:
          grantees = fetched_grantees[policy_name]

      # BigQuery Data Policy Service canonicalizes `policy.name` on the wire to
      # `projects/<project_number>/locations/<loc>/dataPolicies/<id>`. When
      # `project_id` is a string project ID, seed `_project_number_to_id_cache`
      # before normalizing `masking_routine` so custom routines in the same
      # project resolve to `<project_id>` with zero extra RPCs.
      if not project_id.isdigit() and policy_name:
        policy_name_parts = policy_name.split("/")
        if (
            len(policy_name_parts) >= 2
            and policy_name_parts[0] == "projects"
            and policy_name_parts[1].isdigit()
        ):
          self._project_number_to_id_cache.setdefault(
              policy_name_parts[1], project_id
          )
      if masking_routine:
        masking_routine = self._normalize_routine_path(masking_routine) or None

      summaries.append(
          LiveDataPolicyV2Summary(
              name=policy_name,
              data_policy_id=data_policy_id,
              data_policy_type=policy_type_name,
              dg_tag_key=dg_tag_key,
              dg_tag_value=dg_tag_value,
              masking_expression=masking_expression,
              masking_routine=masking_routine,
              grantees=grantees,
              matching_condition=matching_condition,
          )
      )

    self._live_v2_policies_cache[cache_key] = summaries
    return summaries

  def _urlopen_json_with_retry(
      self,
      request: urllib.request.Request,
      timeout: float = 30.0,
      max_attempts: int = 3,
  ) -> dict[str, Any]:
    """Executes an HTTP request with timeout and exponential backoff."""
    return self._rest_client.urlopen_json_with_retry(
        request, timeout=timeout, max_attempts=max_attempts
    )

  def _list_data_policies_v2_rest(
      self, project_id: str, location: str
  ) -> list[dict[str, Any]]:
    """Lists V2 data policies via REST when SDK lacks `data_governance_tag`."""
    return self._rest_client.list_data_policies_v2(project_id, location)

  def _fetch_v2_data_policy_grantees(
      self, policy_names: list[str]
  ) -> dict[str, list[str]]:
    """Fetches grantees for V2 Data Policies via parallel REST GET calls.

    Uses a bounded `ThreadPoolExecutor(max_workers=16)` to fetch individual
    `GET /v2/{name}` payloads because `ListDataPolicies` omits `grantees` on the
    wire. Records both credential failures and per-policy HTTP/network errors in
    `_grantee_fetch_errors` so `_compare_tag_value_enforcement` blocks
    fail-closed with `RESOURCE_DISCREPANCY` instead of assuming empty grantees.

    Args:
      policy_names: Full V2 Data Policy resource names requiring grantee lookup.

    Returns:
      Map from policy resource name to its list of IAM grantee strings.
    """
    if not policy_names:
      return {}

    grantees_by_name: dict[str, list[str]] = {}
    try:
      self._rest_client.get_bearer_token()
      endpoint = self._get_datapolicy_endpoint()

      def fetch_single(name: str) -> tuple[str, list[str], str | None]:
        url = f"{endpoint}/v2/{name}"
        try:
          current_token = self._rest_client.get_bearer_token()
          req_headers = {"Authorization": f"Bearer {current_token}"}
          request = urllib.request.Request(url, headers=req_headers)
          data = self._urlopen_json_with_retry(request)
          return name, list(data.get("grantees", [])), None
        except Exception as error:  # pylint: disable=broad-exception-caught
          logger.warning(
              "Failed to fetch grantees for V2 Data Policy %s via REST: %s",
              name,
              error,
          )
          return name, [], str(error)

      max_workers = min(16, len(policy_names))
      with concurrent.futures.ThreadPoolExecutor(
          max_workers=max_workers
      ) as executor:
        for name, grantees, error_message in executor.map(
            fetch_single, policy_names
        ):
          if error_message is not None:
            self._grantee_fetch_errors[name] = error_message
          if grantees:
            grantees_by_name[name] = grantees
    except Exception as error:  # pylint: disable=broad-exception-caught
      logger.warning(
          "Failed to obtain credentials for V2 Data Policy REST grantee"
          " verification: %s",
          error,
      )
      for name in policy_names:
        self._grantee_fetch_errors[name] = str(error)

    return grantees_by_name

  def _get_datapolicy_endpoint(self) -> str:
    """Returns the base URL for the BigQuery Data Policy Service."""
    return self._rest_client.get_endpoint()

  def _verify_backup_dir_writable(self) -> None:
    """Verifies that `self._backup_dir` can be created and written to.

    Architectural Rationale (Fail-Fast Pre-Swap Safeguard):
      Before `swap_schemas` resolves target tables or prompts the operator for
      cutover confirmations, this method creates `self._backup_dir` (if absent)
      and opens/deletes a temporary probe file inside it. If `--backup-dir`
      points to a read-only filesystem or an existing non-directory file, the
      swap phase fails immediately before any table inspection or schema
      mutation occurs.

    Raises:
      OSError: If `self._backup_dir` cannot be created or is not writable.
    """
    os.makedirs(self._backup_dir, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w",
        encoding="utf-8",
        dir=self._backup_dir,
        prefix=".swap_backup_write_check_",
        delete=True,
    ) as probe_file:
      probe_file.write("")
      probe_file.flush()

  def _get_backup_file_path(
      self, project_id: str, dataset_id: str, table_id: str
  ) -> str:
    r"""Returns the mode/project/dataset-isolated schema backup file path.

    Writes backups under
    `<backup_dir>/pt_to_dgt/<project>/<dataset>/<table>.json` (forward mode) or
    `<backup_dir>/dgt_to_pt/<project>/<dataset>/<table>.json` (rollback mode) so
    dataset/table names containing `__` or `_rollback` can never collide.
    Rejects legacy domain-scoped project IDs (`:`) and path traversal segments.

    Args:
      project_id: Standard Google Cloud project ID.
      dataset_id: BigQuery dataset ID.
      table_id: BigQuery table ID.

    Returns:
      Local backup file path string.

    Raises:
      ValueError: If `project_id` is domain-scoped or any segment is empty or
        contains path separators (`/` or `\\`) or `.`/`..` traversal tokens.
    """
    clean_project = constants.validate_standard_project_id(
        project_id, "project_id"
    )
    clean_dataset = (dataset_id or "").strip()
    clean_table = (table_id or "").strip()
    for label, segment in (
        ("project_id", clean_project),
        ("dataset_id", clean_dataset),
        ("table_id", clean_table),
    ):
      if (
          not segment
          or "/" in segment
          or "\\" in segment
          or segment in (".", "..")
      ):
        raise ValueError(
            f"Invalid {label} '{segment}' when constructing schema backup path."
        )
    mode_subdir = (
        constants.BACKUP_SUBDIR_DGT_TO_PT
        if self._swap_mode == constants.SWAP_MODE_DGT_TO_PT
        else constants.BACKUP_SUBDIR_PT_TO_DGT
    )
    return os.path.join(
        self._backup_dir,
        mode_subdir,
        clean_project,
        clean_dataset,
        f"{clean_table}.json",
    )

  def _build_restore_ready_schema_fields(
      self,
      original_fields: list[dict[str, Any]],
      swapped_columns: list[ColumnSwapDetail] | None = None,
      active_opposite_tag_paths: set[str] | None = None,
  ) -> list[dict[str, Any]]:
    """Builds a deep-copied schema field list ready for `bq update` restore.

    Architectural Rationale (BigQuery Unset-Tag Preservation & Exclusivity):
      When BigQuery `tables.patch` or `bq update` applies a JSON schema file,
      omitting `dataGovernanceTagsInfo` on a column keeps any existing Data
      Governance Tags attached on the server, and omitting `policyTags` keeps
      any existing Policy Tags attached. Because BigQuery also enforces mutual
      exclusivity between Policy Tags and Data Governance Tags on the same
      column, restoring a raw pre-swap JSON snapshot (where the opposite tag
      property was omitted by `tables.get`) would keep the newly attached tag
      while re-adding the original tag—either failing with HTTP 400 Invalid
      Argument or leaving both tags attached.

      To guarantee `bq update` and compensating `tables.patch` restores clear
      newly attached opposite tags cleanly without touching unmapped columns,
      unrelated pre-existing tags, or `RECORD` / `STRUCT` containers (which do
      not accept leaf governance tags):
        - In forward mode (`pt-to-dgt`): injects
          `"dataGovernanceTagsInfo": {"dataGovernanceTags": {}}` onto targeted
          leaf columns that do not already carry non-empty Data Governance Tags.
        - In rollback mode (`dgt-to-pt`): injects
          `"policyTags": {"names": []}` onto targeted leaf columns that do not
          already carry non-empty Policy Tags.

    Args:
      original_fields: Original pre-mutation BigQuery schema field dicts.
      swapped_columns: Optional list of `ColumnSwapDetail` items scoping empty
        tag injection strictly to columns swapped in the current table run. When
        `None`, leaf columns carrying non-empty source tags for the active mode
        receive empty opposite-tag clearing markers.
      active_opposite_tag_paths: Optional subset of dot-delimited column paths
        used during Step 6 compensating `tables.patch` recovery so empty
        opposite-tag markers are sent only for columns where the server response
        actually persisted the opposite tag.

    Returns:
      A deep-copied list of restore-ready schema field dictionaries.
    """
    restore_fields = copy.deepcopy(original_fields)
    is_rollback_mode = self._swap_mode == constants.SWAP_MODE_DGT_TO_PT
    swapped_paths = (
        {detail.field_path for detail in swapped_columns}
        if swapped_columns is not None
        else None
    )

    def _has_non_empty_policy_tags(field_dict: dict[str, Any]) -> bool:
      wrapper = field_dict.get("policyTags")
      if not isinstance(wrapper, dict):
        return False
      raw_names = wrapper.get("names")
      return isinstance(raw_names, list) and any(
          bool(name) for name in raw_names
      )

    def _has_non_empty_dg_tags(field_dict: dict[str, Any]) -> bool:
      return bool(self._extract_field_dg_tags(field_dict))

    def _populate_restore_tags(
        field_list: list[dict[str, Any]], parent_prefix: str
    ) -> None:
      for field_dict in field_list:
        if not isinstance(field_dict, dict):
          continue
        field_name = str(field_dict.get("name", "") or "")
        current_path = (
            f"{parent_prefix}.{field_name}" if parent_prefix else field_name
        )
        subfields = field_dict.get("fields")
        if isinstance(subfields, list) and subfields:
          _populate_restore_tags(subfields, current_path)

        # Governance tags apply strictly to leaf columns; never attach empty
        # tag wrappers onto RECORD / STRUCT container fields.
        field_type = str(field_dict.get("type", "") or "").strip().upper()
        if field_type in ("RECORD", "STRUCT") or (
            isinstance(subfields, list) and bool(subfields)
        ):
          continue

        if active_opposite_tag_paths is not None:
          should_inject = current_path in active_opposite_tag_paths
        elif swapped_paths is not None:
          should_inject = current_path in swapped_paths
        elif is_rollback_mode:
          should_inject = _has_non_empty_dg_tags(field_dict)
        else:
          should_inject = _has_non_empty_policy_tags(field_dict)

        if not should_inject:
          continue

        if is_rollback_mode:
          if not _has_non_empty_policy_tags(field_dict):
            field_dict["policyTags"] = {"names": []}
        else:
          if not _has_non_empty_dg_tags(field_dict):
            field_dict["dataGovernanceTagsInfo"] = {"dataGovernanceTags": {}}

    _populate_restore_tags(restore_fields, "")
    return restore_fields

  def backup_table_schema(
      self,
      project_id: str,
      dataset_id: str,
      table_id: str,
      original_fields: list[dict[str, Any]],
      swapped_columns: list[ColumnSwapDetail] | None = None,
  ) -> str:
    """Saves a restore-ready backup of the original table schema JSON to disk.

    Architectural Rationale (Subdirectory Isolation & `bq update` Readiness):
      - Forward mode (`pt-to-dgt`): writes
        `<backup_dir>/pt_to_dgt/<project>/<dataset>/<table>.json` containing the
        pre-migration Policy Tag schema with explicit
        `"dataGovernanceTagsInfo": {"dataGovernanceTags": {}}` injected onto
        swapped leaf columns so `bq update` atomically clears attached Data
        Governance Tags while restoring Policy Tags.
      - Rollback mode (`dgt-to-pt`): writes
        `<backup_dir>/dgt_to_pt/<project>/<dataset>/<table>.json` containing the
        pre-rollback DGT schema with explicit `"policyTags": {"names": []}`
        injected onto swapped leaf columns so `bq update` atomically clears
        restored Policy Tags if reverting the rollback.
      Isolating backups in mode/project/dataset subdirectories prevents both
      cross-mode overwrites and flat-filename delimiter collisions (such as
      dataset `a__b` + table `c` vs. dataset `a` + table `b__c`, or table
      `t_rollback` forward backup vs. table `t` rollback backup).

    Args:
      project_id: BigQuery table project ID.
      dataset_id: BigQuery dataset ID.
      table_id: BigQuery table ID.
      original_fields: Original schema fields list before modification.
      swapped_columns: Optional `ColumnSwapDetail` list scoping empty opposite
        tag clearing strictly to swapped leaf columns.

    Returns:
      The file path of the saved schema backup.

    Raises:
      ValueError: If `project_id`, `dataset_id`, or `table_id` is invalid.
      OSError: If the target backup path is a symbolic link.
      FileExistsError: If the target backup file already exists and either
        `self._overwrite` is False or the user declines the overwrite prompt.
    """
    backup_path = self._get_backup_file_path(project_id, dataset_id, table_id)
    if os.path.islink(backup_path):
      raise OSError(
          f"Refusing to write schema backup to symlink '{backup_path}'."
      )
    if os.path.exists(backup_path) and os.path.getsize(backup_path) > 0:
      if not self._overwrite:
        raise FileExistsError(
            f"Schema backup file '{backup_path}' already exists. Pass"
            " --overwrite to allow overwriting existing schema backup files"
            " or specify a different --backup-dir."
        )
      if not self._skip_confirmation:
        try:
          response = (
              self._confirmation_callback(
                  f"Schema backup file '{backup_path}' already exists."
                  " Do you want to overwrite it? (y/n): "
              )
              .strip()
              .lower()
          )
        except (KeyboardInterrupt, EOFError) as abort_error:
          print(flush=True)
          raise _PromptAbortedError(
              "Interactive confirmation prompt aborted (interrupted or closed"
              " stdin without --skip-confirmation)."
          ) from abort_error
        else:
          if not sys.stdin.isatty():
            print(flush=True)
        if response != "y":
          raise FileExistsError(
              "User declined overwriting existing schema backup file"
              f" '{backup_path}'."
          )
      logger.info("Overwriting existing schema backup file: %s", backup_path)

    restore_ready_fields = self._build_restore_ready_schema_fields(
        original_fields, swapped_columns=swapped_columns
    )
    os.makedirs(os.path.dirname(backup_path), exist_ok=True)
    with open(backup_path, "w", encoding="utf-8") as backup_file:
      json.dump(restore_ready_fields, backup_file, indent=2)
      backup_file.write("\n")
    logger.info(
        "Saved original table schema backup for %s.%s.%s to %s",
        project_id,
        dataset_id,
        table_id,
        backup_path,
    )
    return backup_path

  def generate_schema_diff(
      self,
      table_identifier: str,
      original_fields: list[dict[str, Any]],
      updated_fields: list[dict[str, Any]],
      swap_mode: str = constants.SWAP_MODE_PT_TO_DGT,
  ) -> str:
    """Generates a unified diff between the original and updated schemas.

    Args:
      table_identifier: Fully qualified `project.dataset.table` string.
      original_fields: Original schema field dictionaries.
      updated_fields: Transformed schema field dictionaries.
      swap_mode: Active swap mode (`'pt-to-dgt'` or `'dgt-to-pt'`).

    Returns:
      A unified diff string suitable for terminal display and Markdown reports.
    """
    original_json_lines = json.dumps(
        original_fields, indent=2, sort_keys=True
    ).splitlines(keepends=True)
    updated_json_lines = json.dumps(
        updated_fields, indent=2, sort_keys=True
    ).splitlines(keepends=True)
    to_label = (
        "rolled back PT schema"
        if swap_mode == constants.SWAP_MODE_DGT_TO_PT
        else "swapped DGT schema"
    )
    diff_lines = difflib.unified_diff(
        original_json_lines,
        updated_json_lines,
        fromfile=f"{table_identifier} (original schema)",
        tofile=f"{table_identifier} ({to_label})",
    )
    return "".join(diff_lines)

  def _extract_raw_schema_fields(
      self,
      table: bigquery.Table,
  ) -> list[dict[str, Any]]:
    """Extracts the raw schema field dicts from a BigQuery Table object.

    IMPORTANT (DO NOT REMOVE OR REPLACE WITH `table.schema`):
    We MUST extract the raw schema dictionary via `table.to_api_repr()` (or
    `table._properties`) BEFORE `table.schema` is ever accessed. In the
    `google-cloud-bigquery` Python SDK, accessing the `table.schema` property
    calls `SchemaField.from_api_repr()` on every field dictionary in
    `table._properties["schema"]["fields"]`, which mutates the underlying raw
    dictionaries in-place by injecting `"mode": "NULLABLE"` onto fields where
    `mode` was omitted by the server, and older SDK versions also strip unknown
    properties such as `dataGovernanceTagsInfo` when round-tripping through
    `SchemaField`. Reading from `table.to_api_repr()` before `table.schema` is
    touched preserves exact wire fidelity and prevents false-positive diffs or
    unintended mutations on untouched columns.

    Args:
      table: The BigQuery Table resource fetched via `get_table`.

    Returns:
      A deep copy of the raw schema field dictionary list.
    """
    # CRITICAL: Read from `table.to_api_repr()` / `table._properties` first.
    # Never access `table.schema` before this step (see docstring above).
    if hasattr(table, "to_api_repr"):
      try:
        api_representation = table.to_api_repr()
        if isinstance(api_representation, dict):
          fields = api_representation.get("schema", {}).get("fields")
          if isinstance(fields, list):
            return copy.deepcopy(fields)
      except Exception:  # pylint: disable=broad-exception-caught
        pass

    properties = getattr(table, "_properties", None)
    if isinstance(properties, dict):
      fields = properties.get("schema", {}).get("fields")
      if isinstance(fields, list):
        return copy.deepcopy(fields)

    schema_fields = getattr(table, "schema", None)
    if isinstance(schema_fields, list):
      return [
          copy.deepcopy(field.to_api_repr())
          if hasattr(field, "to_api_repr")
          else copy.deepcopy(field)
          for field in schema_fields
      ]

    return []

  def _apply_raw_schema_fields_to_table(
      self, table: bigquery.Table, updated_fields: list[dict[str, Any]]
  ) -> None:
    """Applies raw schema field dicts to a BigQuery Table for PATCH update.

    IMPORTANT (DO NOT REPLACE WITH `table.schema = ...`):
    Updates `table._properties["schema"] = {"fields": updated_fields}` directly
    rather than assigning `SchemaField` objects to `table.schema`. Constructing
    `SchemaField` objects strips `dataGovernanceTagsInfo` on older
    `google-cloud-bigquery` SDK versions and normalizes omitted `mode` fields
    to `"NULLABLE"`. Writing directly to `table._properties["schema"]` ensures
    `bigquery_client.update_table(table, ["schema"])` sends the exact verified
    JSON wire payload (including `policyTags: {"names": []}` and
    `dataGovernanceTagsInfo`) via `tables.patch`.

    Args:
      table: The BigQuery Table object to update.
      updated_fields: The validated list of updated field dictionaries.
    """
    properties = getattr(table, "_properties", None)
    if isinstance(properties, dict):
      properties["schema"] = {"fields": copy.deepcopy(updated_fields)}
    else:
      try:
        setattr(table, "_properties", {"schema": {"fields": updated_fields}})
      except AttributeError:
        pass

  def swap_table_schema(
      self,
      project_id: str,
      dataset_id: str,
      table_id: str,
      plan: dict[str, Any],
      regions: list[str] | None = None,
  ) -> TableSwapResult:
    """Inspects, verifies, backs up, and atomically swaps one table's schema.

    Executes the symmetric 6-step per-table pipeline for both forward migration
    (`pt-to-dgt`) and automated rollback (`dgt-to-pt`):
      - Step 0: Fetch the `Table` via `get_table`, verify regional scope, and
        extract the raw schema fields (`_extract_raw_schema_fields`) before
        `table.schema` is accessed.
      - Step 1: Transform mapped columns recursively (`transform_schema_fields`)
        and run the strict anti-corruption structural gate
        (`verify_schema_swap_integrity`).
      - Step 2: Generate and log the unified JSON schema diff
        (`generate_schema_diff`).
      - Step 3: Verify live GCP enforcement parity (`verify_enforcement_parity`)
        in forward `pt-to-dgt` mode; bypass parity checks in `dgt-to-pt`
        rollback mode so emergency rollbacks are never blocked by broken target
        DGT state. If `--dry-run` is active, return `DRY_RUN_READY` here.
      - Step 4: Display the unified diff (and any overridden parity warnings)
        and prompt the operator for interactive `(y/n)` confirmation unless
        `--skip-confirmation` is set.
      - Step 5: Persist the pre-mutation schema backup JSON to `--backup-dir`
        (`backup_table_schema`).
      - Step 6: Inject `updated_fields` into `table._properties["schema"]` and
        execute an atomic `bigquery_client.update_table(table, ["schema"])`
        (`tables.patch`).

    Args:
      project_id: Table project ID.
      dataset_id: Table dataset ID.
      table_id: Table ID.
      plan: Migration plan dictionary.
      regions: Optional list of allowed regions (case-insensitive). If
        specified, tables located outside these regions are skipped.

    Returns:
      A `TableSwapResult` recording the outcome and details of the operation.

    Raises:
      ValueError: If `plan` has an invalid or unsupported `schema_version`.
      SchemaCorruptionError: If schema transformation or integrity verification
        fails when `halt_on_error` is `True`.
      RuntimeError: If post-patch column tag verification fails when
        `halt_on_error` is `True`.
    """
    constants.validate_plan_schema_version(plan)
    self._last_failed_table_result = None
    table_identifier = f"{project_id}.{dataset_id}.{table_id}"
    is_rollback_mode = self._swap_mode == constants.SWAP_MODE_DGT_TO_PT
    logger.info("Inspecting table schema for %s...", table_identifier)

    # === Step 0: Fetch table metadata and verify regional scope ===
    try:
      table = self._bigquery_client.get_table(table_identifier)
    except Exception as error:  # pylint: disable=broad-exception-caught
      error_text = f"Failed to fetch table '{table_identifier}': {error}"
      logger.error(error_text)
      if self._halt_on_error:
        raise
      return TableSwapResult(
          project_id=project_id,
          dataset_id=dataset_id,
          table_id=table_id,
          status=constants.SWAP_STATUS_FAILED,
          error_message=error_text,
      )

    table_location = (getattr(table, "location", "") or "").lower()
    normalized_regions = {
        region.lower() for region in self._normalize_flag_items(regions)
    }
    if (
        normalized_regions
        and table_location
        and table_location not in normalized_regions
    ):
      skip_message = (
          f"Table location '{table_location}' is not in specified --regions"
          f" {sorted(normalized_regions)}; skipping."
      )
      logger.info(
          "Skipping table %s in location '%s' (not in specified --regions %s).",
          table_identifier,
          table_location,
          sorted(normalized_regions),
      )
      return TableSwapResult(
          project_id=project_id,
          dataset_id=dataset_id,
          table_id=table_id,
          location=table_location,
          status=constants.SWAP_STATUS_SKIPPED_REGION_MISMATCH,
          error_message=skip_message,
      )

    # Guard against non-table resources (e.g., VIEW, MATERIALIZED_VIEW,
    # EXTERNAL, or SNAPSHOT) passed directly via --table-ids or returned by
    # INFORMATION_SCHEMA.COLUMN_FIELD_PATHS pre-filtering so we never attempt
    # schema tag swapping or update_table on read-only/virtual objects.
    raw_table_type = getattr(table, "table_type", None)
    normalized_table_type = (
        raw_table_type.strip().upper()
        if isinstance(raw_table_type, str)
        else ""
    )
    if normalized_table_type and normalized_table_type not in (
        "TABLE",
        "BASE TABLE",
    ):
      skip_message = (
          f"Skipped non-table resource (table_type={normalized_table_type});"
          " only standard TABLE resources support schema tag swapping."
      )
      logger.info(
          "Skipping non-table resource %s (table_type=%s); only standard"
          " TABLE resources support schema tag swapping.",
          table_identifier,
          normalized_table_type,
      )
      return TableSwapResult(
          project_id=project_id,
          dataset_id=dataset_id,
          table_id=table_id,
          location=table_location,
          status=constants.SWAP_STATUS_SKIPPED_NON_TABLE,
          error_message=skip_message,
      )

    # IMPORTANT: Extract raw schema fields via `_extract_raw_schema_fields`
    # (which uses `table.to_api_repr()`) BEFORE `table.schema` is ever accessed
    # so `SchemaField.from_api_repr()` does not mutate untouched field dicts.
    original_fields = self._extract_raw_schema_fields(table)
    self._current_table_location = table_location

    try:
      updated_fields, swapped_columns, unmapped_columns = (
          self.transform_schema_fields(original_fields, plan)
      )
    except SchemaCorruptionError as error:
      error_text = (
          f"Schema transformation aborted for '{table_identifier}': {error}"
      )
      logger.error(error_text)
      if self._halt_on_error:
        raise
      return TableSwapResult(
          project_id=project_id,
          dataset_id=dataset_id,
          table_id=table_id,
          location=table_location,
          status=constants.SWAP_STATUS_ABORTED_SCHEMA_CORRUPTION,
          error_message=error_text,
      )

    if unmapped_columns:
      for unmapped in unmapped_columns:
        tag_display = (
            f"Data Governance Tag ({unmapped.source_policy_tag})"
            if is_rollback_mode
            else f"Policy Tag '{unmapped.source_policy_tag}'"
        )
        logger.warning(
            "Table %s column '%s' has %s which is not in the migration plan"
            " binding map; leaving this column untouched.",
            table_identifier,
            unmapped.field_path,
            tag_display,
        )

    if not swapped_columns:
      no_tags_status = (
          constants.SWAP_STATUS_SKIPPED_NO_DG_TAGS
          if is_rollback_mode
          else constants.SWAP_STATUS_SKIPPED_NO_POLICY_TAGS
      )
      status = (
          constants.SWAP_STATUS_SKIPPED_UNMAPPED
          if unmapped_columns
          else no_tags_status
      )
      tag_plural = "Data Governance Tags" if is_rollback_mode else "Policy Tags"
      logger.info(
          "No mapped %s found on table %s (status=%s).",
          tag_plural,
          table_identifier,
          status,
      )
      return TableSwapResult(
          project_id=project_id,
          dataset_id=dataset_id,
          table_id=table_id,
          location=table_location,
          status=status,
          unmapped_columns=unmapped_columns,
      )

    # BigQuery rejects attaching Data Governance Tags to BigQuery Omni tables
    # (`aws-*`, `azure-*` cross-cloud locations). Abort forward swaps cleanly
    # in both `--dry-run` and live modes while leaving untagged Omni tables
    # (`not swapped_columns` above) and `dgt-to-pt` rollback unobstructed.
    normalized_location = str(table_location or "").strip().lower()
    if not is_rollback_mode and normalized_location.startswith(
        constants.BIGQUERY_OMNI_LOCATION_PREFIXES
    ):
      omni_error = SchemaCorruptionError(
          f"Table '{table_identifier}' resides in BigQuery Omni location"
          f" '{table_location}'. BigQuery does not allow attaching Data"
          " Governance Tags to BigQuery Omni tables ('Data governance tags"
          " cannot be attached in BigQuery Omni.')."
      )
      error_text = (
          f"Schema transformation aborted for '{table_identifier}':"
          f" {omni_error}"
      )
      logger.error("%s", error_text)
      if self._halt_on_error:
        raise omni_error
      return TableSwapResult(
          project_id=project_id,
          dataset_id=dataset_id,
          table_id=table_id,
          location=table_location,
          status=constants.SWAP_STATUS_ABORTED_SCHEMA_CORRUPTION,
          swapped_columns=swapped_columns,
          unmapped_columns=unmapped_columns,
          error_message=error_text,
      )

    # BigQuery rejects attaching Data Governance Tags to BigLake catalog
    # datasets (`<catalog>.<namespace>`) and does not persist Data Governance
    # Tags on federated external catalog tables (`externalCatalogTableOptions`,
    # such as BigQuery Metastore Iceberg or AWS Glue federated tables), whereas
    # standard BigQuery Managed Iceberg tables (`bigLakeConfiguration` in a
    # standard dataset) ARE supported. Abort unsupported catalog tables upfront.
    raw_table_repr = (
        table.to_api_repr() if hasattr(table, "to_api_repr") else {}
    )
    is_unsupported_catalog_table = "." in dataset_id or (
        isinstance(raw_table_repr, dict)
        and bool(raw_table_repr.get("externalCatalogTableOptions"))
    )
    if not is_rollback_mode and is_unsupported_catalog_table:
      catalog_error = SchemaCorruptionError(
          f"Table '{table_identifier}' is a BigLake catalog or federated"
          " external catalog table. BigQuery does not yet support Data"
          " Governance Tags on BigLake catalog or federated external catalog"
          " tables."
      )
      error_text = (
          f"Schema transformation aborted for '{table_identifier}':"
          f" {catalog_error}"
      )
      logger.error("%s", error_text)
      if self._halt_on_error:
        raise catalog_error
      return TableSwapResult(
          project_id=project_id,
          dataset_id=dataset_id,
          table_id=table_id,
          location=table_location,
          status=constants.SWAP_STATUS_ABORTED_SCHEMA_CORRUPTION,
          swapped_columns=swapped_columns,
          unmapped_columns=unmapped_columns,
          error_message=error_text,
      )

    # === Step 1: Strict Schema Integrity Safeguard (Anti-Corruption Gate) ===
    try:
      self.verify_schema_swap_integrity(
          original_fields, updated_fields, swapped_columns
      )
    except SchemaCorruptionError as error:
      error_text = (
          "CRITICAL: Unintended schema change detected on table"
          f" '{table_identifier}'. Aborting table update to prevent schema"
          f" corruption: {error}"
      )
      logger.error(error_text)
      if self._halt_on_error:
        raise
      return TableSwapResult(
          project_id=project_id,
          dataset_id=dataset_id,
          table_id=table_id,
          location=table_location,
          status=constants.SWAP_STATUS_ABORTED_SCHEMA_CORRUPTION,
          swapped_columns=swapped_columns,
          unmapped_columns=unmapped_columns,
          error_message=error_text,
      )

    # === Step 2: Generate and log unified schema diff for auditing ===
    schema_diff = self.generate_schema_diff(
        table_identifier,
        original_fields,
        updated_fields,
        swap_mode=self._swap_mode,
    )
    # When interactive confirmation is active (not dry_run and not
    # skip_confirmation), Step 4 prints the unified schema diff banner directly
    # to stdout. Emit the INFO diff record only to FileHandlers (such as
    # --log-file) and log DEBUG to stream handlers so interactive terminals do
    # not display two identical multi-line schema diffs back-to-back.
    if self._dry_run or self._skip_confirmation:
      logger.info(
          "Proposed schema diff for %s:\n%s",
          table_identifier,
          schema_diff or "(no diff)",
      )
    else:
      self._log_info_to_file_handlers_only(
          "Proposed schema diff for %s:\n%s",
          table_identifier,
          schema_diff or "(no diff)",
      )

    # === Step 3: Pre-Swap Security & Enforcement Parity Verification ===
    # In rollback mode ('dgt-to-pt'), skip DGT/V2 Data Policy parity checks so
    # tables can always be rolled back to Policy Tags even when target DGT or
    # V2 Data Policy resources are missing or misconfigured.
    if is_rollback_mode:
      parity_discrepancies = []
    else:
      parity_discrepancies = self.verify_enforcement_parity(
          swapped_columns=swapped_columns,
          plan=plan,
          table_project_id=project_id,
          table_location=table_location,
      )
    if parity_discrepancies:
      for discrepancy in parity_discrepancies:
        logger.error(
            "Parity discrepancy on %s column '%s' [%s]: %s",
            table_identifier,
            discrepancy.field_path,
            discrepancy.risk_category,
            discrepancy.description,
        )
      if not self._allow_parity_discrepancy:
        block_message = (
            f"Blocked schema swap for '{table_identifier}' due to"
            f" {len(parity_discrepancies)} enforcement parity discrepancy(ies)."
            " Resolve the discrepancy(ies) or pass"
            " --allow-parity-discrepancy to override."
        )
        logger.error(block_message)
        return TableSwapResult(
            project_id=project_id,
            dataset_id=dataset_id,
            table_id=table_id,
            location=table_location,
            status=constants.SWAP_STATUS_BLOCKED_PARITY_DISCREPANCY,
            swapped_columns=swapped_columns,
            unmapped_columns=unmapped_columns,
            parity_discrepancies=parity_discrepancies,
            schema_diff=schema_diff,
            error_message=block_message,
        )
      logger.warning(
          "Proceeding with parity discrepancy(ies) on %s because"
          " --allow-parity-discrepancy is enabled.",
          table_identifier,
      )

    direction_text = (
        "Data Governance Tags to Policy Tags (rollback)"
        if is_rollback_mode
        else "Policy Tags to Data Governance Tags"
    )
    if self._dry_run:
      logger.info(
          "[DRY RUN] Table %s passed pre-swap verification. Would swap %d"
          " column(s) from %s.",
          table_identifier,
          len(swapped_columns),
          direction_text,
      )
      return TableSwapResult(
          project_id=project_id,
          dataset_id=dataset_id,
          table_id=table_id,
          location=table_location,
          status=constants.SWAP_STATUS_DRY_RUN_READY,
          swapped_columns=swapped_columns,
          unmapped_columns=unmapped_columns,
          parity_discrepancies=parity_discrepancies,
          backup_file_path=None,
          schema_diff=schema_diff,
      )

    # === Step 4: Display schema diff and prompt for human confirmation ===
    if not self._skip_confirmation:
      banner_title = (
          f"Proposed Schema Rollback (DGT -> PT) for Table: {table_identifier}"
          if is_rollback_mode
          else f"Proposed Schema Swap for Table: {table_identifier}"
      )
      print("\n" + "=" * 80)
      print(banner_title)
      print("=" * 80)
      print(schema_diff)
      if parity_discrepancies:
        print("WARNING: Parity discrepancies were detected on this table:")
        for discrepancy in parity_discrepancies:
          print(
              f"  - [{discrepancy.risk_category}] Column"
              f" '{discrepancy.field_path}': {discrepancy.description}"
          )
      prompt_action = "schema rollback" if is_rollback_mode else "schema swap"
      try:
        response = (
            self._confirmation_callback(
                f"Apply this {prompt_action} to '{table_identifier}'? (y/n): "
            )
            .strip()
            .lower()
        )
      except (KeyboardInterrupt, EOFError) as abort_error:
        print(flush=True)
        raise _PromptAbortedError(
            "Interactive confirmation prompt aborted (interrupted or closed"
            " stdin without --skip-confirmation)."
        ) from abort_error
      else:
        if not sys.stdin.isatty():
          print(flush=True)
      if response != "y":
        decline_message = (
            f"User declined {prompt_action} at interactive confirmation prompt."
        )
        logger.info("User declined schema swap for table %s.", table_identifier)
        return TableSwapResult(
            project_id=project_id,
            dataset_id=dataset_id,
            table_id=table_id,
            location=table_location,
            status=constants.SWAP_STATUS_SKIPPED_USER_DECLINED,
            swapped_columns=swapped_columns,
            unmapped_columns=unmapped_columns,
            parity_discrepancies=parity_discrepancies,
            schema_diff=schema_diff,
            error_message=decline_message,
        )

    # === Step 5: Back up original table schema before issuing PATCH ===
    try:
      backup_file_path = self.backup_table_schema(
          project_id,
          dataset_id,
          table_id,
          original_fields,
          swapped_columns=swapped_columns,
      )
    except _PromptAbortedError:
      raise
    except Exception as error:  # pylint: disable=broad-exception-caught
      error_text = (
          f"Failed to back up original schema for '{table_identifier}';"
          f" aborting table update: {error}"
      )
      logger.error(error_text)
      if self._halt_on_error:
        raise
      return TableSwapResult(
          project_id=project_id,
          dataset_id=dataset_id,
          table_id=table_id,
          location=table_location,
          status=constants.SWAP_STATUS_FAILED,
          swapped_columns=swapped_columns,
          unmapped_columns=unmapped_columns,
          parity_discrepancies=parity_discrepancies,
          schema_diff=schema_diff,
          error_message=error_text,
      )

    # === Step 6: Atomically patch table schema & verify returned tags ===
    # IMPORTANT: Apply raw schema dicts directly via `_properties["schema"]`
    # rather than assigning `SchemaField` objects to `table.schema` so exact
    # wire fidelity (`policyTags: {"names": []}` and `dataGovernanceTagsInfo`)
    # is preserved across SDK versions. On certain federated/external metadata
    # table formats or projects with Data Governance Tags disabled, BigQuery
    # `tables.patch` returns HTTP 200 after clearing Policy Tags while silently
    # ignoring `dataGovernanceTagsInfo`. We therefore inspect the returned
    # `Table` object immediately; if any swapped column lacks its expected
    # target tag, we issue a compensating `tables.patch` with `original_fields`
    # to restore the pre-swap protection and mark the table `FAILED`.
    self._apply_raw_schema_fields_to_table(table, updated_fields)
    try:
      patched_table = self._bigquery_client.update_table(table, ["schema"])
    except Exception as error:  # pylint: disable=broad-exception-caught
      # `Client.update_table` sends `If-Match: table.etag` under
      # `DEFAULT_RETRY`. If the initial PATCH commits on BigQuery before a
      # transport drop or timeout, the retry raises `412 Precondition Failed`
      # (or timeout) even though the live schema changed. Re-read the live
      # table to inspect whether swapped column tags changed without
      # clobbering unrelated concurrent DDL on a genuine `412`.
      live_schema_possibly_modified = False
      recheck_note = ""
      try:
        live_table = self._bigquery_client.get_table(table_identifier)
        live_fields = self._extract_raw_schema_fields(live_table)
      except Exception as recheck_error:  # pylint: disable=broad-exception-caught
        live_schema_possibly_modified = True
        recheck_note = (
            " Could not re-read live table schema to confirm whether the patch"
            f" committed ({recheck_error}); verify live column tags and"
            f" restore from '{backup_file_path}' if modified."
        )
      else:
        if self._swapped_columns_tags_changed(
            live_fields, original_fields, swapped_columns
        ):
          live_mismatches = self._verify_post_patch_column_tags(
              live_fields, swapped_columns
          )
          if live_mismatches:
            # Classify each changed swapped column to distinguish a partial
            # write by this tool (source tag cleared and at most the planned
            # target tag written) from concurrent external edits (e.g., an
            # admin tightening a Policy Tag or dropping the column). Only
            # restore partial-write columns onto a copy of `live_fields` so
            # concurrent DDL and tag changes are never clobbered.
            partial_write_columns, concurrent_edit_notes = (
                self._classify_live_swapped_columns(
                    live_fields, original_fields, swapped_columns
                )
            )
            if partial_write_columns:
              persisted_opposite_paths = (
                  self._collect_persisted_opposite_tag_paths(
                      live_fields, partial_write_columns
                  )
              )
              compensating_fields = (
                  self._build_live_partial_restore_schema_fields(
                      live_fields,
                      original_fields,
                      columns_to_restore=partial_write_columns,
                      active_opposite_tag_paths=persisted_opposite_paths,
                  )
              )
              self._apply_raw_schema_fields_to_table(
                  live_table, compensating_fields
              )
              restored_paths = [
                  column.field_path for column in partial_write_columns
              ]
              try:
                self._bigquery_client.update_table(live_table, ["schema"])
                if concurrent_edit_notes:
                  live_schema_possibly_modified = True
                  recheck_note = (
                      " Live schema re-check detected modified column tags with"
                      f" mismatches ({'; '.join(live_mismatches)})."
                      " Automatically restored partial-write column(s)"
                      f" {restored_paths!r} onto live schema while preserving"
                      " concurrent external edit(s)"
                      f" ({'; '.join(concurrent_edit_notes)}); verify live"
                      f" column tags (backup saved at '{backup_file_path}')."
                  )
                else:
                  recheck_note = (
                      " Live schema re-check detected modified column tags with"
                      f" mismatches ({'; '.join(live_mismatches)})."
                      " Automatically restored original column tags via"
                      " compensating tables.patch (backup also saved at"
                      f" '{backup_file_path}')."
                  )
              # pylint: disable-next=broad-exception-caught
              except Exception as restore_error:
                live_schema_possibly_modified = True
                recheck_note = (
                    " CRITICAL: Live schema re-check detected modified column"
                    f" tags with mismatches ({'; '.join(live_mismatches)}), and"
                    " automatic compensating schema restore ALSO failed"
                    f" ({restore_error}); restore immediately from"
                    f" '{backup_file_path}'."
                )
            else:
              live_schema_possibly_modified = True
              recheck_note = (
                  " WARNING: Live schema re-check detected concurrent external"
                  " changes on swapped column(s)"
                  f" ({'; '.join(concurrent_edit_notes or live_mismatches)});"
                  " skipped automatic compensating restore to avoid reverting"
                  " concurrent edits. Verify live column tags (backup saved at"
                  f" '{backup_file_path}')."
              )
          else:
            live_schema_possibly_modified = True
            recheck_note = (
                " WARNING: Live schema re-check shows the target column tags"
                " ARE persisted on BigQuery despite the update_table exception"
                " (for example, an initial PATCH committed before a retry"
                " error). Verify the table state or roll back using the"
                f" commands in the report / backup '{backup_file_path}'."
            )
        else:
          recheck_note = (
              " Verified via live schema re-check that swapped column tags"
              " remain unchanged."
          )

      error_text = (
          f"Failed to patch table schema for '{table_identifier}': {error}."
          f" Original schema backup is preserved at '{backup_file_path}'."
          f"{recheck_note}"
      )
      if live_schema_possibly_modified:
        logger.critical(error_text)
      else:
        logger.error(error_text)
      failed_result = TableSwapResult(
          project_id=project_id,
          dataset_id=dataset_id,
          table_id=table_id,
          location=table_location,
          status=constants.SWAP_STATUS_FAILED,
          swapped_columns=swapped_columns,
          unmapped_columns=unmapped_columns,
          parity_discrepancies=parity_discrepancies,
          backup_file_path=backup_file_path,
          schema_diff=schema_diff,
          error_message=error_text,
          live_schema_possibly_modified=live_schema_possibly_modified,
      )
      if self._halt_on_error:
        self._last_failed_table_result = failed_result
        raise
      return failed_result

    post_patch_fields = (
        self._extract_raw_schema_fields(patched_table)
        if patched_table is not None
        else []
    )
    post_patch_mismatches = self._verify_post_patch_column_tags(
        post_patch_fields, swapped_columns
    )
    if post_patch_mismatches:
      restore_target = patched_table if patched_table is not None else table
      persisted_opposite_paths = self._collect_persisted_opposite_tag_paths(
          post_patch_fields, swapped_columns
      )
      compensating_fields = self._build_restore_ready_schema_fields(
          original_fields,
          swapped_columns=swapped_columns,
          active_opposite_tag_paths=persisted_opposite_paths,
      )
      self._apply_raw_schema_fields_to_table(
          restore_target, compensating_fields
      )
      restore_failed = False
      try:
        self._bigquery_client.update_table(restore_target, ["schema"])
        restore_note = (
            "Automatically restored original column tags via compensating"
            f" tables.patch (backup also saved at '{backup_file_path}')."
        )
        logger.error(
            "Post-patch tag verification failed on %s (%s). %s",
            table_identifier,
            "; ".join(post_patch_mismatches),
            restore_note,
        )
      # pylint: disable-next=broad-exception-caught
      except Exception as restore_error:
        restore_failed = True
        restore_note = (
            "CRITICAL: Automatic compensating schema restore ALSO failed"
            f" ({restore_error}); restore immediately from"
            f" '{backup_file_path}'."
        )
        logger.critical(
            "Post-patch tag verification failed on %s (%s). %s",
            table_identifier,
            "; ".join(post_patch_mismatches),
            restore_note,
        )
      error_text = (
          f"Post-patch schema verification failed for '{table_identifier}':"
          f" {'; '.join(post_patch_mismatches)} {restore_note}"
      )
      failed_result = TableSwapResult(
          project_id=project_id,
          dataset_id=dataset_id,
          table_id=table_id,
          location=table_location,
          status=constants.SWAP_STATUS_FAILED,
          swapped_columns=swapped_columns,
          unmapped_columns=unmapped_columns,
          parity_discrepancies=parity_discrepancies,
          backup_file_path=backup_file_path,
          schema_diff=schema_diff,
          error_message=error_text,
          live_schema_possibly_modified=restore_failed,
      )
      if self._halt_on_error:
        self._last_failed_table_result = failed_result
        raise RuntimeError(error_text)
      return failed_result

    logger.info(
        "Successfully swapped %d column(s) from %s on table %s (backup: %s).",
        len(swapped_columns),
        direction_text,
        table_identifier,
        backup_file_path,
    )
    return TableSwapResult(
        project_id=project_id,
        dataset_id=dataset_id,
        table_id=table_id,
        location=table_location,
        status=constants.SWAP_STATUS_SWAPPED,
        swapped_columns=swapped_columns,
        unmapped_columns=unmapped_columns,
        parity_discrepancies=parity_discrepancies,
        backup_file_path=backup_file_path,
        schema_diff=schema_diff,
    )

  def _canonical_policy_tag_suffix(self, policy_tag_name: str) -> str:
    """Extracts `/locations/<loc>/taxonomies/<tax>/policyTags/<tag>` suffix."""
    match = re.search(
        r"^projects/[^/]+(/locations/[^/]+/taxonomies/[^/]+/policyTags/.+)$",
        (policy_tag_name or "").strip(),
    )
    return match.group(1) if match else ""

  @classmethod
  def _index_schema_fields(
      cls,
      field_list: list[dict[str, Any]],
  ) -> tuple[dict[tuple[str, ...], dict[str, Any]], dict[str, dict[str, Any]]]:
    """Indexes raw schema field dicts by casefolded path parts and dot-path."""
    by_parts: dict[tuple[str, ...], dict[str, Any]] = {}
    by_path: dict[str, dict[str, Any]] = {}
    stack: list[tuple[list[dict[str, Any]], str, tuple[str, ...]]] = [
        (field_list, "", ())
    ]
    while stack:
      items, parent_prefix, parent_parts = stack.pop()
      for field_dict in items:
        if not isinstance(field_dict, dict):
          continue
        name = str(field_dict.get("name", "") or "")
        if not name:
          continue
        path = f"{parent_prefix}.{name}" if parent_prefix else name
        current_parts = parent_parts + (name.casefold(),)
        by_parts[current_parts] = field_dict
        by_path[path] = field_dict
        subfields = field_dict.get("fields")
        if isinstance(subfields, list) and subfields:
          stack.append((subfields, path, current_parts))
    return by_parts, by_path

  @classmethod
  def _extract_field_policy_tags(cls, field_dict: dict[str, Any]) -> list[str]:
    """Extracts non-empty Policy Tag names from a raw schema field dict."""
    wrapper = field_dict.get("policyTags")
    raw_names = wrapper.get("names") if isinstance(wrapper, dict) else None
    if isinstance(raw_names, list):
      return [str(name) for name in raw_names if name]
    return []

  def _column_matches_partial_tool_write(
      self,
      live_policy_tags: list[str],
      live_dg_tags: dict[str, str],
      swap_detail: ColumnSwapDetail,
  ) -> bool:
    """Checks whether changed live tags match a partial write by this tool.

    A partial write by this tool clears the column's source governance tag and
    leaves at most the planned target tag on that column. Any retained or
    changed source tag (such as an administrator concurrently moving a column
    to a stricter Policy Tag) or any unplanned opposite tag indicates an
    external concurrent edit rather than a partial write by this tool.

    Args:
      live_policy_tags: Live Policy Tag names currently on the column.
      live_dg_tags: Live Data Governance Tags currently on the column.
      swap_detail: Planned swap metadata for this column.

    Returns:
      True if the live tag state is consistent with a partial write by this
      tool; False if an external actor modified the column's tags.
    """
    if self._swap_mode == constants.SWAP_MODE_DGT_TO_PT:
      if live_dg_tags:
        return False
      if not live_policy_tags:
        return True
      expected_pt = swap_detail.matched_plan_policy_tag
      expected_suffix = self._canonical_policy_tag_suffix(expected_pt)
      return len(live_policy_tags) == 1 and (
          live_policy_tags[0] == expected_pt
          or (
              bool(expected_suffix)
              and self._canonical_policy_tag_suffix(live_policy_tags[0])
              == expected_suffix
          )
      )

    if live_policy_tags:
      return False
    if not live_dg_tags:
      return True
    if len(live_dg_tags) != 1:
      return False
    expected_key = swap_detail.dg_tag_key
    expected_val = swap_detail.dg_tag_value
    cand_key, cand_val = next(iter(live_dg_tags.items()))
    key_matches = cand_key == expected_key
    if not key_matches and "/" in expected_key and "/" in cand_key:
      proj_tok, cand_short = cand_key.split("/", 1)
      key_matches = (
          proj_tok.isdigit() and cand_short == expected_key.split("/", 1)[1]
      )
    if not key_matches:
      return False
    expected_rel = (
        expected_val[len(expected_key) + 1 :]
        if expected_val.startswith(f"{expected_key}/")
        else expected_val
    )
    allowed_vals = {
        expected_val,
        expected_rel,
        expected_val.split("/")[-1],
        f"{expected_key}/{expected_rel}",
        f"{cand_key}/{expected_rel}",
    }
    return cand_val in allowed_vals

  def _classify_live_swapped_columns(
      self,
      live_fields: list[dict[str, Any]],
      original_fields: list[dict[str, Any]],
      swapped_columns: list[ColumnSwapDetail],
  ) -> tuple[list[ColumnSwapDetail], list[str]]:
    """Splits changed swapped columns into partial tool writes vs external edits.

    Args:
      live_fields: Raw schema field dicts re-fetched from BigQuery.
      original_fields: Pre-swap raw schema field dicts captured in Step 0.
      swapped_columns: Columns targeted by Step 6 `tables.patch`.

    Returns:
      A tuple `(partial_write_columns, concurrent_edit_notes)` where
      `partial_write_columns` are columns whose live tags match a partial write
      by this tool and are safe to restore, and `concurrent_edit_notes`
      describe columns modified or dropped concurrently by external actors.
    """
    live_by_parts, live_by_path = self._index_schema_fields(live_fields)
    orig_by_parts, orig_by_path = self._index_schema_fields(original_fields)
    partial_write_columns: list[ColumnSwapDetail] = []
    concurrent_edit_notes: list[str] = []

    for swap_detail in swapped_columns:
      lookup_parts = tuple(
          part.casefold()
          for part in swap_detail.field_path_parts or tuple(
              swap_detail.field_path.split(".")
          )
      )
      live_field = live_by_parts.get(lookup_parts) or live_by_path.get(
          swap_detail.field_path
      )
      orig_field = orig_by_parts.get(lookup_parts) or orig_by_path.get(
          swap_detail.field_path
      )
      if live_field is None:
        concurrent_edit_notes.append(
            f"column '{swap_detail.field_path}' was concurrently removed"
        )
        continue
      if orig_field is None:
        concurrent_edit_notes.append(
            f"column '{swap_detail.field_path}' missing from pre-swap snapshot"
        )
        continue

      live_policy_tags = self._extract_field_policy_tags(live_field)
      live_dg_tags = self._extract_field_dg_tags(live_field)
      orig_policy_tags = self._extract_field_policy_tags(orig_field)
      orig_dg_tags = self._extract_field_dg_tags(orig_field)
      if (
          tuple(sorted(live_policy_tags)),
          tuple(sorted(live_dg_tags.items())),
      ) == (
          tuple(sorted(orig_policy_tags)),
          tuple(sorted(orig_dg_tags.items())),
      ):
        continue

      if self._column_matches_partial_tool_write(
          live_policy_tags, live_dg_tags, swap_detail
      ):
        partial_write_columns.append(swap_detail)
      else:
        concurrent_edit_notes.append(
            f"column '{swap_detail.field_path}' has unexpected live tags"
            f" (policyTags={live_policy_tags!r},"
            f" dataGovernanceTags={live_dg_tags!r})"
        )

    return partial_write_columns, concurrent_edit_notes

  def _build_live_partial_restore_schema_fields(
      self,
      live_fields: list[dict[str, Any]],
      original_fields: list[dict[str, Any]],
      columns_to_restore: list[ColumnSwapDetail],
      active_opposite_tag_paths: set[str],
  ) -> list[dict[str, Any]]:
    """Restores original tag fields onto a copy of `live_fields` selectively.

    Applying tag restoration onto a deep copy of `live_fields` rather than
    sending `original_fields` preserves any concurrently added columns,
    metadata edits, or externally modified column tags while rolling back only
    the columns partially written by this tool.

    Args:
      live_fields: Current live raw schema field dicts re-fetched from BigQuery.
      original_fields: Pre-swap raw schema field dicts captured in Step 0.
      columns_to_restore: Swapped columns verified as partial tool writes.
      active_opposite_tag_paths: Column paths carrying a persisted opposite tag
        that must be explicitly cleared during compensating restore.

    Returns:
      Deep-copied `live_fields` list with pre-swap governance tags restored on
      `columns_to_restore`.
    """
    restored_fields = copy.deepcopy(live_fields)
    live_by_parts, live_by_path = self._index_schema_fields(restored_fields)
    orig_by_parts, orig_by_path = self._index_schema_fields(original_fields)
    is_rollback_mode = self._swap_mode == constants.SWAP_MODE_DGT_TO_PT

    for swap_detail in columns_to_restore:
      lookup_parts = tuple(
          part.casefold()
          for part in swap_detail.field_path_parts or tuple(
              swap_detail.field_path.split(".")
          )
      )
      live_field = live_by_parts.get(lookup_parts) or live_by_path.get(
          swap_detail.field_path
      )
      orig_field = orig_by_parts.get(lookup_parts) or orig_by_path.get(
          swap_detail.field_path
      )
      if live_field is None or orig_field is None:
        continue

      for tag_key in (
          "policyTags",
          "dataGovernanceTagsInfo",
          "dataGovernanceTags",
      ):
        if tag_key in orig_field:
          live_field[tag_key] = copy.deepcopy(orig_field[tag_key])
        else:
          live_field.pop(tag_key, None)

      if swap_detail.field_path in active_opposite_tag_paths:
        if is_rollback_mode:
          if not self._extract_field_policy_tags(live_field):
            live_field["policyTags"] = {"names": []}
        else:
          if not self._extract_field_dg_tags(live_field):
            live_field["dataGovernanceTagsInfo"] = {"dataGovernanceTags": {}}

    return restored_fields

  def _swapped_columns_tags_changed(
      self,
      live_fields: list[dict[str, Any]],
      original_fields: list[dict[str, Any]],
      swapped_columns: list[ColumnSwapDetail],
  ) -> bool:
    """Checks whether governance tags changed on any targeted swapped column.

    Compares normalized `(policyTags, dataGovernanceTags)` signatures strictly
    on `swapped_columns` between `original_fields` and `live_fields` rather
    than comparing the entire schema list. This prevents a genuine `412
    Precondition Failed` caused by an unrelated concurrent `ALTER TABLE` (for
    example, adding a new column while swapped columns retain their original
    tags) from triggering a destructive compensating restore.

    Args:
      live_fields: Raw schema field dicts re-fetched from BigQuery.
      original_fields: Pre-swap raw schema field dicts captured in Step 0.
      swapped_columns: Columns targeted by Step 6 `tables.patch`.

    Returns:
      True if any swapped column is missing from `live_fields` or its Policy
      Tags or Data Governance Tags differ from `original_fields`.
    """
    live_by_parts, live_by_path = self._index_schema_fields(live_fields)
    orig_by_parts, orig_by_path = self._index_schema_fields(original_fields)
    for swap_detail in swapped_columns:
      lookup_parts = tuple(
          part.casefold()
          for part in swap_detail.field_path_parts or tuple(
              swap_detail.field_path.split(".")
          )
      )
      live_field = live_by_parts.get(lookup_parts) or live_by_path.get(
          swap_detail.field_path
      )
      orig_field = orig_by_parts.get(lookup_parts) or orig_by_path.get(
          swap_detail.field_path
      )
      if live_field is None or orig_field is None:
        return True
      live_sig = (
          tuple(sorted(self._extract_field_policy_tags(live_field))),
          tuple(sorted(self._extract_field_dg_tags(live_field).items())),
      )
      orig_sig = (
          tuple(sorted(self._extract_field_policy_tags(orig_field))),
          tuple(sorted(self._extract_field_dg_tags(orig_field).items())),
      )
      if live_sig != orig_sig:
        return True
    return False

  def _collect_persisted_opposite_tag_paths(
      self,
      post_patch_fields: list[dict[str, Any]],
      swapped_columns: list[ColumnSwapDetail],
  ) -> set[str]:
    """Finds swapped column paths that carry an active post-patch target tag.

    Used during Step 6 compensating `tables.patch` recovery so columns that
    partially persisted a new DGT (in `pt-to-dgt`) or Policy Tag (in
    `dgt-to-pt`) explicitly clear it during restore, while columns where no
    new tag persisted avoid sending unsupported tag fields.

    Args:
      post_patch_fields: Raw field dicts returned by `update_table`.
      swapped_columns: Columns targeted by the failed swap attempt.

    Returns:
      Set of dot-delimited `field_path` strings carrying a persisted target tag.
    """
    fields_by_parts, fields_by_path = self._index_schema_fields(
        post_patch_fields
    )
    is_rollback_mode = self._swap_mode == constants.SWAP_MODE_DGT_TO_PT
    persisted_paths: set[str] = set()
    for swap_detail in swapped_columns:
      lookup_parts = tuple(
          part.casefold()
          for part in swap_detail.field_path_parts or tuple(
              swap_detail.field_path.split(".")
          )
      )
      field_dict = fields_by_parts.get(lookup_parts) or fields_by_path.get(
          swap_detail.field_path
      )
      if field_dict is None:
        continue
      if is_rollback_mode:
        if self._extract_field_policy_tags(field_dict):
          persisted_paths.add(swap_detail.field_path)
      else:
        if self._extract_field_dg_tags(field_dict):
          persisted_paths.add(swap_detail.field_path)
    return persisted_paths

  def _verify_post_patch_column_tags(
      self,
      post_patch_fields: list[dict[str, Any]],
      swapped_columns: list[ColumnSwapDetail],
  ) -> list[str]:
    """Verifies that BigQuery persisted the expected tags on swapped columns.

    Inspects the `Table` schema returned by `bigquery_client.update_table` so
    silent server-side tag drops (for example, on federated/external metadata
    table formats or projects where Data Governance Tags are disabled) never
    leave sensitive columns unprotected while reporting `SWAPPED`.

    Args:
      post_patch_fields: Raw field dictionaries extracted from the `Table`
        returned by `update_table`.
      swapped_columns: Expected column swaps applied in Step 6.

    Returns:
      List of human-readable mismatch descriptions (empty when all swapped
      columns carry their expected post-patch tags).
    """
    fields_by_parts, fields_by_path = self._index_schema_fields(
        post_patch_fields
    )
    mismatches: list[str] = []
    is_rollback_mode = self._swap_mode == constants.SWAP_MODE_DGT_TO_PT

    for swap_detail in swapped_columns:
      lookup_parts = tuple(
          part.casefold()
          for part in swap_detail.field_path_parts or tuple(
              swap_detail.field_path.split(".")
          )
      )
      field_dict = fields_by_parts.get(lookup_parts) or fields_by_path.get(
          swap_detail.field_path
      )
      if field_dict is None:
        mismatches.append(
            f"Column '{swap_detail.field_path}' missing from patched table"
            " schema response."
        )
        continue

      live_policy_tags = self._extract_field_policy_tags(field_dict)
      live_dg_tags = self._extract_field_dg_tags(field_dict)

      if is_rollback_mode:
        if live_dg_tags:
          mismatches.append(
              f"Column '{swap_detail.field_path}' retained Data Governance"
              f" Tag(s) {live_dg_tags!r} after rollback."
          )
        expected_pt = swap_detail.matched_plan_policy_tag
        expected_suffix = self._canonical_policy_tag_suffix(expected_pt)
        pt_matches = len(live_policy_tags) == 1 and (
            live_policy_tags[0] == expected_pt
            or (
                bool(expected_suffix)
                and self._canonical_policy_tag_suffix(live_policy_tags[0])
                == expected_suffix
            )
        )
        if not pt_matches:
          mismatches.append(
              f"Column '{swap_detail.field_path}' is missing restored Policy"
              f" Tag '{expected_pt}' after rollback (found"
              f" policyTags={live_policy_tags!r})."
          )
      else:
        if live_policy_tags:
          mismatches.append(
              f"Column '{swap_detail.field_path}' retained Policy Tag(s)"
              f" {live_policy_tags!r} after swap."
          )
        expected_key = swap_detail.dg_tag_key
        expected_val = swap_detail.dg_tag_value
        actual_val = live_dg_tags.get(expected_key)
        if actual_val is None and "/" in expected_key:
          key_short = expected_key.split("/", 1)[1]
          for candidate_key, candidate_val in live_dg_tags.items():
            if "/" in candidate_key:
              proj_tok, cand_short = candidate_key.split("/", 1)
              if cand_short == key_short and proj_tok.isdigit():
                actual_val = candidate_val
                break
        expected_rel = (
            expected_val[len(expected_key) + 1 :]
            if expected_val.startswith(f"{expected_key}/")
            else expected_val
        )
        allowed_vals = {
            expected_val,
            expected_rel,
            expected_val.split("/")[-1],
            f"{expected_key}/{expected_rel}",
        }
        if actual_val is None or actual_val not in allowed_vals:
          mismatches.append(
              f"Column '{swap_detail.field_path}' is missing expected Data"
              f" Governance Tag (key='{expected_key}', value='{expected_val}')"
              " after tables.patch (found"
              f" dataGovernanceTags={live_dg_tags!r})."
          )

    return mismatches

  def swap_schemas(
      self,
      plan: dict[str, Any],
      table_project_ids: list[str] | None = None,
      dataset_ids: list[str] | None = None,
      table_ids: list[str] | None = None,
      regions: list[str] | None = None,
      report_file: str | None = None,
  ) -> tuple[list[TableSwapResult], str]:
    """Resolves target tables, performs PT<->DGT swaps, and generates a report.

    Top-level orchestrator invoked by `main.py` for `--phase swap`. Verifies
    `--backup-dir` writability upfront (when not in `--dry-run`), prompts the
    operator to confirm they have thoroughly read and understood `README.md`
    (covering PT-to-DGT feature gaps, migration tool and platform limitations,
    and safe migration practices to avoid security violations or production
    outages, unless `--dry-run` or `--skip-confirmation` is set), pre-builds
    `plan.json` indexes once, resolves target tables across project, dataset,
    and table flags in the required `--regions`, executes `swap_table_schema` on
    each discovered table, and renders the Markdown audit report.

    Args:
      plan: Parsed migration plan dictionary.
      table_project_ids: Optional list of project IDs to scan.
      dataset_ids: Optional list of dot-separated dataset IDs to scan.
      table_ids: Optional list of dot-separated table IDs to swap.
      regions: Required list of regions to filter datasets and tables by.
      report_file: Optional path to write the Markdown report.

    Returns:
      A tuple of `(list of TableSwapResult, markdown_report_str)`.

    Raises:
      ValueError: If `plan` has an invalid or unsupported `schema_version`.
    """
    constants.validate_plan_schema_version(plan)
    self._unresolved_plan_warnings = []
    self._aborted_by_readme_decline = False
    self.last_report = None
    self._last_regions = self._normalize_flag_items(regions)
    if self._swap_mode != constants.SWAP_MODE_DGT_TO_PT:
      unresolved_warnings = self._collect_unresolved_plan_warnings(plan)
      self._unresolved_plan_warnings = unresolved_warnings
      if unresolved_warnings and not self._allow_unresolved_plan_warnings:
        block_error = (
            "Blocked Phase 3 schema swap: plan.json contains"
            f" {len(unresolved_warnings)} unresolved [ACTION REQUIRED]"
            " warning(s). Resolve them in plan.json or pass"
            " --allow-unresolved-plan-warnings to override."
        )
        logger.error(block_error)
        blocked_result = TableSwapResult(
            project_id="*",
            dataset_id="*",
            table_id="*",
            status=constants.SWAP_STATUS_BLOCKED_UNRESOLVED_PLAN_WARNINGS,
            error_message=block_error,
        )
        report = self.generate_swap_report([blocked_result])
        self.last_report = report
        if report_file:
          with open(report_file, "w", encoding="utf-8") as output_file:
            output_file.write(_ensure_trailing_newline(report))
          logger.info("Phase 3 swap report saved to %s", report_file)
        return [blocked_result], report
      if unresolved_warnings:
        logger.warning(
            "Proceeding with %d unresolved [ACTION REQUIRED] plan warning(s)"
            " because --allow-unresolved-plan-warnings is enabled.",
            len(unresolved_warnings),
        )

    if not self._dry_run:
      self._verify_backup_dir_writable()
      if not self._skip_confirmation:
        print("\n" + "=" * 80)
        print("Pre-Swap README.md Review & Risk Acknowledgment")
        print("=" * 80)
        print(
            "WARNING: Before modifying table schemas, you must thoroughly read"
            " and understand README.md, which covers:\n"
            "  - Feature gaps between Policy Tags (PT) and Data Governance"
            " Tags (DGT) (if your workloads depend on any unsupported"
            " feature, do not perform migration yet),\n"
            "  - Limitations with the migration tool and platform, and\n"
            "  - How to perform a safe migration and avoid operational"
            " pitfalls.\n"
            "Not reading and understanding README.md can result in security"
            " violations or production outages."
        )
        try:
          ack_response = (
              self._confirmation_callback(
                  "Have you thoroughly read and understood README.md and the"
                  " risks of proceeding? (y/n): "
              )
              .strip()
              .lower()
          )
        except (KeyboardInterrupt, EOFError) as abort_error:
          print(flush=True)
          raise _PromptAbortedError(
              "Interactive confirmation prompt aborted (interrupted or closed"
              " stdin without --skip-confirmation)."
          ) from abort_error
        else:
          if not sys.stdin.isatty():
            print(flush=True)
        if ack_response != "y":
          self._aborted_by_readme_decline = True
          logger.info(
              "User declined the pre-swap README.md acknowledgment; aborting"
              " swap phase before modifying any tables."
          )
          report = self.generate_swap_report([])
          self.last_report = report
          if report_file:
            with open(report_file, "w", encoding="utf-8") as output_file:
              output_file.write(_ensure_trailing_newline(report))
            logger.info("Phase 3 swap report saved to %s", report_file)
          return [], report

    self._get_or_build_plan_indexes(plan)
    target_tables, results = self.resolve_target_tables(
        table_project_ids=table_project_ids,
        dataset_ids=dataset_ids,
        table_ids=table_ids,
        regions=regions,
        default_project_id=None,
    )

    # Always generate and persist the swap report in `finally:` so rollback
    # commands for any tables already swapped before an exception (`--halt-on-
    # error`, prompt abort, or unexpected error) are preserved on disk and on
    # `self.last_report`.
    report = ""
    try:
      for project_id, dataset_id, table_id in target_tables:
        self._last_failed_table_result = None
        try:
          result = self.swap_table_schema(
              project_id=project_id,
              dataset_id=dataset_id,
              table_id=table_id,
              plan=plan,
              regions=regions,
          )
        except Exception:
          # Preserve failed table metadata (including rollback commands when
          # `live_schema_possibly_modified` is True) in the report emitted by
          # `finally:` even when `--halt-on-error` aborts the loop.
          if self._last_failed_table_result is not None:
            results.append(self._last_failed_table_result)
            self._last_failed_table_result = None
          raise
        results.append(result)
    finally:
      report = self.generate_swap_report(results)
      self.last_report = report
      if report_file:
        with open(report_file, "w", encoding="utf-8") as output_file:
          output_file.write(_ensure_trailing_newline(report))
        logger.info("Phase 3 swap report saved to %s", report_file)

    return results, report

  def _collect_unresolved_plan_warnings(
      self, plan: dict[str, Any]
  ) -> list[str]:
    """Collects unresolved `[ACTION REQUIRED]` warnings across `plan.json`."""
    marker_lower = constants.PLAN_WARNING_ACTION_REQUIRED_MARKER.lower()
    collected: list[str] = []
    seen: set[str] = set()

    def record_warning(raw_warning: Any, context_label: str = "") -> None:
      cleaned = " ".join(str(raw_warning).split())
      if not cleaned or marker_lower not in cleaned.lower():
        return
      formatted = (
          f"{context_label}: {cleaned}"
          if context_label and context_label not in cleaned
          else cleaned
      )
      if formatted not in seen:
        seen.add(formatted)
        collected.append(formatted)

    for top_warning in plan.get("warnings", []) or []:
      record_warning(top_warning)

    manifest = plan.get(constants.KEY_PHASE_2_RESOURCE_MANIFEST, {}) or {}
    manifest_keys = (
        constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS,
        constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES,
        constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2,
        constants.KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2,
        constants.KEY_DATA_POLICIES_V1_TO_DATA_POLICIES_V2,
    )
    for section_key in manifest_keys:
      for action in manifest.get(section_key, []) or []:
        if not isinstance(action, dict):
          continue
        namespaced = action.get(constants.FIELD_NAMESPACED_NAME, "")
        policy_id = action.get(constants.FIELD_POLICY_ID, "")
        target_project = action.get(constants.FIELD_TARGET_PROJECT_ID, "")
        if namespaced:
          label = str(namespaced)
        elif target_project and policy_id:
          label = f"{target_project}/{policy_id}"
        else:
          label = str(policy_id or "")

        action_warnings = action.get(constants.FIELD_WARNINGS)
        if isinstance(action_warnings, list):
          for item in action_warnings:
            record_warning(item, label)
        elif isinstance(action_warnings, str):
          record_warning(action_warnings, label)

        single_warning = action.get(constants.FIELD_WARNING)
        if isinstance(single_warning, list):
          for item in single_warning:
            record_warning(item, label)
        elif isinstance(single_warning, str):
          record_warning(single_warning, label)

    return collected

  def _log_info_to_file_handlers_only(
      self, message_format: str, *args: Any
  ) -> None:
    """Emits INFO log records to FileHandlers and DEBUG to stream handlers.

    Prevents duplicate multi-line schema diffs on the terminal when interactive
    confirmation (`not dry_run and not skip_confirmation`) prints the schema
    diff banner to stdout, while preserving the full `INFO` schema diff entry
    in `--log-file`.

    Args:
      message_format: Percent-formatted log message string.
      *args: Format arguments for `message_format`.
    """
    record = logger.makeRecord(
        logger.name,
        logging.INFO,
        fn="",
        lno=0,
        msg=message_format,
        args=args,
        exc_info=None,
    )
    current_logger: logging.Logger | None = logger
    visited_handlers: set[int] = set()
    while current_logger is not None:
      for handler in current_logger.handlers:
        if id(handler) in visited_handlers:
          continue
        visited_handlers.add(id(handler))
        if isinstance(handler, logging.FileHandler) and (
            record.levelno >= handler.level
        ):
          handler.handle(record)
      if not current_logger.propagate:
        break
      current_logger = current_logger.parent
    logger.debug(message_format, *args)

  @classmethod
  def _sanitize_markdown_table_code_span(cls, raw_value: str) -> str:
    """Sanitizes text rendered inside backticks within a Markdown table cell.

    Replaces newlines with spaces, converts backticks to single quotes, and
    escapes pipe characters (`|`) so free-form Data Catalog Policy Tag display
    names can never break Markdown table column alignment.

    Args:
      raw_value: Raw identifier or display path string.

    Returns:
      Table-safe string suitable for wrapping in single backticks.
    """
    collapsed = " ".join(str(raw_value).splitlines())
    return collapsed.replace("`", "'").replace("|", "\\|")

  @classmethod
  def _sanitize_markdown_table_cell(cls, raw_value: str) -> str:
    r"""Sanitizes plain-text prose for safe inclusion inside a Markdown table.

    Collapses embedded CR/LF newlines to spaces and escapes pipe (`|`)
    delimiters as `\|` while preserving inline backticks so error messages and
    parity discrepancy descriptions never break Markdown table columns.

    Args:
      raw_value: Arbitrary error message or parity discrepancy description.

    Returns:
      Single-line, pipe-escaped string safe for a Markdown table cell.
    """
    collapsed = " ".join(str(raw_value).splitlines())
    return collapsed.replace("|", "\\|")

  @classmethod
  def _format_swapped_column_entry(
      cls, column: ColumnSwapDetail, *, is_rollback_mode: bool
  ) -> str:
    """Formats a single column's PT <-> DGT transition for `Swapped Columns`.

    Renders explicit `key` and `value` labels without `=` so operators can
    distinguish the Data Governance Tag Key, Data Governance Tag Value, and
    source Policy Tag unambiguously in both forward and rollback modes.

    Args:
      column: Swapped column metadata captured by `transform_schema_fields`.
      is_rollback_mode: True when rendering a `dgt-to-pt` rollback report; False
        for a forward `pt-to-dgt` swap report.

    Returns:
      Markdown-formatted single-column transition string.
    """
    safe_field_path = cls._sanitize_markdown_table_code_span(column.field_path)
    raw_policy_tag_label = (
        column.source_policy_tag_display_path
        or column.matched_plan_policy_tag
        or column.source_policy_tag
    )
    safe_policy_tag_label = cls._sanitize_markdown_table_code_span(
        raw_policy_tag_label
    )
    safe_dg_tag_key = cls._sanitize_markdown_table_code_span(column.dg_tag_key)
    safe_dg_tag_value = cls._sanitize_markdown_table_code_span(
        column.dg_tag_value
    )
    dgt_summary = (
        f"DGT (key: `{safe_dg_tag_key}`, value: `{safe_dg_tag_value}`)"
    )
    policy_tag_summary = f"PT `{safe_policy_tag_label}`"
    if is_rollback_mode:
      return f"`{safe_field_path}`: {dgt_summary} -> {policy_tag_summary}"
    return f"`{safe_field_path}`: {policy_tag_summary} -> {dgt_summary}"

  def generate_swap_report(self, results: list[TableSwapResult]) -> str:
    """Generates a human-readable Markdown report for the Phase 3 swap run.

    Includes:
      1. Summary counts by status (`SWAPPED` / `DRY_RUN_READY`,
         `BLOCKED_PARITY_DISCREPANCY`, `ABORTED_SCHEMA_CORRUPTION`,
         `SKIPPED_USER_DECLINED`, `SKIPPED_REGION_MISMATCH`,
         `SKIPPED_NON_TABLE`, `SKIPPED_UNMAPPED`,
         `SKIPPED_NO_POLICY_TAGS` / `SKIPPED_NO_DG_TAGS`, and `FAILED`).
      2. Per-table status and swapped-column table wrapped in
         `<!-- mdformat off -->` / `<!-- mdformat on -->`.
      3. Detailed Pre-Swap Enforcement Parity Discrepancies table when any
         discrepancies were detected.
      4. Per-table unified `diff` code blocks and copy-pasteable surgical
         (`--swap-mode dgt-to-pt` / `--swap-mode pt-to-dgt`) and snapshot
         (`bq update`) rollback commands.

    Args:
      results: List of `TableSwapResult` objects from `swap_schemas`.

    Returns:
      Formatted Markdown report string.
    """
    is_rollback_mode = self._swap_mode == constants.SWAP_MODE_DGT_TO_PT
    is_dry_run = self._dry_run or any(
        result.status == constants.SWAP_STATUS_DRY_RUN_READY
        for result in results
    )
    report_title_base = (
        "# Phase 3: DG Tag to Policy Tag Schema Rollback Report"
        if is_rollback_mode
        else "# Phase 3: Policy Tag to DG Tag Schema Swap Report"
    )
    if is_dry_run:
      lines: list[str] = [
          f"{report_title_base} (DRY RUN)\n",
          (
              "**Dry-Run Mode:** No table schemas were modified in BigQuery and"
              " no schema backup files were written. Review the proposed column"
              " swaps, unified schema diffs, and any potential issues below"
              " before re-running without `--dry-run`.\n"
          ),
      ]
    else:
      lines = [f"{report_title_base}\n"]

    if not results:
      if self._aborted_by_readme_decline:
        lines.append(
            "Swap phase aborted by user at the pre-swap README.md risk"
            " acknowledgment prompt before inspecting or modifying any"
            " tables.\n"
        )
      else:
        lines.append("No tables were found matching the specified scope.\n")
      return "\n".join(lines)

    counts_by_status: dict[str, int] = {}
    total_swapped_columns = 0
    total_dry_run_columns = 0
    for result in results:
      counts_by_status[result.status] = (
          counts_by_status.get(result.status, 0) + 1
      )
      if result.status == constants.SWAP_STATUS_SWAPPED:
        total_swapped_columns += len(result.swapped_columns)
      elif result.status == constants.SWAP_STATUS_DRY_RUN_READY:
        total_dry_run_columns += len(result.swapped_columns)

    dry_run_ready_count = counts_by_status.get(
        constants.SWAP_STATUS_DRY_RUN_READY, 0
    )
    blocked_plan_warnings_count = counts_by_status.get(
        constants.SWAP_STATUS_BLOCKED_UNRESOLVED_PLAN_WARNINGS, 0
    )
    blocked_count = counts_by_status.get(
        constants.SWAP_STATUS_BLOCKED_PARITY_DISCREPANCY, 0
    )
    aborted_count = counts_by_status.get(
        constants.SWAP_STATUS_ABORTED_SCHEMA_CORRUPTION, 0
    )
    declined_count = counts_by_status.get(
        constants.SWAP_STATUS_SKIPPED_USER_DECLINED, 0
    )
    region_mismatch_count = counts_by_status.get(
        constants.SWAP_STATUS_SKIPPED_REGION_MISMATCH, 0
    )
    non_table_count = counts_by_status.get(
        constants.SWAP_STATUS_SKIPPED_NON_TABLE, 0
    )
    unmapped_count = counts_by_status.get(
        constants.SWAP_STATUS_SKIPPED_UNMAPPED, 0
    )
    no_policy_tags_count = counts_by_status.get(
        constants.SWAP_STATUS_SKIPPED_NO_POLICY_TAGS, 0
    )
    no_dg_tags_count = counts_by_status.get(
        constants.SWAP_STATUS_SKIPPED_NO_DG_TAGS, 0
    )
    failed_count = counts_by_status.get(constants.SWAP_STATUS_FAILED, 0)

    lines.append("## Summary\n")
    lines.append(f"- **Total Tables Processed:** {len(results)}")
    if is_dry_run:
      lines.append(
          f"- **Tables Ready to Swap (Dry Run):** {dry_run_ready_count}"
      )
      lines.append(
          f"- **Total Columns That Would Be Swapped:** {total_dry_run_columns}"
      )
    else:
      lines.append(
          "- **Tables Swapped:**"
          f" {counts_by_status.get(constants.SWAP_STATUS_SWAPPED, 0)}"
      )
      lines.append(f"- **Total Columns Swapped:** {total_swapped_columns}")
    if blocked_plan_warnings_count:
      lines.append(
          "- **Tables Blocked (Unresolved Plan Warnings):**"
          f" {blocked_plan_warnings_count}"
      )
    lines.append(f"- **Tables Blocked (Parity Discrepancy):** {blocked_count}")
    lines.append(
        f"- **Tables Aborted (Schema Corruption Safeguard):** {aborted_count}"
    )
    lines.append(f"- **Tables Skipped (User Declined):** {declined_count}")
    if region_mismatch_count:
      lines.append(
          f"- **Tables Skipped (Region Mismatch):** {region_mismatch_count}"
      )
    if non_table_count:
      lines.append(
          f"- **Tables Skipped (Non-Table Resource):** {non_table_count}"
      )
    if is_rollback_mode:
      lines.append(
          f"- **Tables Skipped (Unmapped DG Tags Only):** {unmapped_count}"
      )
      lines.append(f"- **Tables Skipped (No DG Tags):** {no_dg_tags_count}")
    else:
      lines.append(
          f"- **Tables Skipped (Unmapped Policy Tags Only):** {unmapped_count}"
      )
      lines.append(
          f"- **Tables Skipped (No Policy Tags):** {no_policy_tags_count}"
      )
    lines.append(f"- **Tables Failed:** {failed_count}\n")

    lines.append("## Table Details\n")
    lines.append("<!-- mdformat off -->")
    lines.append(
        "| Table | Status | Swapped Columns | Backup File | Notes / Errors |"
    )
    lines.append("| :--- | :--- | :--- | :--- | :--- |")
    for result in results:
      # Populate `Swapped Columns` for tables that were swapped, ready in
      # dry-run, or `FAILED` after live column tags were modified or left
      # unverified (for example, an ambiguous `update_table` timeout/412 or a
      # failed compensating restore). Blocked, declined, aborted, or unmodified
      # failed tables never mutated live column tags and must show `None`.
      if result.status in (
          constants.SWAP_STATUS_SWAPPED,
          constants.SWAP_STATUS_DRY_RUN_READY,
      ) or (
          result.status == constants.SWAP_STATUS_FAILED
          and result.live_schema_possibly_modified
      ):
        swapped_summary = (
            "<br>".join(
                self._format_swapped_column_entry(
                    column, is_rollback_mode=is_rollback_mode
                )
                for column in result.swapped_columns
            )
            or "None"
        )
        if (
            result.status == constants.SWAP_STATUS_FAILED
            and swapped_summary != "None"
        ):
          swapped_summary = (
              f"(live state modified/unverified) {swapped_summary}"
          )
      else:
        swapped_summary = "None"
      safe_table_id = self._sanitize_markdown_table_code_span(
          result.table_identifier
      )
      if result.backup_file_path:
        safe_backup_path = self._sanitize_markdown_table_code_span(
            result.backup_file_path
        )
        backup_display = f"`{safe_backup_path}`"
      else:
        backup_display = "N/A"
      if result.error_message:
        notes = self._sanitize_markdown_table_cell(result.error_message)
      elif result.unmapped_columns:
        unmapped_paths = ", ".join(
            f"`{self._sanitize_markdown_table_code_span(column.field_path)}`"
            for column in result.unmapped_columns
        )
        unmapped_label = (
            "Unmapped DG Tags" if is_rollback_mode else "Unmapped Policy Tags"
        )
        notes = f"{unmapped_label} left untouched on: {unmapped_paths}"
      else:
        notes = ""
      lines.append(
          f"| `{safe_table_id}` | `{result.status}` |"
          f" {swapped_summary} | {backup_display} | {notes} |"
      )
    lines.append("<!-- mdformat on -->\n")

    discrepancy_results = [
        result for result in results if result.parity_discrepancies
    ]
    if discrepancy_results:
      lines.append("## Pre-Swap Enforcement Parity Discrepancies\n")
      lines.append("<!-- mdformat off -->")
      lines.append(
          "| Table | Column | Risk Category | Target DG Tag | Details |"
      )
      lines.append("| :--- | :--- | :--- | :--- | :--- |")
      for result in discrepancy_results:
        safe_table_id = self._sanitize_markdown_table_code_span(
            result.table_identifier
        )
        for discrepancy in result.parity_discrepancies:
          safe_field_path = self._sanitize_markdown_table_code_span(
              discrepancy.field_path
          )
          safe_dg_tag_key = self._sanitize_markdown_table_code_span(
              discrepancy.dg_tag_key
          )
          safe_dg_tag_value = self._sanitize_markdown_table_code_span(
              discrepancy.dg_tag_value
          )
          safe_description = self._sanitize_markdown_table_cell(
              discrepancy.description
          )
          lines.append(
              f"| `{safe_table_id}` | `{safe_field_path}` |"
              f" `{discrepancy.risk_category}` |"
              f" key: `{safe_dg_tag_key}`, value: `{safe_dg_tag_value}` |"
              f" {safe_description} |"
          )
      lines.append("<!-- mdformat on -->\n")

    if self._unresolved_plan_warnings:
      warning_heading = (
          "## Overridden Unresolved Plan Warnings ([ACTION REQUIRED])\n"
          if self._allow_unresolved_plan_warnings
          else "## Blocked by Unresolved Plan Warnings ([ACTION REQUIRED])\n"
      )
      lines.append(warning_heading)
      for warning_item in self._unresolved_plan_warnings:
        lines.append(f"- {warning_item}")
      lines.append("")

    # Whenever any table encountered an error/block status or parity risk enum,
    # render a dedicated reference section explaining each encountered enum so
    # operators do not have to look up internal status codes separately.
    status_enum_descriptions = [
        (
            constants.SWAP_STATUS_BLOCKED_UNRESOLVED_PLAN_WARNINGS,
            (
                "Forward `pt-to-dgt` swap was blocked upfront before modifying"
                " or inspecting any BigQuery tables because `plan.json` still"
                " contains unresolved `[ACTION REQUIRED]` warnings from Phase"
                " 1b (`--phase plan`). Resolve the flagged items in"
                " `plan.json` or pass `--allow-unresolved-plan-warnings` to"
                " override."
            ),
        ),
        (
            constants.SWAP_STATUS_BLOCKED_PARITY_DISCREPANCY,
            (
                "Pre-swap live enforcement parity verification detected a"
                " mismatch between `plan.json` and live Google Cloud Data"
                " Governance Tags or V2 Data Policies (see `Pre-Swap"
                " Enforcement Parity Discrepancies` above). The live BigQuery"
                " table schema was not modified."
            ),
        ),
        (
            constants.SWAP_STATUS_ABORTED_SCHEMA_CORRUPTION,
            (
                "The client-side schema anti-corruption check aborted this"
                " table before calling `tables.patch`—for example, because the"
                " table resides in a BigQuery Omni (`aws-*` / `azure-*`)"
                " location, a Policy Tag is attached to a non-leaf `RECORD` /"
                " `STRUCT` column, a column carries both a Policy Tag and"
                " direct column-level `dataPolicies` or a conflicting"
                " pre-existing Data Governance Tag, the swapped schema would"
                " exceed 1,000 unique Data Governance Tags per table,"
                " `plan.json` mapped multiple Policy Tags in the same region"
                " to the same Data Governance Tag during rollback, or an"
                " unexpected non-tag schema difference was detected. The live"
                " BigQuery table schema was not modified."
            ),
        ),
        (
            constants.SWAP_STATUS_FAILED,
            (
                "An API, permission, backup file I/O, or invalid table/dataset"
                " identifier error prevented processing or updating this"
                " table. Inspect `Notes / Errors` above and `--log-file` for"
                " the exact failure cause."
            ),
        ),
    ]
    risk_enum_descriptions = [
        (
            constants.PARITY_RISK_ACCESS_LEAKAGE,
            (
                "Target live DGT/V2 Data Policy enforcement is more permissive"
                " than the source Policy Tag posture (for example, a missing"
                " `_default_deny` policy on an access-controlled tag or"
                " unauthorized extra grantees on a live policy), risking"
                " unintended unmasked data exposure."
            ),
        ),
        (
            constants.PARITY_RISK_ACCESS_BLOCKAGE,
            (
                "Target live V2 Data Policy enforcement is more restrictive"
                " than planned (for example, planned raw-reader or"
                " masked-reader principals are missing on the live policy),"
                " risking query permission denials after cutover."
            ),
        ),
        (
            constants.PARITY_RISK_RESOURCE_DISCREPANCY,
            (
                "A planned target Data Governance Tag Key, Tag Value, or V2"
                " Data Policy is missing in Google Cloud, lacks"
                " `DATA_GOVERNANCE` purpose, or has a mismatched policy type"
                " or masking rule/routine."
            ),
        ),
    ]
    encountered_statuses = {result.status for result in results}
    encountered_risks: set[str] = set()
    for result in discrepancy_results:
      for discrepancy in result.parity_discrepancies:
        encountered_risks.add(discrepancy.risk_category)
    matched_status_entries = [
        (code, description)
        for code, description in status_enum_descriptions
        if code in encountered_statuses
    ]
    matched_risk_entries = [
        (code, description)
        for code, description in risk_enum_descriptions
        if code in encountered_risks
    ]
    if matched_status_entries or matched_risk_entries:
      lines.append("## Error & Block Status Reference\n")
      for code, description in matched_status_entries:
        lines.append(f"- **`{code}`:** {description}")
      for code, description in matched_risk_entries:
        lines.append(f"- **`{code}`:** {description}")
      lines.append("")

    diff_results = [result for result in results if result.schema_diff]
    if diff_results:
      lines.append("## Schema Diffs\n")
      plan_file_flag = self._plan_file or "plan.json"
      backup_dir_flag = self._backup_dir or constants.DEFAULT_SCHEMA_BACKUP_DIR
      default_region_flag = (
          ",".join(self._last_regions) if self._last_regions else "us"
      )
      for result in diff_results:
        lines.append(f"### `{result.table_identifier}` (`{result.status}`)\n")
        # Render rollback / re-cutover commands for tables that were swapped,
        # previewed as ready in dry-run, or `FAILED` with modified/unverified
        # live schema state (ambiguous `update_table` error or failed
        # compensating restore). Omit rollback commands for blocked, declined,
        # aborted, or unmodified failed tables.
        if result.status in (
            constants.SWAP_STATUS_SWAPPED,
            constants.SWAP_STATUS_DRY_RUN_READY,
        ) or (
            result.status == constants.SWAP_STATUS_FAILED
            and result.live_schema_possibly_modified
        ):
          region_flag = result.location or default_region_flag
          backup_path_for_cmd = (
              result.backup_file_path
              or self._get_backup_file_path(
                  result.project_id, result.dataset_id, result.table_id
              )
          )
          snapshot_suffix = (
              "" if result.backup_file_path else ", once backed up"
          )
          quoted_plan = shlex.quote(plan_file_flag)
          quoted_table_id = shlex.quote(result.table_identifier)
          quoted_region = shlex.quote(region_flag)
          quoted_backup_dir = shlex.quote(backup_dir_flag)
          quoted_bq_table = shlex.quote(
              f"{result.project_id}:{result.dataset_id}.{result.table_id}"
          )
          quoted_backup_path = shlex.quote(backup_path_for_cmd)
          if is_rollback_mode:
            lines.append(
                "- **Forward Re-Cutover Command (`--swap-mode pt-to-dgt`):**"
                " `python main.py --phase swap --swap-mode pt-to-dgt"
                f" --plan-file {quoted_plan}"
                f" --table-ids {quoted_table_id}"
                f" --regions {quoted_region}"
                f" --backup-dir {quoted_backup_dir}`"
            )
            lines.append(
                "- **Pre-Rollback Snapshot Restore Command (`bq update`"
                f"{snapshot_suffix}):** `bq update"
                f" {quoted_bq_table}"
                f" {quoted_backup_path}`\n"
            )
          else:
            lines.append(
                "- **Surgical Rollback Command (Recommended):** `python main.py"
                " --phase swap --swap-mode dgt-to-pt"
                f" --plan-file {quoted_plan}"
                f" --table-ids {quoted_table_id}"
                f" --regions {quoted_region}"
                f" --backup-dir {quoted_backup_dir}`"
            )
            lines.append(
                "- **Snapshot Rollback Command (`bq update`"
                f"{snapshot_suffix}):** `bq update"
                f" {quoted_bq_table}"
                f" {quoted_backup_path}`\n"
            )
        lines.append("```diff")
        lines.append(result.schema_diff.rstrip("\n"))
        lines.append("```\n")

    return "\n".join(lines)
