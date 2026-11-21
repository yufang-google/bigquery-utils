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

"""Cross-phase constants and schema contracts for PT-to-DGT migration.

Architectural Role & Bigger-Picture Fit:
----------------------------------------
This module defines the shared vocabulary, JSON manifest keys, status tokens,
IAM role/permission identifiers, and Google Cloud API limits that bind together
all three phases of the BigQuery Policy Tag (PT) to Data Governance Tag (DGT)
migration pipeline:

1. Phase 1a (Discovery & Audit - `analyzer.py`):
   Uses `ANALYZE_TYPE_*`, `CUSTOM_ROUTINE_PREFIX`, `TAG_PURPOSE_*`, and the IAM
   role/permission constants (`FINE_GRAINED_READER_*`, `MASKED_READER_*`,
   `RAW_DATA_READER_*`) to inspect legacy Data Catalog Policy Tag taxonomies,
   V1 Data Policies, BigQuery `INFORMATION_SCHEMA.COLUMN_FIELD_PATHS` bindings,
   and target Resource Manager DG Tags / V2 Data Policies.
2. Phase 1b (Migration Planning - `planner.py`):
   Uses `PREFIX_MIGRATED_*`, `SUFFIX_DEFAULT_DENY_POLICY`, `PARITY_*`,
   `POLICY_ORIGIN_*`, `TARGET_DATA_POLICY_MODE_*`, `COLLISION_RESOLUTION_*`,
   `MAX_TAG_DESCRIPTION_LENGTH`, `MAX_DATA_POLICIES_PER_DG_TAG_KEY`,
   `DR_WARN_*`, `ACTION_CREATE_*`, `FIELD_*`, and `KEY_*` to serialize a
   deterministic `plan.json` manifest and human-readable Markdown summary
   (`REPORT_HEADERS`).
3. Phase 2a & 2b (Resource Provisioning & Teardown - `creator.py`/`deleter.py`):
   Consumes the `KEY_PHASE_2_RESOURCE_MANIFEST` sections and `FIELD_*` keys from
   `plan.json`, dispatches by `RESOURCE_TYPE_*` and `ACTION_CREATE_*`, and
   reports per-resource execution outcomes via `STATUS_*` and `DELETE_STATUS_*`.
4. Phase 3 (Atomic Table Schema Cutover & Rollback - `swapper.py`):
   Consumes `phase_3_binding_map` and `KEY_PHASE_2_RESOURCE_MANIFEST` from
   `plan.json`, verifies live enforcement parity (`PARITY_RISK_*`), saves
   pre-mutation table schema backups (`DEFAULT_SCHEMA_BACKUP_DIR`), and reports
   per-table cutover or rollback results (`SWAP_MODE_*`, `SWAP_STATUS_*`).
5. CLI Orchestrator (`main.py`):
   Validates CLI flags against these constant choices and maps failure statuses
   to process exit codes (`0` vs. `1`).

Design Decision (Centralized Schema Contract):
----------------------------------------------
Centralizing every JSON key, enum token, and service limit in a dependency-free
module prevents circular imports and guarantees that producer modules
(`analyzer.py`, `planner.py`) and consumer modules (`creator.py`, `deleter.py`,
`swapper.py`, `main.py`) never drift on `plan.json` field names or status
strings.
"""

from __future__ import annotations

from collections.abc import Mapping
import re
import types
from typing import Any

# ==============================================================================
# 1. Custom Masking Routine & Generated Data Policy Naming Conventions
# ==============================================================================

# Prefix prepended by `Analyzer._list_data_policies` when serializing a V1 Data
# Policy whose masking rule is a custom BigQuery UDF routine rather than a
# predefined masking expression (such as `ALWAYS_NULL` or `SHA256`).
# Downstream, `Planner._map_data_policies` and
# `Swapper.verify_enforcement_parity` check for this prefix to format or compare
# the full V2 routine resource path
# (`projects/<project>/datasets/<dataset>/routines/<routine>`).
CUSTOM_ROUTINE_PREFIX = "Custom Routine:"

# Prefixes and suffixes for generated V2 Data Policy IDs (`data_policy_id`).
#
# Key Design Decision (Prefixing Only Data Policies, Not DG Tag Keys/Values):
# ---------------------------------------------------------------------------
# We apply the `migrated_` prefix ONLY to V2 Data Policies, keeping Resource
# Manager DG Tag Key and Tag Value `short_name`s clean (matching the original
# Taxonomy and Policy Tag display names after space sanitization).
#
# Rationale & Trade-offs:
# 1. User Experience: DG Tag Keys/Values are permanent, user-facing catalog
#    governance tags attached to BigQuery columns. Keeping them clean avoids
#    cluttering SQL queries, `INFORMATION_SCHEMA` views, and catalog UIs.
# 2. Strict 63-Char Limit: Resource Manager TagKey/TagValue `short_name`s are
#    capped at 63 characters (whereas V2 Data Policy IDs allow up to 200
#    characters). Prepending `migrated_` to Tag Keys/Values would consume 9
#    characters of budget at both levels and increase collision/length warnings.
# 3. Avoiding Double Prefixes: Because synthesized V2 Data Policy IDs embed the
#    DG Tag Key and Tag Value names (`migrated_raw_<key>_<value>`), prefixing
#    the tag names themselves would produce redundant IDs like
#    `migrated_raw_migrated_key_migrated_value`.
# 4. Lineage Preservation: Full migration provenance is recorded in the Tag
#    Key/Value `description` field and in `audit_lineage` inside `plan.json`.
#
# Note on Data Policy Collision Suffixes (`_1`, `_2` vs. `-1`, `-2`):
# -------------------------------------------------------------------
# BigQuery V2 Data Policy IDs enforce `^[a-zA-Z0-9_]{1,200}$` and strictly
# forbid hyphens (`-`). Therefore, when two V2 Data Policies within the same
# `(target_project_id, region)` produce the same sanitized base ID, `Planner`
# resolves the collision by appending underscore suffixes (`_1`, `_2`), whereas
# DG Tag Key/Value collisions use hyphen suffixes (`-1`, `-2`).
PREFIX_MIGRATED_RAW_POLICY = "migrated_raw_"
PREFIX_MIGRATED_MASKING_POLICY = "migrated_masking_"

# Reserved suffix identifying synthetic Fail-Closed Default-Deny seatbelt
# policies (`RAW_DATA_ACCESS_POLICY` with `grantees: []`).
#
# Architectural Invariant & Cross-Phase Usage:
# 1. Phase 1b (`planner.py`): Appends `_default_deny` to the policy ID of every
#    Tag Value in an access-controlled taxonomy (`is_access_control=True`) so
#    migrated DGT columns remain Fail-Closed even if no explicit readers exist
#    or if a sibling/ancestor raw-reader policy is deleted later.
# 2. Phase 1a (`analyzer.py`) & Phase 3 (`swapper.py`): Hydrate `grantees` via
#    REST `GET /v2/{name}` across all V2 Data Policies (including
#    `*_default_deny`, cached once per `(project_id, location)`) so any
#    out-of-band grantee drift on a seatbelt policy fails closed as
#    `ACCESS_LEAKAGE_RISK`.
# 3. Phase 2b (`deleter.py`): Detects this suffix to emit a prominent
#    `[WARNING - FAIL-OPEN RISK]` before an operator deletes a seatbelt policy.
SUFFIX_DEFAULT_DENY_POLICY = "_default_deny"

# ==============================================================================
# 2. Data Policy Parity Categories & Lineage Origins
# ==============================================================================

# Human-readable parity labels stored in the `note` and `audit_lineage` fields
# of `plan.json` and displayed in the `Note` column of `plan_report.md`:
# - `PARITY_RAW_READER`: Synthesized `RAW_DATA_ACCESS_POLICY` migrating legacy
#   Data Catalog `roles/datacatalog.categoryFineGrainedReader` IAM bindings on
#   a Policy Tag (or Root Tag Values and non-root masked Tag Values for
#   taxonomy-level readers).
# - `PARITY_DEFAULT_DENY`: Synthesized `RAW_DATA_ACCESS_POLICY` with empty
#   `grantees: []` enforcing Fail-Closed Default Deny parity on every Tag Value
#   in an access-controlled taxonomy.
# - `PARITY_MIGRATED_V1`: V2 Data Policy migrated 1:1 from an existing V1 Data
#   Policy (`DATA_MASKING_POLICY` or `RAW_DATA_ACCESS_POLICY`).
PARITY_RAW_READER = "Raw Reader Parity"
PARITY_DEFAULT_DENY = "Default Deny Parity"
PARITY_MIGRATED_V1 = "Migrated V1 Data Policy"

# Machine-readable policy origin enum tokens mapped to the human-readable
# `PARITY_*` labels above in `Planner.generate_markdown_report` so plans using
# either symbolic origin tokens or display labels render identical reports.
POLICY_ORIGIN_SYNTHETIC_RAW_READER = "SYNTHETIC_RAW_READER_PARITY"
POLICY_ORIGIN_SYNTHETIC_DEFAULT_DENY = "SYNTHETIC_DEFAULT_DENY_PARITY"
POLICY_ORIGIN_MIGRATED_V1 = "MIGRATED_V1_DATA_POLICY"

# Source entity type recorded on synthetic V2 Data Policy actions (`Raw Reader
# Parity` and `Default Deny Parity`) to distinguish policies derived directly
# from a Data Catalog Policy Tag (`SOURCE_ENTITY_TYPE_POLICY_TAG`) from policies
# derived from a legacy V1 Data Policy (`DATA_MASKING_POLICY` or
# `COLUMN_LEVEL_SECURITY_POLICY`).
SOURCE_ENTITY_TYPE_POLICY_TAG = "Policy Tag"

# ==============================================================================
# 3. Google Cloud Service Limits & Constraints
# ==============================================================================

# Google Cloud Resource Manager enforces a maximum length of 256 characters on
# TagKey and TagValue `description` fields. `Planner` slices the API payload's
# `description` field to 256 characters so Phase 2a creation never fails on
# deeply nested Policy Tag display paths, while preserving the complete
# untruncated provenance string in the plan's `audit_lineage` field.
MAX_TAG_DESCRIPTION_LENGTH = 256

# BigQuery Data Policy Service enforces a maximum of 1,000 V2 Data Policies
# associated with a single Data Governance Tag Key within a single project.
# Because every Tag Value in an access-controlled taxonomy receives a
# `_default_deny` seatbelt policy plus any explicit raw-reader or masking
# policies, `Planner` (`generate_plan`) and `Creator`
# (`_collect_potential_issues`) validate per-`(target_project_id, dg_tag_key)`
# policy counts against this threshold so customers are warned in Phase 1b
# before hitting mid-run quota failures in Phase 2a.
MAX_DATA_POLICIES_PER_DG_TAG_KEY = 1000

# Google Cloud Resource Manager enforces a default limit of 1,000 Tag Keys per
# parent project (`--target-dgt-project-id`), shared across both standard IAM
# Tag Keys and `DATA_GOVERNANCE` Tag Keys in that project.
MAX_DG_TAG_KEYS_PER_PROJECT = 1000

# Google Cloud Resource Manager enforces a default limit of 1,000 Tag Values
# under a single Tag Key across all hierarchy depths.
MAX_DG_TAG_VALUES_PER_TAG_KEY = 1000

# BigQuery Data Policy Service V2 compiles inline `grantees` into an IAM v3
# Access Policy enforcing at most 500 distinct IAM principals per policy and at
# most 100 distinct group/pool (`principalSet://`) principals per policy
# (excluding BigQuery view/dataset catalog URIs). Because legacy IAM v1 on
# Policy Tags allowed up to 1,500 principals and > 100 groups, `Planner` and
# `Creator` flag policies exceeding these V2 limits before Phase 2a creation.
MAX_GRANTEES_PER_DATA_POLICY_V2 = 500
MAX_GROUP_GRANTEES_PER_DATA_POLICY_V2 = 100

# BigQuery enforces a default limit of 1,000 unique Data Governance Tags per
# table on REST `tables.patch` updates (and 1,000 total column tag bindings in
# SQL `CREATE TABLE` DDL). `Swapper.transform_schema_fields` validates unique
# `(dg_tag_key, dg_tag_value)` pairs per table before patching schemas.
MAX_DG_TAGS_PER_TABLE = 1000

# BigQuery Organization `default_data_policy_projects` (`ALTER ORGANIZATION SET
# OPTIONS`) accepts at most 1 centralized Data Policy project per region.
MAX_DEFAULT_DATA_POLICY_PROJECTS_PER_ORG = 1

# Lowercase BigQuery Omni cross-cloud location prefixes (`aws-*`, `azure-*`).
# BigQuery prohibits attaching Data Governance Tags to BigQuery Omni tables
# (`Data governance tags cannot be attached in BigQuery Omni.`), so `Swapper`
# aborts forward `pt-to-dgt` swaps on Omni tables before mutating schemas.
BIGQUERY_OMNI_LOCATION_PREFIXES = ("aws-", "azure-")

# ==============================================================================
# 4. Phase 1a (`--phase analyze`) Discovery Modes
# ==============================================================================

# Supported values for `--analyze-type` in `--phase analyze`:
# - `static-taxonomy`: Pre-migration inventory of Data Catalog Policy Tag
#   taxonomies, tag hierarchies, IAM bindings, and V1 Data Policies.
# - `static-dgt`: Post-Phase-2a inventory of Resource Manager DG Tag Keys/Values
#   and regional V2 Data Policies (with REST grantee hydration).
# - `column-binding`: Pre- and post-migration blast-radius scan of BigQuery
#   columns bound to Policy Tags, DG Tags, and direct column-level Data Policies
#   via `INFORMATION_SCHEMA.COLUMN_FIELD_PATHS`.
ANALYZE_TYPE_STATIC_TAXONOMY = "static-taxonomy"
ANALYZE_TYPE_STATIC_DGT = "static-dgt"
ANALYZE_TYPE_COLUMN_BINDING = "column-binding"

# Maximum number of `dataset.table.column` paths returned per Policy Tag, DG
# Tag Value, or direct Column Data Policy when `--verbose-bindings` is passed
# in `--phase analyze --analyze-type column-binding`. Capping `ARRAY_AGG` at
# 1,000 paths avoids exceeding BigQuery's 100 MB row size limit while `COUNT(1)`
# still computes the exact untruncated `Bound Columns` total; whenever
# `bound_columns_count > len(bound_columns)` for a verbose entry, `Analyzer`
# emits an explicit truncation notice in the report so operators never mistake
# the 1,000-item display cap for the total column count.
VERBOSE_BINDINGS_LIMIT = 1000

# Synthetic Policy Tag taxonomy URI segment assigned by BigQuery Cross-Region
# Replication (CRR) to secondary (unpromoted) dataset replica columns in
# regional `INFORMATION_SCHEMA.COLUMN_FIELD_PATHS` (`projects/<project>/`
# `locations/<secondary_region>/taxonomies/0/policyTags/<tag_id>`). Because
# legacy Policy Tags are regional and only exist in the primary dataset's
# region, `Analyzer._analyze_column_bindings` and
# `Swapper._try_pre_filter_project_tables_via_info_schema` exclude
# `/taxonomies/0/policyTags/` entries in SQL and skip Data Catalog
# `get_policy_tag` lookups on them (avoiding guaranteed `404 Requested taxonomy`
# `id of 0 was not found` warnings and secondary-region metric inflation).
CRR_PLACEHOLDER_POLICY_TAG_SEGMENT = "/taxonomies/0/policyTags/"
CRR_REPLICA_POLICY_TAG_DISPLAY_NAME = "[CRR Secondary Replica Placeholder]"

# ==============================================================================
# 5. Phase 1b & Phase 2 (`plan`, `create`, `delete`) Action & Status Tokens
# ==============================================================================

# Action identifiers recorded on each item in `phase_2_resource_manifest` by
# `Planner` and validated by `Creator` before dispatching API calls.
ACTION_CREATE_DG_TAG_KEY = "CREATE_DG_TAG_KEY"
ACTION_CREATE_DG_TAG_VALUE = "CREATE_DG_TAG_VALUE"
ACTION_CREATE_DATA_POLICY_V2 = "CREATE_DATA_POLICY_V2"

# CLI `--resource-type` choices used in `--phase create --resource-name` and
# `--phase delete --resource-name` to target a single resource from `plan.json`.
RESOURCE_TYPE_DG_TAG_KEY = "dg-tag-key"
RESOURCE_TYPE_DG_TAG_VALUE = "dg-tag-value"
RESOURCE_TYPE_DATA_POLICY_V2 = "data-policy-v2"

# BigQuery Data Policy types across V1 and V2 APIs:
# - `RAW_DATA_ACCESS_POLICY`: V2 policy granting unmasked read access to
#   `grantees` (or denying everyone when `grantees: []`).
# - `DATA_MASKING_POLICY`: V1/V2 policy applying a predefined masking expression
#   or custom UDF routine for `grantees`.
# - `COLUMN_LEVEL_SECURITY_POLICY`: Legacy V1 policy type mapped to
#   `RAW_DATA_ACCESS_POLICY` in V2 by `Planner._map_data_policies`.
DATA_POLICY_TYPE_RAW = "RAW_DATA_ACCESS_POLICY"
DATA_POLICY_TYPE_MASKING = "DATA_MASKING_POLICY"
DATA_POLICY_TYPE_CLS = "COLUMN_LEVEL_SECURITY_POLICY"

# Per-resource outcome tokens returned by `Creator` in Phase 2a:
# - `CREATED`: Resource did not exist and was newly provisioned in GCP.
# - `SKIPPED`: Resource already existed in GCP (idempotent check-before-create).
# - `WOULD_CREATE`: `--dry-run` mode verified the resource does not yet exist
#   and passed pre-flight checks.
STATUS_CREATED = "CREATED"
STATUS_SKIPPED = "SKIPPED"
STATUS_WOULD_CREATE = "WOULD_CREATE"
STATUS_BLOCKED_UNRESOLVED_PLAN_WARNINGS = "BLOCKED_UNRESOLVED_PLAN_WARNINGS"

# Substring marker emitted by `Planner` on `plan.json` warnings that require
# operator remediation (such as invalid >63-char tag `short_name`s, >200-char
# `policy_id`s, unresolved `<unknown-project-...>` routine placeholders,
# `deleted:` tombstones, or unsupported `domain:` / public principals).
# `Creator` and forward `Swapper` (`pt-to-dgt`) fail closed when any warning
# contains this marker unless `--allow-unresolved-plan-warnings` is passed.
PLAN_WARNING_ACTION_REQUIRED_MARKER = "[ACTION REQUIRED"

# Per-resource outcome tokens returned by `Deleter` in Phase 2b:
# - `DELETED`: Resource existed and was deleted after its LRO completed.
# - `SKIPPED`: Resource was already absent in GCP (idempotent no-op).
# - `WOULD_DELETE`: `--dry-run` mode verified the resource exists and has zero
#   child Tag Values or V2 Data Policy dependents blocking deletion.
# - `BLOCKED`: `--dry-run` mode detected active child Tag Values or V2 Data
#   Policies that must be deleted first (bottom-up deletion order).
DELETE_STATUS_DELETED = "DELETED"
DELETE_STATUS_SKIPPED = "SKIPPED"
DELETE_STATUS_WOULD_DELETE = "WOULD_DELETE"
DELETE_STATUS_BLOCKED = "BLOCKED"

# ==============================================================================
# 6. Phase 3 (`--phase swap`) Cutover, Rollback & Parity Verification Constants
# ==============================================================================

# Supported directions for `--swap-mode` in Phase 3 (`swapper.py`):
# - `pt-to-dgt` (Mode 1, default forward migration): Atomically clears mapped
#   Policy Tags from BigQuery table columns and attaches the corresponding
#   Data Governance Tags defined in `phase_3_binding_map`.
# - `dgt-to-pt` (Mode 2, automated emergency rollback): Atomically clears mapped
#   Data Governance Tags from BigQuery table columns and restores the original
#   Policy Tags using the reversed `phase_3_binding_map`, sharing the exact same
#   recursive anti-corruption check, schema diff, backup, and approval workflow.
SWAP_MODE_PT_TO_DGT = "pt-to-dgt"
SWAP_MODE_DGT_TO_PT = "dgt-to-pt"
VALID_SWAP_MODES = (SWAP_MODE_PT_TO_DGT, SWAP_MODE_DGT_TO_PT)

# Per-table outcome statuses recorded by `Swapper.swap_schemas`:
# - `SWAPPED`: Live `tables.patch` (`update_table(..., ["schema"])`) succeeded.
# - `DRY_RUN_READY`: `--dry-run` verified schema integrity and enforcement
#   parity; table is ready for live cutover.
# - `SKIPPED_NO_POLICY_TAGS` / `SKIPPED_NO_DG_TAGS`: Table has zero columns
#   carrying source tags for the selected `--swap-mode`.
# - `SKIPPED_NON_TABLE`: Target resource passed directly via `--table-ids` is a
#   non-table BigQuery object (`VIEW`, `MATERIALIZED_VIEW`, `EXTERNAL`, or
#   `SNAPSHOT`) rather than a standard `TABLE`.
# - `SKIPPED_UNMAPPED`: Table has source tags, but none belong to the taxonomies
#   mapped in the provided `plan.json`.
# - `SKIPPED_REGION_MISMATCH`: Dataset location is outside the `--regions`
#   filter or the source taxonomy region.
# - `SKIPPED_USER_DECLINED`: Operator answered 'n' at the interactive diff
#   confirmation prompt.
# - `BLOCKED_UNRESOLVED_PLAN_WARNINGS`: Forward `pt-to-dgt` swap was blocked
#   upfront before table discovery because `plan.json` still contains
#   unresolved `[ACTION REQUIRED]` warnings (exits with code `1` unless
#   `--allow-unresolved-plan-warnings` is set; skipped in `dgt-to-pt` rollback).
# - `BLOCKED_PARITY_DISCREPANCY`: Pre-swap enforcement parity verification
#   found missing target DGTs, missing `_default_deny` seatbelts, or mismatched
#   grantees/masking rules (causes `main.py` to exit with code `1` unless
#   `--allow-parity-discrepancy` is explicitly set).
# - `ABORTED_SCHEMA_CORRUPTION`: Client-side recursive anti-corruption check
#   (`verify_schema_swap_integrity`) detected an unexpected field mutation or a
#   column carrying both a Policy Tag and a remaining DGT (exits with code `1`).
# - `FAILED`: An API or I/O error occurred while processing the table (exits
#   with code `1`).
SWAP_STATUS_SWAPPED = "SWAPPED"
SWAP_STATUS_DRY_RUN_READY = "DRY_RUN_READY"
SWAP_STATUS_SKIPPED_NO_POLICY_TAGS = "SKIPPED_NO_POLICY_TAGS"
SWAP_STATUS_SKIPPED_NO_DG_TAGS = "SKIPPED_NO_DG_TAGS"
SWAP_STATUS_SKIPPED_NON_TABLE = "SKIPPED_NON_TABLE"
SWAP_STATUS_SKIPPED_UNMAPPED = "SKIPPED_UNMAPPED"
SWAP_STATUS_SKIPPED_REGION_MISMATCH = "SKIPPED_REGION_MISMATCH"
SWAP_STATUS_SKIPPED_USER_DECLINED = "SKIPPED_USER_DECLINED"
SWAP_STATUS_BLOCKED_UNRESOLVED_PLAN_WARNINGS = (
    "BLOCKED_UNRESOLVED_PLAN_WARNINGS"
)
SWAP_STATUS_BLOCKED_PARITY_DISCREPANCY = "BLOCKED_PARITY_DISCREPANCY"
SWAP_STATUS_ABORTED_SCHEMA_CORRUPTION = "ABORTED_SCHEMA_CORRUPTION"
SWAP_STATUS_FAILED = "FAILED"

# Risk categories assigned by `Swapper.verify_enforcement_parity` when comparing
# planned vs. live target DGT and V2 Data Policy state before schema cutover:
# - `ACCESS_LEAKAGE_RISK`: Target state is more permissive than source Policy
#   Tag state (e.g., missing `_default_deny` seatbelt policy on an
#   access-controlled tag, or extra unauthorized grantees on a live policy).
# - `ACCESS_BLOCKAGE_RISK`: Target state is more restrictive than source Policy
#   Tag state (e.g., missing raw-reader or masked-reader grantees, which would
#   break authorized queries after cutover).
# - `RESOURCE_DISCREPANCY`: Target Tag Key, Tag Value, or V2 Data Policy is
#   missing, has a non-`DATA_GOVERNANCE` purpose, or has a mismatched masking
#   expression/routine.
PARITY_RISK_ACCESS_LEAKAGE = "ACCESS_LEAKAGE_RISK"
PARITY_RISK_ACCESS_BLOCKAGE = "ACCESS_BLOCKAGE_RISK"
PARITY_RISK_RESOURCE_DISCREPANCY = "RESOURCE_DISCREPANCY"

# Default local directory where `Swapper` writes pre-swap table schema backups
# under mode/project/dataset subdirectories
# (`<backup_dir>/pt_to_dgt/<project>/<dataset>/<table>.json` in `pt-to-dgt`
# mode and `<backup_dir>/dgt_to_pt/<project>/<dataset>/<table>.json` in
# `dgt-to-pt` mode) before calling `update_table` in live mode.
DEFAULT_SCHEMA_BACKUP_DIR = "schema_backups"
BACKUP_SUBDIR_PT_TO_DGT = "pt_to_dgt"
BACKUP_SUBDIR_DGT_TO_PT = "dgt_to_pt"

# Shared error prefix emitted whenever a caller passes a legacy domain-scoped
# Google Cloud project ID (`example.com:my-project`). Legacy domain-scoped
# projects use `:` inside project IDs, which conflicts with Resource Manager
# Tag `namespaced_name` syntax and BigQuery dot/colon table identifiers.
UNSUPPORTED_DOMAIN_SCOPED_PROJECT_MSG = (
    "Legacy domain-scoped project IDs (containing ':', such as"
    " 'example.com:my-project') are not supported"
)


_STANDARD_PROJECT_ID_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_-]{0,62}$")


def validate_standard_project_id(raw_project_id: str, context: str) -> str:
  """Validates that `raw_project_id` is a safe, non-domain-scoped project ID.

  Args:
    raw_project_id: Raw project ID string supplied via CLI flag or `plan.json`.
    context: Human-readable flag or field label for error reporting.

  Returns:
    Trimmed project ID string.

  Raises:
    ValueError: If `raw_project_id` is empty, contains `:` (legacy
      domain-scoped project ID), or contains invalid characters.
  """
  cleaned = (raw_project_id or "").strip()
  if not cleaned:
    raise ValueError(f"{context} must be a non-empty project ID.")
  if ":" in cleaned:
    raise ValueError(
        f"Invalid {context} '{raw_project_id}':"
        f" {UNSUPPORTED_DOMAIN_SCOPED_PROJECT_MSG}."
    )
  if not _STANDARD_PROJECT_ID_PATTERN.fullmatch(cleaned):
    raise ValueError(
        f"Invalid {context} '{raw_project_id}': project IDs must start with an"
        " ASCII letter or digit and contain only letters, digits, hyphens,"
        " or underscores (1-63 characters)."
    )
  return cleaned


def format_colon_identifier_error(
    raw_value: str,
    context: str,
    expected_format: str,
) -> str:
  """Formats an actionable error for colon-containing dataset/table flags.

  Distinguishes standard BigQuery CLI (`bq`) colon syntax (`project:dataset` or
  `project:dataset.table`) from legacy domain-scoped project IDs
  (`example.com:my-project.dataset.table`) so operators copying identifiers
  from `bq show` or `bq update` receive a direct dot-notation syntax hint.

  Args:
    raw_value: Raw dataset or table identifier string containing `:`.
    context: Human-readable flag or field label (for example, `"--table-ids
      value"` or `"table identifier"`).
    expected_format: Expected dot-separated format string (for example,
      `"<project_id>.<dataset_id>"` or
      `"<project_id>.<dataset_id>.<table_id>"`).

  Returns:
    Actionable error message string describing the required dot notation.
  """
  cleaned = (raw_value or "").strip()
  if cleaned.count(":") == 1:
    before_colon, _, after_colon = cleaned.partition(":")
    if (
        _STANDARD_PROJECT_ID_PATTERN.fullmatch(before_colon)
        and not before_colon.isdigit()
    ):
      expected_dots_after_colon = max(expected_format.count(".") - 1, 0)
      after_parts = after_colon.split(".") if after_colon else []
      example_suffix = ""
      if len(after_parts) == expected_dots_after_colon + 1 and all(
          part.strip() for part in after_parts
      ):
        example_suffix = f" (for example, '{before_colon}.{after_colon}')"
      return (
          f"Invalid {context} '{raw_value}': Colon-separated BigQuery CLI"
          f" notation is not supported; use dot-separated '{expected_format}'"
          f" instead{example_suffix}. {UNSUPPORTED_DOMAIN_SCOPED_PROJECT_MSG}."
      )
  return (
      f"Invalid {context} '{raw_value}':"
      f" {UNSUPPORTED_DOMAIN_SCOPED_PROJECT_MSG}. Expected dot-separated"
      f" '{expected_format}'."
  )


# ==============================================================================
# 7. IAM Roles, Permissions & Resource Manager Tag Purpose
# ==============================================================================

# Mandatory `purpose` value on Resource Manager Tag Keys used for BigQuery
# Column-Level Security (`purpose = Purpose.DATA_GOVERNANCE`). Standard IAM Tag
# Keys without `DATA_GOVERNANCE` purpose cannot be referenced by BigQuery V2
# Data Policies.
TAG_PURPOSE_DATA_GOVERNANCE = "DATA_GOVERNANCE"

# Predefined IAM roles and underlying permissions inspected by `Analyzer` on
# Data Catalog Taxonomies, Policy Tags, and V1 Data Policies:
# - `FINE_GRAINED_READER_ROLE` / `FINE_GRAINED_READER_PERMISSION`: Grants
#   unmasked read access on Data Catalog Policy Tags or Taxonomies; migrated to
#   V2 `RAW_DATA_ACCESS_POLICY` `grantees`.
# - `MASKED_READER_ROLE` / `MASKED_READER_PERMISSION`: Grants masked read access
#   on V1 Data Policies; migrated to V2 `DATA_MASKING_POLICY` `grantees`.
# - `RAW_DATA_READER_ROLE` / `RAW_DATA_READER_PERMISSION`: Defensive fallback
#   in case a V1 CLS/Raw Data Policy carries a raw-data reader binding;
#   migrated to V2 `RAW_DATA_ACCESS_POLICY` `grantees` (in standard V1 setups,
#   unmasked readers are bound via `FINE_GRAINED_READER_ROLE` on the Policy Tag
#   while V1 Data Policies carry `MASKED_READER_ROLE`).
# Note: Primitive and broad administrative roles (such as `roles/owner` or
# `roles/bigquery.admin`) do not include `datacatalog.categories.fineGrainedGet`
# or `bigquery.dataPolicies.maskedGet` in Google Cloud IAM; any other role
# bound directly to a Taxonomy, Policy Tag, or V1 Data Policy is dynamically
# inspected via `iam.roles.get`.
FINE_GRAINED_READER_ROLE = "roles/datacatalog.categoryFineGrainedReader"
MASKED_READER_ROLE = "roles/bigquerydatapolicy.maskedReader"
RAW_DATA_READER_ROLE = "roles/bigquerydatapolicy.rawDataReader"

FINE_GRAINED_READER_PERMISSION = "datacatalog.categories.fineGrainedGet"
MASKED_READER_PERMISSION = "bigquery.dataPolicies.maskedGet"
RAW_DATA_READER_PERMISSION = "bigquery.dataPolicies.getRawData"

# ==============================================================================
# 8. Target Architecture Modes, Collision Resolution & DR Warning Codes
# ==============================================================================

# Target V2 Data Policy placement modes in `--phase plan`:
# - `DEFAULT_DATA_POLICY_PROJECT` (Mode 1, `--target-default-dp-project-id`):
#   Creates regional V2 Data Policies in a single centralized governance
#   project. Because BigQuery evaluates and replicates V2 Data Policies only
#   from a table's parent project (`parentProject`) or projects registered in
#   the Organization's `default_data_policy_projects` setting, Mode 1 requires
#   the customer to register that project in `default_data_policy_projects` in
#   both primary and Disaster Recovery (CRR) secondary regions.
# - `TABLE_PARENT_PROJECTS` (Mode 2, `--target-table-dp-project-ids`):
#   Creates identical regional V2 Data Policies directly inside each specified
#   BigQuery table parent project, all referencing the shared global DG Tag
#   Values in `--target-dgt-project-id`. Requires zero Organization-level
#   `default_data_policy_projects` configuration.
TARGET_DATA_POLICY_MODE_DEFAULT_PROJECT = "DEFAULT_DATA_POLICY_PROJECT"
TARGET_DATA_POLICY_MODE_TABLE_PROJECTS = "TABLE_PARENT_PROJECTS"

# Cross-region DG Tag Key `short_name` collision resolution strategies in
# `--phase plan` (`--collision-resolution`):
# Because `Planner` uses a Separation-Only (1:1) mapping from each regional
# Policy Tag taxonomy to its own global DG Tag Key (preserving BigQuery
# Cross-Region Replication compatibility), two taxonomies with the same display
# name in different regions (e.g., `Sensitive Data` in `us` and `eu`) collide in
# the global Tag Key namespace of `--target-dgt-project-id`:
# - `counter` (default): Keeps the first key as `Sensitive_Data` and appends
#   `-1`, `-2` to colliding keys (`Sensitive_Data-1`), recording the source
#   region in each Tag Key's `description`.
# - `from_region`: Appends `_from_<region>` to all colliding keys
#   (`Sensitive_Data_from_us`, `Sensitive_Data_from_eu`). A `from_` prefix is
#   used instead of a bare `_us` suffix so global Tag Keys clearly express
#   historical migration provenance rather than geographic restriction after
#   CRR.
COLLISION_RESOLUTION_COUNTER = "counter"
COLLISION_RESOLUTION_FROM_REGION = "from_region"

# Proactive Disaster Recovery (BigQuery Cross-Region Replication / CRR) warning
# codes emitted by `Planner` in `plan.json` and `plan_report.md`:
# - `DR_WARN_01`: Multi-region V2 Data Policy conflict on the same DG Tag Key
#   (detected by `Planner.validate_plan_dr_readiness` if a plan schedules V2
#   Data Policies in multiple regions for the same Tag Key within a project,
#   which causes BigQuery CRR dataset replication to fail in the secondary
#   region).
# - `DR_WARN_02`: Target Data Policy project lookup reminder (reminding Mode 1
#   customers to register `--target-default-dp-project-id` in Organization-level
#   `default_data_policy_projects` in both primary and secondary CRR regions).
# - `DR_WARN_03`: Custom masking routine dataset replication requirement
#   (alerting customers that the dataset containing a custom masking UDF routine
#   must be replicated to the secondary region before replicating protected
#   tables; otherwise secondary-region queries fail with Access Denied).
# - `DR_WARN_04`: Authorized view/dataset non-delegation and DR replication
#   warning (alerting customers that BigQuery Data Governance Tag policies do
#   not delegate column-level access through Authorized Views or Authorized
#   Datasets—querying users must be granted access directly in `grantees`—and
#   that any referenced datasets must also be replicated to secondary CRR
#   regions).
DR_WARN_01 = "DR_WARN_01"
DR_WARN_02 = "DR_WARN_02"
DR_WARN_03 = "DR_WARN_03"
DR_WARN_04 = "DR_WARN_04"

# ==============================================================================
# 9. `plan.json` Schema Version, Manifest Keys & Markdown Report Headers
# ==============================================================================

# Monotonically increasing integer version for the `plan.json` blueprint format.
# Stamped into `plan["metadata"]["schema_version"]` by `Planner.generate_plan`
# and verified fail-closed by `validate_plan_schema_version` across `main.py`,
# `Creator`, `Deleter`, and `Swapper` so an older tool release refuses to mutate
# cloud resources from an incompatible future `plan.json` format.
PLAN_SCHEMA_VERSION = 1
FIELD_SCHEMA_VERSION = "schema_version"


def validate_plan_schema_version(plan: Mapping[str, Any]) -> int:
  """Validates `plan["metadata"]["schema_version"]` fail-closed.

  Treats an absent `metadata` block or absent `schema_version` key as schema
  version `1` for backward compatibility with unversioned v1.0 plans and minimal
  in-memory test fixtures, while rejecting non-object `plan`/`metadata` roots,
  non-integer or boolean `schema_version` values, and unsupported schema
  versions.

  Args:
    plan: Parsed `plan.json` mapping passed to Phase 2 or Phase 3 consumers.

  Returns:
    The validated integer schema version (`PLAN_SCHEMA_VERSION`).

  Raises:
    ValueError: If `plan` or `plan["metadata"]` is not a mapping, or if
      `schema_version` is non-integer, boolean, `< 1`, or unsupported by this
      tool version.
  """
  if not isinstance(plan, Mapping):
    raise ValueError(
        "Invalid migration plan: top-level JSON root must be an object."
    )
  metadata = plan.get("metadata")
  if metadata is None:
    return PLAN_SCHEMA_VERSION
  if not isinstance(metadata, Mapping):
    raise ValueError(
        "Invalid migration plan: 'metadata' must be a JSON object."
    )
  if FIELD_SCHEMA_VERSION not in metadata:
    return PLAN_SCHEMA_VERSION

  raw_version = metadata[FIELD_SCHEMA_VERSION]
  if (
      isinstance(raw_version, bool)
      or not isinstance(raw_version, int)
      or raw_version < 1
  ):
    raise ValueError(
        "Invalid migration plan: 'metadata.schema_version' must be a positive"
        f" integer (got {raw_version!r})."
    )
  if raw_version != PLAN_SCHEMA_VERSION:
    raise ValueError(
        f"Unsupported migration plan schema_version={raw_version} (this"
        " version of the migration tool supports"
        f" schema_version={PLAN_SCHEMA_VERSION}). Upgrade the migration script"
        " or regenerate plan.json with '--phase plan'."
    )
  return raw_version


# Field keys inside individual action dicts in `phase_2_resource_manifest`:
# - `namespaced_name`: Global path of a DG Tag Key (`<proj>/<key>`) or DG Tag
#   Value (`<proj>/<key>/<val>[/<child_val>...]`).
# - `parent_namespaced_name`: Parent Tag Key or parent Tag Value path used by
#   `Creator._get_parent_id` to resolve dynamic `tagKeys/<id>` or
#   `tagValues/<id>` parent resource IDs at creation time.
# - `dg_tag_value_namespaced_name`: Full hierarchical Tag Value path stored on
#   `CREATE_DATA_POLICY_V2` actions so `Creator` and `Swapper` can resolve deep
#   nested Tag Values unambiguously.
# - `policy_id`, `region`, `target_project_id`, `api_payload`, `warnings`,
#   `warning`: Standard action attributes consumed across Phases 2 and 3.
FIELD_NAMESPACED_NAME = "namespaced_name"
FIELD_PARENT_NAMESPACED_NAME = "parent_namespaced_name"
FIELD_DG_TAG_VALUE_NAMESPACED_NAME = "dg_tag_value_namespaced_name"
FIELD_POLICY_ID = "policy_id"
FIELD_REGION = "region"
FIELD_TARGET_PROJECT_ID = "target_project_id"
FIELD_API_PAYLOAD = "api_payload"
FIELD_WARNINGS = "warnings"
FIELD_WARNING = "warning"

# Top-level and section keys inside `plan.json`:
# `KEY_PHASE_2_RESOURCE_MANIFEST` groups Phase 2a creation actions into 5
# ordered lists (`Tag Keys` -> `Tag Values` -> `Raw Reader Policies` ->
# `Default Deny Policies` -> `Migrated V1 Policies`), which `Creator` executes
# top-down and `Deleter` / `Swapper` index for lookup and verification.
KEY_PHASE_2_RESOURCE_MANIFEST = "phase_2_resource_manifest"
KEY_TAXONOMIES_TO_DG_TAG_KEYS = "taxonomies_to_dg_tag_keys"
KEY_POLICY_TAGS_TO_DG_TAG_VALUES = "policy_tags_to_dg_tag_values"
KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2 = (
    "policy_tags_to_raw_reader_data_policies_v2"
)
KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2 = (
    "policy_tags_to_default_deny_data_policies_v2"
)
KEY_DATA_POLICIES_V1_TO_DATA_POLICIES_V2 = (
    "data_policies_v1_to_data_policies_v2"
)

# Immutable mapping from `phase_2_resource_manifest` section keys to their
# human-readable H3 section titles in `Planner.generate_markdown_report`.
REPORT_HEADERS = types.MappingProxyType({
    KEY_TAXONOMIES_TO_DG_TAG_KEYS: "Taxonomies to DG Tag Keys",
    KEY_POLICY_TAGS_TO_DG_TAG_VALUES: "Policy Tags to DG Tag Values",
    KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2: (
        "Policy Tags to Data Policies (V2) - Raw Reader Parity"
    ),
    KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2: (
        "Policy Tags to Data Policies (V2) - Default Deny Parity"
    ),
    KEY_DATA_POLICIES_V1_TO_DATA_POLICIES_V2: (
        "Data Policies (V1) to Data Policies (V2)"
    ),
})
