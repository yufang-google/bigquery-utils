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

# pylint: disable=g-bad-todo

"""Analyzes BigQuery Policy Tags, Data Governance Tags, and Data Policies.

Architectural Overview & Role in the 3-Phase Migration Pipeline:
----------------------------------------------------------------
This module implements the discovery and verification engine (`Analyzer`) for
migrating BigQuery Column-Level Security (CLS) and dynamic data masking from
legacy regional Data Catalog Policy Tags (PT) to global Google Cloud Resource
Manager Data Governance Tags (DGT) and BigQuery V2 Data Policies:

1. Phase 1a (`--phase analyze`): Standalone read-only discovery across three
   analysis modes (`--analyze-type`):
   - Mode 1 (`static-taxonomy`): Enumerates source Data Catalog Taxonomies,
     Policy Tag hierarchies, resource-level IAM policies (including custom
     project/organization IAM roles), and attached BigQuery V1 Data Policies.
   - Mode 2 (`static-dgt`): Inspects target Resource Manager Tag Keys
     (`purpose=DATA_GOVERNANCE`), hierarchical Tag Values (reconstructed in
     memory from a single `list_tag_values` RPC per key), and attached BigQuery
     V2 Data Policies (with automatic GAPIC-to-REST `/v2/` fallback).
   - Mode 3 (`column-binding`): Audits BigQuery table schemas at scale using
     server-side `INFORMATION_SCHEMA.COLUMN_FIELD_PATHS` SQL aggregation across
     Policy Tags, Data Governance Tags, and column-level Data Policies.
2. Phase 1b (`--phase plan`): `Analyzer.analyze_static_taxonomies()` serves as
   the upstream data producer for `Planner.generate_plan()`, supplying
   normalized `StaticTaxonomyAnalysisResult` trees that `Planner` compiles into
   `plan.json` (`phase_2_resource_manifest` and `phase_3_binding_map`).
3. Phase 3 (`--phase swap`): Operators re-run `column-binding` and `static-dgt`
   before and after schema cutover waves to verify migration completion.

Two-Stage Migration Strategy Context:
-------------------------------------
1. Stage 1 (Initial Release): Migration is performed by atomically swapping
   Policy Tags with Data Governance Tags in table schemas via `tables.patch`.
   In Stage 1, column-level coexistence of a Policy Tag and a Data Governance
   Tag on the same column is not supported; each column carries either a Policy
   Tag or a Data Governance Tag (never both simultaneously).
2. Stage 2 (Planned Future): Column-level coexistence is planned for a later
   stage, allowing customers to switch enforcement between Policy Tags and Data
   Governance Tags via project-level configuration flags without re-patching
   table schemas.
"""

from __future__ import annotations

import concurrent.futures
import copy
import dataclasses
import datetime
import logging
import os
import sys
from typing import Any
import urllib.request
import warnings

# Suppress UserWarning from proto-plus when older SDK libraries encounter
# new enum values like Purpose.DATA_GOVERNANCE (= 2).
warnings.filterwarnings(
    "ignore",
    message=".*Unrecognized Purpose enum value.*",
    category=UserWarning,
)

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# pylint: disable=g-import-not-at-top
import constants
from google.api_core import exceptions
from google.api_core import retry
from google.cloud import bigquery
from google.cloud import bigquery_datapolicies_v1
from google.cloud import datacatalog_v1
from google.cloud import iam_admin_v1
from google.cloud import resourcemanager_v3
import rest_utils

# pylint: enable=g-import-not-at-top

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


# === Section: Transient RPC Retry Configuration ===
# Standard exponential backoff applied to all read-only Data Catalog, BigQuery
# Data Policy, Resource Manager Tag, and IAM discovery RPCs. Retrying HTTP 429
# (rate-limit) and 5xx server errors up to a 120-second deadline prevents
# transient quota spikes on large (1,000+ tag) taxonomies from aborting scans.
RETRY_CONFIG = retry.Retry(
    initial=1.0,
    maximum=60.0,
    multiplier=1.5,
    deadline=120.0,
    predicate=retry.if_exception_type(
        exceptions.TooManyRequests,  # 429
        exceptions.InternalServerError,  # 500
        exceptions.BadGateway,  # 502
        exceptions.ServiceUnavailable,  # 503
        exceptions.GatewayTimeout,  # 504
    ),
)

logger = logging.getLogger(__name__)


# === Section: Data Models for Mode 1 (Static Taxonomy) & Mode 2 (Bindings) ===
@dataclasses.dataclass
class DataPolicyInfo:
  """Holds metadata and IAM principals for a legacy BigQuery V1 Data Policy.

  Produced by `Analyzer._list_data_policies` during Mode 1 (`static-taxonomy`)
  scans and consumed by `Planner._map_data_policies` in Phase 1b to synthesize
  target V2 Data Policies (`data_policies_v1_to_data_policies_v2` in
  `plan.json`).

  Attributes:
    name: Full V1 resource name
      (`projects/{project}/locations/{location}/dataPolicies/{id}`).
    policy_tag: Normalized Policy Tag resource name using the numeric project
      number
      (`projects/{number}/locations/{loc}/taxonomies/{t}/policyTags/{p}`).
    masking_rule: Predefined masking expression name (e.g., `SHA256`,
      `ALWAYS_NULL`) or `Custom Routine: {project_id}.{dataset}.{routine}` for
      UDF masking policies; `None` for raw access policies.
    raw_readers: IAM v1 member strings granted `RAW_DATA_READER_PERMISSION` on
      `COLUMN_LEVEL_SECURITY_POLICY` / `RAW_DATA_ACCESS_POLICY` policies.
    masked_readers: IAM v1 member strings granted `MASKED_READER_PERMISSION` on
      `DATA_MASKING_POLICY` policies.
    policy_type: String name of the V1 `DataPolicy.DataPolicyType` enum.
    warnings: Actionable warnings collected while inspecting this policy (e.g.,
      failed custom role lookups or unresolvable routine project IDs).
    custom_roles_by_principal: Optional mapping from IAM v1 principal string to
      sorted project/organization custom role names that granted access.
  """

  name: str
  policy_tag: str
  masking_rule: str | None
  raw_readers: list[str] = dataclasses.field(default_factory=list)
  masked_readers: list[str] = dataclasses.field(default_factory=list)
  policy_type: str | None = None
  warnings: list[str] = dataclasses.field(default_factory=list)
  custom_roles_by_principal: dict[str, list[str]] = dataclasses.field(
      default_factory=dict
  )


@dataclasses.dataclass
class PolicyTagInfo:
  """Holds metadata, IAM readers, and V1 Data Policies for a Policy Tag.

  Produced by `Analyzer._list_policy_tags` and enriched by
  `Analyzer._list_data_policies`. Consumed in Phase 1b by `Planner` to generate
  hierarchical `DGTagValue` creation actions, `phase_3_binding_map` entries,
  and per-tag V2 Data Policies (both explicit Raw Reader policies and
  `_default_deny` fail-closed seatbelt policies).

  Invariant:
    `name` and `parent_policy_tag` always normalize the project segment to the
    numeric project number (`projects/{project_number}/...`) so they join
    deterministically with BigQuery V1 Data Policy `policy_tag` references and
    `INFORMATION_SCHEMA.COLUMN_FIELD_PATHS` column bindings.

  Attributes:
    name: Normalized Policy Tag resource name (`projects/{number}/...`).
    display_name: Human-readable Policy Tag display name in Data Catalog.
    parent_policy_tag: Normalized parent Policy Tag resource name, or `""` for
      root-level Policy Tags directly under the Taxonomy.
    fine_grained_readers: IAM v1 principals granted
      `datacatalog.categories.fineGrainedGet` directly on this Policy Tag.
    data_policies: V1 Data Policies attached to this Policy Tag.
    warnings: Actionable warnings collected while inspecting this Policy Tag's
      IAM policy (e.g., failed custom role lookups).
    custom_roles_by_principal: Optional mapping from IAM v1 principal string to
      sorted project/organization custom role names that granted
      `datacatalog.categories.fineGrainedGet` on this Policy Tag.
  """

  name: str
  display_name: str
  parent_policy_tag: str
  fine_grained_readers: list[str] = dataclasses.field(default_factory=list)
  data_policies: list[DataPolicyInfo] = dataclasses.field(default_factory=list)
  warnings: list[str] = dataclasses.field(default_factory=list)
  custom_roles_by_principal: dict[str, list[str]] = dataclasses.field(
      default_factory=dict
  )


@dataclasses.dataclass
class TaxonomyInfo:
  """Holds metadata, Policy Tags, and enforcement state for a Taxonomy.

  Produced by `Analyzer._analyze_static_taxonomy` and consumed by
  `Planner.generate_plan` in Phase 1b. Each regional `TaxonomyInfo` maps 1:1 to
  a global Resource Manager DG Tag Key (Separation strategy).

  Access Control Classification Invariant (`is_access_control`):
    `is_access_control` is `True` if EITHER:
    1. Explicit signal: `FINE_GRAINED_ACCESS_CONTROL` is present in the Data
       Catalog Taxonomy's `activated_policy_types`, OR
    2. Implicit signal: At least one BigQuery V1 Data Policy is attached to any
       Policy Tag in the taxonomy.
    When `is_access_control` is `True`, `Planner` creates a `_default_deny`
    V2 Data Policy (`grantees: []`) on every Tag Value in the key to preserve
    BigQuery's fail-closed posture. When `is_access_control` is `False`
    (Classification-Only / Default Allow), any `fine_grained_readers` on the
    taxonomy or its tags are currently ignored by BigQuery and are surfaced by
    `Planner` as `dangling_fine_grained_readers` warnings without creating
    restrictive policies that would break existing table readers.

  Attributes:
    name: Normalized Taxonomy resource name (`projects/{number}/...`).
    display_name: Human-readable Taxonomy display name in Data Catalog.
    location: Lowercase or canonical region of the Taxonomy (e.g., `us`).
    policy_tags: Flat list of all Policy Tags in the Taxonomy (parent-child
      edges are encoded via `PolicyTagInfo.parent_policy_tag`).
    is_access_control: Whether BigQuery enforces access control on this Taxonomy
      (via explicit activation or implicit attached V1 Data Policies).
    fine_grained_readers: IAM v1 principals granted
      `datacatalog.categories.fineGrainedGet` at the Taxonomy resource level
      (mapped by `Planner` to Root Tag Values and masked non-root Tag Values so
      descendants inherit access via `matchTagHierarchy`).
    warnings: Actionable warnings collected while inspecting the Taxonomy IAM
      policy.
    is_explicit_access_control: Whether `FINE_GRAINED_ACCESS_CONTROL` was
      explicitly present in Data Catalog's `activated_policy_types` (`False`
      when access control is active only implicitly via attached V1 Data
      Policies; `None` when unspecified by caller).
    custom_roles_by_principal: Optional mapping from IAM v1 principal string to
      sorted project/organization custom role names that granted
      `datacatalog.categories.fineGrainedGet` at the Taxonomy level.
  """

  name: str
  display_name: str
  location: str
  policy_tags: list[PolicyTagInfo] = dataclasses.field(default_factory=list)
  is_access_control: bool = False
  fine_grained_readers: list[str] = dataclasses.field(default_factory=list)
  warnings: list[str] = dataclasses.field(default_factory=list)
  is_explicit_access_control: bool | None = None
  custom_roles_by_principal: dict[str, list[str]] = dataclasses.field(
      default_factory=dict
  )

  @property
  def total_data_policies(self) -> int:
    """Calculates the total number of V1 Data Policies across all Policy Tags.

    Returns:
      Total count of V1 Data Policies attached to Policy Tags in this Taxonomy.
    """
    return sum(len(policy_tag.data_policies) for policy_tag in self.policy_tags)


@dataclasses.dataclass
class ColumnBindingMetrics:
  """Holds region-wide table and column coverage metrics for Mode 2 scans.

  Populated by the single-pass `INFORMATION_SCHEMA.COLUMN_FIELD_PATHS` CTE in
  `Analyzer._analyze_column_bindings` and rendered in the summary header of
  `Analyzer.generate_column_binding_report`.

  Attributes:
    total_tables_scanned: Total number of tables scanned in the region.
    total_columns_scanned: Total number of columns/nested struct fields scanned.
    tables_with_policy_tags: Number of tables with >= 1 Policy Tag column.
    columns_with_policy_tags: Number of columns/fields with a Policy Tag.
    active_policy_tags_bound: Count of distinct Policy Tag resources in use.
    tables_with_dg_tags: Number of tables with >= 1 Data Governance Tag column.
    columns_with_dg_tags: Number of columns/fields with a Data Governance Tag.
    active_dg_tags_bound: Count of distinct `(key, value)` DGT pairs in use.
    tables_with_column_data_policies: Number of tables with direct column-level
      Data Policies.
    columns_with_column_data_policies: Number of columns with direct
      column-level Data Policies.
    active_column_data_policies_bound: Count of distinct direct column-level
      Data Policies in use.
    tables_with_any_cls: Number of tables protected by any CLS mechanism (PT,
      DGT, or direct column Data Policy).
    columns_with_any_cls: Number of columns protected by any CLS mechanism.
  """

  total_tables_scanned: int = 0
  total_columns_scanned: int = 0
  tables_with_policy_tags: int = 0
  columns_with_policy_tags: int = 0
  active_policy_tags_bound: int = 0
  tables_with_dg_tags: int = 0
  columns_with_dg_tags: int = 0
  active_dg_tags_bound: int = 0
  tables_with_column_data_policies: int = 0
  columns_with_column_data_policies: int = 0
  active_column_data_policies_bound: int = 0
  tables_with_any_cls: int = 0
  columns_with_any_cls: int = 0


@dataclasses.dataclass
class PolicyTagBindingDetails:
  """Holds column binding counts and optional column paths for one Policy Tag.

  Attributes:
    policy_tag_name: Policy Tag resource name reported by `INFORMATION_SCHEMA`.
    bound_columns_count: Total number of columns bound to this Policy Tag.
    policy_tag_display_name: Human-readable display name resolved via
      `get_policy_tag` (or `None` if lookup failed due to permissions/deletion).
    bound_columns: Up to 1,000 `dataset.table.field_path` strings when
      `--verbose-bindings` is enabled; empty in standard summary mode.
  """

  policy_tag_name: str
  bound_columns_count: int
  policy_tag_display_name: str | None = None
  bound_columns: list[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class ColumnDataPolicyBindingDetails:
  """Holds column binding counts for a Data Policy bound directly to columns.

  Attributes:
    data_policy_name: Full resource name of the column-bound Data Policy.
    bound_columns_count: Total number of columns bound to this Data Policy.
    data_policy_id: Short trailing ID extracted from `data_policy_name`.
    bound_columns: Up to 1,000 `dataset.table.field_path` strings when
      `--verbose-bindings` is enabled; empty in standard summary mode.
  """

  data_policy_name: str
  bound_columns_count: int
  data_policy_id: str | None = None
  bound_columns: list[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class ColumnBindingAnalysisResult:
  """Holds the complete Mode 2 (`column-binding`) result for one project/region.

  Attributes:
    project_id: Scanned BigQuery data project ID.
    location: Scanned BigQuery region (e.g., `us`).
    metrics: Aggregated table and column CLS coverage metrics.
    bindings_by_taxonomy_project: Dictionary mapping resolved taxonomy project
      ID (or numeric fallback) to its list of `PolicyTagBindingDetails`.
    bindings_by_tag_key: Dictionary mapping DGT key namespaced name/resource to
      its list of `DGTagBindingDetails`.
    column_data_policy_bindings: List of direct column-level Data Policy binding
      summaries.
    error: Error message if the regional `INFORMATION_SCHEMA` scan failed;
      `None` when the scan succeeded.
  """

  project_id: str
  location: str
  metrics: ColumnBindingMetrics = dataclasses.field(
      default_factory=ColumnBindingMetrics
  )
  bindings_by_taxonomy_project: dict[str, list[PolicyTagBindingDetails]] = (
      dataclasses.field(default_factory=dict)
  )
  bindings_by_tag_key: dict[str, list[DGTagBindingDetails]] = dataclasses.field(
      default_factory=dict
  )
  column_data_policy_bindings: list[ColumnDataPolicyBindingDetails] = (
      dataclasses.field(default_factory=list)
  )
  error: str | None = None


@dataclasses.dataclass
class StaticTaxonomyAnalysisResult:
  """Holds the complete Mode 1 (`static-taxonomy`) result for a project/region.

  Returned by `Analyzer.analyze_static_taxonomies` and passed directly into
  `Planner.generate_plan` during Phase 1b (`--phase plan`).

  Attributes:
    project_id: Scanned source taxonomy project ID.
    location: Scanned taxonomy region (e.g., `us`).
    taxonomies: List of discovered `TaxonomyInfo` hierarchies in this region.
    error: Error message if the regional Data Catalog / Data Policy scan failed;
      `None` when the scan succeeded.
  """

  project_id: str
  location: str
  taxonomies: list[TaxonomyInfo] = dataclasses.field(default_factory=list)
  error: str | None = None


# === Section: Data Models for Static DGT & Column DGT Bindings ===
@dataclasses.dataclass
class DataPolicyV2Info:
  """Holds metadata and IAM v3 grantees for a BigQuery V2 Data Policy.

  Produced by `Analyzer._analyze_static_dgt` during Mode 3 (`static-dgt`)
  target-state inspections.

  Attributes:
    name: Full V2 Data Policy resource name
      (`projects/{project}/locations/{location}/dataPolicies/{id}`).
    data_policy_id: Short identifier of the V2 Data Policy (`<= 200` chars).
    policy_type: V2 policy type string (`RAW_DATA_ACCESS_POLICY`,
      `DATA_MASKING_POLICY`, or `COLUMN_LEVEL_SECURITY_POLICY`).
    masking_rule: Predefined expression name or `Custom Routine: ...` string
      when `policy_type == DATA_MASKING_POLICY`; `None` otherwise.
    grantees: List of IAM v3 Next-Gen principal URIs (`principal://...`,
      `principalSet://...`) or IAM v1 strings returned by the V2 API. Empty for
      `_default_deny` seatbelt policies.
    data_governance_tag_key: Referenced DG Tag Key resource or namespaced name.
    data_governance_tag_value: Referenced DG Tag Value resource, short name, or
      namespaced name (`None` for key-level policies).
    matching_condition: Optional condition expression string from a
      condition-bound V2 Data Policy (`matching_condition` or
      `data_governance_tag_condition.expression`).
    region: Regional location of the V2 Data Policy.
    warnings: Warnings captured while hydrating this policy (e.g., REST grantee
      lookup failures).
  """

  name: str
  data_policy_id: str
  policy_type: str | None = None
  masking_rule: str | None = None
  grantees: list[str] = dataclasses.field(default_factory=list)
  data_governance_tag_key: str | None = None
  data_governance_tag_value: str | None = None
  matching_condition: str | None = None
  region: str | None = None
  warnings: list[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class DGTagValueInfo:
  """Holds metadata, child values, and V2 Data Policies for a DG Tag Value.

  Assembled into an in-memory tree by `Analyzer._list_tag_values_recursive`
  from a single `list_tag_values(parent="tagKeys/...")` RPC per Tag Key.

  Attributes:
    name: Resource Manager Tag Value name (e.g., `tagValues/123456789`).
    short_name: User-visible short name within its parent (`1-63` chars).
    namespaced_name: Full namespaced path (e.g., `project/key/parent_val/val`).
    description: Optional description text on the Tag Value.
    parent: Parent resource name (`tagKeys/{id}` for root values, or
      `tagValues/{id}` for hierarchical child values).
    data_policies: Regional V2 Data Policies attached to this Tag Value.
    child_values: Nested child `DGTagValueInfo` nodes in hierarchical tags.
    warnings: Warnings associated with this Tag Value.
  """

  name: str
  short_name: str
  namespaced_name: str | None = None
  description: str | None = None
  parent: str | None = None
  data_policies: list[DataPolicyV2Info] = dataclasses.field(
      default_factory=list
  )
  child_values: list[DGTagValueInfo] = dataclasses.field(default_factory=list)
  warnings: list[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class DGTagKeyInfo:
  """Holds metadata, root Tag Values, and key-level V2 policies for a Tag Key.

  Produced by `Analyzer._analyze_static_dgt` for Tag Keys whose `purpose` is
  `DATA_GOVERNANCE`.

  Attributes:
    name: Resource Manager Tag Key name (e.g., `tagKeys/123456789`).
    short_name: User-visible short name of the Tag Key (`1-63` chars).
    namespaced_name: Project-scoped namespaced name (`{project_id}/{key}`).
    description: Optional description text on the Tag Key.
    purpose: Tag Key purpose string (`DATA_GOVERNANCE`).
    tag_values: Root-level `DGTagValueInfo` nodes (each containing its own
      recursive `child_values` subtree).
    data_policies: V2 Data Policies attached directly at the Tag Key level
      (where `data_governance_tag.value` is unset).
    warnings: Warnings associated with this Tag Key.
  """

  name: str
  short_name: str
  namespaced_name: str | None = None
  description: str | None = None
  purpose: str | None = None
  tag_values: list[DGTagValueInfo] = dataclasses.field(default_factory=list)
  data_policies: list[DataPolicyV2Info] = dataclasses.field(
      default_factory=list
  )
  warnings: list[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class StaticDgtAnalysisResult:
  """Holds the complete Mode 3 (`static-dgt`) result for a project/region.

  Attributes:
    project_id: Scanned V2 Data Policy project ID.
    location: Scanned V2 Data Policy region (e.g., `us`).
    tag_keys: Discovered `DATA_GOVERNANCE` Tag Keys and their value trees.
    unattached_data_policies: V2 Data Policies in `(project_id, location)` whose
      `data_governance_tag` references a Tag Key in another project or a deleted
      Tag Key/Value not present in `tag_keys`.
    error: Error message if the scan failed; `None` on success.
    dgt_project_id: Optional GCP project ID where global `DATA_GOVERNANCE` Tag
      Keys and Tag Values were queried when separate from `project_id`.
  """

  project_id: str
  location: str
  tag_keys: list[DGTagKeyInfo] = dataclasses.field(default_factory=list)
  unattached_data_policies: list[DataPolicyV2Info] = dataclasses.field(
      default_factory=list
  )
  error: str | None = None
  dgt_project_id: str | None = None


@dataclasses.dataclass
class DGTagBindingDetails:
  """Holds column binding counts and optional column paths for one DGT value.

  Attributes:
    dg_tag_key: Namespaced key or resource name of the DG Tag Key.
    dg_tag_value: Short name or resource name of the DG Tag Value.
    bound_columns_count: Total number of columns bound to this `(key, value)`.
    bound_columns: Up to 1,000 `dataset.table.field_path` strings when
      `--verbose-bindings` is enabled; empty in standard summary mode.
  """

  dg_tag_key: str
  dg_tag_value: str
  bound_columns_count: int
  bound_columns: list[str] = dataclasses.field(default_factory=list)


# === Section: Static DGT Report Formatting Helpers ===
def _format_static_dgt_policy_line(data_policy: DataPolicyV2Info) -> str:
  """Formats one V2 Data Policy summary line for `generate_static_dgt_report`."""
  details = []
  if data_policy.policy_type:
    details.append(f"Type: {data_policy.policy_type}")
  if data_policy.masking_rule:
    details.append(f"Rule: {data_policy.masking_rule}")
  details_str = f" ({', '.join(details)})" if details else ""
  return f'"{data_policy.data_policy_id}"{details_str}'


def _append_static_dgt_grantees(
    target_lines: list[str],
    grantees: list[str],
    indent_prefix: str,
) -> None:
  """Appends formatted V2 Data Policy grantees to `target_lines`."""
  if grantees:
    target_lines.append(f"{indent_prefix}└── Grantees:")
    for grantee in grantees:
      target_lines.append(f"{indent_prefix}    - {grantee}")
  else:
    target_lines.append(f"{indent_prefix}└── Grantees: None")


def _append_static_dgt_policy_warnings(
    target_lines: list[str],
    data_policy: DataPolicyV2Info,
    indent_prefix: str,
    collected_warnings: list[str],
) -> None:
  """Appends per-policy warnings to `target_lines` and `collected_warnings`."""
  for warning in data_policy.warnings:
    target_lines.append(f"{indent_prefix}└── [WARNING]: {warning}")
    collected_warnings.append(
        f'Data Policy "{data_policy.data_policy_id}": {warning}'
    )


def _append_static_dgt_tag_value_hierarchy(
    target_lines: list[str],
    tag_value: DGTagValueInfo,
    prefix: str,
    collected_warnings: list[str],
) -> None:
  """Recursively renders a `DGTagValueInfo` subtree and its V2 Data Policies."""
  target_lines.append(
      f'{prefix}> DG Tag Value: "{tag_value.short_name}" ({tag_value.name})'
  )
  if tag_value.namespaced_name:
    target_lines.append(
        f"{prefix}  ├── Namespaced Name: {tag_value.namespaced_name}"
    )
  for data_policy in tag_value.data_policies:
    data_policy_line = _format_static_dgt_policy_line(data_policy)
    target_lines.append(f"{prefix}  └── Data Policy: {data_policy_line}")
    _append_static_dgt_grantees(
        target_lines, data_policy.grantees, f"{prefix}      "
    )
    _append_static_dgt_policy_warnings(
        target_lines, data_policy, f"{prefix}      ", collected_warnings
    )
  for child_value in tag_value.child_values:
    _append_static_dgt_tag_value_hierarchy(
        target_lines, child_value, prefix + "  ", collected_warnings
    )


def _count_dg_tag_values(tag_values: list[DGTagValueInfo]) -> int:
  """Counts all `DGTagValueInfo` nodes recursively across a Tag Value forest."""
  return len(tag_values) + sum(
      _count_dg_tag_values(tag_value.child_values) for tag_value in tag_values
  )


def _count_dg_tag_policies(tag_values: list[DGTagValueInfo]) -> int:
  """Counts all attached V2 Data Policies recursively across Tag Values."""
  return sum(
      len(tag_value.data_policies)
      + _count_dg_tag_policies(tag_value.child_values)
      for tag_value in tag_values
  )


# === Section: Analyzer Discovery & Reporting Engine ===
class Analyzer:
  """Discovers and audits Policy Tags, DGTs, Data Policies, and table bindings.

  `Analyzer` is designed around dependency injection and in-memory caching so it
  scales cleanly to enterprise environments with 10,000+ BigQuery tables and
  1,000+ Policy Tags / Data Policies without redundant RPC amplification.
  """

  def __init__(
      self,
      data_catalog_client: datacatalog_v1.PolicyTagManagerClient,
      data_policy_client: bigquery_datapolicies_v1.DataPolicyServiceClient,
      bigquery_client: bigquery.Client,
      resourcemanager_client: resourcemanager_v3.ProjectsClient,
      iam_client: iam_admin_v1.IAMClient,
      execution_project: str | None = None,
      dg_tag_keys_client: resourcemanager_v3.TagKeysClient | None = None,
      dg_tag_values_client: resourcemanager_v3.TagValuesClient | None = None,
      data_policy_v2_client: Any | None = None,
      halt_on_error: bool = False,
  ):
    """Initializes the Analyzer with injected Google Cloud API clients.

    Args:
      data_catalog_client: Initialized Data Catalog `PolicyTagManagerClient` for
        listing taxonomies, policy tags, and tag/taxonomy IAM policies.
      data_policy_client: Initialized BigQuery V1 `DataPolicyServiceClient` for
        listing legacy V1 Data Policies and their IAM policies.
      bigquery_client: Initialized `bigquery.Client` for running regional
        `INFORMATION_SCHEMA.COLUMN_FIELD_PATHS` aggregation queries.
      resourcemanager_client: Cloud Resource Manager `ProjectsClient` for
        bidirectional `project_id <-> project_number` normalization.
      iam_client: Initialized `iam_admin_v1.IAMClient` for inspecting custom
        project and organization IAM role permissions (`iam.roles.get`).
      execution_project: Optional project ID used to bill/execute BigQuery
        `INFORMATION_SCHEMA` query jobs when the caller lacks
        `bigquery.jobs.create` on the scanned data project. Defaults to the
        scanned `project_id` when `None`.
      dg_tag_keys_client: Optional Resource Manager `TagKeysClient` required for
        Mode 3 (`static-dgt`) Tag Key discovery.
      dg_tag_values_client: Optional Resource Manager `TagValuesClient` required
        for Mode 3 (`static-dgt`) Tag Value hierarchy discovery.
      data_policy_v2_client: Optional BigQuery Data Policy V2 client (with
        automatic REST `/v2/` fallback) for Mode 3 (`static-dgt`) analysis.
      halt_on_error: When `True`, stops multi-region/multi-project discovery
        immediately upon the first regional scan failure instead of continuing
        to remaining regions.
    """
    if execution_project is not None:
      execution_project = constants.validate_standard_project_id(
          execution_project, "execution_project"
      )
    self._data_catalog_client = data_catalog_client
    self._data_policy_client = data_policy_client
    self._bigquery_client = bigquery_client
    self._execution_project = execution_project
    self._resource_manager_client = resourcemanager_client
    self._iam_client = iam_client
    self._dg_tag_keys_client = dg_tag_keys_client
    self._dg_tag_values_client = dg_tag_values_client
    self._data_policy_v2_client = data_policy_v2_client
    self._rest_client = rest_utils.DataPolicyRestClient(
        data_policy_v2_client, backoff_multiplier=1.5
    )
    self._halt_on_error = halt_on_error

    # --- In-Memory Caches & Pre-Seeded Role Permissions ---
    # 1. Bidirectional Project ID <-> Project Number caches avoid repeated
    #    `resourcemanager.projects.get` RPCs across tags and routines.
    self._project_id_to_number_cache = {}
    self._project_number_to_id_cache = {}
    # 2. Policy Tag display-name cache stores human-readable names keyed by
    #    both `projects/<id>/...` and `projects/<number>/...` resource names.
    self._policy_tag_display_name_cache: dict[str, str] = {}
    # 3. Role permission cache (`_role_permission_cache`) is pre-seeded with
    #    the predefined column-level reader/masking roles to avoid unnecessary
    #    `iam.roles.get` RPCs for common bindings:
    #    - `roles/datacatalog.categoryFineGrainedReader`
    #    - `roles/bigquerydatapolicy.maskedReader`
    #    - `roles/bigquerydatapolicy.rawDataReader` (defensive fallback)
    #    Any other role bound to a Taxonomy, Policy Tag, or V1 Data Policy
    #    (such as `projects/*/roles/*` or `organizations/*/roles/*`) is
    #    inspected dynamically via `iam_client.get_role` and cached so each
    #    unique role is fetched at most once across 1,000+ tags (note that
    #    broad roles like `roles/owner` or `roles/bigquery.admin` do not carry
    #    `datacatalog.categories.fineGrainedGet` or
    #    `bigquery.dataPolicies.maskedGet` in Google Cloud IAM).
    self._role_permission_cache = {
        constants.FINE_GRAINED_READER_ROLE: [
            constants.FINE_GRAINED_READER_PERMISSION
        ],
        constants.MASKED_READER_ROLE: [constants.MASKED_READER_PERMISSION],
        constants.RAW_DATA_READER_ROLE: [constants.RAW_DATA_READER_PERMISSION],
    }
    # 4. Negative-lookup map (`_failed_roles`) records roles whose `get_role`
    #    call failed (e.g., missing `roles/iam.organizationRoleViewer` on an
    #    organization custom role) along with the failure message. Subsequent
    #    bindings referencing the same failed role skip redundant RPCs while
    #    emitting an `[ACTION REQUIRED]` warning on every affected resource.
    self._failed_roles: dict[str, str] = {}
    self._active_halt_on_error = False
    #    Inactive custom roles (`deleted=True` or `stage=DISABLED`) still return
    #    `included_permissions` from `iam.roles.get` even though Cloud IAM
    #    grants zero runtime access through them; `_inactive_roles` records
    #    their state so cached bindings skip granting access and emit warnings.
    self._inactive_roles: dict[str, str] = {}
    # 5. Per-run global DGT Tag Key/Value tree cache (`_static_dgt_keys_cache`),
    #    scoped to an active `analyze_static_dgt` invocation so scanning P V2
    #    Data Policy projects across R regions fetches global Resource Manager
    #    Tag Keys and Tag Values once instead of P * R times while deep-copying
    #    per section to keep attached regional Data Policies isolated.
    self._static_dgt_keys_cache: dict[str, list[DGTagKeyInfo]] = {}
    self._static_dgt_cache_active = False

  # === Section: Project ID <-> Project Number Normalization ===
  def _get_project_number(self, project_id: str) -> str | None:
    """Resolves a GCP project ID string to its numeric project number.

    Architectural Why:
      Data Catalog `list_taxonomies` and `list_policy_tags` return resource
      names containing `projects/<project_id>/...` when queried by project ID,
      whereas BigQuery V1 Data Policy `policy_tag` references and
      `INFORMATION_SCHEMA.COLUMN_FIELD_PATHS` store `projects/<number>/...`.
      Normalizing all Taxonomy and Policy Tag resource names to numeric
      `project_number` upfront guarantees exact string joins between Policy Tags
      and V1 Data Policies.

    Args:
      project_id: The GCP project ID string (e.g., `"my-taxonomy-proj"`).

    Returns:
      The numeric project number string (e.g., `"123456789"`), or `None` if the
      Cloud Resource Manager lookup fails or returns a non-numeric identifier.
    """
    if project_id in self._project_id_to_number_cache:
      return self._project_id_to_number_cache[project_id]
    try:
      project = self._resource_manager_client.get_project(
          name=f"projects/{project_id}"
      )
      project_number = str(project.name).split("/")[-1]
      if project_number and project_number.isdigit():
        logger.info(
            "Looked up project number for %s: %s", project_id, project_number
        )
        self._project_id_to_number_cache[project_id] = project_number
        self._project_number_to_id_cache[project_number] = project_id
        return project_number
      else:
        logger.error(
            "Cloud Resource Manager API did not return a valid project number"
            " for %s.",
            project_id,
        )
        return None
    except exceptions.GoogleAPIError as e:
      if logger.isEnabledFor(logging.DEBUG):
        logger.exception(
            "Failed to look up project number for %s using Cloud Resource"
            " Manager API",
            project_id,
        )
      else:
        logger.error(
            "Failed to look up project number for %s: %s", project_id, e
        )
      return None

  def _get_project_id(self, project_number: str) -> str | None:
    """Resolves a numeric GCP project number back to its human-readable ID.

    Architectural Why:
      BigQuery V1 Data Policy custom masking routines (`routine` field) and
      `INFORMATION_SCHEMA.COLUMN_FIELD_PATHS` `policy_tags` paths often encode
      the project segment as a numeric `project_number` (e.g.,
      `projects/12345/datasets/ds/routines/fn`). Resolving that number back to
      `project_id` allows `Analyzer` and `Planner` to display and validate
      human-readable project IDs in reports and `plan.json`.

    Args:
      project_number: The numeric GCP project number string (e.g., `"12345"`).

    Returns:
      The human-readable `project_id` string, or `None` if the lookup fails.
    """
    if project_number in self._project_number_to_id_cache:
      return self._project_number_to_id_cache[project_number]
    try:
      project = self._resource_manager_client.get_project(
          name=f"projects/{project_number}"
      )
      project_id = project.project_id
      if project_id:
        self._project_id_to_number_cache[project_id] = project_number
        self._project_number_to_id_cache[project_number] = project_id
        return project_id
      else:
        logger.error(
            "Cloud Resource Manager API did not return a valid project ID"
            " for %s.",
            project_number,
        )
        return None
    except exceptions.GoogleAPIError as e:
      if logger.isEnabledFor(logging.DEBUG):
        logger.exception(
            "Failed to look up project ID for %s using Cloud Resource Manager"
            " API",
            project_number,
        )
      else:
        logger.error(
            "Failed to look up project ID for %s: %s", project_number, e
        )
      return None

  # === Section: IAM Policy Principal Extraction & Custom Role Caching ===
  # pylint: disable=redefined-outer-name
  def _get_principals_with_permission(
      self,
      policy: policy_pb2.Policy,
      permission: str,
      warnings: list[str] | None = None,
      custom_roles_by_principal: dict[str, list[str]] | None = None,
  ) -> list[str]:
    # pylint: enable=redefined-outer-name
    """Extracts principals from an IAM policy whose role grants `permission`.

    Architectural Design & Security Invariants:
      1. Custom IAM Role Resolution & Caching: For roles not in
         `_role_permission_cache` (such as `projects/*/roles/*` and
         `organizations/*/roles/*`), this method calls `iam_client.get_role`
         once and caches the returned `included_permissions`. Note that
         inspecting organization-level custom roles requires
         `roles/iam.organizationRoleViewer` on the organization. If `get_role`
         fails, raises immediately when `halt_on_error=True`; otherwise records
         the error in `_failed_roles` (fail-closed) so every affected binding
         surfaces an `[ACTION REQUIRED]` warning in `plan.json` and reports.
      2. Conditional IAM Bindings (Fail-Closed Omission): Source IAM lookups
         request `requested_policy_version = 3` so IAM Conditions are preserved
         on `binding.condition` rather than down-converted to synthetic
         `_withcond_<hash>` role names. Because BigQuery V2 Data Policy inline
         `grantees` do not support IAM Conditions, any binding carrying a
         non-empty `binding.condition.expression` whose role grants `permission`
         is omitted fail-closed with an `[ACTION REQUIRED]` warning rather than
         promoting time-bounded or attribute-restricted grants to permanent
         unconditional access.
      3. Ancestor IAM Inheritance Trade-off: Resource-level `get_iam_policy`
         inspects bindings attached directly to the Taxonomy, Policy Tag, or V1
         Data Policy; roles inherited from Project, Folder, or Organization
         ancestors are not returned by resource-level `get_iam_policy`.

    Args:
      policy: The protobuf `google.iam.v1.Policy` returned by `get_iam_policy`.
      permission: Target IAM permission string to match (e.g.,
        `datacatalog.categories.fineGrainedGet`).
      warnings: Optional mutable list where warning strings for failed custom
        role lookups, inactive roles, or omitted conditional bindings are
        appended.
      custom_roles_by_principal: Optional mutable dictionary populated with
        `{principal: [custom_role_name, ...]}` whenever `permission` is granted
        via a non-predefined custom IAM role.

    Returns:
      Sorted, deduplicated list of IAM v1 member strings granted `permission`.

    Raises:
      RuntimeError: If a custom role permission lookup fails while
        `halt_on_error` is enabled.
    """
    principals = []
    predefined_roles = {
        constants.FINE_GRAINED_READER_ROLE,
        constants.MASKED_READER_ROLE,
        constants.RAW_DATA_READER_ROLE,
    }

    def _record_custom_role(
        role_name: str, members: list[str] | tuple[str, ...]
    ) -> None:
      if custom_roles_by_principal is None or role_name in predefined_roles:
        return
      for member in members:
        existing_roles = custom_roles_by_principal.setdefault(member, [])
        if role_name not in existing_roles:
          existing_roles.append(role_name)
          existing_roles.sort()

    def _record_conditional_binding_warning(
        role_name: str,
        members: list[str] | tuple[str, ...],
        condition_expression: str,
    ) -> None:
      members_display = ", ".join(sorted(members)) or "<none>"
      logger.warning(
          "Skipping conditional IAM binding on role %s for [%s] (condition:"
          " %s) because BigQuery V2 Data Policy grantees do not support IAM"
          " Conditions.",
          role_name,
          members_display,
          condition_expression,
      )
      if warnings is not None:
        warnings.append(
            f"[ACTION REQUIRED] Conditional IAM binding for role '{role_name}'"
            f" granting '{permission}' to [{members_display}] with condition"
            f" '{condition_expression}' was omitted fail-closed because"
            " BigQuery V2 Data Policy grantees do not support IAM Conditions."
            " Review whether these principals should receive unconditional"
            " access or remain excluded before running '--phase create'."
        )

    for binding in policy.bindings:
      role = binding.role
      condition_obj = getattr(binding, "condition", None)
      condition_expr = str(
          getattr(condition_obj, "expression", "") or ""
      ).strip()

      if role in self._failed_roles:
        previous_error = self._failed_roles[role]
        if self._halt_on_error or self._active_halt_on_error:
          raise RuntimeError(
              f"Failed to get permissions for role {role}: {previous_error}"
          )
        if warnings is not None:
          warnings.append(
              f"[ACTION REQUIRED] Skipped custom role inspection for {role}"
              f" due to previous failure ({previous_error}). Principals bound"
              " via this role were omitted fail-closed; grant"
              " roles/iam.organizationRoleViewer or roles/iam.roleViewer and"
              " regenerate the migration plan."
          )
        continue

      # Fast path: Check if role permissions are already in cache (either from
      # the 3 pre-seeded reader roles or a previous custom role lookup).
      if role in self._role_permission_cache:
        if permission in self._role_permission_cache[role]:
          if condition_expr:
            _record_conditional_binding_warning(
                role, binding.members, condition_expr
            )
          else:
            principals.extend(binding.members)
            _record_custom_role(role, binding.members)
        if role in self._inactive_roles and warnings is not None:
          inactive_state = self._inactive_roles[role]
          warnings.append(
              f"Skipped custom role {role} because it is {inactive_state} in"
              " IAM (grants zero effective permissions)."
          )
        continue

      # Slow path: Query IAM API for uncached role permissions and memoize.
      # Cloud IAM's `GetRole` still returns `included_permissions` for roles
      # that are `deleted` or in `DISABLED` launch stage (enum value 5), even
      # though IAM grants zero permissions at runtime through such roles. Skip
      # them with an explicit warning so migration never over-grants access.
      try:
        role_info = self._iam_client.get_role(
            request={"name": role}, retry=RETRY_CONFIG
        )
        is_deleted = bool(getattr(role_info, "deleted", False))
        raw_stage = getattr(role_info, "stage", None)
        stage_name = getattr(raw_stage, "name", None)
        is_disabled = (
            stage_name == "DISABLED"
            or raw_stage == "DISABLED"
            or (not isinstance(raw_stage, bool) and raw_stage == 5)
        )
        if is_deleted or is_disabled:
          inactive_state = "deleted" if is_deleted else "DISABLED"
          self._role_permission_cache[role] = []
          self._inactive_roles[role] = inactive_state
          logger.warning(
              "Skipping custom role %s because it is %s in IAM.",
              role,
              inactive_state,
          )
          if warnings is not None:
            warnings.append(
                f"Skipped custom role {role} because it is {inactive_state} in"
                " IAM (grants zero effective permissions)."
            )
          continue

        permissions = role_info.included_permissions
        self._role_permission_cache[role] = permissions

        if permission in permissions:
          if condition_expr:
            _record_conditional_binding_warning(
                role, binding.members, condition_expr
            )
          else:
            principals.extend(binding.members)
            _record_custom_role(role, binding.members)
      except Exception as e:  # pylint: disable=broad-exception-caught
        logger.error("Failed to get permissions for role %s: %s", role, e)
        if self._halt_on_error or self._active_halt_on_error:
          raise RuntimeError(
              f"Failed to get permissions for role {role}: {e}"
          ) from e
        self._failed_roles[role] = str(e)
        if warnings is not None:
          warnings.append(
              f"[ACTION REQUIRED] Failed to get permissions for role {role}:"
              f" {e}. Principals bound via this role were omitted"
              " fail-closed; grant roles/iam.organizationRoleViewer or"
              " roles/iam.roleViewer and regenerate the migration plan."
          )

    return sorted(list(set(principals)))

  @classmethod
  def _build_get_iam_policy_request(
      cls,
      resource: str,
  ) -> iam_policy_pb2.GetIamPolicyRequest:
    """Builds a version-3 `GetIamPolicyRequest` preserving IAM Conditions.

    Requesting `requested_policy_version = 3` ensures Cloud IAM returns
    conditional bindings intact on `binding.condition` rather than rewriting
    their role names to v1 `_withcond_<hash>` synthetic roles.

    Args:
      resource: Full resource name passed to `get_iam_policy`.

    Returns:
      Configured `iam_policy_pb2.GetIamPolicyRequest` with policy version 3.
    """
    request = iam_policy_pb2.GetIamPolicyRequest(resource=resource)
    request.options.requested_policy_version = 3
    return request

  def _format_custom_routine_rule(
      self,
      routine_name: str,
      policy_name: str,
      warnings_list: list[str],
  ) -> str:
    """Formats a custom masking routine path into `Custom Routine: p.d.r`.

    Resolves numeric project numbers in `projects/{p}/datasets/{d}/routines/{r}`
    via `_get_project_id` so both Mode 1 (`static-taxonomy`) and Mode 3
    (`static-dgt`) render human-readable `{project_id}.{dataset}.{routine}`
    identifiers consistently.

    Args:
      routine_name: Raw `routine` string from a V1 or V2 `DataMaskingPolicy`.
      policy_name: Resource name of the owning Data Policy for warning context.
      warnings_list: Mutable list where malformed or unresolvable routine
        warnings are appended.

    Returns:
      Formatted `Custom Routine: ...` rule string.
    """
    routine_parts = routine_name.split("/")
    if len(routine_parts) < 5:
      warnings_list.append(
          "Malformed custom masking routine resource name"
          f" '{routine_name}' on Data Policy '{policy_name}'."
      )
      return f"{constants.CUSTOM_ROUTINE_PREFIX} {routine_name}"

    routine_project_token = routine_parts[-5]
    if routine_project_token.isdigit():
      routine_project_id = self._get_project_id(routine_project_token)
      if not routine_project_id:
        routine_project_id = f"<unknown-project-{routine_project_token}>"
        logger.warning(
            "Data Policy '%s' references a routine in project"
            " number '%s' which cannot be mapped to a project ID.",
            policy_name,
            routine_project_token,
        )
        warnings_list.append(
            "Custom masking routine references project number"
            f" '{routine_project_token}' which could not be"
            " resolved to a project ID."
        )
    else:
      routine_project_id = routine_project_token
    return (
        f"{constants.CUSTOM_ROUTINE_PREFIX} "
        f"{routine_project_id}.{routine_parts[-3]}.{routine_parts[-1]}"
    )

  # === Section: Mode 1 (`static-taxonomy`) Discovery Helpers ===
  def _list_policy_tags(
      self, taxonomy_name: str, project_id: str, project_number: str
  ) -> list[PolicyTagInfo]:
    """Lists all Policy Tags in a taxonomy and hydrates their IAM readers.

    How It Works:
      1. Step 1 (Paginated Tag Enumeration & Name Normalization): Calls
         `list_policy_tags(parent=taxonomy_name)` to retrieve all Policy Tags
         in the taxonomy. Replaces the leading `projects/{project_id}/` prefix
         (`count=1`) with `projects/{project_number}/` on both `name` and
         `parent_policy_tag` so all identifiers match BigQuery V1 Data Policy
         references. Populates `_policy_tag_display_name_cache` under both the
         project-ID and project-number resource paths.
      2. Step 2 (Concurrent IAM Policy Fetch + Sequential Role Evaluation):
         Uses `ThreadPoolExecutor(max_workers=16)` to issue `get_iam_policy`
         RPCs in parallel across all Policy Tags in the taxonomy, avoiding
         $O(N)$ sequential RPC latency on large taxonomies. Once all IAM
         policies are fetched, `_get_principals_with_permission` runs
         sequentially on the main thread so updates to `_role_permission_cache`
         and `_failed_roles` remain race-free and warning order is 100%
         deterministic.

    Args:
      taxonomy_name: Resource name of the parent Data Catalog Taxonomy.
      project_id: Source GCP project ID string to replace in resource names.
      project_number: Numeric GCP project number string used for normalization.

    Returns:
      List of `PolicyTagInfo` objects with normalized resource names and
      populated `fine_grained_readers`.

    Raises:
      exceptions.PermissionDenied: If the caller lacks Data Catalog list or
        `datacatalog.policyTags.getIamPolicy` permissions.
      exceptions.GoogleAPICallError: If any underlying Data Catalog RPC fails.
    """
    policy_tags: list[PolicyTagInfo] = []
    try:
      # Step 1: Enumerate all Policy Tags in the taxonomy and normalize names
      # from `projects/<project_id>/...` to `projects/<project_number>/...`.
      policy_tag_pager = self._data_catalog_client.list_policy_tags(
          parent=taxonomy_name, retry=RETRY_CONFIG
      )
      for policy_tag in policy_tag_pager:
        policy_tag_name_for_iam = policy_tag.name.replace(
            f"projects/{project_id}/", f"projects/{project_number}/", 1
        )
        policy_tag_parent_for_iam = ""
        if policy_tag.parent_policy_tag:
          policy_tag_parent_for_iam = policy_tag.parent_policy_tag.replace(
              f"projects/{project_id}/", f"projects/{project_number}/", 1
          )
        if policy_tag.display_name:
          self._policy_tag_display_name_cache[policy_tag.name] = (
              policy_tag.display_name
          )
          self._policy_tag_display_name_cache[policy_tag_name_for_iam] = (
              policy_tag.display_name
          )
        policy_tag_info = PolicyTagInfo(
            name=policy_tag_name_for_iam,
            display_name=policy_tag.display_name,
            parent_policy_tag=policy_tag_parent_for_iam,
        )
        policy_tags.append(policy_tag_info)

      def _fetch_policy_tag_iam(
          policy_tag_info: PolicyTagInfo,
      ) -> policy_pb2.Policy:
        try:
          return self._data_catalog_client.get_iam_policy(
              request=self._build_get_iam_policy_request(policy_tag_info.name),
              retry=RETRY_CONFIG,
          )
        except exceptions.PermissionDenied as e:
          logger.error(
              "Permission denied to get IAM policy for policy tag %s."
              " Please check your IAM permissions (requires"
              " datacatalog.policyTags.getIamPolicy).",
              policy_tag_info.name,
          )
          raise e
        except exceptions.GoogleAPICallError as e:
          logger.error(
              "Failed to get IAM policy for policy tag %s: %s",
              policy_tag_info.name,
              e,
          )
          raise e

      # Step 2: Fetch per-tag IAM policies concurrently (up to 16 workers),
      # then extract principals sequentially on the main thread to keep shared
      # role-cache mutations thread-safe and warning ordering deterministic.
      if policy_tags:
        max_workers = min(16, len(policy_tags))
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers
        ) as executor:
          iam_policies = list(executor.map(_fetch_policy_tag_iam, policy_tags))
        for policy_tag_info, iam_policy in zip(policy_tags, iam_policies):
          policy_tag_info.fine_grained_readers = (
              self._get_principals_with_permission(
                  iam_policy,
                  constants.FINE_GRAINED_READER_PERMISSION,
                  policy_tag_info.warnings,
                  policy_tag_info.custom_roles_by_principal,
              )
          )
    except exceptions.PermissionDenied as e:
      logger.error(
          "Permission denied to list policy tags for taxonomy %s."
          " Please check your IAM permissions.",
          taxonomy_name,
      )
      raise e
    except exceptions.GoogleAPICallError as e:
      logger.error("Failed to list policy tags for %s: %s", taxonomy_name, e)
      raise e
    return policy_tags

  def _list_data_policies(
      self, project_id: str, location: str, taxonomy: TaxonomyInfo
  ) -> None:
    """Discovers V1 Data Policies for `taxonomy` and attaches them to its tags.

    How It Works:
      1. Step 1 (Prefix-Filtered V1 Data Policy Listing & Implicit Access
         Control): Queries `list_data_policies` with
         `filter="policy_tag:{taxonomy.name}*"` (where `taxonomy.name` is
         already normalized to `projects/{project_number}/...`). Whenever any
         V1 Data Policy matches a Policy Tag in `taxonomy`, sets
         `taxonomy.is_access_control = True` (Implicit Access Control signal),
         because BigQuery enforces column-level access control whenever Data
         Policies exist even if `activated_policy_types` was not explicitly set.
      2. Step 2 (Masking Rule & Custom Routine Project Resolution): Extracts
         either the `PredefinedExpression` enum name (e.g., `SHA256`,
         `ALWAYS_NULL`) or the custom UDF masking `routine` path
         (`projects/{p}/datasets/{d}/routines/{r}`). If the routine path uses a
         numeric project number, resolves it via `_get_project_id` (falling
         back to `<unknown-project-{number}>` with a warning if unresolvable).
      3. Step 3 (Concurrent V1 Data Policy IAM Hydration): Fetches each V1 Data
         Policy's IAM policy in parallel via
         `ThreadPoolExecutor(max_workers=16)` and resolves `raw_readers` (for
         `COLUMN_LEVEL_SECURITY_POLICY` / `RAW_DATA_ACCESS_POLICY`) or
         `masked_readers` (for `DATA_MASKING_POLICY`).

    Args:
      project_id: Source GCP project ID string.
      location: Region of the taxonomy and V1 Data Policies.
      taxonomy: Mutable `TaxonomyInfo` whose `is_access_control` flag and child
        `PolicyTagInfo.data_policies` lists are updated in place.

    Raises:
      exceptions.PermissionDenied: If the caller lacks
        `bigquery.dataPolicies.list` or `bigquery.dataPolicies.getIamPolicy`.
      exceptions.GoogleAPICallError: If any V1 Data Policy RPC fails.
    """
    policy_tag_names = {policy_tag.name for policy_tag in taxonomy.policy_tags}
    policy_tag_map = {
        policy_tag.name: policy_tag for policy_tag in taxonomy.policy_tags
    }
    try:
      # Step 1: List V1 Data Policies filtered by normalized taxonomy prefix.
      data_policy_filter = f"policy_tag:{taxonomy.name}*"
      request = bigquery_datapolicies_v1.ListDataPoliciesRequest(
          parent=f"projects/{project_id}/locations/{location}",
          filter=data_policy_filter,
      )
      data_policy_pager = self._data_policy_client.list_data_policies(
          request=request, retry=RETRY_CONFIG
      )
      pending_policies: list[tuple[PolicyTagInfo, DataPolicyInfo, str]] = []
      for data_policy in data_policy_pager:
        if data_policy.policy_tag in policy_tag_names:
          # Implicit Access Control Signal: BigQuery enforces column-level
          # security whenever any Data Policy is attached to a taxonomy's
          # policy tags, even if `FINE_GRAINED_ACCESS_CONTROL` is absent from
          # `activated_policy_types`. Combining explicit and implicit signals
          # via OR logic guarantees that Phase 1b `Planner` generates
          # `_default_deny` seatbelts for all enforced taxonomies.
          taxonomy.is_access_control = True
          policy_tag_info = policy_tag_map[data_policy.policy_tag]

          # Step 2: Parse predefined masking expression or custom UDF routine.
          masking_rule = None
          data_policy_warnings: list[str] = []
          if data_policy.data_masking_policy:
            predefined_expression_name = (
                bigquery_datapolicies_v1.DataMaskingPolicy.PredefinedExpression(
                    data_policy.data_masking_policy.predefined_expression
                ).name
            )
            if (
                predefined_expression_name
                != "PREDEFINED_EXPRESSION_UNSPECIFIED"
            ):
              masking_rule = predefined_expression_name
            elif data_policy.data_masking_policy.routine:
              masking_rule = self._format_custom_routine_rule(
                  data_policy.data_masking_policy.routine,
                  data_policy.name,
                  data_policy_warnings,
              )

          policy_type_name = bigquery_datapolicies_v1.DataPolicy.DataPolicyType(
              data_policy.data_policy_type
          ).name

          data_policy_info = DataPolicyInfo(
              name=data_policy.name,
              policy_tag=data_policy.policy_tag,
              masking_rule=masking_rule,
              policy_type=policy_type_name,
              warnings=data_policy_warnings,
          )
          pending_policies.append(
              (policy_tag_info, data_policy_info, policy_type_name)
          )

      def _fetch_data_policy_iam(
          item: tuple[PolicyTagInfo, DataPolicyInfo, str],
      ) -> policy_pb2.Policy:
        _, data_policy_info, _ = item
        try:
          return self._data_policy_client.get_iam_policy(
              request=self._build_get_iam_policy_request(data_policy_info.name),
              retry=RETRY_CONFIG,
          )
        except exceptions.PermissionDenied as e:
          logger.error(
              "Permission denied to get IAM policy for data policy %s."
              " Please check your IAM permissions (requires"
              " bigquery.dataPolicies.getIamPolicy).",
              data_policy_info.name,
          )
          raise e
        except exceptions.GoogleAPICallError as e:
          logger.error(
              "Failed to get IAM policy for data policy %s: %s",
              data_policy_info.name,
              e,
          )
          raise e

      # Step 3: Fetch V1 Data Policy IAM policies concurrently, then resolve
      # principals sequentially and attach policies in deterministic order.
      if pending_policies:
        max_workers = min(16, len(pending_policies))
        with concurrent.futures.ThreadPoolExecutor(
            max_workers=max_workers
        ) as executor:
          iam_policies = list(
              executor.map(_fetch_data_policy_iam, pending_policies)
          )
        for (
            policy_tag_info,
            data_policy_info,
            policy_type_name,
        ), iam_policy in zip(pending_policies, iam_policies):
          if policy_type_name in [
              constants.DATA_POLICY_TYPE_CLS,
              constants.DATA_POLICY_TYPE_RAW,
          ]:
            data_policy_info.raw_readers = self._get_principals_with_permission(
                iam_policy,
                constants.RAW_DATA_READER_PERMISSION,
                data_policy_info.warnings,
                data_policy_info.custom_roles_by_principal,
            )
          else:
            data_policy_info.masked_readers = (
                self._get_principals_with_permission(
                    iam_policy,
                    constants.MASKED_READER_PERMISSION,
                    data_policy_info.warnings,
                    data_policy_info.custom_roles_by_principal,
                )
            )
          policy_tag_info.data_policies.append(data_policy_info)
    except exceptions.PermissionDenied as e:
      logger.error(
          "Permission denied to list data policies for project %s in"
          " location %s. Please check your IAM permissions.",
          project_id,
          location,
      )
      raise e
    except exceptions.GoogleAPICallError as e:
      logger.error(
          "Failed to list data policies for project %s in location %s: %s",
          project_id,
          location,
          e,
      )
      raise e

  def _analyze_static_taxonomy(
      self, project_id: str, location: str
  ) -> list[TaxonomyInfo]:
    """Discovers all Data Catalog Taxonomies, Policy Tags, and V1 Data Policies.

    How It Works & Key Design Decisions:
      1. Step 1 (Project Number Lookup): Resolves `project_id` to its numeric
         `project_number` via Cloud Resource Manager so all taxonomy and policy
         tag resource names can be normalized before querying V1 Data Policies.
      2. Step 2 (Explicit vs. Implicit Access Control Detection): Checks if
         `FINE_GRAINED_ACCESS_CONTROL` is in `taxonomy.activated_policy_types`
         (Explicit signal), and subsequently checks in `_list_data_policies`
         whether any V1 Data Policy is attached to the taxonomy's tags
         (Implicit signal). In BigQuery, a taxonomy is Classification-Only
         (Default Allow) ONLY when both signals are false. If both signals are
         false, any `fine_grained_readers` on the taxonomy or its tags are
         retained on `TaxonomyInfo` / `PolicyTagInfo` with
         `is_access_control=False` so `Planner` can report them as
         `dangling_fine_grained_readers` warnings without generating
         `_default_deny` policies that would break Default Allow access.
      3. Step 3 (Policy Tag & Taxonomy-Level IAM Discovery): Enumerates all
         Policy Tags and their IAM policies (`_list_policy_tags`), normalizes
         `taxonomy_info.name` to `projects/{project_number}/...`, and fetches
         the Taxonomy-level IAM policy to extract taxonomy-wide
         `fine_grained_readers` (which `Planner` maps to Root Tag Values and
         masked non-root Tag Values so child values inherit via
         `matchTagHierarchy`).
      4. Step 4 (V1 Data Policy Attachment): Calls `_list_data_policies` to
         attach masking and raw access policies to their target Policy Tags.

    Args:
      project_id: Source GCP project ID to scan.
      location: Region to scan (e.g., `"us"`, `"eu"`).

    Returns:
      List of populated `TaxonomyInfo` objects for `(project_id, location)`.

    Raises:
      RuntimeError: If `project_id` cannot be resolved to a `project_number`.
      exceptions.PermissionDenied: If the caller lacks Data Catalog or Data
        Policy read/IAM permissions.
      exceptions.GoogleAPICallError: If any underlying discovery RPC fails.
    """
    taxonomies = []
    try:
      # Step 1: Resolve project_id to numeric project_number for resource name
      # normalization across Data Catalog and BigQuery Data Policy V1 APIs.
      project_number = self._get_project_number(project_id)
      if not project_number:
        raise RuntimeError(
            f"Could not determine project number for project {project_id}."
            " This is required for consistent resource name handling."
        )
      taxonomy_pager = self._data_catalog_client.list_taxonomies(
          parent=f"projects/{project_id}/locations/{location}",
          retry=RETRY_CONFIG,
      )
      for taxonomy in taxonomy_pager:
        # Step 2: Check Explicit Access Control signal (`activated_policy_types`
        # contains `FINE_GRAINED_ACCESS_CONTROL`). `_list_data_policies` below
        # applies OR logic with the Implicit signal (presence of any attached
        # V1 Data Policy) so `is_access_control` accurately reflects BigQuery
        # enforcement semantics.
        is_access_control = False
        activated_policy_types = getattr(taxonomy, "activated_policy_types", [])

        if activated_policy_types:
          if (
              datacatalog_v1.Taxonomy.PolicyType.FINE_GRAINED_ACCESS_CONTROL
              in activated_policy_types
          ):
            is_access_control = True

        taxonomy_info = TaxonomyInfo(
            name=taxonomy.name,
            display_name=taxonomy.display_name,
            location=location,
            is_access_control=is_access_control,
            is_explicit_access_control=is_access_control,
        )
        # Step 3: Enumerate Policy Tags and normalize taxonomy resource name to
        # numeric project_number before querying taxonomy IAM and V1 policies.
        taxonomy_info.policy_tags = self._list_policy_tags(
            taxonomy.name, project_id, project_number
        )

        taxonomy_info.name = taxonomy_info.name.replace(
            f"projects/{project_id}/", f"projects/{project_number}/", 1
        )

        taxonomy_name_for_iam = taxonomy_info.name
        try:
          taxonomy_iam_policy = self._data_catalog_client.get_iam_policy(
              request=self._build_get_iam_policy_request(taxonomy_name_for_iam),
              retry=RETRY_CONFIG,
          )
          taxonomy_info.fine_grained_readers = (
              self._get_principals_with_permission(
                  taxonomy_iam_policy,
                  constants.FINE_GRAINED_READER_PERMISSION,
                  taxonomy_info.warnings,
                  taxonomy_info.custom_roles_by_principal,
              )
          )
        except exceptions.PermissionDenied as e:
          logger.error(
              "Permission denied to get IAM policy for taxonomy %s."
              " Please check your IAM permissions (requires"
              " datacatalog.taxonomies.getIamPolicy).",
              taxonomy_name_for_iam,
          )
          raise e
        except exceptions.GoogleAPICallError as e:
          logger.error(
              "Failed to get IAM policy for taxonomy %s: %s",
              taxonomy_name_for_iam,
              e,
          )
          raise e

        # Step 4: Attach V1 Data Policies and apply Implicit Access Control OR.
        self._list_data_policies(project_id, location, taxonomy_info)
        taxonomies.append(taxonomy_info)
    except exceptions.PermissionDenied as e:
      logger.error(
          "Permission denied to list taxonomies for project %s in location %s."
          " Please check your IAM permissions.",
          project_id,
          location,
      )
      raise e
    except exceptions.GoogleAPICallError as e:
      # Log at debug level so public orchestration wrapper
      # `analyze_static_taxonomies` logs the failure once at ERROR level.
      logger.debug(
          "Failed to list taxonomies for project %s in location %s: %s",
          project_id,
          location,
          e,
      )
      raise e
    return taxonomies

  # === Section: Mode 2 (`column-binding`) Discovery via INFORMATION_SCHEMA ===
  def _analyze_column_bindings(
      self, project_id: str, location: str, verbose: bool = False
  ) -> ColumnBindingAnalysisResult:
    """Audits column-level security bindings across all tables in a region.

    How It Works & Scale Design Decisions:
      1. Server-Side SQL Aggregation (`INFORMATION_SCHEMA.COLUMN_FIELD_PATHS`):
         Instead of calling `list_datasets` -> `list_tables` -> `get_table`
         ($O(T)$ client-side RPCs across 10,000+ tables), this method queries
         the regional `INFORMATION_SCHEMA.COLUMN_FIELD_PATHS` view directly,
         scanning top-level columns and nested `STRUCT` fields in a single
         server-side SQL pass per query.
      2. Step 1 (Single-Pass Coverage Metrics CTE & Automatic Fallback):
         Runs a two-stage CTE (`column_level` -> `table_level`) computing table
         and column totals across Policy Tags (`policy_tags`, excluding
         synthetic Cross-Region Replication secondary-replica placeholders
         matching `/taxonomies/0/policyTags/`), Data Governance Tags
         (`data_governance_tags`), and direct column-level Data Policies
         (`data_policies`). If the target region does not yet expose the
         `data_policies` column on `COLUMN_FIELD_PATHS` (raising a SQL error
         mentioning `"data_policies"`), automatically falls back to
         `fallback_metrics_query` (scanning only `policy_tags` and
         `data_governance_tags`) and disables Step 4.
      3. Step 2 (Policy Tag Bindings & Concurrent Display-Name Prefetch):
         Aggregates column counts per Policy Tag (`UNNEST(policy_tags)`),
         filtering out `/taxonomies/0/policyTags/` CRR secondary-replica
         placeholders and applying an optional `ARRAY_AGG(... LIMIT 1000)` when
         `verbose=True` so projects with 10,000+ tagged columns never exceed
         BigQuery's 100 MB row size limit. Uncached Policy Tag display names
         are pre-fetched in parallel via `ThreadPoolExecutor(max_workers=16)`
         before assembling `PolicyTagBindingDetails`, avoiding $O(P)$
         sequential Data Catalog `get_policy_tag` RPCs (and guarding against
         `/taxonomies/0/policyTags/` in Python so synthetic CRR placeholders
         never trigger `404` Data Catalog calls).
      4. Step 3 (Data Governance Tag Bindings): Aggregates column counts per
         `(dg_tag.key, dg_tag.value)` via `UNNEST(data_governance_tags)`.
      5. Step 4 (Direct Column-Level Data Policy Bindings): When supported by
         the region, aggregates column counts per `data_policy.name` via
         `UNNEST(data_policies)`.

    Args:
      project_id: BigQuery data project ID whose tables are scanned.
      location: BigQuery dataset/table region (e.g., `"us"`, `"eu"`).
      verbose: When `True`, populates up to 1,000 `dataset.table.field_path`
        entries per tag or policy in `bound_columns`.

    Returns:
      Populated `ColumnBindingAnalysisResult` for `(project_id, location)`.

    Raises:
      exceptions.PermissionDenied: If the caller lacks `bigquery.jobs.create`
        on the execution project or `bigquery.tables.get` on the scanned
        project's `INFORMATION_SCHEMA` views.
      exceptions.GoogleAPICallError: If the regional metrics or Policy Tag
        binding query fails.
    """
    location_lower = location.lower()
    metrics = ColumnBindingMetrics()
    bindings_by_taxonomy_project: dict[str, list[PolicyTagBindingDetails]] = {}
    bindings_by_tag_key: dict[str, list[DGTagBindingDetails]] = {}
    column_data_policy_bindings: list[ColumnDataPolicyBindingDetails] = []

    target_execution_project = self._execution_project or project_id
    info_schema = (
        f"`{project_id}`.`region-{location_lower}`"
        ".INFORMATION_SCHEMA.COLUMN_FIELD_PATHS"
    )
    crr_placeholder_segment = constants.CRR_PLACEHOLDER_POLICY_TAG_SEGMENT

    # Step 1: Single-pass CTE aggregating table-level and column-level CLS
    # coverage across Policy Tags (excluding `/taxonomies/0/policyTags/` CRR
    # secondary-replica placeholders), DGTs, and direct column Data Policies.
    metrics_query = f"""
    WITH column_level AS (
      SELECT
        table_schema,
        table_name,
        field_path,
        EXISTS(
          SELECT 1
          FROM UNNEST(policy_tags) AS policy_tag
          WHERE NOT CONTAINS_SUBSTR(policy_tag, '{crr_placeholder_segment}')
        ) AS has_policy_tags,
        (data_governance_tags IS NOT NULL
         AND ARRAY_LENGTH(data_governance_tags) > 0)
          AS has_data_governance_tags,
        (data_policies IS NOT NULL
         AND ARRAY_LENGTH(data_policies) > 0) AS has_data_policies
      FROM
        {info_schema}
    ),
    table_level AS (
      SELECT
        table_schema,
        table_name,
        LOGICAL_OR(has_policy_tags) AS table_has_policy_tags,
        LOGICAL_OR(has_data_governance_tags) AS table_has_data_governance_tags,
        LOGICAL_OR(has_data_policies) AS table_has_data_policies,
        COUNT(1) AS table_total_columns,
        COUNTIF(has_policy_tags) AS table_pt_columns,
        COUNTIF(has_data_governance_tags) AS table_dgt_columns,
        COUNTIF(has_data_policies) AS table_dp_columns,
        COUNTIF(has_policy_tags
                OR has_data_governance_tags
                OR has_data_policies) AS table_any_cls_columns
      FROM
        column_level
      GROUP BY
        table_schema,
        table_name
    )
    SELECT
      COUNT(1) AS total_tables,
      COALESCE(SUM(table_total_columns), 0) AS total_columns,
      COUNTIF(table_has_policy_tags) AS tables_with_policy_tags,
      COALESCE(SUM(table_pt_columns), 0) AS columns_with_policy_tags,
      COUNTIF(table_has_data_governance_tags) AS tables_with_dg_tags,
      COALESCE(SUM(table_dgt_columns), 0) AS columns_with_dg_tags,
      COUNTIF(table_has_data_policies) AS tables_with_data_policies,
      COALESCE(SUM(table_dp_columns), 0) AS columns_with_data_policies,
      COUNTIF(table_has_policy_tags
              OR table_has_data_governance_tags
              OR table_has_data_policies) AS tables_with_any_cls,
      COALESCE(SUM(table_any_cls_columns), 0) AS columns_with_any_cls
    FROM
      table_level
    """

    has_column_data_policies_support = True
    try:
      try:
        metrics_job = self._bigquery_client.query(
            metrics_query,
            location=location_lower,
            project=target_execution_project,
        )
        metrics_result = metrics_job.result()
      except exceptions.GoogleAPIError as e:
        # Automatic Regional Schema Fallback: If `data_policies` is not yet
        # exposed in `COLUMN_FIELD_PATHS` for this region, re-run without it.
        if "data_policies" in str(e):
          logger.debug(
              "data_policies column not found in %s, falling back to"
              " PT and DGT metrics query: %s",
              project_id,
              e,
          )
          has_column_data_policies_support = False
          fallback_metrics_query = f"""
          WITH column_level AS (
            SELECT
              table_schema,
              table_name,
              field_path,
              EXISTS(
                SELECT 1
                FROM UNNEST(policy_tags) AS policy_tag
                WHERE NOT CONTAINS_SUBSTR(
                  policy_tag, '{crr_placeholder_segment}'
                )
              ) AS has_policy_tags,
              (data_governance_tags IS NOT NULL
               AND ARRAY_LENGTH(data_governance_tags) > 0)
               AS has_data_governance_tags
            FROM
              {info_schema}
          ),
          table_level AS (
            SELECT
              table_schema,
              table_name,
              LOGICAL_OR(has_policy_tags) AS table_has_policy_tags,
              LOGICAL_OR(has_data_governance_tags)
                AS table_has_data_governance_tags,
              COUNT(1) AS table_total_columns,
              COUNTIF(has_policy_tags) AS table_pt_columns,
              COUNTIF(has_data_governance_tags) AS table_dgt_columns,
              COUNTIF(has_policy_tags
                      OR has_data_governance_tags) AS table_any_cls_columns
            FROM
              column_level
            GROUP BY
              table_schema,
              table_name
          )
          SELECT
            COUNT(1) AS total_tables,
            COALESCE(SUM(table_total_columns), 0) AS total_columns,
            COUNTIF(table_has_policy_tags) AS tables_with_policy_tags,
            COALESCE(SUM(table_pt_columns), 0) AS columns_with_policy_tags,
            COUNTIF(table_has_data_governance_tags) AS tables_with_dg_tags,
            COALESCE(SUM(table_dgt_columns), 0) AS columns_with_dg_tags,
            0 AS tables_with_data_policies,
            0 AS columns_with_data_policies,
            COUNTIF(table_has_policy_tags
                    OR table_has_data_governance_tags) AS tables_with_any_cls,
            COALESCE(SUM(table_any_cls_columns), 0) AS columns_with_any_cls
          FROM
            table_level
          """
          metrics_job = self._bigquery_client.query(
              fallback_metrics_query,
              location=location_lower,
              project=target_execution_project,
          )
          metrics_result = metrics_job.result()
        else:
          raise

      row: Any = next(iter(metrics_result), None)
      if row:
        metrics.total_tables_scanned = getattr(row, "total_tables", 0) or 0
        metrics.total_columns_scanned = getattr(row, "total_columns", 0) or 0
        metrics.tables_with_policy_tags = (
            getattr(row, "tables_with_policy_tags", None)
            or getattr(row, "tables_with_tags", 0)
            or 0
        )
        metrics.columns_with_policy_tags = (
            getattr(row, "columns_with_policy_tags", None)
            or getattr(row, "columns_with_tags", 0)
            or 0
        )
        metrics.tables_with_dg_tags = (
            getattr(row, "tables_with_dg_tags", 0) or 0
        )
        metrics.columns_with_dg_tags = (
            getattr(row, "columns_with_dg_tags", 0) or 0
        )
        metrics.tables_with_column_data_policies = (
            getattr(row, "tables_with_data_policies", 0) or 0
        )
        metrics.columns_with_column_data_policies = (
            getattr(row, "columns_with_data_policies", 0) or 0
        )
        metrics.tables_with_any_cls = (
            getattr(row, "tables_with_any_cls", None)
            or max(metrics.tables_with_policy_tags, metrics.tables_with_dg_tags)
            or 0
        )
        metrics.columns_with_any_cls = (
            getattr(row, "columns_with_any_cls", None)
            or max(
                metrics.columns_with_policy_tags,
                metrics.columns_with_dg_tags,
            )
            or 0
        )

      # Step 2: Query detailed Policy Tag bindings and pre-fetch uncached
      # Policy Tag display names concurrently via ThreadPoolExecutor.
      select_columns_policy_tag = "policy_tag, COUNT(1) AS bound_columns"
      if verbose:
        # Cap ARRAY_AGG at `VERBOSE_BINDINGS_LIMIT` (1,000) column paths per
        # tag to avoid exceeding BigQuery's 100 MB row size limit on projects
        # with tens of thousands of tagged columns; `COUNT(1)` above remains
        # exact, and `generate_column_binding_report` emits an explicit
        # truncation notice whenever `bound_columns_count` exceeds the cap.
        select_columns_policy_tag += (
            ", ARRAY_AGG(CONCAT(table_schema, '.', table_name, '.', "
            "field_path) ORDER BY table_schema, table_name, field_path "
            f"LIMIT {constants.VERBOSE_BINDINGS_LIMIT}) AS bound_columns_list"
        )
      policy_tag_bindings_query = f"""
      SELECT
        {select_columns_policy_tag}
      FROM
        {info_schema},
        UNNEST(policy_tags) AS policy_tag
      WHERE
        policy_tags IS NOT NULL
        AND ARRAY_LENGTH(policy_tags) > 0
        AND NOT CONTAINS_SUBSTR(policy_tag, '{crr_placeholder_segment}')
      GROUP BY
        policy_tag
      """
      policy_tag_bindings_job = self._bigquery_client.query(
          policy_tag_bindings_query,
          location=location_lower,
          project=target_execution_project,
      )
      policy_tag_rows = list(policy_tag_bindings_job.result())

      # Scale Optimization (Concurrent Display-Name Prefetch): When running
      # standalone `column-binding` analysis across 1,000+ bound Policy Tags,
      # `_policy_tag_display_name_cache` starts empty. Pre-fetching all unique
      # uncached Policy Tag display names with up to 16 worker threads avoids
      # 1,000+ sequential `get_policy_tag` RPCs while preserving deterministic
      # cache updates and graceful fallback to `None` (resource name) on error.
      # Any `/taxonomies/0/policyTags/` CRR secondary-replica placeholder (for
      # example, if returned by a custom or mocked query) is resolved locally
      # without calling Data Catalog `get_policy_tag`.
      uncached_policy_tags: list[str] = []
      seen_uncached_tags: set[str] = set()
      for row in policy_tag_rows:
        policy_tag = getattr(row, "policy_tag", None)
        if not policy_tag:
          continue
        if crr_placeholder_segment in policy_tag:
          self._policy_tag_display_name_cache[policy_tag] = (
              constants.CRR_REPLICA_POLICY_TAG_DISPLAY_NAME
          )
          continue
        if (
            policy_tag not in self._policy_tag_display_name_cache
            and policy_tag not in seen_uncached_tags
        ):
          uncached_policy_tags.append(policy_tag)
          seen_uncached_tags.add(policy_tag)

      def _fetch_policy_tag_display_name(
          policy_tag_name: str,
      ) -> tuple[str, Any]:
        if crr_placeholder_segment in policy_tag_name:
          return (
              policy_tag_name,
              constants.CRR_REPLICA_POLICY_TAG_DISPLAY_NAME,
          )
        try:
          policy_tag_obj = self._data_catalog_client.get_policy_tag(
              request={"name": policy_tag_name}, retry=RETRY_CONFIG
          )
          return policy_tag_name, getattr(policy_tag_obj, "display_name", None)
        except exceptions.GoogleAPIError as e:
          if logger.isEnabledFor(logging.DEBUG):
            logger.exception(
                "Failed to get display name for %s", policy_tag_name
            )
          else:
            logger.warning(
                "Failed to get display name for %s: %s", policy_tag_name, e
            )
          return policy_tag_name, None

      if uncached_policy_tags:
        # Resolve the first uncached Policy Tag synchronously on the main
        # thread before fanning out `uncached_policy_tags[1:]` across worker
        # threads. In standalone `column-binding` scans, `_data_catalog_client`
        # has not issued a prior RPC yet (`credentials.valid` is False);
        # priming the first call on the main thread refreshes the OAuth2 access
        # token once instead of triggering up to 16 concurrent token refreshes
        # against `oauth2.googleapis.com` (which overflows `urllib3`'s default
        # 10-connection pool and logs `Connection pool is full` warnings).
        fetched_display_names = [
            _fetch_policy_tag_display_name(uncached_policy_tags[0])
        ]
        remaining_policy_tags = uncached_policy_tags[1:]
        if remaining_policy_tags:
          max_workers = min(16, len(remaining_policy_tags))
          with concurrent.futures.ThreadPoolExecutor(
              max_workers=max_workers
          ) as executor:
            fetched_display_names.extend(
                executor.map(
                    _fetch_policy_tag_display_name, remaining_policy_tags
                )
            )
        for tag_name, fetched_display_name in fetched_display_names:
          if fetched_display_name:
            self._policy_tag_display_name_cache[tag_name] = fetched_display_name

      unique_policy_tags = set()
      for row in policy_tag_rows:
        policy_tag = getattr(row, "policy_tag", None)
        if not policy_tag:
          continue
        bound_columns = getattr(row, "bound_columns", 0) or 0
        unique_policy_tags.add(policy_tag)

        bound_columns_list = []
        if verbose and hasattr(row, "bound_columns_list"):
          bound_columns_list = getattr(row, "bound_columns_list", None) or []

        display_name = self._policy_tag_display_name_cache.get(policy_tag)

        parts = policy_tag.split("/")
        if len(parts) >= 2 and parts[0] == "projects":
          taxonomy_project_raw = parts[1]
          taxonomy_project_id = taxonomy_project_raw
          if taxonomy_project_raw.isdigit():
            resolved_id = self._get_project_id(taxonomy_project_raw)
            if resolved_id:
              taxonomy_project_id = resolved_id

          if taxonomy_project_id not in bindings_by_taxonomy_project:
            bindings_by_taxonomy_project[taxonomy_project_id] = []

          bindings_by_taxonomy_project[taxonomy_project_id].append(
              PolicyTagBindingDetails(
                  policy_tag_name=policy_tag,
                  bound_columns_count=bound_columns,
                  policy_tag_display_name=display_name,
                  bound_columns=bound_columns_list,
              )
          )

      metrics.active_policy_tags_bound = len(unique_policy_tags)

      # Step 3: Query detailed Data Governance Tag bindings grouped by
      # `(dg_tag.key, dg_tag.value)`.
      select_columns_dgt = (
          "dg_tag.key AS dg_tag_key, dg_tag.value AS dg_tag_value, COUNT(1) AS"
          " bound_columns"
      )
      if verbose:
        select_columns_dgt += (
            ", ARRAY_AGG(CONCAT(table_schema, '.', table_name, '.', "
            "field_path) ORDER BY table_schema, table_name, field_path "
            f"LIMIT {constants.VERBOSE_BINDINGS_LIMIT}) AS bound_columns_list"
        )
      dgt_bindings_query = f"""
      SELECT
        {select_columns_dgt}
      FROM
        {info_schema},
        UNNEST(data_governance_tags) AS dg_tag
      WHERE
        data_governance_tags IS NOT NULL
        AND ARRAY_LENGTH(data_governance_tags) > 0
      GROUP BY
        dg_tag.key,
        dg_tag.value
      """
      dgt_bindings_job = self._bigquery_client.query(
          dgt_bindings_query,
          location=location_lower,
          project=target_execution_project,
      )
      dgt_bindings_result = dgt_bindings_job.result()

      unique_dg_tags = set()
      for row in dgt_bindings_result:
        tag_key = getattr(row, "dg_tag_key", None) or ""
        tag_value = getattr(row, "dg_tag_value", None) or ""
        bound_columns = getattr(row, "bound_columns", 0) or 0
        unique_dg_tags.add((tag_key, tag_value))

        bound_columns_list = []
        if verbose and hasattr(row, "bound_columns_list"):
          bound_columns_list = getattr(row, "bound_columns_list", None) or []

        if tag_key not in bindings_by_tag_key:
          bindings_by_tag_key[tag_key] = []

        bindings_by_tag_key[tag_key].append(
            DGTagBindingDetails(
                dg_tag_key=tag_key,
                dg_tag_value=tag_value,
                bound_columns_count=bound_columns,
                bound_columns=bound_columns_list,
            )
        )
      metrics.active_dg_tags_bound = len(unique_dg_tags)

      # Step 4: Query detailed direct column-level Data Policy bindings when
      # the region's `COLUMN_FIELD_PATHS` view supports `data_policies`.
      if has_column_data_policies_support:
        select_columns_data_policy = (
            "data_policy.name AS data_policy_name, COUNT(1) AS bound_columns"
        )
        if verbose:
          select_columns_data_policy += (
              ", ARRAY_AGG(CONCAT(table_schema, '.', table_name, '.', "
              "field_path) ORDER BY table_schema, table_name, field_path "
              f"LIMIT {constants.VERBOSE_BINDINGS_LIMIT}) AS bound_columns_list"
          )
        data_policy_bindings_query = f"""
        SELECT
          {select_columns_data_policy}
        FROM
          {info_schema},
          UNNEST(data_policies) AS data_policy
        WHERE
          data_policies IS NOT NULL
          AND ARRAY_LENGTH(data_policies) > 0
        GROUP BY
          data_policy.name
        """
        data_policy_bindings_job = self._bigquery_client.query(
            data_policy_bindings_query,
            location=location_lower,
            project=target_execution_project,
        )
        data_policy_bindings_result = data_policy_bindings_job.result()

        unique_data_policies = set()
        for row in data_policy_bindings_result:
          data_policy_name = getattr(row, "data_policy_name", None) or ""
          bound_columns = getattr(row, "bound_columns", 0) or 0
          unique_data_policies.add(data_policy_name)

          bound_columns_list = []
          if verbose and hasattr(row, "bound_columns_list"):
            bound_columns_list = getattr(row, "bound_columns_list", None) or []

          data_policy_id = (
              data_policy_name.split("/")[-1]
              if "/" in data_policy_name
              else data_policy_name
          )
          column_data_policy_bindings.append(
              ColumnDataPolicyBindingDetails(
                  data_policy_name=data_policy_name,
                  bound_columns_count=bound_columns,
                  data_policy_id=data_policy_id,
                  bound_columns=bound_columns_list,
              )
          )
        metrics.active_column_data_policies_bound = len(unique_data_policies)

      return ColumnBindingAnalysisResult(
          project_id=project_id,
          location=location,
          metrics=metrics,
          bindings_by_taxonomy_project=bindings_by_taxonomy_project,
          bindings_by_tag_key=bindings_by_tag_key,
          column_data_policy_bindings=column_data_policy_bindings,
      )

    except exceptions.PermissionDenied as e:
      logger.error(
          "Permission denied to query INFORMATION_SCHEMA for project %s."
          " Please check your IAM permissions (requires bigquery.jobs.create"
          " and bigquery.tables.get on INFORMATION_SCHEMA views).",
          project_id,
      )
      raise e
    except exceptions.GoogleAPICallError as e:
      # Log at debug level so public orchestration wrapper
      # `analyze_column_bindings` logs the failure once at ERROR level.
      logger.debug(
          "Failed to query INFORMATION_SCHEMA for project %s: %s", project_id, e
      )
      raise e

  # === Section: Mode 3 (`static-dgt`) Discovery & REST `/v2/` Fallbacks ===
  def _list_tag_values_recursive(
      self,
      parent_name: str,
      parent_namespaced_name: str | None = None,
  ) -> list[DGTagValueInfo]:
    """Lists Tag Values under `parent_name` and builds the hierarchy in memory.

    Scale Optimization ($O(K)$ RPCs vs. $O(V)$ Recursive RPCs):
      In Google Cloud Resource Manager Tags v3, calling
      `list_tag_values(parent="tagKeys/{id}")` returns ALL descendant
      `TagValue` resources across all hierarchy depths under that Tag Key in a
      single paginated response. Instead of issuing a recursive RPC for every
      Tag Value node ($O(V)$ RPCs), this method indexes all fetched values by
      their `parent` resource name (`children_by_parent`) and reconstructs the
      nested `DGTagValueInfo.child_values` tree in memory in $O(1)$ RPCs per
      Tag Key. If called directly with a `tagValues/{id}` parent whose own
      grandchildren were not in the response, falls back to recursive calls.

    Hierarchical Namespaced Path Reconstruction:
      Resource Manager Tags v3 populates raw `TagValue.namespaced_name` as a
      flat 3-segment string (`<project>/<tag_key_short>/<tag_value_short>`)
      even when a Tag Value is nested under a parent `TagValue`. Because the
      migration planner, creator, deleter, and swapper address hierarchical Tag
      Values by their full slash-delimited lineage
      (`<project>/<tag_key_short>/<root_short>/.../<leaf_short>`), this method
      propagates `current_parent_namespaced` top-down so nested child and
      grandchild `DGTagValueInfo.namespaced_name` fields reflect their full
      hierarchical path.

    Args:
      parent_name: Parent resource name (`"tagKeys/{id}"` or
        `"tagValues/{id}"`).
      parent_namespaced_name: Optional namespaced path of `parent_name` (for
        example, `"my-proj/my_key"` or `"my-proj/my_key/root_val"`).

    Returns:
      List of root `DGTagValueInfo` nodes directly under `parent_name`, with
      recursive `child_values` populated.
    """
    if not self._dg_tag_values_client:
      return []
    pager = self._dg_tag_values_client.list_tag_values(
        parent=parent_name, retry=RETRY_CONFIG
    )
    fetched_values = list(pager)

    if not fetched_values:
      return []

    # Group all fetched values by their immediate parent resource name so the
    # entire Tag Value hierarchy is assembled in memory from 1 RPC per TagKey.
    children_by_parent: dict[str, list[Any]] = {}
    for value in fetched_values:
      effective_parent = getattr(value, "parent", None) or parent_name
      if effective_parent not in children_by_parent:
        children_by_parent[effective_parent] = []
      children_by_parent[effective_parent].append(value)

    is_tag_key_root = parent_name.startswith("tagKeys/")

    def _build_subtree(
        current_parent: str,
        current_parent_namespaced: str | None = None,
    ) -> list[DGTagValueInfo]:
      nodes: list[DGTagValueInfo] = []
      for value in children_by_parent.get(current_parent, []):
        raw_namespaced = getattr(value, "namespaced_name", None)
        short_name = getattr(value, "short_name", None)
        # Reconstruct the full hierarchical namespaced path whenever the parent
        # path is known (or when raw_namespaced is a 3-segment flat path under
        # a nested TagValue parent), preserving explicit mock/custom paths when
        # current_parent_namespaced is unavailable.
        if current_parent_namespaced and short_name:
          resolved_namespaced = f"{current_parent_namespaced}/{short_name}"
        else:
          resolved_namespaced = raw_namespaced
        if value.name in children_by_parent or is_tag_key_root:
          child_values = _build_subtree(value.name, resolved_namespaced)
        else:
          child_values = self._list_tag_values_recursive(
              value.name, parent_namespaced_name=resolved_namespaced
          )
        value_info = DGTagValueInfo(
            name=value.name,
            short_name=value.short_name,
            namespaced_name=resolved_namespaced,
            description=getattr(value, "description", None),
            parent=value.parent,
            child_values=child_values,
        )
        nodes.append(value_info)
      return nodes

    return _build_subtree(parent_name, parent_namespaced_name)

  def _urlopen_json_with_retry(
      self,
      request: urllib.request.Request,
      timeout: float = 30.0,
      max_attempts: int = 3,
  ) -> dict[str, Any]:
    """Executes an HTTP REST request with timeout and exponential backoff.

    Delegates to `self._rest_client.urlopen_json_with_retry` (`rest_utils.py`)
    for uniform transient error handling (`429`, `500`, `502`, `503`, `504`,
    and `URLError`).

    Args:
      request: Prepared `urllib.request.Request` with bearer token headers.
      timeout: Per-attempt socket timeout in seconds (default: `30.0`).
      max_attempts: Maximum number of attempts before re-raising (default: `3`).

    Returns:
      Parsed JSON response dictionary (or `{}` if `max_attempts <= 0`).
    """
    return self._rest_client.urlopen_json_with_retry(
        request, timeout=timeout, max_attempts=max_attempts
    )

  def _list_data_policies_v2_rest(
      self, project_id: str, location: str
  ) -> list[dict[str, Any]]:
    """Lists V2 Data Policies via raw REST `/v2/` when the local SDK is stale.

    Architectural Why (Dual GAPIC-to-REST Fallback):
      Older versions of `google-cloud-bigquery-datapolicies` (`<= 0.10.0`) lack
      the `data_governance_tag` and `grantees` fields in their compiled protobuf
      descriptors and silently strip those fields during GAPIC response
      deserialization. Delegating to `DataPolicyRestClient` (`rest_utils.py`)
      reuses cached Application Default Credentials across paginated `/v2/`
      requests while honoring custom VPC-SC or regional transport endpoints
      configured on `self._data_policy_v2_client`.

    Args:
      project_id: Target GCP project ID containing the V2 Data Policies.
      location: Region of the V2 Data Policies (e.g., `"us"`).

    Returns:
      List of raw JSON policy dictionaries across all paginated REST responses.
    """
    self._rest_client.set_data_policy_client(self._data_policy_v2_client)
    return self._rest_client.list_data_policies_v2(project_id, location)

  def _fetch_v2_data_policy_grantees(
      self,
      project_id: str,
      location: str | list[str] | None = None,
      policy_names: list[str] | None = None,
      warnings_by_policy: dict[str, list[str]] | None = None,
  ) -> Any:
    """Fetches inline grantees for V2 Data Policies via concurrent REST calls.

    The BigQuery Data Policy V2 `ListDataPolicies` API omits inline `grantees`
    from list responses. To populate the exact principal list for each policy,
    this helper calls `GET /v2/{policy_name}` concurrently across up to 16
    worker threads while reusing the per-instance ADC bearer token cached in
    `self._rest_client`.

    Supports two calling conventions for backward compatibility with existing
    callers and tests:
    - Single-policy mode (`policy_names is None`): `project_id` holds the single
      full policy resource name, and `location` optionally holds a mutable
      `list[str]` to receive warnings. Returns `list[str]` of grantees.
    - Batch mode (`policy_names` is provided): `policy_names` holds a list of
      full policy resource names, and `warnings_by_policy` maps each policy name
      to any warning strings encountered. Returns `dict[str, list[str]]`.

    Args:
      project_id: In batch mode, the GCP project ID (unused when `policy_names`
        are already fully qualified); in single-policy mode, the full V2 Data
        Policy resource name.
      location: In batch mode, the region (unused); in single-policy mode, an
        optional `list[str]` to collect warning messages.
      policy_names: Optional list of full V2 Data Policy resource names to fetch
        in batch mode.
      warnings_by_policy: Optional dictionary mapping each policy resource name
        to a list of warning strings when a REST call or credential refresh
        fails.

    Returns:
      In single-policy mode, a `list[str]` of grantee identifiers. In batch
      mode, a `dict[str, list[str]]` mapping each policy resource name to its
      list of grantee identifiers.
    """
    # Step 1: Normalize arguments between single-policy mode and batch mode.
    single_policy_mode = policy_names is None
    if single_policy_mode:
      target_policy_names = [project_id] if project_id else []
      single_warnings = location if isinstance(location, list) else None
    else:
      del project_id, location  # Unused, resource names are fully qualified.
      target_policy_names = policy_names or []
      single_warnings = None

    if not target_policy_names:
      return [] if single_policy_mode else {}

    # Step 2: Pre-flight check that ADC credentials can be obtained once up
    # front (each worker also calls `get_bearer_token()` so tokens refresh
    # safely if a large batch spans token expiry). If initial authentication
    # fails, record a warning per policy and return gracefully.
    try:
      self._rest_client.get_bearer_token()
    except Exception as error:  # pylint: disable=broad-exception-caught
      logger.warning(
          "Failed to obtain credentials for policy grantees: %s", error
      )
      for name in target_policy_names:
        warning_message = (
            f"Failed to fetch V2 Data Policy grantees via REST for '{name}':"
            f" {error}"
        )
        if warnings_by_policy is not None:
          warnings_by_policy.setdefault(name, []).append(warning_message)
        if single_warnings is not None:
          single_warnings.append(warning_message)
      return [] if single_policy_mode else {}

    # Step 3: Resolve the regional or global endpoint host from the configured
    # V2 client transport so custom endpoints (e.g., regional or test hosts) are
    # honored.
    endpoint = rest_utils.resolve_datapolicy_endpoint(
        self._data_policy_v2_client
    )

    grantees_by_name: dict[str, list[str]] = {}

    def fetch_single(name: str) -> tuple[str, list[str], str | None]:
      url = f"{endpoint}/v2/{name}"
      try:
        current_token = self._rest_client.get_bearer_token()
        req_headers = {"Authorization": f"Bearer {current_token}"}
        request = urllib.request.Request(url, headers=req_headers)
        data = self._urlopen_json_with_retry(request)
        return name, list(data.get("grantees", [])), None
      except Exception as error:  # pylint: disable=broad-exception-caught
        logger.warning("Failed to fetch grantees for %s: %s", name, error)
        warning_message = (
            f"Failed to fetch V2 Data Policy grantees via REST for '{name}':"
            f" {error}"
        )
        return name, [], warning_message

    # Step 4: Fan out concurrent GET /v2/{name} requests across up to 16 worker
    # threads while preserving deterministic output order via executor.map.
    max_workers = min(16, len(target_policy_names))
    with concurrent.futures.ThreadPoolExecutor(
        max_workers=max_workers
    ) as executor:
      for name, grantees, warning_message in executor.map(
          fetch_single, target_policy_names
      ):
        grantees_by_name[name] = grantees
        if warning_message:
          if warnings_by_policy is not None:
            warnings_by_policy.setdefault(name, []).append(warning_message)
          if single_warnings is not None:
            single_warnings.append(warning_message)

    if single_policy_mode:
      return grantees_by_name.get(target_policy_names[0], [])
    return grantees_by_name

  @classmethod
  def _extract_policy_matching_condition(
      cls, policy: Any, is_rest: bool
  ) -> str | None:
    """Extracts a condition expression from a REST or SDK V2 Data Policy.

    Inspects both the SQL-like `matching_condition` (`matchingCondition`) field
    and the CEL `data_governance_tag_condition.expression`
    (`dataGovernanceTagCondition.expression`) submessage so condition-bound V2
    Data Policies are preserved and accurately labeled in static DGT reports.

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

  def _analyze_static_dgt(
      self,
      project_id: str,
      location: str,
      data_policy_project_id: str | None = None,
  ) -> tuple[list[DGTagKeyInfo], list[DataPolicyV2Info]]:
    """Analyzes static DGT keys, values, and V2 Data Policies in a region.

    Implements Mode 3 (`static-dgt`), used both during Phase 1a (to inspect any
    pre-existing Data Governance Tags and V2 Data Policies) and during Phase 1b
    / Phase 3 (to audit the newly provisioned Tag Keys, Tag Values, and V2 Data
    Policies created by `creator.py`). Because global Data Governance Tag Keys
    and Tag Values routinely reside in a centralized tag project while regional
    V2 Data Policies reside in one or more separate governance or table parent
    projects, `project_id` specifies the DGT project and
    `data_policy_project_id` optionally overrides the V2 Data Policy project.

    Args:
      project_id: The GCP project ID containing the global `DATA_GOVERNANCE` Tag
        Keys and Tag Values (and V2 Data Policies when `data_policy_project_id`
        is omitted).
      location: The BigQuery region/location of the V2 Data Policies.
      data_policy_project_id: Optional GCP project ID where regional V2 Data
        Policies are queried. Defaults to `project_id` when omitted.

    Returns:
      A 2-tuple `(tag_keys, unattached_data_policies)` where `tag_keys` is the
      list of `DGTagKeyInfo` trees with their matched V2 Data Policies attached,
      and `unattached_data_policies` is the list of `DataPolicyV2Info` objects
      whose `data_governance_tag` did not match any Tag Key/Value in
      `project_id`.

    Raises:
      RuntimeError: If `dg_tag_keys_client` was not provided to `Analyzer`.
      exceptions.PermissionDenied: If the caller lacks permission to list Tag
        Keys or V2 Data Policies.
      exceptions.GoogleAPICallError: If a Resource Manager or Data Policy API
        call fails.
    """
    if not self._dg_tag_keys_client:
      raise RuntimeError(
          "TagKeysClient was not provided to Analyzer for static DGT analysis."
      )

    dgt_project_id = project_id
    effective_policy_project_id = data_policy_project_id or dgt_project_id

    # === Step 1: Discover Data Governance Tag Keys and Build Value Trees ===
    # Resource Manager `list_tag_keys` returns all Tag Keys under the project,
    # including standard resource tags (e.g., cost-center or firewall tags). We
    # filter strictly to Tag Keys whose `purpose` is `DATA_GOVERNANCE` (enum
    # value 2 or string representation) and build each key's descendant Tag
    # Value tree in O(1) RPCs via `_list_tag_values_recursive`. During multi-
    # project / multi-region `analyze_static_dgt` runs, global Tag Keys/Values
    # for `dgt_project_id` are cached once and deep-copied per `(policy_project,
    # location)` scan so attached V2 Data Policies never bleed across sections.
    if (
        self._static_dgt_cache_active
        and dgt_project_id in self._static_dgt_keys_cache
    ):
      tag_keys = copy.deepcopy(self._static_dgt_keys_cache[dgt_project_id])
    else:
      tag_keys = []
      parent = f"projects/{dgt_project_id}"
      try:
        pager = self._dg_tag_keys_client.list_tag_keys(
            parent=parent, retry=RETRY_CONFIG
        )
        for key in pager:
          # Seed `_project_number_to_id_cache` directly from `TagKey.parent`
          # (`projects/<project_number>`) so V2 Data Policies referencing
          # `<dgt_project_number>/<key_short>` attach cleanly without requiring
          # `resourcemanager.projects.get` (absent from least-privilege
          # `roles/resourcemanager.tagViewer`).
          tag_key_parent = getattr(key, "parent", "")
          if (
              isinstance(tag_key_parent, str)
              and tag_key_parent.startswith("projects/")
              and not dgt_project_id.isdigit()
          ):
            parent_project_number = tag_key_parent.removeprefix("projects/")
            if parent_project_number.isdigit():
              self._project_number_to_id_cache.setdefault(
                  parent_project_number, dgt_project_id
              )
              self._project_id_to_number_cache.setdefault(
                  dgt_project_id, parent_project_number
              )
          purpose_value = getattr(key, "purpose", None)
          is_data_governance = False
          if purpose_value is not None:
            if purpose_value == 2 or str(purpose_value) in (
                "2",
                "DATA_GOVERNANCE",
                "Purpose.DATA_GOVERNANCE",
            ):
              is_data_governance = True
            elif hasattr(resourcemanager_v3.TagKey, "Purpose"):
              try:
                if (
                    purpose_value
                    == resourcemanager_v3.TagKey.Purpose.DATA_GOVERNANCE
                ):
                  is_data_governance = True
              except (ValueError, AttributeError):
                pass
          if not is_data_governance:
            continue

          purpose_str = constants.TAG_PURPOSE_DATA_GOVERNANCE
          if purpose_value is not None and str(purpose_value) not in (
              "2",
              "DATA_GOVERNANCE",
              "Purpose.DATA_GOVERNANCE",
          ):
            purpose_str = str(purpose_value)

          key_namespaced_name = getattr(key, "namespaced_name", None)
          parent_namespaced_name = None
          if isinstance(key_namespaced_name, str) and key_namespaced_name:
            parent_namespaced_name = key_namespaced_name
          tag_values = self._list_tag_values_recursive(
              key.name,
              parent_namespaced_name=parent_namespaced_name,
          )
          key_info = DGTagKeyInfo(
              name=key.name,
              short_name=key.short_name,
              namespaced_name=key_namespaced_name,
              description=getattr(key, "description", None),
              purpose=purpose_str,
              tag_values=tag_values,
          )
          tag_keys.append(key_info)
        if self._static_dgt_cache_active:
          self._static_dgt_keys_cache[dgt_project_id] = copy.deepcopy(tag_keys)
      except exceptions.PermissionDenied as e:
        logger.error(
            "Permission denied to list tag keys or values for project %s."
            " Please check your IAM permissions.",
            dgt_project_id,
        )
        raise e
      except exceptions.GoogleAPICallError as e:
        # Log at debug level so `analyze_static_dgt` logs the failure once.
        logger.debug(
            "Failed to list tag keys or values for project %s: %s",
            dgt_project_id,
            e,
        )
        raise e

    # === Step 2: List V2 Data Policies with GAPIC-to-REST Fallback ===
    # Mirror `Swapper._list_live_v2_data_policies`:
    # - When `bigquery_datapolicies_v2` is aliased to V1, V1 `ListDataPolicies`
    #   omits DGT-backed and condition-bound V2 policies on the server (even
    #   when legacy V1 policies are present), so always query REST `/v2/`.
    # - Older or intermediate V2 GAPIC wheels lack `data_governance_tag` or
    #   `matching_condition` in their compiled protobuf descriptors and drop
    #   those fields during deserialization. Whenever the client is V1, the SDK
    #   call fails, or SDK policies lack DGT/condition field support, fall back
    #   unconditionally to REST `/v2/`.
    unattached_data_policies = []
    if self._data_policy_v2_client:
      try:
        policy_parent = (
            f"projects/{effective_policy_project_id}/locations/{location}"
        )
        raw_policies: list[tuple[Any, bool]] = []

        # 2a. Attempt listing via standard GAPIC SDK client.
        sdk_policies = []
        sdk_error: Exception | None = None
        try:
          policy_pager = self._data_policy_v2_client.list_data_policies(
              parent=policy_parent, retry=RETRY_CONFIG
          )
          sdk_policies = list(policy_pager)
        except Exception as e:  # pylint: disable=broad-exception-caught
          sdk_error = e
          logger.warning(
              "GAPIC list_data_policies failed (%s); attempting REST fallback.",
              e,
          )

        # 2b. Verify whether the SDK preserved DGT and `matching_condition`
        # fields or needs REST fallback hydration. If both the SDK client and
        # the `/v2/` REST fallback fail, fail closed by raising so
        # `analyze_static_dgt` records an `[ERROR]` section (and honors
        # `--halt-on-error`) rather than misreporting zero V2 Data Policies.
        client_module = getattr(
            type(self._data_policy_v2_client), "__module__", ""
        )
        is_v1_client = client_module.startswith(
            "google.cloud.bigquery_datapolicies_v1"
        )
        has_dgt_support = any(
            getattr(policy_item, "data_governance_tag", None) is not None
            or self._extract_policy_matching_condition(policy_item, False)
            is not None
            for policy_item in sdk_policies
        )
        # Require both `matching_condition` and `data_governance_tag_condition`
        # support on every returned SDK object so intermediate wheels lacking
        # either condition field fall back to REST `/v2/` instead of silently
        # dropping condition-bound policies as label-less entries.
        has_condition_field_support = all(
            hasattr(policy_item, "matching_condition")
            and hasattr(policy_item, "data_governance_tag_condition")
            for policy_item in sdk_policies
        )
        if (
            sdk_error is None
            and not is_v1_client
            and (
                not sdk_policies
                or (has_dgt_support and has_condition_field_support)
            )
        ):
          raw_policies = [(p, False) for p in sdk_policies]
        else:
          # pylint: disable=broad-exception-caught
          try:
            rest_policies = self._list_data_policies_v2_rest(
                effective_policy_project_id, location
            )
            raw_policies = [(p, True) for p in rest_policies]
          except Exception as rest_error:
            if sdk_error is not None and isinstance(
                sdk_error, (exceptions.GoogleAPIError, RuntimeError)
            ):
              raise sdk_error from rest_error
            if isinstance(
                rest_error, (exceptions.GoogleAPIError, RuntimeError)
            ):
              if sdk_error is not None:
                raise rest_error from sdk_error
              raise rest_error
            if sdk_error is not None:
              raise RuntimeError(
                  f"Failed to list V2 Data Policies via client ({sdk_error})"
                  f" and REST fallback ({rest_error})."
              ) from rest_error
            raise RuntimeError(
                "Failed to list V2 Data Policies via REST fallback:"
                f" {rest_error}"
            ) from rest_error
          # pylint: enable=broad-exception-caught

        # === Step 3: Batch-Fetch Missing Inline Grantees via REST ===
        # BigQuery V2 `ListDataPolicies` omits `grantees` on listed policies.
        # Every DGT-backed or condition-bound V2 policy (including
        # `*_default_deny` seatbelts so out-of-band grantee tampering is visible
        # in static-dgt audits) is hydrated via parallel REST GET calls,
        # skipping only legacy V1 `policyTag`-only policies that belong to
        # Mode 1 (`static-taxonomy`).
        policies_needing_grantees = []
        for policy, is_rest in raw_policies:
          matching_condition = self._extract_policy_matching_condition(
              policy, is_rest
          )
          if is_rest:
            policy_name = policy.get("name", "")
            if not policy.get("grantees") and policy_name:
              if (
                  policy.get("policyTag")
                  and not policy.get("dataGovernanceTag")
                  and not matching_condition
              ):
                continue
              policies_needing_grantees.append(policy_name)
          else:
            policy_name = getattr(policy, "name", None)
            if policy_name and not getattr(policy, "grantees", None):
              if (
                  getattr(policy, "policy_tag", None)
                  and not getattr(policy, "data_governance_tag", None)
                  and not matching_condition
              ):
                continue
              policies_needing_grantees.append(policy_name)

        fetched_grantees = {}
        grantee_warnings_by_policy: dict[str, list[str]] = {}
        if policies_needing_grantees:
          fetched_grantees = self._fetch_v2_data_policy_grantees(
              effective_policy_project_id,
              location,
              policies_needing_grantees,
              warnings_by_policy=grantee_warnings_by_policy,
          )

        # === Step 4: Parse V2 Policies and Attach to Tag Keys / Tag Values ===
        def attach_to_matching_value(
            value_list: list[DGTagValueInfo],
            target_tag_value: str,
            policy_info: DataPolicyV2Info,
            key_namespaced_name: str | None = None,
        ) -> bool:
          """Recursively attaches `policy_info` to the matching Tag Value."""
          for tag_value in value_list:
            if (
                tag_value.short_name == target_tag_value
                or tag_value.name == target_tag_value
                or tag_value.namespaced_name == target_tag_value
                or (
                    key_namespaced_name
                    and f"{key_namespaced_name}/{tag_value.short_name}"
                    == target_tag_value
                )
                or (
                    tag_value.namespaced_name
                    and tag_value.namespaced_name.endswith(
                        f"/{target_tag_value}"
                    )
                )
            ):
              tag_value.data_policies.append(policy_info)
              return True
            if attach_to_matching_value(
                tag_value.child_values,
                target_tag_value,
                policy_info,
                key_namespaced_name=key_namespaced_name,
            ):
              return True
          return False

        for policy, is_rest in raw_policies:
          matching_condition = self._extract_policy_matching_condition(
              policy, is_rest
          )
          if is_rest:
            dg_tag_field = policy.get("dataGovernanceTag")
            dg_tag_key = dg_tag_field.get("key") if dg_tag_field else None
            dg_tag_value = dg_tag_field.get("value") if dg_tag_field else None
            policy_tag = policy.get("policyTag")
            # Skip legacy V1 policies that have policyTag and neither a DG tag
            # nor a matching condition.
            if policy_tag and not dg_tag_field and not matching_condition:
              continue

            data_policy_id = (
                policy.get("dataPolicyId") or policy["name"].split("/")[-1]
            )
            policy_type_name = policy.get("dataPolicyType")
            policy_name = policy.get(
                "name", f"{policy_parent}/dataPolicies/{data_policy_id}"
            )
            policy_warnings = list(
                grantee_warnings_by_policy.get(policy_name, [])
            )

            rule = None
            masking_policy = policy.get("dataMaskingPolicy")
            if masking_policy:
              if "predefinedExpression" in masking_policy:
                rule = masking_policy["predefinedExpression"]
              elif "routine" in masking_policy:
                rule = self._format_custom_routine_rule(
                    masking_policy["routine"], policy_name, policy_warnings
                )

            grantees_list = list(policy.get("grantees", []))
            if not grantees_list and policy_name in fetched_grantees:
              grantees_list = fetched_grantees[policy_name]
          else:
            dg_tag_field = getattr(policy, "data_governance_tag", None)
            dg_tag_key = (
                getattr(dg_tag_field, "key", None) if dg_tag_field else None
            )
            dg_tag_value = (
                getattr(dg_tag_field, "value", None) if dg_tag_field else None
            )
            policy_tag = getattr(policy, "policy_tag", None)
            # Skip legacy V1 policies that have policyTag and neither a DG tag
            # nor a matching condition.
            if policy_tag and not dg_tag_field and not matching_condition:
              continue

            policy_type_name = None
            data_policy_type = getattr(policy, "data_policy_type", None)
            if data_policy_type is not None:
              if hasattr(data_policy_type, "name"):
                policy_type_name = data_policy_type.name
              else:
                type_map = {
                    1: constants.DATA_POLICY_TYPE_MASKING,
                    2: constants.DATA_POLICY_TYPE_RAW,
                    3: constants.DATA_POLICY_TYPE_CLS,
                }
                policy_type_name = type_map.get(
                    data_policy_type, str(data_policy_type)
                )

            data_policy_id = (
                getattr(policy, "data_policy_id", None)
                or policy.name.split("/")[-1]
            )
            policy_name = policy.name
            policy_warnings = list(
                grantee_warnings_by_policy.get(policy_name, [])
            )

            rule = None
            masking_policy = getattr(policy, "data_masking_policy", None)
            if masking_policy:
              predefined_expression = getattr(
                  masking_policy, "predefined_expression", None
              )
              if predefined_expression:
                rule = (
                    predefined_expression.name
                    if hasattr(predefined_expression, "name")
                    else str(predefined_expression)
                )
              elif getattr(masking_policy, "routine", None):
                rule = self._format_custom_routine_rule(
                    masking_policy.routine, policy_name, policy_warnings
                )

            grantees_list = list(getattr(policy, "grantees", []))
            if not grantees_list and policy_name in fetched_grantees:
              grantees_list = fetched_grantees[policy_name]

          data_policy_v2_info = DataPolicyV2Info(
              name=policy_name,
              data_policy_id=data_policy_id,
              policy_type=policy_type_name,
              masking_rule=rule,
              grantees=grantees_list,
              data_governance_tag_key=dg_tag_key,
              data_governance_tag_value=dg_tag_value,
              matching_condition=matching_condition,
              region=location,
              warnings=policy_warnings,
          )

          # Match strictly against the Tag Key's resource name, short_name, or
          # full project-scoped namespaced_name
          # (`{dgt_project_id}/{short_name}`) so a policy referencing a
          # same-named Tag Key in another project is placed in
          # `unattached_data_policies` rather than mis-attached.
          matched = False
          if dg_tag_key:
            resolved_policy_key = dg_tag_key
            if "/" in dg_tag_key:
              pol_proj, pol_short = dg_tag_key.split("/", 1)
              if pol_proj.isdigit():
                resolved_proj_id = self._project_number_to_id_cache.get(
                    pol_proj
                )
                if not resolved_proj_id and self._resource_manager_client:
                  resolved_proj_id = self._get_project_id(pol_proj)
                if resolved_proj_id:
                  resolved_policy_key = f"{resolved_proj_id}/{pol_short}"
            for key_info in tag_keys:
              expected_namespaced_key = (
                  key_info.namespaced_name
                  or f"{dgt_project_id}/{key_info.short_name}"
              )
              key_matched = (
                  dg_tag_key == key_info.name
                  or dg_tag_key == key_info.short_name
                  or dg_tag_key == expected_namespaced_key
                  or resolved_policy_key == expected_namespaced_key
              )
              if key_matched:
                if dg_tag_value:
                  effective_target_value = dg_tag_value
                  if (
                      resolved_policy_key != dg_tag_key
                      and dg_tag_value.startswith(f"{dg_tag_key}/")
                  ):
                    effective_target_value = (
                        f"{resolved_policy_key}/"
                        f"{dg_tag_value[len(dg_tag_key) + 1:]}"
                    )
                  if attach_to_matching_value(
                      key_info.tag_values,
                      effective_target_value,
                      data_policy_v2_info,
                      key_namespaced_name=expected_namespaced_key,
                  ):
                    matched = True
                    break
                else:
                  key_info.data_policies.append(data_policy_v2_info)
                  matched = True
                  break

          if not matched:
            unattached_data_policies.append(data_policy_v2_info)

      except exceptions.PermissionDenied as e:
        logger.error(
            "Permission denied to list data policies for project %s in"
            " location %s. Please check your IAM permissions.",
            effective_policy_project_id,
            location,
        )
        raise e
      except exceptions.GoogleAPICallError as e:
        # Log at debug level so `analyze_static_dgt` logs the failure once.
        logger.debug(
            "Failed to list data policies for project %s in location %s: %s",
            effective_policy_project_id,
            location,
            e,
        )
        raise e

    return tag_keys, unattached_data_policies

  # ==========================================================================
  # Section 4: Public Orchestration Facade Methods (Modes 1–3)
  # ==========================================================================
  # Each public `analyze_*` method iterates across the caller-supplied
  # `(project_id, location)` pairs and isolates per-region API or runtime
  # failures into the corresponding `*AnalysisResult.error` field rather than
  # raising and aborting the entire multi-region scan (unless `halt_on_error` is
  # enabled, in which case iteration stops immediately after recording the first
  # failed region so subsequent regions are not queried).

  def analyze_static_taxonomies(
      self,
      source_project_id: str | list[str],
      locations: list[str],
      halt_on_error: bool = False,
  ) -> list[StaticTaxonomyAnalysisResult]:
    """Runs Mode 1 (`static-taxonomy`) across one or more projects and regions.

    Invoked by the CLI `analyze --mode=static-taxonomy` command and by
    `planner.py` during Phase 1a to inventory legacy Data Catalog Taxonomies,
    Policy Tags, V1 Data Policies, and resolved IAM principals.

    Args:
      source_project_id: A single GCP project ID string or a list of GCP project
        IDs to scan.
      locations: A list of BigQuery/Data Catalog region names (e.g., `["us",
        "eu"]`) to scan in each project.
      halt_on_error: When `True` (or when `self._halt_on_error` is `True`),
        stops scanning remaining regions/projects immediately after the first
        regional error is recorded.

    Returns:
      A list of `StaticTaxonomyAnalysisResult` objects, one per scanned
      `(project_id, location)` pair, in deterministic iteration order.
    """
    project_ids = [
        constants.validate_standard_project_id(pid, "source_project_id")
        for pid in (
            [source_project_id]
            if isinstance(source_project_id, str)
            else source_project_id
        )
    ]
    should_halt = halt_on_error or self._halt_on_error
    previous_active_halt = self._active_halt_on_error
    self._active_halt_on_error = should_halt
    results = []
    # TODO: For customers with massive setups (many regions), # NOLINT
    # consider future parallelization (e.g., concurrent.futures)
    # to speed up analysis.
    try:
      for project_id in project_ids:
        for location in locations:
          logger.info(
              "Scanning project %s in location %s...", project_id, location
          )
          try:
            taxonomies = self._analyze_static_taxonomy(project_id, location)
            results.append(
                StaticTaxonomyAnalysisResult(
                    project_id=project_id,
                    location=location,
                    taxonomies=taxonomies,
                )
            )
          except (exceptions.GoogleAPIError, RuntimeError) as e:
            logger.error(
                "Static analysis failed for %s in %s: %s",
                project_id,
                location,
                e,
            )
            results.append(
                StaticTaxonomyAnalysisResult(
                    project_id=project_id, location=location, error=str(e)
                )
            )
            if should_halt:
              return results
      return results
    finally:
      self._active_halt_on_error = previous_active_halt

  def analyze_column_bindings(
      self,
      source_project_id: str | list[str],
      locations: list[str],
      verbose: bool = False,
      halt_on_error: bool = False,
  ) -> list[ColumnBindingAnalysisResult]:
    """Runs Mode 2 (`column-binding`) across one or more projects and regions.

    Invoked by the CLI `analyze --mode=column-binding` command to inventory all
    active column-level security bindings (Policy Tags, Data Governance Tags,
    and direct Column Data Policies) across BigQuery datasets.

    Args:
      source_project_id: A single GCP data project ID string or a list of data
        project IDs to scan.
      locations: A list of BigQuery region names to scan in each project.
      verbose: If True, includes up to 1,000 `dataset.table.column` paths per
        bound tag or policy.
      halt_on_error: When `True` (or when `self._halt_on_error` is `True`),
        stops scanning remaining regions/projects immediately after the first
        regional error is recorded.

    Returns:
      A list of `ColumnBindingAnalysisResult` objects, one per scanned
      `(project_id, location)` pair.
    """
    project_ids = [
        constants.validate_standard_project_id(pid, "source_project_id")
        for pid in (
            [source_project_id]
            if isinstance(source_project_id, str)
            else source_project_id
        )
    ]
    should_halt = halt_on_error or self._halt_on_error
    results = []
    # TODO: Consider future parallelization (e.g., concurrent.futures) # NOLINT
    # to speed up analysis for customers with massive setups.
    for project_id in project_ids:
      for location in locations:
        if self._execution_project:
          logger.info(
              "Querying column bindings for project %s in location %s"
              " (execution project: %s)...",
              project_id,
              location,
              self._execution_project,
          )
        else:
          logger.info(
              "Querying column bindings for project %s in location %s...",
              project_id,
              location,
          )
        try:
          result = self._analyze_column_bindings(
              project_id, location, verbose=verbose
          )
          results.append(result)
        except exceptions.GoogleAPIError as e:
          logger.error(
              "Binding analysis failed for %s in %s: %s",
              project_id,
              location,
              e,
          )
          results.append(
              ColumnBindingAnalysisResult(
                  project_id=project_id, location=location, error=str(e)
              )
          )
          if should_halt:
            return results
    return results

  def analyze_static_dgt(
      self,
      source_project_id: str | list[str],
      locations: list[str],
      data_policy_v2_project_ids: str | list[str] | None = None,
      halt_on_error: bool = False,
  ) -> list[StaticDgtAnalysisResult]:
    """Runs Mode 3 (`static-dgt`) across DGT and V2 Data Policy projects.

    Invoked by the CLI `--phase analyze --analyze-type static-dgt` command (with
    `source_project_id` set to `--dgt-project-id` and
    `data_policy_v2_project_ids` set to `--data-policy-v2-project-ids`) to
    inventory global Resource Manager Tag Keys (`purpose=DATA_GOVERNANCE`), Tag
    Value hierarchies, and regional V2 Data Policies across separate or shared
    GCP projects.

    Args:
      source_project_id: A single GCP project ID string or list of project IDs
        containing the global `DATA_GOVERNANCE` Tag Keys and Tag Values (and V2
        Data Policies when `data_policy_v2_project_ids` is omitted).
      locations: A list of BigQuery region names to scan for V2 Data Policies.
      data_policy_v2_project_ids: Optional GCP project ID string or list of
        project IDs where regional V2 Data Policies are queried and joined back
        to the Data Governance Tags in `source_project_id`.
      halt_on_error: When `True` (or when `self._halt_on_error` is `True`),
        stops scanning remaining regions/projects immediately after the first
        regional error is recorded.

    Returns:
      A list of `StaticDgtAnalysisResult` objects, one per scanned V2 Data
      Policy `(project_id, location)` pair.
    """
    self._static_dgt_keys_cache.clear()
    self._static_dgt_cache_active = True
    should_halt = halt_on_error or self._halt_on_error
    results = []
    try:
      if data_policy_v2_project_ids is None:
        raw_project_ids = (
            [source_project_id]
            if isinstance(source_project_id, str)
            else source_project_id
        )
        project_ids = [
            constants.validate_standard_project_id(pid, "source_project_id")
            for pid in raw_project_ids
        ]
        for project_id in project_ids:
          for location in locations:
            logger.info(
                "Scanning static DGT resources for project %s in location"
                " %s...",
                project_id,
                location,
            )
            try:
              tag_keys, unattached_policies = self._analyze_static_dgt(
                  project_id, location
              )
              results.append(
                  StaticDgtAnalysisResult(
                      project_id=project_id,
                      location=location,
                      tag_keys=tag_keys,
                      unattached_data_policies=unattached_policies,
                  )
              )
            except (exceptions.GoogleAPIError, RuntimeError) as e:
              logger.error(
                  "Static DGT analysis failed for %s in %s: %s",
                  project_id,
                  location,
                  e,
              )
              results.append(
                  StaticDgtAnalysisResult(
                      project_id=project_id, location=location, error=str(e)
                  )
              )
              if should_halt:
                return results
        return results

      raw_dgt_project_ids = (
          [source_project_id]
          if isinstance(source_project_id, str)
          else source_project_id
      )
      dgt_project_ids = [
          constants.validate_standard_project_id(pid, "dgt_project_id")
          for pid in raw_dgt_project_ids
      ]
      raw_policy_project_ids = (
          [data_policy_v2_project_ids]
          if isinstance(data_policy_v2_project_ids, str)
          else data_policy_v2_project_ids
      )
      policy_project_ids = [
          constants.validate_standard_project_id(
              pid, "data_policy_v2_project_id"
          )
          for pid in raw_policy_project_ids
      ]
      for dgt_project_id in dgt_project_ids:
        for policy_project_id in policy_project_ids:
          for location in locations:
            logger.info(
                "Scanning static DGT resources for DGT project %s and Data"
                " Policy project %s in location %s...",
                dgt_project_id,
                policy_project_id,
                location,
            )
            try:
              tag_keys, unattached_policies = self._analyze_static_dgt(
                  dgt_project_id,
                  location,
                  data_policy_project_id=policy_project_id,
              )
              results.append(
                  StaticDgtAnalysisResult(
                      project_id=policy_project_id,
                      location=location,
                      tag_keys=tag_keys,
                      unattached_data_policies=unattached_policies,
                      dgt_project_id=dgt_project_id,
                  )
              )
            except (exceptions.GoogleAPIError, RuntimeError) as e:
              logger.error(
                  "Static DGT analysis failed for DGT project %s / Data Policy"
                  " project %s in %s: %s",
                  dgt_project_id,
                  policy_project_id,
                  location,
                  e,
              )
              results.append(
                  StaticDgtAnalysisResult(
                      project_id=policy_project_id,
                      location=location,
                      error=str(e),
                      dgt_project_id=dgt_project_id,
                  )
              )
              if should_halt:
                return results
      return results
    finally:
      self._static_dgt_cache_active = False
      self._static_dgt_keys_cache.clear()

  # ==========================================================================
  # Section 5: Human-Readable Markdown Report Generators (Modes 1–3)
  # ==========================================================================
  # All 3 report generators format their structured `*AnalysisResult` lists into
  # Markdown (`.md`) documents featuring a top-level `#` Markdown heading and a
  # fenced ```text ... ``` code block wrapping the 72-column (`"=" * 72` and
  # `"-" * 72`) ASCII banners and box-drawing trees (`├──`, `└──`, `│`). Using a
  # fenced `text` code block guarantees that all five CLI phases (`analyze`,
  # `plan`, `create`, `delete`, `swap`) emit `.md` reports for `--report-file`
  # while preventing Markdown parsers from misinterpreting literal underscores
  # (`_`), asterisks (`*`), pipes (`|`), or brackets (`[...]`) inside Tag Keys,
  # Tag Values, and ASCII tree connectors.

  def generate_static_taxonomy_report(
      self, results: list[StaticTaxonomyAnalysisResult]
  ) -> str:
    """Generates a Markdown (`.md`) report for Mode 1 (`static-taxonomy`).

    Renders a top-level Markdown heading followed by a fenced `text` block
    containing a 72-column header banner with UTC scan timestamp and total
    taxonomy count, followed by per-(project, location) sections. For each
    taxonomy, prints `[STATS]` (region, Access Control vs. Classification Only,
    total Policy Tags, total V1 Data Policies, taxonomy-level readers) and
    `[DETAILS]` as a recursive ASCII tree of Policy Tags, their Fine-Grained
    Readers, and their attached V1 Data Policies (with masking rules, Raw Data
    Readers, and Masked Readers). Any warnings collected on taxonomies, policy
    tags, or data policies are aggregated into a final `WARNINGS` banner at the
    end of the report.

    Args:
      results: A list of `StaticTaxonomyAnalysisResult` objects produced by
        `analyze_static_taxonomies`.

    Returns:
      The formatted multi-line Markdown report string.
    """
    # Step 1: Render the top-level Markdown heading, fenced `text` block, and
    # 72-column report header and summary metrics.
    report_lines = [
        "# Static Taxonomy & Data Policy Analysis Report",
        "",
        "```text",
    ]
    total_taxonomies = sum(len(r.taxonomies) for r in results if r.taxonomies)
    scan_time = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M UTC"
    )

    report_lines.append("=" * 72)
    report_lines.append(" " * 24 + "STATIC TAXONOMY ANALYSIS")
    report_lines.append("=" * 72)
    report_lines.append(f"Scan Time: {scan_time}")
    report_lines.append(f"Total Taxonomies Found: {total_taxonomies}")
    report_lines.append("=" * 72)

    taxonomy_counter = 0
    collected_warnings = []

    # Pre-scan discovered taxonomies by display_name so multi-region or
    # duplicate-name taxonomies are flagged as global DGT Tag Key collision
    # candidates requiring `--collision-resolution` (`counter` or `from_region`)
    # in Phase 1b (`--phase plan`).
    taxonomy_occurrences_by_display_name: dict[str, list[tuple[str, str]]] = {}
    for result_entry in results:
      if not result_entry.taxonomies:
        continue
      for tax_entry in result_entry.taxonomies:
        if tax_entry.display_name:
          taxonomy_occurrences_by_display_name.setdefault(
              tax_entry.display_name, []
          ).append((tax_entry.location, tax_entry.name))
    emitted_collision_names: set[str] = set()

    def _format_principal_with_custom_roles(
        principal: str,
        custom_roles_map: dict[str, list[str]],
    ) -> str:
      custom_roles = custom_roles_map.get(principal)
      if not custom_roles:
        return principal
      return f"{principal} (via custom role: {', '.join(custom_roles)})"

    # Step 2: Define recursive helper to render the Policy Tag hierarchy tree
    # (`parent_policy_tag` -> child `PolicyTagInfo` nodes) and collect any
    # per-tag or per-policy warnings.
    def print_policy_tag_hierarchy(
        policy_tag: PolicyTagInfo,
        prefix: str,
        children_map: dict[str, list[PolicyTagInfo]],
        taxonomy: TaxonomyInfo,
    ):
      report_lines.append(
          f'{prefix}> Policy Tag: "{policy_tag.display_name}"'
          f" ({policy_tag.name})"
      )
      if policy_tag.warnings:
        for warning in policy_tag.warnings:
          collected_warnings.append(
              f'Policy Tag "{policy_tag.display_name}"'
              f" ({policy_tag.name}): {warning}"
          )
      if policy_tag.fine_grained_readers:
        dangling_suffix = (
            " [DANGLING - NOT ENFORCED (Enforce Access Control is OFF)]"
            if not taxonomy.is_access_control
            else ""
        )
        report_lines.append(
            f"{prefix}  ├── Permission: Fine-Grained Reader (Raw Access)"
            f"{dangling_suffix}"
        )
        for principal in policy_tag.fine_grained_readers:
          formatted_principal = _format_principal_with_custom_roles(
              principal, policy_tag.custom_roles_by_principal
          )
          report_lines.append(
              f"{prefix}  │   └── Principals: {formatted_principal}"
          )
        if not taxonomy.is_access_control:
          dangling_readers_csv = ", ".join(policy_tag.fine_grained_readers)
          collected_warnings.append(
              f'Policy Tag "{policy_tag.display_name}" ({policy_tag.name}) in'
              f' Classification-Only Taxonomy "{taxonomy.display_name}" has'
              f" Fine-Grained Reader IAM bindings ({dangling_readers_csv})"
              " while Enforce Access Control is OFF. These dangling bindings"
              " are currently ignored by BigQuery and will not be migrated to"
              " restrictive V2 Data Policies in --phase plan."
          )
      for data_policy in policy_tag.data_policies:
        rule = (
            f" (Rule: {data_policy.masking_rule})"
            if data_policy.masking_rule
            else ""
        )
        report_lines.append(
            f"{prefix}  └── Data Policy:"
            f' "{data_policy.name.split("/")[-1]}"{rule}'
        )
        if data_policy.warnings:
          for warning in data_policy.warnings:
            collected_warnings.append(
                f'Data Policy "{data_policy.name.split("/")[-1]}"'
                f' on Policy Tag "{policy_tag.display_name}": {warning}'
            )
        if data_policy.raw_readers:
          report_lines.append(f"{prefix}    ├── Permission: Raw Data Reader")
          for principal in data_policy.raw_readers:
            formatted_principal = _format_principal_with_custom_roles(
                principal, data_policy.custom_roles_by_principal
            )
            report_lines.append(
                f"{prefix}    │   └── Principals: {formatted_principal}"
            )
        if data_policy.masked_readers:
          report_lines.append(f"{prefix}    ├── Permission: Masked Reader")
          for principal in data_policy.masked_readers:
            formatted_principal = _format_principal_with_custom_roles(
                principal, data_policy.custom_roles_by_principal
            )
            report_lines.append(
                f"{prefix}    │   └── Principals: {formatted_principal}"
            )

      for child_policy_tag in children_map[policy_tag.name]:
        print_policy_tag_hierarchy(
            child_policy_tag, prefix + "  ", children_map, taxonomy
        )

    # Step 3: Render each (project, location) section, reconstructing the
    # parent-to-children Policy Tag adjacency list sorted by `display_name`.
    for result in results:
      report_lines.append("-" * 72)
      report_lines.append(
          f"Scan of Project: {result.project_id} in Location: {result.location}"
      )
      report_lines.append("-" * 72)

      if result.error:
        report_lines.append(f"  [ERROR]: {result.error}")
        report_lines.append("=" * 72)
        continue

      if not result.taxonomies:
        report_lines.append(
            "  No taxonomies found in this project in this region."
        )
        report_lines.append("=" * 72)
        continue

      for taxonomy in result.taxonomies:
        taxonomy_counter += 1
        report_lines.append("-" * 72)
        report_lines.append(
            f'{taxonomy_counter}. Taxonomy: "{taxonomy.display_name}"'
            f" ({taxonomy.name})"
        )
        report_lines.append("-" * 72)
        report_lines.append("   [STATS]")
        taxonomy_type = (
            "Access Control"
            if taxonomy.is_access_control
            else "Classification Only"
        )
        if not taxonomy.is_access_control:
          enforce_access = "OFF"
        elif (
            taxonomy.is_explicit_access_control is not None
            and not taxonomy.is_explicit_access_control
        ):
          enforce_access = (
              "ON (Implicit via attached V1 Data Policies;"
              " activated_policy_types=[] / Data Catalog toggle OFF)"
          )
          collected_warnings.append(
              f'Taxonomy "{taxonomy.display_name}" ({taxonomy.name}) has'
              " empty activated_policy_types (Data Catalog 'Enforce access"
              " control' toggle is OFF) but has attached V1 Data Policies."
              " BigQuery enforces access control implicitly on this taxonomy,"
              " so Phase 1b (--phase plan) will treat it as Access Control and"
              " generate Default-Deny V2 Data Policy seatbelts."
          )
        else:
          enforce_access = "ON"
        report_lines.append(f"    Region:                 {taxonomy.location}")
        report_lines.append(f"    Taxonomy Type:          {taxonomy_type}")
        report_lines.append(f"    Enforce Access Control: {enforce_access}")
        report_lines.append(
            f"    Total Policy Tags:      {len(taxonomy.policy_tags)}"
        )
        report_lines.append(
            f"    Total Data Policies:    {taxonomy.total_data_policies}"
        )
        if taxonomy.fine_grained_readers:
          report_lines.append(
              "    Taxonomy-Level Readers:"
              f" {len(taxonomy.fine_grained_readers)}"
          )
        same_name_occurrences = taxonomy_occurrences_by_display_name.get(
            taxonomy.display_name, []
        )
        if len(same_name_occurrences) > 1:
          collision_regions = ", ".join(loc for loc, _ in same_name_occurrences)
          report_lines.append(
              "    Global DGT Collision:   YES"
              f' ("{taxonomy.display_name}" appears in regions:'
              f" {collision_regions}; select --collision-resolution"
              " counter|from_region in --phase plan)"
          )
          if taxonomy.display_name not in emitted_collision_names:
            emitted_collision_names.add(taxonomy.display_name)
            occurrences_detail = ", ".join(
                f"{loc} ({res_name})" for loc, res_name in same_name_occurrences
            )
            collected_warnings.append(
                "Cross-Region Taxonomy Name Collision: Taxonomy"
                f' "{taxonomy.display_name}" appears'
                f" {len(same_name_occurrences)} times across scanned regions"
                f" ({occurrences_detail}). Because target Data Governance Tag"
                " Keys are global resources, Phase 1b (--phase plan) maps each"
                " regional taxonomy to a separate global DG Tag Key (Separation"
                " strategy) and resolves naming collisions using"
                " --collision-resolution (counter or from_region)."
            )
        report_lines.append("   [DETAILS]")

        if taxonomy.warnings:
          for warning in taxonomy.warnings:
            collected_warnings.append(
                f'Taxonomy "{taxonomy.display_name}"'
                f" ({taxonomy.name}): {warning}"
            )

        if taxonomy.fine_grained_readers:
          tax_dangling_suffix = (
              " [DANGLING - NOT ENFORCED (Enforce Access Control is OFF)]"
              if not taxonomy.is_access_control
              else ""
          )
          report_lines.append(
              "   ├── Taxonomy Permission: Fine-Grained Reader (Raw Access)"
              f"{tax_dangling_suffix}"
          )
          for principal in taxonomy.fine_grained_readers:
            formatted_principal = _format_principal_with_custom_roles(
                principal, taxonomy.custom_roles_by_principal
            )
            report_lines.append(f"   │   └── Principals: {formatted_principal}")
          if not taxonomy.is_access_control:
            dangling_tax_readers_csv = ", ".join(taxonomy.fine_grained_readers)
            collected_warnings.append(
                f'Classification-Only Taxonomy "{taxonomy.display_name}"'
                f" ({taxonomy.name}) has Taxonomy-level Fine-Grained Reader"
                f" IAM bindings ({dangling_tax_readers_csv}) while Enforce"
                " Access Control is OFF. These dangling bindings are currently"
                " ignored by BigQuery and will not be migrated to restrictive"
                " V2 Data Policies in --phase plan."
            )

        policy_tags_map = {
            policy_tag.name: policy_tag for policy_tag in taxonomy.policy_tags
        }
        children_map = {
            policy_tag_name: [] for policy_tag_name in policy_tags_map
        }
        root_tags = []
        for policy_tag in taxonomy.policy_tags:
          if (
              policy_tag.parent_policy_tag
              and policy_tag.parent_policy_tag in policy_tags_map
          ):
            children_map[policy_tag.parent_policy_tag].append(policy_tag)
          else:
            root_tags.append(policy_tag)

        for policy_tag_list in children_map.values():
          policy_tag_list.sort(key=lambda p: p.display_name)
        root_tags.sort(key=lambda p: p.display_name)

        for root_policy_tag in root_tags:
          print_policy_tag_hierarchy(
              root_policy_tag, "   ", children_map, taxonomy
          )

        report_lines.append("=" * 72)

    # Step 4: Append aggregated warnings block if any taxonomy, policy tag, or
    # data policy recorded warnings during IAM/resource resolution.
    if collected_warnings:
      report_lines.append("\n" + "=" * 72)
      report_lines.append(" " * 32 + "WARNINGS")
      report_lines.append("=" * 72)
      for warning in collected_warnings:
        report_lines.append(f"[WARNING]: {warning}")

    report_lines.append("```")
    return "\n".join(report_lines)

  def generate_column_binding_report(
      self, results: list[ColumnBindingAnalysisResult]
  ) -> str:
    """Generates a Markdown (`.md`) report for Mode 2 (`column-binding`).

    Renders a top-level Markdown heading and fenced `text` block containing
    per-(project, location) coverage percentages across all three column-level
    security mechanisms (`[1. POLICY TAG BINDINGS]`,
    `[2. DATA GOVERNANCE TAG BINDINGS]`, and `[3. DATA POLICIES ON COLUMN]`),
    followed by ASCII trees of bound tags/policies and their column counts (plus
    individual `dataset.table.column` paths when `verbose=True`).

    Args:
      results: A list of `ColumnBindingAnalysisResult` objects produced by
        `analyze_column_bindings`.

    Returns:
      The formatted multi-line Markdown report string.
    """
    report_lines = [
        "# Column-Level Security (CLS) Binding Analysis Report",
        "",
        "```text",
    ]
    scan_time = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M UTC"
    )

    report_lines.append("=" * 72)
    report_lines.append(" " * 22 + "COLUMN BINDING ANALYSIS")
    report_lines.append("=" * 72)
    report_lines.append(f"Scan Time: {scan_time}")
    report_lines.append("=" * 72)

    for result in results:
      report_lines.append("-" * 72)
      report_lines.append(f"Project ID: {result.project_id}")
      report_lines.append(f"Location:   {result.location}")
      report_lines.append("-" * 72)

      if result.error:
        report_lines.append(f"  [ERROR]: {result.error}")
        report_lines.append("=" * 72)
        continue

      # Step 1: Compute and format table/column coverage percentages across
      # Policy Tags, Data Governance Tags, direct Column Data Policies, and the
      # combined "Any CLS" union.
      metrics = result.metrics
      total_tables = metrics.total_tables_scanned
      tables_with_tags = metrics.tables_with_policy_tags
      total_columns = metrics.total_columns_scanned
      columns_with_tags = metrics.columns_with_policy_tags

      if total_tables == 0:
        report_lines.append(
            "  [NOTE]: No tables found in this project in this region."
        )
        report_lines.append("=" * 72)
        continue

      table_percent = (
          (tables_with_tags / total_tables) * 100 if total_tables > 0 else 0
      )
      column_percent = (
          (columns_with_tags / total_columns) * 100 if total_columns > 0 else 0
      )

      report_lines.append(f"Total Tables Scanned:        {total_tables}")
      report_lines.append(
          f"Tables with Policy Tags:     {tables_with_tags} "
          f" ({table_percent:.1f}%)"
      )
      report_lines.append(f"Total Columns/Fields:        {total_columns}")
      report_lines.append(
          f"Columns with Policy Tags:    {columns_with_tags} "
          f" ({column_percent:.1f}%)"
      )
      report_lines.append(
          f"Active Policy Tags Bound:    {metrics.active_policy_tags_bound} "
          "(distinct tags in use)"
      )

      dgt_table_percent = (
          (metrics.tables_with_dg_tags / total_tables) * 100
          if total_tables > 0
          else 0
      )
      dgt_column_percent = (
          (metrics.columns_with_dg_tags / total_columns) * 100
          if total_columns > 0
          else 0
      )
      data_policy_table_percent = (
          (metrics.tables_with_column_data_policies / total_tables) * 100
          if total_tables > 0
          else 0
      )
      data_policy_column_percent = (
          (metrics.columns_with_column_data_policies / total_columns) * 100
          if total_columns > 0
          else 0
      )
      any_table_percent = (
          (metrics.tables_with_any_cls / total_tables) * 100
          if total_tables > 0
          else 0
      )
      any_column_percent = (
          (metrics.columns_with_any_cls / total_columns) * 100
          if total_columns > 0
          else 0
      )

      report_lines.append(
          f"Tables with DG Tags:         {metrics.tables_with_dg_tags} "
          f" ({dgt_table_percent:.1f}%)"
      )
      report_lines.append(
          f"Columns with DG Tags:        {metrics.columns_with_dg_tags} "
          f" ({dgt_column_percent:.1f}%)"
      )
      report_lines.append(
          f"Active DG Tags Bound:        {metrics.active_dg_tags_bound} "
          "(distinct tags in use)"
      )
      report_lines.append(
          "Tables with Data Policies:   "
          f"{metrics.tables_with_column_data_policies} "
          f" ({data_policy_table_percent:.1f}%)"
      )
      report_lines.append(
          "Columns with Data Policies:  "
          f"{metrics.columns_with_column_data_policies} "
          f" ({data_policy_column_percent:.1f}%)"
      )
      report_lines.append(
          "Active Data Policies Bound:  "
          f"{metrics.active_column_data_policies_bound} "
          "(distinct policies in use)"
      )
      report_lines.append(
          f"Tables with Any CLS:         {metrics.tables_with_any_cls} "
          f" ({any_table_percent:.1f}%)"
      )
      report_lines.append(
          f"Columns with Any CLS:        {metrics.columns_with_any_cls} "
          f" ({any_column_percent:.1f}%)"
      )

      # Explicitly notify operators whenever `--verbose-bindings` capped any
      # tag or policy's column-path list at `VERBOSE_BINDINGS_LIMIT` (1,000) so
      # they never mistake a truncated display list for the true column total.
      all_binding_entries = []
      for bindings in result.bindings_by_taxonomy_project.values():
        all_binding_entries.extend(bindings)
      for dgt_bindings in result.bindings_by_tag_key.values():
        all_binding_entries.extend(dgt_bindings)
      all_binding_entries.extend(result.column_data_policy_bindings)
      has_truncated_verbose_list = any(
          bool(binding.bound_columns)
          and binding.bound_columns_count > len(binding.bound_columns)
          for binding in all_binding_entries
      )
      if has_truncated_verbose_list:
        report_lines.append("")
        report_lines.append(
            "  [NOTE]: One or more --verbose-bindings column lists below were"
            f" capped at {constants.VERBOSE_BINDINGS_LIMIT} columns per"
            " tag/policy. All 'Bound Columns' and summary counts above reflect"
            " exact untruncated totals."
        )

      def _append_verbose_columns(
          bound_columns: list[str], bound_columns_count: int, indent: str
      ) -> None:
        """Renders verbose column paths and an explicit notice when capped."""
        report_lines.append(f"  {indent}└── Columns:")
        for column_name in bound_columns:
          report_lines.append(f"  {indent}    - {column_name}")
        shown_count = len(bound_columns)
        if bound_columns_count > shown_count:
          omitted_count = bound_columns_count - shown_count
          report_lines.append(
              f"  {indent}    - ... [TRUNCATED: showing {shown_count} of"
              f" {bound_columns_count} bound columns; {omitted_count}"
              " additional column(s) omitted due to"
              f" {constants.VERBOSE_BINDINGS_LIMIT}-column --verbose-bindings"
              " display cap]"
          )

      # Step 2: Render Section [1. POLICY TAG BINDINGS] grouped by Taxonomy
      # Project and sorted by Policy Tag resource name.
      report_lines.append("")
      report_lines.append("=" * 72)
      report_lines.append("[1. POLICY TAG BINDINGS]")
      report_lines.append("-" * 72)

      if not result.bindings_by_taxonomy_project:
        report_lines.append("  (No Policy Tags bound to columns)")
      else:
        for (
            taxonomy_project,
            bindings,
        ) in result.bindings_by_taxonomy_project.items():
          # Note: We don't verify if project is active, just output identifier.
          report_lines.append(
              f'> Taxonomy Project: "{taxonomy_project}" (Active)'
          )
          bindings.sort(key=lambda b: b.policy_tag_name)

          for i, binding in enumerate(bindings):
            is_last = i == len(bindings) - 1
            tree_char = "└──" if is_last else "├──"

            if binding.policy_tag_display_name:
              report_lines.append(
                  f"  {tree_char} Policy Tag: "
                  f'"{binding.policy_tag_display_name}" '
                  f"({binding.policy_tag_name})"
              )
            else:
              report_lines.append(
                  f"  {tree_char} Policy Tag: {binding.policy_tag_name}"
              )

            indent = "    " if is_last else "│   "
            tree_char_internal = "├──" if binding.bound_columns else "└──"
            report_lines.append(
                f"  {indent}{tree_char_internal} Bound Columns:"
                f" {binding.bound_columns_count}"
            )
            if binding.bound_columns:
              _append_verbose_columns(
                  binding.bound_columns, binding.bound_columns_count, indent
              )

      # Step 3: Render Section [2. DATA GOVERNANCE TAG BINDINGS] grouped by Tag
      # Key and sorted by Tag Value.
      report_lines.append("")
      report_lines.append("=" * 72)
      report_lines.append("[2. DATA GOVERNANCE TAG BINDINGS]")
      report_lines.append("-" * 72)

      if not result.bindings_by_tag_key:
        report_lines.append("  (No Data Governance Tags bound to columns)")
      else:
        for tag_key, dgt_bindings in result.bindings_by_tag_key.items():
          report_lines.append(f'> Tag Key: "{tag_key}"')
          dgt_bindings.sort(key=lambda b: b.dg_tag_value)

          for i, binding in enumerate(dgt_bindings):
            is_last = i == len(dgt_bindings) - 1
            tree_char = "└──" if is_last else "├──"

            report_lines.append(
                f'  {tree_char} Tag Value: "{binding.dg_tag_value}"'
            )
            indent = "    " if is_last else "│   "
            tree_char_internal = "├──" if binding.bound_columns else "└──"
            report_lines.append(
                f"  {indent}{tree_char_internal} Bound Columns:"
                f" {binding.bound_columns_count}"
            )
            if binding.bound_columns:
              _append_verbose_columns(
                  binding.bound_columns, binding.bound_columns_count, indent
              )

      # Step 4: Render Section [3. DATA POLICIES ON COLUMN] sorted by policy
      # resource name.
      report_lines.append("")
      report_lines.append("=" * 72)
      report_lines.append("[3. DATA POLICIES ON COLUMN]")
      report_lines.append("-" * 72)

      if not result.column_data_policy_bindings:
        report_lines.append("  (No Data Policies directly bound to columns)")
      else:
        sorted_policies = sorted(
            result.column_data_policy_bindings, key=lambda b: b.data_policy_name
        )
        for i, binding in enumerate(sorted_policies):
          is_last = i == len(sorted_policies) - 1
          tree_char = "└──" if is_last else "├──"

          policy_label = (
              f'"{binding.data_policy_id}" ({binding.data_policy_name})'
              if binding.data_policy_id
              else binding.data_policy_name
          )
          report_lines.append(f"  {tree_char} Data Policy: {policy_label}")
          indent = "    " if is_last else "│   "
          tree_char_internal = "├──" if binding.bound_columns else "└──"
          report_lines.append(
              f"  {indent}{tree_char_internal} Bound Columns:"
              f" {binding.bound_columns_count}"
          )
          if binding.bound_columns:
            _append_verbose_columns(
                binding.bound_columns, binding.bound_columns_count, indent
            )

      report_lines.append("=" * 72)

    report_lines.append("```")
    return "\n".join(report_lines)

  def _classify_unattached_static_dgt_policy(
      self,
      data_policy: DataPolicyV2Info,
      effective_dgt_project_id: str,
  ) -> str:
    """Classifies a V2 Data Policy that did not match a scanned DGT Tag Key.

    Separates genuinely unattached/missing-tag policies from cross-project DGT
    policies (referencing a Tag Key in another DGT project), direct column-level
    V2 Data Policies, and condition-bound V2 Data Policies so Mode 3
    (`static-dgt`) reports never mislabel cross-project policies as unattached
    or mislabel missing same-project tags as cross-project.

    Args:
      data_policy: Unmatched `DataPolicyV2Info` entry from `analyze_static_dgt`.
      effective_dgt_project_id: Effective DGT Tag Key project ID scanned for
        this report section.

    Returns:
      One of `"other_dgt_project"`, `"direct_column"`, `"condition_bound"`, or
      `"unattached"`.
    """
    tag_key = (data_policy.data_governance_tag_key or "").strip()
    tag_value = (data_policy.data_governance_tag_value or "").strip()
    matching_condition = (data_policy.matching_condition or "").strip()

    if not tag_key and not tag_value and not matching_condition:
      return "direct_column"
    if matching_condition and not tag_key:
      return "condition_bound"
    if tag_key and "/" in tag_key:
      key_prefix, _ = tag_key.split("/", 1)
      # Raw CRM resource names (`tagKeys/<id>`) lack a project namespace, so
      # only classify `<project>/<tag_key_short>` references as cross-project
      # when the project segment deterministically differs from the scanned
      # DGT project.
      if key_prefix and key_prefix != "tagKeys":
        if key_prefix.isdigit():
          resolved_project_id = self._project_number_to_id_cache.get(key_prefix)
          scanned_project_number = self._project_id_to_number_cache.get(
              effective_dgt_project_id
          )
          if resolved_project_id:
            if resolved_project_id != effective_dgt_project_id:
              return "other_dgt_project"
          elif scanned_project_number and key_prefix != scanned_project_number:
            return "other_dgt_project"
        elif key_prefix != effective_dgt_project_id:
          return "other_dgt_project"
    return "unattached"

  def generate_static_dgt_report(
      self, results: list[StaticDgtAnalysisResult]
  ) -> str:
    """Generates a Markdown (`.md`) report for Mode 3 (`static-dgt`).

    Renders a top-level Markdown heading and fenced `text` block containing a
    72-column header banner with UTC scan timestamp and distinct DGT Tag Key
    count, followed by per-(project, location) sections with per-section Tag Key
    numbering (`1..N`). For each Tag Key, prints `[STATS]` (namespaced name,
    purpose, total recursive Tag Values, total attached V2 Data Policies) and
    `[DETAILS]` (key-level V2 Data Policies and recursive Tag Value hierarchies
    with their attached V2 Data Policies, masking rules, and grantees).
    Partitions V2 Data Policies that did not attach to a scanned Tag Key into
    accurate sections (`[DATA POLICIES (V2) ATTACHED TO OTHER DGT PROJECTS]`,
    `[DIRECT COLUMN-LEVEL DATA POLICIES (V2)]`, `[CONDITION-BOUND DATA POLICIES
    (V2)]`, and `[UNATTACHED DATA POLICIES (V2)]`), and aggregates all policy
    warnings at the bottom.

    Args:
      results: A list of `StaticDgtAnalysisResult` objects produced by
        `analyze_static_dgt`.

    Returns:
      The formatted multi-line Markdown report string.
    """
    # Step 1: Render the top-level Markdown heading, fenced `text` block, and
    # 72-column report header.
    report_lines = [
        "# Static Data Governance Tag (DGT) Analysis Report",
        "",
        "```text",
    ]
    distinct_tag_keys = set()
    for r in results:
      if r.tag_keys:
        for tag_key in r.tag_keys:
          distinct_tag_keys.add(
              tag_key.name or tag_key.namespaced_name or tag_key.short_name
          )
    total_tag_keys = len(distinct_tag_keys)
    scan_time = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M UTC"
    )

    report_lines.append("=" * 72)
    report_lines.append(" " * 25 + "STATIC DGT ANALYSIS")
    report_lines.append("=" * 72)
    report_lines.append(f"Scan Time: {scan_time}")
    report_lines.append(f"Total DG Tag Keys Found: {total_tag_keys}")
    report_lines.append("=" * 72)

    collected_warnings = []

    # Step 2: Render each (project, location) section, resetting Tag Key
    # numbering per section and partitioning unmatched V2 Data Policies.
    for result in results:
      key_counter = 0
      report_lines.append("-" * 72)
      if result.dgt_project_id and result.dgt_project_id != result.project_id:
        report_lines.append(
            f"Scan of DGT Project: {result.dgt_project_id} | Data Policy"
            f" Project: {result.project_id} in Location: {result.location}"
        )
      else:
        report_lines.append(
            f"Scan of Project: {result.project_id} in Location:"
            f" {result.location}"
        )
      report_lines.append("-" * 72)

      if result.error:
        report_lines.append(f"  [ERROR]: {result.error}")
        report_lines.append("=" * 72)
        continue

      if not result.tag_keys:
        report_lines.append(
            "  No Data Governance Tag keys found in this project."
        )
        report_lines.append("=" * 72)
        if not result.unattached_data_policies:
          continue

      for tag_key in result.tag_keys:
        key_counter += 1
        report_lines.append("-" * 72)
        report_lines.append(
            f'{key_counter}. DG Tag Key: "{tag_key.short_name}"'
            f" ({tag_key.name})"
        )
        report_lines.append("-" * 72)
        report_lines.append("   [STATS]")
        report_lines.append(
            f"    Namespaced Name:     {tag_key.namespaced_name or 'N/A'}"
        )
        report_lines.append(
            f"    Purpose:             {tag_key.purpose or 'DATA_GOVERNANCE'}"
        )
        total_values = _count_dg_tag_values(tag_key.tag_values)
        total_policies = len(tag_key.data_policies) + _count_dg_tag_policies(
            tag_key.tag_values
        )
        report_lines.append(f"    Total DG Tag Values: {total_values}")
        report_lines.append(f"    Total Data Policies: {total_policies}")
        report_lines.append("   [DETAILS]")

        if tag_key.data_policies:
          report_lines.append("   [Key-Level Data Policies]")
          for data_policy in tag_key.data_policies:
            data_policy_line = _format_static_dgt_policy_line(data_policy)
            report_lines.append(f"   └── Data Policy: {data_policy_line}")
            _append_static_dgt_grantees(
                report_lines, data_policy.grantees, "       "
            )
            _append_static_dgt_policy_warnings(
                report_lines, data_policy, "       ", collected_warnings
            )

        for root_value in tag_key.tag_values:
          _append_static_dgt_tag_value_hierarchy(
              report_lines, root_value, "   ", collected_warnings
          )

        report_lines.append("=" * 72)

      if result.unattached_data_policies:
        effective_dgt_project_id = result.dgt_project_id or result.project_id
        categorized_policies: dict[str, list[DataPolicyV2Info]] = {
            "other_dgt_project": [],
            "direct_column": [],
            "condition_bound": [],
            "unattached": [],
        }
        for data_policy in result.unattached_data_policies:
          category = self._classify_unattached_static_dgt_policy(
              data_policy, effective_dgt_project_id
          )
          categorized_policies[category].append(data_policy)

        section_specs = [
            (
                "other_dgt_project",
                "[DATA POLICIES (V2) ATTACHED TO OTHER DGT PROJECTS]",
            ),
            (
                "direct_column",
                "[DIRECT COLUMN-LEVEL DATA POLICIES (V2)]",
            ),
            (
                "condition_bound",
                "[CONDITION-BOUND DATA POLICIES (V2)]",
            ),
            (
                "unattached",
                "[UNATTACHED DATA POLICIES (V2)]",
            ),
        ]
        for category_key, section_header in section_specs:
          section_policies = categorized_policies[category_key]
          if not section_policies:
            continue
          report_lines.append(section_header)
          report_lines.append("-" * 72)
          for data_policy in section_policies:
            data_policy_line = _format_static_dgt_policy_line(data_policy)
            report_lines.append(f"  > Data Policy: {data_policy_line}")
            if data_policy.data_governance_tag_key:
              report_lines.append(
                  f"    ├── Tag Key: {data_policy.data_governance_tag_key}"
              )
            if data_policy.data_governance_tag_value:
              report_lines.append(
                  f"    ├── Tag Value: {data_policy.data_governance_tag_value}"
              )
            if data_policy.matching_condition:
              report_lines.append(
                  "    ├── Matching Condition:"
                  f" {data_policy.matching_condition}"
              )
            if (
                not data_policy.data_governance_tag_key
                and not data_policy.data_governance_tag_value
                and not data_policy.matching_condition
            ):
              report_lines.append(
                  "    ├── Tag Key: None (Direct Column-Level Data Policy; no"
                  " Data Governance Tag attached)"
              )
            _append_static_dgt_grantees(
                report_lines, data_policy.grantees, "    "
            )
            _append_static_dgt_policy_warnings(
                report_lines, data_policy, "    ", collected_warnings
            )
          report_lines.append("=" * 72)

    # Step 4: Append aggregated warnings block if any V2 Data Policy encountered
    # REST grantee hydration errors.
    if collected_warnings:
      report_lines.append("\n" + "=" * 72)
      report_lines.append(" " * 32 + "WARNINGS")
      report_lines.append("=" * 72)
      for warning in collected_warnings:
        report_lines.append(f"[WARNING]: {warning}")

    report_lines.append("```")
    return "\n".join(report_lines)
