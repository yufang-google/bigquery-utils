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

"""Phase 2a Creator module for provisioning Data Governance Tag resources.

Role in the 3-Phase Migration Architecture:
  - Phase 1a (`analyzer.py`) discovers source Policy Tag taxonomies, IAM
    bindings, V1 Data Policies, and BigQuery column bindings.
  - Phase 1b (`planner.py`) translates the source taxonomy state into a
    deterministic `plan.json` containing `phase_2_resource_manifest` (5 ordered
    resource action lists) and `phase_3_binding_map`.
  - Phase 2a (`creator.py`, this module) executes `phase_2_resource_manifest`
    to provision target Cloud Resource Manager Data Governance Tag Keys
    (`purpose = DATA_GOVERNANCE`), hierarchical Data Governance Tag Values, and
    regional BigQuery V2 Data Policies (`RAW_DATA_ACCESS_POLICY` and
    `DATA_MASKING_POLICY`). Phase 2a is strictly additive and never modifies
    BigQuery table schemas.
  - Phase 2b (`deleter.py`) provides surgical individual resource deletion for
    sandbox teardown or misconfiguration cleanup.
  - Phase 3 (`swapper.py`) verifies live enforcement parity against the
    resources created by this module before atomically swapping table schemas.

Key Architectural & Design Decisions:
  1. Stateless Idempotency (Live GCP Check-Before-Create vs. Local State Files):
     Rather than writing local checkpoint files (which can drift from reality
     or break across machines), `Creator` queries live Google Cloud state before
     every creation and skips resources that already exist (`STATUS_SKIPPED`).
  2. VPC-SC-Compatible Parent Listing (`list_tag_keys` / `list_tag_values` vs.
     `get_namespaced_tag_*`):
     Avoids `get_namespaced_tag_key` and `get_namespaced_tag_value` because
     namespaced lookup endpoints frequently fail with resource-extraction
     `PermissionDenied` or `NotFound` errors across VPC Service Controls
     (VPC-SC) perimeters. Instead, lists tags under each resolved parent and
     filters direct children via `tag_value.parent == parent_id`.
  3. Positive & Negative In-Memory Lookup Caching (`_listed_tag_key_projects`
     and `_listed_tag_value_parents`):
     Caches resolved resource IDs (`_dg_tag_key_cache`, `_dg_tag_value_cache`)
     and records already-listed parent scopes so creating $N$ new sibling Tag
     Values under a parent issues only 1 `list_tag_values` RPC instead of
     $O(N)$ RPCs ($O(N^2)$ streamed items).
  4. Dual GAPIC-to-REST `/v2/` Fallback for V2 Data Policies:
     Older `google-cloud-bigquery-datapolicies` client libraries lack the
     `data_governance_tag` proto field and fail with `TypeError`, `ValueError`,
     or `InvalidArgument`. `Creator` automatically falls back to authenticated
     raw `/v2/` REST `GET` and `POST` requests with exponential backoff.
"""

from __future__ import annotations

import collections.abc
import copy
import logging
import os
import re
import sys
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# pylint: disable=g-import-not-at-top,g-bad-import-order
import constants
import rest_utils
from google.api_core import exceptions  # pylint: disable=g-import-not-at-top
from google.api_core import retry  # pylint: disable=g-import-not-at-top

# pylint: enable=g-import-not-at-top,g-bad-import-order

# Exponential backoff retry configuration for Cloud Resource Manager and
# BigQuery Data Policy GAPIC RPCs. Retries transient throttling (429) and
# server errors (500, 502, 503, 504) up to a 120-second deadline.
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

_ROUTINE_PATH_PATTERN = re.compile(
    r"^projects/([^/]+)/datasets/([^/]+)/routines/([^/]+)$"
)
_DRIFT_GRANTEES_PREVIEW_LIMIT = 5
_TAG_KEY_PURPOSE_LABELS: dict[Any, str] = {
    0: "PURPOSE_UNSPECIFIED",
    1: "GCE_FIREWALL",
    2: constants.TAG_PURPOSE_DATA_GOVERNANCE,
    "0": "PURPOSE_UNSPECIFIED",
    "1": "GCE_FIREWALL",
    "2": constants.TAG_PURPOSE_DATA_GOVERNANCE,
}


def _ensure_trailing_newline(content: str) -> str:
  """Ensures non-empty file content terminates with a single newline."""
  if not content or content.endswith("\n"):
    return content
  return f"{content}\n"


def _format_tag_key_purpose(purpose: Any) -> str:
  """Formats a Resource Manager `TagKey.purpose` value as a readable name.

  Python 3.11+ `IntEnum` / proto-plus `Purpose` values stringify as bare
  integers (`'0'`, `'1'`, `'2'`), which obscures what collided in operator error
  messages. Resolves `.name` first and falls back to known enum mappings.

  Args:
    purpose: Raw `purpose` value from a `TagKey` protobuf or mock object.

  Returns:
    Human-readable enum label such as `'PURPOSE_UNSPECIFIED'` or
    `'GCE_FIREWALL'`.
  """
  purpose_name = getattr(purpose, "name", None)
  if isinstance(purpose_name, str) and purpose_name:
    return purpose_name
  if not isinstance(purpose, bool) and purpose in _TAG_KEY_PURPOSE_LABELS:
    return _TAG_KEY_PURPOSE_LABELS[purpose]
  return str(purpose)


def _format_bounded_grantee_list(
    items: list[str],
    preview_limit: int = _DRIFT_GRANTEES_PREVIEW_LIMIT,
) -> str:
  """Formats a sorted grantee list with an explicit cap notification.

  Args:
    items: Sorted list of IAM principal strings.
    preview_limit: Maximum number of URIs to display inline before truncating.

  Returns:
    Compact representation displaying at most `preview_limit` entries plus the
    exact omitted/total counts when truncated.
  """
  if len(items) <= preview_limit:
    return str(items)
  omitted_count = len(items) - preview_limit
  preview_entries = ", ".join(repr(item) for item in items[:preview_limit])
  return (
      f"[{preview_entries}, ... (+{omitted_count} more; showing"
      f" {preview_limit} of {len(items)})]"
  )


def _format_grantee_drift_mismatch(
    actual_grantees: list[str],
    expected_grantees: list[str],
    preview_limit: int = _DRIFT_GRANTEES_PREVIEW_LIMIT,
) -> str | None:
  """Summarizes live-vs-planned grantee set differences with bounded output.

  Computes set differences (`missing_in_live`, `extra_in_live`) and caps inline
  URI previews so policies with hundreds of principals never dump tens of
  kilobytes onto a single log line or Markdown report bullet.

  Args:
    actual_grantees: Live V2 Data Policy grantee URIs from GCP.
    expected_grantees: Planned V2 Data Policy grantee URIs from `plan.json`.
    preview_limit: Maximum URIs shown per diff side before truncating.

  Returns:
    Formatted mismatch description string, or `None` if grantee sets match.
  """
  actual_set = set(actual_grantees)
  expected_set = set(expected_grantees)
  missing_in_live = sorted(expected_set - actual_set)
  extra_in_live = sorted(actual_set - expected_set)
  if not missing_in_live and not extra_in_live:
    return None

  diff_parts: list[str] = []
  if missing_in_live:
    diff_parts.append(
        f"missing_in_live ({len(missing_in_live)})="
        f"{_format_bounded_grantee_list(missing_in_live, preview_limit)}"
    )
  if extra_in_live:
    diff_parts.append(
        f"extra_in_live ({len(extra_in_live)})="
        f"{_format_bounded_grantee_list(extra_in_live, preview_limit)}"
    )
  return (
      f"grantees ({'; '.join(diff_parts)};"
      f" live_total={len(actual_set)}, planned_total={len(expected_set)})"
  )


def _extract_live_data_policy_v2_fields(
    existing_policy: Any, is_rest: bool
) -> tuple[
    str,
    str | None,
    str | None,
    str | None,
    str | None,
    str | None,
    list[str] | None,
]:
  """Extracts normalized fields from a live REST or proto V2 Data Policy.

  Args:
    existing_policy: Live V2 Data Policy protobuf message or REST JSON dict.
    is_rest: True if `existing_policy` is a REST JSON dictionary.

  Returns:
    Tuple of `(policy_name, policy_type, tag_key, tag_value,
    predefined_expression, routine, grantees)`.
  """
  actual_type: str | None = None
  actual_tag_key: str | None = None
  actual_tag_value: str | None = None
  actual_predefined: str | None = None
  actual_routine: str | None = None
  actual_grantees: list[str] | None = None
  existing_policy_name = ""

  if is_rest and isinstance(existing_policy, dict):
    raw_name = existing_policy.get("name")
    if isinstance(raw_name, str):
      existing_policy_name = raw_name
    raw_type = existing_policy.get("dataPolicyType")
    if isinstance(raw_type, str) and raw_type:
      actual_type = raw_type
    dg_tag_dict = existing_policy.get("dataGovernanceTag")
    if isinstance(dg_tag_dict, dict):
      raw_key = dg_tag_dict.get("key")
      if isinstance(raw_key, str) and raw_key:
        actual_tag_key = raw_key
      raw_val = dg_tag_dict.get("value")
      if isinstance(raw_val, str) and raw_val:
        actual_tag_value = raw_val
    masking_dict = existing_policy.get("dataMaskingPolicy")
    if isinstance(masking_dict, dict):
      raw_pred = masking_dict.get("predefinedExpression") or masking_dict.get(
          "predefined_expression"
      )
      if isinstance(raw_pred, str) and raw_pred:
        actual_predefined = raw_pred
      raw_routine = masking_dict.get("routine")
      if isinstance(raw_routine, str) and raw_routine:
        actual_routine = raw_routine
    raw_grantees = existing_policy.get("grantees")
    if (
        isinstance(raw_grantees, collections.abc.Sequence)
        and not isinstance(raw_grantees, (str, bytes))
        and all(isinstance(item, str) for item in raw_grantees)
    ):
      actual_grantees = list(raw_grantees)
    elif raw_grantees is None and len(existing_policy) > 1:
      # `GET /v2/{name}` omits repeated `grantees` in JSON when empty (`[]`).
      actual_grantees = []
  else:
    raw_name = getattr(existing_policy, "name", None)
    if isinstance(raw_name, str):
      existing_policy_name = raw_name
    raw_type = getattr(existing_policy, "data_policy_type", None)
    if isinstance(raw_type, str) and raw_type:
      actual_type = raw_type
    elif isinstance(getattr(raw_type, "name", None), str):
      actual_type = raw_type.name
    raw_dg_tag = getattr(existing_policy, "data_governance_tag", None)
    raw_key = getattr(raw_dg_tag, "key", None)
    if isinstance(raw_key, str) and raw_key:
      actual_tag_key = raw_key
    raw_val = getattr(raw_dg_tag, "value", None)
    if isinstance(raw_val, str) and raw_val:
      actual_tag_value = raw_val
    raw_masking = getattr(existing_policy, "data_masking_policy", None)
    raw_pred = getattr(raw_masking, "predefined_expression", None)
    if isinstance(raw_pred, str) and raw_pred:
      actual_predefined = raw_pred
    elif isinstance(getattr(raw_pred, "name", None), str):
      actual_predefined = raw_pred.name
    raw_routine = getattr(raw_masking, "routine", None)
    if isinstance(raw_routine, str) and raw_routine:
      actual_routine = raw_routine
    # Proto-plus messages expose repeated fields as `Repeated` (a
    # `MutableSequence`, not `list`/`tuple`), so accept any non-string
    # `Sequence` of strings.
    raw_grantees = getattr(existing_policy, "grantees", None)
    if (
        isinstance(raw_grantees, collections.abc.Sequence)
        and not isinstance(raw_grantees, (str, bytes))
        and all(isinstance(item, str) for item in raw_grantees)
    ):
      actual_grantees = list(raw_grantees)

  return (
      existing_policy_name,
      actual_type,
      actual_tag_key,
      actual_tag_value,
      actual_predefined,
      actual_routine,
      actual_grantees,
  )


def _routines_match(
    live_routine_path: str,
    planned_routine_path: str,
    target_project_id: str,
    policy_project_token: str,
) -> bool:
  """Compares custom routine paths while normalizing numeric project numbers."""
  if live_routine_path == planned_routine_path:
    return True
  live_match = _ROUTINE_PATH_PATTERN.match(live_routine_path)
  planned_match = _ROUTINE_PATH_PATTERN.match(planned_routine_path)
  if not live_match or not planned_match:
    return False
  live_proj, live_ds, live_fn = live_match.groups()
  planned_proj, planned_ds, planned_fn = planned_match.groups()
  if (live_ds, live_fn) != (planned_ds, planned_fn):
    return False
  # `GetDataPolicy` returns `data_masking_policy.routine` with the numeric
  # project number (`projects/<number>/datasets/<d>/routines/<r>`), whereas
  # `plan.json` uses the string project ID. When one side is numeric and the
  # other matches the policy's owning `target_project_id`, treat them as
  # equivalent unless `existing_policy.name` carries a different numeric ID.
  if live_proj.isdigit() and not planned_proj.isdigit():
    if target_project_id and planned_proj != target_project_id:
      return False
    if policy_project_token.isdigit() and live_proj != policy_project_token:
      return False
    return True
  if planned_proj.isdigit() and not live_proj.isdigit():
    if target_project_id and live_proj != target_project_id:
      return False
    if policy_project_token.isdigit() and planned_proj != policy_project_token:
      return False
    return True
  return False


class Creator:
  """Provisions Data Governance Tag Keys, Tag Values, and V2 Data Policies.

  Executes Phase 2a of the migration tool in strict topological order:
    1. Global Data Governance Tag Keys (`purpose = DATA_GOVERNANCE`).
    2. Global Data Governance Tag Values (ordered parent-before-child by
       hierarchy depth so parent numeric IDs exist before children are created).
    3. Regional BigQuery V2 Data Policies across three manifest categories:
       - Raw Reader Parity (`policy_tags_to_raw_reader_data_policies_v2`)
       - Default Deny Seatbelt (`policy_tags_to_default_deny_data_policies_v2`)
       - Migrated V1 Policies (`data_policies_v1_to_data_policies_v2`)
  """

  def __init__(
      self,
      dg_tag_keys_client: Any,
      dg_tag_values_client: Any,
      data_policy_v2_client: Any,
      halt_on_error: bool = False,
      dry_run: bool = False,
      skip_confirmation: bool = False,
      allow_unresolved_plan_warnings: bool = False,
  ):
    """Initializes the Creator with API clients and execution flags.

    Args:
      dg_tag_keys_client: Resource Manager TagKeysClient for listing and
        creating Data Governance Tag Keys.
      dg_tag_values_client: Resource Manager TagValuesClient for listing and
        creating hierarchical Data Governance Tag Values.
      data_policy_v2_client: BigQuery DataPolicyServiceClient for checking and
        creating regional V2 Data Policies.
      halt_on_error: Whether to stop execution and re-raise on the first error
        instead of logging and continuing with independent resources.
      dry_run: Whether to run in read-only dry-run mode (inspecting live GCP
        existence and validating payloads/quotas without mutating cloud state).
      skip_confirmation: Whether to bypass interactive confirmation prompts.
      allow_unresolved_plan_warnings: Whether to proceed when `plan.json`
        contains unresolved `[ACTION REQUIRED]` warnings instead of blocking
        upfront (`BLOCKED_UNRESOLVED_PLAN_WARNINGS`).
    """
    self._dg_tag_keys_client = dg_tag_keys_client
    self._dg_tag_values_client = dg_tag_values_client
    self._data_policy_v2_client = data_policy_v2_client
    self._rest_client = rest_utils.DataPolicyRestClient(data_policy_v2_client)
    self._halt_on_error = halt_on_error
    self._dry_run = dry_run
    self._skip_confirmation = skip_confirmation
    self._allow_unresolved_plan_warnings = allow_unresolved_plan_warnings
    # Positive lookup caches mapping namespaced_name -> numeric resource ID
    # (e.g., "my-proj/my_key" -> "tagKeys/281474976710656").
    self._dg_tag_key_cache: dict[str, str] = {}
    self._dg_tag_key_purpose_cache: dict[str, Any] = {}
    self._dg_tag_value_cache: dict[str, str] = {}
    # Negative lookup sets tracking which project IDs and parent Tag Key/Value
    # resource names have already been listed via list_tag_keys /
    # list_tag_values. Prevents O(N^2) redundant list RPCs when creating N new
    # sibling Tag Values that do not yet exist in GCP.
    self._listed_tag_key_projects: set[str] = set()
    self._listed_tag_value_parents: set[str] = set()
    # Tracks resources scheduled for creation during a --dry-run pass so child
    # Tag Values under a not-yet-created parent report WOULD_CREATE cleanly.
    self._planned_dg_tag_keys: set[str] = set()
    self._planned_dg_tag_values: set[str] = set()
    # Tracks whether V2 REST fallback warnings have already been emitted in this
    # Creator instance so batch creation of 30+ V2 Data Policies logs the SDK
    # fallback notice once at WARNING level and at DEBUG thereafter.
    self._warned_v2_rest_inspect_fallback: bool = False
    self._warned_v2_rest_create_fallback: bool = False
    # Records drift warnings when pre-existing skipped V2 Data Policies in GCP
    # differ from their planned configuration in plan.json.
    self._skipped_resource_drift_warnings: list[str] = []
    self.last_error_message: str | None = None
    self.last_report: str | None = None
    self.last_summary: dict[str, int] = {
        "succeeded": 0,
        "skipped": 0,
        "failed": 0,
    }

  def _is_non_data_governance_purpose(self, purpose: Any) -> bool:
    """Checks if a Tag Key purpose is explicitly set to non-DATA_GOVERNANCE.

    Cloud Resource Manager represents `Purpose.DATA_GOVERNANCE` as integer `2`,
    string `"DATA_GOVERNANCE"`, or an enum instance across different client
    library versions. If a pre-existing Tag Key has an explicit non-governance
    purpose (such as `0` UNSPECIFIED or `1` GCE_FIREWALL), it cannot be used
    for BigQuery Data Governance column-level security.

    Args:
      purpose: The `purpose` attribute from a TagKey protobuf or mock object.

    Returns:
      True if `purpose` is explicitly set to a value other than
      `DATA_GOVERNANCE`; False if it is `DATA_GOVERNANCE` or `None`.
    """
    if purpose is None:
      return False
    if isinstance(purpose, int) and not isinstance(purpose, bool):
      return purpose != 2
    if isinstance(purpose, str):
      return purpose not in (
          "2",
          constants.TAG_PURPOSE_DATA_GOVERNANCE,
          f"Purpose.{constants.TAG_PURPOSE_DATA_GOVERNANCE}",
      )
    purpose_name = getattr(purpose, "name", None)
    if isinstance(purpose_name, str):
      return purpose_name != constants.TAG_PURPOSE_DATA_GOVERNANCE
    return False

  def _get_dg_tag_key_id(self, namespaced_name: str) -> str | None:
    """Resolves a DG Tag Key numeric resource ID from its namespaced name.

    Design Decision (VPC-SC Compatibility & O(1) Negative Caching):
      We avoid `get_namespaced_tag_key` because it frequently fails with
      resource extraction errors (`PermissionDenied` / `NotFound`) across
      VPC-SC perimeters. Instead, we call `list_tag_keys` once per project,
      populate `_dg_tag_key_cache` for all keys in that project, and record the
      project in `_listed_tag_key_projects` so subsequent lookups for missing
      keys in the same project return `None` in O(1) without extra RPCs.

    Args:
      namespaced_name: Tag Key namespaced name (`<project_id>/<short_name>`).

    Returns:
      The Tag Key resource name (e.g., `"tagKeys/123456"`) if found, or `None`.

    Raises:
      Exception: If the `list_tag_keys` API call fails.
    """
    # === Step 1: Check positive in-memory cache ===
    if namespaced_name in self._dg_tag_key_cache:
      return self._dg_tag_key_cache[namespaced_name]

    parts = namespaced_name.split("/")
    if len(parts) == 2:
      parent_id, _ = parts
      # === Step 2: Check negative lookup set to avoid redundant list RPCs ===
      if parent_id in self._listed_tag_key_projects:
        return None

      # === Step 3: List all Tag Keys in the project and populate cache ===
      parent = f"projects/{parent_id}"
      try:
        pager = self._dg_tag_keys_client.list_tag_keys(
            parent=parent, retry=RETRY_CONFIG
        )
        for key in pager:
          # Reconstruct namespaced_name from parent_id and short_name to
          # guarantee consistency with plan.json (project ID rather than
          # project number).
          cached_namespaced_name = f"{parent_id}/{key.short_name}"
          self._dg_tag_key_cache[cached_namespaced_name] = key.name
          self._dg_tag_key_purpose_cache[cached_namespaced_name] = getattr(
              key, "purpose", None
          )
        self._listed_tag_key_projects.add(parent_id)

        if namespaced_name in self._dg_tag_key_cache:
          return self._dg_tag_key_cache[namespaced_name]
      except Exception as e:
        logger.error("Failed to list tag keys for %s: %s", parent, e)
        raise
    return None

  def _get_dg_tag_value_id(self, namespaced_name: str) -> str | None:
    """Resolves a DG Tag Value numeric resource ID from its namespaced name.

    Design Decision (Hierarchy Filtering & Negative Caching):
      1. Avoids `get_namespaced_tag_value` for VPC-SC compatibility.
      2. Resolves `parent_id` top-down via `_get_parent_id`.
      3. Checks `_listed_tag_value_parents` before calling `list_tag_values`
         so creating $N$ sibling Tag Values under the same parent issues only
         a single `list_tag_values` call instead of $O(N)$ calls.
      4. Filters `tag_value.parent == parent_id` because Resource Manager's
         `list_tag_values` under a Tag Key can return nested descendants at
         deeper hierarchy levels that happen to share the same `short_name`.

    Args:
      namespaced_name: Tag Value namespaced path
        (`<project_id>/<key_short_name>/<value_short_name>[/<child>...]`).

    Returns:
      The Tag Value resource name (e.g., `"tagValues/456789"`) if found, or
      `None`.

    Raises:
      ValueError: If `namespaced_name` has fewer than 3 slash-separated parts.
      Exception: If the `list_tag_values` API call fails.
    """
    # === Step 1: Check positive in-memory cache ===
    if namespaced_name in self._dg_tag_value_cache:
      return self._dg_tag_value_cache[namespaced_name]

    # === Step 2: Validate path structure and resolve parent resource ID ===
    parts = namespaced_name.split("/")
    if len(parts) < 3:
      raise ValueError(
          f"Invalid namespaced name for DG Tag Value: '{namespaced_name}'."
          " Expected at least 3 parts separated by '/', but found"
          f" {len(parts)}. Format should be"
          " '{project_id}/{tag_key_short_name}/{tag_value_short_name}'."
      )

    parent_namespaced_name = "/".join(parts[:-1])
    parent_id = self._get_parent_id(parent_namespaced_name)
    if parent_id:
      # === Step 3: Check negative lookup set to avoid O(N^2) list RPCs ===
      if parent_id in self._listed_tag_value_parents:
        return self._dg_tag_value_cache.get(namespaced_name)

      # === Step 4: List direct child Tag Values under parent_id and cache ===
      try:
        pager = self._dg_tag_values_client.list_tag_values(
            parent=parent_id, retry=RETRY_CONFIG
        )
        for tag_value in pager:
          tag_value_parent = getattr(tag_value, "parent", None)
          if (
              isinstance(tag_value_parent, str)
              and tag_value_parent
              and tag_value_parent != parent_id
          ):
            continue
          cached_namespaced_name = (
              f"{parent_namespaced_name}/{tag_value.short_name}"
          )
          self._dg_tag_value_cache[cached_namespaced_name] = tag_value.name
        self._listed_tag_value_parents.add(parent_id)

        if namespaced_name in self._dg_tag_value_cache:
          return self._dg_tag_value_cache[namespaced_name]
      except Exception as e:
        logger.error("Failed to list tag values for %s: %s", parent_id, e)
        raise
    return None

  def _get_parent_id(self, namespaced_name: str) -> str | None:
    """Resolves a parent resource ID (Tag Key or Tag Value) by segment count.

    Args:
      namespaced_name: Either a 2-segment Tag Key path (`<project>/<key>`) or a
        3+-segment parent Tag Value path (`<project>/<key>/<val>[/...]`).

    Returns:
      The parent's numeric resource name (`tagKeys/<id>` or `tagValues/<id>`),
      or `None` if the parent does not exist.
    """
    parts = namespaced_name.split("/")
    if len(parts) == 2:
      return self._get_dg_tag_key_id(namespaced_name)
    elif len(parts) >= 3:
      return self._get_dg_tag_value_id(namespaced_name)
    return None

  def create_dg_tag_key(
      self, dg_tag_key_action: dict[str, Any]
  ) -> tuple[str | None, str]:
    """Creates a Data Governance Tag Key idempotently if it does not exist.

    Args:
      dg_tag_key_action: Action dictionary from
        `phase_2_resource_manifest.taxonomies_to_dg_tag_keys` containing
        `namespaced_name` and `api_payload`.

    Returns:
      A tuple of `(tag_key_resource_name, status_token)` where `status_token`
      is `STATUS_CREATED`, `STATUS_SKIPPED`, or `STATUS_WOULD_CREATE`.

    Raises:
      ValueError: If a pre-existing Tag Key with the same `short_name` has a
        non-`DATA_GOVERNANCE` purpose.
      Exception: If the `create_tag_key` RPC or LRO fails.
    """
    namespaced_name = dg_tag_key_action["namespaced_name"]
    project_id = constants.validate_standard_project_id(
        namespaced_name.split("/")[0], "DG Tag Key project_id"
    )

    # === Step 1: Check if the Tag Key already exists in live GCP ===
    existing_id = self._get_dg_tag_key_id(namespaced_name)
    if existing_id:
      existing_purpose = self._dg_tag_key_purpose_cache.get(namespaced_name)
      if self._is_non_data_governance_purpose(existing_purpose):
        formatted_purpose = _format_tag_key_purpose(existing_purpose)
        raise ValueError(
            f"Tag Key '{namespaced_name}' ({existing_id}) already exists in"
            f" project '{project_id}' with non-DATA_GOVERNANCE purpose"
            f" '{formatted_purpose}'. Cannot use a standard IAM Tag Key for"
            " BigQuery Data Governance."
        )
      logger.info(
          "DG Tag Key %s already exists: %s", namespaced_name, existing_id
      )
      return existing_id, constants.STATUS_SKIPPED

    # === Step 2: Handle read-only dry-run mode ===
    if self._dry_run:
      dry_run_id = f"tagKeys/<dry-run:{namespaced_name}>"
      self._planned_dg_tag_keys.add(namespaced_name)
      self._dg_tag_key_cache[namespaced_name] = dry_run_id
      self._dg_tag_key_purpose_cache[namespaced_name] = 2
      self._listed_tag_value_parents.add(dry_run_id)
      logger.info(
          "[DRY RUN] Would create DG Tag Key: %s in project: %s",
          namespaced_name,
          project_id,
      )
      return (
          dry_run_id,
          constants.STATUS_WOULD_CREATE,
      )

    # === Step 3: Normalize payload purpose enum for SDK compatibility ===
    payload = copy.deepcopy(dg_tag_key_action["api_payload"])
    # Workaround for google-cloud-resourcemanager library versions that do not
    # recognize "DATA_GOVERNANCE" as a string enum label; integer 2 is accepted
    # across all protobuf descriptor versions.
    if payload.get("purpose") == constants.TAG_PURPOSE_DATA_GOVERNANCE:
      payload["purpose"] = 2

    # === Step 4: Create the Tag Key, await LRO, and update caches ===
    logger.info(
        "Creating DG Tag Key: %s in project: %s",
        namespaced_name,
        project_id,
    )
    try:
      operation = self._dg_tag_keys_client.create_tag_key(
          tag_key=payload, retry=RETRY_CONFIG
      )
      result = operation.result()
      self._dg_tag_key_cache[namespaced_name] = result.name
      self._dg_tag_key_purpose_cache[namespaced_name] = 2
      # A newly created Tag Key has zero child Tag Values in GCP; marking it as
      # already listed avoids an unnecessary list_tag_values RPC on its first
      # child Tag Value creation.
      self._listed_tag_value_parents.add(result.name)
      logger.info(
          "Created DG Tag Key %s: %s in project: %s",
          namespaced_name,
          result.name,
          project_id,
      )
      return result.name, constants.STATUS_CREATED
    except exceptions.AlreadyExists:
      logger.warning(
          "DG Tag Key %s already exists (race condition?)", namespaced_name
      )
      self._listed_tag_key_projects.discard(project_id)
      return self._get_dg_tag_key_id(namespaced_name), constants.STATUS_SKIPPED
    except Exception as e:
      logger.error("Failed to create DG Tag Key %s: %s", namespaced_name, e)
      if "organization" in str(e).lower():
        logger.error(
            "Google Cloud Data Governance Tags require participating projects"
            " to belong to a Google Cloud Organization resource (project"
            " '%s'); organizationless projects are not supported.",
            project_id,
        )
      raise

  def create_dg_tag_value(
      self, dg_tag_value_action: dict[str, Any]
  ) -> tuple[str | None, str]:
    """Creates a Data Governance Tag Value idempotently if it does not exist.

    Args:
      dg_tag_value_action: Action dictionary from
        `phase_2_resource_manifest.policy_tags_to_dg_tag_values` containing
        `namespaced_name`, `parent_namespaced_name`, and `api_payload`.

    Returns:
      A tuple of `(tag_value_resource_name, status_token)` where `status_token`
      is `STATUS_CREATED`, `STATUS_SKIPPED`, or `STATUS_WOULD_CREATE`.

    Raises:
      ValueError: If the parent Tag Key or parent Tag Value does not exist.
      Exception: If the `create_tag_value` RPC or LRO fails.
    """
    namespaced_name = dg_tag_value_action["namespaced_name"]
    project_id = constants.validate_standard_project_id(
        namespaced_name.split("/")[0], "DG Tag Value project_id"
    )
    parent_namespaced_name = dg_tag_value_action.get(
        "parent_namespaced_name", "/".join(namespaced_name.split("/")[:-1])
    )

    # === Step 1: Short-circuit dry-run when parent is also planned ===
    # If the parent Tag Key or parent Tag Value does not exist in GCP yet and
    # was scheduled for creation earlier in this same dry-run pass, this child
    # Tag Value cannot exist in GCP either.
    if self._dry_run and (
        parent_namespaced_name in self._planned_dg_tag_keys
        or parent_namespaced_name in self._planned_dg_tag_values
    ):
      dry_run_id = f"tagValues/<dry-run:{namespaced_name}>"
      self._planned_dg_tag_values.add(namespaced_name)
      self._dg_tag_value_cache[namespaced_name] = dry_run_id
      self._listed_tag_value_parents.add(dry_run_id)
      logger.info(
          "[DRY RUN] Would create DG Tag Value: %s in project: %s (under"
          " planned parent %s)",
          namespaced_name,
          project_id,
          parent_namespaced_name,
      )
      return (
          dry_run_id,
          constants.STATUS_WOULD_CREATE,
      )

    # === Step 2: Check if the Tag Value already exists in live GCP ===
    existing_id = self._get_dg_tag_value_id(namespaced_name)
    if existing_id:
      logger.info(
          "DG Tag Value %s already exists: %s", namespaced_name, existing_id
      )
      return existing_id, constants.STATUS_SKIPPED

    # === Step 3: Dynamically resolve the parent's numeric resource ID ===
    # In plan.json, the Planner records `parent_namespaced_name` because the
    # parent Tag Key or parent Tag Value numeric ID (e.g., "tagKeys/12345") is
    # assigned by GCP at creation time. We resolve it from cache or live GCP.
    parent_id = self._get_parent_id(parent_namespaced_name)
    if not parent_id:
      logger.error(
          "Parent %s not found for DG Tag Value %s",
          parent_namespaced_name,
          namespaced_name,
      )
      raise ValueError(f"Parent {parent_namespaced_name} not found")

    # === Step 4: Handle dry-run when parent already exists in live GCP ===
    if self._dry_run:
      dry_run_id = f"tagValues/<dry-run:{namespaced_name}>"
      self._planned_dg_tag_values.add(namespaced_name)
      self._dg_tag_value_cache[namespaced_name] = dry_run_id
      self._listed_tag_value_parents.add(dry_run_id)
      logger.info(
          "[DRY RUN] Would create DG Tag Value: %s in project: %s",
          namespaced_name,
          project_id,
      )
      return (
          dry_run_id,
          constants.STATUS_WOULD_CREATE,
      )

    # === Step 5: Create the Tag Value, await LRO, and update caches ===
    payload = copy.deepcopy(dg_tag_value_action["api_payload"])
    payload["parent"] = parent_id

    logger.info(
        "Creating DG Tag Value: %s in project: %s",
        namespaced_name,
        project_id,
    )
    try:
      operation = self._dg_tag_values_client.create_tag_value(
          tag_value=payload, retry=RETRY_CONFIG
      )
      result = operation.result()
      self._dg_tag_value_cache[namespaced_name] = result.name
      # A newly created Tag Value has zero child Tag Values in GCP; marking it
      # as already listed avoids an unnecessary list_tag_values RPC if child
      # Tag Values are created under it in the same run.
      self._listed_tag_value_parents.add(result.name)
      logger.info(
          "Created DG Tag Value %s: %s in project: %s",
          namespaced_name,
          result.name,
          project_id,
      )
      return result.name, constants.STATUS_CREATED
    except exceptions.AlreadyExists as exists_error:
      # Resource Manager enforces Tag Value `short_name` uniqueness across the
      # entire parent Tag Key (not only within a single parent Tag Value). Re-
      # lookup `namespaced_name` under `parent_id`: if still absent, another Tag
      # Value with the same `short_name` exists under a different parent in the
      # Tag Key, so fail closed instead of returning `(None, STATUS_SKIPPED)`.
      self._listed_tag_value_parents.discard(parent_id)
      resolved_id = self._get_dg_tag_value_id(namespaced_name)
      if not resolved_id:
        short_name = payload.get("short_name", namespaced_name.split("/")[-1])
        tag_key_name = "/".join(namespaced_name.split("/")[:2])
        conflict_error = (
            f"Cannot create DG Tag Value '{namespaced_name}': Resource Manager"
            f" requires Tag Value short_name '{short_name}' to be unique"
            f" across the entire Tag Key '{tag_key_name}', and another Tag"
            " Value with that short_name already exists under a different"
            " parent."
        )
        logger.error("%s", conflict_error)
        raise exceptions.AlreadyExists(conflict_error) from exists_error
      logger.warning(
          "DG Tag Value %s already exists (race condition?)", namespaced_name
      )
      return (
          resolved_id,
          constants.STATUS_SKIPPED,
      )
    except Exception as e:
      logger.error("Failed to create DG Tag Value %s: %s", namespaced_name, e)
      raise

  def _get_datapolicy_endpoint(self) -> str:
    """Determines the BigQuery Data Policy API endpoint URL.

    Inspects `self._data_policy_v2_client.transport.host` via
    `rest_utils.resolve_datapolicy_endpoint` so custom VPC-SC or regional
    endpoints configured on the GAPIC client are honored by raw REST fallback
    requests.

    Returns:
      The base HTTPS endpoint URL without a trailing slash.
    """
    return rest_utils.resolve_datapolicy_endpoint(self._data_policy_v2_client)

  def _get_data_policy_v2_rest(
      self, policy_resource_name: str
  ) -> dict[str, Any] | None:
    """Fetches a V2 Data Policy via raw REST GET when the GAPIC client fails.

    Delegates to `DataPolicyRestClient.get_data_policy_v2` (`rest_utils.py`) so
    Application Default Credentials tokens are cached across sequential policy
    inspections and HTTP 404 returns `None`.

    Args:
      policy_resource_name: Full resource name
        (`projects/{project}/locations/{region}/dataPolicies/{policy_id}`).

    Returns:
      The parsed JSON dictionary if the policy exists (HTTP 200), or `None` if
      the policy does not exist (HTTP 404).

    Raises:
      RuntimeError: On non-retryable HTTP errors or exhausted retry attempts.
    """
    self._rest_client.set_data_policy_client(self._data_policy_v2_client)
    return self._rest_client.get_data_policy_v2(
        policy_resource_name, not_found_behavior="return_none"
    )

  def _create_data_policy_v2_rest(
      self, parent: str, policy_id: str, payload: dict[str, Any]
  ) -> dict[str, Any]:
    """Creates a V2 Data Policy using the raw `/v2/` REST API with retries.

    Delegates camelCase wire translation, ADC bearer-token caching, and
    exponential backoff retry handling to
    `DataPolicyRestClient.create_data_policy_v2` (`rest_utils.py`).

    Args:
      parent: Regional parent path (`projects/{project}/locations/{region}`).
      policy_id: Target `data_policy_id` (`1-200` alphanumeric/underscore
        characters).
      payload: The `api_payload` dictionary from `plan.json`.

    Returns:
      The parsed JSON response dictionary representing the created Data Policy.

    Raises:
      exceptions.AlreadyExists: If the REST API returns HTTP 409 Conflict.
      RuntimeError: On non-retryable HTTP/network errors or exhausted retries.
    """
    self._rest_client.set_data_policy_client(self._data_policy_v2_client)
    return self._rest_client.create_data_policy_v2(
        parent=parent, policy_id=policy_id, snake_case_payload=payload
    )

  def _check_skipped_data_policy_v2_drift(
      self,
      policy_label: str,
      expected_payload: dict[str, Any],
      existing_policy: Any,
      is_rest: bool,
  ) -> None:
    """Checks if a skipped pre-existing V2 Data Policy differs from plan.json.

    When `create_data_policy_v2` skips a pre-existing V2 Data Policy in Google
    Cloud (`STATUS_SKIPPED`), this helper compares any explicit live fields on
    `existing_policy` (`data_policy_type`, `data_governance_tag`,
    `data_masking_policy`, and `grantees`) against `expected_payload`. If a
    mismatch is found (such as a pre-existing policy pointing to a different
    custom masking routine or masking expression), it logs a warning and
    records a drift entry in `_skipped_resource_drift_warnings` so the final
    creation report's `### Potential Issues & Warnings` section alerts the
    operator.

    Args:
      policy_label: Project-qualified policy label
        (`<target_project_id>/<policy_id>`).
      expected_payload: Planned `api_payload` dictionary from `plan.json`.
      existing_policy: Live V2 Data Policy protobuf message or REST JSON dict.
      is_rest: True if `existing_policy` is a REST JSON dictionary.
    """
    (
        existing_policy_name,
        actual_type,
        actual_tag_key,
        actual_tag_value,
        actual_predefined,
        actual_routine,
        actual_grantees,
    ) = _extract_live_data_policy_v2_fields(existing_policy, is_rest)

    target_proj = policy_label.split("/", 1)[0] if "/" in policy_label else ""
    policy_name_parts = existing_policy_name.split("/")
    policy_proj_token = (
        policy_name_parts[1]
        if len(policy_name_parts) >= 2 and policy_name_parts[0] == "projects"
        else ""
    )

    mismatches: list[str] = []
    expected_type = expected_payload.get(
        "data_policy_type"
    ) or expected_payload.get("dataPolicyType")
    if (
        isinstance(expected_type, str)
        and expected_type
        and actual_type
        and actual_type != expected_type
    ):
      mismatches.append(
          f"data_policy_type (live='{actual_type}', planned='{expected_type}')"
      )

    expected_dg_tag = (
        expected_payload.get("data_governance_tag")
        or expected_payload.get("dataGovernanceTag")
        or {}
    )
    if isinstance(expected_dg_tag, dict):
      expected_key = expected_dg_tag.get("key")
      if isinstance(expected_key, str) and expected_key:
        same_proj_numeric_key = (
            "/" in expected_key
            and bool(target_proj)
            and expected_key.split("/", 1)[0] == target_proj
            and policy_proj_token.isdigit()
            and actual_tag_key
            == f"{policy_proj_token}/{expected_key.split('/', 1)[1]}"
        )
        if not actual_tag_key or (
            actual_tag_key != expected_key
            and not actual_tag_key.endswith(f"/{expected_key}")
            and not same_proj_numeric_key
        ):
          live_key_display = actual_tag_key or "<none>"
          mismatches.append(
              f"data_governance_tag.key (live='{live_key_display}',"
              f" planned='{expected_key}')"
          )
      expected_val = expected_dg_tag.get("value")
      if isinstance(expected_val, str) and expected_val:
        same_proj_numeric_val = (
            "/" in expected_val
            and bool(target_proj)
            and expected_val.split("/", 1)[0] == target_proj
            and policy_proj_token.isdigit()
            and actual_tag_value
            == f"{policy_proj_token}/{expected_val.split('/', 1)[1]}"
        )
        if not actual_tag_value or (
            actual_tag_value != expected_val
            and not actual_tag_value.endswith(f"/{expected_val}")
            and not same_proj_numeric_val
        ):
          live_val_display = actual_tag_value or "<none>"
          mismatches.append(
              f"data_governance_tag.value (live='{live_val_display}',"
              f" planned='{expected_val}')"
          )

    expected_masking = (
        expected_payload.get("data_masking_policy")
        or expected_payload.get("dataMaskingPolicy")
        or {}
    )
    if isinstance(expected_masking, dict):
      expected_predefined = expected_masking.get(
          "predefined_expression"
      ) or expected_masking.get("predefinedExpression")
      expected_routine = expected_masking.get("routine")
      if (
          isinstance(expected_predefined, str)
          and expected_predefined
          and actual_predefined
          and actual_predefined != expected_predefined
      ):
        mismatches.append(
            "data_masking_policy.predefined_expression"
            f" (live='{actual_predefined}', planned='{expected_predefined}')"
        )
      if (
          isinstance(expected_routine, str)
          and expected_routine
          and actual_routine
          and not _routines_match(
              actual_routine,
              expected_routine,
              target_proj,
              policy_proj_token,
          )
      ):
        mismatches.append(
            f"data_masking_policy.routine (live='{actual_routine}',"
            f" planned='{expected_routine}')"
        )
      if (
          isinstance(expected_predefined, str)
          and expected_predefined
          and actual_routine
          and not actual_predefined
      ):
        mismatches.append(
            f"data_masking_policy (live routine='{actual_routine}',"
            f" planned predefined_expression='{expected_predefined}')"
        )
      if (
          isinstance(expected_routine, str)
          and expected_routine
          and actual_predefined
          and not actual_routine
      ):
        mismatches.append(
            "data_masking_policy (live"
            f" predefined_expression='{actual_predefined}', planned"
            f" routine='{expected_routine}')"
        )

    expected_grantees = expected_payload.get("grantees")
    if isinstance(expected_grantees, list) and actual_grantees is not None:
      grantee_drift = _format_grantee_drift_mismatch(
          actual_grantees, expected_grantees
      )
      if grantee_drift:
        mismatches.append(grantee_drift)

    if mismatches:
      drift_warning = (
          f"Skipped pre-existing Data Policy V2 '{policy_label}' in Google"
          f" Cloud differs from plan.json on: {'; '.join(mismatches)}."
      )
      logger.warning("%s", drift_warning)
      if drift_warning not in self._skipped_resource_drift_warnings:
        self._skipped_resource_drift_warnings.append(drift_warning)

  def create_data_policy_v2(
      self, data_policy_v2_action: dict[str, Any]
  ) -> tuple[str | None, str]:
    """Creates a BigQuery V2 Data Policy idempotently if it does not exist.

    Supports all three V2 Data Policy manifest categories generated by Phase 1b:
      1. Raw Reader Parity (`RAW_DATA_ACCESS_POLICY` with `grantees` migrated
         from legacy `roles/datacatalog.categoryFineGrainedReader`).
      2. Default Deny Seatbelt (`RAW_DATA_ACCESS_POLICY` with `grantees: []`
         and suffix `_default_deny` preserving Fail-Closed semantics).
      3. Migrated V1 Policies (`DATA_MASKING_POLICY` or `RAW_DATA_ACCESS_POLICY`
         with inline `grantees`).

    Args:
      data_policy_v2_action: Action dictionary from `phase_2_resource_manifest`
        containing `policy_id`, `region`, `target_project_id`, and
        `api_payload`.

    Returns:
      A tuple of `(policy_resource_name, status_token)` where `status_token` is
      `STATUS_CREATED`, `STATUS_SKIPPED`, or `STATUS_WOULD_CREATE`.

    Raises:
      ValueError: If `target_project_id` is missing from the action dictionary.
      Exception: If both the GAPIC client and REST fallback fail.
    """
    # === Step 1: Extract and validate target project, region, and payload ===
    policy_id = data_policy_v2_action["policy_id"]
    region = data_policy_v2_action["region"]
    payload = data_policy_v2_action["api_payload"]

    target_project_id = data_policy_v2_action.get("target_project_id")
    if not target_project_id:
      raise ValueError(
          f"Missing 'target_project_id' for Data Policy {policy_id}. Please"
          " generate a new migration plan with explicit target_project_id."
      )
    project_id = constants.validate_standard_project_id(
        target_project_id, "target_project_id"
    )

    parent = f"projects/{project_id}/locations/{region}"
    policy_name = f"{parent}/dataPolicies/{policy_id}"

    # === Step 2: Check live existence via GAPIC client (with REST fallback) ===
    policy_label = f"{project_id}/{policy_id}"
    try:
      try:
        existing_policy = self._data_policy_v2_client.get_data_policy(
            name=policy_name, retry=RETRY_CONFIG
        )
        # When `bigquery_datapolicies_v2` is aliased to V1 (or an older SDK
        # wheel is installed), the returned proto-plus message lacks V2 fields
        # (`grantees` / `data_governance_tag`). Fall back to `/v2/` REST GET so
        # pre-existing policy drift is inspected against full V2 metadata.
        if not hasattr(existing_policy, "grantees") or not hasattr(
            existing_policy, "data_governance_tag"
        ):
          raise TypeError(
              "GAPIC DataPolicy response lacks V2 'grantees' or"
              " 'data_governance_tag' fields"
          )
        self._check_skipped_data_policy_v2_drift(
            policy_label=policy_label,
            expected_payload=payload,
            existing_policy=existing_policy,
            is_rest=False,
        )
        logger.info("Data Policy V2 %s already exists", policy_name)
        return policy_name, constants.STATUS_SKIPPED
      except (
          TypeError,
          ValueError,
          exceptions.InvalidArgument,
          exceptions.FailedPrecondition,
      ) as client_error:
        if not self._warned_v2_rest_inspect_fallback:
          logger.warning(
              "Falling back to V2 REST API to inspect Data Policy %s: %s",
              policy_name,
              client_error,
          )
          self._warned_v2_rest_inspect_fallback = True
        else:
          logger.debug(
              "Falling back to V2 REST API to inspect Data Policy %s: %s",
              policy_name,
              client_error,
          )
        rest_policy = self._get_data_policy_v2_rest(policy_name)
        if rest_policy is not None:
          self._check_skipped_data_policy_v2_drift(
              policy_label=policy_label,
              expected_payload=payload,
              existing_policy=rest_policy,
              is_rest=True,
          )
          logger.info("Data Policy V2 %s already exists", policy_name)
          return policy_name, constants.STATUS_SKIPPED
    except exceptions.NotFound:
      pass

    # === Step 3: Handle read-only dry-run mode ===
    if self._dry_run:
      logger.info(
          "[DRY RUN] Would create Data Policy V2: %s in project: %s"
          " (region: %s)",
          policy_name,
          project_id,
          region,
      )
      return policy_name, constants.STATUS_WOULD_CREATE

    # === Step 4: Create V2 Data Policy via GAPIC (falling back to REST v2) ===
    logger.info(
        "Creating Data Policy V2: %s in project: %s (region: %s)",
        policy_name,
        project_id,
        region,
    )

    try:
      result = self._data_policy_v2_client.create_data_policy(
          request={
              "parent": parent,
              "data_policy_id": policy_id,
              "data_policy": payload,
          },
          retry=RETRY_CONFIG,
      )
      logger.info(
          "Created Data Policy V2 %s in project: %s (region: %s)",
          policy_name,
          project_id,
          region,
      )
      return result.name, constants.STATUS_CREATED

    except exceptions.AlreadyExists:
      logger.warning(
          "Data Policy V2 %s already exists (race condition?)", policy_name
      )
      return policy_name, constants.STATUS_SKIPPED

    except Exception as e:  # pylint: disable=broad-exception-caught
      # Fallback to raw REST /v2/ when the installed SDK wheel lacks the V2
      # `data_governance_tag` protobuf field or connects to the V1 endpoint,
      # raising TypeError, ValueError, or InvalidArgument.
      has_dg_tag = (
          "data_governance_tag" in payload or "dataGovernanceTag" in payload
      )
      if (
          isinstance(
              e,
              (
                  TypeError,
                  ValueError,
                  exceptions.InvalidArgument,
              ),
          )
          or "Unknown field" in str(e)
      ) and has_dg_tag:
        if not self._warned_v2_rest_create_fallback:
          logger.warning(
              "Local client library lacks 'data_governance_tag' support (likely"
              " outdated version). Falling back to raw REST/HTTP API to bypass"
              " SDK validation."
          )
          self._warned_v2_rest_create_fallback = True
        else:
          logger.debug(
              "Local client library lacks 'data_governance_tag' support."
              " Falling back to raw REST/HTTP API for Data Policy %s.",
              policy_name,
          )
        try:
          response_data = self._create_data_policy_v2_rest(
              parent=parent, policy_id=policy_id, payload=payload
          )
          logger.info(
              "Created Data Policy V2 %s via REST in project: %s (region: %s)",
              policy_name,
              project_id,
              region,
          )
          return response_data.get("name"), constants.STATUS_CREATED
        except exceptions.AlreadyExists:
          logger.warning(
              "Data Policy V2 %s already exists (REST Conflict)", policy_name
          )
          return policy_name, constants.STATUS_SKIPPED
        except Exception as fallback_error:
          logger.error("REST fallback failed: %s", fallback_error)
          if "organization" in str(fallback_error).lower():
            logger.error(
                "BigQuery V2 Data Policies require participating projects to"
                " belong to a Google Cloud Organization resource (project"
                " '%s'); organizationless projects are not supported.",
                project_id,
            )
          raise fallback_error
      else:
        logger.error("Failed to create Data Policy V2 %s: %s", policy_name, e)
        if "organization" in str(e).lower():
          logger.error(
              "BigQuery V2 Data Policies require participating projects to"
              " belong to a Google Cloud Organization resource (project"
              " '%s'); organizationless projects are not supported.",
              project_id,
          )
        raise e

  def _extract_action_resource_label(self, action: dict[str, Any]) -> str:
    """Returns the display label (`namespaced_name` or `<proj>/<policy_id>`)."""
    namespaced_name = action.get(constants.FIELD_NAMESPACED_NAME, "")
    policy_id = action.get(constants.FIELD_POLICY_ID, "")
    target_project_id = action.get(constants.FIELD_TARGET_PROJECT_ID, "")
    if namespaced_name:
      return str(namespaced_name)
    if target_project_id and policy_id:
      return f"{target_project_id}/{policy_id}"
    return str(policy_id or "")

  def _collect_action_plan_warnings(
      self, action: dict[str, Any]
  ) -> tuple[list[str], list[str]]:
    """Extracts raw and formatted plan warnings attached to a manifest action.

    Args:
      action: Single resource action dict from `phase_2_resource_manifest`.

    Returns:
      Tuple `(raw_action_warnings, formatted_warning_lines)`.
    """
    resource_label = self._extract_action_resource_label(action)
    action_warnings: list[str] = []
    raw_warnings = action.get(constants.FIELD_WARNINGS)
    if isinstance(raw_warnings, list):
      action_warnings.extend(
          str(warning_item) for warning_item in raw_warnings if warning_item
      )
    elif isinstance(raw_warnings, str) and raw_warnings:
      action_warnings.append(raw_warnings)
    single_warning = action.get(constants.FIELD_WARNING)
    if isinstance(single_warning, str) and single_warning:
      action_warnings.append(single_warning)

    formatted_warnings: list[str] = []
    # Prefix per-action plan warnings with `[<resource_label>]` so operators can
    # trace each warning in `### Potential Issues & Warnings` back to its exact
    # Tag Key, Tag Value, or project-qualified V2 Data Policy.
    for warning_message in action_warnings:
      if resource_label and resource_label not in warning_message:
        formatted_warnings.append(
            f"[{resource_label}] Plan warning: {warning_message}"
        )
      else:
        formatted_warnings.append(f"Plan warning: {warning_message}")
    return action_warnings, formatted_warnings

  def _collect_action_hard_validation_errors(
      self,
      action: dict[str, Any],
      resource_type: str,
      *,
      suppress_from_warnings: list[str] | None = None,
      include_resource_prefix: bool = False,
  ) -> list[str]:
    """Detects deterministic API contract violations on a single plan action.

    Evaluates hard Google Cloud Resource Manager and BigQuery Data Policy V2
    limits locally so hand-edited `plan.json` files (including those with
    `[ACTION REQUIRED]` warnings stripped) fail `--dry-run` pre-flight checks
    with exit code `1` rather than silently reporting `Failed / Blocked: 0`.

    Args:
      action: Single resource action dict from `phase_2_resource_manifest`.
      resource_type: Resource type constant (`RESOURCE_TYPE_DG_TAG_KEY`,
        `RESOURCE_TYPE_DG_TAG_VALUE`, or `RESOURCE_TYPE_DATA_POLICY_V2`).
      suppress_from_warnings: Optional list of Phase 1b `action_warnings` used
        by `_collect_action_validation_issues` to avoid duplicating warnings
        already emitted by `Planner`. Leave `None` for fail-closed dry-run
        blocker gating.
      include_resource_prefix: When True, prefixes each message with the
        resource type and identifier (used by
        `_collect_action_validation_issues` for flat warning lists). When False,
        omits the redundant prefix because `### Failed Pre-Flight Checks /
        Blockers` already keys bullets by resource identifier.

    Returns:
      List of deterministic API validation failure strings.
    """
    errors: list[str] = []
    namespaced_name = action.get(constants.FIELD_NAMESPACED_NAME, "")
    policy_id = action.get(constants.FIELD_POLICY_ID, "")
    target_project_id = action.get(constants.FIELD_TARGET_PROJECT_ID, "")
    resource_label = self._extract_action_resource_label(action)
    action_warnings = suppress_from_warnings or []
    payload = action.get(constants.FIELD_API_PAYLOAD, {}) or {}

    if resource_type in (
        constants.RESOURCE_TYPE_DG_TAG_KEY,
        constants.RESOURCE_TYPE_DG_TAG_VALUE,
    ):
      label = (
          "DG Tag Key"
          if resource_type == constants.RESOURCE_TYPE_DG_TAG_KEY
          else "DG Tag Value"
      )
      prefix = (
          f"{label} '{namespaced_name}': " if include_resource_prefix else ""
      )
      has_short_name = "short_name" in payload
      short_name = payload.get("short_name", "")
      if (has_short_name or payload) and (
          not isinstance(short_name, str)
          or not re.search(
              r"^[a-zA-Z0-9]([a-zA-Z0-9._-]{0,61}[a-zA-Z0-9])?$", short_name
          )
      ):
        errors.append(
            f"{prefix}short_name '{short_name}' does not meet Resource Manager"
            " naming constraints (1-63 chars, starting/ending with"
            " alphanumeric)."
        )
      description = payload.get("description", "")
      if (
          isinstance(description, str)
          and len(description) > constants.MAX_TAG_DESCRIPTION_LENGTH
      ):
        errors.append(
            f"{prefix}description length ({len(description)}) exceeds the"
            f" {constants.MAX_TAG_DESCRIPTION_LENGTH}-character Resource"
            " Manager limit."
        )
    elif resource_type == constants.RESOURCE_TYPE_DATA_POLICY_V2:
      policy_label = resource_label or policy_id
      prefix = (
          f"Data Policy V2 '{policy_label}': "
          if include_resource_prefix
          else ""
      )
      if constants.FIELD_POLICY_ID in action and (
          not isinstance(policy_id, str)
          or not re.search(r"^[a-zA-Z0-9_]{1,200}$", policy_id)
      ):
        errors.append(
            f"{prefix}policy_id must contain only letters, numbers, and"
            " underscores (<= 200 characters)."
        )
      data_policy_type = str(
          payload.get("data_policy_type") or payload.get("dataPolicyType") or ""
      ).strip()
      masking_policy = (
          payload.get("data_masking_policy")
          or payload.get("dataMaskingPolicy")
          or {}
      )
      if data_policy_type == constants.DATA_POLICY_TYPE_MASKING:
        has_predefined = isinstance(masking_policy, dict) and bool(
            str(
                masking_policy.get("predefined_expression")
                or masking_policy.get("predefinedExpression")
                or ""
            ).strip()
        )
        has_routine = isinstance(masking_policy, dict) and bool(
            str(masking_policy.get("routine") or "").strip()
        )
        if not has_predefined and not has_routine:
          errors.append(
              f"{prefix}DATA_MASKING_POLICY requires a non-empty"
              " data_masking_policy (either predefined_expression or routine)."
          )
      if isinstance(masking_policy, dict):
        routine_str = str(masking_policy.get("routine", ""))
        if "<unknown-project-" in routine_str:
          errors.append(
              f"{prefix}data_masking_policy.routine contains an unresolved"
              " '<unknown-project-...>' placeholder that must be replaced with"
              " the routine's actual project ID."
          )
        elif routine_str:
          # BigQuery Data Policy Service V2 rejects Data Policies whose
          # `data_masking_policy.routine` project differs from the Data Policy's
          # parent project (`All referenced resources must reside in the same
          # project.`).
          has_existing_routine_warning = any(
              routine_str in warning_item
              or "custom masking routine" in warning_item.lower()
              for warning_item in action_warnings
          )
          routine_parts = routine_str.split("/")
          if (
              not has_existing_routine_warning
              and len(routine_parts) == 6
              and routine_parts[0] == "projects"
              and routine_parts[2] == "datasets"
              and routine_parts[4] == "routines"
              and target_project_id
              and routine_parts[1] != target_project_id
          ):
            errors.append(
                f"{prefix}data_masking_policy.routine '{routine_str}' resides"
                f" in project '{routine_parts[1]}', which differs from target"
                f" Data Policy project '{target_project_id}'. BigQuery Data"
                " Policy Service requires custom masking routines to reside"
                " in the same project as the Data Policy."
            )

      raw_grantees = payload.get("grantees")
      if isinstance(raw_grantees, list):
        distinct_iam_principals: set[str] = set()
        distinct_group_principals: set[str] = set()
        for raw_grantee in raw_grantees:
          grantee_str = str(raw_grantee or "")
          if not grantee_str:
            continue
          if grantee_str.startswith("deleted:"):
            has_deleted_warning = any(
                grantee_str in warning_item
                or "deleted:" in warning_item.lower()
                for warning_item in action_warnings
            )
            if not has_deleted_warning:
              errors.append(
                  f"{prefix}grantee '{grantee_str}' is a deleted principal"
                  " tombstone, which is rejected by BigQuery V2 Data Policies."
              )
          elif grantee_str.startswith("domain:"):
            has_domain_warning = any(
                grantee_str in warning_item or "domain:" in warning_item.lower()
                for warning_item in action_warnings
            )
            if not has_domain_warning:
              errors.append(
                  f"{prefix}grantee '{grantee_str}' uses unsupported Workspace"
                  " 'domain:' notation; replace with a Google Group"
                  " ('principalSet://goog/group/...') before creation."
              )
          elif grantee_str in ("allUsers", "allAuthenticatedUsers"):
            has_public_warning = any(
                grantee_str in warning_item for warning_item in action_warnings
            )
            if not has_public_warning:
              errors.append(
                  f"{prefix}grantee '{grantee_str}' is a public principal,"
                  " which is not supported in V2 Data Policy grantees."
              )
          elif "/routines/" in grantee_str:
            has_routine_grantee_warning = any(
                grantee_str in warning_item
                or "authorized routine" in warning_item.lower()
                for warning_item in action_warnings
            )
            if not has_routine_grantee_warning:
              errors.append(
                  f"{prefix}grantee '{grantee_str}' is a BigQuery Authorized"
                  " Routine principal, which is not supported in V2 Data Policy"
                  " grantees."
              )
          elif (
              grantee_str.startswith(("principal://", "principalSet://"))
              and "/datasets/" not in grantee_str
              and "/views/" not in grantee_str
          ):
            distinct_iam_principals.add(grantee_str)
            if grantee_str.startswith("principalSet://"):
              distinct_group_principals.add(grantee_str)

        has_iam_count_warning = any(
            "distinct iam principals" in warning_item.lower()
            for warning_item in action_warnings
        )
        if (
            not has_iam_count_warning
            and len(distinct_iam_principals)
            > constants.MAX_GRANTEES_PER_DATA_POLICY_V2
        ):
          errors.append(
              f"Quota Limit Exceeded: Data Policy V2 '{policy_label}' has"
              f" {len(distinct_iam_principals)} distinct IAM principals,"
              " exceeding BigQuery's limit of"
              f" {constants.MAX_GRANTEES_PER_DATA_POLICY_V2} IAM principals"
              " per V2 Data Policy."
          )

        has_group_count_warning = any(
            "principalset:// groups" in warning_item.lower()
            for warning_item in action_warnings
        )
        if (
            not has_group_count_warning
            and len(distinct_group_principals)
            > constants.MAX_GROUP_GRANTEES_PER_DATA_POLICY_V2
        ):
          errors.append(
              f"Quota Limit Exceeded: Data Policy V2 '{policy_label}' has"
              f" {len(distinct_group_principals)} distinct principalSet://"
              " groups, exceeding BigQuery's limit of"
              f" {constants.MAX_GROUP_GRANTEES_PER_DATA_POLICY_V2} groups per"
              " V2 Data Policy."
          )

    return errors

  def _collect_action_validation_issues(
      self,
      action: dict[str, Any],
      resource_type: str,
  ) -> list[str]:
    """Validates a single manifest action for naming, length, and placeholders.

    Checks Resource Manager and BigQuery Data Policy V2 constraints locally
    (especially during `--dry-run`) so customers can fix manual `plan.json`
    edits before running live mutations:
      - Tag Key / Value `short_name`: 1-63 chars, starts/ends with alphanumeric.
      - Tag Key / Value `description`: <= 256 characters.
      - V2 `policy_id`: 1-200 alphanumeric or underscore characters.
      - Custom masking `routine`: flags unresolved `<unknown-project-...>`
        placeholders and cross-project routine references (`routine` project
        differing from `target_project_id`).

    Args:
      action: Single resource action dict from `phase_2_resource_manifest`.
      resource_type: Resource type constant (`RESOURCE_TYPE_DG_TAG_KEY`,
        `RESOURCE_TYPE_DG_TAG_VALUE`, or `RESOURCE_TYPE_DATA_POLICY_V2`).

    Returns:
      A list of human-readable validation warning/issue strings.
    """
    action_warnings, formatted_warnings = self._collect_action_plan_warnings(
        action
    )
    hard_errors = self._collect_action_hard_validation_errors(
        action,
        resource_type,
        suppress_from_warnings=action_warnings,
        include_resource_prefix=True,
    )
    return formatted_warnings + hard_errors

  def _collect_quota_blockers(self, plan: dict[str, Any]) -> list[str]:
    """Checks plan-wide Tag Key, Tag Value, and V2 Data Policy quota limits.

    Evaluates the three aggregate Google Cloud hard limits (1,000 Tag Keys per
    project combining live + planned keys, 1,000 Tag Values per Tag Key, and
    1,000 V2 Data Policies per `(target_project_id, dg_tag_key)`).

    Args:
      plan: Parsed migration plan dictionary.

    Returns:
      List of quota-exceeded blocker strings (empty when within all limits).
    """
    quota_blockers: list[str] = []
    manifest = plan.get(constants.KEY_PHASE_2_RESOURCE_MANIFEST, {})

    planned_keys_by_project: dict[str, set[str]] = {}
    for action in manifest.get(constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS, []):
      key_namespaced_name = str(
          action.get(constants.FIELD_NAMESPACED_NAME, "") or ""
      )
      if "/" in key_namespaced_name:
        key_project_id = key_namespaced_name.split("/", 1)[0]
        if key_project_id:
          planned_keys_by_project.setdefault(key_project_id, set()).add(
              key_namespaced_name
          )

    for key_project_id, planned_key_set in sorted(
        planned_keys_by_project.items()
    ):
      cached_keys_in_project = {
          cached_key
          for cached_key in self._dg_tag_key_cache
          if cached_key.startswith(f"{key_project_id}/")
      }
      combined_key_count = len(planned_key_set | cached_keys_in_project)
      if len(planned_key_set) > constants.MAX_DG_TAG_KEYS_PER_PROJECT:
        quota_blockers.append(
            f"Quota Limit Exceeded: Project '{key_project_id}' has"
            f" {len(planned_key_set)} planned DG Tag Keys, exceeding the"
            " Resource Manager limit of"
            f" {constants.MAX_DG_TAG_KEYS_PER_PROJECT} Tag Keys per project."
        )
      elif combined_key_count > constants.MAX_DG_TAG_KEYS_PER_PROJECT:
        quota_blockers.append(
            f"Quota Limit Exceeded: Project '{key_project_id}' would contain"
            f" {combined_key_count} total Tag Keys (combining pre-existing"
            " project Tag Keys and planned DG Tag Keys), exceeding the"
            " Resource Manager limit of"
            f" {constants.MAX_DG_TAG_KEYS_PER_PROJECT} Tag Keys per project."
        )

    planned_values_by_key: dict[str, set[str]] = {}
    for action in manifest.get(constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES, []):
      value_namespaced_name = str(
          action.get(constants.FIELD_NAMESPACED_NAME, "") or ""
      )
      value_parts = value_namespaced_name.split("/")
      if len(value_parts) >= 3:
        root_key_name = f"{value_parts[0]}/{value_parts[1]}"
        planned_values_by_key.setdefault(root_key_name, set()).add(
            value_namespaced_name
        )

    for root_key_name, planned_value_set in sorted(
        planned_values_by_key.items()
    ):
      cached_values_for_key = {
          cached_value
          for cached_value in self._dg_tag_value_cache
          if cached_value.startswith(f"{root_key_name}/")
      }
      combined_value_count = len(planned_value_set | cached_values_for_key)
      if len(planned_value_set) > constants.MAX_DG_TAG_VALUES_PER_TAG_KEY:
        quota_blockers.append(
            f"Quota Limit Exceeded: DG Tag Key '{root_key_name}' has"
            f" {len(planned_value_set)} planned DG Tag Values, exceeding the"
            " Resource Manager limit of"
            f" {constants.MAX_DG_TAG_VALUES_PER_TAG_KEY} Tag Values per Tag"
            " Key."
        )
      elif combined_value_count > constants.MAX_DG_TAG_VALUES_PER_TAG_KEY:
        quota_blockers.append(
            f"Quota Limit Exceeded: DG Tag Key '{root_key_name}' would contain"
            f" {combined_value_count} total Tag Values (combining pre-existing"
            " and planned Tag Values), exceeding the Resource Manager limit of"
            f" {constants.MAX_DG_TAG_VALUES_PER_TAG_KEY} Tag Values per Tag"
            " Key."
        )

    all_policy_actions = (
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
    )
    policies_per_key: dict[tuple[str, str], int] = {}
    for action in all_policy_actions:
      target_project_id = action.get(constants.FIELD_TARGET_PROJECT_ID, "")
      dg_tag_key = (
          action.get(constants.FIELD_API_PAYLOAD, {})
          .get("data_governance_tag", {})
          .get("key", "")
      )
      if target_project_id and dg_tag_key:
        pair = (target_project_id, dg_tag_key)
        policies_per_key[pair] = policies_per_key.get(pair, 0) + 1

    for (target_project_id, dg_tag_key), count in sorted(
        policies_per_key.items()
    ):
      if count > constants.MAX_DATA_POLICIES_PER_DG_TAG_KEY:
        quota_blockers.append(
            f"Quota Limit Exceeded: DG Tag Key '{dg_tag_key}' in project"
            f" '{target_project_id}' has {count} planned V2 Data Policies,"
            " exceeding the BigQuery limit of"
            f" {constants.MAX_DATA_POLICIES_PER_DG_TAG_KEY} policies per Tag"
            " Key."
        )

    return quota_blockers

  def _collect_potential_issues(
      self,
      plan: dict[str, Any],
      skipped_dg_tag_keys: set[str],
      skipped_dg_tag_values: set[str],
      skipped_data_policies_v2: set[str],
      *,
      include_hard_blockers: bool = True,
  ) -> list[str]:
    """Aggregates plan-level warnings, quota checks, and validation issues.

    Args:
      plan: Parsed migration plan dictionary.
      skipped_dg_tag_keys: Set of skipped Tag Key namespaced names.
      skipped_dg_tag_values: Set of skipped Tag Value namespaced names.
      skipped_data_policies_v2: Set of skipped V2 Data Policy identifiers.
      include_hard_blockers: When True (default, preserving direct helper
        callers), includes hard per-action and aggregate quota errors. When
        False (used by `create_all_dgt_resources` dry-run after promoting hard
        violations into `### Failed Pre-Flight Checks / Blockers`), returns only
        advisory warnings and drift notices to prevent duplicate reporting.

    Returns:
      Deduplicated list of potential issue and warning strings.
    """
    issues: list[str] = []
    seen_issues: set[str] = set()

    def add_issue(message: str) -> None:
      cleaned = " ".join(str(message).split())
      if (
          self._allow_unresolved_plan_warnings
          and constants.PLAN_WARNING_ACTION_REQUIRED_MARKER in cleaned
          and not cleaned.startswith("Overridden Plan Warning:")
      ):
        # When `--allow-unresolved-plan-warnings` is enabled, all
        # `[ACTION REQUIRED]` warnings are already seeded at the top of
        # `potential_issues` as `Overridden Plan Warning: ...` entries.
        return
      if cleaned and cleaned not in seen_issues:
        seen_issues.add(cleaned)
        issues.append(cleaned)

    for plan_warning in plan.get("warnings", []) or []:
      add_issue(f"Plan Warning: {plan_warning}")

    for drift_warning in self._skipped_resource_drift_warnings:
      add_issue(drift_warning)

    manifest = plan.get(constants.KEY_PHASE_2_RESOURCE_MANIFEST, {})
    manifest_sections = (
        (
            constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS,
            constants.RESOURCE_TYPE_DG_TAG_KEY,
        ),
        (
            constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES,
            constants.RESOURCE_TYPE_DG_TAG_VALUE,
        ),
        (
            constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2,
            constants.RESOURCE_TYPE_DATA_POLICY_V2,
        ),
        (
            constants.KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2,
            constants.RESOURCE_TYPE_DATA_POLICY_V2,
        ),
        (
            constants.KEY_DATA_POLICIES_V1_TO_DATA_POLICIES_V2,
            constants.RESOURCE_TYPE_DATA_POLICY_V2,
        ),
    )
    for section_key, resource_type in manifest_sections:
      for action in manifest.get(section_key, []):
        if include_hard_blockers:
          action_issues = self._collect_action_validation_issues(
              action, resource_type
          )
        else:
          _, action_issues = self._collect_action_plan_warnings(action)
        for issue in action_issues:
          add_issue(issue)

    if include_hard_blockers:
      for quota_blocker in self._collect_quota_blockers(plan):
        add_issue(quota_blocker)

    total_skipped = (
        len(skipped_dg_tag_keys)
        + len(skipped_dg_tag_values)
        + len(skipped_data_policies_v2)
    )
    if total_skipped > 0:
      add_issue(
          f"{total_skipped} resource(s) already exist in Google Cloud and will"
          " be skipped during creation. Verify that pre-existing resources"
          " match the expected configuration in your migration plan."
      )

    return issues

  def _collect_unresolved_plan_warnings(
      self, plan: dict[str, Any]
  ) -> list[str]:
    """Collects unresolved `[ACTION REQUIRED]` warnings across `plan.json`.

    Scans both top-level `plan["warnings"]` and per-action `warnings`/`warning`
    fields across all five `phase_2_resource_manifest` lists so `--phase create`
    fails closed before prompting or mutating Google Cloud whenever manual
    remediation in `plan.json` is still pending.

    Args:
      plan: Parsed migration plan dictionary (`plan.json`).

    Returns:
      Deduplicated list of `[ACTION REQUIRED]` warning strings in plan order.
    """
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

  def _render_blocked_plan_warnings_report(
      self,
      unresolved_warnings: list[str],
      report_file: str | None = None,
      resource_name: str | None = None,
      resource_type: str | None = None,
  ) -> str:
    """Renders and optionally saves a fail-closed report for plan warnings."""
    title = "# Data Governance Tag Resource Creation Report"
    if resource_name is not None:
      if self._dry_run:
        title += " (Individual - DRY RUN)"
      else:
        title += " (Individual)"
    elif self._dry_run:
      title += " (DRY RUN)"
    lines = [title, ""]
    if self._dry_run:
      lines.append(
          "**Dry-Run Mode:** No resources were created or modified in Google"
          " Cloud."
      )
      lines.append("")
    if resource_name is not None:
      lines.append(f"- **Resource Name:** {resource_name}")
      lines.append(f"- **Resource Type:** {resource_type}")
    lines.append(
        f"- **Status:** {constants.STATUS_BLOCKED_UNRESOLVED_PLAN_WARNINGS}"
    )
    lines.append(f"- **Unresolved Plan Warnings:** {len(unresolved_warnings)}")
    lines.append("")
    lines.append("### Blocked by Unresolved Plan Warnings ([ACTION REQUIRED])")
    for warning_item in unresolved_warnings:
      lines.append(f"- {warning_item}")
    lines.append("")
    lines.append("### Error & Failure Status Reference")
    lines.append(
        f"- **`{constants.STATUS_BLOCKED_UNRESOLVED_PLAN_WARNINGS}`:**"
        " Execution was blocked before creating or modifying any Google Cloud"
        " resources because `plan.json` still contains unresolved"
        " `[ACTION REQUIRED]` warnings from Phase 1b (`--phase plan`)."
        " Resolve the flagged items in `plan.json` (and delete their"
        " `[ACTION REQUIRED]` warning entries) or pass"
        " `--allow-unresolved-plan-warnings` to override and attempt"
        " remaining valid resources."
    )
    lines.append("")
    report_content = "\n".join(lines)
    if report_file:
      try:
        with open(report_file, "w", encoding="utf-8") as file_handle:
          file_handle.write(_ensure_trailing_newline(report_content))
        logger.info("Creation report saved to %s", report_file)
      except OSError as file_error:
        logger.error(
            "Failed to write creation report to %s: %s",
            report_file,
            file_error,
        )
    return report_content

  def _validate_and_match_data_policy_action(
      self,
      manifest: dict[str, Any],
      resource_name: str,
  ) -> dict[str, Any]:
    """Validates `<target_project_id>/<data_policy_id>` and returns action."""
    data_policy_keys = (
        constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2,
        constants.KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2,
        constants.KEY_DATA_POLICIES_V1_TO_DATA_POLICIES_V2,
    )
    parts = resource_name.split("/")
    if len(parts) != 2 or not parts[0] or not parts[1]:
      matching_examples: list[str] = []
      for category_key in data_policy_keys:
        for candidate in manifest.get(category_key, []):
          candidate_id = candidate.get(constants.FIELD_POLICY_ID, "")
          candidate_project = candidate.get(
              constants.FIELD_TARGET_PROJECT_ID, ""
          )
          if candidate_id == resource_name and candidate_project:
            example = f"'{candidate_project}/{candidate_id}'"
            if example not in matching_examples:
              matching_examples.append(example)
      examples_hint = (
          ", ".join(sorted(matching_examples))
          if matching_examples
          else "'my-target-project/my_data_policy'"
      )
      raise ValueError(
          f"Invalid Data Policy V2 resource name '{resource_name}': expected"
          " '<target_project_id>/<data_policy_id>' format in both Mode 1 and"
          f" Mode 2 (for example, {examples_hint})."
      )

    target_project_id, policy_id = parts
    for category_key in data_policy_keys:
      for candidate in manifest.get(category_key, []):
        if (
            candidate.get(constants.FIELD_TARGET_PROJECT_ID)
            == target_project_id
            and candidate.get(constants.FIELD_POLICY_ID) == policy_id
        ):
          return candidate

    raise ValueError(
        f"Resource {resource_name} of type"
        f" {constants.RESOURCE_TYPE_DATA_POLICY_V2} not found in plan"
    )

  def _generate_report(
      self,
      succeeded_dg_tag_keys: set[str],
      skipped_dg_tag_keys: set[str],
      failed_dg_tag_keys: set[str] | dict[str, str],
      succeeded_dg_tag_values: set[str],
      skipped_dg_tag_values: set[str],
      failed_dg_tag_values: set[str] | dict[str, str],
      succeeded_data_policies_v2: set[str],
      skipped_data_policies_v2: set[str],
      failed_data_policies_v2: set[str] | dict[str, str],
      potential_issues: list[str] | None = None,
      preflight_blockers: list[str] | None = None,
  ) -> str:
    """Renders a deterministic Markdown report of the Phase 2a creation run.

    Args:
      succeeded_dg_tag_keys: Created (or would-create) Tag Key names.
      skipped_dg_tag_keys: Already-existing Tag Key names.
      failed_dg_tag_keys: Failed Tag Key names (set or dict mapping to error).
      succeeded_dg_tag_values: Created (or would-create) Tag Value names.
      skipped_dg_tag_values: Already-existing Tag Value names.
      failed_dg_tag_values: Failed Tag Value names (set or dict with error).
      succeeded_data_policies_v2: Created (or would-create) V2 Policy IDs.
      skipped_data_policies_v2: Already-existing V2 Policy IDs.
      failed_data_policies_v2: Failed V2 Policy IDs (set or dict with error).
      potential_issues: Optional list of advisory warnings and drift notices.
      preflight_blockers: Optional list of plan-wide quota blocker strings
        detected during dry-run pre-flight checks.

    Returns:
      Formatted Markdown report string.
    """
    report_lines = []
    if self._dry_run:
      report_lines.append(
          "# Data Governance Tag Resource Creation Report (DRY RUN)"
      )
      report_lines.append("")
      report_lines.append(
          "**Dry-Run Mode:** No resources were created or modified in Google"
          " Cloud. Review the proposed creations and any potential issues below"
          " before re-running without `--dry-run`."
      )
    else:
      report_lines.append("# Data Governance Tag Resource Creation Report")
    report_lines.append("")
    report_lines.append("## Summary")
    created_label = "Would Create" if self._dry_run else "Succeeded"
    skipped_label = "Would Skip (Already Exist)" if self._dry_run else "Skipped"
    failed_label = "Failed / Blocked" if self._dry_run else "Failed"
    report_lines.append(
        f"- **DG Tag Keys:** {created_label}: {len(succeeded_dg_tag_keys)}, "
        f"{skipped_label}: {len(skipped_dg_tag_keys)}, "
        f"{failed_label}: {len(failed_dg_tag_keys)}"
    )
    report_lines.append(
        f"- **DG Tag Values:** {created_label}:"
        f" {len(succeeded_dg_tag_values)}, {skipped_label}:"
        f" {len(skipped_dg_tag_values)}, {failed_label}:"
        f" {len(failed_dg_tag_values)}"
    )
    report_lines.append(
        f"- **Data Policies V2:** {created_label}:"
        f" {len(succeeded_data_policies_v2)}, {skipped_label}:"
        f" {len(skipped_data_policies_v2)}, {failed_label}:"
        f" {len(failed_data_policies_v2)}"
    )
    if preflight_blockers:
      report_lines.append(
          f"- **Plan / Quota Blockers:** {len(preflight_blockers)}"
      )
    if potential_issues:
      report_lines.append(
          f"- **Potential Issues / Warnings:** {len(potential_issues)}"
      )
    report_lines.append("")
    report_lines.append("## Details")
    report_lines.append("")

    if (
        succeeded_dg_tag_keys
        or succeeded_dg_tag_values
        or succeeded_data_policies_v2
    ):
      section_header = (
          "### Resources That Would Be Created"
          if self._dry_run
          else "### Succeeded Creations"
      )
      report_lines.append(section_header)
      if succeeded_dg_tag_keys:
        report_lines.append("#### DG Tag Keys")
        for name in sorted(succeeded_dg_tag_keys):
          report_lines.append(f"- {name}")
      if succeeded_dg_tag_values:
        report_lines.append("#### DG Tag Values")
        for name in sorted(succeeded_dg_tag_values):
          report_lines.append(f"- {name}")
      if succeeded_data_policies_v2:
        report_lines.append("#### Data Policies V2")
        for policy_id in sorted(succeeded_data_policies_v2):
          report_lines.append(f"- {policy_id}")
      report_lines.append("")

    if skipped_dg_tag_keys or skipped_dg_tag_values or skipped_data_policies_v2:
      skipped_header = (
          "### Resources That Would Be Skipped (Already Exist)"
          if self._dry_run
          else "### Skipped Creations (Already Existed)"
      )
      report_lines.append(skipped_header)
      if skipped_dg_tag_keys:
        report_lines.append("#### DG Tag Keys")
        for name in sorted(skipped_dg_tag_keys):
          report_lines.append(f"- {name}")
      if skipped_dg_tag_values:
        report_lines.append("#### DG Tag Values")
        for name in sorted(skipped_dg_tag_values):
          report_lines.append(f"- {name}")
      if skipped_data_policies_v2:
        report_lines.append("#### Data Policies V2")
        for policy_id in sorted(skipped_data_policies_v2):
          report_lines.append(f"- {policy_id}")
      report_lines.append("")

    has_failures = bool(
        failed_dg_tag_keys
        or failed_dg_tag_values
        or failed_data_policies_v2
        or preflight_blockers
    )
    if has_failures:
      failed_header = (
          "### Failed Pre-Flight Checks / Blockers"
          if self._dry_run
          else "### Failed Creations"
      )
      report_lines.append(failed_header)
      if failed_dg_tag_keys:
        report_lines.append("#### DG Tag Keys")
        for name in sorted(failed_dg_tag_keys):
          error_message = (
              failed_dg_tag_keys[name]
              if isinstance(failed_dg_tag_keys, dict)
              else ""
          )
          if error_message:
            clean_error = " ".join(error_message.split())
            report_lines.append(f"- {name}: {clean_error}")
          else:
            report_lines.append(f"- {name}")
      if failed_dg_tag_values:
        report_lines.append("#### DG Tag Values")
        for name in sorted(failed_dg_tag_values):
          error_message = (
              failed_dg_tag_values[name]
              if isinstance(failed_dg_tag_values, dict)
              else ""
          )
          if error_message:
            clean_error = " ".join(error_message.split())
            report_lines.append(f"- {name}: {clean_error}")
          else:
            report_lines.append(f"- {name}")
      if failed_data_policies_v2:
        report_lines.append("#### Data Policies V2")
        for policy_id in sorted(failed_data_policies_v2):
          error_message = (
              failed_data_policies_v2[policy_id]
              if isinstance(failed_data_policies_v2, dict)
              else ""
          )
          if error_message:
            clean_error = " ".join(error_message.split())
            report_lines.append(f"- {policy_id}: {clean_error}")
          else:
            report_lines.append(f"- {policy_id}")
      if preflight_blockers:
        report_lines.append("#### Plan & Quota Limits")
        for blocker in preflight_blockers:
          clean_blocker = " ".join(str(blocker).split())
          report_lines.append(f"- {clean_blocker}")
      report_lines.append("")

    if potential_issues:
      report_lines.append("### Potential Issues & Warnings")
      for issue in potential_issues:
        report_lines.append(f"- {issue}")
      report_lines.append("")

    # Explain the failure/blocker status token whenever any resource failed or
    # failed dry-run pre-flight checks.
    if has_failures:
      report_lines.append("### Error & Failure Status Reference")
      if self._dry_run:
        report_lines.append(
            "- **`Failed / Blocked`:** Dry-run pre-flight validation detected"
            " a deterministic API contract violation (invalid `short_name` or"
            " `policy_id`, description `> 256` chars, unresolved or"
            " cross-project custom masking routine, unsupported Authorized"
            " Routine grantee, `> 500` IAM principals or `> 100` groups per"
            " policy, or `> 1,000` Tag Keys / Tag Values / V2 Data Policies),"
            " a missing parent Tag Key/Value dependency, or an API inspection"
            " error that will prevent live creation until resolved."
        )
      else:
        report_lines.append(
            "- **`Failed`:** Live Google Cloud creation failed due to an API"
            " error (such as missing IAM permissions, invalid principal or"
            " payload syntax, or quota exhaustion), or creation was skipped"
            " because its parent DG Tag Key or Tag Value failed earlier in the"
            " same run."
        )
      report_lines.append("")

    return "\n".join(report_lines)

  def _create_data_policies_from_actions(
      self,
      actions: list[dict[str, Any]],
      failed_dg_tag_keys: set[str] | dict[str, str],
      failed_dg_tag_values: set[str] | dict[str, str],
      failed_data_policies_v2: dict[str, str],
      succeeded_data_policies_v2: set[str],
      skipped_data_policies_v2: set[str],
      qualify_with_project: bool = True,
  ) -> None:
    """Processes a batch of V2 Data Policy creation actions with cascade checks.

    If a policy's referenced DG Tag Key or DG Tag Value failed creation in an
    earlier pass, the policy is automatically skipped and recorded in
    `failed_data_policies_v2` rather than issuing a doomed API call.

    Args:
      actions: List of V2 Data Policy action dicts for a manifest category.
      failed_dg_tag_keys: Tag Keys that failed creation in Pass 1.
      failed_dg_tag_values: Tag Values that failed creation in Pass 2.
      failed_data_policies_v2: Output dict recording failed policy keys/reasons.
      succeeded_data_policies_v2: Output set recording created policy keys.
      skipped_data_policies_v2: Output set recording skipped policy keys.
      qualify_with_project: If True (default), formats report keys as
        `<target_project_id>/<policy_id>` whenever `target_project_id` is
        present so report entries match the `--resource-name` CLI contract in
        both Mode 1 and Mode 2.
    """
    for action in actions:
      policy_id = action[constants.FIELD_POLICY_ID]
      target_project_id = action.get(constants.FIELD_TARGET_PROJECT_ID)
      policy_key = (
          f"{target_project_id}/{policy_id}"
          if qualify_with_project and target_project_id
          else policy_id
      )
      payload = action[constants.FIELD_API_PAYLOAD]
      dg_tag_key = payload["data_governance_tag"]["key"]
      dg_tag_value = payload["data_governance_tag"]["value"]

      # Check whether the referenced Tag Key or Tag Value failed earlier.
      tag_key_failed = dg_tag_key in failed_dg_tag_keys
      dg_tag_value_namespaced = action.get(
          constants.FIELD_DG_TAG_VALUE_NAMESPACED_NAME
      )
      if dg_tag_value_namespaced:
        tag_value_failed = dg_tag_value_namespaced in failed_dg_tag_values
      else:
        tag_value_failed = any(
            failed_value == f"{dg_tag_key}/{dg_tag_value}"
            or (
                failed_value.startswith(f"{dg_tag_key}/")
                and failed_value.split("/")[-1] == dg_tag_value
            )
            for failed_value in failed_dg_tag_values
        )

      if tag_key_failed or tag_value_failed:
        failed_reason = (
            dg_tag_key
            if tag_key_failed
            else (dg_tag_value_namespaced or f"{dg_tag_key}/.../{dg_tag_value}")
        )
        logger.warning(
            "Skipping Data Policy V2 %s because tag or key %s failed",
            policy_key,
            failed_reason,
        )
        failed_data_policies_v2[policy_key] = (
            f"Parent tag or key {failed_reason} failed"
        )
        continue

      try:
        _, status = self.create_data_policy_v2(action)
        if status in (
            constants.STATUS_CREATED,
            constants.STATUS_WOULD_CREATE,
        ):
          succeeded_data_policies_v2.add(policy_key)
        elif status == constants.STATUS_SKIPPED:
          skipped_data_policies_v2.add(policy_key)
      except Exception as e:  # pylint: disable=broad-exception-caught
        logger.error(
            "Failed to create Data Policy V2 %s: %s",
            policy_key,
            e,
        )
        failed_data_policies_v2[policy_key] = str(e)
        if self._halt_on_error:
          raise

  def create_all_dgt_resources(
      self, plan: dict[str, Any], report_file: str | None = None
  ) -> str | None:
    """Provisions all planned DGT Keys, Values, and V2 Data Policies in order.

    Executes the 5-step topological creation pipeline:
      - Step 1: Create Data Governance Tag Keys (`taxonomies_to_dg_tag_keys`).
      - Step 2: Create Data Governance Tag Values
        (`policy_tags_to_dg_tag_values`), sorted top-down by slash depth so
        parent Tag Values are always created before their child Tag Values.
      - Step 3: Create Raw Reader Parity V2 Data Policies.
      - Step 4: Create Default Deny Seatbelt V2 Data Policies.
      - Step 5: Create Migrated V1 V2 Data Policies.

    Always updates `self.last_summary` and persists `report_file` inside a
    `finally` block so partial progress is saved even if `halt_on_error` or an
    interrupt aborts execution mid-run.

    Args:
      plan: Parsed migration plan dictionary (`plan.json`).
      report_file: Optional file path where the Markdown creation report is
        written.

    Returns:
      The formatted Markdown report string, or `None` if the user declines the
      interactive confirmation prompt.

    Raises:
      ValueError: If `plan` has an invalid or unsupported `schema_version`.
      RuntimeError: If the interactive confirmation prompt is interrupted or
        aborted on closed `stdin` without `--skip-confirmation`.
    """
    constants.validate_plan_schema_version(plan)
    manifest = plan.get(constants.KEY_PHASE_2_RESOURCE_MANIFEST, {})
    unresolved_warnings = self._collect_unresolved_plan_warnings(plan)
    if unresolved_warnings and not self._allow_unresolved_plan_warnings:
      logger.error(
          "Blocked Phase 2a creation: plan contains %d unresolved [ACTION"
          " REQUIRED] warning(s). Resolve them in plan.json or pass"
          " --allow-unresolved-plan-warnings to override.",
          len(unresolved_warnings),
      )
      self.last_summary = {
          "succeeded": 0,
          "skipped": 0,
          "failed": len(unresolved_warnings),
      }
      return self._render_blocked_plan_warnings_report(
          unresolved_warnings=unresolved_warnings,
          report_file=report_file,
      )
    if unresolved_warnings:
      logger.warning(
          "Proceeding with %d unresolved [ACTION REQUIRED] plan warning(s)"
          " because --allow-unresolved-plan-warnings is enabled.",
          len(unresolved_warnings),
      )

    total_dg_tag_keys = len(
        manifest.get(constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS, [])
    )
    total_dg_tag_values = len(
        manifest.get(constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES, [])
    )
    total_data_policies_v2_raw_reader = len(
        manifest.get(
            constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2, []
        )
    )
    total_data_policies_v2_default_deny = len(
        manifest.get(
            constants.KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2, []
        )
    )
    total_data_policies_v2_migrated = len(
        manifest.get(constants.KEY_DATA_POLICIES_V1_TO_DATA_POLICIES_V2, [])
    )

    banner_title = (
        "Summary of DG Tag Resources to Preview (DRY RUN)"
        if self._dry_run
        else "Summary of DG Tag Resources to Create"
    )
    # Flush stdout on console banners and section headers so piped runs (such
    # as `2>&1 | tee`) interleave section headers with stderr logger output in
    # chronological execution order.
    print("\n" + "=" * 40, flush=True)
    print(banner_title, flush=True)
    print("=" * 40, flush=True)
    print(f"  DG Tag Keys: {total_dg_tag_keys}", flush=True)
    print(f"  DG Tag Values: {total_dg_tag_values}", flush=True)
    print(
        "  Data Policies V2 (Raw Reader Parity):"
        f" {total_data_policies_v2_raw_reader}",
        flush=True,
    )
    print(
        "  Data Policies V2 (Default Deny Parity):"
        f" {total_data_policies_v2_default_deny}",
        flush=True,
    )
    print(
        f"  Data Policies V2 (Migrated V1): {total_data_policies_v2_migrated}",
        flush=True,
    )
    print("=" * 40, flush=True)

    if not self._dry_run and not self._skip_confirmation:
      try:
        confirm = input("Proceed with creation of ALL resources? (y/n): ")
      except (KeyboardInterrupt, EOFError) as abort_error:
        print("\nCreation aborted by user.", flush=True)
        raise RuntimeError(
            "Interactive confirmation prompt aborted (interrupted or closed"
            " stdin without --skip-confirmation)."
        ) from abort_error
      if not sys.stdin.isatty():
        print(flush=True)
      if confirm.lower() != "y":
        print("Creation aborted by user.", flush=True)
        return None

    self._skipped_resource_drift_warnings.clear()
    failed_dg_tag_keys: dict[str, str] = {}
    succeeded_dg_tag_keys: set[str] = set()
    skipped_dg_tag_keys: set[str] = set()

    failed_dg_tag_values: dict[str, str] = {}
    succeeded_dg_tag_values: set[str] = set()
    skipped_dg_tag_values: set[str] = set()

    failed_data_policies_v2: dict[str, str] = {}
    succeeded_data_policies_v2: set[str] = set()
    skipped_data_policies_v2: set[str] = set()
    preflight_blockers: list[str] = []
    potential_issues: list[str] = [
        f"Overridden Plan Warning: {warning_item}"
        for warning_item in unresolved_warnings
    ]

    report = None
    try:
      # === Step 1: Create Data Governance Tag Keys ===
      step_prefix = "Previewing" if self._dry_run else "Creating"
      print(f"\n--- {step_prefix} DG Tag Keys ---", flush=True)
      for action in manifest.get(constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS, []):
        namespaced_name = action["namespaced_name"]
        try:
          _, status = self.create_dg_tag_key(action)
          if status in (
              constants.STATUS_CREATED,
              constants.STATUS_WOULD_CREATE,
          ):
            succeeded_dg_tag_keys.add(namespaced_name)
          elif status == constants.STATUS_SKIPPED:
            skipped_dg_tag_keys.add(namespaced_name)
        except Exception as e:  # pylint: disable=broad-exception-caught
          logger.error("Failed to create DG Tag Key %s: %s", namespaced_name, e)
          failed_dg_tag_keys[namespaced_name] = str(e)
          if self._halt_on_error:
            raise
          logger.error(
              "Skipping dependent resources for %s due to failure",
              namespaced_name,
          )

      # === Step 2: Create Data Governance Tag Values (Top-Down by Depth) ===
      # Stable-sort Tag Value actions by slash-segment count so parent Tag
      # Values are guaranteed to be created before their child Tag Values even
      # if the user manually reordered entries in plan.json.
      print(f"\n--- {step_prefix} DG Tag Values ---", flush=True)
      sorted_tag_value_actions = sorted(
          manifest.get(constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES, []),
          key=lambda item: len(str(item.get("namespaced_name", "")).split("/")),
      )
      for action in sorted_tag_value_actions:
        namespaced_name = action["namespaced_name"]
        parent_namespaced_name = action["parent_namespaced_name"]

        if (
            parent_namespaced_name in failed_dg_tag_keys
            or parent_namespaced_name in failed_dg_tag_values
        ):
          reason = f"Parent {parent_namespaced_name} failed"
          logger.warning(
              "Skipping DG Tag Value %s because parent %s failed",
              namespaced_name,
              parent_namespaced_name,
          )
          failed_dg_tag_values[namespaced_name] = reason
          continue

        try:
          _, status = self.create_dg_tag_value(action)
          if status in (
              constants.STATUS_CREATED,
              constants.STATUS_WOULD_CREATE,
          ):
            succeeded_dg_tag_values.add(namespaced_name)
          elif status == constants.STATUS_SKIPPED:
            skipped_dg_tag_values.add(namespaced_name)
        except Exception as e:  # pylint: disable=broad-exception-caught
          logger.error(
              "Failed to create DG Tag Value %s: %s", namespaced_name, e
          )
          failed_dg_tag_values[namespaced_name] = str(e)
          if self._halt_on_error:
            raise
          logger.error(
              "Skipping dependent resources for %s due to failure",
              namespaced_name,
          )

      raw_reader_actions = manifest.get(
          constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2, []
      )
      default_deny_actions = manifest.get(
          constants.KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2, []
      )
      migrated_actions = manifest.get(
          constants.KEY_DATA_POLICIES_V1_TO_DATA_POLICIES_V2, []
      )
      # Always qualify V2 Data Policy report entries as
      # `<target_project_id>/<policy_id>` whenever `target_project_id` is
      # present so both Mode 1 and Mode 2 reports can be copy-pasted directly
      # into `--resource-name` for `--phase create` and `--phase delete`.
      qualify_with_project = True

      # === Step 3: Create Data Policies V2 (Raw Reader Parity) ===
      print(
          f"\n--- {step_prefix} Data Policies V2 (Raw Reader Parity) ---",
          flush=True,
      )
      self._create_data_policies_from_actions(
          raw_reader_actions,
          failed_dg_tag_keys,
          failed_dg_tag_values,
          failed_data_policies_v2,
          succeeded_data_policies_v2,
          skipped_data_policies_v2,
          qualify_with_project=qualify_with_project,
      )

      # === Step 4: Create Data Policies V2 (Default Deny Seatbelt Parity) ===
      print(
          f"\n--- {step_prefix} Data Policies V2 (Default Deny Parity) ---",
          flush=True,
      )
      self._create_data_policies_from_actions(
          default_deny_actions,
          failed_dg_tag_keys,
          failed_dg_tag_values,
          failed_data_policies_v2,
          succeeded_data_policies_v2,
          skipped_data_policies_v2,
          qualify_with_project=qualify_with_project,
      )

      # === Step 5: Create Data Policies V2 (Migrated V1 Policies) ===
      print(
          f"\n--- {step_prefix} Data Policies V2 (Migrated) ---",
          flush=True,
      )
      self._create_data_policies_from_actions(
          migrated_actions,
          failed_dg_tag_keys,
          failed_dg_tag_values,
          failed_data_policies_v2,
          succeeded_data_policies_v2,
          skipped_data_policies_v2,
          qualify_with_project=qualify_with_project,
      )

      if self._dry_run:
        # Promote deterministic API contract violations on planned resources
        # (invalid names/IDs, description > 256 chars, unresolved or
        # cross-project custom masking routines, Authorized Routine grantees,
        # and > 500 principals / > 100 groups per policy) into `failed_*` so
        # CI/CD dry-run gates fail closed with exit code 1.
        for section_key, resource_type, failed_map, ok_set, skip_set in (
            (
                constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS,
                constants.RESOURCE_TYPE_DG_TAG_KEY,
                failed_dg_tag_keys,
                succeeded_dg_tag_keys,
                skipped_dg_tag_keys,
            ),
            (
                constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES,
                constants.RESOURCE_TYPE_DG_TAG_VALUE,
                failed_dg_tag_values,
                succeeded_dg_tag_values,
                skipped_dg_tag_values,
            ),
            (
                constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2,
                constants.RESOURCE_TYPE_DATA_POLICY_V2,
                failed_data_policies_v2,
                succeeded_data_policies_v2,
                skipped_data_policies_v2,
            ),
            (
                constants.KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2,
                constants.RESOURCE_TYPE_DATA_POLICY_V2,
                failed_data_policies_v2,
                succeeded_data_policies_v2,
                skipped_data_policies_v2,
            ),
            (
                constants.KEY_DATA_POLICIES_V1_TO_DATA_POLICIES_V2,
                constants.RESOURCE_TYPE_DATA_POLICY_V2,
                failed_data_policies_v2,
                succeeded_data_policies_v2,
                skipped_data_policies_v2,
            ),
        ):
          for action in manifest.get(section_key, []):
            hard_errors = self._collect_action_hard_validation_errors(
                action, resource_type
            )
            if not hard_errors:
              continue
            action_label = self._extract_action_resource_label(action)
            if not action_label:
              continue
            combined_reason = "; ".join(hard_errors)
            if action_label in failed_map:
              if combined_reason not in failed_map[action_label]:
                failed_map[action_label] = (
                    f"{failed_map[action_label]}; {combined_reason}"
                )
            else:
              failed_map[action_label] = combined_reason
            ok_set.discard(action_label)
            skip_set.discard(action_label)

        preflight_blockers = self._collect_quota_blockers(plan)
        collected_issues = self._collect_potential_issues(
            plan=plan,
            skipped_dg_tag_keys=skipped_dg_tag_keys,
            skipped_dg_tag_values=skipped_dg_tag_values,
            skipped_data_policies_v2=skipped_data_policies_v2,
            include_hard_blockers=False,
        )
        for issue in collected_issues:
          if issue not in potential_issues:
            potential_issues.append(issue)
        print(
            "\nDry-run preview completed (no resources were modified).",
            flush=True,
        )
      else:
        for drift_warning in self._skipped_resource_drift_warnings:
          if drift_warning not in potential_issues:
            potential_issues.append(drift_warning)
        print("\nCreation phase completed.", flush=True)
      report = self._generate_report(
          succeeded_dg_tag_keys,
          skipped_dg_tag_keys,
          failed_dg_tag_keys,
          succeeded_dg_tag_values,
          skipped_dg_tag_values,
          failed_dg_tag_values,
          succeeded_data_policies_v2,
          skipped_data_policies_v2,
          failed_data_policies_v2,
          potential_issues=potential_issues,
          preflight_blockers=preflight_blockers,
      )
      return report
    finally:
      self.last_summary = {
          "succeeded": (
              len(succeeded_dg_tag_keys)
              + len(succeeded_dg_tag_values)
              + len(succeeded_data_policies_v2)
          ),
          "skipped": (
              len(skipped_dg_tag_keys)
              + len(skipped_dg_tag_values)
              + len(skipped_data_policies_v2)
          ),
          "failed": (
              len(failed_dg_tag_keys)
              + len(failed_dg_tag_values)
              + len(failed_data_policies_v2)
              + len(preflight_blockers)
          ),
      }
      report_str = report
      if report_str is None:
        report_str = self._generate_report(
            succeeded_dg_tag_keys,
            skipped_dg_tag_keys,
            failed_dg_tag_keys,
            succeeded_dg_tag_values,
            skipped_dg_tag_values,
            failed_dg_tag_values,
            succeeded_data_policies_v2,
            skipped_data_policies_v2,
            failed_data_policies_v2,
            potential_issues=potential_issues,
            preflight_blockers=preflight_blockers,
        )
        print("\n" + "=" * 40, flush=True)
        print("Creation halted due to error. Report so far:", flush=True)
        print("=" * 40, flush=True)
        print(report_str, flush=True)

      if report_file and report_str:
        try:
          with open(report_file, "w", encoding="utf-8") as f:
            f.write(_ensure_trailing_newline(report_str))
          logger.info("Creation report saved to %s", report_file)
        except OSError as file_error:
          logger.error(
              "Failed to write creation report to %s: %s",
              report_file,
              file_error,
          )

  def create_individual_dgt_resource(
      self,
      plan: dict[str, Any],
      resource_name: str,
      resource_type: str,
      report_file: str | None = None,
  ) -> str | None:
    """Provisions or dry-run previews a single resource from the migration plan.

    Requires `<target_project_id>/<data_policy_id>` for `data-policy-v2` in
    both Mode 1 (`DEFAULT_DATA_POLICY_PROJECT`) and Mode 2
    (`TABLE_PARENT_PROJECTS`), and blocks upfront if `plan.json` contains
    unresolved `[ACTION REQUIRED]` warnings unless
    `allow_unresolved_plan_warnings` is True.

    Args:
      plan: Parsed migration plan dictionary (`plan.json`).
      resource_name: Identifier of the resource (`namespaced_name` for Tag Keys
        and Tag Values; `<target_project_id>/<data_policy_id>` for V2 Data
        Policies).
      resource_type: Resource type constant (`dg-tag-key`, `dg-tag-value`, or
        `data-policy-v2`).
      report_file: Optional path to save the Markdown creation report.

    Returns:
      The formatted Markdown report string, or `None` if aborted by the user.

    Raises:
      ValueError: If `plan` has an invalid or unsupported `schema_version`, if
        `resource_name` is malformed or not found in `plan.json`, or if
        `resource_type` is unknown.
    """
    constants.validate_plan_schema_version(plan)
    unresolved_warnings = self._collect_unresolved_plan_warnings(plan)
    if unresolved_warnings and not self._allow_unresolved_plan_warnings:
      logger.error(
          "Blocked individual Phase 2a creation for '%s': plan contains %d"
          " unresolved [ACTION REQUIRED] warning(s). Resolve them in plan.json"
          " or pass --allow-unresolved-plan-warnings to override.",
          resource_name,
          len(unresolved_warnings),
      )
      self.last_summary = {
          "succeeded": 0,
          "skipped": 0,
          "failed": len(unresolved_warnings),
      }
      return self._render_blocked_plan_warnings_report(
          unresolved_warnings=unresolved_warnings,
          report_file=report_file,
          resource_name=resource_name,
          resource_type=resource_type,
      )
    if unresolved_warnings:
      logger.warning(
          "Proceeding with %d unresolved [ACTION REQUIRED] plan warning(s)"
          " because --allow-unresolved-plan-warnings is enabled.",
          len(unresolved_warnings),
      )

    manifest = plan.get(constants.KEY_PHASE_2_RESOURCE_MANIFEST, {})
    self._skipped_resource_drift_warnings.clear()
    self.last_error_message = None
    self.last_report = None
    status = None
    created_id = None
    error_message = None
    prompt_aborted = False
    dry_run_hard_errors: list[str] = []
    potential_issues: list[str] = [
        f"Overridden Plan Warning: {warning_item}"
        for warning_item in unresolved_warnings
    ]

    try:
      # Validate resource_type, strict naming format, and plan allowlist before
      # prompting interactively so invalid inputs fail fast without prompting.
      if "/" in resource_name:
        constants.validate_standard_project_id(
            resource_name.split("/")[0], "--resource-name project_id"
        )
      matched_action: dict[str, Any] | None = None
      if resource_type == constants.RESOURCE_TYPE_DG_TAG_KEY:
        for candidate in manifest.get(
            constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS, []
        ):
          if candidate[constants.FIELD_NAMESPACED_NAME] == resource_name:
            matched_action = candidate
            break
        if matched_action is None:
          raise ValueError(
              f"Resource {resource_name} of type {resource_type} not found in"
              " plan"
          )
      elif resource_type == constants.RESOURCE_TYPE_DG_TAG_VALUE:
        tag_value_candidates = manifest.get(
            constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES, []
        )
        for candidate in tag_value_candidates:
          if candidate[constants.FIELD_NAMESPACED_NAME] == resource_name:
            matched_action = candidate
            break
        if matched_action is None and len(resource_name.split("/")) == 3:
          # Also match a unique nested Tag Value when the caller supplies the
          # 3-segment Resource Manager namespaced name
          # (`<project>/<tag_key_short>/<tag_value_short>`).
          proj_part, key_part, val_part = resource_name.split("/")
          shorthand_matches = [
              candidate
              for candidate in tag_value_candidates
              if str(
                  candidate.get(constants.FIELD_NAMESPACED_NAME, "")
              ).startswith(f"{proj_part}/{key_part}/")
              and str(
                  candidate.get(constants.FIELD_NAMESPACED_NAME, "")
              ).endswith(f"/{val_part}")
          ]
          if len(shorthand_matches) == 1:
            matched_action = shorthand_matches[0]
        if matched_action is None:
          raise ValueError(
              f"Resource {resource_name} of type {resource_type} not found in"
              " plan"
          )
      elif resource_type == constants.RESOURCE_TYPE_DATA_POLICY_V2:
        matched_action = self._validate_and_match_data_policy_action(
            manifest, resource_name
        )
      else:
        raise ValueError(f"Unknown resource type: {resource_type}")

      if not self._dry_run and not self._skip_confirmation:
        print(
            "\nYou are about to create the individual resource:"
            f" {resource_name} of type {resource_type}",
            flush=True,
        )
        try:
          confirm = input("Proceed? (y/n): ")
        except (KeyboardInterrupt, EOFError) as abort_error:
          prompt_aborted = True
          print("\nCreation aborted by user.", flush=True)
          raise RuntimeError(
              "Interactive confirmation prompt aborted (interrupted or closed"
              " stdin without --skip-confirmation)."
          ) from abort_error
        if not sys.stdin.isatty():
          print(flush=True)
        if confirm.lower() != "y":
          prompt_aborted = True
          print("Creation aborted by user.", flush=True)
          return None

      # === Case 1: Individual Data Governance Tag Key ===
      if resource_type == constants.RESOURCE_TYPE_DG_TAG_KEY:
        if self._dry_run:
          _, plan_warning_lines = self._collect_action_plan_warnings(
              matched_action
          )
          potential_issues.extend(plan_warning_lines)
          dry_run_hard_errors = self._collect_action_hard_validation_errors(
              matched_action, resource_type
          )
        result = self.create_dg_tag_key(matched_action)
        if isinstance(result, tuple) and len(result) == 2:
          created_id, status = result
        else:
          created_id, status = result, constants.STATUS_CREATED
      # === Case 2: Individual Data Governance Tag Value ===
      elif resource_type == constants.RESOURCE_TYPE_DG_TAG_VALUE:
        if self._dry_run:
          _, plan_warning_lines = self._collect_action_plan_warnings(
              matched_action
          )
          potential_issues.extend(plan_warning_lines)
          dry_run_hard_errors = self._collect_action_hard_validation_errors(
              matched_action, resource_type
          )
        result = self.create_dg_tag_value(matched_action)
        if isinstance(result, tuple) and len(result) == 2:
          created_id, status = result
        else:
          created_id, status = result, constants.STATUS_CREATED
      # === Case 3: Individual BigQuery V2 Data Policy ===
      elif resource_type == constants.RESOURCE_TYPE_DATA_POLICY_V2:
        action = matched_action
        if self._dry_run:
          _, plan_warning_lines = self._collect_action_plan_warnings(action)
          potential_issues.extend(plan_warning_lines)
          dry_run_hard_errors = self._collect_action_hard_validation_errors(
              action, resource_type
          )
          dg_tag_spec = action.get(constants.FIELD_API_PAYLOAD, {}).get(
              "data_governance_tag", {}
          )
          dg_tag_key = dg_tag_spec.get("key", "")
          dg_tag_value_namespaced = action.get(
              constants.FIELD_DG_TAG_VALUE_NAMESPACED_NAME
          ) or (
              f"{dg_tag_key}/{dg_tag_spec.get('value', '')}"
              if dg_tag_key and dg_tag_spec.get("value")
              else ""
          )
          key_id = None
          if dg_tag_key:
            # pylint: disable=broad-exception-caught
            try:
              key_id = self._get_dg_tag_key_id(dg_tag_key)
              if not key_id:
                potential_issues.append(
                    f"Referenced DG Tag Key '{dg_tag_key}' does not exist"
                    " in Google Cloud yet. Create the DG Tag Key and Tag"
                    " Value before creating this V2 Data Policy."
                )
            except Exception as tag_error:
              potential_issues.append(
                  "Could not verify referenced DG Tag Key"
                  f" '{dg_tag_key}': {tag_error}"
              )
            # pylint: enable=broad-exception-caught
          if dg_tag_value_namespaced:
            if not key_id:
              potential_issues.append(
                  f"Referenced DG Tag Value '{dg_tag_value_namespaced}'"
                  " does not exist in GCP yet."
              )
            else:
              # pylint: disable=broad-exception-caught
              try:
                value_id = self._get_dg_tag_value_id(dg_tag_value_namespaced)
                if not value_id:
                  potential_issues.append(
                      "Referenced DG Tag Value"
                      f" '{dg_tag_value_namespaced}' does not exist in"
                      " GCP yet."
                  )
              except Exception as value_error:
                potential_issues.append(
                    "Could not verify referenced DG Tag Value"
                    f" '{dg_tag_value_namespaced}': {value_error}"
                )
              # pylint: enable=broad-exception-caught
        result = self.create_data_policy_v2(action)
        if isinstance(result, tuple) and len(result) == 2:
          created_id, status = result
        else:
          created_id, status = result, constants.STATUS_CREATED

    except Exception as error:  # pylint: disable=broad-exception-caught
      error_message = str(error)
      if (
          self._dry_run
          and not self._halt_on_error
          and "not found in plan" not in error_message
          and "Unknown resource type" not in error_message
          and "Invalid Data Policy V2 resource name" not in error_message
      ):
        potential_issues.append(
            f"Pre-flight check failed for '{resource_name}': {error_message}"
        )
      else:
        raise
    finally:
      if prompt_aborted:
        # Mirror `create_all_dgt_resources` and `Deleter`: aborting at the
        # confirmation prompt before any GCP API call must not emit a bogus
        # `Status: Failed` report or overwrite `report_file`.
        self.last_error_message = None
        self.last_report = None
        self.last_summary = {"succeeded": 0, "skipped": 0, "failed": 0}
        report_str = None
      else:
        if self._dry_run and dry_run_hard_errors:
          combined_hard_error = "; ".join(dry_run_hard_errors)
          if error_message:
            if combined_hard_error not in error_message:
              error_message = f"{error_message}; {combined_hard_error}"
          else:
            error_message = combined_hard_error
            status = None
        for drift_warning in self._skipped_resource_drift_warnings:
          if drift_warning not in potential_issues:
            potential_issues.append(drift_warning)
        if self._allow_unresolved_plan_warnings and potential_issues:
          deduped_issues: list[str] = []
          for issue_item in potential_issues:
            if (
                constants.PLAN_WARNING_ACTION_REQUIRED_MARKER in issue_item
                and not issue_item.startswith("Overridden Plan Warning:")
            ):
              continue
            if issue_item not in deduped_issues:
              deduped_issues.append(issue_item)
          potential_issues = deduped_issues
        self.last_error_message = error_message
        is_succeeded = status in (
            constants.STATUS_CREATED,
            constants.STATUS_WOULD_CREATE,
        )
        self.last_summary = {
            "succeeded": 1 if is_succeeded else 0,
            "skipped": 1 if status == constants.STATUS_SKIPPED else 0,
            "failed": 1 if error_message else 0,
        }
        if self._dry_run:
          title = (
              "# Data Governance Tag Resource Creation Report (Individual - DRY"
              " RUN)"
          )
        else:
          title = "# Data Governance Tag Resource Creation Report (Individual)"
        report_lines = [title, ""]
        if self._dry_run:
          report_lines.append(
              "**Dry-Run Mode:** No resources were created or modified in"
              " Google Cloud."
          )
          report_lines.append("")
        report_lines.extend([
            f"- **Resource Name:** {resource_name}",
            f"- **Resource Type:** {resource_type}",
        ])
        if error_message:
          clean_error = " ".join(error_message.split())
          report_lines.append("- **Status:** Failed")
          report_lines.append(f"- **Error:** {clean_error}")
          if self._dry_run:
            report_lines.append("")
            report_lines.append("### Failed Pre-Flight Checks / Blockers")
            report_lines.append(f"- {resource_name}: {clean_error}")
        elif status:
          report_lines.append(f"- **Status:** {status}")
          if created_id:
            report_lines.append(f"- **Resource ID:** {created_id}")
        if potential_issues:
          report_lines.append("")
          report_lines.append("### Potential Issues & Warnings")
          for issue in potential_issues:
            report_lines.append(f"- {issue}")
        if error_message:
          report_lines.append("")
          report_lines.append("### Error & Failure Status Reference")
          if self._dry_run:
            report_lines.append(
                "- **`Failed` / `Failed / Blocked`:** Dry-run pre-flight"
                " validation or lookup failed for the requested resource;"
                " resolve the reported error before running live creation."
            )
          else:
            report_lines.append(
                "- **`Failed`:** Live Google Cloud creation failed due to an"
                " API, permission, or validation error; inspect `- **Error:**`"
                " above and `--log-file` for full details."
            )
        report_lines.append("")
        report_str = "\n".join(report_lines)
        self.last_report = report_str

        if report_file and (status or error_message):
          try:
            with open(report_file, "w", encoding="utf-8") as f:
              f.write(_ensure_trailing_newline(report_str))
            logger.info("Creation report saved to %s", report_file)
          except OSError as file_error:
            logger.error(
                "Failed to write creation report to %s: %s",
                report_file,
                file_error,
            )

    return report_str
