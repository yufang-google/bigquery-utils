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

"""Phase 2b Resource Deleter for Policy Tag to Data Governance Tag Migration.

Architectural Purpose & Role in the 3-Phase Migration Pipeline:
===============================================================
The migration tool is architected as a 3-phase pipeline:
  - Phase 1 (`Analyzer` + `Planner`): Scans Legacy Policy Tag Taxonomies, V1
    Data Policies, and BigQuery table schemas to build a deterministic
    `plan.json` manifest.
  - Phase 2a (`Creator`): Reads `phase_2_resource_manifest` from `plan.json`
    and provisions the parallel Data Governance Tag Keys, Tag Values, and V2
    Data Policies in Google Cloud.
  - Phase 2b (`Deleter` - THIS MODULE): Provides surgical, operator-controlled
    deletion (`delete-dgt-resource`) and dry-run dependency auditing for
    individual Phase 2 Data Governance Tag resources (`dg_tag_key`,
    `dg_tag_value`, or `data_policy_v2`) defined in `plan.json`.
  - Phase 3 (`Swapper`): Reads `phase_3_binding_map` from `plan.json` to
    bind the new Data Governance Tag Values to BigQuery table columns or
    revert back to Legacy Policy Tags.

How Phase 2b (`Deleter`) Works Step-by-Step:
============================================
1. Manifest Lookup & Disambiguation (`delete_individual_dgt_resource`):
   Validates that the requested `--resource-name` and `--resource-type` exist
   in `plan.json` (`phase_2_resource_manifest`). For V2 Data Policies in Mode 2
   (`TABLE_PARENT_PROJECTS`), detects cross-project collisions when an
   unqualified `<policy_id>` matches multiple data projects and requires
   `<target_project_id>/<policy_id>` or full resource name disambiguation.
2. Pre-Delete Dependency & Fail-Open Risk Auditing:
   - Before deleting a V2 Data Policy (`_check_data_policy_dependents`), warns
     if the policy is a Default-Deny safety net or governs a Tag Value that may
     be bound to BigQuery columns (where removing all policies causes columns
     to revert to Default Allow / Fail-Open).
   - Before deleting a DG Tag Value (`_check_tag_value_plan_dependents`), warns
     if `plan.json` contains child DG Tag Values with
     `parent_namespaced_name == resource_name` or V2 Data Policies referencing
     that Tag Value.
3. Dry-Run Live Dependency Inspection (`_inspect_dry_run_deletion`):
   When `--dry-run` is active, queries GCP without mutating state to check
   whether the target resource exists (`WOULD_DELETE` vs `SKIPPED`) or whether
   live child DG Tag Values currently block deletion in GCP Resource Manager
   (`BLOCKED`).
4. Interactive Confirmation & Live Deletion Execution:
   In live mode, logs and prints all pre-delete warnings, prompts for operator
   confirmation (unless `--skip-confirmation` is set), executes the deletion
   with exponential backoff (`RETRY_CONFIG`) and V2 REST fallback, and writes a
   Markdown audit report (`--report-file`) on both success and exception.

Key Design Decisions, Alternatives Considered & Trade-Offs:
===========================================================
1. Individual-Only Resource Deletion (No Bulk "Delete All" Command):
   - Decision: `Deleter` only exposes `delete_individual_dgt_resource` for a
     single named resource at a time.
   - Alternative Considered: Providing a bulk `delete_all_dgt_resources` command
     that wipes every Tag Key, Tag Value, and V2 Data Policy in `plan.json`.
   - Why Rejected / Trade-Off: Deleting a V2 Data Policy while its DG Tag Value
     is bound to production BigQuery columns immediately removes access control
     or masking (Fail-Open), and GCP rejects deleting Tag Values or Tag Keys
     that still have active bindings or child resources. Forcing per-resource
     deletion with explicit dependency and Fail-Open warnings trades bulk
     convenience for strong operational safety.
2. List-and-Cache + Negative-Lookup Sets vs. `get_namespaced_tag_*`:
   - Decision: Resolve Tag Keys and Tag Values via `list_tag_keys` /
     `list_tag_values`, caching discovered mappings in `_dg_tag_key_cache` /
     `_dg_tag_value_cache` and tracking already-listed parents in
     `_listed_tag_key_projects` and `_listed_tag_value_parents`.
   - Alternative Considered: Calling `get_namespaced_tag_key` /
     `get_namespaced_tag_value` directly, or re-listing the parent on every
     cache miss.
   - Trade-Off: `get_namespaced_tag_*` frequently fails with permission/resource
     extraction errors across organizational boundaries. Tracking listed
     projects and parent IDs in `_listed_tag_key_projects` and
     `_listed_tag_value_parents` prevents repeated $O(N)$ list RPCs when
     probing already-deleted or missing resources.
3. Dual-Transport V2 Data Policy Deletion (GAPIC + Raw `/v2/` REST Fallback):
   - Decision: Attempt `get_data_policy` / `delete_data_policy` via the GAPIC
     client first, and automatically fall back to `_get_data_policy_v2_rest` /
     `_delete_data_policy_v2_rest` on `AttributeError`, `TypeError`,
     `InvalidArgument`, or `Unknown`.
   - Trade-Off: Ensures compatibility across environments where only the V1
     GAPIC library is installed while still honoring custom regional endpoints.
"""

from __future__ import annotations

from collections.abc import Callable
import logging
import os
import re
import sys
import time
from typing import Any

from google.api_core import exceptions
from google.api_core import retry

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# pylint: disable=g-import-not-at-top,g-bad-import-order
import constants
import rest_utils

# pylint: enable=g-import-not-at-top,g-bad-import-order

# Exponential backoff configuration applied to Resource Manager and Data Policy
# RPCs to absorb transient HTTP 429 rate limits and 5xx server errors.
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


def _clean_exception_message(error: Exception) -> str:
  """Strips duplicated trailing gRPC status-code suffixes from LRO errors.

  Google Cloud Resource Manager Long-Running Operations often raise
  `FailedPrecondition` strings formatted as `"400 <msg> 9: <msg>"`, where the
  gRPC status code (`9: `) repeats the exact HTTP error text a second time.
  Deduplicating that suffix keeps error logs and Markdown failure reports
  concise without losing any diagnostic detail.

  Args:
    error: Caught exception instance.

  Returns:
    Deduplicated string representation of `error`.
  """
  raw_message = str(error)
  match = re.search(r" \d+: ", raw_message)
  if match:
    prefix = raw_message[: match.start()].strip()
    suffix = raw_message[match.end() :].strip()
    if suffix and suffix in prefix:
      return prefix
  return raw_message


def _ensure_trailing_newline(content: str) -> str:
  """Ensures non-empty file content terminates with a single newline."""
  if not content or content.endswith("\n"):
    return content
  return f"{content}\n"


def _streams_share_destination() -> bool:
  """Returns True when `sys.stdout` and `sys.stderr` share a console/stream."""
  try:
    if sys.stdout.isatty() and sys.stderr.isatty():
      return True
    return os.path.sameopenfile(sys.stdout.fileno(), sys.stderr.fileno())
  except (AttributeError, OSError, ValueError):
    return False


def _logger_emits_to_console(target_logger: logging.Logger, level: int) -> bool:
  """Returns True if `target_logger` writes `level` records to stdout/stderr.

  Used in interactive confirmation flows to avoid printing the identical
  `[WARNING - FAIL-OPEN RISK]` paragraph twice back-to-back when both
  `logger.warning` and `print` target the same console or `2>&1` stream.

  Args:
    target_logger: Logger instance used for warning emission.
    level: Numeric logging level (for example, `logging.WARNING`).

  Returns:
    True when `target_logger` will visibly emit `level` records on `sys.stdout`
    or on a `sys.stderr` stream sharing the same console destination.
  """
  if not target_logger.isEnabledFor(level):
    return False
  shares_stdout_stderr = _streams_share_destination()
  current_logger: logging.Logger | None = target_logger
  visited_handlers: set[int] = set()
  found_any_handler = False
  while current_logger is not None:
    for handler in current_logger.handlers:
      if id(handler) in visited_handlers:
        continue
      visited_handlers.add(id(handler))
      found_any_handler = True
      if isinstance(handler, logging.FileHandler):
        continue
      if isinstance(handler, logging.StreamHandler) and level >= handler.level:
        stream = getattr(handler, "stream", None)
        if stream is sys.stdout:
          return True
        if stream in (None, sys.stderr) and shares_stdout_stderr:
          return True
    if not current_logger.propagate:
      break
    current_logger = current_logger.parent
  if not found_any_handler and logging.lastResort is not None:
    return level >= logging.lastResort.level and shares_stdout_stderr
  return False


class Deleter:
  """Deletes individual Data Governance Tag resources with safety checks.

  This class implements Phase 2b (`delete-dgt-resource`) of the migration tool,
  supporting both read-only dependency inspection (`dry_run=True`) and live
  deletion (`dry_run=False`) of individual Data Governance Tag Keys, Tag Values,
  and V2 Data Policies declared in `plan.json`.

  Attributes:
    _dg_tag_keys_client: Resource Manager `TagKeysClient` for listing and
      deleting Data Governance Tag Keys.
    _dg_tag_values_client: Resource Manager `TagValuesClient` for listing and
      deleting Data Governance Tag Values.
    _data_policy_v2_client: BigQuery `DataPolicyServiceClient` for inspecting
      and deleting V2 Data Policies.
    _halt_on_error: Whether to halt execution immediately on the first error.
    _dry_run: When True, performs read-only dependency and existence checks in
      GCP without mutating any resources.
    _skip_confirmation: When True, bypasses interactive `input()` prompts in
      live deletion mode.
    _dg_tag_key_cache: In-memory cache mapping `<project_id>/<key_short_name>`
      to `tagKeys/<id>`.
    _dg_tag_value_cache: In-memory cache mapping hierarchical Tag Value
      namespaced names (`<project_id>/<key_short_name>/.../<val_short_name>`) to
      `tagValues/<id>`.
    _listed_tag_key_projects: Set of project IDs whose Tag Keys have already
      been listed via `list_tag_keys`, preventing redundant list RPCs on
      repeated lookups of missing/deleted keys.
    _listed_tag_value_parents: Set of parent resource IDs (`tagKeys/<id>` or
      `tagValues/<id>`) whose direct child Tag Values have already been listed
      via `list_tag_values`, preventing redundant list RPCs on missing values.
    last_report: Most recent Markdown deletion report generated by
      `delete_individual_dgt_resource` (including `FAILED` reports on
      exceptions).
  """

  def __init__(
      self,
      dg_tag_keys_client: Any,
      dg_tag_values_client: Any,
      data_policy_v2_client: Any,
      halt_on_error: bool = False,
      dry_run: bool = False,
      skip_confirmation: bool = False,
      allow_fail_open_policy_delete: bool = False,
  ):
    """Initializes the Phase 2b Deleter with GCP clients and execution flags.

    Args:
      dg_tag_keys_client: Resource Manager TagKeysClient.
      dg_tag_values_client: Resource Manager TagValuesClient.
      data_policy_v2_client: BigQuery DataPolicyServiceClient.
      halt_on_error: Whether to stop execution on first error.
      dry_run: If True, perform read-only checks and report what would be
        deleted and any potential dependency blockers without mutating GCP.
      skip_confirmation: Whether to bypass interactive confirmation prompts.
      allow_fail_open_policy_delete: Whether live deletion of a V2 Data Policy
        is explicitly authorized despite Fail-Open exposure risk when its Data
        Governance Tag Value is still bound to BigQuery columns. Defaults to
        False (blocking live `data-policy-v2` deletions even when
        `skip_confirmation` is True).
    """
    self._dg_tag_keys_client = dg_tag_keys_client
    self._dg_tag_values_client = dg_tag_values_client
    self._data_policy_v2_client = data_policy_v2_client
    self._rest_client = rest_utils.DataPolicyRestClient(data_policy_v2_client)
    self._halt_on_error = halt_on_error
    self._dry_run = dry_run
    self._skip_confirmation = skip_confirmation
    self._allow_fail_open_policy_delete = allow_fail_open_policy_delete
    self._dg_tag_key_cache: dict[str, str] = {}
    self._dg_tag_value_cache: dict[str, str] = {}
    self._listed_tag_key_projects: set[str] = set()
    self._listed_tag_value_parents: set[str] = set()
    self._emitted_skip_confirmation_warnings = False
    self.last_report: str | None = None

  def _get_dg_tag_key_id(self, namespaced_name: str) -> str | None:
    """Resolves a DG Tag Key resource name (`tagKeys/<id>`) by namespaced name.

    What It Does & How It Works:
      1. Checks `_dg_tag_key_cache` for an $O(1)$ hit on `namespaced_name`.
      2. Parses `namespaced_name` (`<project_id>/<key_short_name>`). If
         `project_id` is already in `_listed_tag_key_projects`, returns `None`
         immediately without issuing another `list_tag_keys` RPC.
      3. Lists all Tag Keys under `projects/<project_id>`, populates
         `_dg_tag_key_cache`, records `project_id` in
         `_listed_tag_key_projects`, and returns the matching `tagKeys/<id>`
         (or `None` if absent).

    Args:
      namespaced_name: Project-scoped Tag Key (`<project_id>/<short_name>`).

    Returns:
      The GCP Tag Key resource name (`tagKeys/<id>`) if found, or `None`.

    Raises:
      Exception: Propagates any RPC error raised by `list_tag_keys`.
    """
    # === Step 1: Fast-path cache and negative-lookup checks ===
    if namespaced_name in self._dg_tag_key_cache:
      return self._dg_tag_key_cache[namespaced_name]

    # === Step 2: List Tag Keys once per project and populate cache ===
    # Design Note: We avoid get_namespaced_tag_key because it frequently fails
    # with resource extraction errors (PermissionDenied/NotFound). Instead, we
    # list and cache all keys for the project, and record the project in
    # _listed_tag_key_projects so missing keys do not trigger re-listing.
    parts = namespaced_name.split("/")
    if len(parts) == 2:
      parent_id, _ = parts
      if parent_id in self._listed_tag_key_projects:
        return None
      parent = f"projects/{parent_id}"
      try:
        pager = self._dg_tag_keys_client.list_tag_keys(
            parent=parent, retry=RETRY_CONFIG
        )
        for key in pager:
          cached_namespaced_name = f"{parent_id}/{key.short_name}"
          self._dg_tag_key_cache[cached_namespaced_name] = key.name
        self._listed_tag_key_projects.add(parent_id)
        if namespaced_name in self._dg_tag_key_cache:
          return self._dg_tag_key_cache[namespaced_name]
      except Exception as e:
        logger.error("Failed to list tag keys for %s: %s", parent, e)
        raise
    return None

  def _get_dg_tag_value_id(self, namespaced_name: str) -> str | None:
    """Resolves a DG Tag Value resource name (`tagValues/<id>`) by path.

    What It Does & How It Works:
      1. Checks `_dg_tag_value_cache` for an $O(1)$ hit on `namespaced_name`.
      2. Validates that `namespaced_name` has at least 3 slash-separated
         segments (`<project_id>/<key_short_name>/<val_short_name>[/...]`).
      3. Recursively resolves the immediate parent (`tagKeys/<id>` for depth 1,
         or `tagValues/<id>` for nested Tag Values).
      4. If `parent_id` was already listed in `_listed_tag_value_parents`,
         returns `None` immediately without re-calling `list_tag_values`.
      5. Otherwise lists direct child Tag Values under `parent_id`, filters out
         any non-direct descendants (`tag_value.parent != parent_id`), caches
         all direct children, marks `parent_id` in `_listed_tag_value_parents`,
         and returns the resolved `tagValues/<id>` (or `None`).

    Args:
      namespaced_name: Hierarchical Tag Value namespaced name.

    Returns:
      The GCP Tag Value resource name (`tagValues/<id>`) if found, or `None`.

    Raises:
      Exception: Propagates any RPC error raised by `list_tag_values`.
    """
    # === Step 1: Fast-path cache check and path structure validation ===
    if namespaced_name in self._dg_tag_value_cache:
      return self._dg_tag_value_cache[namespaced_name]

    parts = namespaced_name.split("/")
    # A Tag Value namespaced name must have at least 3 parts:
    # {project_id}/{tag_key_short_name}/{tag_value_short_name}
    if len(parts) < 3:
      return None

    # === Step 2: Resolve immediate parent (Tag Key or parent Tag Value) ===
    parent_namespaced_name = "/".join(parts[:-1])

    parent_parts = parent_namespaced_name.split("/")
    if len(parent_parts) == 2:
      parent_id = self._get_dg_tag_key_id(parent_namespaced_name)
    elif len(parent_parts) >= 3:
      parent_id = self._get_dg_tag_value_id(parent_namespaced_name)
    else:
      parent_id = None

    # === Step 3: List direct child Tag Values once per parent_id ===
    if parent_id:
      if namespaced_name in self._dg_tag_value_cache:
        return self._dg_tag_value_cache[namespaced_name]
      if parent_id in self._listed_tag_value_parents:
        return None
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

  def _get_datapolicy_endpoint(self) -> str:
    """Determines the BigQuery Data Policy API base URL for `/v2/` REST calls.

    Inspects `self._data_policy_v2_client.transport.host` via
    `rest_utils.resolve_datapolicy_endpoint` so regional or test-universe
    endpoints configured on the GAPIC client are preserved when falling back to
    raw HTTP REST calls.

    Returns:
      Base HTTPS URL without a trailing slash.
    """
    return rest_utils.resolve_datapolicy_endpoint(self._data_policy_v2_client)

  def _get_data_policy_v2_rest(
      self, policy_resource_name: str
  ) -> dict[str, Any]:
    """Fetches a V2 Data Policy using the raw `/v2/` REST API with retries.

    Delegates to `DataPolicyRestClient.get_data_policy_v2` (`rest_utils.py`)
    with `not_found_behavior="raise_not_found"` so HTTP 404 raises
    `google.api_core.exceptions.NotFound` identically to the GAPIC client.

    Args:
      policy_resource_name: Full resource name
        `projects/<project>/locations/<region>/dataPolicies/<policy_id>`.

    Returns:
      Parsed JSON dictionary representing the V2 Data Policy resource.

    Raises:
      exceptions.NotFound: If the REST endpoint returns HTTP 404.
      RuntimeError: If a non-404 HTTP error or network error persists after
        retries.
    """
    self._rest_client.set_data_policy_client(self._data_policy_v2_client)
    result = self._rest_client.get_data_policy_v2(
        policy_resource_name, not_found_behavior="raise_not_found"
    )
    return result or {}

  def _delete_data_policy_v2_rest(self, policy_resource_name: str) -> None:
    """Deletes a V2 Data Policy using the raw `/v2/` REST API with retries.

    Delegates to `DataPolicyRestClient.delete_data_policy_v2` (`rest_utils.py`)
    so Application Default Credentials tokens are cached and HTTP 404 raises
    `google.api_core.exceptions.NotFound`.

    Args:
      policy_resource_name: Full resource name
        `projects/<project>/locations/<region>/dataPolicies/<policy_id>`.

    Raises:
      exceptions.NotFound: If the REST endpoint returns HTTP 404.
      RuntimeError: If a non-404 HTTP error or network error persists after
        retries.
    """
    self._rest_client.set_data_policy_client(self._data_policy_v2_client)
    self._rest_client.delete_data_policy_v2(policy_resource_name)

  def delete_dg_tag_key(self, namespaced_name: str) -> str:
    """Deletes a Data Governance Tag Key in GCP if it exists.

    What It Does & How It Works:
      1. Resolves `namespaced_name` (`<project_id>/<short_name>`) to its
         `tagKeys/<id>` via `_get_dg_tag_key_id`. Returns
         `DELETE_STATUS_SKIPPED` if absent.
      2. If `_dry_run` is True, logs the intended action and returns
         `DELETE_STATUS_WOULD_DELETE`.
      3. Calls `delete_tag_key` with `RETRY_CONFIG`, waits synchronously for
         the Long-Running Operation (`operation.result()`), evicts the deleted
         key from `_dg_tag_key_cache`, and returns `DELETE_STATUS_DELETED`.

    Args:
      namespaced_name: Project-scoped Tag Key (`<project_id>/<short_name>`).

    Returns:
      One of `DELETE_STATUS_DELETED`, `DELETE_STATUS_SKIPPED`, or
      `DELETE_STATUS_WOULD_DELETE`.

    Raises:
      Exception: Propagates any RPC or LRO error from `delete_tag_key`.
    """
    # === Step 1: Resolve Tag Key ID (idempotent skip if already absent) ===
    tag_key_id = self._get_dg_tag_key_id(namespaced_name)
    if not tag_key_id:
      logger.warning(
          "DG Tag Key %s not found, skipping deletion.", namespaced_name
      )
      return constants.DELETE_STATUS_SKIPPED

    # === Step 2: Short-circuit in dry-run mode ===
    if self._dry_run:
      logger.info(
          "[DRY RUN] Would delete DG Tag Key: %s (%s)",
          namespaced_name,
          tag_key_id,
      )
      return constants.DELETE_STATUS_WOULD_DELETE

    # === Step 3: Execute deletion LRO and evict from cache ===
    logger.info("Deleting DG Tag Key: %s (%s)", namespaced_name, tag_key_id)
    try:
      operation = self._dg_tag_keys_client.delete_tag_key(
          name=tag_key_id, retry=RETRY_CONFIG
      )
      # Wait for the Long Running Operation (LRO) to complete.
      # Deletion is asynchronous in GCP. Calling .result() blocks until the
      # operation is finalized, ensuring the resource is deleted before
      # proceeding.
      operation.result()
      self._dg_tag_key_cache.pop(namespaced_name, None)
      time.sleep(1)  # Allow time for deletion to propagate
      logger.info("Deleted DG Tag Key %s", namespaced_name)
      return constants.DELETE_STATUS_DELETED
    except Exception as e:
      logger.error(
          "Failed to delete DG Tag Key %s: %s",
          namespaced_name,
          _clean_exception_message(e),
      )
      raise

  def delete_dg_tag_value(self, namespaced_name: str) -> str:
    """Deletes a Data Governance Tag Value in GCP if it exists.

    What It Does & How It Works:
      1. Resolves `namespaced_name` (`<project_id>/<key>/<value>[/...]`) to its
         `tagValues/<id>` via `_get_dg_tag_value_id`. Returns
         `DELETE_STATUS_SKIPPED` if absent.
      2. If `_dry_run` is True, logs the intended action and returns
         `DELETE_STATUS_WOULD_DELETE`.
      3. Calls `delete_tag_value` with `RETRY_CONFIG`, waits synchronously for
         the Long-Running Operation (`operation.result()`), evicts the deleted
         value from `_dg_tag_value_cache`, and returns `DELETE_STATUS_DELETED`.

    Args:
      namespaced_name: Hierarchical Tag Value namespaced name.

    Returns:
      One of `DELETE_STATUS_DELETED`, `DELETE_STATUS_SKIPPED`, or
      `DELETE_STATUS_WOULD_DELETE`.

    Raises:
      Exception: Propagates any RPC or LRO error from `delete_tag_value`.
    """
    # === Step 1: Resolve Tag Value ID (idempotent skip if already absent) ===
    tag_value_id = self._get_dg_tag_value_id(namespaced_name)
    if not tag_value_id:
      logger.warning(
          "DG Tag Value %s not found, skipping deletion.", namespaced_name
      )
      return constants.DELETE_STATUS_SKIPPED

    # === Step 2: Short-circuit in dry-run mode ===
    if self._dry_run:
      logger.info(
          "[DRY RUN] Would delete DG Tag Value: %s (%s)",
          namespaced_name,
          tag_value_id,
      )
      return constants.DELETE_STATUS_WOULD_DELETE

    # === Step 3: Execute deletion LRO and evict from cache ===
    logger.info("Deleting DG Tag Value: %s (%s)", namespaced_name, tag_value_id)
    try:
      operation = self._dg_tag_values_client.delete_tag_value(
          name=tag_value_id, retry=RETRY_CONFIG
      )
      # Wait for the Long Running Operation (LRO) to complete.
      # Deletion is asynchronous in GCP. Calling .result() blocks until the
      # operation is finalized, ensuring the resource is deleted before
      # proceeding.
      operation.result()
      self._dg_tag_value_cache.pop(namespaced_name, None)
      time.sleep(1)  # Allow time for deletion to propagate
      logger.info("Deleted DG Tag Value %s", namespaced_name)
      return constants.DELETE_STATUS_DELETED
    except Exception as e:
      logger.error(
          "Failed to delete DG Tag Value %s: %s",
          namespaced_name,
          _clean_exception_message(e),
      )
      raise

  def delete_data_policy_v2(self, data_policy_v2_action: dict[str, Any]) -> str:
    """Deletes a V2 Data Policy in GCP if it exists.

    What It Does & How It Works:
      1. Extracts `policy_id`, `region`, and mandatory `target_project_id` from
         `data_policy_v2_action` to build the regional resource name
         `projects/<target_project_id>/locations/<region>/dataPolicies/<id>`.
      2. In dry-run mode, verifies whether the policy currently exists via
         `get_data_policy` (falling back to `_get_data_policy_v2_rest`),
         returning `DELETE_STATUS_WOULD_DELETE` or `DELETE_STATUS_SKIPPED`.
      3. In live mode, calls `delete_data_policy` (falling back to
         `_delete_data_policy_v2_rest`), treating `NotFound` idempotently as
         `DELETE_STATUS_SKIPPED` and returning `DELETE_STATUS_DELETED` on
         success.

    Args:
      data_policy_v2_action: Manifest dictionary describing the V2 Data Policy.

    Returns:
      One of `DELETE_STATUS_DELETED`, `DELETE_STATUS_SKIPPED`, or
      `DELETE_STATUS_WOULD_DELETE`.

    Raises:
      ValueError: If `target_project_id` is missing on `data_policy_v2_action`.
      Exception: Propagates any non-NotFound deletion error.
    """
    # === Step 1: Validate target project and construct resource name ===
    policy_id = data_policy_v2_action[constants.FIELD_POLICY_ID]
    region = data_policy_v2_action[constants.FIELD_REGION]
    # Extract target project ID. Must be explicit in action.
    target_project_id = data_policy_v2_action.get(
        constants.FIELD_TARGET_PROJECT_ID
    )
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

    # === Step 2: Dry-run existence probe with V2 REST fallback ===
    if self._dry_run:
      try:
        if self._data_policy_v2_client is None:
          raise AttributeError("Data Policy V2 client is not initialized.")
        try:
          self._data_policy_v2_client.get_data_policy(
              name=policy_name, retry=RETRY_CONFIG
          )
        except (
            AttributeError,
            TypeError,
            exceptions.InvalidArgument,
            exceptions.FailedPrecondition,
            exceptions.Unknown,
        ) as client_error:
          logger.warning(
              "Falling back to V2 REST API to inspect Data Policy %s: %s",
              policy_name,
              client_error,
          )
          self._get_data_policy_v2_rest(policy_name)
        logger.info("[DRY RUN] Would delete Data Policy V2: %s", policy_name)
        return constants.DELETE_STATUS_WOULD_DELETE
      except exceptions.NotFound:
        logger.warning(
            "Data Policy V2 %s not found, would skip deletion.", policy_name
        )
        return constants.DELETE_STATUS_SKIPPED

    # === Step 3: Live deletion with V2 REST fallback & idempotent 404 ===
    logger.info("Deleting Data Policy V2: %s", policy_name)
    try:
      if self._data_policy_v2_client is None:
        raise AttributeError("Data Policy V2 client is not initialized.")
      try:
        self._data_policy_v2_client.delete_data_policy(
            name=policy_name, retry=RETRY_CONFIG
        )
      except (
          AttributeError,
          TypeError,
          exceptions.InvalidArgument,
          exceptions.FailedPrecondition,
          exceptions.Unknown,
      ) as client_error:
        logger.warning(
            "Falling back to V2 REST API to delete Data Policy %s: %s",
            policy_name,
            client_error,
        )
        self._delete_data_policy_v2_rest(policy_name)
      logger.info("Deleted Data Policy V2 %s", policy_name)
      return constants.DELETE_STATUS_DELETED
    except exceptions.NotFound:
      logger.warning(
          "Data Policy V2 %s not found, skipping deletion.", policy_name
      )
      return constants.DELETE_STATUS_SKIPPED
    except Exception as e:
      logger.error(
          "Failed to delete Data Policy V2 %s: %s",
          policy_name,
          _clean_exception_message(e),
      )
      raise

  def _check_data_policy_dependents(
      self,
      action: dict[str, Any],
      category_key: str | None = None,
  ) -> list[str]:
    """Returns Fail-Open and column-binding warnings for policy deletion.

    Why This Matters (Security Invariant):
      In Google Cloud Data Governance Tags, a Tag Value bound to a BigQuery
      table column enforces access control or data masking ONLY through the V2
      Data Policies attached to that Tag Value. If all V2 Data Policies (or the
      Default-Deny safety-net policy) on a bound Tag Value are deleted while
      the Tag Value remains attached to table columns, those columns
      immediately revert to Default Allow (Fail-Open).

    Args:
      action: Manifest dictionary describing the V2 Data Policy.
      category_key: Optional manifest category key (e.g.,
        `KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2`).

    Returns:
      List of human-readable Fail-Open warning strings.
    """
    # === Step 1: Extract policy resource name and governed Tag Value path ===
    issues: list[str] = []
    policy_id = action.get(constants.FIELD_POLICY_ID, "")
    region = action.get(constants.FIELD_REGION, "")
    target_project_id = action.get(constants.FIELD_TARGET_PROJECT_ID, "")
    if target_project_id and region:
      policy_name = (
          f"projects/{target_project_id}/locations/{region}/"
          f"dataPolicies/{policy_id}"
      )
    else:
      policy_name = policy_id
    tag_value_namespaced = action.get(
        constants.FIELD_DG_TAG_VALUE_NAMESPACED_NAME, ""
    )
    if not tag_value_namespaced:
      dg_tag_spec = action.get(constants.FIELD_API_PAYLOAD, {}).get(
          "data_governance_tag", {}
      ) or action.get(constants.FIELD_API_PAYLOAD, {}).get(
          "dataGovernanceTag", {}
      )
      if isinstance(dg_tag_spec, dict):
        key_part = dg_tag_spec.get("key", "")
        val_part = dg_tag_spec.get("value", "")
        if key_part and val_part:
          tag_value_namespaced = f"{key_part}/{val_part}"

    # === Step 2: Emit tailored Fail-Open warning for Default-Deny vs standard =
    if (
        category_key
        == constants.KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2
        or policy_id.endswith(constants.SUFFIX_DEFAULT_DENY_POLICY)
    ):
      target_label = tag_value_namespaced or "its Data Governance Tag Value"
      issues.append(
          f"[WARNING - FAIL-OPEN RISK] Data Policy `{policy_name}` is a"
          f" Default-Deny safety-net policy for `{target_label}`. If"
          f" `{target_label}` is currently bound to any BigQuery table"
          " columns, deleting its Default-Deny Data Policy without another"
          " active policy on that Tag Value will cause those columns to revert"
          " to Default Allow (Fail-Open)."
      )
    elif tag_value_namespaced:
      issues.append(
          f"[WARNING - FAIL-OPEN RISK] Verify whether `{tag_value_namespaced}`"
          " is currently bound to any BigQuery table columns before deleting"
          f" V2 Data Policy `{policy_name}`. Removing all V2 Data Policies"
          " from a bound Data Governance Tag Value causes governed columns to"
          " revert to Default Allow (Fail-Open)."
      )
    return issues

  def _format_policy_identifier(self, policy_action: dict[str, Any]) -> str:
    """Formats a V2 Data Policy action as `<target_project_id>/<policy_id>`.

    Qualifying every V2 Data Policy with its `target_project_id` eliminates
    duplicate bare policy IDs in Mode 2 (`TABLE_PARENT_PROJECTS`) and ensures
    names printed in dependency warnings can be passed directly to
    `--phase delete --resource-type data-policy-v2 --resource-name`.

    Args:
      policy_action: Manifest dictionary describing a planned V2 Data Policy.

    Returns:
      Project-qualified `<target_project_id>/<policy_id>` when
      `target_project_id` is present, or bare `<policy_id>` otherwise.
    """
    policy_id = str(policy_action.get(constants.FIELD_POLICY_ID, ""))
    target_project_id = str(
        policy_action.get(constants.FIELD_TARGET_PROJECT_ID, "")
    )
    if target_project_id and policy_id:
      return f"{target_project_id}/{policy_id}"
    return policy_id

  def _find_referencing_policy_actions(
      self,
      manifest: dict[str, Any],
      resource_name: str,
  ) -> list[dict[str, Any]]:
    """Finds all V2 Data Policy actions in `manifest` referencing a Tag Value.

    Args:
      manifest: The `phase_2_resource_manifest` dictionary from `plan.json`.
      resource_name: Hierarchical namespaced name of the target DG Tag Value.

    Returns:
      List of matching V2 Data Policy action dictionaries across all 3 policy
      categories (`raw_reader`, `default_deny`, and `v1_to_v2`).
    """
    matched_actions: list[dict[str, Any]] = []
    data_policy_categories = [
        constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2,
        constants.KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2,
        constants.KEY_DATA_POLICIES_V1_TO_DATA_POLICIES_V2,
    ]
    for policy_category in data_policy_categories:
      for policy_action in manifest.get(policy_category, []):
        matched_value = (
            policy_action.get(constants.FIELD_DG_TAG_VALUE_NAMESPACED_NAME)
            == resource_name
        )
        if not matched_value:
          dg_tag_spec = policy_action.get(constants.FIELD_API_PAYLOAD, {}).get(
              "data_governance_tag", {}
          ) or policy_action.get(constants.FIELD_API_PAYLOAD, {}).get(
              "dataGovernanceTag", {}
          )
          if isinstance(dg_tag_spec, dict):
            key_part = dg_tag_spec.get("key", "")
            val_part = dg_tag_spec.get("value", "")
            if key_part and val_part:
              matched_value = resource_name in (f"{key_part}/{val_part}",) or (
                  resource_name.startswith(f"{key_part}/")
                  and resource_name.split("/")[-1] == val_part
              )
        if matched_value:
          matched_actions.append(policy_action)
    return matched_actions

  def _data_policy_v2_exists(
      self, policy_action: dict[str, Any]
  ) -> bool | None:
    """Probes whether a planned V2 Data Policy currently exists in GCP.

    Args:
      policy_action: Manifest dictionary describing a V2 Data Policy.

    Returns:
      `True` if the V2 Data Policy exists in GCP, `False` if GCP returns
      `404 NotFound`, or `None` if `policy_action` lacks `target_project_id` or
      `region` metadata required to construct a regional resource path.
    """
    policy_id = policy_action.get(constants.FIELD_POLICY_ID)
    region = policy_action.get(constants.FIELD_REGION)
    target_project_id = policy_action.get(constants.FIELD_TARGET_PROJECT_ID)
    if not (policy_id and region and target_project_id):
      return None

    policy_name = (
        f"projects/{target_project_id}/locations/{region}/"
        f"dataPolicies/{policy_id}"
    )
    try:
      if self._data_policy_v2_client is None:
        raise AttributeError("Data Policy V2 client is not initialized.")
      try:
        self._data_policy_v2_client.get_data_policy(
            name=policy_name, retry=RETRY_CONFIG
        )
      except (
          AttributeError,
          TypeError,
          exceptions.InvalidArgument,
          exceptions.FailedPrecondition,
          exceptions.Unknown,
      ) as client_error:
        logger.warning(
            "Falling back to V2 REST API to inspect Data Policy %s: %s",
            policy_name,
            client_error,
        )
        self._get_data_policy_v2_rest(policy_name)
      return True
    except exceptions.NotFound:
      return False

  def _format_child_tag_value_names(
      self,
      parent_namespaced_name: str,
      child_values: list[Any],
      parent_id: str | None = None,
  ) -> list[str]:
    """Formats live child `TagValue` objects as hierarchical paths for reports.

    Cloud Resource Manager populates `TagValue.namespaced_name` as a flat
    3-segment `<project>/<tag_key_short>/<value_short>` string even for nested
    Tag Values, and `list_tag_values(parent="tagKeys/...")` returns all
    descendants under the Tag Key. This helper walks `child.parent` pointers
    using `short_name` to reconstruct full hierarchical paths matching
    `plan.json` and `Analyzer._analyze_static_dgt`.

    Args:
      parent_namespaced_name: Full hierarchical namespaced name of the parent
        Tag Key or Tag Value.
      child_values: Sequence of child/descendant `TagValue` objects returned by
        `list_tag_values`.
      parent_id: Optional resource name (`tagKeys/<id>` or `tagValues/<id>`) of
        the listed parent used as the root stop condition when walking nested
        `parent` chains.

    Returns:
      Deduplicated list of hierarchical child Tag Value namespaced names.
    """
    values_by_id: dict[str, Any] = {}
    for child in child_values:
      child_id = getattr(child, "name", None)
      if isinstance(child_id, str) and child_id:
        values_by_id[child_id] = child

    formatted_names: list[str] = []
    for child in child_values:
      namespaced = getattr(child, "namespaced_name", None)
      short_name = getattr(child, "short_name", None)
      raw_name = getattr(child, "name", None)
      if isinstance(short_name, str) and short_name:
        short_chain: list[str] = [short_name]
        current_parent = getattr(child, "parent", None)
        visited: set[str] = set()
        if isinstance(raw_name, str) and raw_name:
          visited.add(raw_name)
        reached_root = (
            not parent_id
            or not isinstance(current_parent, str)
            or not current_parent
            or current_parent == parent_id
        )
        while (
            not reached_root
            and isinstance(current_parent, str)
            and current_parent in values_by_id
            and current_parent not in visited
        ):
          visited.add(current_parent)
          parent_obj = values_by_id[current_parent]
          parent_short = getattr(parent_obj, "short_name", None)
          if not isinstance(parent_short, str) or not parent_short:
            break
          short_chain.append(parent_short)
          current_parent = getattr(parent_obj, "parent", None)
          if current_parent == parent_id:
            reached_root = True
        if reached_root:
          label = f"{parent_namespaced_name}/{'/'.join(reversed(short_chain))}"
        elif isinstance(namespaced, str) and namespaced:
          label = namespaced
        else:
          label = f"{parent_namespaced_name}/{'/'.join(reversed(short_chain))}"
      elif isinstance(namespaced, str) and namespaced:
        label = namespaced
      elif isinstance(raw_name, str) and raw_name:
        label = raw_name
      else:
        label = str(child)
      if label not in formatted_names:
        formatted_names.append(label)
    return formatted_names

  def _check_tag_value_plan_dependents(
      self,
      manifest: dict[str, Any],
      resource_name: str,
  ) -> list[str]:
    """Checks `plan.json` for active child Tag Values and V2 Data Policies.

    What It Does & Why:
      Before deleting a Data Governance Tag Value (`resource_name`) in either
      dry-run or live mode, inspects `phase_2_resource_manifest` in `plan.json`
      for:
      1. Planned child DG Tag Values whose `parent_namespaced_name` equals
         `resource_name` (filtering out children already deleted in GCP when
         the parent Tag Value exists in GCP).
      2. Planned V2 Data Policies across all three policy categories whose
         `dg_tag_value_namespaced_name` (or `api_payload.data_governance_tag`)
         references `resource_name` (formatted as
         `<target_project_id>/<policy_id>` and filtering out policies that have
         already been deleted in GCP when regional metadata is present).
      Surfacing these warnings before the interactive confirmation prompt and
      in the deletion report prevents operators from attempting out-of-order
      top-down deletions that GCP will reject with `FailedPrecondition`, while
      avoiding false warnings after dependent policies or child values have
      already been deleted bottom-up.

    Args:
      manifest: The `phase_2_resource_manifest` dictionary from `plan.json`.
      resource_name: Hierarchical namespaced name of the target DG Tag Value.

    Returns:
      List of dependency warning messages discovered in `plan.json`.
    """
    warnings: list[str] = []

    # === Step 1: Check for child Tag Values with parent_namespaced_name ===
    planned_child_values: list[str] = []
    for value_action in manifest.get(
        constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES, []
    ):
      if (
          value_action.get(constants.FIELD_PARENT_NAMESPACED_NAME)
          == resource_name
      ):
        child_name = value_action.get(constants.FIELD_NAMESPACED_NAME, "")
        if child_name:
          planned_child_values.append(child_name)

    child_tag_values: list[str] = []
    if planned_child_values:
      parent_id = self._get_dg_tag_value_id(resource_name)
      if parent_id is not None:
        for child_name in planned_child_values:
          if self._get_dg_tag_value_id(child_name) is not None:
            child_tag_values.append(child_name)
      else:
        child_tag_values = list(planned_child_values)

    if child_tag_values:
      warnings.append(
          f"The migration plan defines {len(child_tag_values)} child DG Tag"
          f" Value(s) ({', '.join(child_tag_values)}) with"
          f" parent_namespaced_name `{resource_name}`. Delete leaf child DG"
          " Tag Values before deleting parent Tag Values, otherwise GCP will"
          " reject the deletion."
      )

    # === Step 2: Check for V2 Data Policies referencing this Tag Value ===
    referencing_policies: list[str] = []
    for policy_action in self._find_referencing_policy_actions(
        manifest, resource_name
    ):
      exists = self._data_policy_v2_exists(policy_action)
      if exists is not None and not exists:
        continue
      policy_label = self._format_policy_identifier(policy_action)
      if policy_label and policy_label not in referencing_policies:
        referencing_policies.append(policy_label)

    if referencing_policies:
      warnings.append(
          f"The migration plan defines {len(referencing_policies)} V2 Data"
          f" Policy resource(s) ({', '.join(referencing_policies)})"
          f" referencing DG Tag Value `{resource_name}`. Ensure all V2 Data"
          " Policies and BigQuery column bindings referencing this DG Tag"
          " Value are removed before deleting the Tag Value, otherwise GCP"
          " will reject the deletion."
      )
    return warnings

  def _inspect_dry_run_deletion(
      self,
      plan: dict[str, Any],
      action: dict[str, Any],
      resource_name: str,
      resource_type: str,
      category_key: str | None = None,
  ) -> tuple[str, str, list[str]]:
    """Checks live GCP state and deletion dependencies in dry-run mode.

    What It Does & How It Works:
      1. For `RESOURCE_TYPE_DG_TAG_KEY`: Resolves `tag_key_id`. If absent in
         GCP, returns `DELETE_STATUS_SKIPPED` with zero warnings. Otherwise
         lists child Tag Values under `tag_key_id`; if any exist, returns
         `DELETE_STATUS_BLOCKED` naming the blocking child Tag Values;
         otherwise returns `DELETE_STATUS_WOULD_DELETE`.
      2. For `RESOURCE_TYPE_DG_TAG_VALUE`: Resolves `tag_value_id` (returning
         `DELETE_STATUS_SKIPPED` with zero warnings if absent), and checks for
         live child Tag Values under `tag_value_id` and live referencing V2
         Data Policies from `plan.json` (`BLOCKED` if either live dependency
         exists, or `WOULD_DELETE` otherwise).
      3. For `RESOURCE_TYPE_DATA_POLICY_V2`: Probes live policy existence via
         `get_data_policy` / `_get_data_policy_v2_rest` (`WOULD_DELETE` with
         Fail-Open warnings vs `SKIPPED` with zero warnings).

    Args:
      plan: Parsed `plan.json` dictionary.
      action: Matched manifest dictionary for the target resource.
      resource_name: Target resource identifier passed on the CLI.
      resource_type: Target resource type (`dg_tag_key`, `dg_tag_value`, or
        `data_policy_v2`).
      category_key: Optional manifest category key for V2 Data Policies.

    Returns:
      Tuple `(status, detail, potential_issues)`.

    Raises:
      ValueError: If `target_project_id` is missing on a V2 Data Policy action.
    """
    potential_issues: list[str] = []
    manifest = plan.get(constants.KEY_PHASE_2_RESOURCE_MANIFEST, {})

    # === Case 1: Dry-run inspection for DG Tag Key ===
    if resource_type == constants.RESOURCE_TYPE_DG_TAG_KEY:
      tag_key_id = self._get_dg_tag_key_id(resource_name)
      if not tag_key_id:
        return (
            constants.DELETE_STATUS_SKIPPED,
            f"DG Tag Key `{resource_name}` not found in GCP.",
            [],
        )
      child_values = list(
          self._dg_tag_values_client.list_tag_values(
              parent=tag_key_id, retry=RETRY_CONFIG
          )
      )
      if child_values:
        child_names = self._format_child_tag_value_names(
            resource_name, child_values, parent_id=tag_key_id
        )
        child_names_str = ", ".join(child_names)
        potential_issues.append(
            f"DG Tag Key `{resource_name}` ({tag_key_id}) currently has"
            f" {len(child_values)} live child DG Tag Value(s) in GCP"
            f" ({child_names_str}). GCP Resource Manager rejects deleting a"
            " Tag Key while child Tag Values exist. Delete V2 Data Policies"
            " and child DG Tag Values first (bottom-up deletion sequence)."
        )
        return (
            constants.DELETE_STATUS_BLOCKED,
            (
                f"Blocked by {len(child_values)} existing child DG Tag"
                f" Value(s) ({child_names_str}) under `{resource_name}`"
                f" ({tag_key_id})."
            ),
            potential_issues,
        )
      return (
          constants.DELETE_STATUS_WOULD_DELETE,
          f"Would delete DG Tag Key `{resource_name}` ({tag_key_id}).",
          potential_issues,
      )

    # === Case 2: Dry-run inspection for DG Tag Value ===
    if resource_type == constants.RESOURCE_TYPE_DG_TAG_VALUE:
      resolved_tag_value_name = (
          action.get(constants.FIELD_NAMESPACED_NAME) or resource_name
      )
      tag_value_id = self._get_dg_tag_value_id(resolved_tag_value_name)
      if not tag_value_id:
        return (
            constants.DELETE_STATUS_SKIPPED,
            f"DG Tag Value `{resource_name}` not found in GCP.",
            [],
        )

      child_values = list(
          self._dg_tag_values_client.list_tag_values(
              parent=tag_value_id, retry=RETRY_CONFIG
          )
      )
      for child_val in child_values:
        child_short = getattr(child_val, "short_name", None)
        child_name_id = getattr(child_val, "name", None)
        if (
            isinstance(child_short, str)
            and child_short
            and isinstance(child_name_id, str)
        ):
          self._dg_tag_value_cache[
              f"{resolved_tag_value_name}/{child_short}"
          ] = child_name_id
      self._listed_tag_value_parents.add(tag_value_id)

      live_referencing_policies: list[str] = []
      unprobed_plan_policies: list[str] = []
      for policy_action in self._find_referencing_policy_actions(
          manifest, resolved_tag_value_name
      ):
        policy_label = self._format_policy_identifier(policy_action)
        exists = self._data_policy_v2_exists(policy_action)
        if exists:
          if policy_label not in live_referencing_policies:
            live_referencing_policies.append(policy_label)
        elif exists is None:
          if policy_label not in unprobed_plan_policies:
            unprobed_plan_policies.append(policy_label)

      blocker_parts: list[str] = []
      if child_values:
        child_names = self._format_child_tag_value_names(
            resolved_tag_value_name, child_values, parent_id=tag_value_id
        )
        child_names_str = ", ".join(child_names)
        potential_issues.append(
            f"DG Tag Value `{resource_name}` ({tag_value_id}) currently has"
            f" {len(child_values)} live child DG Tag Value(s) in GCP"
            f" ({child_names_str}). Delete leaf child DG Tag Values before"
            " deleting parent Tag Values."
        )
        blocker_parts.append(
            f"{len(child_values)} existing child DG Tag Value(s)"
            f" ({child_names_str})"
        )

      if live_referencing_policies:
        live_policies_str = ", ".join(live_referencing_policies)
        potential_issues.append(
            f"DG Tag Value `{resource_name}` ({tag_value_id}) is currently"
            f" referenced by {len(live_referencing_policies)} live V2 Data"
            f" Policy resource(s) in GCP ({live_policies_str}). Delete all"
            " referencing V2 Data Policies and remove BigQuery column"
            " bindings before deleting the Tag Value, otherwise GCP will"
            " reject the deletion."
        )
        blocker_parts.append(
            f"{len(live_referencing_policies)} live referencing V2 Data"
            f" Policy resource(s) ({live_policies_str})"
        )

      if unprobed_plan_policies:
        potential_issues.append(
            f"The migration plan defines {len(unprobed_plan_policies)} V2 Data"
            f" Policy resource(s) ({', '.join(unprobed_plan_policies)})"
            f" referencing DG Tag Value `{resolved_tag_value_name}`. Ensure"
            " all V2 Data Policies and BigQuery column bindings referencing"
            " this DG Tag Value are removed before deleting the Tag Value,"
            " otherwise GCP will reject the deletion."
        )

      if blocker_parts:
        return (
            constants.DELETE_STATUS_BLOCKED,
            (
                f"Blocked by {' and '.join(blocker_parts)} under"
                f" `{resource_name}` ({tag_value_id})."
            ),
            potential_issues,
        )
      return (
          constants.DELETE_STATUS_WOULD_DELETE,
          f"Would delete DG Tag Value `{resource_name}` ({tag_value_id}).",
          potential_issues,
      )

    # === Case 3: Dry-run inspection for Data Policy V2 ===
    policy_id = action[constants.FIELD_POLICY_ID]
    region = action[constants.FIELD_REGION]
    target_project_id = action.get(constants.FIELD_TARGET_PROJECT_ID)
    if not target_project_id:
      raise ValueError(
          f"Missing 'target_project_id' for Data Policy {policy_id}. Please"
          " generate a new migration plan with explicit target_project_id."
      )
    policy_name = (
        f"projects/{target_project_id}/locations/{region}/"
        f"dataPolicies/{policy_id}"
    )

    if self._data_policy_v2_exists(action):
      potential_issues.extend(
          self._check_data_policy_dependents(action, category_key)
      )
      return (
          constants.DELETE_STATUS_WOULD_DELETE,
          f"Would delete Data Policy V2 `{policy_name}`.",
          potential_issues,
      )
    return (
        constants.DELETE_STATUS_SKIPPED,
        f"Data Policy V2 `{policy_name}` not found in GCP.",
        [],
    )

  def _generate_delete_report(
      self,
      resource_name: str,
      resource_type: str,
      status: str,
      detail: str,
      potential_issues: list[str],
      report_file: str | None = None,
  ) -> str:
    """Generates a Markdown report for resource deletion or dry-run preview.

    Args:
      resource_name: Target resource identifier.
      resource_type: Target resource type (`dg_tag_key`, `dg_tag_value`, or
        `data_policy_v2`).
      status: Deletion outcome (`DELETED`, `SKIPPED`, `WOULD_DELETE`, `BLOCKED`,
        or `FAILED`).
      detail: Human-readable explanation of the deletion outcome.
      potential_issues: List of dependency or Fail-Open warning strings.
      report_file: Optional file path where the Markdown report is written.

    Returns:
      Formatted Markdown report string.
    """
    # === Step 1: Assemble Markdown header and summary metadata ===
    lines: list[str] = []
    if self._dry_run:
      lines.append("# Resource Deletion Report (DRY RUN)")
      lines.append("")
      lines.append(
          "**DRY RUN MODE**: No resources were deleted in Google Cloud. This"
          " report previews the deletion outcome and any potential dependency"
          " or security issues."
      )
    else:
      lines.append("# Resource Deletion Report")
    lines.append("")
    lines.append("## Summary")
    lines.append(f"- **Resource Type**: `{resource_type}`")
    lines.append(f"- **Resource Identifier**: `{resource_name}`")
    lines.append(f"- **Status**: **{status}**")
    lines.append(f"- **Details**: {detail}")
    lines.append(f"- **Potential Issues Detected**: {len(potential_issues)}")
    lines.append("")

    # === Step 2: Append potential issues and warnings section ===
    if potential_issues:
      lines.append("## Potential Issues & Warnings")
      for issue in potential_issues:
        lines.append(f"- **WARNING**: {issue}")
      lines.append("")

    # Explain non-success error/block status enums when encountered so operators
    # know how to unblock or remediate deletion safely.
    delete_error_descriptions = {
        constants.DELETE_STATUS_BLOCKED: (
            "Deletion was blocked before mutating Google Cloud either because"
            " (1) live `data-policy-v2` deletion requires"
            " `--allow-fail-open-policy-delete` after verifying zero BigQuery"
            " columns remain bound to the policy's Data Governance Tag Value"
            " (BigQuery does not check table column references when deleting"
            " tag-based V2 Data Policies, so deleting a `_default_deny` or"
            " access policy while columns remain bound can immediately expose"
            " restricted data), or (2) `--dry-run` dependency verification"
            " found active child Tag Values or live"
            " referencing V2 Data Policies in `plan.json` that must be deleted"
            " first (bottom-up order: detach column bindings -> V2 Data"
            " Policies -> leaf Tag Values -> parent Tag Values -> Tag Keys)."
            " Run `--phase analyze --analyze-type column-binding"
            " --verbose-bindings` to audit active BigQuery column bindings and"
            " `--phase analyze --analyze-type static-dgt` to inspect live tags"
            " and policies."
        ),
        "FAILED": (
            "The live Google Cloud deletion API call failed (for example,"
            " missing IAM permissions, or global Cloud Resource Manager"
            " `400 FAILED_PRECONDITION` enforcement when any BigQuery column"
            " or V2 Data Policy in any project still references the Tag Value,"
            " or when child Tag Values still exist). To remediate before"
            " retrying deletion: (1) run `--phase analyze --analyze-type"
            " column-binding --verbose-bindings` to locate BigQuery columns"
            " still bound to the Tag Value; (2) run `--phase swap --swap-mode"
            " dgt-to-pt` (or detach non-migrated column bindings in BigQuery)"
            " to remove active DGT column bindings (note that BigQuery"
            " soft-deleted tables within the Time Travel window also retain"
            " tag bindings until recreated and deleted without DGT bindings);"
            " and (3) run `--phase analyze --analyze-type static-dgt` or"
            " delete any remaining `--resource-type data-policy-v2` resources"
            " referencing the Tag Value. Inspect `Details` above and"
            " `--log-file` for the exact API error."
        ),
    }
    if status in delete_error_descriptions:
      lines.append("## Error & Block Status Reference")
      lines.append(f"- **`{status}`**: {delete_error_descriptions[status]}")
      lines.append("")

    # === Step 3: Persist report to disk when report_file is specified ===
    report_content = "\n".join(lines)
    if report_file:
      try:
        with open(report_file, "w", encoding="utf-8") as file_handle:
          file_handle.write(_ensure_trailing_newline(report_content))
        logger.info("Deletion report saved to %s", report_file)
      except IOError as error:
        logger.error(
            "Failed to write deletion report to %s: %s", report_file, error
        )
    return report_content

  _generate_markdown_report = _generate_delete_report

  def _target_exists_before_delete(
      self,
      matched_action: dict[str, Any],
      resource_name: str,
      resource_type: str,
  ) -> bool | None:
    """Best-effort existence check before emitting `--skip-confirmation` warns.

    Why This Exists:
      Under `--skip-confirmation`, Fail-Open and dependency warnings must be
      logged *before* the live delete RPC runs so operators and audit logs see
      the risk prior to mutation, yet already-absent resources (`SKIPPED`)
      must not emit false Fail-Open warnings. Probing existence first preserves
      both invariants while falling back to `None` (conservative warn) on any
      non-404 probe error.

    Args:
      matched_action: Manifest action dictionary for the target resource.
      resource_name: Operator-supplied resource identifier.
      resource_type: Normalized resource type constant.

    Returns:
      `True` if the target exists, `False` if confirmed absent (`NotFound`), or
      `None` if existence could not be determined without failing the delete.
    """
    try:
      if resource_type == constants.RESOURCE_TYPE_DATA_POLICY_V2:
        return self._data_policy_v2_exists(matched_action)
      if resource_type == constants.RESOURCE_TYPE_DG_TAG_VALUE:
        resolved_name = (
            matched_action.get(constants.FIELD_NAMESPACED_NAME) or resource_name
        )
        return self._get_dg_tag_value_id(resolved_name) is not None
      if resource_type == constants.RESOURCE_TYPE_DG_TAG_KEY:
        return self._get_dg_tag_key_id(resource_name) is not None
    except Exception:  # pylint: disable=broad-exception-caught
      return None
    return None

  def _execute_and_report_deletion(
      self,
      plan: dict[str, Any],
      matched_action: dict[str, Any],
      resource_name: str,
      resource_type: str,
      display_label: str,
      delete_callable: Callable[[], Any],
      pre_delete_warnings: list[str],
      report_file: str | None = None,
      category_key: str | None = None,
  ) -> str:
    """Runs dry-run inspection or live deletion and writes the delete report.

    Consolidates status normalization, skipped-vs-deleted detail messages,
    non-interactive warning logging, and `_generate_delete_report` rendering
    across all three supported resource types.

    Args:
      plan: Parsed migration plan dictionary.
      matched_action: Matched manifest action dictionary for the resource.
      resource_name: Operator-supplied resource identifier.
      resource_type: Normalized resource type constant.
      display_label: Human-readable resource type + identifier label used in
        report detail strings (e.g., ``"DG Tag Key `proj/key`"``).
      delete_callable: Zero-arg callable performing live deletion of the target.
      pre_delete_warnings: Pre-computed safety warnings for live deletion.
      report_file: Optional file path for the Markdown deletion report.
      category_key: Optional manifest section key for V2 Data Policies.

    Returns:
      Rendered Markdown deletion report string.
    """
    if self._dry_run:
      status, detail, issues = self._inspect_dry_run_deletion(
          plan,
          matched_action,
          resource_name,
          resource_type,
          category_key=category_key,
      )
    else:
      if self._skip_confirmation and pre_delete_warnings:
        # Log Fail-Open / dependency warnings *before* mutating GCP whenever
        # the target is not confirmed absent, so audit trails never print the
        # warning only after deletion has already succeeded.
        target_exists = self._target_exists_before_delete(
            matched_action, resource_name, resource_type
        )
        if target_exists is None or target_exists:
          for warning_msg in pre_delete_warnings:
            logger.warning("%s", warning_msg)
          self._emitted_skip_confirmation_warnings = True

      raw_status = delete_callable()
      status = (
          raw_status
          if isinstance(raw_status, str)
          else constants.DELETE_STATUS_DELETED
      )
      detail = (
          f"{display_label} not found in GCP."
          if status == constants.DELETE_STATUS_SKIPPED
          else f"Deleted {display_label}."
      )
      issues = (
          []
          if status == constants.DELETE_STATUS_SKIPPED
          else list(pre_delete_warnings)
      )
    self.last_report = self._generate_delete_report(
        resource_name,
        resource_type,
        status,
        detail,
        issues,
        report_file=report_file,
    )
    return self.last_report

  def delete_individual_dgt_resource(
      self,
      plan: dict[str, Any],
      resource_name: str,
      resource_type: str,
      report_file: str | None = None,
  ) -> str | None:
    """Deletes a single DGT resource by name (or previews in dry-run mode).

    What It Does & How It Works:
      1. Looks up `resource_name` under the corresponding `resource_type`
         section in `plan["phase_2_resource_manifest"]`. For V2 Data Policies,
         strictly requires `<target_project_id>/<data_policy_id>` in both Mode
         1 (`DEFAULT_DATA_POLICY_PROJECT`) and Mode 2
         (`TABLE_PARENT_PROJECTS`), raising `ValueError` before prompting if an
         unqualified `<data_policy_id>` or malformed identifier is passed.
      2. Computes `pre_delete_warnings`:
         - For `RESOURCE_TYPE_DG_TAG_VALUE`: checks `plan.json` for child Tag
           Values (`parent_namespaced_name == resource_name`) and referencing
           V2 Data Policies (`_check_tag_value_plan_dependents`).
         - For `RESOURCE_TYPE_DATA_POLICY_V2`: checks for Default-Deny and
           column-binding Fail-Open risks (`_check_data_policy_dependents`).
      3. In live mode, emits all `pre_delete_warnings` before prompting for
         interactive confirmation (mirroring to stdout only when the logger is
         not already writing to the same console stream) or, under
         `_skip_confirmation`, immediately before invoking the live delete RPC
         whenever the target resource is not confirmed absent (`SKIPPED`).
      4. Executes dry-run inspection (`_inspect_dry_run_deletion`) or live
         deletion (`delete_dg_tag_key`, `delete_dg_tag_value`, or
         `delete_data_policy_v2`). If live deletion raises an exception,
         records a `FAILED` report on `self.last_report` (and writes it to
         `report_file` when provided) before re-raising the exception.

    Args:
      plan: Parsed `plan.json` dictionary.
      resource_name: Identifier of the resource to delete.
      resource_type: Resource type (`dg_tag_key`, `dg_tag_value`, or
        `data_policy_v2`).
      report_file: Optional path to save the Markdown deletion report.

    Returns:
      Markdown deletion report string, or `None` if aborted at the interactive
      confirmation prompt.

    Raises:
      ValueError: If `plan` has an invalid or unsupported `schema_version`, if
        the resource is not found in `plan.json`, or if a V2 Data Policy name
        is ambiguous across multiple Mode 2 target projects.
      Exception: Re-raises any live deletion error after writing the failure
        report to `report_file` (when specified).
    """
    # === Step 1: Locate target resource in plan.json & collect warnings ===
    self.last_report = None
    self._emitted_skip_confirmation_warnings = False
    constants.validate_plan_schema_version(plan)
    if "/" in resource_name:
      constants.validate_standard_project_id(
          resource_name.split("/")[0], "--resource-name project_id"
      )
    manifest = plan.get(constants.KEY_PHASE_2_RESOURCE_MANIFEST, {})
    matched_action: dict[str, Any] | None = None
    matched_category_key: str | None = None
    pre_delete_warnings: list[str] = []

    if resource_type == constants.RESOURCE_TYPE_DG_TAG_KEY:
      for action in manifest.get(constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS, []):
        if action[constants.FIELD_NAMESPACED_NAME] == resource_name:
          matched_action = action
          break
    elif resource_type == constants.RESOURCE_TYPE_DG_TAG_VALUE:
      tag_value_actions = manifest.get(
          constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES, []
      )
      for action in tag_value_actions:
        if action[constants.FIELD_NAMESPACED_NAME] == resource_name:
          matched_action = action
          break
      if matched_action is None and len(resource_name.split("/")) == 3:
        # Also match a unique nested Tag Value when the caller supplies the
        # 3-segment Resource Manager namespaced name
        # (`<project>/<tag_key_short>/<tag_value_short>`).
        proj_part, key_part, val_part = resource_name.split("/")
        shorthand_matches = [
            action
            for action in tag_value_actions
            if str(action.get(constants.FIELD_NAMESPACED_NAME, "")).startswith(
                f"{proj_part}/{key_part}/"
            )
            and str(action.get(constants.FIELD_NAMESPACED_NAME, "")).endswith(
                f"/{val_part}"
            )
        ]
        if len(shorthand_matches) == 1:
          matched_action = shorthand_matches[0]
      if matched_action is not None and not self._dry_run:
        pre_delete_warnings = self._check_tag_value_plan_dependents(
            manifest,
            matched_action.get(constants.FIELD_NAMESPACED_NAME)
            or resource_name,
        )
    elif resource_type == constants.RESOURCE_TYPE_DATA_POLICY_V2:
      data_policy_keys = [
          constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2,
          constants.KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2,
          constants.KEY_DATA_POLICIES_V1_TO_DATA_POLICIES_V2,
      ]
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
        for action in manifest.get(category_key, []):
          if (
              action.get(constants.FIELD_TARGET_PROJECT_ID) == target_project_id
              and action.get(constants.FIELD_POLICY_ID) == policy_id
          ):
            matched_category_key = category_key
            matched_action = action
            break
        if matched_action is not None:
          break

      if (
          matched_action is not None
          and matched_category_key is not None
          and not self._dry_run
      ):
        pre_delete_warnings = self._check_data_policy_dependents(
            matched_action, matched_category_key
        )

    if matched_action is None:
      raise ValueError(
          f"Resource {resource_name} of type {resource_type} not found in plan"
      )

    # === Step 1b: Fail-Closed Live V2 Data Policy Deletion Gate ===
    # BigQuery Data Policy Service V2 does not verify BigQuery table column
    # bindings when deleting a tag-based Data Policy. Deleting a `_default_deny`
    # or Raw Reader / Masking V2 Data Policy while its Data Governance Tag Value
    # is still attached to BigQuery columns can immediately leave those columns
    # unprotected (Default Allow / Fail-Open). Unless the policy is already
    # absent in GCP (`SKIPPED`) or `--allow-fail-open-policy-delete` was
    # explicitly passed, block live deletion before prompting (`--skip-
    # confirmation` never overrides this safety gate).
    if (
        resource_type == constants.RESOURCE_TYPE_DATA_POLICY_V2
        and not self._dry_run
        and not self._allow_fail_open_policy_delete
    ):
      policy_id = matched_action[constants.FIELD_POLICY_ID]
      target_project_id = matched_action.get(constants.FIELD_TARGET_PROJECT_ID)
      region = matched_action.get(constants.FIELD_REGION)
      full_name = (
          f"projects/{target_project_id}/locations/{region}/"
          f"dataPolicies/{policy_id}"
      )
      exists = self._data_policy_v2_exists(matched_action)
      if not exists:
        logger.warning(
            "Data Policy V2 %s not found, skipping deletion.", full_name
        )
        self.last_report = self._generate_delete_report(
            resource_name,
            resource_type,
            constants.DELETE_STATUS_SKIPPED,
            f"Data Policy V2 `{full_name}` not found in GCP.",
            [],
            report_file=report_file,
        )
        return self.last_report

      for warning_msg in pre_delete_warnings:
        logger.warning("%s", warning_msg)
      blocked_detail = (
          f"Blocked live deletion of Data Policy V2 `{full_name}`: BigQuery"
          " does not check active table column references when deleting"
          " tag-based V2 Data Policies, so deleting this policy while its"
          " Data Governance Tag Value remains bound to BigQuery columns can"
          " leave governed columns unprotected (Default Allow / Fail-Open)."
          " First verify zero columns remain bound via `--phase analyze"
          " --analyze-type column-binding --verbose-bindings` (or revert"
          " column bindings via `--phase swap --swap-mode dgt-to-pt`), then"
          " re-run `--phase delete` with `--allow-fail-open-policy-delete`."
      )
      logger.error("%s", blocked_detail)
      self.last_report = self._generate_delete_report(
          resource_name,
          resource_type,
          constants.DELETE_STATUS_BLOCKED,
          blocked_detail,
          list(pre_delete_warnings),
          report_file=report_file,
      )
      return self.last_report

    # === Step 2: Emit pre-delete warnings & prompt for confirmation ===
    if not self._dry_run and not self._skip_confirmation:
      mirror_warnings_to_stdout = not _logger_emits_to_console(
          logger, logging.WARNING
      )
      for warning_msg in pre_delete_warnings:
        logger.warning("%s", warning_msg)
        if mirror_warnings_to_stdout:
          print(f"\n{warning_msg}", flush=True)

      print(
          f"\nYou are about to delete the individual resource: {resource_name}"
          f" of type {resource_type}",
          flush=True,
      )
      print(
          "Warning: Ensure dependencies are resolved (e.g., delete Data"
          " Policies V2 before DG Tag Values).",
          flush=True,
      )
      try:
        confirm = input("Proceed? (y/n): ")
      except (KeyboardInterrupt, EOFError) as abort_error:
        print("\nDeletion aborted by user.", flush=True)
        raise RuntimeError(
            "Interactive confirmation prompt aborted (interrupted or closed"
            " stdin without --skip-confirmation)."
        ) from abort_error
      if not sys.stdin.isatty():
        print(flush=True)
      if confirm.lower() != "y":
        print("Deletion aborted by user.", flush=True)
        return None
    elif self._dry_run:
      logger.info(
          "[DRY RUN] Previewing deletion of %s (%s) without mutating GCP.",
          resource_name,
          resource_type,
      )

    # === Step 3: Execute dry-run inspection or live deletion with reporting ===
    try:
      if resource_type == constants.RESOURCE_TYPE_DG_TAG_KEY:
        return self._execute_and_report_deletion(
            plan=plan,
            matched_action=matched_action,
            resource_name=resource_name,
            resource_type=resource_type,
            display_label=f"DG Tag Key `{resource_name}`",
            delete_callable=lambda: self.delete_dg_tag_key(resource_name),
            pre_delete_warnings=pre_delete_warnings,
            report_file=report_file,
        )

      if resource_type == constants.RESOURCE_TYPE_DG_TAG_VALUE:
        resolved_tag_value_name = (
            matched_action.get(constants.FIELD_NAMESPACED_NAME) or resource_name
        )
        return self._execute_and_report_deletion(
            plan=plan,
            matched_action=matched_action,
            resource_name=resource_name,
            resource_type=resource_type,
            display_label=f"DG Tag Value `{resource_name}`",
            delete_callable=lambda: self.delete_dg_tag_value(
                resolved_tag_value_name
            ),
            pre_delete_warnings=pre_delete_warnings,
            report_file=report_file,
        )

      # RESOURCE_TYPE_DATA_POLICY_V2
      policy_id = matched_action[constants.FIELD_POLICY_ID]
      target_project_id = matched_action.get(constants.FIELD_TARGET_PROJECT_ID)
      region = matched_action.get(constants.FIELD_REGION)
      full_name = (
          f"projects/{target_project_id}/locations/{region}/"
          f"dataPolicies/{policy_id}"
      )
      return self._execute_and_report_deletion(
          plan=plan,
          matched_action=matched_action,
          resource_name=resource_name,
          resource_type=resource_type,
          display_label=f"Data Policy V2 `{full_name}`",
          delete_callable=lambda: self.delete_data_policy_v2(matched_action),
          pre_delete_warnings=pre_delete_warnings,
          report_file=report_file,
          category_key=matched_category_key,
      )
    except Exception as e:
      if not self._dry_run:
        if (
            self._skip_confirmation
            and not self._emitted_skip_confirmation_warnings
        ):
          for warning_msg in pre_delete_warnings:
            logger.warning("%s", warning_msg)
          self._emitted_skip_confirmation_warnings = True
        clean_err = _clean_exception_message(e)
        self.last_report = self._generate_delete_report(
            resource_name,
            resource_type,
            "FAILED",
            f"Failed to delete {resource_type} '{resource_name}': {clean_err}",
            pre_delete_warnings,
            report_file=report_file,
        )
      raise
