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

"""Command-line entrypoint for the BigQuery PT-to-DGT migration tool.

Architectural Role & 3-Phase Pipeline Overview:
-----------------------------------------------
`main.py` is the unified command-line orchestrator for migrating BigQuery
Column-Level Security (CLS) from regional Data Catalog Policy Tags (PT) to
global Resource Manager Data Governance Tags (DGT) and V2 Data Policies. It
exposes five `--phase` sub-workflows corresponding to the 3-Phase migration
architecture:

1. Phase 1a (`--phase analyze` -> `analyzer.Analyzer`):
   Read-only discovery and blast-radius auditing across three `--analyze-type`
   modes: `static-taxonomy` (source Policy Tag taxonomies, IAM roles, and V1
   Data Policies), `static-dgt` (target DG Tag Keys/Values and V2 Data
   Policies), and `column-binding` (BigQuery `INFORMATION_SCHEMA` column
   bindings across Policy Tags, DG Tags, and direct column Data Policies).
2. Phase 1b (`--phase plan` -> `analyzer.Analyzer` + `planner.Planner`):
   Runs live `static-taxonomy` discovery on `--taxonomy-project-id` and
   synthesizes a deterministic `plan.json` (`phase_2_resource_manifest` +
   `phase_3_binding_map`) and a human-readable Markdown summary report.
3. Phase 2a (`--phase create` -> `creator.Creator`):
   Idempotently provisions target global DG Tag Keys, hierarchical Tag Values,
   and regional V2 Data Policies (`RAW_DATA_ACCESS_POLICY` raw-reader parity,
   `_default_deny` fail-closed policies, and migrated V1 policies) from
   `plan.json`, supporting `--all`, single-resource `--resource-name`, and
   `--dry-run` pre-flight validation.
4. Phase 2b (`--phase delete` -> `deleter.Deleter`):
   Deletes an individual created resource (`--resource-type` +
   `--resource-name`) with bottom-up dependency checks and `--dry-run` preview.
   Intentionally omits bulk `--all` deletion to prevent accidental mass removal
   of shared governance tags.
5. Phase 3 (`--phase swap` -> `swapper.Swapper`):
   Atomically swaps Policy Tags with DG Tags on BigQuery table schemas
   (`--swap-mode pt-to-dgt` for forward cutover, or `--swap-mode dgt-to-pt` for
   automated rollback to Policy Tags), guarded by live enforcement parity
   verification, recursive anti-corruption checks, local JSON schema backups,
   and `--dry-run` preview.

CLI Exit-Code Contract (For CI/CD & Automation Pipelines):
----------------------------------------------------------
- `0`: Complete success (or clean user cancellation when declining an output
  file overwrite prompt).
- `1`: Runtime, API, file I/O, pre-flight blocker, schema corruption, or
  enforcement parity failure (including when all regions fail in `analyze` or
  `plan`, when any region fails under `--halt-on-error`, or when any resource or
  table fails in `create`, `delete`, or `swap`).
- `2`: Command-line argument validation error raised by `argparse`
  (`parser.error`).
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import tempfile
from typing import Any
import warnings

# Suppress benign UserWarning emitted by older proto-plus / Resource Manager SDK
# builds when deserializing TagKey messages that carry the newer enum value
# `Purpose.DATA_GOVERNANCE` (= 2) not yet present in the local proto descriptor.
warnings.filterwarnings(
    "ignore",
    message=".*Unrecognized Purpose enum value.*",
    category=UserWarning,
)

# Ensure sibling modules (`analyzer`, `planner`, `creator`, `deleter`,
# `swapper`, `constants`) are importable both when invoked as a standalone
# script (`python3 main.py`) and when imported inside test runners.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

# pylint: disable=g-import-not-at-top,g-bad-import-order
from analyzer import Analyzer
import constants
from creator import Creator
from deleter import Deleter
from google.api_core import client_options
from google.api_core import exceptions
from google.auth import exceptions as auth_exceptions
from google.cloud import bigquery
from google.cloud import bigquery_datapolicies_v1

# Design Decision (Graceful SDK Import Fallback for V2 Data Policies):
# Older installations of `google-cloud-bigquery-datapolicies` only ship the
# `bigquery_datapolicies_v1` module or ship a `v2` proto descriptor lacking
# `data_governance_tag` and inline `grantees`. Aliasing `v2` to `v1` on
# `ImportError` allows `main.py` to construct a client object carrying ADC
# credentials and custom `--datapolicy-endpoint` options, while `Analyzer`,
# `Creator`, `Deleter`, and `Swapper` automatically detect missing V2 proto
# support and fall back to authenticated raw REST `/v2/` HTTP calls.
try:
  from google.cloud import bigquery_datapolicies_v2
except ImportError:
  bigquery_datapolicies_v2 = bigquery_datapolicies_v1

from google.cloud import datacatalog_v1
from google.cloud import iam_admin_v1
from google.cloud import resourcemanager_v3
from planner import Planner
from swapper import Swapper

# pylint: enable=g-import-not-at-top,g-bad-import-order

logger = logging.getLogger(__name__)

TOOL_VERSION = "1.0.0"
_SAFE_REGION_PATTERN = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9-]{0,62}$")


def _normalize_multi_value_flag(raw_values: list[str] | None) -> list[str]:
  """Normalizes multi-value CLI flags supporting space or comma separators.

  Why This Helper Exists (CLI Ergonomics Across Interactive & CI Shells):
  Operators and CI pipelines pass multi-value arguments in different styles:
  space-separated (`--regions us eu`), comma-separated (`--regions us,eu`), or
  a mixture of both (`--regions "us, eu" us-central1`). Splitting every element
  on commas and stripping whitespace ensures uniform behavior across all
  multi-value flags (`--regions`, `--data-policy-v2-project-ids`,
  `--target-table-dp-project-ids`, `--table-project-ids`, `--dataset-ids`, and
  `--table-ids`).

  Args:
      raw_values: Raw list of strings captured by `argparse` (`nargs="+"`), or
        `None` if the flag was omitted.

  Returns:
      Ordered list of non-empty, whitespace-trimmed token strings.
  """
  if not raw_values:
    return []
  normalized: list[str] = []
  for raw_item in raw_values:
    if not raw_item:
      continue
    for token in raw_item.split(","):
      cleaned = token.strip()
      if cleaned:
        normalized.append(cleaned)
  return normalized


def _check_output_file_overwrite(
    filepath: str | None,
    overwrite_flag: bool,
    skip_confirmation: bool = False,
) -> None:
  """Guards against accidentally overwriting non-empty output files.

  Architectural Timing & Exit-Code Semantics:
  `main()` invokes this check in Step 2 *before* initializing Google Cloud
  clients or issuing any discovery/mutation RPCs. Running overwrite checks up
  front prevents wasting a multi-minute regional scan only to abort at the end
  when writing `--report-file`, `--plan-file`, or `--log-file`.
  - When `overwrite_flag` is False (default): exits immediately with status code
    `1` and an error message instructing the caller to pass `--overwrite`.
  - When `overwrite_flag` is True and `skip_confirmation` is True: logs and
    overwrites the file without prompting.
  - When `overwrite_flag` is True and `skip_confirmation` is False: prompts the
    operator interactively (`(y/n)`). If the user declines (`response != "y"`),
    exits with status code `0` so the operator can re-run with a different file
    path. If stdin is closed in a non-interactive environment (`EOFError`) or
    the user sends `SIGINT` (`KeyboardInterrupt`), exits with status code `1`.

  Args:
      filepath: Target output file path (`--report-file`, `--plan-file`, or
        `--log-file`), or `None` if not specified.
      overwrite_flag: True if `--overwrite` was explicitly set.
      skip_confirmation: True if `--skip-confirmation` was set.
  """
  if not filepath:
    return
  if os.path.islink(filepath):
    logger.error(
        "Output file '%s' is a symbolic link; refusing to write through"
        " symlinks.",
        filepath,
    )
    sys.exit(1)
  if os.path.exists(filepath) and os.path.getsize(filepath) > 0:
    if not overwrite_flag:
      logger.error(
          "Output file '%s' already exists. Pass --overwrite to allow"
          " overwriting existing output files.",
          filepath,
      )
      sys.exit(1)

    if skip_confirmation:
      logger.info("Overwriting existing file: %s", filepath)
      return

    print(f"Warning: Output file '{filepath}' already exists and is not empty.")
    print("This script will overwrite its content.")
    try:
      response = input("Do you want to proceed? (y/n): ").strip().lower()
      if not sys.stdin.isatty():
        print(flush=True)
    except (KeyboardInterrupt, EOFError):
      print("\nAborted by user.")
      sys.exit(1)
    if response != "y":
      print("Exiting to allow specifying a different output file.")
      sys.exit(0)
    logger.info("Overwriting existing file: %s", filepath)


def _verify_output_file_writable(filepath: str | None) -> None:
  """Verifies that `filepath` and its parent directory are writable at startup.

  Runs before initializing Google Cloud clients or executing any phase RPCs so
  an invalid path or read-only directory fails immediately instead of after
  multi-minute discovery or resource mutations.

  Args:
      filepath: Target output file path (`--report-file`, `--plan-file`, or
        `--log-file`), or `None` if not specified.
  """
  if not filepath:
    return
  try:
    if os.path.islink(filepath):
      raise OSError(
          f"'{filepath}' is a symbolic link; refusing to write through"
          " symlinks."
      )
    if os.path.isdir(filepath):
      raise IsADirectoryError(f"'{filepath}' is a directory, not a file.")
    parent_dir = os.path.dirname(os.path.abspath(filepath)) or "."
    os.makedirs(parent_dir, exist_ok=True)
    if os.path.exists(filepath) and not os.access(filepath, os.W_OK):
      raise PermissionError(
          f"Permission denied writing to existing file '{filepath}'."
      )
    try:
      with tempfile.NamedTemporaryFile(
          dir=parent_dir, prefix=".migration_write_check_", delete=True
      ):
        pass
    except PermissionError as perm_error:
      raise PermissionError(
          f"Permission denied writing to directory '{parent_dir}'."
      ) from perm_error
  except OSError as error:
    logger.error(
        "Output file '%s' is not writable: %s",
        filepath,
        error,
    )
    sys.exit(1)


def _verify_directory_writable(directory_path: str | None) -> None:
  """Verifies that `directory_path` can be created and written to at startup.

  Used to validate `--backup-dir` before executing `--phase swap` (when not in
  `--dry-run` mode) so table schema swaps abort before any table is inspected or
  patched if the backup directory is unwritable.

  Args:
      directory_path: Target directory path (e.g., `--backup-dir`), or `None`.
  """
  if not directory_path:
    return
  try:
    if os.path.islink(directory_path):
      raise OSError(
          f"'{directory_path}' is a symbolic link; refusing to write backups"
          " through symlinks."
      )
    os.makedirs(directory_path, exist_ok=True)
    try:
      with tempfile.NamedTemporaryFile(
          dir=directory_path, prefix=".migration_write_check_", delete=True
      ):
        pass
    except PermissionError as perm_error:
      raise PermissionError(
          f"Permission denied writing to directory '{directory_path}'."
      ) from perm_error
  except OSError as error:
    logger.error(
        "Backup directory '%s' is not writable: %s",
        directory_path,
        error,
    )
    sys.exit(1)


def _write_output_file(filepath: str, content: str, description: str) -> None:
  """Writes UTF-8 text content to `filepath` or exits with code `1` on error.

  Automatically creates any missing parent directories before opening the file
  so nested paths (e.g., `--report-file out/reports/plan_report.md`) succeed
  without manual directory setup.

  Args:
      filepath: Destination file path.
      content: UTF-8 string payload (JSON migration plan or Markdown/text
        report).
      description: Human-readable artifact label for log messages (e.g.,
        `"Migration plan"`, `"Report"`).
  """
  try:
    if os.path.islink(filepath):
      raise OSError(
          f"'{filepath}' is a symbolic link; refusing to write through"
          " symlinks."
      )
    parent_dir = os.path.dirname(os.path.abspath(filepath))
    if parent_dir:
      os.makedirs(parent_dir, exist_ok=True)
    # Ensure generated text/JSON files end with a single POSIX newline so
    # subsequent terminal output after `cat` does not fuse onto the last line.
    output_text = (
        content if not content or content.endswith("\n") else f"{content}\n"
    )
    with open(filepath, "w", encoding="utf-8") as file_handle:
      file_handle.write(output_text)
    logger.info("%s saved to %s", description, filepath)
  except OSError as error:
    logger.error(
        "Failed to write %s to '%s': %s",
        description.lower(),
        filepath,
        error,
    )
    sys.exit(1)


def _streams_share_destination() -> bool:
  """Returns True when `sys.stdout` and `sys.stderr` share a console/stream."""
  try:
    if sys.stdout.isatty() and sys.stderr.isatty():
      return True
    return os.path.sameopenfile(sys.stdout.fileno(), sys.stderr.fileno())
  except (AttributeError, OSError, ValueError):
    return False


def _print_stdout_report(content: str) -> None:
  """Prints `content` to stdout with blank-line separation from stderr logs.

  When `stdout` and `stderr` share the same interactive terminal or merged
  `2>&1` stream, writes surrounding blank lines to `stderr` and flushes both
  streams in order so operational `INFO:`/`ERROR:` logs are visually separated
  from the rendered report without adding leading blank lines to redirected
  `> report.md` or `> plan.json` files.

  Args:
      content: Rendered Markdown or JSON payload to print to `stdout`.
  """
  shared_console = _streams_share_destination()
  if shared_console:
    sys.stderr.write("\n")
    sys.stderr.flush()
  print(content, flush=True)
  if shared_console:
    sys.stderr.write("\n")
    sys.stderr.flush()


def _build_client_options(
    raw_endpoint: str | None, *, require_https_scheme: bool = False
) -> client_options.ClientOptions | None:
  """Normalizes a CLI `--*-endpoint` override for gRPC or HTTP REST clients.

  Architectural Role & Transport-Scheme Asymmetry:
  Operators configure custom Private Service Connect (PSC), mTLS / Context-Aware
  Access, or VPC Service Controls (VPC-SC) endpoints in two formats: bare
  hostnames (`bigquery.mtls.googleapis.com`, `datacatalog-psc.p.googleapis.com`)
  or full URLs copied from `gcloud config set api_endpoint_overrides/*`
  (`https://datacatalog.mtls.googleapis.com/`). However, Google Cloud Python SDK
  clients split across two incompatible transport expectations:
    1. gRPC GAPIC Clients (`PolicyTagManagerClient`, `DataPolicyServiceClient`
       v1/v2, `TagKeysClient`, `TagValuesClient`, `ProjectsClient`, and
       `IAMClient`): Pass `ClientOptions.api_endpoint` directly as the target
       `host[:port]` to `grpc.secure_channel()`. Including an `https://` scheme
       causes C-core gRPC to parse `//hostname` as a port number and fail with
       `503 Failed to parse port in name: https://...`. Downstream raw `/v2/`
       REST helpers in `Analyzer`, `Creator`, `Deleter`, and `Swapper` inspect
       `client.transport.host` and automatically prepend `https://` when absent.
    2. HTTP REST Clients (`bigquery.Client`): Pass `ClientOptions.api_endpoint`
       directly as `Connection.API_BASE_URL` into `requests.Session`. Passing a
       bare hostname without `https://` produces scheme-less URLs
       (`bigquery.mtls.googleapis.com/bigquery/v2/...`) that fail with
       `requests.exceptions.MissingSchema`.

  Args:
      raw_endpoint: Raw `--*-endpoint` string from `argparse`, or `None`.
      require_https_scheme: If `True` (used for `bigquery.Client`), ensures the
        normalized endpoint carries an `https://` scheme prefix without a
        trailing slash. If `False` (default, used for all gRPC GAPIC clients),
        strips any `https://` prefix and trailing slash so gRPC receives a clean
        `host[:port]` target.

  Returns:
      Configured `client_options.ClientOptions` instance, or `None` if
      `raw_endpoint` is empty or `None`.

  Raises:
      ValueError: If `raw_endpoint` specifies an insecure `http://` scheme.
  """
  # === Step 1: Trim whitespace, reject http://, and strip trailing '/' ===
  if not raw_endpoint:
    return None
  cleaned_endpoint = raw_endpoint.strip()
  if not cleaned_endpoint:
    return None

  lower_endpoint = cleaned_endpoint.lower()
  if lower_endpoint.startswith("http://"):
    raise ValueError(
        f"Insecure 'http://' endpoint override '{raw_endpoint}' is not"
        " supported; use 'https://' or a bare hostname."
    )
  if lower_endpoint.startswith("https://"):
    cleaned_endpoint = cleaned_endpoint[len("https://") :].lstrip("/")

  cleaned_endpoint = cleaned_endpoint.rstrip("/")
  if not cleaned_endpoint:
    return None

  # === Step 2: Format for HTTP REST (`https://host`) vs. gRPC (`host`) ===
  if require_https_scheme:
    normalized_endpoint = f"https://{cleaned_endpoint}"
  else:
    normalized_endpoint = cleaned_endpoint
  return client_options.ClientOptions(api_endpoint=normalized_endpoint)


def _resolve_default_bigquery_client_project(
    args: argparse.Namespace,
) -> str | None:
  """Resolves a fallback project ID for `bigquery.Client(project=...)`.

  When Application Default Credentials (such as Workload Identity, GCE/Cloud Run
  service accounts, or user ADC without `gcloud config set project`) carry no
  ambient default project, `bigquery.Client()` raises `EnvironmentError` at
  construction time unless `project=` is supplied. Selecting
  `--execution-project` first and falling back to the primary validated phase
  project ID ensures client construction succeeds without relying on host
  ambient configuration.

  Args:
    args: Parsed and Step-1-validated CLI `argparse.Namespace`.

  Returns:
    Explicit standard GCP project ID string, or `None` if unavailable.
  """
  if getattr(args, "execution_project", None):
    return args.execution_project
  if args.phase == "analyze":
    if args.analyze_type == constants.ANALYZE_TYPE_COLUMN_BINDING:
      return args.table_project_id
    if args.analyze_type == constants.ANALYZE_TYPE_STATIC_TAXONOMY:
      return args.taxonomy_project_id
    if args.analyze_type == constants.ANALYZE_TYPE_STATIC_DGT:
      return args.dgt_project_id
  elif args.phase == "plan":
    return args.taxonomy_project_id
  elif args.phase == "swap":
    if args.table_project_ids:
      return args.table_project_ids[0]
    for scoped_ids in (args.dataset_ids, args.table_ids):
      if scoped_ids and "." in scoped_ids[0]:
        return scoped_ids[0].split(".", 1)[0]
  return None


def _load_plan_file(plan_file: str) -> dict[str, Any]:
  """Reads `--plan-file` JSON and validates `metadata.schema_version`.

  Args:
    plan_file: Path to `plan.json` supplied via `--plan-file`.

  Returns:
    Parsed and version-validated migration plan dictionary.
  """
  try:
    with open(plan_file, "r", encoding="utf-8") as f:
      plan = json.load(f)
  except FileNotFoundError:
    logger.error("Plan file not found: %s", plan_file)
    sys.exit(1)
  except json.JSONDecodeError as e:
    logger.error("Failed to parse plan file %s: %s", plan_file, e)
    sys.exit(1)
  except OSError as e:
    logger.error("Failed to read plan file %s: %s", plan_file, e)
    sys.exit(1)

  try:
    constants.validate_plan_schema_version(plan)
  except ValueError as e:
    logger.error("Invalid plan file %s: %s", plan_file, e)
    sys.exit(1)
  return plan


def main() -> None:
  """Parses CLI flags, initializes phase clients, and dispatches execution."""

  # ============================================================================
  # Step 1: CLI Argument Definitions, Normalization & Cross-Flag Validation
  # ============================================================================
  # Key Design Decisions in CLI Contract:
  # 1. Explicit Role-Specific Project Flags (`--taxonomy-project-id`,
  #    `--dgt-project-id`, `--data-policy-v2-project-ids`,
  #    `--table-project-id`):
  #    Because Policy Tag taxonomies, global Data Governance Tags, regional V2
  #    Data Policies, and BigQuery tables routinely reside in separate GCP
  #    projects, `analyze` and `plan` require dedicated role-specific flags
  #    rather than an overloaded `--source-project-id`. Specifically:
  #    - `static-taxonomy` and `plan` take a single `--taxonomy-project-id` to
  #      prevent ambiguous M x N source-to-target mappings and cross-project DG
  #      Tag Key naming collisions.
  #    - `static-dgt` takes `--dgt-project-id` (for global DG Tag Keys/Values)
  #      plus `--data-policy-v2-project-ids` (one or more governance or table
  #      projects where regional V2 Data Policies reside).
  #    - `column-binding` takes a single `--table-project-id`.
  # 2. Explicit, Non-Defaulting Target Project Flags in `plan`:
  #    Target project flags (`--target-dgt-project-id` and either Mode 1
  #    `--target-default-dp-project-id` or Mode 2 `--target-table-dp-project-
  #    ids`) never silently default to `--taxonomy-project-id`. Requiring
  #    explicit flags prevents operators from accidentally creating permanent
  #    global DG Tags in a legacy project or placing V2 Data Policies in a
  #    project where BigQuery query evaluation will not look them up.
  # 3. Uniform Safety Flags Across Mutation Phases (`create`, `delete`, `swap`):
  #    `--dry-run`, `--overwrite`, `--skip-confirmation`, and `--halt-on-error`
  #    behave consistently across phases so operators can preview every step
  #    before mutating production resources.
  parser = argparse.ArgumentParser(
      description="Policy Tag to Data Governance Tag migration tool."
  )
  parser.add_argument(
      "--version",
      action="version",
      version=f"%(prog)s {TOOL_VERSION}",
      help="Print the migration tool version and exit.",
  )
  parser.add_argument(
      "--debug",
      action="store_true",
      help=(
          "[All phases] Enable debug-level logging and display full stack"
          " traces on error."
      ),
  )
  parser.add_argument(
      "--phase",
      required=True,
      choices=["analyze", "plan", "create", "swap", "delete"],
      help=(
          "The migration phase to execute: 'analyze' (read-only discovery of"
          " Policy Tags, DG Tags, or column bindings), 'plan' (generate"
          " JSON migration plan and Markdown summary), 'create' (provision"
          " target DG Tag Keys, Tag Values, and V2 Data Policies), 'swap'"
          " (atomically swap mapped Policy Tags with DG Tags on BigQuery table"
          " schemas), or 'delete' (delete an individual created DG Tag"
          " resource)."
      ),
  )
  parser.add_argument(
      "--taxonomy-project-id",
      help=(
          "[Required in 'analyze' ('static-taxonomy') and 'plan' phases] A"
          " single Google Cloud project ID (string ID, not numeric project"
          " number; one project per run) containing the Data Catalog Policy"
          " Tag taxonomies and V1 Data Policies to analyze or migrate from."
      ),
  )
  parser.add_argument(
      "--dgt-project-id",
      help=(
          "[Required in 'analyze' ('static-dgt')] A single Google Cloud"
          " project ID (string ID, not numeric project number) containing the"
          " global Data Governance Tag Keys and Tag Values to inspect."
      ),
  )
  parser.add_argument(
      "--data-policy-v2-project-ids",
      nargs="+",
      help=(
          "[Required in 'analyze' ('static-dgt')] One or more Google Cloud"
          " project IDs (separated by spaces or commas, e.g.,"
          " '--data-policy-v2-project-ids proj-1 proj-2' or"
          " '--data-policy-v2-project-ids proj-1,proj-2') where regional V2"
          " Data Policies are queried across --regions and matched to the"
          " Data Governance Tags in --dgt-project-id."
      ),
  )
  parser.add_argument(
      "--table-project-id",
      help=(
          "[Required in 'analyze' ('column-binding')] A single Google Cloud"
          " BigQuery data project ID (string ID, not numeric project number)"
          " whose regional INFORMATION_SCHEMA views are scanned for column"
          " bindings across Policy Tags, Data Governance Tags, and direct"
          " column Data Policies."
      ),
  )
  parser.add_argument(
      "--regions",
      nargs="+",
      help=(
          "[Required in 'analyze', 'plan', and 'swap' phases] One or more"
          " Google Cloud locations/regions (e.g., 'us', 'eu', 'us-central1'),"
          " separated by spaces or commas (e.g., '--regions us us-central1' or"
          " '--regions us,us-central1'). Phase semantics: (1) In '--phase"
          " analyze' ('static-taxonomy', 'static-dgt'), the regions to scan"
          " for taxonomies or V2 Data Policies. (2) In '--phase analyze'"
          " ('column-binding'), the regions whose"
          " 'region-<region>.INFORMATION_SCHEMA' views are queried. (3) In"
          " '--phase plan', the regions to scan for source Policy Tag"
          " taxonomies and V1 Data Policies. (4) In '--phase swap', the"
          " required region(s) used to query regional INFORMATION_SCHEMA views"
          " when discovering tagged tables in '--table-project-ids' and to"
          " restrict table schema swapping strictly to datasets and tables"
          " located in the specified region(s)."
      ),
  )
  parser.add_argument(
      "--execution-project",
      help=(
          "[Optional in 'analyze' ('column-binding') and 'swap'] A single"
          " Google Cloud project ID used to execute and bill BigQuery"
          " INFORMATION_SCHEMA query jobs. Defaults to --table-project-id (in"
          " 'analyze') or each scanned table project (in 'swap'). Specify a"
          " centralized billing or admin project here if the caller lacks"
          " bigquery.jobs.create permission in the target table project(s)."
      ),
  )
  parser.add_argument(
      "--target-dgt-project-id",
      help=(
          "[Required in 'plan' phase] A single target Google Cloud project ID"
          " (string ID, not numeric project number) where global Data"
          " Governance Tag Keys and Tag Values will be created."
      ),
  )
  parser.add_argument(
      "--target-default-dp-project-id",
      help=(
          "[Required in 'plan' phase if Mode 1 is selected] Mode 1"
          " (Organization-Level Default Data Policy Project): A single target"
          " Google Cloud project ID where regional V2 Data Policies will be"
          " created. Must be registered in your Organization's"
          " default_data_policy_projects setting in both primary and Disaster"
          " Recovery secondary regions. Mutually exclusive with"
          " --target-table-dp-project-ids."
      ),
  )
  parser.add_argument(
      "--target-table-dp-project-ids",
      nargs="+",
      help=(
          "[Required in 'plan' phase if Mode 2 is selected] Mode 2 (Data Table"
          " Parent Project(s)): One or more Google Cloud data project IDs"
          " (separated by spaces or commas, e.g.,"
          " '--target-table-dp-project-ids proj-a proj-b' or"
          " '--target-table-dp-project-ids proj-a,proj-b') that own the"
          " governed BigQuery tables where regional V2 Data Policies will be"
          " created. Requires no Organization-level"
          " default_data_policy_projects setup. Mutually exclusive with"
          " --target-default-dp-project-id."
      ),
  )
  parser.add_argument(
      "--collision-resolution",
      choices=[
          constants.COLLISION_RESOLUTION_COUNTER,
          constants.COLLISION_RESOLUTION_FROM_REGION,
      ],
      default=constants.COLLISION_RESOLUTION_COUNTER,
      help=(
          "[Optional in 'plan' phase] Strategy for resolving Data Governance"
          " Tag Key short_name collisions across regions: 'counter' (default,"
          " appends -1, -2) or 'from_region' (appends _from_<region>)."
      ),
  )
  parser.add_argument(
      "--analyze-type",
      choices=[
          constants.ANALYZE_TYPE_STATIC_TAXONOMY,
          constants.ANALYZE_TYPE_STATIC_DGT,
          constants.ANALYZE_TYPE_COLUMN_BINDING,
      ],
      default=constants.ANALYZE_TYPE_STATIC_TAXONOMY,
      help=(
          "[Used in 'analyze' phase] The type of analysis to run:"
          " 'static-taxonomy' (default; Policy Tag taxonomies, IAM bindings,"
          " and V1 policies), 'static-dgt' (Data Governance Tag Keys/Values"
          " and V2 policies), or 'column-binding' (Column-Level Security"
          " column bindings across Policy Tags, DG Tags, and Data Policies)."
      ),
  )
  parser.add_argument(
      "--verbose-bindings",
      action="store_true",
      help=(
          "[Optional in 'analyze' ('column-binding')] List individual table"
          " and column paths bound to each Policy Tag, Data Governance Tag,"
          " or direct column-level Data Policy (capped at 1,000 columns per"
          " tag or policy with an explicit truncation notice when capped)."
      ),
  )
  parser.add_argument(
      "--report-file",
      help=(
          "[Optional in 'analyze', 'plan', 'create', 'swap', and 'delete'"
          " phases] File path to save the human-readable Markdown (.md) report"
          " (prints to stdout if omitted). Phase semantics: (1) In 'analyze',"
          " writes the Markdown (.md) taxonomy, DGT, or column-binding"
          " analysis report. (2) In 'plan', writes the Markdown (.md)"
          " migration mapping summary and warnings. (3) In 'create', writes"
          " the Markdown (.md) resource creation or dry-run preview report."
          " (4) In 'swap', writes the Markdown (.md) table schema swap or"
          " dry-run preview report including summary counts, parity"
          " discrepancies, rollback commands, and unified schema diffs. (5) In"
          " 'delete', writes the Markdown (.md) resource deletion or dry-run"
          " preview report."
      ),
  )
  parser.add_argument(
      "--log-file",
      help=(
          "[Optional in all phases] File path to write timestamped operational"
          " execution logs. In 'swap' phase, always records the full unified"
          " schema diff and parity verification details for every table."
      ),
  )
  parser.add_argument(
      "--overwrite",
      action="store_true",
      help=(
          "[Optional in all phases] Allow overwriting existing non-empty"
          " output files (--report-file, --plan-file, --log-file) or existing"
          " schema backup files in --backup-dir. Prompts for confirmation"
          " unless --skip-confirmation is also set."
      ),
  )
  parser.add_argument(
      "--plan-file",
      help=(
          "[Optional output in 'plan'; required input in 'create', 'swap', and"
          " 'delete'] File path to the machine-readable JSON migration plan."
          " Phase semantics: (1) In 'plan' phase, the output file path where"
          " the generated migration plan JSON is saved (prints to stdout if"
          " omitted). (2) In 'create', 'swap', and 'delete' phases, the"
          " required input file path to the existing JSON migration plan."
      ),
  )
  parser.add_argument(
      "--table-project-ids",
      nargs="+",
      help=(
          "[Used in 'swap' phase] One or more Google Cloud project IDs"
          " (separated by spaces or commas, e.g., '--table-project-ids proj-1"
          " proj-2' or '--table-project-ids proj-1,proj-2') to scan for"
          " BigQuery datasets and tables with Policy Tags to swap. Can be"
          " combined with --dataset-ids and --table-ids."
      ),
  )
  parser.add_argument(
      "--dataset-ids",
      nargs="+",
      help=(
          "[Used in 'swap' phase] One or more BigQuery dataset identifiers in"
          " dot-separated '<project_id>.<dataset_id>' format (separated by"
          " spaces or commas, e.g., '--dataset-ids p.d1 p.d2' or"
          " '--dataset-ids p.d1,p.d2') to scan for tables with Policy Tags."
          " Can be combined with --table-project-ids and --table-ids."
      ),
  )
  parser.add_argument(
      "--table-ids",
      nargs="+",
      help=(
          "[Used in 'swap' phase] One or more BigQuery table identifiers in"
          " dot-separated '<project_id>.<dataset_id>.<table_id>' format"
          " (separated by spaces or commas, e.g., '--table-ids p.d.t1 p.d.t2'"
          " or '--table-ids p.d.t1,p.d.t2') to swap Policy Tags with Data"
          " Governance Tags. Can be combined with --table-project-ids and"
          " --dataset-ids."
      ),
  )
  parser.add_argument(
      "--swap-mode",
      choices=list(constants.VALID_SWAP_MODES),
      default=constants.SWAP_MODE_PT_TO_DGT,
      dest="swap_mode",
      help=(
          "[Optional in 'swap' phase] Direction of the atomic schema swap:"
          " 'pt-to-dgt' (Mode 1, default: clear mapped Policy Tags and attach"
          " Data Governance Tags for forward migration) or 'dgt-to-pt'"
          " (Mode 2: clear mapped Data Governance Tags and restore original"
          " Policy Tags for automated rollback to Policy Tags)."
      ),
  )
  parser.add_argument(
      "--backup-dir",
      default=constants.DEFAULT_SCHEMA_BACKUP_DIR,
      help=(
          "[Optional in 'swap' phase] Local directory path where original"
          " table schema JSON backups are saved before patching each table"
          " (default: 'schema_backups')."
      ),
  )
  parser.add_argument(
      "--skip-confirmation",
      action="store_true",
      help=(
          "[Optional in all phases] Bypass interactive human confirmation"
          " prompts before creating resources, applying table schema updates,"
          " deleting resources, or overwriting existing files when"
          " --overwrite is also specified."
      ),
  )
  parser.add_argument(
      "--allow-parity-discrepancy",
      action="store_true",
      help=(
          "[Optional in 'swap' phase] Allow proceeding with a table schema"
          " swap even if pre-swap enforcement parity verification detects"
          " discrepancies between the source Policy Tag and target Data"
          " Governance Tag / V2 Data Policies."
      ),
  )
  parser.add_argument(
      "--allow-unresolved-plan-warnings",
      action="store_true",
      help=(
          "[Optional in 'create' and forward 'swap' phases] Allow proceeding"
          " even if --plan-file still contains unresolved [ACTION REQUIRED]"
          " warnings (by default, 'create' and forward 'pt-to-dgt' swap block"
          " upfront with BLOCKED_UNRESOLVED_PLAN_WARNINGS)."
      ),
  )
  parser.add_argument(
      "--allow-fail-open-policy-delete",
      action="store_true",
      help=(
          "[Optional in 'delete' phase] Explicitly authorize deleting a live V2"
          " Data Policy ('--resource-type data-policy-v2'). Because BigQuery"
          " skips column-reference checks when deleting tag-based V2 Data"
          " Policies, deleting a live '_default_deny' or raw-reader policy"
          " while its DG Tag Value is still bound to BigQuery columns"
          " immediately leaves those columns Fail-Open to table readers. Never"
          " implied by --skip-confirmation."
      ),
  )
  parser.add_argument(
      "--skip-default-dp-org-check",
      action="store_true",
      help=(
          "[Optional in 'swap' phase] Skip querying regional"
          " INFORMATION_SCHEMA.EFFECTIVE_PROJECT_OPTIONS to inspect"
          " Organization default_data_policy_projects (both verifying Mode 1"
          " --target-default-dp-project-id registration and checking default"
          " Data Policy projects for conflicting V2 policies in Mode 1 and"
          " Mode 2). Use only when the caller lacks bigquery.config.get"
          " permission and has verified the Organization setting manually."
      ),
  )
  parser.add_argument(
      "--all",
      action="store_true",
      help=(
          "[Used in 'create' phase] Create all DG Tag Keys, Tag Values, and V2"
          " Data Policies defined in the migration plan. Mutually exclusive"
          " with --resource-name."
      ),
  )
  parser.add_argument(
      "--resource-name",
      help=(
          "[Used in 'create' and 'delete' phases] Identifier of a single"
          " resource from the migration plan to create or delete. Expected"
          " value by --resource-type: (1) For 'dg-tag-key', the key"
          " namespaced_name (e.g., 'my-project/sensitive_data'). (2) For"
          " 'dg-tag-value', the value namespaced_name (e.g.,"
          " 'my-project/sensitive_data/ssn'). (3) For 'data-policy-v2',"
          " '<target_project_id>/<data_policy_id>' in both Mode 1 and Mode 2"
          " (e.g., 'my-data-project/migrated_raw_sensitive_data_ssn')."
      ),
  )
  parser.add_argument(
      "--resource-type",
      choices=[
          constants.RESOURCE_TYPE_DG_TAG_KEY,
          constants.RESOURCE_TYPE_DG_TAG_VALUE,
          constants.RESOURCE_TYPE_DATA_POLICY_V2,
      ],
      help=(
          "[Used in 'create' and 'delete' phases] Type of the single resource"
          " specified by --resource-name: 'dg-tag-key', 'dg-tag-value', or"
          " 'data-policy-v2'. Required whenever --resource-name is used."
      ),
  )
  parser.add_argument(
      "--halt-on-error",
      action="store_true",
      help=(
          "[Optional in all phases] Halt execution immediately on the first"
          " regional scan, API, validation, or schema corruption error instead"
          " of recording the failure and continuing with remaining regions,"
          " resources, or tables."
      ),
  )
  parser.add_argument(
      "--dry-run",
      action="store_true",
      dest="dry_run",
      help=(
          "[Optional in 'create', 'swap', and 'delete' phases] Preview mode:"
          " perform all read-only validation, existence, dependency, and"
          " enforcement parity checks without mutating any Google Cloud"
          " resources or BigQuery table schemas, and output a report detailing"
          " what changes would be made and any potential issues or blockers"
          " detected."
      ),
  )
  parser.add_argument(
      "--datacatalog-endpoint",
      help=(
          "[Optional in 'analyze' and 'plan' phases] Custom API endpoint"
          " hostname or URL for Data Catalog Policy Tag Manager (e.g.,"
          " 'datacatalog-psc.p.googleapis.com' or"
          " 'datacatalog.mtls.googleapis.com'; note that regional"
          " '<region>-datacatalog.googleapis.com' hosts do not serve"
          " PolicyTagManager)."
      ),
  )
  parser.add_argument(
      "--datapolicy-endpoint",
      help=(
          "[Optional in all phases] Custom API endpoint hostname or URL for"
          " BigQuery Data Policy Service (e.g.,"
          " 'bigquerydatapolicy-psc.p.googleapis.com' or"
          " 'bigquerydatapolicy.mtls.googleapis.com')."
      ),
  )
  parser.add_argument(
      "--bigquery-endpoint",
      help=(
          "[Optional in 'analyze' and 'swap' phases] Custom API endpoint"
          " hostname or URL for BigQuery API (e.g.,"
          " 'bigquery-psc.p.googleapis.com' or"
          " 'bigquery.mtls.googleapis.com'; note that"
          " '<region>-bigquery.googleapis.com' requires Locational Endpoint"
          " project enrollment)."
      ),
  )
  parser.add_argument(
      "--resourcemanager-endpoint",
      help=(
          "[Optional in all phases] Custom API endpoint hostname or URL for"
          " Cloud Resource Manager (e.g.,"
          " 'cloudresourcemanager-psc.p.googleapis.com' or"
          " 'cloudresourcemanager.mtls.googleapis.com')."
      ),
  )
  parser.add_argument(
      "--iam-endpoint",
      help=(
          "[Optional in 'analyze' and 'plan' phases] Custom API endpoint"
          " hostname or URL for IAM API (e.g., 'iam-psc.p.googleapis.com' or"
          " 'iam.mtls.googleapis.com')."
      ),
  )
  args = parser.parse_args()

  # Normalize all multi-value flags so both space-separated (`--regions us eu`)
  # and comma-separated (`--regions us,eu`) invocations produce identical lists.
  args.regions = _normalize_multi_value_flag(args.regions)
  args.data_policy_v2_project_ids = _normalize_multi_value_flag(
      args.data_policy_v2_project_ids
  )
  args.target_table_dp_project_ids = _normalize_multi_value_flag(
      args.target_table_dp_project_ids
  )
  args.table_project_ids = _normalize_multi_value_flag(args.table_project_ids)
  args.dataset_ids = _normalize_multi_value_flag(args.dataset_ids)
  args.table_ids = _normalize_multi_value_flag(args.table_ids)

  def _require_single_project_id(
      raw_value: str | None, flag_name: str, required_for: str
  ) -> str:
    """Validates that `flag_name` is present and holds one safe project ID."""
    if not raw_value or not raw_value.strip():
      parser.error(f"{flag_name} is required for {required_for}.")
    cleaned = raw_value.strip()
    if "," in cleaned or len(cleaned.split()) > 1:
      parser.error(f"{flag_name} accepts only a single project ID.")
    try:
      return constants.validate_standard_project_id(cleaned, flag_name)
    except ValueError as err:
      parser.error(str(err))
    return cleaned

  def _reject_embedded_whitespace(
      values: list[str], flag_name: str, item_label: str
  ) -> None:
    """Rejects multi-value flag items that contain internal whitespace."""
    if any(len(item.split()) > 1 for item in values):
      parser.error(
          f"{flag_name} contains an invalid {item_label} with embedded"
          " whitespace."
      )

  def _reject_colon_identifiers(
      values: list[str], flag_name: str, expected_format: str
  ) -> None:
    """Rejects `bq`-style colon syntax and legacy domain-scoped identifiers."""
    for item in values:
      if ":" in item:
        parser.error(
            constants.format_colon_identifier_error(
                item, f"{flag_name} value", expected_format
            )
        )

  def _validate_project_id_list(values: list[str], flag_name: str) -> None:
    """Validates every project ID in a multi-value flag."""
    for item in values:
      try:
        constants.validate_standard_project_id(item, f"{flag_name} value")
      except ValueError as err:
        parser.error(str(err))

  _reject_embedded_whitespace(args.regions, "--regions", "region")
  _reject_embedded_whitespace(
      args.data_policy_v2_project_ids,
      "--data-policy-v2-project-ids",
      "project ID",
  )
  _reject_embedded_whitespace(
      args.target_table_dp_project_ids,
      "--target-table-dp-project-ids",
      "project ID",
  )
  _reject_embedded_whitespace(
      args.table_project_ids, "--table-project-ids", "project ID"
  )
  _reject_embedded_whitespace(
      args.dataset_ids, "--dataset-ids", "dataset identifier"
  )
  _reject_embedded_whitespace(args.table_ids, "--table-ids", "table identifier")

  for region_item in args.regions:
    if not _SAFE_REGION_PATTERN.fullmatch(region_item):
      parser.error(
          f"Invalid --regions value '{region_item}': region names must start"
          " with an ASCII letter or digit and contain only letters, digits,"
          " or hyphens (1-63 characters)."
      )

  _validate_project_id_list(
      args.data_policy_v2_project_ids, "--data-policy-v2-project-ids"
  )
  _validate_project_id_list(
      args.target_table_dp_project_ids, "--target-table-dp-project-ids"
  )
  _validate_project_id_list(args.table_project_ids, "--table-project-ids")
  _reject_colon_identifiers(
      args.dataset_ids, "--dataset-ids", "<project_id>.<dataset_id>"
  )
  _reject_colon_identifiers(
      args.table_ids, "--table-ids", "<project_id>.<dataset_id>.<table_id>"
  )
  if args.resource_name and ":" in args.resource_name:
    parser.error(
        f"Invalid --resource-name '{args.resource_name}':"
        f" {constants.UNSUPPORTED_DOMAIN_SCOPED_PROJECT_MSG}."
    )
  for endpoint_flag_name, raw_endpoint_value in (
      ("--datacatalog-endpoint", args.datacatalog_endpoint),
      ("--datapolicy-endpoint", args.datapolicy_endpoint),
      ("--bigquery-endpoint", args.bigquery_endpoint),
      ("--resourcemanager-endpoint", args.resourcemanager_endpoint),
      ("--iam-endpoint", args.iam_endpoint),
  ):
    if raw_endpoint_value:
      try:
        _build_client_options(raw_endpoint_value)
      except ValueError as endpoint_err:
        parser.error(f"Invalid {endpoint_flag_name}: {endpoint_err}")
  if args.allow_fail_open_policy_delete and args.phase != "delete":
    parser.error(
        "--allow-fail-open-policy-delete is only supported in 'delete' phase."
    )
  if args.skip_default_dp_org_check and args.phase != "swap":
    parser.error(
        "--skip-default-dp-org-check is only supported in 'swap' phase."
    )

  # Enforce role-specific project flags across Phase 1a (`analyze`), Phase 1b
  # (`plan`), and other phases so mismatched project flags fail fast with a
  # clear parser error rather than being silently ignored.
  if args.phase == "analyze":
    if args.analyze_type == constants.ANALYZE_TYPE_STATIC_TAXONOMY:
      if (
          args.dgt_project_id
          or args.data_policy_v2_project_ids
          or args.table_project_id
          or args.table_project_ids
      ):
        parser.error(
            "--dgt-project-id, --data-policy-v2-project-ids,"
            " --table-project-id, and --table-project-ids are not supported"
            " with '--analyze-type static-taxonomy'; use"
            " --taxonomy-project-id."
        )
      args.taxonomy_project_id = _require_single_project_id(
          args.taxonomy_project_id,
          "--taxonomy-project-id",
          "'analyze' ('static-taxonomy')",
      )
    elif args.analyze_type == constants.ANALYZE_TYPE_STATIC_DGT:
      if (
          args.taxonomy_project_id
          or args.table_project_id
          or args.table_project_ids
      ):
        parser.error(
            "--taxonomy-project-id, --table-project-id, and"
            " --table-project-ids are not supported with '--analyze-type"
            " static-dgt'; use --dgt-project-id and"
            " --data-policy-v2-project-ids."
        )
      args.dgt_project_id = _require_single_project_id(
          args.dgt_project_id,
          "--dgt-project-id",
          "'analyze' ('static-dgt')",
      )
      if not args.data_policy_v2_project_ids:
        parser.error(
            "--data-policy-v2-project-ids is required for 'analyze'"
            " ('static-dgt')."
        )
    elif args.analyze_type == constants.ANALYZE_TYPE_COLUMN_BINDING:
      if (
          args.taxonomy_project_id
          or args.dgt_project_id
          or args.data_policy_v2_project_ids
          or args.table_project_ids
      ):
        parser.error(
            "--taxonomy-project-id, --dgt-project-id,"
            " --data-policy-v2-project-ids, and --table-project-ids are not"
            " supported with '--analyze-type column-binding'; use"
            " --table-project-id."
        )
      args.table_project_id = _require_single_project_id(
          args.table_project_id,
          "--table-project-id",
          "'analyze' ('column-binding')",
      )
  elif args.phase == "plan":
    if (
        args.dgt_project_id
        or args.data_policy_v2_project_ids
        or args.table_project_id
        or args.table_project_ids
    ):
      parser.error(
          "--dgt-project-id, --data-policy-v2-project-ids,"
          " --table-project-id, and --table-project-ids are not supported in"
          " 'plan' phase; use --taxonomy-project-id, --target-dgt-project-id,"
          " and --target-default-dp-project-id or"
          " --target-table-dp-project-ids."
      )
    args.taxonomy_project_id = _require_single_project_id(
        args.taxonomy_project_id, "--taxonomy-project-id", "'plan' phase"
    )
  else:
    if args.phase == "swap" and args.table_project_id:
      parser.error(
          "--table-project-id is only for '--phase analyze --analyze-type"
          " column-binding'; use --table-project-ids in 'swap' phase."
      )
    if (
        args.taxonomy_project_id
        or args.dgt_project_id
        or args.data_policy_v2_project_ids
        or args.table_project_id
    ):
      parser.error(
          "--taxonomy-project-id, --dgt-project-id,"
          " --data-policy-v2-project-ids, and --table-project-id are not"
          f" supported in '{args.phase}' phase."
      )

  if args.phase != "plan" and (
      args.target_dgt_project_id
      or args.target_default_dp_project_id
      or args.target_table_dp_project_ids
  ):
    parser.error(
        "--target-dgt-project-id, --target-default-dp-project-id, and"
        " --target-table-dp-project-ids are only supported in 'plan' phase."
    )

  if args.phase != "swap" and (
      args.table_project_ids or args.dataset_ids or args.table_ids
  ):
    parser.error(
        "--table-project-ids, --dataset-ids, and --table-ids are only"
        " supported in 'swap' phase."
    )

  if args.execution_project is not None:
    is_analyze_column_binding = (
        args.phase == "analyze"
        and args.analyze_type == constants.ANALYZE_TYPE_COLUMN_BINDING
    )
    if not is_analyze_column_binding and args.phase != "swap":
      parser.error(
          "--execution-project is only supported with '--phase analyze"
          " --analyze-type column-binding' or '--phase swap'."
      )
    phase_label = (
        "'swap'" if args.phase == "swap" else "'analyze' ('column-binding')"
    )
    args.execution_project = _require_single_project_id(
        args.execution_project,
        "--execution-project",
        phase_label,
    )

  if args.phase in ["analyze", "plan", "swap"]:
    if not args.regions:
      parser.error(f"--regions is required for '{args.phase}' phase.")

  # Enforce explicit target project architecture selection in Phase 1b (`plan`):
  # require a single `--target-dgt-project-id` and strictly one of Mode 1
  # (`--target-default-dp-project-id`) or Mode 2 (`--target-table-dp-project-
  # ids`).
  target_data_policy_mode = None
  target_data_policy_project_ids = []
  if args.phase == "plan":
    if not args.target_dgt_project_id or not args.target_dgt_project_id.strip():
      parser.error("--target-dgt-project-id is required for 'plan' phase.")
    args.target_dgt_project_id = args.target_dgt_project_id.strip()
    if (
        "," in args.target_dgt_project_id
        or len(args.target_dgt_project_id.split()) > 1
    ):
      parser.error("--target-dgt-project-id accepts only a single project ID.")
    try:
      args.target_dgt_project_id = constants.validate_standard_project_id(
          args.target_dgt_project_id, "--target-dgt-project-id"
      )
    except ValueError as err:
      parser.error(str(err))

    has_default_data_policy_project = bool(
        args.target_default_dp_project_id
        and args.target_default_dp_project_id.strip()
    )
    target_table_data_policy_project_ids = list(
        args.target_table_dp_project_ids
    )
    has_table_data_policy_projects = bool(target_table_data_policy_project_ids)
    if has_default_data_policy_project == has_table_data_policy_projects:
      parser.error(
          "Exactly one of --target-default-dp-project-id (Mode 1) or"
          " --target-table-dp-project-ids (Mode 2) is required for 'plan'"
          " phase."
      )
    if has_default_data_policy_project:
      default_data_policy_project_id = args.target_default_dp_project_id.strip()
      if (
          "," in default_data_policy_project_id
          or len(default_data_policy_project_id.split()) > 1
      ):
        parser.error(
            "--target-default-dp-project-id accepts only a single project ID."
        )
      try:
        default_data_policy_project_id = constants.validate_standard_project_id(
            default_data_policy_project_id, "--target-default-dp-project-id"
        )
      except ValueError as err:
        parser.error(str(err))
      target_data_policy_mode = (
          constants.TARGET_DATA_POLICY_MODE_DEFAULT_PROJECT
      )
      target_data_policy_project_ids = [default_data_policy_project_id]
    else:
      target_data_policy_mode = constants.TARGET_DATA_POLICY_MODE_TABLE_PROJECTS
      target_data_policy_project_ids = target_table_data_policy_project_ids

  # Validate required and mutually exclusive phase-specific CLI flags for
  # `create`, `delete`, and `swap` in Step 1 via `parser.error` (exit code 2)
  # before Step 2 (`--log-file` truncation / overwrite prompts) and Step 3
  # (Google Cloud SDK client initialization).
  if args.phase in ["create", "delete", "swap"]:
    if not args.plan_file or not args.plan_file.strip():
      parser.error(f"--plan-file is required for '{args.phase}' phase.")
    args.plan_file = args.plan_file.strip()

  if args.phase == "create":
    if not args.all and not args.resource_name:
      parser.error(
          "Either --all or --resource-name must be specified for 'create'"
          " phase."
      )
    if args.all and args.resource_name:
      parser.error("Cannot specify both --all and --resource-name.")
    if args.resource_name and not args.resource_type:
      parser.error(
          "--resource-type is required when --resource-name is specified."
      )
    if args.resource_type and not args.resource_name:
      parser.error(
          "--resource-name is required when --resource-type is specified."
      )
  elif args.phase == "delete":
    if args.all:
      parser.error(
          "--all is not supported in 'delete' phase; specify --resource-name"
          " and --resource-type to delete a single resource."
      )
    if not args.resource_name:
      parser.error("--resource-name is required for 'delete' phase.")
    if not args.resource_type:
      parser.error("--resource-type is required for 'delete' phase.")
  elif args.phase == "swap":
    if (
        not args.table_project_ids
        and not args.dataset_ids
        and not args.table_ids
    ):
      parser.error(
          "At least one of --table-project-ids, --dataset-ids, or --table-ids"
          " is required for 'swap' phase."
      )

  # ============================================================================
  # Step 2: Logging Configuration & Pre-Execution Output Overwrite Guards
  # ============================================================================
  # Why Overwrite Checks Run Before Client Initialization & RPCs:
  # Checking `--log-file`, `--plan-file`, and `--report-file` for existing
  # non-empty content before issuing any Google Cloud RPCs guarantees that an
  # operator is prompted immediately on launch rather than after waiting several
  # minutes for taxonomy discovery, resource creation, or table schema checks.
  log_level = logging.DEBUG if args.debug else logging.INFO
  logging.basicConfig(
      level=log_level, format="%(levelname)s: %(message)s", force=True
  )
  # Suppress benign `urllib3.connectionpool` keep-alive socket discard notices
  # ("Connection pool is full, discarding connection: ...") during multi-worker
  # bursts unless `--debug` is explicitly requested.
  if not args.debug:
    logging.getLogger("urllib3.connectionpool").setLevel(logging.ERROR)

  # Collect all output file paths for this invocation and verify overwrite
  # policy BEFORE opening `--log-file` or initializing Google Cloud clients.
  output_files_to_check: list[str] = []
  if args.log_file:
    output_files_to_check.append(args.log_file)
  if args.phase == "plan" and args.plan_file:
    output_files_to_check.append(args.plan_file)
  if args.report_file:
    output_files_to_check.append(args.report_file)

  for output_filepath in output_files_to_check:
    if os.path.islink(output_filepath):
      logger.error(
          "Output file '%s' is a symbolic link; refusing to write through"
          " symlinks.",
          output_filepath,
      )
      sys.exit(1)

  if not args.overwrite:
    existing_output_files = [
        path
        for path in output_files_to_check
        if os.path.exists(path) and os.path.getsize(path) > 0
    ]
    if existing_output_files:
      formatted_files = ", ".join(f"'{path}'" for path in existing_output_files)
      logger.error(
          "Output file(s) already exist: %s. Pass --overwrite to allow"
          " overwriting existing output files.",
          formatted_files,
      )
      sys.exit(1)

  # Verify target output files and backup directories are writable BEFORE
  # prompting interactively for file overwrite confirmation.
  for output_filepath in output_files_to_check:
    _verify_output_file_writable(output_filepath)

  if args.phase == "swap" and not args.dry_run:
    _verify_directory_writable(args.backup_dir)

  overwritten_output_files: list[str] = []
  for output_filepath in output_files_to_check:
    is_existing_non_empty = (
        os.path.exists(output_filepath) and os.path.getsize(output_filepath) > 0
    )
    _check_output_file_overwrite(
        output_filepath,
        overwrite_flag=args.overwrite,
        skip_confirmation=args.skip_confirmation,
    )
    if is_existing_non_empty:
      overwritten_output_files.append(output_filepath)

  if args.log_file:
    try:
      log_parent_dir = os.path.dirname(os.path.abspath(args.log_file))
      if log_parent_dir:
        os.makedirs(log_parent_dir, exist_ok=True)
      file_handler = logging.FileHandler(
          args.log_file, mode="w", encoding="utf-8"
      )
      file_handler.setFormatter(
          logging.Formatter("%(asctime)s [%(levelname)s] %(name)s: %(message)s")
      )
      logging.getLogger().addHandler(file_handler)
      for overwritten_filepath in overwritten_output_files:
        overwrite_record = logger.makeRecord(
            logger.name,
            logging.INFO,
            __file__,
            0,
            "Overwriting existing file: %s",
            (overwritten_filepath,),
            None,
        )
        file_handler.emit(overwrite_record)
    except OSError as e:
      logger.error("Unable to open log file '%s': %s", args.log_file, e)
      sys.exit(1)

  logger.debug(
      "CLI arguments validated: phase=%s, analyze_type=%s, regions=%s,"
      " dry_run=%s, halt_on_error=%s",
      args.phase,
      args.analyze_type if args.phase == "analyze" else None,
      args.regions,
      args.dry_run,
      args.halt_on_error,
  )

  # ============================================================================
  # Step 3: Lazy, Phase-Scoped Google Cloud Client & Endpoint Initialization
  # ============================================================================
  # Architectural Rationale:
  # 1. Application Default Credentials (ADC): All SDK clients are initialized
  #    without hardcoded key files, relying on the caller's environment ADC
  #    (`gcloud auth application-default login` or attached service account).
  # 2. VPC-SC & Regional Endpoint Overrides: Every `--*-endpoint` flag maps to a
  #    `google.api_core.client_options.ClientOptions(api_endpoint=...)` object
  #    passed to both GAPIC clients and downstream raw REST `/v2/` helpers
  #    (which inspect `client.transport.host` to honor restricted/private VIPs).
  # 3. Phase-Scoped Instantiation: While Resource Manager Tag clients
  #    (`TagKeysClient`, `TagValuesClient`) and `data_policy_v2_client` are used
  #    across all phases, `bigquery.Client()` and `ProjectsClient()` are only
  #    needed by `analyze`, `plan`, and `swap`, and Data Catalog / V1 Data
  #    Policy / IAM clients are only needed by `analyze` and `plan`. Skipping
  #    `bigquery.Client()` during `create` and `delete` prevents unnecessary
  #    `DefaultCredentialsError` or missing default project errors when running
  #    tag creation/deletion with credentials that have no default BigQuery
  #    quota project set.
  try:
    data_policy_options = _build_client_options(args.datapolicy_endpoint)
    data_policy_v2_client = bigquery_datapolicies_v2.DataPolicyServiceClient(
        client_options=data_policy_options
    )

    resource_manager_options = _build_client_options(
        args.resourcemanager_endpoint
    )
    dg_tag_keys_client = resourcemanager_v3.TagKeysClient(
        client_options=resource_manager_options
    )
    dg_tag_values_client = resourcemanager_v3.TagValuesClient(
        client_options=resource_manager_options
    )

    bigquery_client = None
    resourcemanager_client = None
    if args.phase in ("analyze", "plan", "swap"):
      bigquery_options = _build_client_options(
          args.bigquery_endpoint, require_https_scheme=True
      )
      default_bq_project = _resolve_default_bigquery_client_project(args)
      bigquery_client = bigquery.Client(
          project=default_bq_project, client_options=bigquery_options
      )
      resourcemanager_client = resourcemanager_v3.ProjectsClient(
          client_options=resource_manager_options
      )

    data_catalog_client = None
    data_policy_v1_client = None
    iam_client = None
    if args.phase in ("analyze", "plan"):
      data_catalog_options = _build_client_options(args.datacatalog_endpoint)
      data_catalog_client = datacatalog_v1.PolicyTagManagerClient(
          client_options=data_catalog_options
      )
      data_policy_v1_client = bigquery_datapolicies_v1.DataPolicyServiceClient(
          client_options=data_policy_options
      )
      iam_options = _build_client_options(args.iam_endpoint)
      iam_client = iam_admin_v1.IAMClient(client_options=iam_options)
    logger.debug(
        "Initialized Google Cloud SDK clients for phase '%s'"
        " (datacatalog_endpoint=%s, datapolicy_endpoint=%s,"
        " bigquery_endpoint=%s, resourcemanager_endpoint=%s,"
        " iam_endpoint=%s).",
        args.phase,
        args.datacatalog_endpoint or "default",
        args.datapolicy_endpoint or "default",
        args.bigquery_endpoint or "default",
        args.resourcemanager_endpoint or "default",
        args.iam_endpoint or "default",
    )
  except auth_exceptions.DefaultCredentialsError:
    logger.error(
        "Authentication failed. Please configure your GCP credentials"
        " (e.g., by running 'gcloud auth application-default login')."
    )
    sys.exit(1)
  except exceptions.GoogleAPIError as e:
    if args.debug:
      logger.exception("Failed to initialize Google Cloud clients")
    else:
      logger.error("Failed to initialize Google Cloud clients: %s", e)
    sys.exit(1)

  # ============================================================================
  # Step 4: Phase Dispatch, Execution & Exit-Code Determination
  # ============================================================================
  if args.phase in ("analyze", "plan"):
    analyzer = Analyzer(
        data_catalog_client,
        data_policy_v1_client,
        bigquery_client,
        resourcemanager_client,
        iam_client,
        execution_project=args.execution_project,
        dg_tag_keys_client=dg_tag_keys_client,
        dg_tag_values_client=dg_tag_values_client,
        data_policy_v2_client=data_policy_v2_client,
        halt_on_error=args.halt_on_error,
    )
    planner = Planner(tool_version=TOOL_VERSION)
  else:
    analyzer = None
    planner = None

  # ----------------------------------------------------------------------------
  # Phase 1a: Read-Only Discovery & Blast-Radius Analysis (`--phase analyze`)
  # ----------------------------------------------------------------------------
  # Dispatches to one of the three `Analyzer` modes (`static-taxonomy`,
  # `static-dgt`, `column-binding`). By default, regional scan errors are
  # recorded inside the per-region result dataclass and rendered in the report's
  # error summary so one inaccessible region does not discard data from healthy
  # regions; the process exits with code `1` if *all* scanned regions failed or
  # if `--halt-on-error` was set and *any* region failed.
  if args.phase == "analyze":
    assert analyzer is not None
    results = []
    if args.analyze_type == constants.ANALYZE_TYPE_STATIC_TAXONOMY:
      try:
        results = analyzer.analyze_static_taxonomies(
            args.taxonomy_project_id, args.regions
        )
        report = analyzer.generate_static_taxonomy_report(results)
        if args.report_file:
          _write_output_file(args.report_file, report, "Report")
        else:
          _print_stdout_report(report)
      except exceptions.GoogleAPIError as e:
        if args.debug:
          logger.exception("Static analysis failed")
        else:
          logger.error("Static analysis failed: %s", e)
        sys.exit(1)
    elif args.analyze_type == constants.ANALYZE_TYPE_STATIC_DGT:
      try:
        results = analyzer.analyze_static_dgt(
            args.dgt_project_id,
            args.regions,
            data_policy_v2_project_ids=args.data_policy_v2_project_ids,
        )
        report = analyzer.generate_static_dgt_report(results)
        if args.report_file:
          _write_output_file(args.report_file, report, "Report")
        else:
          _print_stdout_report(report)
      except exceptions.GoogleAPIError as e:
        if args.debug:
          logger.exception("Static DGT analysis failed")
        else:
          logger.error("Static DGT analysis failed: %s", e)
        sys.exit(1)
    elif args.analyze_type == constants.ANALYZE_TYPE_COLUMN_BINDING:
      try:
        results = analyzer.analyze_column_bindings(
            args.table_project_id, args.regions, verbose=args.verbose_bindings
        )
        report = analyzer.generate_column_binding_report(results)
        if args.report_file:
          _write_output_file(args.report_file, report, "Report")
        else:
          _print_stdout_report(report)
      except exceptions.GoogleAPIError as e:
        if args.debug:
          logger.exception("Binding analysis failed")
        else:
          logger.error("Binding analysis failed: %s", e)
        sys.exit(1)

    if (results and all(result.error for result in results)) or (
        args.halt_on_error and any(result.error for result in results)
    ):
      logger.error(
          "Analysis encountered errors in one or more scanned regions."
      )
      sys.exit(1)

  # ----------------------------------------------------------------------------
  # Phase 1b: Migration Plan & Report Generation (`--phase plan`)
  # ----------------------------------------------------------------------------
  # Runs `Analyzer.analyze_static_taxonomies` across `--regions`, aborts with
  # exit code `1` before calling `Planner.generate_plan` if all regions failed
  # (or if any region failed under `--halt-on-error`), and outputs both the
  # machine-readable `plan.json` and the human-readable Markdown summary report.
  elif args.phase == "plan":
    assert analyzer is not None and planner is not None
    try:
      results = analyzer.analyze_static_taxonomies(
          args.taxonomy_project_id, args.regions
      )

      if (results and all(result.error for result in results)) or (
          args.halt_on_error and any(result.error for result in results)
      ):
        logger.error(
            "Aborting plan generation due to static taxonomy analysis errors."
        )
        sys.exit(1)

      errors_found = [result.error for result in results if result.error]
      if errors_found:
        logger.warning(
            "Errors encountered during static analysis. Plan might be"
            " incomplete."
        )
        for error_message in errors_found:
          logger.warning("  - %s", error_message)

      logger.info(
          "Target DG Tag project: %s | Target Data Policy mode: %s | Target"
          " Data Policy project(s): %s",
          args.target_dgt_project_id,
          target_data_policy_mode,
          ", ".join(target_data_policy_project_ids),
      )

      plan = planner.generate_plan(
          results,
          target_dgt_project_id=args.target_dgt_project_id,
          target_data_policy_project_ids=target_data_policy_project_ids,
          target_data_policy_mode=target_data_policy_mode,
          collision_resolution=args.collision_resolution,
      )

      # Write `plan.json` to `--plan-file` and `plan_report.md` to
      # `--report-file` (or stdout if omitted, separated by an 80-char `=`
      # divider when both outputs go to stdout).
      plan_json_str = json.dumps(plan, indent=2)
      markdown_report = planner.generate_markdown_report(plan)
      if args.plan_file:
        _write_output_file(args.plan_file, plan_json_str, "Migration plan")
      if args.report_file:
        _write_output_file(
            args.report_file, markdown_report, "Plan summary report"
        )
      if not args.plan_file and not args.report_file:
        _print_stdout_report(
            f"{plan_json_str}\n\n{'=' * 80}\n\n{markdown_report}"
        )
      elif not args.plan_file:
        _print_stdout_report(plan_json_str)
      elif not args.report_file:
        _print_stdout_report(markdown_report)

    except exceptions.GoogleAPIError as e:
      if args.debug:
        logger.exception("Operation failed")
      else:
        logger.error("Operation failed: %s", e)
      sys.exit(1)

  # ----------------------------------------------------------------------------
  # Phase 2a: Target Resource Provisioning (`--phase create`)
  # ----------------------------------------------------------------------------
  # Dispatches batch top-down creation (`--all`) or single-resource creation
  # (`--resource-name` + `--resource-type`) validated in Step 1. Inspects both
  # `Creator`'s `last_summary["failed"]` counter and report failure sections so
  # partial failures (when `--halt-on-error` is not set) still exit with code
  # `1`.
  elif args.phase == "create":
    plan = _load_plan_file(args.plan_file)

    creator = Creator(
        dg_tag_keys_client=dg_tag_keys_client,
        dg_tag_values_client=dg_tag_values_client,
        data_policy_v2_client=data_policy_v2_client,
        halt_on_error=args.halt_on_error,
        dry_run=args.dry_run,
        skip_confirmation=args.skip_confirmation,
        allow_unresolved_plan_warnings=args.allow_unresolved_plan_warnings,
    )

    if args.all:
      try:
        result = creator.create_all_dgt_resources(
            plan, report_file=args.report_file
        )
        summary: dict[str, int] = {}
        if isinstance(result, tuple) and len(result) == 2:
          report, summary = result
        else:
          report = result
          raw_summary = getattr(creator, "last_summary", None)
          if isinstance(raw_summary, dict):
            summary = raw_summary
        if report and not args.report_file:
          _print_stdout_report(report)
        has_report_failures = isinstance(report, str) and (
            "### Failed Creations" in report
            or "### Failed Pre-Flight Checks / Blockers" in report
            or constants.STATUS_BLOCKED_UNRESOLVED_PLAN_WARNINGS in report
        )
        if summary.get("failed", 0) > 0 or has_report_failures:
          logger.error(
              "One or more resources failed during the 'create' phase."
          )
          sys.exit(1)
      except Exception as e:  # pylint: disable=broad-exception-caught
        if args.debug:
          logger.exception("Creation failed")
        else:
          logger.error("Creation failed: %s", e)
        sys.exit(1)
    else:
      try:
        result = creator.create_individual_dgt_resource(
            plan,
            args.resource_name,
            args.resource_type,
            report_file=args.report_file,
        )
        summary = {}
        if isinstance(result, tuple) and len(result) == 2:
          report, summary = result
        else:
          report = result
          raw_summary = getattr(creator, "last_summary", None)
          if isinstance(raw_summary, dict):
            summary = raw_summary
        if report and not args.report_file:
          _print_stdout_report(report)
        has_report_failures = isinstance(report, str) and (
            "- **Status:** Failed" in report
            or "### Failed Pre-Flight Checks / Blockers" in report
            or constants.STATUS_BLOCKED_UNRESOLVED_PLAN_WARNINGS in report
        )
        if summary.get("failed", 0) > 0 or has_report_failures:
          last_error = getattr(creator, "last_error_message", None)
          if isinstance(last_error, str) and last_error:
            logger.error("Failed to create individual resource: %s", last_error)
          else:
            logger.error("Failed to create individual resource.")
          sys.exit(1)
      except Exception as e:  # pylint: disable=broad-exception-caught
        last_report = getattr(creator, "last_report", None)
        if (
            isinstance(last_report, str)
            and last_report
            and not args.report_file
        ):
          _print_stdout_report(last_report)
        if args.debug:
          logger.exception("Failed to create individual resource")
        else:
          logger.error("Failed to create individual resource: %s", e)
        sys.exit(1)

  # ----------------------------------------------------------------------------
  # Phase 2b: Individual Resource Teardown (`--phase delete`)
  # ----------------------------------------------------------------------------
  # Design Decision (Single-Resource Blast Radius Only):
  # `--phase delete` strictly requires both `--resource-name` and
  # `--resource-type` and intentionally rejects `--all` in Step 1. Requiring
  # explicit per-resource invocations prevents accidental bulk deletion of
  # pre-existing Data Governance Tags that may already protect production
  # columns.
  elif args.phase == "delete":
    plan = _load_plan_file(args.plan_file)

    deleter = Deleter(
        dg_tag_keys_client=dg_tag_keys_client,
        dg_tag_values_client=dg_tag_values_client,
        data_policy_v2_client=data_policy_v2_client,
        halt_on_error=args.halt_on_error,
        dry_run=args.dry_run,
        skip_confirmation=args.skip_confirmation,
        allow_fail_open_policy_delete=args.allow_fail_open_policy_delete,
    )

    try:
      report = deleter.delete_individual_dgt_resource(
          plan,
          args.resource_name,
          args.resource_type,
          report_file=args.report_file,
      )
      if report and not args.report_file:
        _print_stdout_report(report)
      # Exit with status code 1 when dry-run dependency checks report BLOCKED
      # (or FAILED) so CI/CD pipelines detect blocked deletions consistently.
      has_report_failures = isinstance(report, str) and (
          f"- **Status**: **{constants.DELETE_STATUS_BLOCKED}**" in report
          or "- **Status**: **FAILED**" in report
      )
      if has_report_failures:
        logger.error("Resource deletion failed or was blocked.")
        sys.exit(1)
    except Exception as e:  # pylint: disable=broad-exception-caught
      last_report = getattr(deleter, "last_report", None)
      if isinstance(last_report, str) and last_report and not args.report_file:
        _print_stdout_report(last_report)
      if args.debug:
        logger.exception("Failed to delete individual resource")
      elif not isinstance(last_report, str) or not last_report:
        logger.error("Failed to delete individual resource: %s", e)
      sys.exit(1)

  # ----------------------------------------------------------------------------
  # Phase 3: Atomic Table Schema Cutover & Rollback (`--phase swap`)
  # ----------------------------------------------------------------------------
  # Uses `--plan-file` and at least one table-scope selector
  # (`--table-project-ids`, `--dataset-ids`, or `--table-ids`) validated in
  # Step 1. Supports both forward migration (`--swap-mode pt-to-dgt`) and
  # emergency rollback to Policy Tags (`--swap-mode dgt-to-pt`). Exits with
  # status code `1` if any table encounters `FAILED`,
  # `ABORTED_SCHEMA_CORRUPTION`, `BLOCKED_PARITY_DISCREPANCY`, or
  # `BLOCKED_UNRESOLVED_PLAN_WARNINGS`.
  elif args.phase == "swap":
    plan = _load_plan_file(args.plan_file)

    swapper = Swapper(
        bigquery_client=bigquery_client,
        dg_tag_keys_client=dg_tag_keys_client,
        dg_tag_values_client=dg_tag_values_client,
        data_policy_v2_client=data_policy_v2_client,
        resourcemanager_client=resourcemanager_client,
        execution_project=args.execution_project,
        backup_dir=args.backup_dir,
        overwrite=args.overwrite,
        skip_confirmation=args.skip_confirmation,
        allow_parity_discrepancy=args.allow_parity_discrepancy,
        allow_unresolved_plan_warnings=args.allow_unresolved_plan_warnings,
        skip_default_dp_org_check=args.skip_default_dp_org_check,
        halt_on_error=args.halt_on_error,
        dry_run=args.dry_run,
        swap_mode=args.swap_mode,
        plan_file=args.plan_file,
    )

    try:
      results, report = swapper.swap_schemas(
          plan=plan,
          table_project_ids=args.table_project_ids,
          dataset_ids=args.dataset_ids,
          table_ids=args.table_ids,
          regions=args.regions,
          report_file=args.report_file,
      )
      if report and not args.report_file:
        _print_stdout_report(report)
      error_statuses = {
          constants.SWAP_STATUS_FAILED,
          constants.SWAP_STATUS_ABORTED_SCHEMA_CORRUPTION,
          constants.SWAP_STATUS_BLOCKED_PARITY_DISCREPANCY,
          constants.SWAP_STATUS_BLOCKED_UNRESOLVED_PLAN_WARNINGS,
      }
      if any(result.status in error_statuses for result in results):
        logger.error(
            "One or more tables encountered errors, parity discrepancies, or"
            " schema corruption safeguards during the 'swap' phase."
        )
        sys.exit(1)
    except Exception as e:  # pylint: disable=broad-exception-caught
      last_report = getattr(swapper, "last_report", None)
      if isinstance(last_report, str) and last_report and not args.report_file:
        _print_stdout_report(last_report)
      if args.debug:
        logger.exception("Schema swap failed")
      else:
        logger.error("Schema swap failed: %s", e)
      sys.exit(1)


if __name__ == "__main__":
  main()
