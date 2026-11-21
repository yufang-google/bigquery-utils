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

"""Unit tests for the CLI entrypoint (`main.py`).

Architectural Role & Verification Scope:
----------------------------------------
This test suite validates the command-line contract of `main.py` across all
five migration phases (`analyze`, `plan`, `create`, `delete`, and `swap`):

1. Multi-Value Flag Normalization & Overwrite Guards:
   Verifies `_normalize_multi_value_flag` (supporting mixed comma-separated and
   space-separated tokens) and `_check_output_file_overwrite` (clean exit on
   non-interactive `EOFError` and parent-directory creation in
   `_write_output_file`).
2. Cross-Flag Validation (`SystemExit(2)`):
   Verifies that `analyze` and `plan` enforce role-specific project flags
   (`--taxonomy-project-id`, `--dgt-project-id`, `--data-policy-v2-project-ids`,
   `--table-project-id`), that `plan` requires `--target-dgt-project-id` plus
   mutually exclusive Mode 1 (`--target-default-dp-project-id`) vs. Mode 2
   (`--target-table-dp-project-ids`), and that `create`, `delete`, and `swap`
   reject missing or conflicting CLI flags (`--plan-file`, `--all` vs.
   `--resource-name`, `--resource-type`, and table scope selectors) with exit
   code `2` before initializing SDK clients.
3. Phase Dispatch, VPC-SC Endpoint Wiring & Exit-Code Contracts (`0` vs. `1`):
   Verifies that each phase initializes its required Google Cloud SDK clients
   (honoring `--*-endpoint` and `--execution-project`), forwards arguments to
   `Analyzer`, `Planner`, `Creator`, `Deleter`, and `Swapper`, and exits with
   status code `1` whenever regional scans, resource creations, or table schema
   swaps encounter errors, parity discrepancies, or schema corruption guards.
"""

import io
import json
import os
import sys
import tempfile
import types
import unittest
from unittest import mock


class _StubPolicyTagManagerClient:
  """Stub client class used when `datacatalog_v1` is absent in test runners."""


# Hermetic Test Environment Fallback:
# Inject a minimal `google.cloud.datacatalog_v1` module into `sys.modules` if
# the optional C-extension/GAPIC package is not installed in the local test
# runner so `main.py` can be imported and `PolicyTagManagerClient` autospecced.
if "google.cloud.datacatalog_v1" not in sys.modules:
  stub_datacatalog_module = types.ModuleType("google.cloud.datacatalog_v1")
  setattr(
      stub_datacatalog_module,
      "PolicyTagManagerClient",
      _StubPolicyTagManagerClient,
  )
  sys.modules["google.cloud.datacatalog_v1"] = stub_datacatalog_module

# Ensure local imports work in both package and standalone script execution.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# pylint: disable=g-import-not-at-top,g-bad-import-order
import analyzer
import constants
import creator
import deleter
import main
import planner
import swapper

# pylint: enable=g-import-not-at-top,g-bad-import-order


class MainTest(unittest.TestCase):
  """Tests CLI parsing, client initialization, and phase dispatch in `main`."""

  def setUp(self):
    """Patches all Google Cloud SDK clients with `autospec=True`.

    Why All SDK Clients Are Autospecced in `setUp`:
    Patching every client class (`PolicyTagManagerClient`,
    `DataPolicyServiceClient` v1/v2, `bigquery.Client`, `ProjectsClient`,
    `TagKeysClient`, `TagValuesClient`, and `IAMClient`) with `autospec=True`
    prevents unit tests from attempting live Application Default Credentials
    (ADC) discovery or network connections while verifying constructor
    signatures.
    """
    super().setUp()
    self.addCleanup(mock.patch.stopall)
    self.patcher_datacatalog = mock.patch.object(
        main.datacatalog_v1, "PolicyTagManagerClient", autospec=True
    )
    self.patcher_data_policy_v1 = mock.patch.object(
        main.bigquery_datapolicies_v1, "DataPolicyServiceClient", autospec=True
    )
    self.patcher_bigquery = mock.patch.object(
        main.bigquery, "Client", autospec=True
    )
    self.patcher_projects = mock.patch.object(
        main.resourcemanager_v3, "ProjectsClient", autospec=True
    )
    self.patcher_tag_keys = mock.patch.object(
        main.resourcemanager_v3, "TagKeysClient", autospec=True
    )
    self.patcher_tag_values = mock.patch.object(
        main.resourcemanager_v3, "TagValuesClient", autospec=True
    )
    self.patcher_iam = mock.patch.object(
        main.iam_admin_v1, "IAMClient", autospec=True
    )

    self.mock_datacatalog = self.patcher_datacatalog.start()
    self.mock_data_policy_v1 = self.patcher_data_policy_v1.start()
    if main.bigquery_datapolicies_v2 is not main.bigquery_datapolicies_v1:
      self.patcher_data_policy_v2 = mock.patch.object(
          main.bigquery_datapolicies_v2,
          "DataPolicyServiceClient",
          autospec=True,
      )
      self.mock_data_policy_v2 = self.patcher_data_policy_v2.start()
    else:
      self.mock_data_policy_v2 = self.mock_data_policy_v1
    self.mock_bigquery = self.patcher_bigquery.start()
    self.mock_projects = self.patcher_projects.start()
    self.mock_tag_keys = self.patcher_tag_keys.start()
    self.mock_tag_values = self.patcher_tag_values.start()
    self.mock_iam = self.patcher_iam.start()

  # ============================================================================
  # Section 1: CLI Helper Functions (Flag Normalization & File Overwrite Guards)
  # ============================================================================

  def test_normalize_multi_value_flag(self):
    """Verifies comma- and space-separated multi-value flags are normalized."""
    # Arrange: Provide a mixed list of comma-delimited and whitespace-padded
    # region tokens as captured by `argparse` (`nargs="+"`).
    raw_values = ["us,eu", "us-central1", " asia-east1 , "]

    # Act: Normalize the raw CLI flag values.
    normalized = main._normalize_multi_value_flag(raw_values)

    # Assert: All tokens are split on commas, trimmed of whitespace, and
    # preserved in their original order with empty tokens discarded.
    self.assertEqual(
        normalized,
        ["us", "eu", "us-central1", "asia-east1"],
    )

  # Verifies _build_client_options strips https:// for gRPC GAPIC transports
  # and prepends https:// for HTTP REST transports (bigquery.Client).
  def test_build_client_options_normalizes_grpc_and_rest_endpoints(self):
    """Verifies `_build_client_options` handles gRPC and HTTP REST schemes."""
    # Empty, whitespace-only, or scheme-only inputs return None so SDK clients
    # fall back to their default service endpoints.
    self.assertIsNone(main._build_client_options(None))
    self.assertIsNone(main._build_client_options("   "))
    self.assertIsNone(main._build_client_options("https://"))

    # gRPC GAPIC clients require a bare host[:port] target without https:// or
    # trailing slashes so grpc.secure_channel does not fail port parsing.
    grpc_from_url = main._build_client_options(
        "https://datacatalog.mtls.googleapis.com/"
    )
    self.assertIsNotNone(grpc_from_url)
    self.assertEqual(
        grpc_from_url.api_endpoint, "datacatalog.mtls.googleapis.com"
    )
    grpc_from_host = main._build_client_options(
        "datacatalog-psc.p.googleapis.com:443"
    )
    self.assertIsNotNone(grpc_from_host)
    self.assertEqual(
        grpc_from_host.api_endpoint, "datacatalog-psc.p.googleapis.com:443"
    )

    # HTTP REST clients (bigquery.Client) require an explicit scheme prefix so
    # requests.Session does not raise MissingSchema on bare hostnames.
    rest_from_host = main._build_client_options(
        "bigquery.mtls.googleapis.com", require_https_scheme=True
    )
    self.assertIsNotNone(rest_from_host)
    self.assertEqual(
        rest_from_host.api_endpoint, "https://bigquery.mtls.googleapis.com"
    )
    rest_from_url = main._build_client_options(
        "https://bigquery-psc.p.googleapis.com/", require_https_scheme=True
    )
    self.assertIsNotNone(rest_from_url)
    self.assertEqual(
        rest_from_url.api_endpoint, "https://bigquery-psc.p.googleapis.com"
    )

  def test_check_output_file_overwrite_exits_when_overwrite_false(self):
    """Verifies existing output file with `overwrite_flag=False` exits 1."""
    # Create a non-empty temporary output file to trigger the overwrite guard.
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", delete=False
    ) as temp_file:
      temp_file.write("existing content")
      temp_path = temp_file.name

    try:
      with mock.patch("builtins.input") as mock_input:
        # Even when skip_confirmation=True, overwrite_flag=False must exit with
        # code 1 without prompting so --skip-confirmation alone cannot overwrite
        # existing files.
        with self.assertRaises(SystemExit) as context:
          main._check_output_file_overwrite(
              temp_path, overwrite_flag=False, skip_confirmation=True
          )
        self.assertEqual(context.exception.code, 1)
        mock_input.assert_not_called()
    finally:
      if os.path.exists(temp_path):
        os.remove(temp_path)

  def test_check_output_file_overwrite_prompts_when_overwrite_true(self):
    """Verifies `overwrite_flag=True` prompts unless `skip_confirmation` set."""
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", delete=False
    ) as temp_file:
      temp_file.write("existing content")
      temp_path = temp_file.name

    try:
      # Approving ("y") allows overwriting when overwrite_flag=True.
      with mock.patch("builtins.input", return_value="y") as mock_input:
        main._check_output_file_overwrite(
            temp_path, overwrite_flag=True, skip_confirmation=False
        )
        mock_input.assert_called_once()

      # Declining ("n") exits cleanly with status code 0.
      with mock.patch("builtins.input", return_value="n"):
        with self.assertRaises(SystemExit) as context:
          main._check_output_file_overwrite(
              temp_path, overwrite_flag=True, skip_confirmation=False
          )
        self.assertEqual(context.exception.code, 0)

      # Non-interactive EOFError during the prompt exits with status code 1.
      with mock.patch("builtins.input", side_effect=EOFError):
        with self.assertRaises(SystemExit) as context:
          main._check_output_file_overwrite(
              temp_path, overwrite_flag=True, skip_confirmation=False
          )
        self.assertEqual(context.exception.code, 1)

      # Setting both overwrite_flag=True and skip_confirmation=True bypasses
      # the interactive prompt.
      with mock.patch("builtins.input") as mock_input:
        main._check_output_file_overwrite(
            temp_path, overwrite_flag=True, skip_confirmation=True
        )
        mock_input.assert_not_called()
    finally:
      if os.path.exists(temp_path):
        os.remove(temp_path)

  def test_main_exits_when_existing_output_file_without_overwrite(self):
    """Verifies `main()` exits 1 if output file exists without `--overwrite`."""
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", delete=False
    ) as temp_file:
      temp_file.write("existing report")
      report_path = temp_file.name

    try:
      self.mock_datacatalog.reset_mock()
      # Passing --skip-confirmation without --overwrite must still reject
      # overwriting an existing --report-file before initializing clients.
      with mock.patch.object(
          sys,
          "argv",
          [
              "main.py",
              "--phase",
              "analyze",
              "--taxonomy-project-id",
              "source-project",
              "--regions",
              "us",
              "--report-file",
              report_path,
              "--skip-confirmation",
          ],
      ):
        with self.assertRaises(SystemExit) as context:
          main.main()
        self.assertEqual(context.exception.code, 1)
      self.mock_datacatalog.assert_not_called()
    finally:
      if os.path.exists(report_path):
        os.remove(report_path)

  def test_main_exits_when_output_or_backup_dir_is_not_writable(self):
    """Verifies startup writability checks fail fast before SDK client init."""
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", delete=False
    ) as blocking_file:
      blocking_file.write('{"phase_2_resource_manifest": {}}')
      blocking_path = blocking_file.name

    try:
      self.mock_datacatalog.reset_mock()
      # Passing a --report-file under a regular file path (not a directory)
      # fails _verify_output_file_writable at startup before client creation.
      invalid_report_path = os.path.join(blocking_path, "report.md")
      with mock.patch.object(
          sys,
          "argv",
          [
              "main.py",
              "--phase",
              "analyze",
              "--taxonomy-project-id",
              "source-project",
              "--regions",
              "us",
              "--report-file",
              invalid_report_path,
          ],
      ):
        with self.assertRaises(SystemExit) as context:
          main.main()
        self.assertEqual(context.exception.code, 1)
      self.mock_datacatalog.assert_not_called()

      self.mock_bigquery.reset_mock()
      # Passing a --backup-dir that points to an existing regular file fails
      # _verify_directory_writable at startup during non-dry-run swap.
      with mock.patch.object(
          sys,
          "argv",
          [
              "main.py",
              "--phase",
              "swap",
              "--plan-file",
              blocking_path,
              "--regions",
              "us",
              "--table-ids",
              "data-proj.ds.tbl",
              "--backup-dir",
              blocking_path,
          ],
      ):
        with self.assertRaises(SystemExit) as context:
          main.main()
        self.assertEqual(context.exception.code, 1)
      self.mock_bigquery.assert_not_called()
    finally:
      if os.path.exists(blocking_path):
        os.remove(blocking_path)

  # ============================================================================
  # Section 2: CLI Argument Validation (`SystemExit(2)`)
  # ============================================================================

  # Role-specific project flags must be present and must reject cross-mode or
  # cross-phase mismatches with SystemExit(2).
  def test_analyze_and_plan_project_flag_validation_exits(self):
    """Verifies role-specific project flag validation exits with code 2."""
    invalid_argv_cases = [
        # Missing --taxonomy-project-id in default static-taxonomy mode.
        ["main.py", "--phase", "analyze", "--regions", "us"],
        # Multi-project comma list rejected on singular --taxonomy-project-id.
        [
            "main.py",
            "--phase",
            "analyze",
            "--taxonomy-project-id",
            "project-one,project-two",
            "--regions",
            "us",
        ],
        # Missing --data-policy-v2-project-ids in static-dgt mode.
        [
            "main.py",
            "--phase",
            "analyze",
            "--analyze-type",
            constants.ANALYZE_TYPE_STATIC_DGT,
            "--dgt-project-id",
            "dgt-project",
            "--regions",
            "us",
        ],
        # Mismatched --taxonomy-project-id passed to static-dgt mode.
        [
            "main.py",
            "--phase",
            "analyze",
            "--analyze-type",
            constants.ANALYZE_TYPE_STATIC_DGT,
            "--taxonomy-project-id",
            "taxonomy-project",
            "--dgt-project-id",
            "dgt-project",
            "--data-policy-v2-project-ids",
            "policy-project",
            "--regions",
            "us",
        ],
        # Missing --table-project-id in column-binding mode.
        [
            "main.py",
            "--phase",
            "analyze",
            "--analyze-type",
            constants.ANALYZE_TYPE_COLUMN_BINDING,
            "--taxonomy-project-id",
            "taxonomy-project",
            "--regions",
            "us",
        ],
        # Mismatched singular --table-project-id passed to swap phase instead
        # of --table-project-ids.
        [
            "main.py",
            "--phase",
            "swap",
            "--plan-file",
            "plan.json",
            "--table-project-id",
            "data-project",
            "--regions",
            "us",
        ],
        # Target project flags (--target-*) rejected outside plan phase.
        [
            "main.py",
            "--phase",
            "analyze",
            "--taxonomy-project-id",
            "taxonomy-project",
            "--target-dgt-project-id",
            "dgt-project",
            "--regions",
            "us",
        ],
        [
            "main.py",
            "--phase",
            "create",
            "--plan-file",
            "plan.json",
            "--all",
            "--target-default-dp-project-id",
            "policy-project",
        ],
        # Swap scope selectors (--table-project-ids, --dataset-ids, --table-ids)
        # rejected outside swap phase.
        [
            "main.py",
            "--phase",
            "create",
            "--plan-file",
            "plan.json",
            "--all",
            "--table-project-ids",
            "data-project",
        ],
        [
            "main.py",
            "--phase",
            "analyze",
            "--taxonomy-project-id",
            "taxonomy-project",
            "--dataset-ids",
            "data-project.dataset_one",
            "--regions",
            "us",
        ],
        # --execution-project rejected outside analyze column-binding / swap
        # phases and when given multiple comma/space-delimited projects.
        [
            "main.py",
            "--phase",
            "analyze",
            "--analyze-type",
            constants.ANALYZE_TYPE_STATIC_TAXONOMY,
            "--taxonomy-project-id",
            "taxonomy-project",
            "--execution-project",
            "billing-project",
            "--regions",
            "us",
        ],
        [
            "main.py",
            "--phase",
            "plan",
            "--taxonomy-project-id",
            "taxonomy-project",
            "--target-dgt-project-id",
            "target-dgt-proj",
            "--target-default-dp-project-id",
            "target-dp-proj",
            "--execution-project",
            "billing-project",
            "--regions",
            "us",
        ],
        [
            "main.py",
            "--phase",
            "analyze",
            "--analyze-type",
            constants.ANALYZE_TYPE_COLUMN_BINDING,
            "--table-project-id",
            "data-project",
            "--execution-project",
            "billing-one,billing-two",
            "--regions",
            "us",
        ],
        # Embedded whitespace rejected across multi-value project/resource/
        # region flags when passed as a single quoted argument.
        [
            "main.py",
            "--phase",
            "analyze",
            "--taxonomy-project-id",
            "taxonomy-project",
            "--regions",
            "us eu",
        ],
        [
            "main.py",
            "--phase",
            "plan",
            "--taxonomy-project-id",
            "taxonomy-project",
            "--target-dgt-project-id",
            "dgt-project",
            "--target-table-dp-project-ids",
            "table-one table-two",
            "--regions",
            "us",
        ],
        [
            "main.py",
            "--phase",
            "swap",
            "--plan-file",
            "plan.json",
            "--table-project-ids",
            "data-one data-two",
            "--regions",
            "us",
        ],
    ]
    for argv in invalid_argv_cases:
      with self.subTest(argv=argv):
        with mock.patch.object(sys, "argv", argv):
          with self.assertRaises(SystemExit) as context:
            main.main()
          self.assertEqual(context.exception.code, 2)

  def test_plan_phase_requires_mutually_exclusive_data_policy_mode_flags(self):
    """Verifies `--phase plan` requires either Mode 1 or Mode 2 flags."""
    # Arrange: Patch `sys.argv` with `--phase plan` omitting both Mode 1
    # (`--target-default-dp-project-id`) and Mode 2
    # (`--target-table-dp-project-ids`).
    with mock.patch.object(
        sys,
        "argv",
        [
            "main.py",
            "--phase",
            "plan",
            "--taxonomy-project-id",
            "source-project",
            "--regions",
            "us",
            "--target-dgt-project-id",
            "target-dgt-project",
        ],
    ):
      # Act & Assert: `main()` rejects the ambiguous target policy mode with
      # `SystemExit(2)` rather than defaulting to `--taxonomy-project-id`.
      with self.assertRaises(SystemExit) as context:
        main.main()
      self.assertEqual(context.exception.code, 2)

  # Phase 2a, 2b, and 3 flag Combinations must fail fast in Step 1 with
  # SystemExit(2) before output-file truncation or SDK client initialization.
  def test_create_delete_and_swap_flag_validation_exits_with_code_2(self):
    """Verifies `create`, `delete`, and `swap` flag guards exit with code 2."""
    invalid_argv_cases = [
        # Missing --plan-file in create phase.
        ["main.py", "--phase", "create", "--all"],
        # Missing both --all and --resource-name in create phase.
        ["main.py", "--phase", "create", "--plan-file", "plan.json"],
        # Conflicting --all and --resource-name in create phase.
        [
            "main.py",
            "--phase",
            "create",
            "--plan-file",
            "plan.json",
            "--all",
            "--resource-name",
            "my-project/my_key",
            "--resource-type",
            constants.RESOURCE_TYPE_DG_TAG_KEY,
        ],
        # --resource-name without --resource-type in create phase.
        [
            "main.py",
            "--phase",
            "create",
            "--plan-file",
            "plan.json",
            "--resource-name",
            "my-project/my_key",
        ],
        # --resource-type without --resource-name in create phase.
        [
            "main.py",
            "--phase",
            "create",
            "--plan-file",
            "plan.json",
            "--resource-type",
            constants.RESOURCE_TYPE_DG_TAG_KEY,
        ],
        # Forbidden --all flag in single-resource delete phase.
        ["main.py", "--phase", "delete", "--plan-file", "plan.json", "--all"],
        # Missing --resource-name in delete phase.
        [
            "main.py",
            "--phase",
            "delete",
            "--plan-file",
            "plan.json",
            "--resource-type",
            constants.RESOURCE_TYPE_DG_TAG_KEY,
        ],
        # Missing --resource-type in delete phase.
        [
            "main.py",
            "--phase",
            "delete",
            "--plan-file",
            "plan.json",
            "--resource-name",
            "my-project/my_key",
        ],
        # Missing table scope selector flags in swap phase.
        [
            "main.py",
            "--phase",
            "swap",
            "--plan-file",
            "plan.json",
            "--regions",
            "us",
        ],
    ]
    self.mock_tag_keys.reset_mock()
    self.mock_bigquery.reset_mock()
    for argv in invalid_argv_cases:
      with self.subTest(argv=argv):
        # Step 1 parser.error must abort with code 2 before Step 3 constructs
        # any TagKeysClient or bigquery.Client instances.
        with mock.patch.object(sys, "argv", argv):
          with self.assertRaises(SystemExit) as context:
            main.main()
          self.assertEqual(context.exception.code, 2)
    self.mock_tag_keys.assert_not_called()
    self.mock_bigquery.assert_not_called()

  # ============================================================================
  # Section 3: Phase 1a (`analyze`) & Phase 1b (`plan`) Execution & Exit Codes
  # ============================================================================

  @mock.patch.object(main, "Analyzer", autospec=True)
  def test_analyze_phase_exits_nonzero_when_all_regions_fail(
      self, mock_analyzer_class
  ):
    """Verifies `--phase analyze` exits with code 1 when all regions fail."""
    # Arrange: Configure the autospecced `Analyzer` to return a single regional
    # result containing an API error (`403 PermissionDenied`).
    mock_analyzer = mock.create_autospec(
        analyzer.Analyzer, instance=True, spec_set=True
    )
    mock_analyzer_class.return_value = mock_analyzer
    mock_analyzer.analyze_static_taxonomies.return_value = [
        analyzer.StaticTaxonomyAnalysisResult(
            project_id="source-project",
            location="us",
            error="403 PermissionDenied",
        )
    ]
    mock_analyzer.generate_static_taxonomy_report.return_value = "Error Report"

    # Act & Assert: Running `--phase analyze` prints the error report and exits
    # with status code 1 so automated pipelines detect the total failure.
    with mock.patch.object(
        sys,
        "argv",
        [
            "main.py",
            "--phase",
            "analyze",
            "--taxonomy-project-id",
            "source-project",
            "--regions",
            "us",
        ],
    ):
      with self.assertRaises(SystemExit) as context:
        main.main()
      self.assertEqual(context.exception.code, 1)
    self.assertFalse(mock_analyzer_class.call_args.kwargs["halt_on_error"])

    # Passing --halt-on-error wires halt_on_error=True into Analyzer.__init__.
    with mock.patch.object(
        sys,
        "argv",
        [
            "main.py",
            "--phase",
            "analyze",
            "--taxonomy-project-id",
            "source-project",
            "--regions",
            "us-nonexistent99,us",
            "--halt-on-error",
        ],
    ):
      with self.assertRaises(SystemExit) as context:
        main.main()
      self.assertEqual(context.exception.code, 1)
    self.assertTrue(mock_analyzer_class.call_args.kwargs["halt_on_error"])

  # Static DGT analysis must forward --dgt-project-id and normalized
  # --data-policy-v2-project-ids to Analyzer.analyze_static_dgt.
  @mock.patch.object(main, "Analyzer", autospec=True)
  def test_analyze_static_dgt_dispatches_dgt_and_data_policy_projects(
      self, mock_analyzer_class
  ):
    """Verifies `static-dgt` forwards separate DGT and Data Policy projects."""
    mock_analyzer = mock.create_autospec(
        analyzer.Analyzer, instance=True, spec_set=True
    )
    mock_analyzer_class.return_value = mock_analyzer
    mock_analyzer.analyze_static_dgt.return_value = [
        analyzer.StaticDgtAnalysisResult(
            project_id="policy-project-1",
            location="us",
            dgt_project_id="dgt-project",
        )
    ]
    mock_analyzer.generate_static_dgt_report.return_value = "# DGT Report"

    # Pass mixed comma-separated and space-separated --data-policy-v2-project-
    # ids to verify multi-value normalization before Analyzer dispatch.
    with mock.patch.object(
        sys,
        "argv",
        [
            "main.py",
            "--phase",
            "analyze",
            "--analyze-type",
            constants.ANALYZE_TYPE_STATIC_DGT,
            "--dgt-project-id",
            "dgt-project",
            "--data-policy-v2-project-ids",
            "policy-project-1,policy-project-2",
            "policy-project-3",
            "--regions",
            "us,eu",
        ],
    ):
      main.main()

    # Confirm Analyzer.analyze_static_dgt received the singular DGT project and
    # the normalized list of V2 Data Policy projects.
    mock_analyzer.analyze_static_dgt.assert_called_once_with(
        "dgt-project",
        ["us", "eu"],
        data_policy_v2_project_ids=[
            "policy-project-1",
            "policy-project-2",
            "policy-project-3",
        ],
    )

  @mock.patch.object(main, "Planner", autospec=True)
  @mock.patch.object(main, "Analyzer", autospec=True)
  def test_plan_phase_exits_nonzero_when_all_regions_fail(
      self, mock_analyzer_class, mock_planner_class
  ):
    """Verifies `--phase plan` aborts with code 1 when all regions fail."""
    # Arrange: Configure `Analyzer` to return a failed regional result and
    # autospec `Planner`.
    mock_analyzer = mock.create_autospec(
        analyzer.Analyzer, instance=True, spec_set=True
    )
    mock_analyzer_class.return_value = mock_analyzer
    mock_planner = mock.create_autospec(
        planner.Planner, instance=True, spec_set=True
    )
    mock_planner_class.return_value = mock_planner
    mock_analyzer.analyze_static_taxonomies.return_value = [
        analyzer.StaticTaxonomyAnalysisResult(
            project_id="source-project",
            location="us",
            error="403 PermissionDenied",
        )
    ]

    # Act & Assert: Running `--phase plan` exits with status code 1 and never
    # invokes `Planner.generate_plan()` on an empty/failed discovery set.
    with mock.patch.object(
        sys,
        "argv",
        [
            "main.py",
            "--phase",
            "plan",
            "--taxonomy-project-id",
            "source-project",
            "--regions",
            "us",
            "--target-dgt-project-id",
            "target-dgt-project",
            "--target-default-dp-project-id",
            "target-policy-project",
        ],
    ):
      with self.assertRaises(SystemExit) as context:
        main.main()
      self.assertEqual(context.exception.code, 1)
      mock_planner.generate_plan.assert_not_called()

  @mock.patch.object(main, "Planner", autospec=True)
  @mock.patch.object(main, "Analyzer", autospec=True)
  def test_plan_phase_writes_plan_and_report_files_in_mode_2(
      self, mock_analyzer_class, mock_planner_class
  ):
    """Verifies `--phase plan` in Mode 2 writes plan JSON and Markdown files."""
    # Arrange: Configure `Analyzer` and `Planner` mocks for a successful Mode 2
    # (`--target-table-dp-project-ids`) run writing to nested output paths.
    mock_analyzer = mock.create_autospec(
        analyzer.Analyzer, instance=True, spec_set=True
    )
    mock_analyzer_class.return_value = mock_analyzer
    mock_analyzer.analyze_static_taxonomies.return_value = [
        analyzer.StaticTaxonomyAnalysisResult(
            project_id="source-project",
            location="us",
            taxonomies=[],
        )
    ]

    mock_planner = mock.create_autospec(
        planner.Planner, instance=True, spec_set=True
    )
    mock_planner_class.return_value = mock_planner
    expected_plan = {"metadata": {"source_project_id": "source-project"}}
    mock_planner.generate_plan.return_value = expected_plan
    mock_planner.generate_markdown_report.return_value = "# Plan Report"

    with tempfile.TemporaryDirectory() as temp_dir:
      plan_path = os.path.join(temp_dir, "nested", "plan.json")
      report_path = os.path.join(temp_dir, "nested", "plan_report.md")

      # Act: Execute `main()` in Mode 2 with comma-separated table project IDs.
      with mock.patch.object(
          sys,
          "argv",
          [
              "main.py",
              "--phase",
              "plan",
              "--taxonomy-project-id",
              "source-project",
              "--regions",
              "us,eu",
              "--target-dgt-project-id",
              "target-dgt-project",
              "--target-table-dp-project-ids",
              "table-proj-1,table-proj-2",
              "--collision-resolution",
              constants.COLLISION_RESOLUTION_FROM_REGION,
              "--plan-file",
              plan_path,
              "--report-file",
              report_path,
          ],
      ):
        main.main()

      # Assert: `Planner.generate_plan` received Mode 2 parameters and both
      # output files were created in the auto-created `nested/` directory.
      mock_planner.generate_plan.assert_called_once_with(
          mock_analyzer.analyze_static_taxonomies.return_value,
          target_dgt_project_id="target-dgt-project",
          target_data_policy_project_ids=["table-proj-1", "table-proj-2"],
          target_data_policy_mode=(
              constants.TARGET_DATA_POLICY_MODE_TABLE_PROJECTS
          ),
          collision_resolution=constants.COLLISION_RESOLUTION_FROM_REGION,
      )
      with open(plan_path, "r", encoding="utf-8") as plan_file:
        self.assertEqual(json.load(plan_file), expected_plan)
      with open(report_path, "r", encoding="utf-8") as report_file:
        self.assertEqual(report_file.read(), "# Plan Report\n")

  @mock.patch.object(main, "Analyzer", autospec=True)
  def test_custom_endpoints_and_execution_project_wired_to_clients(
      self, mock_analyzer_class
  ):
    """Verifies VPC-SC endpoint and `--execution-project` flags wire up."""
    # Arrange: Configure `Analyzer` mock for a `column-binding` run with custom
    # service endpoints and a dedicated `--execution-project`.
    mock_analyzer = mock.create_autospec(
        analyzer.Analyzer, instance=True, spec_set=True
    )
    mock_analyzer_class.return_value = mock_analyzer
    mock_analyzer.analyze_column_bindings.return_value = [
        analyzer.ColumnBindingAnalysisResult(
            project_id="source-project", location="us"
        )
    ]
    mock_analyzer.generate_column_binding_report.return_value = "Binding Report"

    # Act: Run `main()` with custom VPC-SC endpoints (passing an `https://` URL
    # to `--datacatalog-endpoint` and a bare hostname to `--bigquery-endpoint`)
    # and `--execution-project`.
    with mock.patch.object(
        sys,
        "argv",
        [
            "main.py",
            "--phase",
            "analyze",
            "--analyze-type",
            constants.ANALYZE_TYPE_COLUMN_BINDING,
            "--table-project-id",
            "source-project",
            "--execution-project",
            "billing-project",
            "--regions",
            "us",
            "--datacatalog-endpoint",
            "https://datacatalog.mtls.googleapis.com/",
            "--bigquery-endpoint",
            "bigquery.mtls.googleapis.com",
        ],
    ):
      main.main()

    # Assert: `PolicyTagManagerClient` receives a scheme-stripped gRPC hostname,
    # `bigquery.Client` receives an `https://`-prefixed REST base URL, and
    # `Analyzer` receives `execution_project`.
    datacatalog_kwargs = self.mock_datacatalog.call_args.kwargs
    self.assertEqual(
        datacatalog_kwargs["client_options"].api_endpoint,
        "datacatalog.mtls.googleapis.com",
    )
    bigquery_kwargs = self.mock_bigquery.call_args.kwargs
    self.assertEqual(
        bigquery_kwargs["client_options"].api_endpoint,
        "https://bigquery.mtls.googleapis.com",
    )
    self.assertEqual(
        mock_analyzer_class.call_args.kwargs["execution_project"],
        "billing-project",
    )

  # ============================================================================
  # Section 4: Phase 2a (`create`), Phase 2b (`delete`) & Phase 3 (`swap`)
  # ============================================================================

  @mock.patch.object(main, "Creator", autospec=True)
  def test_create_all_exits_nonzero_when_resources_fail(
      self, mock_creator_class
  ):
    """Verifies `--phase create --all` exits with code 1 on partial failures."""
    # Arrange: Configure `Creator` mock with a failure recorded in
    # `last_summary` and in the Markdown report's `### Failed Creations`
    # section.
    mock_creator = mock.create_autospec(
        creator.Creator, instance=True, spec_set=False
    )
    mock_creator.last_summary = {"succeeded": 1, "skipped": 0, "failed": 1}
    mock_creator.create_all_dgt_resources.return_value = (
        "# Data Governance Tag Resource Creation Report\n"
        "### Failed Creations\n- my-project/my_key: 403 PermissionDenied\n"
    )
    mock_creator_class.return_value = mock_creator

    plan_data = {constants.KEY_PHASE_2_RESOURCE_MANIFEST: {}}
    with tempfile.TemporaryDirectory() as temp_dir:
      plan_path = os.path.join(temp_dir, "plan.json")
      with open(plan_path, "w", encoding="utf-8") as file_handle:
        json.dump(plan_data, file_handle)

      # Act & Assert: Running `--phase create --all` exits with status code 1
      # and does not instantiate `bigquery.Client` during Phase 2a.
      self.mock_bigquery.reset_mock()
      with mock.patch.object(
          sys,
          "argv",
          [
              "main.py",
              "--phase",
              "create",
              "--plan-file",
              plan_path,
              "--all",
              "--skip-confirmation",
          ],
      ):
        with self.assertRaises(SystemExit) as context:
          main.main()
        self.assertEqual(context.exception.code, 1)
      self.mock_bigquery.assert_not_called()

  @mock.patch.object(main, "Deleter", autospec=True)
  def test_delete_phase_passes_report_file(self, mock_deleter_class):
    """Verifies `--phase delete` forwards `--report-file` to `Deleter`."""
    # Arrange: Create a temporary `plan.json` and configure the autospecced
    # `Deleter` instance.
    mock_deleter = mock.create_autospec(
        deleter.Deleter, instance=True, spec_set=True
    )
    mock_deleter_class.return_value = mock_deleter
    mock_deleter.delete_individual_dgt_resource.return_value = (
        "# Resource Deletion Report"
    )
    plan_data = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS: [
                {constants.FIELD_NAMESPACED_NAME: "my-project/my_key"}
            ]
        }
    }
    with tempfile.TemporaryDirectory() as temp_dir:
      plan_path = os.path.join(temp_dir, "plan.json")
      report_path = os.path.join(temp_dir, "delete_report.md")
      with open(plan_path, "w", encoding="utf-8") as file_handle:
        json.dump(plan_data, file_handle)

      # Act: Run `main()` with `--phase delete` and `--report-file`.
      self.mock_bigquery.reset_mock()
      with mock.patch.object(
          sys,
          "argv",
          [
              "main.py",
              "--phase",
              "delete",
              "--plan-file",
              plan_path,
              "--resource-type",
              constants.RESOURCE_TYPE_DG_TAG_KEY,
              "--resource-name",
              "my-project/my_key",
              "--report-file",
              report_path,
              "--skip-confirmation",
          ],
      ):
        main.main()

      # Assert: `delete_individual_dgt_resource` received the exact
      # `report_file` path and `bigquery.Client` was not instantiated.
      mock_deleter.delete_individual_dgt_resource.assert_called_once_with(
          plan_data,
          "my-project/my_key",
          constants.RESOURCE_TYPE_DG_TAG_KEY,
          report_file=report_path,
      )
      self.mock_bigquery.assert_not_called()

  # Verifies --phase delete --dry-run exits with code 1 when deletion is BLOCKED
  # by child dependencies.
  @mock.patch.object(main, "Deleter", autospec=True)
  def test_delete_phase_exits_nonzero_when_blocked(self, mock_deleter_class):
    mock_deleter = mock.create_autospec(
        deleter.Deleter, instance=True, spec_set=True
    )
    mock_deleter_class.return_value = mock_deleter
    # Simulate a dry-run deletion report where live child Tag Values block
    # deleting the parent Tag Key.
    mock_deleter.delete_individual_dgt_resource.return_value = (
        "# Resource Deletion Report (DRY RUN)\n- **Status**: **BLOCKED**\n"
    )
    plan_data = {
        constants.KEY_PHASE_2_RESOURCE_MANIFEST: {
            constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS: [
                {constants.FIELD_NAMESPACED_NAME: "my-project/my_key"}
            ]
        }
    }
    with tempfile.TemporaryDirectory() as temp_dir:
      plan_path = os.path.join(temp_dir, "plan.json")
      with open(plan_path, "w", encoding="utf-8") as file_handle:
        json.dump(plan_data, file_handle)

      # Running --phase delete --dry-run must exit with status code 1 so
      # automated callers detect the BLOCKED dependency state.
      with mock.patch.object(
          sys,
          "argv",
          [
              "main.py",
              "--phase",
              "delete",
              "--plan-file",
              plan_path,
              "--resource-type",
              constants.RESOURCE_TYPE_DG_TAG_KEY,
              "--resource-name",
              "my-project/my_key",
              "--dry-run",
          ],
      ):
        with self.assertRaises(SystemExit) as context:
          main.main()
        self.assertEqual(context.exception.code, 1)

  @mock.patch.object(main, "Swapper", autospec=True)
  def test_swap_phase_exits_nonzero_on_blocked_or_corrupted_status(
      self, mock_swapper_class
  ):
    """Verifies `--phase swap` exits code 1 when parity or corruption blocks."""
    # Arrange: Configure `Swapper.swap_schemas` to return a table result with
    # `SWAP_STATUS_BLOCKED_PARITY_DISCREPANCY`.
    mock_swapper = mock.create_autospec(
        swapper.Swapper, instance=True, spec_set=True
    )
    mock_swapper_class.return_value = mock_swapper
    blocked_result = swapper.TableSwapResult(
        project_id="data-proj",
        dataset_id="ds",
        table_id="tbl",
        location="us",
        status=constants.SWAP_STATUS_BLOCKED_PARITY_DISCREPANCY,
    )
    mock_swapper.swap_schemas.return_value = ([blocked_result], "# Swap Report")

    plan_data = {constants.KEY_PHASE_2_RESOURCE_MANIFEST: {}}
    with tempfile.TemporaryDirectory() as temp_dir:
      plan_path = os.path.join(temp_dir, "plan.json")
      with open(plan_path, "w", encoding="utf-8") as file_handle:
        json.dump(plan_data, file_handle)

      # Act & Assert: Running `--phase swap` exits with status code 1 when a
      # table is blocked by enforcement parity verification.
      with mock.patch.object(
          sys,
          "argv",
          [
              "main.py",
              "--phase",
              "swap",
              "--plan-file",
              plan_path,
              "--regions",
              "us",
              "--table-ids",
              "data-proj.ds.tbl",
              "--dry-run",
          ],
      ):
        with self.assertRaises(SystemExit) as context:
          main.main()
        self.assertEqual(context.exception.code, 1)

      # Omitting --regions in --phase swap must fail fast with SystemExit(2).
      with mock.patch.object(
          sys,
          "argv",
          [
              "main.py",
              "--phase",
              "swap",
              "--plan-file",
              plan_path,
              "--table-ids",
              "data-proj.ds.tbl",
              "--dry-run",
          ],
      ):
        with self.assertRaises(SystemExit) as context:
          main.main()
        self.assertEqual(context.exception.code, 2)

  @mock.patch.object(main, "Creator", autospec=True)
  def test_create_wires_allow_unresolved_plan_warnings_and_exits_1_when_blocked(
      self, mock_creator_class
  ):
    """Wires `--allow-unresolved-plan-warnings` and exits 1 when blocked."""
    # Return a blocked report on run 1 and a clean report on run 2.
    blocked_creator = mock.create_autospec(
        creator.Creator, instance=True, spec_set=False
    )
    blocked_creator.create_all_dgt_resources.return_value = (
        f"- **Status:** {constants.STATUS_BLOCKED_UNRESOLVED_PLAN_WARNINGS}"
    )
    blocked_creator.last_summary = {"succeeded": 0, "skipped": 0, "failed": 1}

    allowed_creator = mock.create_autospec(
        creator.Creator, instance=True, spec_set=False
    )
    allowed_creator.create_all_dgt_resources.return_value = "# Clean Report"
    allowed_creator.last_summary = {"succeeded": 1, "skipped": 0, "failed": 0}
    mock_creator_class.side_effect = [blocked_creator, allowed_creator]

    with tempfile.TemporaryDirectory() as temp_dir:
      plan_path = os.path.join(temp_dir, "plan.json")
      with open(plan_path, "w", encoding="utf-8") as file_handle:
        json.dump({constants.KEY_PHASE_2_RESOURCE_MANIFEST: {}}, file_handle)

      # Without `--allow-unresolved-plan-warnings`, blocked creation exits 1.
      with mock.patch.object(
          sys,
          "argv",
          [
              "main.py",
              "--phase",
              "create",
              "--plan-file",
              plan_path,
              "--all",
              "--dry-run",
          ],
      ):
        with self.assertRaises(SystemExit) as context:
          main.main()
        self.assertEqual(context.exception.code, 1)
      self.assertFalse(
          mock_creator_class.call_args_list[0].kwargs[
              "allow_unresolved_plan_warnings"
          ]
      )

      # Passing `--allow-unresolved-plan-warnings` sets the Creator flag True.
      with mock.patch.object(
          sys,
          "argv",
          [
              "main.py",
              "--phase",
              "create",
              "--plan-file",
              plan_path,
              "--all",
              "--dry-run",
              "--allow-unresolved-plan-warnings",
          ],
      ):
        main.main()
      self.assertTrue(
          mock_creator_class.call_args_list[1].kwargs[
              "allow_unresolved_plan_warnings"
          ]
      )

  @mock.patch.object(main, "Swapper", autospec=True)
  def test_swap_wires_allow_unresolved_plan_warnings_and_exits_1_when_blocked(
      self, mock_swapper_class
  ):
    """Exits 1 on `SWAP_STATUS_BLOCKED_UNRESOLVED_PLAN_WARNINGS` in swap."""
    # Configure Swapper mock to return a plan-warning block status.
    mock_swapper = mock.create_autospec(
        swapper.Swapper, instance=True, spec_set=True
    )
    blocked_result = swapper.TableSwapResult(
        project_id="data-proj",
        dataset_id="ds",
        table_id="tbl",
        location="us",
        status=constants.SWAP_STATUS_BLOCKED_UNRESOLVED_PLAN_WARNINGS,
    )
    mock_swapper.swap_schemas.return_value = ([blocked_result], "# Blocked")
    mock_swapper_class.return_value = mock_swapper

    with tempfile.TemporaryDirectory() as temp_dir:
      plan_path = os.path.join(temp_dir, "plan.json")
      with open(plan_path, "w", encoding="utf-8") as file_handle:
        json.dump({constants.KEY_PHASE_2_RESOURCE_MANIFEST: {}}, file_handle)

      # Verify CLI exits with status code 1 and forwards the default False flag.
      with mock.patch.object(
          sys,
          "argv",
          [
              "main.py",
              "--phase",
              "swap",
              "--plan-file",
              plan_path,
              "--regions",
              "us",
              "--table-ids",
              "data-proj.ds.tbl",
              "--dry-run",
          ],
      ):
        with self.assertRaises(SystemExit) as context:
          main.main()
        self.assertEqual(context.exception.code, 1)
      self.assertFalse(
          mock_swapper_class.call_args.kwargs["allow_unresolved_plan_warnings"]
      )

  # Verifies `_print_stdout_report` separates shared console logs with blank
  # lines while keeping redirected `stdout` files pure.
  def test_print_stdout_report_separates_shared_console_and_keeps_redirect_pure(
      self,
  ):
    """Separates shared console stderr logs without polluting stdout files."""
    # When stdout and stderr share a terminal (`_streams_share_destination`
    # True), surrounding blank lines are emitted on stderr around stdout.
    shared_stdout = io.StringIO()
    shared_stderr = io.StringIO()
    with (
        mock.patch.object(
            main, "_streams_share_destination", return_value=True
        ),
        mock.patch.object(sys, "stdout", shared_stdout),
        mock.patch.object(sys, "stderr", shared_stderr),
    ):
      main._print_stdout_report("# Static Taxonomy Report")
    self.assertEqual(shared_stdout.getvalue(), "# Static Taxonomy Report\n")
    self.assertEqual(shared_stderr.getvalue(), "\n\n")

    # When stdout is redirected to a separate file (`_streams_share_destination`
    # False), neither stdout nor stderr receives extra blank lines.
    redirected_stdout = io.StringIO()
    redirected_stderr = io.StringIO()
    with (
        mock.patch.object(
            main, "_streams_share_destination", return_value=False
        ),
        mock.patch.object(sys, "stdout", redirected_stdout),
        mock.patch.object(sys, "stderr", redirected_stderr),
    ):
      main._print_stdout_report("# Static Taxonomy Report")
    self.assertEqual(redirected_stdout.getvalue(), "# Static Taxonomy Report\n")
    self.assertEqual(redirected_stderr.getvalue(), "")

  # Suppresses urllib3.connectionpool keep-alive discard warnings during normal
  # runs while keeping debug-level visibility when --debug is enabled.
  @mock.patch.object(main, "Analyzer", autospec=True)
  def test_main_suppresses_urllib3_pool_warnings_unless_debug(
      self, mock_analyzer_class
  ):
    """Sets `urllib3.connectionpool` to `ERROR` unless `--debug` is passed."""
    # Configure Analyzer mock to return a valid static-taxonomy result.
    mock_analyzer = mock.create_autospec(
        analyzer.Analyzer, instance=True, spec_set=True
    )
    mock_analyzer.analyze_static_taxonomies.return_value = [
        analyzer.StaticTaxonomyAnalysisResult(
            project_id="tax-proj", location="us"
        )
    ]
    mock_analyzer.generate_static_taxonomy_report.return_value = "# Report"
    mock_analyzer_class.return_value = mock_analyzer
    pool_logger = main.logging.getLogger("urllib3.connectionpool")

    # Without --debug, urllib3.connectionpool is raised to logging.ERROR.
    pool_logger.setLevel(main.logging.NOTSET)
    with mock.patch.object(
        sys,
        "argv",
        [
            "main.py",
            "--phase",
            "analyze",
            "--analyze-type",
            "static-taxonomy",
            "--taxonomy-project-id",
            "tax-proj",
            "--regions",
            "us",
        ],
    ):
      main.main()
    self.assertEqual(pool_logger.level, main.logging.ERROR)

    # With --debug, urllib3.connectionpool is not forced to logging.ERROR.
    pool_logger.setLevel(main.logging.NOTSET)
    with mock.patch.object(
        sys,
        "argv",
        [
            "main.py",
            "--phase",
            "analyze",
            "--analyze-type",
            "static-taxonomy",
            "--taxonomy-project-id",
            "tax-proj",
            "--regions",
            "us",
            "--debug",
        ],
    ):
      main.main()
    self.assertEqual(pool_logger.level, main.logging.NOTSET)

  # Aborting `--phase plan --halt-on-error` must log the abort error without
  # emitting the contradictory `Plan might be incomplete.` warning.
  @mock.patch.object(main, "Planner", autospec=True)
  @mock.patch.object(main, "Analyzer", autospec=True)
  def test_plan_phase_halt_on_error_aborts_without_incomplete_plan_warning(
      self, mock_analyzer_class, mock_planner_class
  ):
    """Aborts `--phase plan --halt-on-error` without partial-plan warnings."""
    # Return one failed region and one healthy region to exercise the
    # `--halt-on-error` abort branch in `--phase plan`.
    mock_analyzer = mock.create_autospec(
        analyzer.Analyzer, instance=True, spec_set=True
    )
    mock_analyzer.analyze_static_taxonomies.return_value = [
        analyzer.StaticTaxonomyAnalysisResult(
            project_id="source-project",
            location="us-nonexistent99",
            error="501 Invalid regional endpoint.",
        ),
        analyzer.StaticTaxonomyAnalysisResult(
            project_id="source-project",
            location="us",
            taxonomies=[],
        ),
    ]
    mock_analyzer_class.return_value = mock_analyzer
    mock_planner = mock.create_autospec(
        planner.Planner, instance=True, spec_set=True
    )
    mock_planner_class.return_value = mock_planner

    # Execute `--phase plan --halt-on-error` while capturing `main.logger`
    # records.
    with (
        self.assertLogs(main.logger, level="WARNING") as log_context,
        mock.patch.object(
            sys,
            "argv",
            [
                "main.py",
                "--phase",
                "plan",
                "--taxonomy-project-id",
                "source-project",
                "--regions",
                "us-nonexistent99,us",
                "--target-dgt-project-id",
                "target-dgt-project",
                "--target-default-dp-project-id",
                "target-policy-project",
                "--halt-on-error",
            ],
        ),
    ):
      with self.assertRaises(SystemExit) as context:
        main.main()
      self.assertEqual(context.exception.code, 1)

    # Confirm the abort error was logged, no `Plan might be incomplete.` warning
    # was emitted, and `Planner.generate_plan` was not called.
    self.assertEqual(
        [
            (record.levelname, record.getMessage())
            for record in log_context.records
        ],
        [(
            "ERROR",
            "Aborting plan generation due to static taxonomy analysis errors.",
        )],
    )
    mock_planner.generate_plan.assert_not_called()

  # Verifies `--log-file` captures pre-FileHandler overwrite audit notices and
  # structured `[DEBUG]` CLI/client initialization traces when `--debug` is set.
  @mock.patch.object(main, "Analyzer", autospec=True)
  def test_log_file_records_overwrite_audit_and_debug_traces(
      self, mock_analyzer_class
  ):
    """Persists overwrite notices and `[DEBUG]` traces into `--log-file`."""
    mock_analyzer = mock.create_autospec(
        analyzer.Analyzer, instance=True, spec_set=True
    )
    mock_analyzer.analyze_static_taxonomies.return_value = [
        analyzer.StaticTaxonomyAnalysisResult(
            project_id="tax-proj", location="us"
        )
    ]
    mock_analyzer.generate_static_taxonomy_report.return_value = "# Report"
    mock_analyzer_class.return_value = mock_analyzer

    with tempfile.TemporaryDirectory() as temp_dir:
      report_path = os.path.join(temp_dir, "report.md")
      log_path = os.path.join(temp_dir, "debug.log")
      # Pre-populate report.md so the pre-FileHandler overwrite guard triggers.
      with open(report_path, "w", encoding="utf-8") as report_handle:
        report_handle.write("existing report")

      with mock.patch.object(
          sys,
          "argv",
          [
              "main.py",
              "--phase",
              "analyze",
              "--analyze-type",
              "static-taxonomy",
              "--taxonomy-project-id",
              "tax-proj",
              "--regions",
              "us",
              "--report-file",
              report_path,
              "--log-file",
              log_path,
              "--debug",
              "--overwrite",
              "--skip-confirmation",
          ],
      ):
        main.main()

      # Verify the opened log file starts with the overwrite audit entry and
      # records application-level [DEBUG] trace points.
      with open(log_path, "r", encoding="utf-8") as log_handle:
        log_contents = log_handle.read()
      self.assertIn(f"Overwriting existing file: {report_path}", log_contents)
      self.assertIn("[DEBUG]", log_contents)
      self.assertIn("CLI arguments validated:", log_contents)
      self.assertIn("Initialized Google Cloud SDK clients", log_contents)

  # Read-only directory failures must report the target directory without
  # leaking the internal `.migration_write_check_*` probe filename.
  def test_verify_output_file_writable_hides_temp_probe_filename(self):
    """Formats read-only directory errors without internal temp filenames."""
    with (
        mock.patch.object(
            tempfile,
            "NamedTemporaryFile",
            side_effect=PermissionError(
                13,
                "Permission denied",
                "/tmp/ro_dir/.migration_write_check_secret",
            ),
        ),
        self.assertLogs(main.logger, level="ERROR") as log_context,
    ):
      with self.assertRaises(SystemExit) as context:
        main._verify_output_file_writable("/tmp/ro_dir/cannot_write.md")
      self.assertEqual(context.exception.code, 1)

    logged_error_text = "\n".join(log_context.output)
    self.assertIn(
        "Permission denied writing to directory '/tmp/ro_dir'",
        logged_error_text,
    )
    self.assertNotIn(".migration_write_check_", logged_error_text)

  # When individual `--phase create --dry-run` fails a pre-flight validation
  # check (such as a non-DATA_GOVERNANCE Tag Key purpose), `main.py` must log
  # the specific `last_error_message` from `Creator`.
  @mock.patch.object(main, "Creator", autospec=True)
  def test_create_individual_dry_run_failure_logs_detailed_last_error_message(
      self, mock_creator_class
  ):
    """Logs `creator.last_error_message` on failed dry-run individual create."""
    mock_creator = mock_creator_class.return_value
    mock_creator.create_individual_dgt_resource.return_value = (
        "# Individual Report\n- **Status:** Failed\n"
    )
    mock_creator.last_summary = {"succeeded": 0, "skipped": 0, "failed": 1}
    mock_creator.last_error_message = (
        "Tag Key 'p1/k1' already exists with non-DATA_GOVERNANCE purpose."
    )

    with tempfile.TemporaryDirectory() as temp_dir:
      plan_path = os.path.join(temp_dir, "plan.json")
      with open(plan_path, "w", encoding="utf-8") as plan_file:
        plan_file.write("{}")
      with (
          mock.patch.object(
              sys,
              "argv",
              [
                  "main.py",
                  "--phase",
                  "create",
                  "--plan-file",
                  plan_path,
                  "--resource-type",
                  "dg-tag-key",
                  "--resource-name",
                  "p1/k1",
                  "--dry-run",
              ],
          ),
          self.assertLogs(main.logger, level="ERROR") as log_context,
      ):
        with self.assertRaises(SystemExit) as context:
          main.main()
        self.assertEqual(context.exception.code, 1)

    self.assertIn(
        "Failed to create individual resource: Tag Key 'p1/k1' already exists"
        " with non-DATA_GOVERNANCE purpose.",
        "\n".join(log_context.output),
    )

  # When `--phase swap` fails mid-batch without `--report-file`, `main.py` must
  # print `swapper.last_report` to stdout before exiting with status code 1.
  @mock.patch.object(main, "Swapper", autospec=True)
  @mock.patch.object(main, "_verify_directory_writable")
  def test_swap_failure_prints_partial_last_report_to_stdout(
      self, mock_verify_dir, mock_swapper_class
  ):
    """Prints `swapper.last_report` on stdout when `--phase swap` raises."""
    del mock_verify_dir  # Unused
    mock_swapper = mock_swapper_class.return_value
    mock_swapper.swap_schemas.side_effect = RuntimeError("Mid-batch failure")
    mock_swapper.last_report = "# Phase 3 Swap Report\nPartial results\n"

    with tempfile.TemporaryDirectory() as temp_dir:
      plan_path = os.path.join(temp_dir, "plan.json")
      with open(plan_path, "w", encoding="utf-8") as plan_file:
        plan_file.write("{}")
      with (
          mock.patch.object(
              sys,
              "argv",
              [
                  "main.py",
                  "--phase",
                  "swap",
                  "--plan-file",
                  plan_path,
                  "--table-ids",
                  "proj.ds.t1",
                  "--regions",
                  "us",
                  "--skip-confirmation",
              ],
          ),
          mock.patch.object(main, "_print_stdout_report") as mock_print_report,
          self.assertLogs(main.logger, level="ERROR"),
      ):
        with self.assertRaises(SystemExit) as context:
          main.main()
        self.assertEqual(context.exception.code, 1)

    mock_print_report.assert_called_once_with(
        "# Phase 3 Swap Report\nPartial results\n"
    )

  # `--allow-fail-open-policy-delete` wires into `Deleter` in `delete` phase and
  # fails fast with `SystemExit(2)` outside `delete`.
  @mock.patch.object(main, "Deleter", autospec=True)
  def test_delete_wires_allow_fail_open_policy_delete_and_guards_phase(
      self, mock_deleter_class
  ):
    """Wires `--allow-fail-open-policy-delete` to `Deleter` and guards phase."""
    mock_deleter = mock_deleter_class.return_value
    mock_deleter.delete_individual_dgt_resource.return_value = "# Deleted"

    with tempfile.TemporaryDirectory() as temp_dir:
      plan_path = os.path.join(temp_dir, "plan.json")
      with open(plan_path, "w", encoding="utf-8") as plan_file:
        plan_file.write("{}")
      with mock.patch.object(
          sys,
          "argv",
          [
              "main.py",
              "--phase",
              "delete",
              "--plan-file",
              plan_path,
              "--resource-type",
              constants.RESOURCE_TYPE_DATA_POLICY_V2,
              "--resource-name",
              "proj/policy_default_deny",
              "--allow-fail-open-policy-delete",
              "--skip-confirmation",
          ],
      ):
        main.main()

      self.assertTrue(
          mock_deleter_class.call_args.kwargs["allow_fail_open_policy_delete"]
      )

      with mock.patch.object(
          sys,
          "argv",
          [
              "main.py",
              "--phase",
              "create",
              "--plan-file",
              plan_path,
              "--all",
              "--allow-fail-open-policy-delete",
          ],
      ):
        with self.assertRaises(SystemExit) as context:
          main.main()
        self.assertEqual(context.exception.code, 2)

  # `--skip-default-dp-org-check` wires into `Swapper` in `swap` phase and fails
  # fast with `SystemExit(2)` outside `swap`.
  @mock.patch.object(main, "Swapper", autospec=True)
  def test_swap_wires_skip_default_dp_org_check_and_guards_phase(
      self, mock_swapper_class
  ):
    """Wires `--skip-default-dp-org-check` to `Swapper` and guards phase."""
    mock_swapper = mock_swapper_class.return_value
    mock_swapper.swap_schemas.return_value = ([], "# Swap Report")

    with tempfile.TemporaryDirectory() as temp_dir:
      plan_path = os.path.join(temp_dir, "plan.json")
      with open(plan_path, "w", encoding="utf-8") as plan_file:
        plan_file.write("{}")
      with mock.patch.object(
          sys,
          "argv",
          [
              "main.py",
              "--phase",
              "swap",
              "--plan-file",
              plan_path,
              "--table-ids",
              "proj.ds.t1",
              "--regions",
              "us",
              "--dry-run",
              "--skip-default-dp-org-check",
          ],
      ):
        main.main()

      self.assertTrue(
          mock_swapper_class.call_args.kwargs["skip_default_dp_org_check"]
      )

      with mock.patch.object(
          sys,
          "argv",
          [
              "main.py",
              "--phase",
              "create",
              "--plan-file",
              plan_path,
              "--all",
              "--skip-default-dp-org-check",
          ],
      ):
        with self.assertRaises(SystemExit) as context:
          main.main()
        self.assertEqual(context.exception.code, 2)

  # Legacy domain-scoped project IDs containing ':' are rejected in Step 1 with
  # `SystemExit(2)` across CLI flags before any SDK clients are initialized.
  def test_main_rejects_domain_scoped_project_ids_across_phases(self):
    """Exits with code 2 when any CLI project or resource flag contains ':'."""
    domain_argv_cases = [
        [
            "main.py",
            "--phase",
            "analyze",
            "--taxonomy-project-id",
            "example.com:tax-proj",
            "--regions",
            "us",
        ],
        [
            "main.py",
            "--phase",
            "plan",
            "--taxonomy-project-id",
            "tax-proj",
            "--target-dgt-project-id",
            "example.com:dgt-proj",
            "--target-default-dp-project-id",
            "dp-proj",
            "--regions",
            "us",
        ],
        [
            "main.py",
            "--phase",
            "delete",
            "--plan-file",
            "plan.json",
            "--resource-type",
            constants.RESOURCE_TYPE_DG_TAG_KEY,
            "--resource-name",
            "example.com:dgt-proj/my_key",
        ],
        [
            "main.py",
            "--phase",
            "swap",
            "--plan-file",
            "plan.json",
            "--table-ids",
            "example.com:data-proj.ds.tbl",
            "--regions",
            "us",
        ],
    ]
    self.mock_tag_keys.reset_mock()
    for argv in domain_argv_cases:
      with self.subTest(argv=argv):
        with mock.patch.object(sys, "argv", argv):
          with self.assertRaises(SystemExit) as context:
            main.main()
          self.assertEqual(context.exception.code, 2)
    self.mock_tag_keys.assert_not_called()

  # Plaintext `http://` endpoint overrides and unsafe `--regions` or project ID
  # characters must fail CLI validation with exit code 2 before SDK init.
  def test_main_rejects_http_endpoints_and_unsafe_region_or_project_ids(self):
    invalid_cases = [
        [
            "main.py",
            "--phase",
            "analyze",
            "--analysis-mode",
            "static-taxonomy",
            "--taxonomy-project-id",
            "tax-proj",
            "--regions",
            "us",
            "--datapolicy-endpoint",
            "http://insecure.example.com",
        ],
        [
            "main.py",
            "--phase",
            "analyze",
            "--analysis-mode",
            "column-binding",
            "--table-project-id",
            "data-proj",
            "--regions",
            "us`; DROP TABLE x;--",
        ],
        [
            "main.py",
            "--phase",
            "analyze",
            "--analysis-mode",
            "static-taxonomy",
            "--taxonomy-project-id",
            "../bad/proj",
            "--regions",
            "us",
        ],
    ]
    for argv in invalid_cases:
      with self.subTest(argv=argv):
        with mock.patch.object(sys, "argv", argv):
          with self.assertRaises(SystemExit) as context:
            main.main()
          self.assertEqual(context.exception.code, 2)

  # Symlinked output report files must be rejected with exit code 1 before any
  # target file is overwritten or truncated.
  def test_main_rejects_symlink_output_report_file(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      real_target = os.path.join(temp_dir, "protected.txt")
      with open(real_target, "w", encoding="utf-8") as handle:
        handle.write("intact")
      symlink_report = os.path.join(temp_dir, "report_link.md")
      os.symlink(real_target, symlink_report)

      argv = [
          "main.py",
          "--phase",
          "analyze",
          "--analyze-type",
          "static-taxonomy",
          "--taxonomy-project-id",
          "tax-proj",
          "--regions",
          "us",
          "--overwrite",
          "--skip-confirmation",
          "--report-file",
          symlink_report,
      ]
      with mock.patch.object(sys, "argv", argv):
        with self.assertRaises(SystemExit) as context:
          main.main()
        self.assertEqual(context.exception.code, 1)

      with open(real_target, "r", encoding="utf-8") as handle:
        self.assertEqual(handle.read(), "intact")

  # CLI `create`, `delete`, and `swap` phases exit with code 1 and log a clear
  # upgrade/regenerate error when `--plan-file` has an unsupported version.
  def test_main_rejects_unsupported_plan_schema_version_across_phases(self):
    with tempfile.TemporaryDirectory() as temp_dir:
      future_plan_path = os.path.join(temp_dir, "future_plan.json")
      with open(future_plan_path, "w", encoding="utf-8") as handle:
        json.dump({"metadata": {"schema_version": 2}}, handle)

      phase_commands = [
          [
              "main.py",
              "--phase",
              "create",
              "--plan-file",
              future_plan_path,
              "--all",
              "--dry-run",
          ],
          [
              "main.py",
              "--phase",
              "delete",
              "--plan-file",
              future_plan_path,
              "--resource-type",
              "dg-tag-key",
              "--resource-name",
              "proj/key",
              "--dry-run",
          ],
          [
              "main.py",
              "--phase",
              "swap",
              "--plan-file",
              future_plan_path,
              "--table-ids",
              "proj.ds.tbl",
              "--regions",
              "us",
              "--dry-run",
          ],
      ]
      for argv in phase_commands:
        with self.subTest(phase=argv[2]):
          with mock.patch.object(sys, "argv", argv):
            with self.assertLogs(main.logger, level="ERROR") as log_ctx:
              with self.assertRaises(SystemExit) as exit_ctx:
                main.main()
          self.assertEqual(exit_ctx.exception.code, 1)
          self.assertTrue(
              any(
                  "Unsupported migration plan schema_version=2" in entry
                  for entry in log_ctx.output
              )
          )

  # `--phase swap` must wire `--execution-project` to both `bigquery.Client`
  # and `Swapper`, and fall back to the scoped table project for
  # `bigquery.Client(project=...)` when `--execution-project` is omitted so ADC
  # without an ambient default project never fails at client initialization.
  @mock.patch.object(main, "Swapper", autospec=True)
  def test_swap_wires_execution_project_and_default_bigquery_client_project(
      self, mock_swapper_class
  ):
    mock_swapper_class.return_value.swap_schemas.return_value = (
        [],
        "# Swap Report",
    )

    with tempfile.TemporaryDirectory() as temp_dir:
      plan_path = os.path.join(temp_dir, "plan.json")
      with open(plan_path, "w", encoding="utf-8") as plan_file:
        plan_file.write("{}")
      with mock.patch.object(
          sys,
          "argv",
          [
              "main.py",
              "--phase",
              "swap",
              "--plan-file",
              plan_path,
              "--table-ids",
              "data-proj.demo_ds.users",
              "--regions",
              "us",
              "--execution-project",
              "central-billing-proj",
              "--dry-run",
          ],
      ):
        main.main()

      self.assertEqual(
          self.mock_bigquery.call_args.kwargs["project"],
          "central-billing-proj",
      )
      self.assertEqual(
          mock_swapper_class.call_args.kwargs["execution_project"],
          "central-billing-proj",
      )

      self.mock_bigquery.reset_mock()
      mock_swapper_class.reset_mock()
      mock_swapper_class.return_value.swap_schemas.return_value = (
          [],
          "# Swap Report",
      )
      with mock.patch.object(
          sys,
          "argv",
          [
              "main.py",
              "--phase",
              "swap",
              "--plan-file",
              plan_path,
              "--table-ids",
              "data-proj.demo_ds.users",
              "--regions",
              "us",
              "--dry-run",
          ],
      ):
        main.main()

      self.assertEqual(
          self.mock_bigquery.call_args.kwargs["project"],
          "data-proj",
      )
      self.assertIsNone(
          mock_swapper_class.call_args.kwargs["execution_project"]
      )

  # Verifies `--version` prints the SemVer tool version and exits cleanly
  # without requiring `--phase` or initializing any Google Cloud clients.
  def test_version_flag_prints_semver_and_exits_zero(self):
    stdout_buffer = io.StringIO()
    with (
        mock.patch.object(sys, "argv", ["main.py", "--version"]),
        mock.patch.object(sys, "stdout", stdout_buffer),
        self.assertRaises(SystemExit) as exit_context,
    ):
      main.main()

    self.assertEqual(exit_context.exception.code, 0)
    self.assertEqual(
        stdout_buffer.getvalue().strip(), f"main.py {main.TOOL_VERSION}"
    )
    self.mock_datacatalog.assert_not_called()
    self.mock_bigquery.assert_not_called()

  # CLI validation must give actionable dot-notation hints for BigQuery CLI
  # colon syntax (`proj:ds.tbl`) and reserve the domain-scoped error for
  # domain-prefixed project IDs (`example.com:proj.ds.tbl`).
  def test_colon_identifier_errors_distinguish_bq_syntax_from_domain_scoped(
      self,
  ):
    """Distinguishes `bq`-style colon syntax from domain-scoped projects."""
    cases = [
        (
            ["--table-ids", "my-proj:ds.tbl"],
            (
                "Colon-separated BigQuery CLI notation is not supported; use"
                " dot-separated '<project_id>.<dataset_id>.<table_id>' instead"
                " (for example, 'my-proj.ds.tbl')"
            ),
        ),
        (
            ["--dataset-ids", "my-proj:ds"],
            (
                "Colon-separated BigQuery CLI notation is not supported; use"
                " dot-separated '<project_id>.<dataset_id>' instead (for"
                " example, 'my-proj.ds')"
            ),
        ),
        (
            ["--table-ids", "my-proj:ds"],
            (
                "Colon-separated BigQuery CLI notation is not supported; use"
                " dot-separated '<project_id>.<dataset_id>.<table_id>' instead."
            ),
        ),
        (
            ["--table-ids", "example.com:my-proj.ds.tbl"],
            constants.UNSUPPORTED_DOMAIN_SCOPED_PROJECT_MSG,
        ),
    ]
    for scope_args, expected_snippet in cases:
      stderr_buffer = io.StringIO()
      argv = [
          "main.py",
          "--phase",
          "swap",
          "--plan-file",
          "plan.json",
          "--regions",
          "us",
          *scope_args,
      ]
      with (
          mock.patch.object(sys, "argv", argv),
          mock.patch.object(sys, "stderr", stderr_buffer),
          self.assertRaises(SystemExit) as exit_context,
      ):
        main.main()
      self.assertEqual(exit_context.exception.code, 2)
      self.assertIn(expected_snippet, stderr_buffer.getvalue())

  # `_write_output_file` must terminate non-empty output files with exactly one
  # trailing newline while leaving empty content unchanged.
  def test_write_output_file_appends_single_trailing_newline(self):
    """Ensures `_write_output_file` appends a single POSIX trailing newline."""
    with tempfile.TemporaryDirectory() as temp_dir:
      no_newline_path = os.path.join(temp_dir, "report_no_nl.md")
      has_newline_path = os.path.join(temp_dir, "report_with_nl.md")
      empty_path = os.path.join(temp_dir, "empty.md")

      main._write_output_file(no_newline_path, "# Report", "Report")
      main._write_output_file(has_newline_path, "# Report\n", "Report")
      main._write_output_file(empty_path, "", "Report")

      with open(no_newline_path, "r", encoding="utf-8") as handle:
        self.assertEqual(handle.read(), "# Report\n")
      with open(has_newline_path, "r", encoding="utf-8") as handle:
        self.assertEqual(handle.read(), "# Report\n")
      with open(empty_path, "r", encoding="utf-8") as handle:
        self.assertEqual(handle.read(), "")


if __name__ == "__main__":
  unittest.main()
