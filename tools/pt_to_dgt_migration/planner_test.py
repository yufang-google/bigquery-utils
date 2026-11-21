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

"""Unit tests for the Phase 1b Planner and its naming/validation helpers.

This test suite verifies the pure functional transformation of Phase 1a static
analysis snapshots (`StaticTaxonomyAnalysisResult`) into the deterministic
`plan.json` manifest and `report.md` summary produced by `planner.py`.

Test Suite Organization:
1. `TestSanitizeName`: Verifies minimal whitespace sanitization
   (`sanitize_name`) for DG Tag Key and Tag Value short names.
2. `TestValidateShortName`: Verifies Resource Manager short name validation
   (`_validate_short_name`) for empty names, 63-character limits, start/end
   alphanumeric rules, and disallowed symbols.
3. `TestSanitizeAndValidateDataPolicyId`: Verifies V2 Data Policy ID
   sanitization (`sanitize_data_policy_id`) and validation
   (`_validate_data_policy_id`) for alphanumeric/underscore constraints and the
   200-character length limit.
4. `TestPlanner`: Verifies end-to-end plan generation (`generate_plan`),
   parent-child hierarchy preservation, intra-key and cross-region collision
   resolution (`counter` vs. `from_region`), V1-to-V2 masking translation,
   Raw Reader Parity vs. Default Deny Parity (`_default_deny`) generation,
   Classification-Only (Default Allow) preservation, 1,000-policy service quota
   warnings, Mode 1 vs. Mode 2 multi-project fan-out, DR readiness checks
   (`DR_WARN_01`..`DR_WARN_04`), IAM v1-to-v3 principal conversion, and
   Markdown report formatting (`generate_markdown_report`).
"""

from __future__ import annotations

import os
import sys
import types
from typing import Any
import unittest

# Stub external dependency that might not be available in the test environment.
sys.modules["google.cloud.datacatalog_v1"] = types.ModuleType(
    "google.cloud.datacatalog_v1"
)

# Ensure local imports work in both package and standalone script execution.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
# pylint: disable=g-import-not-at-top,g-bad-import-order
from analyzer import DataPolicyInfo
from analyzer import PolicyTagInfo
from analyzer import StaticTaxonomyAnalysisResult
from analyzer import TaxonomyInfo
import constants
from planner import _convert_to_iam_v3_principal
from planner import _validate_data_policy_id
from planner import _validate_short_name
from planner import Planner
from planner import sanitize_data_policy_id
from planner import sanitize_name

# pylint: enable=g-import-not-at-top,g-bad-import-order


# ==============================================================================
# === Section 1: DG Tag Short Name Sanitization Tests ===
# ==============================================================================


class TestSanitizeName(unittest.TestCase):
  """Tests for `sanitize_name` helper function."""

  def test_basic_sanitization(self):
    """Verifies spaces map to '_' while preserving case and punctuation."""
    # Arrange / Act / Assert: Spaces become underscores; existing underscores
    # and parentheses remain untouched so validation can inspect them.
    self.assertEqual(sanitize_name("My Taxonomy"), "My_Taxonomy")
    self.assertEqual(sanitize_name("Sensitive_Data"), "Sensitive_Data")
    self.assertEqual(sanitize_name("PII (Custom)"), "PII_(Custom)")

  def test_custom_space_replacement(self):
    """Verifies `sanitize_name` honors a custom `space_replacement` string."""
    # Arrange / Act / Assert: Replace spaces with hyphens instead of '_'.
    self.assertEqual(
        sanitize_name("My Taxonomy", space_replacement="-"), "My-Taxonomy"
    )

  def test_collapse_spaces(self):
    """Verifies consecutive whitespace collapsing vs. 1:1 replacement."""
    # Arrange / Act / Assert: collapse_spaces=True merges runs into a single
    # underscore; collapse_spaces=False replaces each character individually.
    self.assertEqual(
        sanitize_name("My   Taxonomy", collapse_spaces=True), "My_Taxonomy"
    )
    self.assertEqual(
        sanitize_name("My   Taxonomy", collapse_spaces=False), "My___Taxonomy"
    )

  def test_special_characters_kept(self):
    """Verifies punctuation and symbols are preserved for downstream checks."""
    # Arrange / Act / Assert: Disallowed symbols remain intact so
    # `_validate_short_name` can flag them explicitly in `plan.json`.
    self.assertEqual(
        sanitize_name("Tag with !@#$%^&*() spaces"),
        "Tag_with_!@#$%^&*()_spaces",
    )
    self.assertEqual(sanitize_name("Dots.and-Dashes."), "Dots.and-Dashes.")

  def test_trimming_not_done(self):
    """Verifies leading and trailing hyphens are not silently stripped."""
    # Arrange / Act / Assert: Leading/trailing hyphens stay intact.
    self.assertEqual(sanitize_name("---Trim Me---"), "---Trim_Me---")

  def test_empty_unmodified(self):
    """Verifies an empty string is returned unchanged."""
    # Arrange / Act / Assert: Empty input yields empty output.
    self.assertEqual(sanitize_name(""), "")

  def test_start_end_unmodified(self):
    """Verifies leading/trailing dots and hyphens remain for validation."""
    # Arrange / Act / Assert: Invalid boundary characters are preserved so
    # `_validate_short_name` can emit actionable warnings.
    self.assertEqual(sanitize_name(".starts-with-dot"), ".starts-with-dot")
    self.assertEqual(sanitize_name("ends-with-dot."), "ends-with-dot.")
    self.assertEqual(
        sanitize_name("-starts-with-hyphen"), "-starts-with-hyphen"
    )


# ==============================================================================
# === Section 2: DG Tag Short Name Validation Tests ===
# ==============================================================================


class TestValidateShortName(unittest.TestCase):
  """Tests for `_validate_short_name` helper function."""

  def test_valid_name(self):
    """Verifies valid DG Tag Key/Value short names produce zero warnings."""
    # Arrange / Act / Assert: Alphanumeric names with internal '-', '_', '.'
    # pass with an empty warning list.
    self.assertEqual(_validate_short_name("ValidTag"), [])
    self.assertEqual(_validate_short_name("Valid-Tag_1.0"), [])

  def test_empty_name(self):
    """Verifies an empty short name produces an explicit warning."""
    # Arrange / Act: Validate an empty string.
    warnings = _validate_short_name("")

    # Assert: The empty-name warning is returned.
    self.assertTrue(any("Name is empty." in w for w in warnings))

  def test_length_exceeded(self):
    """Verifies a 64-character short name triggers the 63-char limit warning."""
    # Arrange: Construct a 64-character string (1 over the 63-char limit).
    long_name = "a" * 64

    # Act: Validate the over-length name.
    warnings = _validate_short_name(long_name)

    # Assert: The 63-character limit warning is returned.
    self.assertTrue(any("exceeds 63 characters" in w for w in warnings))

  def test_invalid_start(self):
    """Verifies short names starting with '-' or '.' trigger a start warning."""
    # Arrange / Act: Validate names starting with hyphen or dot.
    warnings_hyphen = _validate_short_name("-Starts-With-Hyphen")
    warnings_dot = _validate_short_name(".starts-with-dot")

    # Assert: Both produce the start-with-alphanumeric warning.
    self.assertTrue(
        any("must start with an alphanumeric" in w for w in warnings_hyphen)
    )
    self.assertTrue(
        any("must start with an alphanumeric" in w for w in warnings_dot)
    )

  def test_invalid_end(self):
    """Verifies short names ending with '-' or '.' trigger an end warning."""
    # Arrange / Act: Validate names ending with hyphen or dot.
    warnings_hyphen = _validate_short_name("Ends-With-Hyphen-")
    warnings_dot = _validate_short_name("ends-with-dot.")

    # Assert: Both produce the end-with-alphanumeric warning.
    self.assertTrue(
        any("must end with an alphanumeric" in w for w in warnings_hyphen)
    )
    self.assertTrue(
        any("must end with an alphanumeric" in w for w in warnings_dot)
    )

  def test_invalid_characters(self):
    """Verifies disallowed symbols like '!' are listed in the warning."""
    # Arrange / Act: Validate a name containing '!'.
    warnings = _validate_short_name("Tag!")

    # Assert: Warning identifies both the invalid-character condition and '!'.
    self.assertTrue(any("invalid characters" in w for w in warnings))
    self.assertTrue(any("'!'" in w for w in warnings))


# ==============================================================================
# === Section 3: V2 Data Policy ID Sanitization & Validation Tests ===
# ==============================================================================


class TestSanitizeAndValidateDataPolicyId(unittest.TestCase):
  """Tests for `sanitize_data_policy_id` and `_validate_data_policy_id`."""

  def test_sanitize_data_policy_id_replaces_spaces_hyphens_and_dots(self):
    """Verifies spaces, hyphens, and dots are converted to underscores."""
    # Arrange / Act / Assert: Valid Tag short-name characters ('-', '.') and
    # spaces are each converted to '_' so V2 Data Policy IDs remain valid.
    self.assertEqual(
        sanitize_data_policy_id("My-Taxonomy.v1  Tag-Name"),
        "My_Taxonomy_v1__Tag_Name",
    )
    self.assertEqual(sanitize_data_policy_id(""), "")

  def test_validate_data_policy_id_valid_and_invalid_cases(self):
    """Verifies V2 Data Policy ID validation for empty, long, and bad chars."""
    # Arrange / Act / Assert 1: Valid alphanumeric + underscore ID has 0
    # warnings.
    self.assertEqual(
        _validate_data_policy_id("migrated_raw_Sensitive_Data_SSN_1"), []
    )

    # Arrange / Act / Assert 2: Empty ID emits an explicit warning.
    empty_warnings = _validate_data_policy_id("")
    self.assertTrue(
        any("Data Policy ID is empty." in w for w in empty_warnings)
    )

    # Arrange / Act / Assert 3: ID > 200 chars emits the 200-char limit warning.
    overlong_warnings = _validate_data_policy_id("a" * 201)
    self.assertTrue(
        any("exceeds 200 characters" in w for w in overlong_warnings)
    )

    # Arrange / Act / Assert 4: Hyphens or punctuation trigger an invalid-char
    # warning because V2 Data Policy IDs only allow [a-zA-Z0-9_].
    bad_char_warnings = _validate_data_policy_id("policy-with-hyphen!")
    self.assertTrue(
        any("contains invalid characters" in w for w in bad_char_warnings)
    )


# ==============================================================================
# === Section 4: End-to-End Planner & Markdown Report Tests ===
# ==============================================================================


class TestPlanner(unittest.TestCase):
  """Tests for `Planner` plan generation, DR validation, and reporting."""

  def setUp(self):
    super().setUp()
    self.planner = Planner()

  def test_generate_plan_basic(self):
    """Verifies basic mapping of 1 Access Control taxonomy and 1 Policy Tag."""
    # Arrange: Build an access-controlled taxonomy with one SSN policy tag.
    policy_tag = PolicyTagInfo(
        name="projects/12345/locations/us/taxonomies/111/policyTags/222",
        display_name="SSN",
        parent_policy_tag="",
    )
    taxonomy = TaxonomyInfo(
        name="projects/12345/locations/us/taxonomies/111",
        display_name="Sensitive Data",
        location="us",
        policy_tags=[policy_tag],
        is_access_control=True,
    )
    result = StaticTaxonomyAnalysisResult(
        project_id="test-project", location="us", taxonomies=[taxonomy]
    )

    # Act: Generate the migration plan.
    plan = self.planner.generate_plan(
        [result],
        target_dgt_project_id="test-project",
        target_data_policy_project_ids=["test-project"],
    )

    # Assert: Metadata, summary counts, DG Tag Key/Value payloads, and the
    # `_default_deny` policy action are populated as expected.
    self.assertEqual(plan["metadata"]["source_project_id"], "test-project")
    self.assertEqual(plan["plan_summary"]["total_taxonomies_mapped"], 1)
    self.assertEqual(plan["plan_summary"]["total_tags_to_create"], 1)

    tag_key = plan["phase_2_resource_manifest"][
        constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS
    ][0]
    self.assertEqual(tag_key["api_payload"]["short_name"], "Sensitive_Data")
    self.assertEqual(tag_key["namespaced_name"], "test-project/Sensitive_Data")
    self.assertEqual(
        tag_key["api_payload"]["description"],
        "Migrated from Taxonomy: Sensitive Data (region: us)",
    )
    self.assertNotIn("warnings", tag_key)

    tag_value = plan["phase_2_resource_manifest"][
        constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES
    ][0]
    self.assertEqual(tag_value["api_payload"]["short_name"], "SSN")
    self.assertEqual(
        tag_value["namespaced_name"], "test-project/Sensitive_Data/SSN"
    )
    self.assertEqual(
        tag_value["parent_namespaced_name"], "test-project/Sensitive_Data"
    )
    self.assertNotIn("warnings", tag_value)

    data_policy = plan["phase_2_resource_manifest"][
        constants.KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2
    ][0]
    self.assertEqual(data_policy["type"], constants.DATA_POLICY_TYPE_RAW)
    self.assertEqual(data_policy["region"], "us")
    self.assertEqual(
        data_policy["api_payload"]["data_policy_id"],
        "migrated_raw_Sensitive_Data_SSN_default_deny",
    )
    self.assertEqual(
        data_policy["api_payload"]["data_governance_tag"]["key"],
        "test-project/Sensitive_Data",
    )
    self.assertEqual(
        data_policy["api_payload"]["data_governance_tag"]["value"],
        "SSN",
    )
    self.assertEqual(
        data_policy["audit_lineage"],
        "Migrated from Policy Tag: Sensitive Data > SSN"
        f" ({constants.PARITY_DEFAULT_DENY})",
    )
    self.assertEqual(
        len(
            plan["phase_2_resource_manifest"][
                constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2
            ]
        ),
        0,
    )

  def test_generate_plan_hierarchy(self):
    """Verifies parent-child Policy Tag hierarchy maps to Tag Value paths."""
    # Arrange: Build a parent policy tag and child policy tag.
    policy_tag_parent = PolicyTagInfo(
        name="projects/12345/locations/us/taxonomies/111/policyTags/parent",
        display_name="Parent Tag",
        parent_policy_tag="",
    )
    policy_tag_child = PolicyTagInfo(
        name="projects/12345/locations/us/taxonomies/111/policyTags/child",
        display_name="Child Tag",
        parent_policy_tag=(
            "projects/12345/locations/us/taxonomies/111/policyTags/parent"
        ),
    )
    taxonomy = TaxonomyInfo(
        name="projects/12345/locations/us/taxonomies/111",
        display_name="Hierarchy",
        location="us",
        policy_tags=[policy_tag_parent, policy_tag_child],
        is_access_control=False,
    )
    result = StaticTaxonomyAnalysisResult(
        project_id="test-project", location="us", taxonomies=[taxonomy]
    )

    # Act: Generate the migration plan.
    plan = self.planner.generate_plan(
        [result],
        target_dgt_project_id="test-project",
        target_data_policy_project_ids=["test-project"],
    )

    # Assert: Child_Tag references `test-project/Hierarchy/Parent_Tag` as
    # `parent_namespaced_name`.
    self.assertEqual(plan["plan_summary"]["total_tags_to_create"], 2)
    child_tag_value = next(
        tag_value
        for tag_value in plan["phase_2_resource_manifest"][
            constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES
        ]
        if tag_value["api_payload"]["short_name"] == "Child_Tag"
    )
    self.assertEqual(
        child_tag_value["parent_namespaced_name"],
        "test-project/Hierarchy/Parent_Tag",
    )
    self.assertEqual(
        child_tag_value["namespaced_name"],
        "test-project/Hierarchy/Parent_Tag/Child_Tag",
    )

  def test_generate_plan_collision_handling(self):
    """Verifies intra-key Tag Value short-name collisions append `-1`."""
    # Arrange: Create "My Tag" and "My_Tag" in the same taxonomy, which both
    # sanitize to `My_Tag`.
    policy_tag1 = PolicyTagInfo(
        name="projects/12345/locations/us/taxonomies/111/policyTags/1",
        display_name="My Tag",
        parent_policy_tag="",
    )
    policy_tag2 = PolicyTagInfo(
        name="projects/12345/locations/us/taxonomies/111/policyTags/2",
        display_name="My_Tag",
        parent_policy_tag="",
    )
    taxonomy = TaxonomyInfo(
        name="projects/12345/locations/us/taxonomies/111",
        display_name="Collisions",
        location="us",
        policy_tags=[policy_tag1, policy_tag2],
        is_access_control=False,
    )
    result = StaticTaxonomyAnalysisResult(
        project_id="test-project", location="us", taxonomies=[taxonomy]
    )

    # Act: Generate the migration plan.
    plan = self.planner.generate_plan(
        [result],
        target_dgt_project_id="test-project",
        target_data_policy_project_ids=["test-project"],
    )

    # Assert: One Tag Value is "My_Tag" and the other is "My_Tag-1".
    tag_value1 = plan["phase_2_resource_manifest"][
        constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES
    ][0]
    tag_value2 = plan["phase_2_resource_manifest"][
        constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES
    ][1]
    names = {
        tag_value1["api_payload"]["short_name"],
        tag_value2["api_payload"]["short_name"],
    }
    self.assertIn("My_Tag", names)
    self.assertIn("My_Tag-1", names)

  def test_generate_plan_v1_masking(self):
    """Verifies V1 predefined and custom routine masking map to V2 policies."""
    # Arrange: Build one predefined masking policy and one custom routine
    # masking policy on the same Policy Tag.
    data_policy_predefined = DataPolicyInfo(
        name="projects/12345/locations/us/dataPolicies/my_predefined_policy",
        policy_tag="projects/12345/locations/us/taxonomies/111/policyTags/222",
        masking_rule="ALWAYS_NULL",
        policy_type=constants.DATA_POLICY_TYPE_MASKING,
        masked_readers=["user:masked@example.com"],
    )
    data_policy_custom = DataPolicyInfo(
        name="projects/12345/locations/us/dataPolicies/my_custom_policy",
        policy_tag="projects/12345/locations/us/taxonomies/111/policyTags/222",
        masking_rule="Custom Routine: my-project.my_dataset.my_routine",
        policy_type=constants.DATA_POLICY_TYPE_MASKING,
        masked_readers=["user:custom@example.com"],
    )

    policy_tag = PolicyTagInfo(
        name="projects/12345/locations/us/taxonomies/111/policyTags/222",
        display_name="SSN",
        parent_policy_tag="",
        data_policies=[data_policy_predefined, data_policy_custom],
    )
    taxonomy = TaxonomyInfo(
        name="projects/12345/locations/us/taxonomies/111",
        display_name="Sensitive Data",
        location="us",
        policy_tags=[policy_tag],
        is_access_control=True,
    )
    result = StaticTaxonomyAnalysisResult(
        project_id="test-project", location="us", taxonomies=[taxonomy]
    )

    # Act: Generate the migration plan.
    plan = self.planner.generate_plan(
        [result],
        target_dgt_project_id="test-project",
        target_data_policy_project_ids=["test-project"],
    )

    # Assert: Both V1 policies map to V2 actions with IAM v3 grantees and
    # `DR_WARN_03` on the custom routine policy.
    migrated_policies = plan["phase_2_resource_manifest"][
        constants.KEY_DATA_POLICIES_V1_TO_DATA_POLICIES_V2
    ]
    self.assertEqual(len(migrated_policies), 2)

    predefined_action = next(
        p for p in migrated_policies if "my_predefined_policy" in p["policy_id"]
    )
    self.assertEqual(
        predefined_action["api_payload"]["data_masking_policy"][
            "predefined_expression"
        ],
        "ALWAYS_NULL",
    )
    self.assertEqual(
        predefined_action["api_payload"]["grantees"],
        ["principal://goog/subject/masked@example.com"],
    )

    custom_action = next(
        p for p in migrated_policies if "my_custom_policy" in p["policy_id"]
    )
    self.assertEqual(
        custom_action["api_payload"]["data_masking_policy"]["routine"],
        "projects/my-project/datasets/my_dataset/routines/my_routine",
    )
    self.assertIn("warnings", custom_action)
    self.assertTrue(
        any(
            "DR_WARN_03" in warning
            for warning in custom_action.get("warnings", [])
        )
    )

  def test_generate_plan_explicit_readers(self):
    """Verifies a tag with fine_grained_readers gets Raw + Default Deny V2."""
    # Arrange: Build an access-controlled taxonomy with 1 tag and 1 raw reader.
    policy_tag = PolicyTagInfo(
        name="projects/12345/locations/us/taxonomies/111/policyTags/222",
        display_name="SSN",
        parent_policy_tag="",
        fine_grained_readers=["user:raw@example.com"],
    )
    taxonomy = TaxonomyInfo(
        name="projects/12345/locations/us/taxonomies/111",
        display_name="Sensitive Data",
        location="us",
        policy_tags=[policy_tag],
        is_access_control=True,
    )
    result = StaticTaxonomyAnalysisResult(
        project_id="test-project", location="us", taxonomies=[taxonomy]
    )

    # Act: Generate the migration plan.
    plan = self.planner.generate_plan(
        [result],
        target_dgt_project_id="test-project",
        target_data_policy_project_ids=["test-project"],
    )

    # Assert: Both the raw reader policy and the `_default_deny` seatbelt policy
    # are present in `phase_2_resource_manifest`.
    raw_policies = plan["phase_2_resource_manifest"][
        constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2
    ]
    self.assertEqual(len(raw_policies), 1)

    raw_policy = raw_policies[0]
    self.assertEqual(
        raw_policy["api_payload"]["grantees"],
        ["principal://goog/subject/raw@example.com"],
    )
    self.assertEqual(raw_policy["note"], constants.PARITY_RAW_READER)

    default_deny_policies = plan["phase_2_resource_manifest"][
        constants.KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2
    ]
    self.assertEqual(len(default_deny_policies), 1)
    deny_policy = default_deny_policies[0]
    self.assertEqual(deny_policy["api_payload"]["grantees"], [])
    self.assertEqual(deny_policy["note"], constants.PARITY_DEFAULT_DENY)
    self.assertEqual(
        deny_policy["api_payload"]["data_policy_id"],
        "migrated_raw_Sensitive_Data_SSN_default_deny",
    )

  def test_generate_plan_taxonomy_level_readers_root_only(self):
    """Verifies taxonomy-level readers skip unmasked non-root Tag Values."""
    # Arrange: Build a parent-child taxonomy with taxonomy-level and root-level
    # fine-grained readers.
    root_policy_tag = PolicyTagInfo(
        name="projects/12345/locations/us/taxonomies/111/policyTags/root",
        display_name="PII",
        parent_policy_tag="",
        fine_grained_readers=["user:tag_reader@example.com"],
    )
    child_policy_tag = PolicyTagInfo(
        name="projects/12345/locations/us/taxonomies/111/policyTags/child",
        display_name="Email",
        parent_policy_tag=(
            "projects/12345/locations/us/taxonomies/111/policyTags/root"
        ),
        fine_grained_readers=[],
    )
    taxonomy = TaxonomyInfo(
        name="projects/12345/locations/us/taxonomies/111",
        display_name="Sensitive Data",
        location="us",
        policy_tags=[root_policy_tag, child_policy_tag],
        is_access_control=True,
        fine_grained_readers=["user:tax_reader@example.com"],
    )
    result = StaticTaxonomyAnalysisResult(
        project_id="test-project", location="us", taxonomies=[taxonomy]
    )

    # Act: Generate the migration plan.
    plan = self.planner.generate_plan(
        [result],
        target_dgt_project_id="test-project",
        target_data_policy_project_ids=["test-project"],
    )

    # Assert 1: Exactly ONE raw reader policy is generated on the root tag PII
    # so descendant tags inherit access via `column.matchTagHierarchy` without
    # wasting the 1,000-policy per-key quota.
    raw_policies = plan["phase_2_resource_manifest"][
        constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2
    ]
    self.assertEqual(len(raw_policies), 1)
    root_raw_policy = raw_policies[0]
    self.assertEqual(
        root_raw_policy["api_payload"]["data_governance_tag"]["value"], "PII"
    )
    self.assertEqual(
        root_raw_policy["api_payload"]["grantees"],
        [
            "principal://goog/subject/tag_reader@example.com",
            "principal://goog/subject/tax_reader@example.com",
        ],
    )
    self.assertEqual(root_raw_policy["note"], constants.PARITY_RAW_READER)
    self.assertIn("Taxonomy: Sensitive Data", root_raw_policy["audit_lineage"])
    self.assertIn(
        "Policy Tag: Sensitive Data > PII", root_raw_policy["audit_lineage"]
    )

    # Assert 2: Both root (PII) and child (Email) receive default-deny policies.
    deny_policies = plan["phase_2_resource_manifest"][
        constants.KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2
    ]
    self.assertEqual(len(deny_policies), 2)

    deny_values = {
        p["api_payload"]["data_governance_tag"]["value"]: p
        for p in deny_policies
    }
    self.assertIn("PII", deny_values)
    self.assertIn("Email", deny_values)

    root_deny = deny_values["PII"]
    self.assertEqual(root_deny["api_payload"]["grantees"], [])
    self.assertEqual(root_deny["note"], constants.PARITY_DEFAULT_DENY)
    self.assertEqual(
        root_deny["api_payload"]["data_policy_id"],
        "migrated_raw_Sensitive_Data_PII_default_deny",
    )

    child_deny = deny_values["Email"]
    self.assertEqual(child_deny["api_payload"]["grantees"], [])
    self.assertEqual(child_deny["note"], constants.PARITY_DEFAULT_DENY)
    self.assertEqual(
        child_deny["api_payload"]["data_policy_id"],
        "migrated_raw_Sensitive_Data_Email_default_deny",
    )

  def test_generate_plan_classification_only_with_taxonomy_readers(self):
    """Verifies unactivated taxonomies with taxonomy readers create 0 DPs."""
    # Arrange: Build an unactivated taxonomy with taxonomy-level readers.
    policy_tag = PolicyTagInfo(
        name="projects/12345/locations/us/taxonomies/111/policyTags/222",
        display_name="Department",
        parent_policy_tag="",
        fine_grained_readers=[],
    )
    taxonomy = TaxonomyInfo(
        name="projects/12345/locations/us/taxonomies/111",
        display_name="Organization",
        location="us",
        policy_tags=[policy_tag],
        is_access_control=False,
        fine_grained_readers=["user:tax_reader@example.com"],
    )
    result = StaticTaxonomyAnalysisResult(
        project_id="test-project", location="us", taxonomies=[taxonomy]
    )

    # Act: Generate the migration plan.
    plan = self.planner.generate_plan(
        [result],
        target_dgt_project_id="test-project",
        target_data_policy_project_ids=["test-project"],
    )

    # Assert: Zero Data Policies are planned (preserving Default Allow) and an
    # inactive-permissions warning is attached to the root Tag Value.
    self.assertEqual(
        len(
            plan["phase_2_resource_manifest"][
                constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2
            ]
        ),
        0,
    )
    self.assertEqual(
        len(
            plan["phase_2_resource_manifest"][
                constants.KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2
            ]
        ),
        0,
    )

    tag_value = plan["phase_2_resource_manifest"][
        constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES
    ][0]
    self.assertIn("warnings", tag_value)
    self.assertIn(
        "Inactive permissions found on this Policy Tag or Taxonomy",
        tag_value["warnings"][0],
    )

  def test_generate_plan_classification_only_no_data_policies(self):
    """Verifies unactivated taxonomies with tag readers create 0 DPs."""
    # Arrange: Build an unactivated taxonomy with tag-level
    # `fine_grained_readers`.
    policy_tag = PolicyTagInfo(
        name="projects/12345/locations/us/taxonomies/111/policyTags/222",
        display_name="Department",
        parent_policy_tag="",
        fine_grained_readers=["user:dangling@example.com"],
        data_policies=[],
    )
    taxonomy = TaxonomyInfo(
        name="projects/12345/locations/us/taxonomies/111",
        display_name="Business Context",
        location="us",
        policy_tags=[policy_tag],
        is_access_control=False,
    )
    result = StaticTaxonomyAnalysisResult(
        project_id="test-project", location="us", taxonomies=[taxonomy]
    )

    # Act: Generate the migration plan.
    plan = self.planner.generate_plan(
        [result],
        target_dgt_project_id="test-project",
        target_data_policy_project_ids=["test-project"],
    )

    # Assert: DG Tag Key/Value are planned, warning is emitted, and 0 policies
    # are created.
    self.assertEqual(plan["plan_summary"]["total_taxonomies_mapped"], 1)
    self.assertEqual(plan["plan_summary"]["total_tags_to_create"], 1)
    tag_key = plan["phase_2_resource_manifest"][
        constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS
    ][0]
    self.assertEqual(
        tag_key["api_payload"]["purpose"],
        constants.TAG_PURPOSE_DATA_GOVERNANCE,
    )
    tag_value = plan["phase_2_resource_manifest"][
        constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES
    ][0]
    self.assertEqual(tag_value["api_payload"]["short_name"], "Department")
    self.assertIn("warnings", tag_value)
    self.assertTrue(
        any(
            "Inactive permissions found on this Policy Tag" in w
            for w in tag_value["warnings"]
        )
    )

    self.assertEqual(plan["plan_summary"]["total_policies_to_create"], 0)
    self.assertEqual(
        len(
            plan["phase_2_resource_manifest"][
                constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2
            ]
        ),
        0,
    )
    self.assertEqual(
        len(
            plan["phase_2_resource_manifest"][
                constants.KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2
            ]
        ),
        0,
    )
    self.assertEqual(
        len(
            plan["phase_2_resource_manifest"][
                constants.KEY_DATA_POLICIES_V1_TO_DATA_POLICIES_V2
            ]
        ),
        0,
    )

  def test_generate_plan_orphaned_tag(self):
    """Verifies an orphaned Policy Tag falls back to DG Tag Key as parent."""
    # Arrange: Build a tag referencing a non-existent parent policy tag.
    orphaned_tag = PolicyTagInfo(
        name="projects/12345/locations/us/taxonomies/111/policyTags/orphaned",
        display_name="Orphaned Tag",
        parent_policy_tag=(
            "projects/12345/locations/us/taxonomies/111/policyTags/missing"
        ),
    )
    taxonomy = TaxonomyInfo(
        name="projects/12345/locations/us/taxonomies/111",
        display_name="Orphanage",
        location="us",
        policy_tags=[orphaned_tag],
        is_access_control=False,
    )
    result = StaticTaxonomyAnalysisResult(
        project_id="test-project", location="us", taxonomies=[taxonomy]
    )

    # Act: Generate the migration plan.
    plan = self.planner.generate_plan(
        [result],
        target_dgt_project_id="test-project",
        target_data_policy_project_ids=["test-project"],
    )

    # Assert: `Orphaned_Tag` is parented directly by `test-project/Orphanage`.
    tag_values = plan["phase_2_resource_manifest"][
        constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES
    ]
    self.assertEqual(len(tag_values), 1)
    tag_value = tag_values[0]
    self.assertEqual(tag_value["api_payload"]["short_name"], "Orphaned_Tag")
    self.assertEqual(
        tag_value["parent_namespaced_name"], "test-project/Orphanage"
    )

  def test_generate_markdown_report_separate_sections(self):
    """Verifies Markdown report sections, mdformat markers, and DR guidance."""
    # Arrange: Build a synthetic migration plan with 1 Raw Reader policy and 1
    # Default Deny policy.
    plan = {
        "metadata": {
            "source_project_id": "source-project",
            "target_dgt_project_id": "target-dgt-project",
            "target_data_policy_mode": (
                constants.TARGET_DATA_POLICY_MODE_DEFAULT_PROJECT
            ),
            "target_data_policy_project_ids": ["target-policy-project"],
            "source_regions": ["us"],
        },
        "plan_summary": {
            "source_metrics": {
                "total_taxonomies": 1,
                "total_policy_tags": 2,
                "total_data_policies": 0,
            },
            "target_metrics": {
                "total_tag_keys": 1,
                "total_tag_values": 2,
                "total_data_policies": 2,
                "total_raw_reader_policies": 1,
                "total_default_deny_policies": 1,
                "total_migrated_data_policies": 0,
            },
        },
        "phase_2_resource_manifest": {
            constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS: [{
                "namespaced_name": "target-dgt-project/tax_key",
                "source_display_name": "Taxonomy 1",
            }],
            constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES: [{
                "namespaced_name": "target-dgt-project/tax_key/val1",
                "source_display_path": "Taxonomy 1 > Val 1",
            }],
            constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2: [{
                "policy_id": "migrated_raw_tax_key_val1",
                "source_display_path": "Taxonomy 1 > Val 1",
                "note": constants.PARITY_RAW_READER,
            }],
            constants.KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2: [{
                "policy_id": "migrated_raw_tax_key_val2",
                "source_display_path": "Taxonomy 1 > Val 2",
                "note": constants.PARITY_DEFAULT_DENY,
            }],
            constants.KEY_DATA_POLICIES_V1_TO_DATA_POLICIES_V2: [],
        },
    }

    # Act: Generate the Markdown report.
    report = self.planner.generate_markdown_report(plan)

    # Assert: Section headers, explanatory subheaders, table ordering, mdformat
    # markers, and customer-friendly labels are present, and raw identifier
    # `PARITY_DEFAULT_DENY` is absent.
    self.assertIn(
        "### 3. Policy Tags to Data Policies (V2) - Raw Reader Parity",
        report,
    )
    self.assertIn(
        "### 4. Policy Tags to Data Policies (V2) - Default Deny Parity",
        report,
    )
    self.assertIn(
        "### 5. Data Policies (V1) to Data Policies (V2)",
        report,
    )

    self.assertIn("#### Why Raw Reader Parity Policies Are Created", report)
    self.assertIn("#### Why Default Deny Parity Policies Are Created", report)
    self.assertIn(
        "roles/datacatalog.categoryFineGrainedReader",
        report,
    )
    self.assertIn(
        "datacatalog.categories.fineGrainedGet",
        report,
    )
    self.assertIn(
        "Fail-Closed (Default Deny)",
        report,
    )
    self.assertIn(
        "Fail-Open (Default Allow)",
        report,
    )
    self.assertNotIn("`PARITY_DEFAULT_DENY`", report)
    self.assertNotIn("seatbelt", report)
    self.assertIn(
        "Default Deny Parity policy (`_default_deny`, `grantees: []`)",
        report,
    )

    section_3_index = report.index(
        "### 3. Policy Tags to Data Policies (V2) - Raw Reader Parity"
    )
    section_4_index = report.index(
        "### 4. Policy Tags to Data Policies (V2) - Default Deny Parity"
    )
    section_5_index = report.index(
        "### 5. Data Policies (V1) to Data Policies (V2)"
    )

    raw_policy_index = report.index("migrated_raw_tax_key_val1")
    deny_policy_index = report.index("migrated_raw_tax_key_val2")

    self.assertLess(section_3_index, raw_policy_index)
    self.assertLess(raw_policy_index, section_4_index)
    self.assertLess(section_4_index, deny_policy_index)
    self.assertLess(deny_policy_index, section_5_index)

    self.assertIn("<!-- mdformat off -->", report)
    self.assertIn("<!-- mdformat on -->", report)

    self.assertIn("- **Raw Reader Parity Policies:** 1", report)
    self.assertIn("- **Default Deny Parity Policies:** 1", report)

    self.assertIn("DR_WARN_02", report)
    self.assertIn("Separation-Only design decision", report)

  def test_generate_plan_exceeds_max_data_policies_per_dg_tag_key(self):
    """Verifies > 1,000 Data Policies under one DG Tag Key triggers warnings."""
    # Arrange: Create 1,002 policy tags in an access-controlled taxonomy.
    excess_count = 2
    total_tags = constants.MAX_DATA_POLICIES_PER_DG_TAG_KEY + excess_count
    policy_tags = [
        PolicyTagInfo(
            name=f"projects/12345/locations/us/taxonomies/111/policyTags/{i}",
            display_name=f"tag_{i}",
            parent_policy_tag="",
        )
        for i in range(total_tags)
    ]
    taxonomy = TaxonomyInfo(
        name="projects/12345/locations/us/taxonomies/111",
        display_name="Large Taxonomy",
        location="us",
        policy_tags=policy_tags,
        is_access_control=True,
    )
    result = StaticTaxonomyAnalysisResult(
        project_id="test-project", location="us", taxonomies=[taxonomy]
    )

    # Act: Generate the migration plan and Markdown report.
    plan = self.planner.generate_plan(
        [result],
        target_dgt_project_id="test-project",
        target_data_policy_project_ids=["test-project"],
    )

    # Assert: The DG Tag Key and policies at index >= 1000 carry the limit
    # warning, and the Markdown report surfaces `WARNING [CRITICAL]`.
    tag_key_actions = plan["phase_2_resource_manifest"][
        constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS
    ]
    self.assertEqual(len(tag_key_actions), 1)
    tag_key = tag_key_actions[0]
    self.assertIn("warnings", tag_key)
    tag_key_warnings = " ".join(tag_key["warnings"])
    self.assertIn(
        "exceeds the BigQuery Data Policy Service limit of 1000 policies",
        tag_key_warnings,
    )
    self.assertIn(f"{total_tags} data policies", tag_key_warnings)
    self.assertIn("[ACTION REQUIRED:", tag_key_warnings)

    deny_policies = plan["phase_2_resource_manifest"][
        constants.KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2
    ]
    self.assertEqual(len(deny_policies), total_tags)

    for i in range(constants.MAX_DATA_POLICIES_PER_DG_TAG_KEY):
      policy_warnings = " ".join(deny_policies[i].get("warnings", []))
      self.assertNotIn("tag key limit is exhausted", policy_warnings)

    for i in range(constants.MAX_DATA_POLICIES_PER_DG_TAG_KEY, total_tags):
      policy_warnings = " ".join(deny_policies[i].get("warnings", []))
      self.assertIn("exceeds the limit of 1000 data policies", policy_warnings)
      self.assertIn("tag key limit is exhausted", policy_warnings)

    report = self.planner.generate_markdown_report(plan)
    self.assertIn("WARNING [CRITICAL]:", report)
    self.assertIn("test-project/Large_Taxonomy", report)
    self.assertIn("### Warnings", report)

  def test_generate_plan_decoupled_target_projects_mode_1_and_mode_2(self):
    """Verifies Mode 1 (single project) and Mode 2 (multi-project fan-out)."""
    # Arrange: Build a source taxonomy in `source-taxonomy-project`.
    policy_tag = PolicyTagInfo(
        name="projects/12345/locations/us/taxonomies/111/policyTags/tag1",
        display_name="SSN",
        parent_policy_tag="",
        fine_grained_readers=["user:alice@example.com"],
    )
    taxonomy = TaxonomyInfo(
        name="projects/12345/locations/us/taxonomies/111",
        display_name="Customer Data",
        location="us",
        policy_tags=[policy_tag],
        is_access_control=True,
    )
    result = StaticTaxonomyAnalysisResult(
        project_id="source-taxonomy-project",
        location="us",
        taxonomies=[taxonomy],
    )

    # Act & Assert 1 (Mode 1): Single centralized policy project.
    plan_mode_1 = self.planner.generate_plan(
        [result],
        target_dgt_project_id="central-dgt-project",
        target_data_policy_project_ids=["central-default-policy-project"],
        target_data_policy_mode=(
            constants.TARGET_DATA_POLICY_MODE_DEFAULT_PROJECT
        ),
    )
    self.assertEqual(
        plan_mode_1["metadata"]["source_project_id"], "source-taxonomy-project"
    )
    self.assertEqual(
        plan_mode_1["metadata"]["target_dgt_project_id"], "central-dgt-project"
    )
    self.assertEqual(
        plan_mode_1["metadata"]["target_data_policy_mode"],
        constants.TARGET_DATA_POLICY_MODE_DEFAULT_PROJECT,
    )
    self.assertEqual(
        plan_mode_1["metadata"]["target_data_policy_project_ids"],
        ["central-default-policy-project"],
    )
    tag_key = plan_mode_1["phase_2_resource_manifest"][
        constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS
    ][0]
    self.assertEqual(
        tag_key["namespaced_name"], "central-dgt-project/Customer_Data"
    )
    raw_policies_mode_1 = plan_mode_1["phase_2_resource_manifest"][
        constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2
    ]
    self.assertEqual(len(raw_policies_mode_1), 1)
    self.assertEqual(
        raw_policies_mode_1[0]["target_project_id"],
        "central-default-policy-project",
    )
    self.assertEqual(
        raw_policies_mode_1[0]["api_payload"]["data_governance_tag"]["key"],
        "central-dgt-project/Customer_Data",
    )

    # Act & Assert 2 (Mode 2): Multiple table parent projects fan out identical
    # V2 Data Policy actions per target project.
    plan_mode_2 = self.planner.generate_plan(
        [result],
        target_dgt_project_id="central-dgt-project",
        target_data_policy_project_ids=["data-project-1", "data-project-2"],
        target_data_policy_mode=(
            constants.TARGET_DATA_POLICY_MODE_TABLE_PROJECTS
        ),
    )
    self.assertEqual(
        plan_mode_2["metadata"]["target_data_policy_mode"],
        constants.TARGET_DATA_POLICY_MODE_TABLE_PROJECTS,
    )
    self.assertEqual(
        plan_mode_2["metadata"]["target_data_policy_project_ids"],
        ["data-project-1", "data-project-2"],
    )
    raw_policies_mode_2 = plan_mode_2["phase_2_resource_manifest"][
        constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2
    ]
    self.assertEqual(len(raw_policies_mode_2), 2)
    target_projects = [
        policy["target_project_id"] for policy in raw_policies_mode_2
    ]
    self.assertEqual(target_projects, ["data-project-1", "data-project-2"])
    for policy in raw_policies_mode_2:
      self.assertEqual(
          policy["api_payload"]["data_governance_tag"]["key"],
          "central-dgt-project/Customer_Data",
      )

    # Act & Assert 3: Reject missing target project IDs or multiple source
    # projects.
    with self.assertRaises(ValueError):
      self.planner.generate_plan(
          [result],
          target_dgt_project_id="",
          target_data_policy_project_ids=["data-project-1"],
      )
    with self.assertRaises(ValueError):
      self.planner.generate_plan(
          [result],
          target_dgt_project_id="central-dgt-project",
          target_data_policy_project_ids=[],
      )
    result_other_project = StaticTaxonomyAnalysisResult(
        project_id="other-source-project",
        location="us",
        taxonomies=[taxonomy],
    )
    with self.assertRaises(ValueError):
      self.planner.generate_plan(
          [result, result_other_project],
          target_dgt_project_id="central-dgt-project",
          target_data_policy_project_ids=["data-project-1"],
      )

  def test_generate_plan_collision_resolution_counter_and_from_region(self):
    """Verifies cross-region DG Tag Key collision resolution strategies."""
    # Arrange: Build two taxonomies with the same display name ("Confidential
    # Data") in `us` and `eu`.
    policy_tag_us = PolicyTagInfo(
        name="projects/12345/locations/us/taxonomies/111/policyTags/tag1",
        display_name="PII",
        parent_policy_tag="",
    )
    taxonomy_us = TaxonomyInfo(
        name="projects/12345/locations/us/taxonomies/111",
        display_name="Confidential Data",
        location="us",
        policy_tags=[policy_tag_us],
        is_access_control=False,
    )
    result_us = StaticTaxonomyAnalysisResult(
        project_id="source-project", location="us", taxonomies=[taxonomy_us]
    )

    policy_tag_eu = PolicyTagInfo(
        name="projects/12345/locations/eu/taxonomies/222/policyTags/tag2",
        display_name="PII",
        parent_policy_tag="",
    )
    taxonomy_eu = TaxonomyInfo(
        name="projects/12345/locations/eu/taxonomies/222",
        display_name="Confidential Data",
        location="eu",
        policy_tags=[policy_tag_eu],
        is_access_control=False,
    )
    result_eu = StaticTaxonomyAnalysisResult(
        project_id="source-project", location="eu", taxonomies=[taxonomy_eu]
    )

    # Act & Assert 1 (counter mode): `Confidential_Data` and
    # `Confidential_Data-1`.
    plan_counter = self.planner.generate_plan(
        [result_us, result_eu],
        target_dgt_project_id="target-dgt-project",
        target_data_policy_project_ids=["target-policy-project"],
        collision_resolution=constants.COLLISION_RESOLUTION_COUNTER,
    )
    tag_keys_counter = plan_counter["phase_2_resource_manifest"][
        constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS
    ]
    self.assertEqual(len(tag_keys_counter), 2)
    names_counter = [tag_key["namespaced_name"] for tag_key in tag_keys_counter]
    self.assertEqual(
        names_counter,
        [
            "target-dgt-project/Confidential_Data",
            "target-dgt-project/Confidential_Data-1",
        ],
    )
    self.assertIn(
        "(region: us)", tag_keys_counter[0]["api_payload"]["description"]
    )
    self.assertIn(
        "(region: eu)", tag_keys_counter[1]["api_payload"]["description"]
    )

    # Act & Assert 2 (from_region mode): `Confidential_Data_from_us` and
    # `Confidential_Data_from_eu`.
    plan_from_region = self.planner.generate_plan(
        [result_us, result_eu],
        target_dgt_project_id="target-dgt-project",
        target_data_policy_project_ids=["target-policy-project"],
        collision_resolution=constants.COLLISION_RESOLUTION_FROM_REGION,
    )
    tag_keys_from_region = plan_from_region["phase_2_resource_manifest"][
        constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS
    ]
    self.assertEqual(len(tag_keys_from_region), 2)
    names_from_region = [
        tag_key["namespaced_name"] for tag_key in tag_keys_from_region
    ]
    self.assertEqual(
        names_from_region,
        [
            "target-dgt-project/Confidential_Data_from_us",
            "target-dgt-project/Confidential_Data_from_eu",
        ],
    )

  def test_generate_plan_dr_warnings(self):
    """Verifies DR_WARN_01, DR_WARN_03, and DR_WARN_04 warning emission."""
    # Arrange: Build a policy tag with an authorized dataset reader and a custom
    # routine masking policy with an authorized view reader.
    custom_masking_policy = DataPolicyInfo(
        name="projects/12345/locations/us/dataPolicies/custom_mask",
        policy_tag="projects/12345/locations/us/taxonomies/111/policyTags/tag1",
        masking_rule="Custom Routine: my-project.my_dataset.mask_ssn",
        policy_type=constants.DATA_POLICY_TYPE_MASKING,
        masked_readers=[
            "principal://goog/bigquery/datasets/my_dataset/tables/auth_view"
        ],
    )
    policy_tag = PolicyTagInfo(
        name="projects/12345/locations/us/taxonomies/111/policyTags/tag1",
        display_name="SSN",
        parent_policy_tag="",
        fine_grained_readers=[
            "principalSet://goog/bigquery/datasets/shared_views"
        ],
        data_policies=[custom_masking_policy],
    )
    taxonomy = TaxonomyInfo(
        name="projects/12345/locations/us/taxonomies/111",
        display_name="Sensitive Data",
        location="us",
        policy_tags=[policy_tag],
        is_access_control=True,
    )
    result = StaticTaxonomyAnalysisResult(
        project_id="source-project", location="us", taxonomies=[taxonomy]
    )

    # Act 1: Generate the migration plan.
    plan = self.planner.generate_plan(
        [result],
        target_dgt_project_id="target-dgt-project",
        target_data_policy_project_ids=["target-policy-project"],
    )

    # Assert 1: `DR_WARN_03` and `DR_WARN_04` are attached to the policy
    # actions.
    raw_policy = plan["phase_2_resource_manifest"][
        constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2
    ][0]
    raw_warnings = " ".join(raw_policy.get("warnings", []))
    self.assertIn("DR_WARN_04", raw_warnings)

    migrated_policy = plan["phase_2_resource_manifest"][
        constants.KEY_DATA_POLICIES_V1_TO_DATA_POLICIES_V2
    ][0]
    migrated_warnings = " ".join(migrated_policy.get("warnings", []))
    self.assertIn("DR_WARN_03", migrated_warnings)
    self.assertIn("DR_WARN_04", migrated_warnings)

    # Act 2: Append a second-region policy referencing the same DG Tag Key and
    # run `validate_plan_dr_readiness`.
    plan["phase_2_resource_manifest"][
        constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2
    ].append({
        "policy_id": "migrated_raw_Sensitive_Data_SSN_eu",
        "action": constants.ACTION_CREATE_DATA_POLICY_V2,
        "type": constants.DATA_POLICY_TYPE_RAW,
        "region": "eu",
        "target_project_id": "target-policy-project",
        "api_payload": {
            "data_policy_type": constants.DATA_POLICY_TYPE_RAW,
            "data_policy_id": "migrated_raw_Sensitive_Data_SSN_eu",
            "data_governance_tag": {
                "key": "target-dgt-project/Sensitive_Data",
                "value": "SSN",
            },
            "grantees": [],
        },
        "source_resource_name": policy_tag.name,
        "source_display_path": "Sensitive Data > SSN",
        "source_entity_type": "Policy Tag",
    })
    self.planner.validate_plan_dr_readiness(plan)

    # Assert 2: `DR_WARN_01` is attached to the DG Tag Key action.
    tag_key_action = plan["phase_2_resource_manifest"][
        constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS
    ][0]
    tag_key_warnings = " ".join(tag_key_action.get("warnings", []))
    self.assertIn("DR_WARN_01", tag_key_warnings)
    self.assertIn("policy conflict in the secondary region", tag_key_warnings)

  def test_generate_plan_populates_dg_tag_value_and_region_errors(self):
    """Verifies region errors, dg_tag_value_namespaced_name, and routine IDs."""
    # Arrange: Build one succeeding region (`us`) with an unresolved routine
    # project placeholder and one failing region (`eu`).
    data_policy = DataPolicyInfo(
        name="projects/12345/locations/us/dataPolicies/my_custom_policy",
        policy_tag="projects/12345/locations/us/taxonomies/111/policyTags/222",
        masking_rule=(
            "Custom Routine: <unknown-project-999>.my_dataset.my_routine"
        ),
        policy_type=constants.DATA_POLICY_TYPE_MASKING,
        masked_readers=["user:masked@example.com"],
    )
    policy_tag = PolicyTagInfo(
        name="projects/12345/locations/us/taxonomies/111/policyTags/222",
        display_name="SSN",
        parent_policy_tag="",
        fine_grained_readers=["user:raw@example.com"],
        data_policies=[data_policy],
    )
    taxonomy = TaxonomyInfo(
        name="projects/12345/locations/us/taxonomies/111",
        display_name="Sensitive Data",
        location="us",
        policy_tags=[policy_tag],
        is_access_control=True,
    )
    ok_result = StaticTaxonomyAnalysisResult(
        project_id="test-project", location="us", taxonomies=[taxonomy]
    )
    err_result = StaticTaxonomyAnalysisResult(
        project_id="test-project",
        location="eu",
        error="PermissionDenied: missing categoryAdmin in eu",
    )

    # Act: Generate the migration plan and Markdown report.
    plan = self.planner.generate_plan(
        [ok_result, err_result],
        target_dgt_project_id="target-dgt-project",
        target_data_policy_project_ids=["target-policy-project"],
    )

    # Assert: Top-level critical warning, `dg_tag_value_namespaced_name`, and
    # unresolved routine project number warning are all present.
    self.assertIn("warnings", plan)
    self.assertTrue(
        any(
            "[CRITICAL]" in warning and "eu" in warning
            for warning in plan["warnings"]
        )
    )
    markdown_report = self.planner.generate_markdown_report(plan)
    self.assertIn("### Warnings", markdown_report)
    self.assertIn("missing categoryAdmin in eu", markdown_report)

    manifest = plan["phase_2_resource_manifest"]
    for key in (
        constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2,
        constants.KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2,
        constants.KEY_DATA_POLICIES_V1_TO_DATA_POLICIES_V2,
    ):
      for action in manifest[key]:
        self.assertEqual(
            action[constants.FIELD_DG_TAG_VALUE_NAMESPACED_NAME],
            "target-dgt-project/Sensitive_Data/SSN",
        )

    migrated_action = manifest[
        constants.KEY_DATA_POLICIES_V1_TO_DATA_POLICIES_V2
    ][0]
    self.assertTrue(
        any(
            "unresolved project number" in warning
            for warning in migrated_action.get("warnings", [])
        )
    )

  def test_generate_plan_propagates_taxonomy_warnings(self):
    """Verifies taxonomy IAM/custom-role warnings propagate to root actions."""
    # Arrange 1: Root tag has raw readers.
    taxonomy_warning = (
        "Failed to retrieve IAM policy for Taxonomy: PermissionDenied"
    )
    root_with_readers = PolicyTagInfo(
        name="projects/12345/locations/us/taxonomies/111/policyTags/root",
        display_name="RootTag",
        parent_policy_tag="",
        fine_grained_readers=["user:raw@example.com"],
    )
    child_tag = PolicyTagInfo(
        name="projects/12345/locations/us/taxonomies/111/policyTags/child",
        display_name="ChildTag",
        parent_policy_tag=(
            "projects/12345/locations/us/taxonomies/111/policyTags/root"
        ),
        fine_grained_readers=[],
    )
    taxonomy_with_readers = TaxonomyInfo(
        name="projects/12345/locations/us/taxonomies/111",
        display_name="Tax With Readers",
        location="us",
        policy_tags=[root_with_readers, child_tag],
        is_access_control=True,
        warnings=[taxonomy_warning],
    )
    result_with_readers = StaticTaxonomyAnalysisResult(
        project_id="test-project",
        location="us",
        taxonomies=[taxonomy_with_readers],
    )

    # Act & Assert 1: Warning propagates to DG Tag Key and root raw reader
    # policy, not to default-deny policies.
    plan_with_readers = self.planner.generate_plan(
        [result_with_readers],
        target_dgt_project_id="target-dgt-project",
        target_data_policy_project_ids=["target-policy-project"],
    )
    manifest_1 = plan_with_readers["phase_2_resource_manifest"]
    tag_key_1 = manifest_1[constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS][0]
    self.assertIn(taxonomy_warning, tag_key_1.get("warnings", []))

    raw_policy_1 = manifest_1[
        constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2
    ][0]
    self.assertIn(taxonomy_warning, raw_policy_1.get("warnings", []))
    deny_policies_1 = manifest_1[
        constants.KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2
    ]
    for deny_policy in deny_policies_1:
      self.assertNotIn(taxonomy_warning, deny_policy.get("warnings", []))

    # Arrange 2: Root tag has no raw readers.
    root_no_readers = PolicyTagInfo(
        name="projects/12345/locations/us/taxonomies/222/policyTags/root",
        display_name="RootDenyOnly",
        parent_policy_tag="",
        fine_grained_readers=[],
    )
    taxonomy_no_readers = TaxonomyInfo(
        name="projects/12345/locations/us/taxonomies/222",
        display_name="Tax No Readers",
        location="us",
        policy_tags=[root_no_readers],
        is_access_control=True,
        warnings=[taxonomy_warning],
    )
    result_no_readers = StaticTaxonomyAnalysisResult(
        project_id="test-project",
        location="us",
        taxonomies=[taxonomy_no_readers],
    )

    # Act & Assert 2: Warning propagates to DG Tag Key and root default-deny
    # policy.
    plan_no_readers = self.planner.generate_plan(
        [result_no_readers],
        target_dgt_project_id="target-dgt-project",
        target_data_policy_project_ids=["target-policy-project"],
    )
    manifest_2 = plan_no_readers["phase_2_resource_manifest"]
    tag_key_2 = manifest_2[constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS][0]
    self.assertIn(taxonomy_warning, tag_key_2.get("warnings", []))
    deny_policy_2 = manifest_2[
        constants.KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2
    ][0]
    self.assertIn(taxonomy_warning, deny_policy_2.get("warnings", []))

  def test_convert_to_iam_v3_principal_and_validate_grantees_warnings(self):
    """Verifies IAM v1-to-v3 conversion and tombstoned/domain grantee checks."""
    # Arrange / Act / Assert 1: Direct conversion of user, group, and
    # serviceAccount principals.
    self.assertEqual(
        _convert_to_iam_v3_principal("user:alice@example.com"),
        "principal://goog/subject/alice@example.com",
    )
    self.assertEqual(
        _convert_to_iam_v3_principal("group:eng@example.com"),
        "principalSet://goog/group/eng@example.com",
    )
    self.assertEqual(
        _convert_to_iam_v3_principal(
            "serviceAccount:my-sa@my-proj.iam.gserviceaccount.com"
        ),
        (
            "principal://iam.googleapis.com/projects/-/"
            "serviceAccounts/my-sa@my-proj.iam.gserviceaccount.com"
        ),
    )

    # Arrange 2: Build a policy tag with a tombstoned `deleted:` principal and a
    # V1 masking policy with an unsupported `domain:` principal.
    data_policy = DataPolicyInfo(
        name="projects/12345/locations/us/dataPolicies/mask_policy",
        policy_tag="projects/12345/locations/us/taxonomies/111/policyTags/222",
        masking_rule="SHA256",
        policy_type=constants.DATA_POLICY_TYPE_MASKING,
        masked_readers=["domain:example.com"],
    )
    policy_tag = PolicyTagInfo(
        name="projects/12345/locations/us/taxonomies/111/policyTags/222",
        display_name="SSN",
        parent_policy_tag="",
        fine_grained_readers=[
            "deleted:user:old@example.com?uid=12345",
            "user:active@example.com",
        ],
        data_policies=[data_policy],
    )
    taxonomy = TaxonomyInfo(
        name="projects/12345/locations/us/taxonomies/111",
        display_name="Sensitive Data",
        location="us",
        policy_tags=[policy_tag],
        is_access_control=True,
    )
    result = StaticTaxonomyAnalysisResult(
        project_id="test-project", location="us", taxonomies=[taxonomy]
    )

    # Act 2: Generate the migration plan.
    plan = self.planner.generate_plan(
        [result],
        target_dgt_project_id="target-dgt-project",
        target_data_policy_project_ids=["target-policy-project"],
    )
    manifest = plan["phase_2_resource_manifest"]

    # Assert 2: Both tombstoned and unsupported principal warnings are emitted.
    raw_policy = manifest[
        constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2
    ][0]
    raw_warnings = " ".join(raw_policy.get("warnings", []))
    self.assertIn("Tombstoned IAM principal", raw_warnings)
    self.assertIn("deleted:user:old@example.com?uid=12345", raw_warnings)
    self.assertIn("ACTION REQUIRED", raw_warnings)

    migrated_policy = manifest[
        constants.KEY_DATA_POLICIES_V1_TO_DATA_POLICIES_V2
    ][0]
    migrated_warnings = " ".join(migrated_policy.get("warnings", []))
    self.assertIn(
        "Unsupported IAM principal format 'domain:example.com'",
        migrated_warnings,
    )
    self.assertIn("ACTION REQUIRED", migrated_warnings)

  def test_generate_markdown_report_renders_warning_code_reference(self):
    """Explains encountered warning/error codes in the Markdown plan report."""
    # Construct a plan containing `[ACTION REQUIRED]` and `DR_WARN_03` warnings,
    # leaving `DR_WARN_01` absent so only encountered codes are listed.
    plan = {
        "metadata": {
            "source_project_id": "source-proj",
            "target_dgt_project_id": "dgt-proj",
            "target_data_policy_project_ids": ["policy-proj"],
            "target_data_policy_mode": (
                constants.TARGET_DATA_POLICY_MODE_DEFAULT_PROJECT
            ),
        },
        "plan_summary": {
            "source_metrics": {},
            "target_metrics": {},
        },
        "warnings": [
            (
                "[ACTION REQUIRED] Invalid short_name '-bad' on taxonomy;"
                " update plan.json before Phase 2a."
            ),
            (
                f"Warning [{constants.DR_WARN_03}]: Replicate routine dataset"
                " before enabling Cross-Region Replication."
            ),
        ],
        "phase_2_resource_manifest": {
            constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS: [],
            constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES: [],
        },
    }

    # Generate the Markdown report from the plan with warning codes.
    report = self.planner.generate_markdown_report(plan)

    # Confirm the reference section defines `[ACTION REQUIRED]`, `DR_WARN_02`
    # (from the header), and `DR_WARN_03` with nested sub-bullets while omitting
    # unencountered `DR_WARN_01`.
    self.assertIn("#### Warning & Error Code Reference", report)
    self.assertIn("- **`[ACTION REQUIRED]`:**", report)
    self.assertIn("  - **Common Triggers:**", report)
    self.assertIn(f"- **`{constants.DR_WARN_02}`:**", report)
    self.assertIn("  - **Mode 1 (`--target-default-dp-project-id`):**", report)
    self.assertIn(f"- **`{constants.DR_WARN_03}`:**", report)
    self.assertIn("  - **Required Action:** Replicate the BigQuery", report)
    self.assertNotIn(f"- **`{constants.DR_WARN_01}`:**", report)

  # Table 3 must surface whether a Raw Reader Parity policy came from direct
  # Policy Tag IAM, Taxonomy-level IAM on a root tag, or both (including custom
  # IAM roles granting `datacatalog.categories.fineGrainedGet`).
  def test_generate_markdown_report_renders_raw_reader_provenance_notes(self):
    """Distinguishes Policy Tag, Taxonomy, and custom-role IAM in Table 3."""
    # Root tag 1 (`Both_Root`) has direct readers AND inherits taxonomy readers;
    # child tag (`Direct_Child`) has a custom-role Policy Tag reader; root tag 2
    # (`Tax_Only_Root`) has no direct readers and inherits only taxonomy IAM.
    custom_role = "projects/source-project/roles/customFineGrainedReader"
    both_root = PolicyTagInfo(
        name="projects/12345/locations/us/taxonomies/111/policyTags/root1",
        display_name="Both_Root",
        parent_policy_tag="",
        fine_grained_readers=["user:direct-root@example.com"],
    )
    direct_child = PolicyTagInfo(
        name="projects/12345/locations/us/taxonomies/111/policyTags/child1",
        display_name="Direct_Child",
        parent_policy_tag=(
            "projects/12345/locations/us/taxonomies/111/policyTags/root1"
        ),
        fine_grained_readers=["user:direct-child@example.com"],
        custom_roles_by_principal={
            "user:direct-child@example.com": [custom_role]
        },
    )
    tax_only_root = PolicyTagInfo(
        name="projects/12345/locations/us/taxonomies/111/policyTags/root2",
        display_name="Tax_Only_Root",
        parent_policy_tag="",
        fine_grained_readers=[],
    )
    taxonomy = TaxonomyInfo(
        name="projects/12345/locations/us/taxonomies/111",
        display_name="PII",
        location="us",
        policy_tags=[both_root, direct_child, tax_only_root],
        is_access_control=True,
        fine_grained_readers=["user:tax-admin@example.com"],
    )
    result = StaticTaxonomyAnalysisResult(
        project_id="source-project",
        location="us",
        taxonomies=[taxonomy],
    )

    # Plan and render the Markdown report for the 3 provenance combinations.
    plan = self.planner.generate_plan(
        [result],
        target_dgt_project_id="dgt-proj",
        target_data_policy_project_ids=["policy-proj"],
    )
    report = self.planner.generate_markdown_report(plan)

    # Verify Table 3 distinguishes all three IAM provenance paths and surfaces
    # the custom IAM role name on `Direct_Child`.
    self.assertIn(
        "| Policy Tag | PII > Both_Root | -> | Data Policy V2 |"
        " policy-proj/migrated_raw_PII_Both_Root |"
        " Raw Reader Parity (from Policy Tag & Taxonomy IAM) |",
        report,
    )
    self.assertIn(
        "| Policy Tag | PII > Both_Root > Direct_Child | -> | Data Policy V2 |"
        " policy-proj/migrated_raw_PII_Direct_Child |"
        f" Raw Reader Parity (from Policy Tag IAM; custom role: {custom_role})"
        " |",
        report,
    )
    self.assertIn(
        "| Policy Tag | PII > Tax_Only_Root | -> | Data Policy V2 |"
        " policy-proj/migrated_raw_PII_Tax_Only_Root |"
        " Raw Reader Parity (from Taxonomy IAM) |",
        report,
    )

  # Mode 2 multi-project plans must render `<target_project_id>/<policy_id>` in
  # Tables 3, 4, and 5 and deduplicate identical per-source-entity warnings.
  def test_generate_markdown_report_mode_2_qualifies_projects_and_dedups_warns(
      self,
  ):
    """Verifies Mode 2 report qualifies policy target projects and warnings."""
    # Attach a custom routine masking policy (`DR_WARN_03`) and raw reader on a
    # single policy tag so Mode 2 fans out 2 copies of each V2 Data Policy.
    custom_policy = DataPolicyInfo(
        name="projects/12345/locations/us/dataPolicies/phone_udf_policy",
        policy_tag="projects/12345/locations/us/taxonomies/111/policyTags/tag1",
        masking_rule="Custom Routine: my-project.my_dataset.mask_phone_last4",
        policy_type=constants.DATA_POLICY_TYPE_MASKING,
        masked_readers=["user:masked@example.com"],
    )
    policy_tag = PolicyTagInfo(
        name="projects/12345/locations/us/taxonomies/111/policyTags/tag1",
        display_name="Phone",
        parent_policy_tag="",
        fine_grained_readers=["user:raw@example.com"],
        data_policies=[custom_policy],
    )
    taxonomy = TaxonomyInfo(
        name="projects/12345/locations/us/taxonomies/111",
        display_name="Customer Data",
        location="us",
        policy_tags=[policy_tag],
        is_access_control=True,
    )
    result = StaticTaxonomyAnalysisResult(
        project_id="source-project",
        location="us",
        taxonomies=[taxonomy],
    )

    # Generate a Mode 2 plan targeting two data table parent projects and render
    # its Markdown report.
    plan = self.planner.generate_plan(
        [result],
        target_dgt_project_id="central-dgt-project",
        target_data_policy_project_ids=["data-project-1", "data-project-2"],
        target_data_policy_mode=(
            constants.TARGET_DATA_POLICY_MODE_TABLE_PROJECTS
        ),
    )
    report = self.planner.generate_markdown_report(plan)

    # Each V2 Data Policy row in Sections 3, 4, and 5 must include its
    # `<target_project_id>/<policy_id>` prefix rather than rendering two
    # indistinguishable bare `<policy_id>` lines.
    self.assertIn(
        "| Data Policy V2 | data-project-1/migrated_raw_Customer_Data_Phone |"
        " Raw Reader Parity (from Policy Tag IAM) |",
        report,
    )
    self.assertIn(
        "| Data Policy V2 | data-project-2/migrated_raw_Customer_Data_Phone |"
        " Raw Reader Parity (from Policy Tag IAM) |",
        report,
    )
    self.assertIn(
        "| Data Policy V2 |"
        " data-project-1/migrated_raw_Customer_Data_Phone_default_deny |"
        " Default Deny Parity |",
        report,
    )
    self.assertIn(
        "| Data Policy V2 |"
        " data-project-2/migrated_raw_Customer_Data_Phone_default_deny |"
        " Default Deny Parity |",
        report,
    )
    self.assertIn(
        "| Data Policy V2 |"
        " data-project-1/migrated_masking_Customer_Data_phone_udf_policy |",
        report,
    )
    self.assertIn(
        "| Data Policy V2 |"
        " data-project-2/migrated_masking_Customer_Data_phone_udf_policy |",
        report,
    )

    # Confirm the `DR_WARN_03` custom routine warning appears exactly once in
    # `### Warnings` instead of being repeated per target project.
    dr_warn_03_warning_lines = [
        line
        for line in report.splitlines()
        if "mask_phone" in line and constants.DR_WARN_03 in line
    ]
    self.assertEqual(len(dr_warn_03_warning_lines), 1)

  # The 1,000-policy per Tag Key quota check must evaluate policies in Phase 2a
  # execution order (`raw_reader` -> `default_deny` -> `migrated_v1`) rather
  # than per-tag interleaved order.
  def test_generate_plan_quota_check_follows_phase_2a_creation_order(self):
    """Evaluates the 1,000-policy quota in Phase 2a creation sequence."""
    # Seed 501 policy tags that each have a raw reader (501 raw reader + 501
    # default deny = 1,002 policies) plus 1 V1 masking policy on tag 0 (1,003
    # total policies).
    masking_policy = DataPolicyInfo(
        name="projects/12345/locations/us/dataPolicies/udf_policy_0",
        policy_tag="projects/12345/locations/us/taxonomies/111/policyTags/0",
        masking_rule="SHA256",
        policy_type=constants.DATA_POLICY_TYPE_MASKING,
        masked_readers=["user:masked@example.com"],
    )
    policy_tags = [
        PolicyTagInfo(
            name=f"projects/12345/locations/us/taxonomies/111/policyTags/{i}",
            display_name=f"Tag_{i}",
            parent_policy_tag="",
            fine_grained_readers=["user:raw@example.com"],
            data_policies=[masking_policy] if i == 0 else [],
        )
        for i in range(501)
    ]
    taxonomy = TaxonomyInfo(
        name="projects/12345/locations/us/taxonomies/111",
        display_name="Quota_Taxonomy",
        location="us",
        policy_tags=policy_tags,
        is_access_control=True,
    )
    result = StaticTaxonomyAnalysisResult(
        project_id="source-project",
        location="us",
        taxonomies=[taxonomy],
    )

    # Generate the migration plan so Step 4 partitions and evaluates the 1,003
    # V2 Data Policies against `MAX_DATA_POLICIES_PER_DG_TAG_KEY` (1,000).
    plan = self.planner.generate_plan(
        [result],
        target_dgt_project_id="dgt-proj",
        target_data_policy_project_ids=["policy-proj"],
    )
    manifest = plan["phase_2_resource_manifest"]
    raw_policies = manifest[
        constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2
    ]
    deny_policies = manifest[
        constants.KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2
    ]
    migrated_policies = manifest[
        constants.KEY_DATA_POLICIES_V1_TO_DATA_POLICIES_V2
    ]

    # All 501 raw reader policies (indices 0..500) and the first 499 default
    # deny policies (indices 501..999) are within the 1,000-policy limit, while
    # the last 2 default deny policies (indices 1000..1001) and the migrated V1
    # masking policy (index 1002) are flagged as exceeding the limit.
    for raw_policy in raw_policies:
      self.assertNotIn(
          "tag key limit is exhausted",
          " ".join(raw_policy.get("warnings", [])),
      )
    for deny_policy in deny_policies[:499]:
      self.assertNotIn(
          "tag key limit is exhausted",
          " ".join(deny_policy.get("warnings", [])),
      )
    for deny_policy in deny_policies[499:]:
      self.assertIn(
          "tag key limit is exhausted",
          " ".join(deny_policy.get("warnings", [])),
      )
    self.assertIn(
        "tag key limit is exhausted",
        " ".join(migrated_policies[0].get("warnings", [])),
    )

  # Tables 1 and 2 must surface source region and collision resolution notes,
  # clean reports must still render `#### Warning & Error Code Reference`, and
  # regional errors ending with `.` must not produce double periods `..`.
  def test_generate_markdown_report_collision_notes_and_clean_warnings(self):
    """Renders Table 1/2 collision notes and DR_WARN_02 reference on 0 warns."""
    # Build colliding `us` and `eu` taxonomies where `us` also has sibling tags
    # (`PII Email` and `PII_Email`) that collide after space sanitization.
    tag_space = PolicyTagInfo(
        name="projects/12345/locations/us/taxonomies/1/policyTags/1",
        display_name="PII Email",
        parent_policy_tag="",
    )
    tag_underscore = PolicyTagInfo(
        name="projects/12345/locations/us/taxonomies/1/policyTags/2",
        display_name="PII_Email",
        parent_policy_tag="",
    )
    taxonomy_us = TaxonomyInfo(
        name="projects/12345/locations/us/taxonomies/1",
        display_name="mt_pii_tax",
        location="us",
        policy_tags=[tag_space, tag_underscore],
        is_access_control=False,
    )
    taxonomy_eu = TaxonomyInfo(
        name="projects/12345/locations/eu/taxonomies/2",
        display_name="mt_pii_tax",
        location="eu",
        policy_tags=[],
        is_access_control=False,
    )
    result_us = StaticTaxonomyAnalysisResult(
        project_id="source-project", location="us", taxonomies=[taxonomy_us]
    )
    result_eu = StaticTaxonomyAnalysisResult(
        project_id="source-project", location="eu", taxonomies=[taxonomy_eu]
    )

    # Generate a clean multi-region plan in `counter` mode and render its
    # Markdown report.
    plan_counter = self.planner.generate_plan(
        [result_us, result_eu],
        target_dgt_project_id="dgt-proj",
        target_data_policy_project_ids=["policy-proj"],
        collision_resolution=constants.COLLISION_RESOLUTION_COUNTER,
    )
    report_counter = self.planner.generate_markdown_report(plan_counter)

    # Confirm Table 1 shows source regions and counter collision resolution,
    # Table 2 shows sibling Tag Value counter disambiguation, and the clean plan
    # still renders `### Warnings` (`- None`) plus the `DR_WARN_02` reference.
    self.assertIn(
        "| Taxonomy | mt_pii_tax | -> | DG Tag Key | dgt-proj/mt_pii_tax |"
        " Source region: us |",
        report_counter,
    )
    self.assertIn(
        "| Taxonomy | mt_pii_tax | -> | DG Tag Key | dgt-proj/mt_pii_tax-1 |"
        " Source region: eu (Collision resolved via counter) |",
        report_counter,
    )
    self.assertIn(
        "| Policy Tag | mt_pii_tax > PII_Email | -> | DG Tag Value |"
        " dgt-proj/mt_pii_tax/PII_Email-1 | Collision resolved via counter |",
        report_counter,
    )
    self.assertIn("### Warnings\n\n- None\n", report_counter)
    self.assertIn("#### Warning & Error Code Reference", report_counter)
    self.assertIn(f"- **`{constants.DR_WARN_02}`:**", report_counter)

    # Verify `from_region` collision notes and trailing-period deduplication on
    # regional analysis errors.
    failed_region = StaticTaxonomyAnalysisResult(
        project_id="source-project",
        location="us-nonexistent99",
        error="501 Invalid regional endpoint for this service.",
    )
    plan_from_region = self.planner.generate_plan(
        [result_us, result_eu, failed_region],
        target_dgt_project_id="dgt-proj",
        target_data_policy_project_ids=["policy-proj"],
        collision_resolution=constants.COLLISION_RESOLUTION_FROM_REGION,
    )
    report_from_region = self.planner.generate_markdown_report(plan_from_region)
    self.assertIn(
        "Source region: us (Collision resolved via from_region) |",
        report_from_region,
    )
    self.assertIn(
        "Source region: eu (Collision resolved via from_region) |",
        report_from_region,
    )
    self.assertIn(
        "for this service. Taxonomies and policies", report_from_region
    )
    self.assertNotIn(".. Taxonomies", report_from_region)

  # Cross-project custom masking routines must emit `[ACTION REQUIRED]` only on
  # target Data Policy projects that differ from the routine's owning project.
  def test_generate_plan_flags_cross_project_custom_masking_routine(self):
    """Emits `[ACTION REQUIRED]` when custom routine project != policy proj."""
    # Seed a custom routine in `source-project` and fan out V2 Data Policies in
    # Mode 2 across `source-project` (same project) and `secondary-project`
    # (cross-project).
    custom_policy = DataPolicyInfo(
        name="projects/12345/locations/us/dataPolicies/phone_udf",
        policy_tag="projects/12345/locations/us/taxonomies/111/policyTags/1",
        masking_rule="Custom Routine: source-project.gov_us.mask_phone_last4",
        policy_type=constants.DATA_POLICY_TYPE_MASKING,
        masked_readers=["user:masked@example.com"],
    )
    policy_tag = PolicyTagInfo(
        name="projects/12345/locations/us/taxonomies/111/policyTags/1",
        display_name="Phone_Tag",
        parent_policy_tag="",
        data_policies=[custom_policy],
    )
    taxonomy = TaxonomyInfo(
        name="projects/12345/locations/us/taxonomies/111",
        display_name="PII",
        location="us",
        policy_tags=[policy_tag],
        is_access_control=True,
    )
    result = StaticTaxonomyAnalysisResult(
        project_id="source-project", location="us", taxonomies=[taxonomy]
    )

    # Plan Mode 2 across both `source-project` and `secondary-project`.
    plan = self.planner.generate_plan(
        [result],
        target_dgt_project_id="source-project",
        target_data_policy_project_ids=[
            "source-project",
            "secondary-project",
        ],
        target_data_policy_mode=(
            constants.TARGET_DATA_POLICY_MODE_TABLE_PROJECTS
        ),
    )
    migrated = plan["phase_2_resource_manifest"][
        constants.KEY_DATA_POLICIES_V1_TO_DATA_POLICIES_V2
    ]
    self.assertEqual(len(migrated), 2)
    by_project = {item["target_project_id"]: item for item in migrated}

    # The `source-project` policy resides in the same project as the routine so
    # it carries only `DR_WARN_03` and zero `[ACTION REQUIRED]` warnings.
    source_warnings = " ".join(by_project["source-project"].get("warnings", []))
    self.assertIn(constants.DR_WARN_03, source_warnings)
    self.assertNotIn("[ACTION REQUIRED:", source_warnings)

    # The `secondary-project` policy references a routine in `source-project`,
    # which BigQuery Data Policy Service rejects (`All referenced resources must
    # reside in the same project.`), so it carries an `[ACTION REQUIRED]`
    # warning.
    secondary_warnings = " ".join(
        by_project["secondary-project"].get("warnings", [])
    )
    self.assertIn("[ACTION REQUIRED:", secondary_warnings)
    self.assertIn(
        "All referenced resources must reside in the same project.",
        secondary_warnings,
    )
    self.assertIn("secondary-project", secondary_warnings)

  # Taxonomy-level fine-grained readers must also be copied onto non-root Tag
  # Values that have a direct DATA_MASKING_POLICY so DGT's deepest-tag policy
  # precedence preserves unmasked read access, while leaving unmasked child Tag
  # Values inheriting solely from the Root Tag Value.
  def test_taxonomy_readers_copied_onto_masked_child_but_not_unmasked_child(
      self,
  ):
    """Copies taxonomy readers onto non-root masked Tag Values for parity."""
    # Attach a V1 masking policy to `Masked_Child` while keeping sibling
    # `Unmasked_Child` free of masking policies under `Root_Tag`.
    root_uri = "projects/12345/locations/us/taxonomies/111/policyTags/root"
    masked_child_uri = (
        "projects/12345/locations/us/taxonomies/111/policyTags/masked_child"
    )
    unmasked_child_uri = (
        "projects/12345/locations/us/taxonomies/111/policyTags/unmasked_child"
    )
    child_mask_policy = DataPolicyInfo(
        name="projects/12345/locations/us/dataPolicies/child_email_mask",
        policy_tag=masked_child_uri,
        masking_rule="EMAIL_MASK",
        policy_type=constants.DATA_POLICY_TYPE_MASKING,
        masked_readers=["user:tax-reader@example.com"],
    )
    taxonomy = TaxonomyInfo(
        name="projects/12345/locations/us/taxonomies/111",
        display_name="PII",
        location="us",
        policy_tags=[
            PolicyTagInfo(
                name=root_uri,
                display_name="Root_Tag",
                parent_policy_tag="",
            ),
            PolicyTagInfo(
                name=masked_child_uri,
                display_name="Masked_Child",
                parent_policy_tag=root_uri,
                data_policies=[child_mask_policy],
            ),
            PolicyTagInfo(
                name=unmasked_child_uri,
                display_name="Unmasked_Child",
                parent_policy_tag=root_uri,
            ),
        ],
        is_access_control=True,
        fine_grained_readers=["user:tax-reader@example.com"],
    )
    result = StaticTaxonomyAnalysisResult(
        project_id="source-project",
        location="us",
        taxonomies=[taxonomy],
    )

    # Generate the migration plan so _map_data_policies evaluates each Tag
    # Value's direct masking state against taxonomy.fine_grained_readers.
    plan = self.planner.generate_plan(
        [result],
        target_dgt_project_id="dgt-proj",
        target_data_policy_project_ids=["policy-proj"],
    )
    raw_policies = plan["phase_2_resource_manifest"][
        constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2
    ]
    by_tag_path = {
        item[constants.FIELD_DG_TAG_VALUE_NAMESPACED_NAME]: item
        for item in raw_policies
    }

    # Both Root_Tag and Masked_Child receive explicit RAW_DATA_ACCESS_POLICY
    # grants for the taxonomy reader, whereas Unmasked_Child relies on
    # hierarchical inheritance from Root_Tag without duplicating the policy.
    self.assertEqual(
        set(by_tag_path.keys()),
        {
            "dgt-proj/PII/Root_Tag",
            "dgt-proj/PII/Root_Tag/Masked_Child",
        },
    )
    self.assertEqual(
        by_tag_path["dgt-proj/PII/Root_Tag/Masked_Child"]["api_payload"][
            "grantees"
        ],
        ["principal://goog/subject/tax-reader@example.com"],
    )

  # Legacy domain-scoped project IDs containing ':' are rejected upfront across
  # source, DGT, and Data Policy project arguments.
  def test_generate_plan_rejects_domain_scoped_project_ids(self):
    """Raises `ValueError` when any plan project ID contains ':'."""
    result = StaticTaxonomyAnalysisResult(
        project_id="source-project",
        location="us",
        taxonomies=[],
    )
    with self.assertRaises(ValueError) as dgt_ctx:
      self.planner.generate_plan(
          [result],
          target_dgt_project_id="example.com:dgt-proj",
          target_data_policy_project_ids=["policy-proj"],
      )
    self.assertIn(
        constants.UNSUPPORTED_DOMAIN_SCOPED_PROJECT_MSG,
        str(dgt_ctx.exception),
    )
    with self.assertRaises(ValueError) as policy_ctx:
      self.planner.generate_plan(
          [result],
          target_dgt_project_id="dgt-proj",
          target_data_policy_project_ids=["example.com:policy-proj"],
      )
    self.assertIn(
        constants.UNSUPPORTED_DOMAIN_SCOPED_PROJECT_MSG,
        str(policy_ctx.exception),
    )

  # V2 Data Policy grantees reject Authorized Routine URIs and enforce IAM v3
  # Access Policy limits of 500 distinct IAM principals and 100 groups.
  def test_validate_grantees_flags_authorized_routine_and_principal_limits(
      self,
  ):
    routine_uri = (
        "principal://bigquery.googleapis.com/projects/source-project/"
        "datasets/shared_ds/routines/authorized_udf"
    )
    cases = [
        (
            "authorized_routine_rejected",
            [routine_uri],
            "Authorized Routine principal",
        ),
        (
            "exceeds_500_iam_principals",
            [
                f"user:reader-{index}@example.com"
                for index in range(
                    constants.MAX_GRANTEES_PER_DATA_POLICY_V2 + 1
                )
            ],
            "500 distinct IAM principals",
        ),
        (
            "exceeds_100_group_principals",
            [
                f"group:team-{index}@example.com"
                for index in range(
                    constants.MAX_GROUP_GRANTEES_PER_DATA_POLICY_V2 + 1
                )
            ],
            "100 distinct principalSet:// groups",
        ),
    ]
    for case_name, readers, expected_phrase in cases:
      with self.subTest(case=case_name):
        policy_tag = PolicyTagInfo(
            name="projects/12345/locations/us/taxonomies/111/policyTags/1",
            display_name="Restricted_Col",
            parent_policy_tag="",
            fine_grained_readers=readers,
        )
        taxonomy = TaxonomyInfo(
            name="projects/12345/locations/us/taxonomies/111",
            display_name="PII",
            location="us",
            policy_tags=[policy_tag],
            is_access_control=True,
        )
        analysis = StaticTaxonomyAnalysisResult(
            project_id="source-project", location="us", taxonomies=[taxonomy]
        )

        # Generate plan so _validate_grantees audits the converted IAM v3 URIs.
        plan = self.planner.generate_plan(
            [analysis],
            target_dgt_project_id="dgt-proj",
            target_data_policy_project_ids=["policy-proj"],
        )
        raw_action = plan["phase_2_resource_manifest"][
            constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2
        ][0]
        joined_warnings = " ".join(raw_action.get("warnings", []))

        # Confirm [ACTION REQUIRED] fires with the exact violated limit/URI and
        # Authorized Routines do not falsely emit DR_WARN_04.
        self.assertIn("[ACTION REQUIRED:", joined_warnings)
        self.assertIn(expected_phrase, joined_warnings)
        self.assertNotIn(constants.DR_WARN_04, joined_warnings)

    # Boundary check: 500 total IAM principals (100 groups + 400 users) passes
    # with zero [ACTION REQUIRED] grantee warnings.
    boundary_readers = [
        f"group:team-{index}@example.com"
        for index in range(constants.MAX_GROUP_GRANTEES_PER_DATA_POLICY_V2)
    ] + [
        f"user:reader-{index}@example.com"
        for index in range(
            constants.MAX_GRANTEES_PER_DATA_POLICY_V2
            - constants.MAX_GROUP_GRANTEES_PER_DATA_POLICY_V2
        )
    ]
    boundary_tag = PolicyTagInfo(
        name="projects/12345/locations/us/taxonomies/111/policyTags/2",
        display_name="Boundary_Col",
        parent_policy_tag="",
        fine_grained_readers=boundary_readers,
    )
    boundary_plan = self.planner.generate_plan(
        [
            StaticTaxonomyAnalysisResult(
                project_id="source-project",
                location="us",
                taxonomies=[
                    TaxonomyInfo(
                        name="projects/12345/locations/us/taxonomies/111",
                        display_name="PII",
                        location="us",
                        policy_tags=[boundary_tag],
                        is_access_control=True,
                    )
                ],
            )
        ],
        target_dgt_project_id="dgt-proj",
        target_data_policy_project_ids=["policy-proj"],
    )
    boundary_action = boundary_plan["phase_2_resource_manifest"][
        constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2
    ][0]
    self.assertEqual(boundary_action.get("warnings", []), [])

  # DR_WARN_04 must warn that Data Governance Tag policies do not delegate
  # column access through Authorized Views or Authorized Datasets.
  def test_dr_warn_04_warns_authorized_views_do_not_delegate_dgt_access(self):
    authorized_view = (
        "principal://goog/bigquery/datasets/analytics_ds/tables/curated_view"
    )
    policy_tag = PolicyTagInfo(
        name="projects/12345/locations/us/taxonomies/111/policyTags/1",
        display_name="Email",
        parent_policy_tag="",
        fine_grained_readers=[authorized_view],
    )
    plan = self.planner.generate_plan(
        [
            StaticTaxonomyAnalysisResult(
                project_id="source-project",
                location="us",
                taxonomies=[
                    TaxonomyInfo(
                        name="projects/12345/locations/us/taxonomies/111",
                        display_name="PII",
                        location="us",
                        policy_tags=[policy_tag],
                        is_access_control=True,
                    )
                ],
            )
        ],
        target_dgt_project_id="dgt-proj",
        target_data_policy_project_ids=["policy-proj"],
    )
    raw_action = plan["phase_2_resource_manifest"][
        constants.KEY_POLICY_TAGS_TO_RAW_READER_DATA_POLICIES_V2
    ][0]
    joined_warnings = " ".join(raw_action.get("warnings", []))
    report = self.planner.generate_markdown_report(plan)

    # Confirm both the action warning and Markdown reference explain that
    # Authorized Views/Datasets do not delegate DGT column access.
    self.assertIn(constants.DR_WARN_04, joined_warnings)
    self.assertIn(
        "do not delegate column-level access through Authorized Views or"
        " Authorized Datasets",
        joined_warnings,
    )
    self.assertIn("Non-Delegation", report)

  # Multiple custom masking routine policies on the same Tag Value fail closed
  # at query time if a non-raw user matches >= 2 custom routines.
  def test_sibling_custom_masking_routines_flag_overlapping_grantees(self):
    tag_uri = "projects/12345/locations/us/taxonomies/111/policyTags/1"
    # Overlap on `analyst@example.com` (no raw access), while
    # `admin@example.com` holds raw access so `RAW_DATA_ACCESS_POLICY` wins.
    routine_policy_a = DataPolicyInfo(
        name="projects/12345/locations/us/dataPolicies/custom_mask_a",
        policy_tag=tag_uri,
        masking_rule="Custom Routine: policy-proj.gov_ds.mask_a",
        policy_type=constants.DATA_POLICY_TYPE_MASKING,
        masked_readers=["user:analyst@example.com", "user:admin@example.com"],
    )
    routine_policy_b = DataPolicyInfo(
        name="projects/12345/locations/us/dataPolicies/custom_mask_b",
        policy_tag=tag_uri,
        masking_rule="Custom Routine: policy-proj.gov_ds.mask_b",
        policy_type=constants.DATA_POLICY_TYPE_MASKING,
        masked_readers=["user:analyst@example.com", "user:admin@example.com"],
    )
    disjoint_tag_uri = "projects/12345/locations/us/taxonomies/111/policyTags/2"
    disjoint_policy_a = DataPolicyInfo(
        name="projects/12345/locations/us/dataPolicies/group_mask_a",
        policy_tag=disjoint_tag_uri,
        masking_rule="Custom Routine: policy-proj.gov_ds.mask_a",
        policy_type=constants.DATA_POLICY_TYPE_MASKING,
        masked_readers=["group:tier1@example.com"],
    )
    disjoint_policy_b = DataPolicyInfo(
        name="projects/12345/locations/us/dataPolicies/group_mask_b",
        policy_tag=disjoint_tag_uri,
        masking_rule="Custom Routine: policy-proj.gov_ds.mask_b",
        policy_type=constants.DATA_POLICY_TYPE_MASKING,
        masked_readers=["group:tier2@example.com"],
    )
    taxonomy = TaxonomyInfo(
        name="projects/12345/locations/us/taxonomies/111",
        display_name="PII",
        location="us",
        policy_tags=[
            PolicyTagInfo(
                name=tag_uri,
                display_name="Overlap_Tag",
                parent_policy_tag="",
                fine_grained_readers=["user:admin@example.com"],
                data_policies=[routine_policy_a, routine_policy_b],
            ),
            PolicyTagInfo(
                name=disjoint_tag_uri,
                display_name="Disjoint_Tag",
                parent_policy_tag="",
                data_policies=[disjoint_policy_a, disjoint_policy_b],
            ),
        ],
        is_access_control=True,
    )
    plan = self.planner.generate_plan(
        [
            StaticTaxonomyAnalysisResult(
                project_id="source-project",
                location="us",
                taxonomies=[taxonomy],
            )
        ],
        target_dgt_project_id="dgt-proj",
        target_data_policy_project_ids=["policy-proj"],
    )
    migrated = {
        action["policy_id"]: " ".join(action.get("warnings", []))
        for action in plan["phase_2_resource_manifest"][
            constants.KEY_DATA_POLICIES_V1_TO_DATA_POLICIES_V2
        ]
    }

    # Overlapping `analyst@example.com` triggers [ACTION REQUIRED] without
    # falsely blaming `admin@example.com` (who holds raw access).
    overlap_warnings = migrated["migrated_masking_PII_custom_mask_a"]
    self.assertIn("[ACTION REQUIRED:", overlap_warnings)
    self.assertIn(
        "Found multiple conflicting data policies with custom masking"
        " expressions.",
        overlap_warnings,
    )
    self.assertIn(
        "principal://goog/subject/analyst@example.com", overlap_warnings
    )
    self.assertNotIn("admin@example.com", overlap_warnings)

    # Disjoint group URIs emit a non-blocking group-overlap advisory warning.
    disjoint_warnings = migrated["migrated_masking_PII_group_mask_a"]
    self.assertNotIn("[ACTION REQUIRED:", disjoint_warnings)
    self.assertIn(
        "Ensure group memberships across sibling custom masking routine"
        " policies do not overlap",
        disjoint_warnings,
    )

  # Cloud Resource Manager caps Tag Keys at 1,000 per project and Tag Values at
  # 1,000 per Tag Key; exceeding either emits [ACTION REQUIRED] on excess items.
  def test_generate_plan_flags_exceeding_tag_keys_and_tag_values_limits(self):
    # Case 1: 1,001 Tag Values under one classification-only Taxonomy.
    with self.subTest(quota="max_tag_values_per_tag_key"):
      many_tags = [
          PolicyTagInfo(
              name=f"projects/12345/locations/us/taxonomies/1/policyTags/{idx}",
              display_name=f"Tag_{idx}",
              parent_policy_tag="",
          )
          for idx in range(constants.MAX_DG_TAG_VALUES_PER_TAG_KEY + 1)
      ]
      value_plan = self.planner.generate_plan(
          [
              StaticTaxonomyAnalysisResult(
                  project_id="source-project",
                  location="us",
                  taxonomies=[
                      TaxonomyInfo(
                          name="projects/12345/locations/us/taxonomies/1",
                          display_name="Wide_Taxonomy",
                          location="us",
                          policy_tags=many_tags,
                          is_access_control=False,
                      )
                  ],
              )
          ],
          target_dgt_project_id="dgt-proj",
          target_data_policy_project_ids=["policy-proj"],
      )
      key_action = value_plan["phase_2_resource_manifest"][
          constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS
      ][0]
      value_actions = value_plan["phase_2_resource_manifest"][
          constants.KEY_POLICY_TAGS_TO_DG_TAG_VALUES
      ]
      self.assertIn(
          "1001 planned Tag Values", " ".join(key_action.get("warnings", []))
      )
      self.assertEqual(value_actions[999].get("warnings", []), [])
      self.assertIn(
          "[ACTION REQUIRED:",
          " ".join(value_actions[1000].get("warnings", [])),
      )

    # Case 2: 1,001 Taxonomies mapped into `--target-dgt-project-id`.
    with self.subTest(quota="max_tag_keys_per_project"):
      many_taxonomies = [
          TaxonomyInfo(
              name=f"projects/12345/locations/us/taxonomies/{idx}",
              display_name=f"Tax_{idx}",
              location="us",
              policy_tags=[],
              is_access_control=False,
          )
          for idx in range(constants.MAX_DG_TAG_KEYS_PER_PROJECT + 1)
      ]
      key_plan = self.planner.generate_plan(
          [
              StaticTaxonomyAnalysisResult(
                  project_id="source-project",
                  location="us",
                  taxonomies=many_taxonomies,
              )
          ],
          target_dgt_project_id="dgt-proj",
          target_data_policy_project_ids=["policy-proj"],
      )
      key_actions = key_plan["phase_2_resource_manifest"][
          constants.KEY_TAXONOMIES_TO_DG_TAG_KEYS
      ]
      self.assertTrue(
          any(
              "1001 planned Data Governance Tag Keys" in warning
              and "[ACTION REQUIRED:" in warning
              for warning in key_plan.get("warnings", [])
          )
      )
      self.assertEqual(key_actions[999].get("warnings", []), [])
      self.assertIn(
          "[ACTION REQUIRED:", " ".join(key_actions[1000].get("warnings", []))
      )

  # Malformed or partial V1 `DATA_MASKING_POLICY` objects with
  # `masking_rule=None` must plan without crashing and emit `[ACTION REQUIRED]`
  # so `--phase create` and forward `--phase swap` block upfront.
  def test_generate_plan_handles_none_masking_rule_without_crash(self):
    policy_tag = PolicyTagInfo(
        name="projects/12345/locations/us/taxonomies/111/policyTags/1",
        display_name="Nullable_Mask_Tag",
        parent_policy_tag="",
        data_policies=[
            DataPolicyInfo(
                name="projects/source-project/locations/us/dataPolicies/null_m",
                policy_tag=(
                    "projects/12345/locations/us/taxonomies/111/policyTags/1"
                ),
                policy_type=constants.DATA_POLICY_TYPE_MASKING,
                masking_rule=None,
                masked_readers=["user:masked@example.com"],
            )
        ],
    )
    taxonomy = TaxonomyInfo(
        name="projects/12345/locations/us/taxonomies/111",
        display_name="Sensitive_Data",
        location="us",
        policy_tags=[policy_tag],
        is_access_control=True,
    )
    plan = self.planner.generate_plan(
        [
            StaticTaxonomyAnalysisResult(
                project_id="source-project",
                location="us",
                taxonomies=[taxonomy],
            )
        ],
        target_dgt_project_id="dgt-proj",
        target_data_policy_project_ids=["policy-proj"],
    )
    migrated = plan["phase_2_resource_manifest"][
        constants.KEY_DATA_POLICIES_V1_TO_DATA_POLICIES_V2
    ]
    self.assertEqual(len(migrated), 1)
    self.assertEqual(migrated[0]["api_payload"]["data_masking_policy"], {})
    # Confirm empty `data_masking_policy: {}` carries an `[ACTION REQUIRED:`
    # warning naming the offending V1 policy so create/swap block fail-closed.
    joined_warnings = " ".join(migrated[0].get("warnings", []))
    self.assertIn(
        "Source V1 DATA_MASKING_POLICY"
        " 'projects/source-project/locations/us/dataPolicies/null_m' has no"
        " masking expression or custom routine",
        joined_warnings,
    )
    self.assertIn("[ACTION REQUIRED:", joined_warnings)

  # Empty V1 `COLUMN_LEVEL_SECURITY_POLICY` markers must be deduplicated against
  # `_default_deny`, while non-empty raw readers emit `[ACTION REQUIRED]`.
  def test_generate_plan_deduplicates_empty_cls_and_warns_on_cls_grantees(self):
    empty_cls_tag = PolicyTagInfo(
        name="projects/12345/locations/us/taxonomies/111/policyTags/1",
        display_name="Empty_Cls",
        parent_policy_tag="",
        data_policies=[
            DataPolicyInfo(
                name="projects/source-project/locations/us/dataPolicies/cls_0",
                policy_tag=(
                    "projects/12345/locations/us/taxonomies/111/policyTags/1"
                ),
                policy_type=constants.DATA_POLICY_TYPE_CLS,
                masking_rule=None,
                raw_readers=[],
            )
        ],
    )
    grantee_cls_tag = PolicyTagInfo(
        name="projects/12345/locations/us/taxonomies/111/policyTags/2",
        display_name="Grantee_Cls",
        parent_policy_tag="",
        data_policies=[
            DataPolicyInfo(
                name="projects/source-project/locations/us/dataPolicies/cls_1",
                policy_tag=(
                    "projects/12345/locations/us/taxonomies/111/policyTags/2"
                ),
                policy_type=constants.DATA_POLICY_TYPE_CLS,
                masking_rule=None,
                raw_readers=["user:legacy_raw@example.com"],
            )
        ],
    )
    taxonomy = TaxonomyInfo(
        name="projects/12345/locations/us/taxonomies/111",
        display_name="CLS_Tax",
        location="us",
        policy_tags=[empty_cls_tag, grantee_cls_tag],
        is_access_control=True,
    )
    plan = self.planner.generate_plan(
        [
            StaticTaxonomyAnalysisResult(
                project_id="source-project",
                location="us",
                taxonomies=[taxonomy],
            )
        ],
        target_dgt_project_id="dgt-proj",
        target_data_policy_project_ids=["policy-proj"],
    )

    manifest = plan["phase_2_resource_manifest"]
    # `empty_cls_tag` is covered by `_default_deny` without an extra V1->V2 raw
    # policy, while `grantee_cls_tag` emits an `[ACTION REQUIRED:` warning.
    migrated = manifest[constants.KEY_DATA_POLICIES_V1_TO_DATA_POLICIES_V2]
    self.assertEqual(len(migrated), 1)
    self.assertEqual(
        migrated[0]["source_resource_name"],
        "projects/source-project/locations/us/dataPolicies/cls_1",
    )
    joined_warnings = " ".join(migrated[0].get("warnings", []))
    self.assertIn("COLUMN_LEVEL_SECURITY_POLICY", joined_warnings)
    self.assertIn("[ACTION REQUIRED:", joined_warnings)
    default_deny_actions = manifest[
        constants.KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2
    ]
    self.assertEqual(len(default_deny_actions), 2)

  # Generated plans stamp `metadata.schema_version == 1`, while
  # `validate_plan_schema_version` accepts unversioned v1.0 fixtures and rejects
  # invalid or future schema versions fail-closed.
  def test_generate_plan_stamps_schema_version_and_validates_contract(self):
    plan = self.planner.generate_plan(
        [
            StaticTaxonomyAnalysisResult(
                project_id="source-project",
                location="us",
                taxonomies=[],
            )
        ],
        target_dgt_project_id="dgt-proj",
        target_data_policy_project_ids=["policy-proj"],
    )

    # Confirm Phase 1b stamps integer `schema_version: 1` into `metadata`.
    self.assertIs(type(plan["metadata"]["schema_version"]), int)
    self.assertEqual(
        plan["metadata"]["schema_version"], constants.PLAN_SCHEMA_VERSION
    )
    self.assertEqual(constants.validate_plan_schema_version(plan), 1)
    # Unversioned v1.0 fixtures remain backward-compatible as version 1.
    self.assertEqual(constants.validate_plan_schema_version({}), 1)
    self.assertEqual(
        constants.validate_plan_schema_version({"metadata": {}}), 1
    )

    # Future integer versions fail closed with an upgrade/regenerate message.
    with self.assertRaisesRegex(
        ValueError,
        r"Unsupported migration plan schema_version=2.*schema_version=1",
    ):
      constants.validate_plan_schema_version(
          {"metadata": {"schema_version": 2}}
      )

    # Malformed `plan`, `metadata`, boolean, string, null, and non-positive
    # `schema_version` values fail closed (`isinstance(True, int)` guard).
    invalid_plans: list[tuple[Any, str]] = [
        ([], r"top-level JSON root must be an object"),
        ({"metadata": []}, r"'metadata' must be a JSON object"),
        (
            {"metadata": {"schema_version": True}},
            r"'metadata\.schema_version' must be a positive integer",
        ),
        (
            {"metadata": {"schema_version": 0}},
            r"'metadata\.schema_version' must be a positive integer",
        ),
        (
            {"metadata": {"schema_version": "1"}},
            r"'metadata\.schema_version' must be a positive integer",
        ),
        (
            {"metadata": {"schema_version": None}},
            r"'metadata\.schema_version' must be a positive integer",
        ),
    ]
    for bad_plan, expected_regex in invalid_plans:
      with self.subTest(bad_plan=bad_plan):
        with self.assertRaisesRegex(ValueError, expected_regex):
          constants.validate_plan_schema_version(bad_plan)

  # When an empty V1 `COLUMN_LEVEL_SECURITY_POLICY` carries warnings (such as
  # omitted conditional IAM bindings), deduplicating it against `_default_deny`
  # must forward those warnings onto the tag's `_default_deny` policy action.
  def test_generate_plan_preserves_warnings_from_skipped_empty_cls_policy(self):
    warning_msg = (
        "[ACTION REQUIRED] Conditional IAM binding for role"
        " 'roles/bigquerydatapolicy.rawDataReader' omitted fail-closed."
    )
    cls_tag = PolicyTagInfo(
        name="projects/12345/locations/us/taxonomies/111/policyTags/1",
        display_name="Conditional_Cls",
        parent_policy_tag="",
        data_policies=[
            DataPolicyInfo(
                name="projects/source-project/locations/us/dataPolicies/cls_0",
                policy_tag=(
                    "projects/12345/locations/us/taxonomies/111/policyTags/1"
                ),
                policy_type=constants.DATA_POLICY_TYPE_CLS,
                masking_rule=None,
                raw_readers=[],
                warnings=[warning_msg],
            )
        ],
    )
    taxonomy = TaxonomyInfo(
        name="projects/12345/locations/us/taxonomies/111",
        display_name="CLS_Tax",
        location="us",
        policy_tags=[cls_tag],
        is_access_control=True,
    )
    plan = self.planner.generate_plan(
        [
            StaticTaxonomyAnalysisResult(
                project_id="source-project",
                location="us",
                taxonomies=[taxonomy],
            )
        ],
        target_dgt_project_id="dgt-proj",
        target_data_policy_project_ids=["policy-proj"],
    )

    manifest = plan["phase_2_resource_manifest"]
    self.assertEqual(
        manifest[constants.KEY_DATA_POLICIES_V1_TO_DATA_POLICIES_V2], []
    )
    default_deny_actions = manifest[
        constants.KEY_POLICY_TAGS_TO_DEFAULT_DENY_DATA_POLICIES_V2
    ]
    self.assertEqual(len(default_deny_actions), 1)
    self.assertIn(warning_msg, default_deny_actions[0].get("warnings", []))


if __name__ == "__main__":
  unittest.main()
