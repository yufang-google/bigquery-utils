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

"""Analyzes BigQuery Policy Tags and Data Policies.

It is used for migration to Data Governance Tags.
"""

from __future__ import annotations

import dataclasses
import datetime
import logging

from google.api_core import exceptions
from google.api_core import retry
from google.cloud import bigquery_datapolicies_v1
from google.cloud import datacatalog_v1
from googleapiclient import discovery
from googleapiclient import errors

# pylint: disable=g-import-not-at-top
try:
  from google3.google.iam.v1 import iam_policy_pb2
  from google3.google.iam.v1 import policy_pb2
except ImportError:
  from google.iam.v1 import iam_policy_pb2
  from google.iam.v1 import policy_pb2

FINE_GRAINED_READER_ROLE = "roles/datacatalog.categoryFineGrainedReader"
MASKED_READER_ROLE = "roles/bigquerydatapolicy.maskedReader"

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


_project_id_to_number_cache = {}
_project_number_to_id_cache = {}


@dataclasses.dataclass
class DataPolicyInfo:
  """Holds information about a BigQuery Data Policy.

  Attributes:
    name: The active resource name of the data policy.
    policy_tag: The policy tag name.
    masking_rule: The data masking rule for the data policy.
    masked_readers: The list of masked reader principals.
  """

  name: str
  policy_tag: str
  masking_rule: str | None
  masked_readers: list[str] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class PolicyTagInfo:
  """Holds information about a Data Catalog Policy Tag.

  Attributes:
    name: The name of the policy tag.
    display_name: The human-readable name of the policy tag.
    parent_policy_tag: The parent policy tag name, if any.
    fine_grained_readers: Principals with fine-grained reader access.
    data_policies: Associated data policies.
  """

  name: str
  display_name: str
  parent_policy_tag: str
  fine_grained_readers: list[str] = dataclasses.field(default_factory=list)
  data_policies: list[DataPolicyInfo] = dataclasses.field(default_factory=list)


@dataclasses.dataclass
class TaxonomyInfo:
  """Holds information about a Data Catalog Taxonomy.

  Attributes:
    name: The name of the taxonomy.
    display_name: The human-readable name of the taxonomy.
    location: The region or location of the taxonomy.
    policy_tags: Policy tags within the taxonomy.
    is_access_control: Whether the taxonomy is used for access control.
  """

  name: str
  display_name: str
  location: str
  policy_tags: list[PolicyTagInfo] = dataclasses.field(default_factory=list)
  is_access_control: bool = False

  @property
  def total_data_policies(self) -> int:
    """Calculates the total number of data policies in the taxonomy.

    Returns:
        The total count of data policies associated with the policy tags in
        this taxonomy.
    """
    return sum(len(policy_tag.data_policies) for policy_tag in self.policy_tags)


def _get_principals_for_role(policy: policy_pb2.Policy, role: str) -> list[str]:
  """Extracts principals from an IAM policy for a given role."""
  principals = []
  for binding in policy.bindings:
    if binding.role == role:
      principals.extend(binding.members)
  return principals


def _get_project_number(project_id: str) -> str | None:
  """Looks up project number from project ID."""
  if project_id in _project_id_to_number_cache:
    return _project_id_to_number_cache[project_id]
  try:
    crm_service = discovery.build(
        "cloudresourcemanager", "v1", cache_discovery=False
    )
    request = crm_service.projects().get(projectId=project_id)
    response = request.execute()
    project_number = response.get("projectNumber")
    if project_number and project_number.isdigit():
      logger.info(
          "Looked up project number for %s: %s", project_id, project_number
      )
      _project_id_to_number_cache[project_id] = project_number
      _project_number_to_id_cache[project_number] = project_id
      return project_number
    else:
      logger.error(
          "Cloud Resource Manager API did not return a valid project number"
          " for %s.",
          project_id,
      )
      return None
  except errors.HttpError as e:
    logger.exception(
        "Failed to lookup project number for %s using Cloud Resource Manager"
        " API: %s",
        project_id,
        e,
    )
    return None


def _get_project_id(project_number: str) -> str | None:
  """Looks up project id from project number."""
  if project_number in _project_number_to_id_cache:
    return _project_number_to_id_cache[project_number]
  try:
    crm_service = discovery.build(
        "cloudresourcemanager", "v1", cache_discovery=False
    )
    # Note that the projectId parameter accepts both project IDs and project
    # numbers.
    request = crm_service.projects().get(projectId=project_number)
    response = request.execute()
    project_id = response.get("projectId")
    if project_id:
      _project_id_to_number_cache[project_id] = project_number
      _project_number_to_id_cache[project_number] = project_id
      return project_id
    else:
      logger.error(
          "Cloud Resource Manager API did not return a valid project ID"
          " for %s.",
          project_number,
      )
      return None
  except errors.HttpError as e:
    logger.exception(
        "Failed to lookup project ID for %s using Cloud Resource Manager"
        " API: %s",
        project_number,
        e,
    )
    return None


class Analyzer:
  """Analyzes existing Policy Tag setup in given projects and regions."""

  def __init__(
      self,
      data_catalog_client: datacatalog_v1.PolicyTagManagerClient,
      data_policy_client: bigquery_datapolicies_v1.DataPolicyServiceClient,
  ):
    """Initializes the Analyzer.

    Args:
        data_catalog_client: An initialized Data Catalog PolicyTagManagerClient.
        data_policy_client: An initialized BigQuery DataPolicyServiceClient.
    """
    self._data_catalog_client = data_catalog_client
    self._data_policy_client = data_policy_client

  def list_policy_tags_in_taxonomy(
      self, taxonomy_name: str, project_id: str, project_number: str
  ) -> list[PolicyTagInfo]:
    """Lists all policy tags in a given taxonomy.

    Args:
        taxonomy_name: The resource name of the taxonomy.
        project_id: The project ID for string replacement.
        project_number: The project number for string replacement.

    Returns:
        A list of PolicyTagInfo objects.
    """
    policy_tags: list[PolicyTagInfo] = []
    try:
      policy_tag_pager = self._data_catalog_client.list_policy_tags(
          parent=taxonomy_name, retry=RETRY_CONFIG
      )
      for policy_tag in policy_tag_pager:
        policy_tag_name_for_iam = policy_tag.name.replace(
            f"projects/{project_id}/", f"projects/{project_number}/"
        )
        policy_tag_parent_for_iam = ""
        if policy_tag.parent_policy_tag:
          policy_tag_parent_for_iam = policy_tag.parent_policy_tag.replace(
              f"projects/{project_id}/", f"projects/{project_number}/"
          )
        policy_tag_info = PolicyTagInfo(
            name=policy_tag_name_for_iam,
            display_name=policy_tag.display_name,
            parent_policy_tag=policy_tag_parent_for_iam,
        )
        try:
          iam_policy = self._data_catalog_client.get_iam_policy(
              request=iam_policy_pb2.GetIamPolicyRequest(
                  resource=policy_tag_name_for_iam
              ),
              retry=RETRY_CONFIG,
          )
          policy_tag_info.fine_grained_readers = _get_principals_for_role(
              iam_policy, FINE_GRAINED_READER_ROLE
          )
        except exceptions.PermissionDenied as e:
          logger.error(
              "Permission denied to get IAM policy for policy tag %s."
              " Please check your IAM permissions (requires"
              " datacatalog.policyTags.getIamPolicy).",
              policy_tag_name_for_iam,
          )
          raise e
        except exceptions.GoogleAPICallError as e:
          logger.error(
              "Failed to get IAM policy for policy tag %s: %s",
              policy_tag_name_for_iam,
              e,
          )
          raise e
        policy_tags.append(policy_tag_info)
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

  def list_data_policies_in_taxonomy(
      self, project_id: str, location: str, taxonomy: TaxonomyInfo
  ) -> None:
    """Lists data policies associated with a taxonomy and updates PolicyTagInfo.

    Args:
        project_id: The project ID.
        location: The location of the data policies.
        taxonomy: The TaxonomyInfo object to update.
    """
    policy_tag_names = {policy_tag.name for policy_tag in taxonomy.policy_tags}
    policy_tag_map = {
        policy_tag.name: policy_tag for policy_tag in taxonomy.policy_tags
    }
    try:
      # Filter data policies that are associated with the current taxonomy.
      data_policy_filter = f"policy_tag:{taxonomy.name}*"
      request = bigquery_datapolicies_v1.ListDataPoliciesRequest(
          parent=f"projects/{project_id}/locations/{location}",
          filter=data_policy_filter,
      )
      data_policy_pager = self._data_policy_client.list_data_policies(
          request=request, retry=RETRY_CONFIG
      )
      for data_policy in data_policy_pager:
        if data_policy.policy_tag in policy_tag_names:
          taxonomy.is_access_control = True
          policy_tag_info = policy_tag_map[data_policy.policy_tag]
          rule = None
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
              rule = predefined_expression_name
            elif data_policy.data_masking_policy.routine:
              routine_parts = data_policy.data_masking_policy.routine.split("/")
              routine_project_number = routine_parts[-5]
              routine_project_id = _get_project_id(routine_project_number)
              if not routine_project_id:
                routine_project_id = (
                    f"<unknown-project-{routine_project_number}>"
                )
                logger.warning(
                    "Data Policy '%s' references a routine in project number"
                    " '%s' which cannot be mapped to a project ID.",
                    data_policy.name,
                    routine_project_number,
                )
              rule = (
                  "Custom Routine:"
                  f" {routine_project_id}.{routine_parts[-3]}.{routine_parts[-1]}"
              )
          data_policy_info = DataPolicyInfo(
              name=data_policy.name,
              policy_tag=data_policy.policy_tag,
              masking_rule=rule,
          )
          try:
            iam_policy = self._data_policy_client.get_iam_policy(
                request=iam_policy_pb2.GetIamPolicyRequest(
                    resource=data_policy.name
                ),
                retry=RETRY_CONFIG,
            )
            data_policy_info.masked_readers = _get_principals_for_role(
                iam_policy, MASKED_READER_ROLE
            )
          except exceptions.PermissionDenied as e:
            logger.error(
                "Permission denied to get IAM policy for data policy %s."
                " Please check your IAM permissions (requires"
                " bigquery.dataPolicies.getIamPolicy).",
                data_policy.name,
            )
            raise e
          except exceptions.GoogleAPICallError as e:
            logger.error(
                "Failed to get IAM policy for data policy %s: %s",
                data_policy.name,
                e,
            )
            raise e
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

  def list_taxonomies(
      self, project_id: str, location: str
  ) -> list[TaxonomyInfo]:
    """Lists all taxonomies in a given project and location.

    Args:
        project_id: The project ID.
        location: The location of the taxonomies.

    Returns:
        A list of TaxonomyInfo objects representing the taxonomies.
    """
    taxonomies = []
    try:
      project_number = _get_project_number(project_id)
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
        taxonomy_info = TaxonomyInfo(
            name=taxonomy.name,
            display_name=taxonomy.display_name,
            location=location,
        )
        taxonomy_info.policy_tags = self.list_policy_tags_in_taxonomy(
            taxonomy.name, project_id, project_number
        )

        # Policy tag names and taxonomy name should use project number to match
        # DataPolicyServiceClient API policy_tag format in list filter and
        # for matching.
        taxonomy_info.name = taxonomy_info.name.replace(
            f"projects/{project_id}/", f"projects/{project_number}/"
        )

        self.list_data_policies_in_taxonomy(project_id, location, taxonomy_info)
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
      logger.error(
          "Failed to list taxonomies for project %s in location %s: %s",
          project_id,
          location,
          e,
      )
      raise e
    return taxonomies

  def run(
      self, project_ids: list[str], locations: list[str]
  ) -> dict[str, list[TaxonomyInfo]]:
    """Runs the analysis for the given projects and locations.

    Args:
        project_ids: A list of project IDs to scan.
        locations: A list of locations to scan.

    Returns:
        A dictionary mapping project ID to a list of TaxonomyInfo objects.
    """
    results = {}
    for project_id in project_ids:
      results[project_id] = []
      for location in locations:
        logger.info(
            "Scanning project %s in location %s...", project_id, location
        )
        results[project_id].extend(self.list_taxonomies(project_id, location))
    return results

  def generate_report(self, results: dict[str, list[TaxonomyInfo]]) -> str:
    """Generates a human-readable report from analysis results.

    Args:
        results: A dictionary mapping project ID to a list of TaxonomyInfo
          objects.

    Returns:
        The text representation of the report.
    """
    report_lines = []
    total_taxonomies = sum(len(taxonomies) for taxonomies in results.values())
    scan_time = datetime.datetime.now(datetime.timezone.utc).strftime(
        "%Y-%m-%d %H:%M UTC"
    )

    report_lines.append("=" * 72)
    report_lines.append(" " * 19 + "EXISTING POLICY TAG ANALYSIS")
    report_lines.append("=" * 72)
    report_lines.append(f"Scan Time: {scan_time}")
    report_lines.append(f"Total Taxonomies Found: {total_taxonomies}")
    report_lines.append("=" * 72)

    taxonomy_counter = 0

    def print_policy_tag_hierarchy(
        policy_tag: PolicyTagInfo,
        prefix: str,
        children_map: dict[str, list[PolicyTagInfo]],
    ):
      report_lines.append(f'{prefix}> Policy Tag: "{policy_tag.display_name}"')
      if policy_tag.fine_grained_readers:
        report_lines.append(
            f"{prefix}  ├── Permission: Fine-Grained Reader (Raw Access)"
        )
        for principal in policy_tag.fine_grained_readers:
          report_lines.append(f"{prefix}  │   └── Principals: {principal}")
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
        if data_policy.masked_readers:
          report_lines.append(f"{prefix}    ├── Permission: Masked Reader")
          for principal in data_policy.masked_readers:
            report_lines.append(f"{prefix}    │   └── Principals: {principal}")

      for child_policy_tag in children_map[policy_tag.name]:
        print_policy_tag_hierarchy(
            child_policy_tag, prefix + "  ", children_map
        )

    for project_id in results:
      for taxonomy in results[project_id]:
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
        enforce_access = "ON" if taxonomy.is_access_control else "OFF"
        report_lines.append(f"    Region:                 {taxonomy.location}")
        report_lines.append(f"    Taxonomy Type:          {taxonomy_type}")
        report_lines.append(f"    Enforce Access Control: {enforce_access}")
        report_lines.append(
            f"    Total Policy Tags:      {len(taxonomy.policy_tags)}"
        )
        report_lines.append(
            f"    Total Data Policies:    {taxonomy.total_data_policies}"
        )
        report_lines.append("   [DETAILS]")

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
          print_policy_tag_hierarchy(root_policy_tag, "   ", children_map)

        report_lines.append("=" * 72)

    return "\n".join(report_lines)
