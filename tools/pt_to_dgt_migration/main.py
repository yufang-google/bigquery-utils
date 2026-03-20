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

"""Entrypoint for BigQuery Policy Tag to Data Governance Tag migration tool."""

from __future__ import annotations

import argparse
import logging
import sys

from analyzer import Analyzer
from google.api_core import exceptions
from google.cloud import bigquery_datapolicies_v1
from google.cloud import datacatalog_v1

logger = logging.getLogger(__name__)


def main():
  """Main function to run the analyzer."""
  logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")

  parser = argparse.ArgumentParser(
      description="Policy Tag to Data Governance Tag migration tool."
  )
  parser.add_argument(
      "--phase",
      required=True,
      choices=["analyze", "plan", "create", "bind"],
      help="The migration phase to execute.",
  )
  parser.add_argument(
      "--project-ids",
      required=True,
      nargs="+",
      help="One or more Google Cloud project IDs to scan.",
  )
  parser.add_argument(
      "--source-regions",
      required=True,
      nargs="+",
      help="One or more regions to scan for policy tags.",
  )
  args = parser.parse_args()

  try:
    data_catalog_client = datacatalog_v1.PolicyTagManagerClient()
    data_policy_client = bigquery_datapolicies_v1.DataPolicyServiceClient()
  except exceptions.DefaultCredentialsError:
    logger.error(
        "Authentication failed. Please configure your GCP credentials"
        " (e.g., by running 'gcloud auth application-default login')."
    )
    sys.exit(1)
  except exceptions.GoogleAPIError as e:
    logger.error("Failed to initialize Google Cloud clients: %s", e)
    sys.exit(1)

  analyzer = Analyzer(data_catalog_client, data_policy_client)
  if args.phase == "analyze":
    try:
      results = analyzer.run(args.project_ids, args.source_regions)
      report = analyzer.generate_report(results)
      print(report)
    except exceptions.GoogleAPIError as e:
      logger.error("Analysis failed: %s", e)
      sys.exit(1)
  else:
    logger.info("Phase '%s' is not yet implemented.", args.phase)


if __name__ == "__main__":
  main()
