# BigQuery Policy Tag to Data Governance Tag Migration Tool

## Disclaimer

***AS IS, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED***

***NOT AN OFFICIALLY SUPPORTED GOOGLE PRODUCT***

**This script is provided on a best-effort basis to assist with migrating
BigQuery Column Level Security from regional Policy Tags (PT) to global Data
Governance Tags (DGT). It has not been thoroughly tested, and Google provides no
guarantee for its correctness. You agree to use this script at your own risk.**

--------------------------------------------------------------------------------

## Overview

BigQuery is moving from regional Policy Tags (PT) to global Data Governance Tags
(DGT) for Column Level Security (CLS). This tool helps automate the migration
process by analyzing your existing Policy Tag setup, helping you plan the
migration to the new DGT resource model, creating the necessary DGT resources
(Tag Keys, Tag Values, Data Policies), and binding the new DGTs to BigQuery
table columns.

This tool operates in multiple phases:

1.  **Analyze:** Scans specified projects and regions to discover existing
    taxonomies, policy tags, their IAM policies
    (`roles/datacatalog.fineGrainedReader`), and any associated BigQuery Data
    Policies for masking. Outputs a report of the current setup.
2.  **Plan:** (Not yet implemented) Generates a migration plan based on the
    analysis phase.
3.  **Create:** (Not yet implemented) Creates Data Governance Tag Keys, Tag
    Values, and Data Policies based on the migration plan.
4.  **Bind:** (Not yet implemented) Binds the newly created Data Governance Tags
    to BigQuery table columns.

## Prerequisites

1.  Python 3.9+ installed.
2.  Google Cloud SDK (`gcloud`) installed and authenticated:
    *   Run `gcloud auth login`
3.  Required Python libraries installed. We recommend using a virtual
    environment:

    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    pip install google-cloud-bigquery google-cloud-datacatalog google-cloud-bigquery-datapolicies google-api-python-client
    ```

4.  The user or service account running the script needs sufficient IAM
    permissions in the project(s) being scanned. For the `analyze` phase, the
    following roles are recommended:

    *   Data Catalog Viewer (`roles/datacatalog.viewer`) - To list taxonomies.
    *   Data Catalog Policy Tag Admin (`roles/datacatalog.policyTagAdmin`) - To
        get policy tag IAM policies.
    *   BigQuery DataPolicy Viewer (`roles/bigquerydatapolicy.viewer`) - To list
        data policies.
    *   BigQuery DataPolicy Admin (`roles/bigquerydatapolicy.admin`) - To get
        data policy IAM policies.

## Usage

Activate the virtual environment and run the `main.py` script, specifying the
phase and required options.

```bash
source .venv/bin/activate
python main.py --phase <PHASE> [options]
```

### Analyze Phase

*   **Purpose:** Scans the specified projects and regions for taxonomies, policy
    tags, and data policies, then outputs a report to the console.
*   **Usage:**

    ```bash
    python main.py --phase analyze \
      --project-ids my-gcp-project \
      --source-regions us-central1 eu
    ```

*   **Arguments:**

    *   `--phase analyze`: Specifies that the analyze phase should be run.
    *   `--project-ids <ID ...>`: **(Required)** One or more Google Cloud
        project IDs to scan (e.g. 'my-gcp-project').
    *   `--source-regions <REGION ...>`: **(Required)** One or more regions to
        scan for policy tags (e.g., `us`, `eu`, `us-central1`).
