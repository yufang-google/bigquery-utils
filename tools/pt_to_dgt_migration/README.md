# BigQuery Policy Tag to Data Governance Tag Migration Tool

**Phase Guides:** **Overview (`README.md`)** |
[Phase 1a: Analyze](./phase_1a_analyze.md) |
[Phase 1b: Plan](./phase_1b_plan.md) | [Phase 2a: Create](./phase_2a_create.md)
| [Phase 2b: Delete](./phase_2b_delete.md) |
[Phase 3: Swap & Rollback](./phase_3_swap.md) | [Changelog](./CHANGELOG.md)

## Disclaimer

***AS IS, WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED***

***NOT AN OFFICIALLY SUPPORTED GOOGLE PRODUCT***

**This script is provided on a best-effort basis to assist with migrating
BigQuery Column Level Security from regional Policy Tags (PT) to global Data
Governance Tags (DGT). It has undergone limited testing, and Google provides no
guarantee for its correctness. You agree to use this script at your own risk.**

## Feature Gaps Between Policy Tags (PT) and Data Governance Tags (DGT)

Most BigQuery tables can migrate to Data Governance Tags today. A small number
of BigQuery and data pipeline features are still adding full Data Governance Tag
support in upcoming updates, and several architectural differences and service
quotas (documented in detail under
[Migration Tool & Platform Limitations](#migration-tool-platform-limitations))
require upfront review. You do **not** need to delay your overall migration
because of table-specific gaps. Instead, review the three sections below before
switching a dataset:

1.  **Specific tables to hold off migrating:** Keep **only** the matching tables
    on Policy Tags for now (unless your workload matches the safe exceptions
    column) while migrating the rest of your tables.
2.  **Project, IAM, and policy prerequisites (re-architect or hold off before
    migrating):** Confirm your projects, IAM grants, custom masking routines,
    and resource counts satisfy Data Governance Tag and V2 Data Policy platform
    requirements before running the migration tool.
3.  **Operational and tooling differences with simple workarounds:** These
    differences do **not** block migration and have straightforward workarounds.

### 1. Specific Tables to Hold Off Migrating

If a table matches the first column below **and** does not fall under the
exceptions in the third column, keep that specific table on Policy Tags for now
and migrate your other tables first:

<!-- mdformat off -->

| Tables to Hold Off Migrating | Why Hold Off for Now | Exceptions (Safe to Migrate Now) |
| :--- | :--- | :--- |
| **Tables replaced by full-table BigQuery Load Jobs** (or load jobs that attach tags through a schema file) | Full-table overwrite load jobs (`bq load --replace` / `WRITE_TRUNCATE` and SQL `LOAD DATA OVERWRITE`—including batch connectors using unpartitioned `WRITE_TRUNCATE` file loads such as Apache Spark `SaveMode.Overwrite`, Cloud Dataflow `FILE_LOADS`, Fivetran historical re-syncs, Airbyte `Full Refresh - Overwrite`, and unpartitioned BigQuery Data Transfer Service refreshes) replace the entire table schema and clear existing Data Governance Tags, whether the schema comes from Parquet, Avro, or ORC files, schema auto-detection, or a custom schema file. Load jobs also do not yet accept Data Governance Tags inside a custom schema file. | Appending rows (`WRITE_APPEND`), clearing table rows without replacing the schema (`WRITE_TRUNCATE_DATA`, or `TRUNCATE TABLE` followed by an append), updating a single partition (`table$YYYYMMDD`), overwriting an existing CSV or JSON table while reusing its existing schema (without `--schema` or `--autodetect`), standard SQL writes (`INSERT`, `MERGE`, `LOAD DATA INTO`), and the BigQuery Storage Write API. |
| **External tables (`table_type = EXTERNAL`), BigLake External Iceberg or Delta Lake tables, BigLake catalog (`<catalog>.<namespace>`) tables, BigQuery Metastore Iceberg tables, AWS Glue federated tables, and BigQuery Omni (`aws-*`, `azure-*`) tables** | `--phase swap` updates only standard BigQuery `TABLE` resources and skips non-`TABLE` resources (`EXTERNAL`, `VIEW`, `MATERIALIZED_VIEW`, and `SNAPSHOT`—including BigLake External tables over CSV, Parquet, Avro, ORC, JSON, Iceberg, or Delta Lake). In addition, BigQuery does not yet support Data Governance Tags on **BigLake External Iceberg**, **BigLake External Delta Lake**, **BigLake catalog (`<catalog>.<namespace>`)**, **BigQuery Metastore Iceberg**, or **AWS Glue federated** tables, and BigQuery prohibits attaching Data Governance Tags to **BigQuery Omni** cross-cloud tables (`aws-*` and `azure-*` locations); `--phase swap` aborts forward swaps on BigQuery Omni, BigLake catalog, and federated external catalog tables upfront with `ABORTED_SCHEMA_CORRUPTION`. If your workloads require external or cross-cloud table support, contact Google Cloud Support or your BigQuery account team. | Standard BigQuery native tables and **BigQuery Managed Iceberg** tables (BigLake Managed Tables, which have `table_type = TABLE`) in standard Google Cloud regions. |
| **Tables copied, cloned, or snapshotted (`bq cp`, `CREATE TABLE ... CLONE`, `CREATE SNAPSHOT TABLE`) across organizations, across regions, via Analytics Hub without Restricted Export, or across projects in Mode 2 (`--target-table-dp-project-ids`) when the destination project lacks V2 Data Policies** | Copying a DGT-tagged table across Google Cloud Organizations fails tag permission checks on the source organization's tag, and copying across regions fails when destination-region V2 Data Policies do not exist. Within the same organization and region, when V2 Data Policies are created per table project in **Mode 2** (`--target-table-dp-project-ids` in `--phase plan`) rather than in a central Organization governance project (**Mode 1**, `--target-default-dp-project-id`), copying, cloning, or snapshotting a table—or letting **Analytics Hub (BigQuery Sharing)** subscribers copy a shared table—into a destination project that lacks matching V2 Data Policies copies the Data Governance Tag while leaving the destination table **Fail-Open (Default Allow)** to readers in that destination project. | Same-region, same-organization copies, clones, and snapshots in **Mode 1** (`--target-default-dp-project-id` registered in Organization `default_data_policy_projects`), or in **Mode 2** when the destination project already contains matching V2 Data Policies in that region; Analytics Hub listings with **Restricted Export** turned on (disabling table copy); and querying tables directly with SQL (including `CREATE TABLE AS SELECT`). |
| **Full-rebuild tables (`CREATE OR REPLACE TABLE` or `WRITE_TRUNCATE` query jobs) with tagged nested `STRUCT` / `RECORD` subfields, tables using SQL `ALTER TABLE` to add or drop subfields inside a tagged `STRUCT`, or scripts replaying `INFORMATION_SCHEMA.TABLES.ddl`** | Pipelines that rebuild a table from scratch (`CREATE OR REPLACE TABLE` or `WRITE_TRUNCATE` query jobs across Dataform, dbt, SQLMesh, Scheduled Queries, Spark, Dataflow `BigQueryIO`, Looker Persistent Derived Tables, or Fivetran/Airbyte full-refresh) clear existing column tags unless tags are preserved (`preserveGovernanceControls: true`) or re-attached via post-build SQL `ALTER TABLE ... ALTER COLUMN <col> SET OPTIONS (data_governance_tags = [...])`. Current tag-preservation settings and `ALTER COLUMN` DDL support **top-level (flat)** columns only, not nested `STRUCT` / `RECORD` subfields; SQL `ALTER TABLE` adding or dropping subfields inside a `STRUCT` also clears existing Data Governance Tags on sibling subfields of that `STRUCT`; and `INFORMATION_SCHEMA.TABLES.ddl` omits Data Governance Tags. | **Incremental** pipelines (`INSERT`, `MERGE`, or `TRUNCATE TABLE` + `INSERT` with full-refresh disabled, such as `protected: true` / `disallowRefresh: true` in Dataform or `full_refresh: false` in dbt), full-rebuild tables whose tagged columns are **top-level (flat)** columns with tag preservation or `ALTER COLUMN` re-attachment, and schema evolution performed via BigQuery REST `tables.patch`. |
| **Legacy allowlisted tables with Policy Tags on non-leaf `RECORD` / `STRUCT` parent columns, columns carrying both Policy Tags and direct column-level Data Policies, or tables exceeding `1,000` unique tags** | BigQuery allows Data Governance Tags only on leaf columns (rejecting tags on parent `RECORD` / `STRUCT` containers), prohibits a column from holding both a Data Governance Tag and direct column-level `dataPolicies`, and limits each table to `1,000` unique Data Governance Tags via `tables.patch` (`1,000` total column tag bindings in SQL `CREATE TABLE` DDL). `--phase swap` aborts forward swaps on these schemas with `ABORTED_SCHEMA_CORRUPTION` before modifying BigQuery. | Tables after moving any parent `RECORD` / `STRUCT` Policy Tags down to leaf subfields, removing redundant direct column-level `dataPolicies` from Policy-Tag-governed columns, and keeping unique Data Governance Tags at or below `1,000` per table. |
| **Classification-only (non-access-controlled) tagged tables queried from BigQuery Standard Edition reservations, Continuous Queries, or Cross-Region Replica Materialized Views** | Even when a Data Governance Tag has zero attached V2 Data Policies (migrated from a Classification-Only taxonomy), BigQuery currently requires **Enterprise** or **Enterprise Plus** edition reservations (or on-demand billing) to query any table carrying a Data Governance Tag, and rejects **BigQuery Continuous Queries** and **Materialized Views over Cross-Region Replication secondary replicas** when referenced columns carry Data Governance Tags. | Workloads querying DGT-tagged tables under BigQuery **Enterprise** or **Enterprise Plus** reservations or on-demand billing, without Continuous Queries or secondary-replica Materialized Views on tagged columns. |

<!-- mdformat on -->

### 2. Project, IAM & Policy Prerequisites (Re-Architect or Hold Off Before Migrating)

Before running `--phase create` and `--phase swap`, verify that your Google
Cloud environment meets the platform prerequisites below (see
[Migration Tool & Platform Limitations](#migration-tool-platform-limitations)
for full details and remediation steps):

*   **Google Cloud Organization membership and standard project IDs:** Every
    tag, Data Policy, and BigQuery table project must belong to a Google Cloud
    Organization resource (standalone projects without an Organization cannot
    create or enforce Data Governance Tags), and legacy domain-scoped project
    IDs containing `:` (such as `example.com:my-project`) are not supported.
*   **Inherited ancestor IAM, Conditional IAM (CEL), and Privileged Access
    Manager (PAM) grants:** V2 Data Policies evaluate only their inline
    `grantees` list. Organization-, Folder-, and Project-level
    `Fine-Grained Reader` grants are not inherited, IAM Condition (CEL)
    expressions (such as time-bounded or attribute-based access) cannot be
    attached to inline `grantees`, and temporary Privileged Access Manager (PAM)
    entitlements granting roles on ancestor resources do not grant column access
    unless PAM grants temporary membership in a Google Group listed in
    `grantees`.
*   **Authorized Views, Authorized Datasets, Authorized Routines, and
    domain/public principals:** Unlike legacy Policy Tags, BigQuery V2 Data
    Policies on Data Governance Tags do **not** delegate column-level access
    through **Authorized Views** or **Authorized Datasets**—querying users
    receive `403 Access Denied` unless their own user or Google Group principal
    is listed directly in V2 Data Policy `grantees` (`DR_WARN_04`). In addition,
    V2 Data Policy `grantees` reject **BigQuery Authorized Routines**,
    `domain:...`, `allUsers`, and `allAuthenticatedUsers` (flagged with
    `[ACTION REQUIRED]` in `--phase plan`).
*   **Custom masking UDF residency, data types, and multi-routine conflicts:**
    Every custom masking routine (`data_masking_policy.routine`) must reside in
    the **exact same project** as each V2 Data Policy referencing it
    (`[ACTION REQUIRED]`) and cannot use the `GEOGRAPHY` data type. While
    multiple predefined masking rules resolve automatically by restrictiveness,
    if a user without unmasked (`RAW_DATA_ACCESS_POLICY`) access matches **two
    or more custom masking routine policies** at the same tag depth, BigQuery
    fails the query closed ("Found multiple conflicting data policies with
    custom masking expressions."); `--phase plan` flags overlapping custom
    masking grantees upfront.
*   **Cross-Region Replication (CRR) sequence and Mode 1 single-project limit:**
    Complete Phases 1–3 in your primary region **before** enabling Cross-Region
    Replication on datasets (if an existing secondary CRR replica already
    references a Data Governance Tag in a region, BigQuery blocks creating new
    V2 Data Policies for that tag in the primary region). In addition,
    Organization-level `default_data_policy_projects` (**Mode 1**,
    `--target-default-dp-project-id` in `--phase plan`) supports at most **`1`**
    central Data Policy project per region; if your Organization already uses
    that slot for another governance project, either place your V2 Data Policies
    in that shared central project or use **Mode 2**
    (`--target-table-dp-project-ids`, creating V2 Data Policies in each table's
    parent project).
*   **Service scale and quota limits:** Google Cloud enforces default limits of
    `1,000` total Tag Keys per `--target-dgt-project-id` project (shared across
    standard IAM Tag Keys and `DATA_GOVERNANCE` Tag Keys), `1,000` Tag Values
    per Tag Key, `1,000` V2 Data Policies per `(Project, Region, DG Tag Key)`,
    `500` distinct IAM principals and `100` distinct `principalSet://` group
    principals per V2 Data Policy (stricter than legacy IAM v1's
    `1,500`-principal limit on Policy Tags), and `1,000` unique Data Governance
    Tags per table via `tables.patch` (`1,000` total column tag bindings in SQL
    `CREATE TABLE` DDL). `--phase plan`, `--phase create`, and `--phase swap`
    check these limits before modifying cloud resources.

### 3. Operational & Tooling Differences with Simple Workarounds (Safe to Migrate Now)

The operational and tooling differences below apply to tables using Data
Governance Tags today, have straightforward workarounds, and do **not** block
you from migrating tables (see Safeguard #6 in the
[Phase 3 Swap & Rollback guide](phase_3_swap.md) for step-by-step configuration
snippets):

*   **Cloud Audit Logs for table reads, Sensitive Data Protection (Cloud DLP),
    Dataplex Universal Catalog, and third-party data catalogs:** When someone
    reads a table, BigQuery table-read (`DATA_READ`) audit logs record *which
    columns were read* (`tableDataRead.fields`), without listing Data Governance
    Tag names or masking details (audit logs for table creation and schema
    updates *do* include Data Governance Tags). Sensitive Data Protection (Cloud
    DLP) discovery profiles, Dataplex Universal Catalog column security
    propagation rules, and third-party data catalogs (such as Collibra, Atlan,
    or Alation) configured for legacy Policy Tags may also treat migrated
    columns as untagged or attempt to push legacy Policy Tags back onto migrated
    columns (failing with `400 Invalid Argument`). **Workaround:** Join
    read-audit or catalog queries with BigQuery's column metadata view
    (`INFORMATION_SCHEMA.COLUMN_FIELD_PATHS`), and pause or switch Dataplex
    Policy Tag propagation rules, automated DLP taggers, and external catalog
    sync jobs to read-only mode before running `--phase swap`.
*   **Google Cloud Console "Preview" tab:** Opening the **Preview** tab on a
    table in the Google Cloud Console returns `403 Access Denied` unless the
    viewer has *unmasked* access to every tagged column on that table (including
    viewers who have masked access or access to only a subset of columns).
    **Workaround:** Preview rows by running a `SELECT` query in the BigQuery
    Studio editor, where column permissions and data masking work normally.
*   **Terraform, Config Connector, and viewing tags in the `bq` CLI:**
    Infrastructure-as-Code (IaC) tools (such as Terraform, Pulumi, and Config
    Connector) track column tags inside the table schema, and the Terraform Data
    Policy resource does not yet support Data Governance Tag bindings. In
    addition, the default text output of `bq show` and
    `INFORMATION_SCHEMA.TABLES.ddl` do not display Data Governance Tags.
    **Workaround:** Create V2 Data Policies with the migration tool
    (`--phase create`), update your IaC table schemas (replacing `"policyTags"`
    with `"dataGovernanceTagsInfo"`) in the same maintenance window as
    `--phase swap` (pausing continuous sync first if using Config Connector),
    and pass `--format=prettyjson` (or query
    `INFORMATION_SCHEMA.COLUMN_FIELD_PATHS`) when viewing column tags.
*   **Coordinating Dataform, dbt, SQLMesh, and scheduled SQL pipelines:**
    BigQuery does not allow a column to hold both a Policy Tag and a Data
    Governance Tag at the same time (`400 Invalid Argument`), and scheduled
    full-table rebuilds (`CREATE OR REPLACE TABLE`) replace the table schema on
    every run. **Workaround:** Pause scheduled pipeline runs during
    `--phase swap` and update your pipeline definitions in Git during the same
    maintenance window—removing legacy Policy Tag settings from incremental
    models (with full-refresh disabled) and, for flat full-rebuild tables,
    either enabling automatic governance tag preservation
    (`preserveGovernanceControls: true` in Dataform) or adding post-build SQL
    `ALTER COLUMN` re-attachment steps. **`ALTER COLUMN` re-attachment** means
    running `ALTER TABLE <project>.<dataset>.<table> ALTER COLUMN <column> SET
    OPTIONS (data_governance_tags = [('<tag_project>/<tag_key>',
    '<tag_value>')])` immediately after `CREATE OR REPLACE TABLE` finishes
    rebuilding the table (for example, inside Dataform `post_operations`, a dbt
    `post-hook`, or SQLMesh `post_statements`; see Safeguard #6 in the
    [Phase 3 Swap & Rollback guide](phase_3_swap.md)) so Data Governance Tags
    are re-bound to each protected column right after the table is recreated. If
    you later roll a table back to Policy Tags (`--swap-mode dgt-to-pt`), revert
    your pipeline or IaC definition in the same maintenance window so the next
    run keeps your restored Policy Tags.
*   **Post-swap Time Travel (`FOR SYSTEM_TIME AS OF`) dual evaluation and
    `table@<timestamp>` snapshot restores:** During the 2–7 day Time Travel
    window immediately after `--phase swap`, querying a pre-swap timestamp via
    `FOR SYSTEM_TIME AS OF` evaluates **both** the historical snapshot's Policy
    Tag and the live table's Data Governance Tag, and restoring a pre-swap
    point-in-time snapshot via `bq cp dataset.table@<pre_swap_ms> dataset.table`
    restores the historical Policy Tag schema. **Workaround:** Retain your
    source Policy Tag taxonomies, Policy Tags, and V1 Data Policies until the
    full Time Travel window has elapsed, and re-run `--phase swap` if you
    overwrite a migrated table from a pre-swap `@<timestamp>` decorator.

### Reporting Blockers & Unlisted Feature Gaps

If you are blocked from migrating specific tables or projects to Data Governance
Tags by any of the items in Section 1 or Section 2, or if you identify a
difference in behavior between Policy Tags and Data Governance Tags not
documented here:

1.  **Keep the affected tables on Policy Tags for now** (while migrating your
    other unaffected tables).
2.  **Contact Google Cloud Support or your BigQuery account team.** Report the
    issue, including details about your pipeline configuration and the specific
    Policy Tag capabilities your production environment relies on.

## Overview

BigQuery is moving from regional Policy Tags (PT) to global Data Governance Tags
(DGT) for Column Level Security (CLS) (see the official Google Cloud
documentation on
[Data Governance Tags and Data Policies](https://cloud.google.com/bigquery/docs/tags#data-governance-tags)).
This tool helps automate the migration process by analyzing your existing Policy
Tag setup, helping you plan the migration to the new DGT resource model,
creating the necessary DGT resources (Tag Keys, Tag Values, V2 Data Policies),
and attaching the new DGTs to BigQuery table columns while protecting you from
subtle behavioral differences between Policy Tags and Data Governance Tags.

This tool operates in **3 logical phases** (see the detailed per-phase guides:
[Phase 1a Analyze guide](phase_1a_analyze.md),
[Phase 1b Plan guide](phase_1b_plan.md),
[Phase 2a Create guide](phase_2a_create.md),
[Phase 2b Delete guide](phase_2b_delete.md), and
[Phase 3 Swap and Rollback guide](phase_3_swap.md)):

1.  **Phase 1a: Analyze (`--phase analyze`):** Inspects your existing Policy Tag
    taxonomies, Data Governance Tags, V1 and V2 Data Policies, IAM reader
    bindings, and BigQuery table column bindings across specified Google Cloud
    projects and regions, and generates a structured Markdown (`.md`) analysis
    report (detailed in the [Phase 1a Analyze guide](phase_1a_analyze.md)).
    Supports three analysis modes:
    *   **Static Taxonomy & Policy Analysis (`static-taxonomy`):** Scans Policy
        Tag taxonomies (identifying whether each taxonomy is Classification-Only
        or Access-Controlled), policy tags, IAM policies
        (`roles/datacatalog.categoryFineGrainedReader` and custom roles), and
        BigQuery Data Policies (V1), and produces a detailed inventory and
        security posture report.
    *   **Static Data Governance Tag Analysis (`static-dgt`):** Scans existing
        Data Governance Tag Keys, Tag Values (including hierarchical nesting),
        and attached or unattached BigQuery Data Policies (V2), and produces a
        comprehensive DGT and V2 Data Policy inventory report.
    *   **Column Binding Analysis (`column-binding`):** Scans
        `INFORMATION_SCHEMA.COLUMN_FIELD_PATHS` across all three Column-Level
        Security (CLS) mechanisms—legacy Policy Tags, IAM Data Governance Tags,
        and Direct Data Policies on Columns—and produces a summary and
        per-tag/per-policy column binding report (useful both before migration
        to discover governed tables and during/after migration to track which
        tables use Policy Tags vs. Data Governance Tags).
2.  **Phase 1b: Plan (`--phase plan`):** Generates a comprehensive migration
    plan based on the static analysis of your existing Policy Tag taxonomy and
    V1 Data Policy setup (detailed in the
    [Phase 1b Plan guide](phase_1b_plan.md)).
    *   **Resource Mapping:** Proposes a structured mapping of legacy Policy Tag
        entities to new Data Governance Tag entities:
        *   **Taxonomies** map to **Tag Keys**.
        *   **Policy Tags** map to **Tag Values** (preserving hierarchical
            nesting).
        *   **V1 Data Policies** map to **V2 Data Policies**.
    *   **Classification-Only vs. Access Control Taxonomies:** In legacy Policy
        Tags, each taxonomy operates in one of two security postures:
        *   **Classification-Only Taxonomy:** The taxonomy's
            `Enforce access control` setting (`FINE_GRAINED_ACCESS_CONTROL`) is
            **disabled** in Data Catalog **and** no V1 Data Policies are
            attached to any of its Policy Tags. BigQuery treats tags in a
            Classification-Only taxonomy strictly as descriptive metadata
            (**Default Allow / Fail-Open**): any user with table-level read
            access can query the tagged columns, and any
            `roles/datacatalog.categoryFineGrainedReader` IAM bindings on those
            Policy Tags are ignored by BigQuery.
        *   **Access Control Taxonomy:** Either the taxonomy's
            `Enforce access control` setting (`FINE_GRAINED_ACCESS_CONTROL`) is
            **enabled** in Data Catalog, **or** at least one V1 Data Policy
            (masking or raw access) is attached to a Policy Tag in the taxonomy.
            BigQuery enforces Column-Level Security on every Policy Tag in an
            Access Control taxonomy (**Default Deny / Fail-Closed**): users
            without explicit fine-grained reader or masking permissions are
            denied access to the tagged columns.
    *   **Behavior Parity (Synthetic Policies):** To maintain exact security
        posture, the plan proposes "Synthetic" V2 Data Policies for Access
        Control taxonomies. These are categorized into two distinct sections in
        the plan manifest and the report:
        *   **Raw Reader Parity
            (`policy_tags_to_raw_reader_data_policies_v2`):** In legacy Policy
            Tags, raw data access is granted via the
            `roles/datacatalog.categoryFineGrainedReader` role assigned directly
            on Policy Tags (or on the parent Taxonomy). Because Data Governance
            Tags (DGT) do not use tag-level IAM roles to govern column data
            access, the migration planner synthesizes an explicit V2 Data Policy
            of type `RAW_DATA_ACCESS_POLICY` bound to the corresponding DG Tag
            Value for each Policy Tag with existing fine-grained readers. For
            taxonomy-level `fineGrainedReader` grants, the planner places them
            on the **Root Tag Value(s)** (so unmasked child Tag Values inherit
            access via `column.matchTagHierarchy`) **and** copies them onto any
            non-root Tag Value that carries a direct `DATA_MASKING_POLICY`.
            *Why:* In Policy Tags, taxonomy IAM grants unmasked read directly at
            the leaf tag (`RAW` wins over child masking), whereas in DGT V2,
            BigQuery evaluates policies at the deepest matching tag first
            (`MASKED` on a child tag would beat a root-only `RAW` policy for a
            principal in both groups unless the taxonomy reader is also present
            on the masked child tag).
        *   **Default Deny Parity
            (`policy_tags_to_default_deny_data_policies_v2`):** In legacy Policy
            Tags, Access Control taxonomies enforce a strict Fail-Closed
            (Default Deny) posture: attaching a tag automatically locks down the
            column so users without explicit permissions are denied access. In
            contrast, DGT is Fail-Open (Default Allow) by design if a tag is
            attached to a column without an associated Data Policy. Therefore,
            in an access-controlled taxonomy, **every** Tag Value receives a
            permanent `_default_deny` `RAW_DATA_ACCESS_POLICY` (`grantees: []`)
            as a fail-closed safety net—preventing columns from failing open if
            an explicit reader or masking policy is later deleted.
    *   **Important Callouts & Customer Awareness:**
        *   **Name Sanitization:** Spaces in source Taxonomy display names and
            Policy Tag display names (which are allowed in Data Catalog display
            names but invalid in Resource Manager DG Tag Key and Tag Value short
            names) are automatically replaced with underscores (`_`). Other
            invalid characters or length violations (`> 63` characters) generate
            `[ACTION REQUIRED]` warnings and **must be resolved manually before
            proceeding**.
        *   **Case Sensitivity:** GCP Tag Values are case-sensitive. Collisions
            are resolved case-sensitively, but users should beware of confusion
            if names differ only by case.
        *   **Dangling Bindings in Classification-Only Taxonomies:** Flags
            Policy Tags that have `roles/datacatalog.categoryFineGrainedReader`
            IAM bindings attached inside a *Classification-Only* taxonomy (where
            `Enforce access control` is disabled and no V1 Data Policies exist).
            Because BigQuery currently ignores IAM bindings on
            Classification-Only taxonomies and allows all table readers to query
            those columns (Default Allow), the planner does **not** synthesize
            restrictive V2 Data Policies for these tags (which would
            unexpectedly lock down the columns and break existing queries) and
            instead emits a warning in the plan report so you can review the
            ignored IAM bindings.
        *   **Default Deny Logic (Union / `OR` Evaluation Across Policies):** In
            Data Policy V2, each policy grants access to its listed `grantees`;
            synthetic `_default_deny` policies (`grantees: []`) do **not** act
            as strict Deny overrides if another V2 Data Policy bound to the same
            tag (or an ancestor tag) grants access, because BigQuery evaluates
            multiple policies of the same type using union (`OR`) logic. *Quick
            example:* Suppose column `ssn` is tagged with `PII/SSN`, which has
            both (1) `migrated_raw_pii_ssn_default_deny` (`grantees: []`) and
            (2) `migrated_raw_pii_ssn`
            (`grantees: ["group:analysts@example.com"]`). Because
            `[] OR ["group:analysts@example.com"]` evaluates to
            `["group:analysts@example.com"]`, members of `analysts@example.com`
            are granted raw access while all other users receive `Access Denied`
            (rather than failing open).
        *   **Regional Taxonomy Separation:** Cross-region consolidation of
            multiple regional taxonomies into a single shared DG Tag Key is not
            supported yet. Instead, each regional Policy Tag taxonomy is mapped
            1:1 to a distinct global DG Tag Key (recording the source region in
            the Tag Key's `description`). If multiple regional taxonomies share
            the same display name, their short names are disambiguated using
            `--collision-resolution` (`counter` `-1`, `-2` by default, or
            `from_region` `_from_<region>`). If your organization has a use case
            that requires consolidating multiple regional taxonomies into a
            single shared DG Tag Key, please share feedback with the BigQuery
            team.
        *   **Disaster Recovery (DR) & Cross-Region Replication (CRR)
            Readiness:** Proactively checks the generated plan for DR/CRR
            readiness (`DR_WARN_01` through `DR_WARN_04`), including
            multi-region V2 Data Policy conflicts, policy lookup placement
            between **Mode 1** (creating V2 Data Policies in a single
            centralized governance project via `--target-default-dp-project-id`
            registered in your Organization's `default_data_policy_projects`
            setting) and **Mode 2** (creating V2 Data Policies directly in each
            BigQuery project that owns the governed tables via
            `--target-table-dp-project-ids`), non-delegation of column access
            through Authorized Views or Authorized Datasets (`DR_WARN_04`), and
            prerequisites for replicating datasets containing custom masking
            routines before enabling CRR.
    *   **Safety Net:** The plan includes a `phase_3_binding_map` serving as a
        critical rollback manifest to restore original bindings if needed.
3.  **Phase 2: Create & Delete (`--phase create` and `--phase delete`):**
    Creates Data Governance Tag Keys, Tag Values, and Data Policies based on the
    migration plan, and supports individual resource deletion for non-production
    sandbox cleanup (detailed in the [Phase 2a Create guide](phase_2a_create.md)
    and [Phase 2b Delete guide](phase_2b_delete.md)).
    *   This phase focuses solely on the creation (or non-production cleanup) of
        standalone Data Governance Tag Keys, Tag Values, and V2 Data Policies;
        it **does not yet impact BigQuery Column-Level Security enforcement or
        running queries because the Data Governance Tags are not attached to any
        BigQuery table columns until Phase 3 (`--phase swap`)**.
    *   **Supports `--dry-run`:** Previews which resources would be created vs.
        skipped (because they already exist in Google Cloud) or deleted vs.
        blocked, and surfaces any validation warnings, quota issues, or missing
        parent dependencies without mutating any resources. **We strongly
        recommend running `--phase create --dry-run` (and
        `--phase delete --dry-run`) before executing actual mutations.**
4.  **Phase 3: Swap & Rollback (`--phase swap`):** Atomically swaps Policy Tags
    and Data Governance Tags in BigQuery table schemas (`tables.patch`) across
    two modes controlled by `--swap-mode` (detailed in the
    [Phase 3 Swap and Rollback guide](phase_3_swap.md)):
    *   **Mode 1 (`--swap-mode pt-to-dgt`, default - Forward Migration):**
        Atomically clears mapped Policy Tags (by setting
        `"policyTags": {"names": []}` in the table schema) and attaches mapped
        Data Governance Tags (by setting `"dataGovernanceTagsInfo"` in the table
        schema) across top-level columns and nested `RECORD` / `STRUCT` fields.
    *   **Mode 2 (`--swap-mode dgt-to-pt` - Automated Rollback to Policy
        Tags):** Atomically clears mapped Data Governance Tags (by setting
        `"dataGovernanceTagsInfo": {"dataGovernanceTags": {}}` in the table
        schema) and restores the original Policy Tags (by setting
        `"policyTags": {"names": ["<source_policy_tag>"]}` in the table schema)
        based on `phase_3_binding_map` in the migration plan. Use Mode 2 to
        quickly and automatically revert tables back to Policy Tag enforcement
        if an issue is identified after performing a Mode 1 swap.
    *   **Supports `--dry-run`:** Runs full table discovery, schema
        transformation, anti-corruption integrity verification, unified schema
        diff generation, and (in Mode 1 `pt-to-dgt`) live Google Cloud
        enforcement parity checks in either mode (`pt-to-dgt` or `dgt-to-pt`)
        without modifying any BigQuery table schemas or writing local backup
        files. **We strongly recommend running `--phase swap --dry-run` first to
        inspect the proposed schema diffs and resolve any enforcement parity
        discrepancies before modifying production tables.**

### Migration Rollout Stages & Future Works (Coexistence Timeline)

The migration tool is delivered in two evolutionary stages corresponding to
BigQuery backend Column-Level Security capabilities:

*   **Stage 1 (Current Release — Atomic Swap & Rollback via `--phase swap`):**
    `--phase swap` is the short-term solution designed for small-scale
    migrations and early adopters (such as Disaster Recovery migrations):
    *   **No Column-Level Coexistence Yet:** In Stage 1, BigQuery does not yet
        support attaching both a Policy Tag and a Data Governance Tag to the
        same column simultaneously; each column has either a Policy Tag or a
        Data Governance Tag (never both).
    *   **Shared Safety Pipeline Across Forward Swap (`pt-to-dgt`) and Rollback
        (`dgt-to-pt`):** Both modes execute a multi-step safety pipeline:
        *   **Pre-Swap Live Enforcement Parity Verification (Mode 1
            `pt-to-dgt`):** Verifies in live Google Cloud that every target DG
            Tag Key, Tag Value, and V2 Data Policy (including `_default_deny`
            policies and grantees) matches the source Policy Tag security
            posture before modifying the table (skipped automatically in Mode 2
            `dgt-to-pt` rollback so a deleted or misconfigured V2 Data Policy
            never blocks emergency rollback).
        *   **Recursive Schema Anti-Corruption Check:** Verifies that only the
            mapped `policyTags` and `dataGovernanceTagsInfo` attributes on
            in-scope columns change, aborting immediately if any unrelated field
            name, type, mode, description, or unmapped tag would be altered.
        *   **Automatic Restore-Ready Pre-Update Schema Backups & Post-Patch Tag
            Verification:** Saves a restore-ready pre-update table schema JSON
            under mode/project/dataset subdirectories in `--backup-dir` before
            patching
            (`<backup_dir>/pt_to_dgt/<project_id>/<dataset_id>/<table_id>.json`
            in Mode 1 with
            `"dataGovernanceTagsInfo": {"dataGovernanceTags": {}}` on swapped
            leaf columns, and
            `<backup_dir>/dgt_to_pt/<project_id>/<dataset_id>/<table_id>.json`
            in Mode 2 with `"policyTags": {"names": []}` on swapped leaf columns
            so `bq update` clears newly attached tags cleanly, rolling back
            never overwrites your original pre-migration backup, and names
            containing `__` never collide), and verifies the returned table
            schema after `tables.patch` (automatically restoring original column
            tags and reporting `FAILED` if BigQuery silently drops target tags).
        *   **Pre-Swap `README.md` Acknowledgment, Unified Schema Diff &
            Interactive Confirmation:** Prompts the operator to confirm they
            have thoroughly read and understood `README.md` (which discusses
            feature gaps between PT and DGT, limitations with the migration tool
            and platform, and how to perform a safe migration and avoid pitfalls
            so as not to cause security violations or production outages), logs
            the full unified schema diff, and prompts for human confirmation
            (`y/n`) before patching each table unless `--skip-confirmation` is
            specified.
*   **Stage 2 (Planned Future Work — Dual-Binding & Coexistence via
    `--phase bind`):** In a future release, BigQuery plans to support Policy Tag
    and Data Governance Tag coexistence on the same column:
    *   **Dual-Binding (`--phase bind`):** A new `bind` phase will attach
        migrated Data Governance Tags to BigQuery columns that already have
        Policy Tags without removing the existing Policy Tags, resulting in both
        PT and DGT coexisting on the same column (dual-binding). When a column
        is dual-bound, the Policy Tag (PT) remains the effective (enforced) tag
        by default while the Data Governance Tag (DGT) acts as the shadow (not
        enforced) tag until enforcement is explicitly switched.
    *   **Zero-Schema-Rewrite Enforcement Switching:** Once columns are
        dual-bound, customers will be able to audit parity and toggle active
        enforcement between Policy Tags and Data Governance Tags (and back for
        instant rollback) via project-level configuration settings without
        rewriting table schemas.

## Prerequisites

1.  Python 3.9+ installed.
2.  Google Cloud SDK (`gcloud`) installed and authenticated:

    *   Run `gcloud auth login`
    *   **Crucial:** Configure both your default `gcloud` project and your
        Application Default Credentials (ADC) quota project. When you run the
        migration script, Google Cloud checks API enablement and bills quota
        against your ADC quota project; if the project is not configured (or is
        set to an unrelated project where the Cloud Resource Manager, Data
        Catalog, IAM, or BigQuery Data Policy APIs are disabled), running the
        script can fail with `403 SERVICE_DISABLED` errors:

        ```bash
        gcloud config set project <YOUR_PROJECT_ID>
        gcloud auth application-default set-quota-project <YOUR_PROJECT_ID>
        ```

3.  Required Python libraries installed. We recommend using a virtual
    environment:

    ```bash
    python3 -m venv .venv
    source .venv/bin/activate
    pip install -r requirements.txt
    ```

4.  The user or service account running the script needs sufficient IAM
    permissions in the target project(s).

### Analyze & Plan Phases Prerequisites

For the `analyze` and `plan` phases, the following roles and permissions are
required:

*   **Source Taxonomy Project (`--taxonomy-project-id`, and any Custom Masking
    Routine Project):**
    *   Data Catalog Viewer (`roles/datacatalog.viewer`) - To list taxonomies
        and policy tags.
    *   Data Catalog Category Admin (`roles/datacatalog.categoryAdmin`) - To
        read taxonomy and policy tag IAM policies
        (`datacatalog.taxonomies.getIamPolicy`,
        `datacatalog.policyTags.getIamPolicy`).
    *   BigQuery DataPolicy Viewer (`roles/bigquerydatapolicy.viewer`) - To list
        V1 Data Policies.
    *   BigQuery DataPolicy Admin (`roles/bigquerydatapolicy.admin`) - To read
        V1 Data Policy IAM policies (`bigquery.dataPolicies.getIamPolicy`).
    *   IAM Role Viewer (`roles/iam.roleViewer`) - To inspect custom roles.
    *   Project Metadata Viewer (`resourcemanager.projects.get`, included in
        `roles/viewer` or `roles/browser`) - Required on the Source Project (and
        any project hosting a custom masking routine) to resolve numeric project
        numbers into project IDs.
*   **DGT & Data Policy Projects (for `--analyze-type static-dgt`):**
    *   Resource Manager Tag Viewer (`roles/resourcemanager.tagViewer`) on the
        DGT Project (`--dgt-project-id`) - To list Tag Keys and Tag Values.
    *   BigQuery DataPolicy Viewer (`roles/bigquerydatapolicy.viewer`) and
        `bigquery.dataPolicies.getIamPolicy` (`roles/bigquerydatapolicy.admin`)
        on each Data Policy Project (`--data-policy-v2-project-ids`) - To list
        V2 Data Policies and inspect their grantees.
*   **Data Project (`--table-project-id`, for `column-binding`):**
    *   BigQuery Job User (`roles/bigquery.jobUser`) - To run queries (or on
        `--execution-project` when billing/job execution uses a separate
        project).
    *   BigQuery Metadata Viewer (`roles/bigquery.metadataViewer`) - To inspect
        table metadata via `INFORMATION_SCHEMA`.

### Create & Delete Phases Prerequisites

For the `create` and `delete` phases, the following roles are required:

*   **Target DGT Project (`--target-dgt-project-id`):**
    *   Tag Administrator (`roles/resourcemanager.tagAdmin`) - To create or
        delete Tag Keys and Tag Values (`resourcemanager.tagKeys.create`,
        `resourcemanager.tagValues.create`, `resourcemanager.tagKeys.delete`,
        `resourcemanager.tagValues.delete`).
    *   Tag User (`roles/resourcemanager.tagUser`) - Required to associate V2
        Data Policies with Data Governance Tag Values during `--phase create`.
*   **Target Data Policy Project(s) (`--target-default-dp-project-id` when V2
    Data Policies are created in a centralized default project via
    `--phase plan` Mode 1, or each table parent project in
    `--target-table-dp-project-ids` via `--phase plan` Mode 2):**
    *   BigQuery DataPolicy Admin (`roles/bigquerydatapolicy.admin`) - To create
        or delete V2 Data Policies (`bigquery.dataPolicies.create`,
        `bigquery.dataPolicies.setIamPolicy`, `bigquery.dataPolicies.delete`).

### Swap Phase Prerequisites

For the `swap` phase (`--swap-mode pt-to-dgt` forward migration or
`--swap-mode dgt-to-pt` rollback), the following roles are required:

*   **Data Project(s) / Dataset(s) / Table(s):**
    *   BigQuery Data Owner (`roles/bigquery.dataOwner`) or custom role with
        `bigquery.tables.get`, `bigquery.tables.list`, `bigquery.datasets.get`,
        `bigquery.tables.update`, and `bigquery.tables.setCategory` - To inspect
        and patch table schemas (`roles/bigquery.dataEditor` does not include
        `bigquery.tables.setCategory`).
    *   BigQuery Job User (`roles/bigquery.jobUser`, on the data project or on
        `--execution-project`) and `bigquery.config.get` (included in
        `roles/bigquery.admin`, or pass `--skip-default-dp-org-check` if
        manually verified) - Used for `INFORMATION_SCHEMA` table pre-filtering
        and (in `pt-to-dgt`) querying
        `INFORMATION_SCHEMA.EFFECTIVE_PROJECT_OPTIONS` to inspect Organization
        `default_data_policy_projects` registration and companion projects.
*   **Source Taxonomy Project:**
    *   Project Metadata Viewer (`resourcemanager.projects.get`, included in
        `roles/viewer` or `roles/browser`) - Required only when BigQuery table
        schemas store numeric project numbers in legacy Policy Tag resource
        paths so the swapper can normalize them against `plan.json`.
    *   Data Catalog Viewer (`roles/datacatalog.viewer`) - Required by BigQuery
        during `tables.patch` when detaching (`pt-to-dgt`) or re-attaching
        (`dgt-to-pt`) legacy Policy Tags on table columns.
    *   **Note:** Mode 1 (`pt-to-dgt`) pre-swap parity verification compares
        live target Data Governance Tags and V2 Data Policies against the static
        `plan.json` snapshot and does not re-query source Data Catalog or V1
        Data Policy IAM APIs.
*   **Target DGT Project:**
    *   Resource Manager Tag Viewer (`roles/resourcemanager.tagViewer`) - To
        verify live Data Governance Tag Keys and Tag Values before swapping
        (Mode 1).
    *   Resource Manager Tag User (`roles/resourcemanager.tagUser`) - To bind or
        unbind Data Governance Tag Values on BigQuery table columns.
*   **Target Data Policy Project(s) (plus Table Project in Mode 1 and
    Organization Default Projects):**
    *   BigQuery DataPolicy Viewer (`roles/bigquerydatapolicy.viewer`) and
        `bigquery.dataPolicies.get` (or `roles/bigquerydatapolicy.admin`) - To
        verify live V2 Data Policy enforcement parity and grantees before
        swapping across planned Data Policy projects, the table's parent project
        (in `--phase plan` Mode 1), and any Organization
        `default_data_policy_projects` companion projects.

## Usage

Activate the virtual environment and run the `main.py` script, specifying the
phase and required options.

```bash
source .venv/bin/activate
python main.py --version
python main.py --phase <PHASE> [options]
```

For version history and release notes, see [Changelog](CHANGELOG.md). For
detailed phase-by-phase instructions, examples, and operational guidance, refer
to:

*   **Phase 1a (`analyze`):** [Phase 1a Analyze guide](phase_1a_analyze.md)
*   **Phase 1b (`plan`):** [Phase 1b Plan guide](phase_1b_plan.md)
*   **Phase 2a (`create`):** [Phase 2a Create guide](phase_2a_create.md)
*   **Phase 2b (`delete`):** [Phase 2b Delete guide](phase_2b_delete.md)
*   **Phase 3 (`swap`):** [Phase 3 Swap and Rollback guide](phase_3_swap.md)

### Strongly Recommended: Preview Changes with Dry-Run Mode (`--dry-run`)

**Recommended Best Practice:** Always run `--dry-run` before executing any
non-read-only phase (`--phase create`, `--phase swap`, or `--phase delete`).

In dry-run mode, **no mutations or writes are performed** in Google Cloud (and
no local schema backup files are written during `swap` dry-run). Instead, the
tool runs live read-only pre-flight checks against your Google Cloud environment
and generates a comprehensive report detailing:

1.  **What changes would be made:**
    *   **`--phase create --dry-run`:** Lists which Data Governance Tag Keys,
        Tag Values, and V2 Data Policies (Raw Reader Parity, Default Deny
        Parity, and Migrated V1 Data Policies) would be created versus skipped
        because they already exist in Google Cloud.
    *   **`--phase swap --dry-run`:** Lists every table and column (including
        nested `RECORD` / `STRUCT` fields) that is ready to swap, along with the
        full unified schema diff and rollback command for each table.
    *   **`--phase delete --dry-run`:** Performs a client-side check reporting
        whether the target resource exists in Google Cloud and would be deleted,
        skipped because the resource was not found, or blocked because live
        child Tag Values (`tagValues.list`) or live referencing V2 Data Policies
        defined in `plan.json` still exist (note: global tag attachments to
        BigQuery columns or out-of-plan V2 Data Policies in other projects are
        enforced server-side by Cloud Resource Manager during live deletion).
2.  **Potential issues, warnings, and pre-flight blockers:**
    *   **`--phase create --dry-run`:** Fails closed upfront
        (`BLOCKED_UNRESOLVED_PLAN_WARNINGS`) if `plan.json` still contains
        unresolved `[ACTION REQUIRED]` warnings (unless overridden via
        `--allow-unresolved-plan-warnings`), surfaces Disaster Recovery /
        Cross-Region Replication warnings (`DR_WARN_01` through `DR_WARN_04`),
        action-level and project/key-level validation issues (invalid short
        names or policy IDs, Authorized Routine or unsupported grantees, or
        exceeding the `1,000` Tag Keys per project, `1,000` Tag Values per Tag
        Key, `1,000` Data Policies per Tag Key, or `500` IAM principals / `100`
        groups per V2 Data Policy limits), missing parent Tag Keys/Values (when
        testing individual resource creation), and API permission errors.
    *   **`--phase swap --dry-run`:** Fails closed upfront in forward
        `pt-to-dgt` mode if `plan.json` contains unresolved `[ACTION REQUIRED]`
        warnings (unless `--allow-unresolved-plan-warnings` is set), and runs
        full pre-swap live enforcement parity verification
        (`ACCESS_LEAKAGE_RISK`, `ACCESS_BLOCKAGE_RISK`, and
        `RESOURCE_DISCREPANCY`), recursive schema anti-corruption verification,
        and unmapped Policy Tag detection so you can remediate any missing DGT
        resources or policy discrepancies before touching production tables.
    *   **`--phase delete --dry-run`:** Checks live Google Cloud state for child
        Tag Values that would block deletion, active V2 Data Policies from
        `plan.json` still referencing the Tag Key or Tag Value, active column
        binding reminders, and Fail-Open security warnings when deleting a
        `_default_deny` Data Policy.

### Multi-Value Flag Separator Convention (Space or Comma Separated)

Every CLI flag that accepts one or multiple values (`--regions`,
`--data-policy-v2-project-ids`, `--target-table-dp-project-ids`,
`--table-project-ids`, `--dataset-ids`, and `--table-ids`) supports **both
space-separated and comma-separated values** (or a combination of both). For
example, the following two invocations are equivalent:

```bash
# Space-separated values
--dataset-ids data-project-2.finance_ds data-project-2.hr_ds

# Comma-separated values
--dataset-ids data-project-2.finance_ds,data-project-2.hr_ds
```

### Multi-Phase CLI Flags Reference

Several CLI flags are used across multiple phases. The table below summarizes
what each shared flag means in each phase, what values it accepts, and its
default value or behavior:

<!-- mdformat off -->

| Flag | Accepted Values & Default | `analyze` Phase | `plan` Phase | `create` Phase | `swap` Phase | `delete` Phase |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| `--version` | Standalone flag (no value) | Prints the migration tool SemVer version (for example, `main.py 1.0.0`) and exits immediately without requiring `--phase` or Google Cloud credentials. | Same across all phases. | Same across all phases. | Same across all phases. | Same across all phases. |
| `--phase` | `analyze`, `plan`, `create`, `swap`, `delete` (**Required for all phases**, no default) | Runs read-only discovery (`--analyze-type`) and generates a Markdown (`.md`) report. | Generates the JSON migration plan and Markdown summary report. | Creates DG Tag Keys, Tag Values, and V2 Data Policies in Google Cloud. | Atomically swaps mapped Policy Tags and DG Tags on BigQuery table schemas. | Deletes a single resource in Google Cloud (verified against `--plan-file`). |
| `--taxonomy-project-id` | Single GCP project ID string (Default: `None`) | **Required (`static-taxonomy`):** Source Policy Tag taxonomy project ID to scan (for `static-dgt`, use `--dgt-project-id` and `--data-policy-v2-project-ids`; for `column-binding`, use `--table-project-id`). | **Required:** Source Policy Tag taxonomy project ID to migrate from. | Not used (source metadata is read from `--plan-file`). | Not used (tables to swap are specified via `--table-project-ids`, `--dataset-ids`, or `--table-ids`). | Not used (resource metadata is read from `--plan-file`). |
| `--regions` | One or more regions, space or comma separated (Default: `None`) | **Required:** Regions to scan for taxonomies, V2 Data Policies, or `INFORMATION_SCHEMA`. | **Required:** Regions to scan for source Policy Tag taxonomies and V1 Data Policies. | Not used (target regions are read from `--plan-file` actions). | **Required:** Restricts table discovery (`INFORMATION_SCHEMA` pre-filtering) and schema swapping strictly to datasets and tables in the specified region(s) (see note below). | Not used (resource locations are read from `--plan-file`). |
| `--dry-run` | Boolean flag (Default: `False`, executes live) | Not used (phase is already read-only). | Not used (phase is already read-only). | **Optional:** Previews resources to create vs. skip and validation issues without mutating cloud state. | **Optional:** Previews schema diffs and live enforcement parity checks without modifying tables or writing backups. | **Optional:** Previews whether the resource exists and checks dependencies without deleting it. |
| `--plan-file` | Path to `.json` file (Default: `None`) | Not used. | **Optional Output:** Saves the JSON migration plan (prints to `stdout` if omitted). | **Required Input:** Path to the JSON migration plan to execute. | **Required Input:** Path to the JSON migration plan containing the binding map and manifest. | **Required Input:** Path to the JSON migration plan used to look up the resource. |
| `--report-file` | Path to `.md` file (Default: `None`, prints to `stdout`) | **Optional Output (`.md`):** Saves the Markdown analysis report (prints to `stdout` if omitted). | **Optional Output (`.md`):** Saves the Markdown plan summary report (prints to `stdout` if omitted). | **Optional Output (`.md`):** Saves the Markdown creation report (prints to `stdout` if omitted). | **Optional Output (`.md`):** Saves the Markdown swap and schema diff report (prints to `stdout` if omitted). | **Optional Output (`.md`):** Saves the Markdown deletion and dependency report (prints to `stdout` if omitted). |
| `--log-file` | Path to `.log` file (Default: `None`, logs to console only) | **Optional Output:** Saves timestamped diagnostic execution logs to the specified file. | **Optional Output:** Saves timestamped diagnostic execution logs to the specified file. | **Optional Output:** Saves timestamped diagnostic execution logs to the specified file. | **Optional Output:** Saves timestamped execution logs (including full schema diffs and parity details). | **Optional Output:** Saves timestamped diagnostic execution logs to the specified file. |
| `--overwrite` | Boolean flag (Default: `False`, exits with error if output/backup file exists) | **Optional:** Allows overwriting an existing `--report-file` or `--log-file` (prompts unless `--skip-confirmation` is set). | **Optional:** Allows overwriting an existing `--plan-file`, `--report-file`, or `--log-file` (prompts unless `--skip-confirmation` is set). | **Optional:** Allows overwriting an existing `--report-file` or `--log-file` (prompts unless `--skip-confirmation` is set). | **Optional:** Allows overwriting an existing `--report-file`, `--log-file`, or schema backup file (prompts unless `--skip-confirmation` is set). | **Optional:** Allows overwriting an existing `--report-file` or `--log-file` (prompts unless `--skip-confirmation` is set). |
| `--skip-confirmation` | Boolean flag (Default: `False`, prompts `y/n` interactively) | **Optional:** Skips interactive `y/n` file-overwrite prompts when `--overwrite` is also set. | **Optional:** Skips interactive `y/n` file-overwrite prompts when `--overwrite` is also set. | **Optional:** Skips interactive resource creation confirmation prompts (and file-overwrite prompts when `--overwrite` is set). | **Optional:** Skips the pre-swap limitations/checklist acknowledgment prompt, per-table schema patch confirmation prompts, and file/backup overwrite prompts when `--overwrite` is set. | **Optional:** Skips interactive resource deletion confirmation prompt (and file-overwrite prompts when `--overwrite` is set). |
| `--resource-name` | Resource identifier from plan (Default: `None`) | Not used. | Not used. | **Optional (mutually exclusive with `--all`):** Namespaced name (for Tag Key/Value) or `<target_project_id>/<data_policy_id>` (for `data-policy-v2` in both Mode 1 and Mode 2) of a single resource to create. | Not used. | **Required:** Namespaced name (for Tag Key/Value) or `<target_project_id>/<data_policy_id>` (for `data-policy-v2` in both Mode 1 and Mode 2) of the single resource to delete. |
| `--resource-type` | `dg-tag-key`, `dg-tag-value`, `data-policy-v2` (Default: `None`) | Not used. | Not used. | **Required if `--resource-name` is set:** Type of the single resource to create. | Not used. | **Required:** Type of the single resource to delete. |
| `--allow-unresolved-plan-warnings` | Boolean flag (Default: `False`, blocks on `[ACTION REQUIRED]` warnings) | Not used. | Not used. | **Optional:** Allows proceeding when `--plan-file` contains unresolved `[ACTION REQUIRED]` warnings (attempting remaining valid resources). | **Optional (`pt-to-dgt`):** Allows proceeding when `--plan-file` contains unresolved `[ACTION REQUIRED]` warnings (`dgt-to-pt` rollback is never blocked). | Not used. |
| `--halt-on-error` | Boolean flag (Default: `False`, records error and continues) | **Optional:** Halts immediately on the first region or API error instead of continuing. | **Optional:** Halts immediately on the first region or API error instead of continuing. | **Optional:** Halts immediately on the first resource creation error instead of skipping dependents. | **Optional:** Halts immediately on the first table API error, parity block, or schema corruption error. | **Optional:** Accepted for CLI uniformity (single-resource deletion already exits immediately on API error). |
| `--execution-project` | Single GCP project ID string (Default: scanned table project) | **Optional (`column-binding`):** Project used to run and bill `INFORMATION_SCHEMA` query jobs. | Not used. | Not used. | **Optional:** Project used to run and bill `INFORMATION_SCHEMA` query jobs (`COLUMN_FIELD_PATHS` pre-filtering and `EFFECTIVE_PROJECT_OPTIONS` checks). | Not used. |
| `--debug` | Boolean flag (Default: `False`, `INFO` level) | **Optional:** Enables `DEBUG` logging and full stack traces across all phases. | **Optional:** Enables `DEBUG` logging and full stack traces across all phases. | **Optional:** Enables `DEBUG` logging and full stack traces across all phases. | **Optional:** Enables `DEBUG` logging and full stack traces across all phases. | **Optional:** Enables `DEBUG` logging and full stack traces across all phases. |
| `--datacatalog-endpoint`, `--datapolicy-endpoint`, `--bigquery-endpoint`, `--resourcemanager-endpoint`, `--iam-endpoint` | HTTPS endpoint hostname or URL (Default: `None`, standard Google Cloud endpoints; plaintext `http://` rejected) | **Optional:** Overrides service endpoints used by the selected `--analyze-type` in regional or VPC Service Controls environments. | **Optional:** Overrides Data Catalog, Data Policy, Resource Manager, and IAM endpoints. | **Optional:** Overrides Data Policy and Resource Manager endpoints. | **Optional:** Overrides BigQuery, Data Policy, and Resource Manager endpoints. | **Optional:** Overrides Data Policy and Resource Manager endpoints. |

<!-- mdformat on -->

*   **How `--regions` Works in `--phase swap` (Required Region Filtering &
    `INFORMATION_SCHEMA` Pre-Filtering):**
    1.  **Required Region Scope:** Just like in `--phase analyze` and
        `--phase plan`, `--regions` is **required** in `--phase swap` so every
        schema cutover or rollback is explicitly scoped to the intended
        region(s). The tool inspects each dataset/table's location and only
        swaps tables whose location matches one of the specified `--regions`.
    2.  **Fast Project-Level Table Pre-Filtering:** When you pass whole projects
        via `--table-project-ids`, a project may contain thousands of tables
        where only a few have Policy Tags or Data Governance Tags attached.
        Instead of fetching every dataset and table one by one, the swapper
        queries `region-<region>.INFORMATION_SCHEMA.COLUMN_FIELD_PATHS` in each
        region specified via `--regions` to identify only the candidate tables
        that actually have tags attached (`ARRAY_LENGTH(policy_tags) > 0`
        excluding `/taxonomies/0/policyTags/` Cross-Region Replication
        secondary-replica placeholders in `pt-to-dgt` mode, or
        `ARRAY_LENGTH(data_governance_tags) > 0` in `dgt-to-pt` mode, falling
        back to standard dataset/table listing if the `INFORMATION_SCHEMA` query
        fails).

### Overwrite Protection & Confirmation Flags (`--overwrite` vs. `--skip-confirmation`)

To prevent accidental overwriting of important files (such as previously
generated migration plans, reports, logs, or table schema backups) and to keep
flag responsibilities strictly separated, `--overwrite` and
`--skip-confirmation` control two distinct safety gates:

*   **`--overwrite` (Default: `False`) — Permission to Overwrite Existing
    Files:** Controls whether the script is allowed to replace an existing
    non-empty output file (`--plan-file`, `--report-file`, `--log-file`) or
    per-table schema backup file (`--backup-dir` in `--phase swap`).
*   **`--skip-confirmation` (Default: `False`) — Interactive Prompt Bypass:**
    Controls whether the script pauses for interactive `y/n` human confirmation
    prompts (both for cloud resource mutations in `create`/`swap`/`delete` and
    for file overwrites when `--overwrite` is enabled).
*   **Startup Writability Verification (Fail-Fast Before Execution):** At
    startup (`main.py`), before initializing any Google Cloud SDK clients or
    running any phase logic, the tool verifies both the `--overwrite` rules and
    filesystem writability for every specified output file (`--plan-file`,
    `--report-file`, `--log-file`) and (during non-dry-run `--phase swap`)
    `--backup-dir` by creating parent directories if needed and opening/deleting
    a temporary probe file. If any output path or `--backup-dir` cannot be
    created or written to, the script exits immediately with an actionable error
    so a long-running analysis, creation, or swap never fails at the very end
    due to a read-only directory or invalid output path.

The four combinations behave as follows:

1.  **`--overwrite` is `False` (default, regardless of `--skip-confirmation`):**
    If any specified output file (`--plan-file`, `--report-file`, `--log-file`)
    or target schema backup file already exists and is non-empty, the script
    **exits immediately with an error message** listing the exact file path(s)
    that already exist and instructing you to pass `--overwrite` if you want to
    replace them. **Passing `--skip-confirmation` alone without `--overwrite`
    never allows overwriting existing files.**
2.  **`--overwrite` is `True` and `--skip-confirmation` is `False`:** The script
    is permitted to overwrite existing files, but because multiple output or
    backup files could be affected, it **prompts you interactively (`y/n`) to
    confirm overwriting each existing file individually** before replacing it.
3.  **`--overwrite` is `True` and `--skip-confirmation` is `True`:** Existing
    output files and schema backup files are overwritten automatically without
    interactive prompts (ideal for non-interactive CI/CD or automated scripts
    where overwriting is explicitly intended).

### Output Files: Plan File (`--plan-file`), Report File (`--report-file`), and Log File (`--log-file`)

Across all phases, the migration tool supports three output file flags that
serve distinct audiences during migration:

<!-- mdformat off -->

| Output | Flag | Format | Primary Audience & Purpose | Content |
| :--- | :--- | :--- | :--- | :--- |
| **Migration Plan Blueprint** | `--plan-file` (or `stdout`, in `--phase plan`) | JSON (`.json`) | Machine-readable migration blueprint consumed as input by `--phase create`, `--phase delete`, and `--phase swap` (and reviewed/customized by governance engineers before resource creation). | Planned target resource payloads (`phase_2_resource_manifest`), Policy-Tag-to-DGT lookup map (`phase_3_binding_map`), source/target summary metrics, and validation warnings. |
| **Phase Report** | `--report-file` (or `stdout`, in every phase) | Markdown (`.md`) | Migration leads, data stewards, security reviewers, and auditors reviewing **what happened** (migration outcomes) in each phase. | High-level summary counts, categorized resource/table status tables, unified schema diffs (`swap`), actionable warnings, concise error messages per failed resource/table, and an automatic status/warning code reference whenever errors or warnings occur. |
| **Execution Log** | `--log-file` (in every phase) | Plain text (`.log`) | (1) Your engineering team debugging or troubleshooting script execution, and (2) Google Cloud Support or BigQuery engineering when you share the `.log` file to report and troubleshoot an issue with the migration tool. | Granular chronological telemetry (**how it happened**): timestamped API calls, retry attempts, log levels, unified schema diffs, parity verification details, and full exception stack traces (especially when `--debug` is set). |

<!-- mdformat on -->

#### Why It Is Helpful to Have Both `--report-file` and `--log-file`

1.  **Clean Separation Between Auditing and Troubleshooting:**

    *   **`--report-file`** provides a clean, reviewable Markdown document
        (`.md` across all phases: `analyze`, `plan`, `create`, `delete`, and
        `swap`) that you can attach to change management tickets, share with
        stakeholders, or use to verify migration status without wading through
        thousands of lines of terminal logs.
    *   **`--log-file`** captures full runtime diagnostics. When an unexpected
        API error or network timeout occurs, the `.log` file provides exact
        timestamps, request parameters, and tracebacks needed by your
        engineering team to diagnose root causes or to share with Google /
        BigQuery support when reporting an issue with the migration tool.

2.  **Resilience During Troubleshooting & Retries:**

    *   If a batch run fails midway through (e.g., due to a permission issue),
        the report file immediately highlights which resources or tables
        succeeded, which were skipped, and which specific item failed.
    *   Simultaneously, the log file reveals the exact chronological sequence of
        API calls leading up to the failure.

### Phase 1a: Analyze (`--phase analyze`)

*   **Purpose:** Scans specified projects and regions to inspect existing
    Taxonomies, Policy Tags, Data Governance Tags, Data Policies, and Column
    Bindings in BigQuery tables, and generates a Markdown (`.md`) analysis
    report. It supports three analysis types controlled by `--analyze-type`:

    1.  **Static Taxonomy & Policy Analysis (`static-taxonomy`, default):**
        Analyzes Policy Tag Taxonomies (identifying Classification-Only vs.
        Access Control taxonomies), fine-grained reader permissions, and
        associated Data Policies (V1), and produces a detailed inventory report.
    2.  **Static Data Governance Tag Analysis (`static-dgt`):** Discovers
        existing Data Governance Tag Keys, Tag Values (including hierarchical
        trees), and attached BigQuery Data Policies (V2), plus unattached V2
        policies, and produces a DGT inventory report.
    3.  **Column Binding Analysis (`column-binding`):** Analyzes BigQuery
        `INFORMATION_SCHEMA.COLUMN_FIELD_PATHS` across all three Column-Level
        Security (CLS) mechanisms—legacy Policy Tags (automatically excluding
        synthetic `/taxonomies/0/policyTags/` Cross-Region Replication
        secondary-replica placeholders), IAM Data Governance Tags, and Direct
        Data Policies on Columns—and produces a column binding report showing
        which tables and columns use each mechanism.

*   **Usage Examples:**

    *   **Static Taxonomy Analysis (Default):**

        ```bash
        python main.py --phase analyze --analyze-type static-taxonomy \
          --taxonomy-project-id my-taxonomy-project \
          --regions us-central1 eu \
          --report-file static_taxonomy_report.md
        ```

    *   **Static Data Governance Tag Analysis:**

        ```bash
        python main.py --phase analyze --analyze-type static-dgt \
          --dgt-project-id my-tag-project \
          --data-policy-v2-project-ids my-policy-project \
          --regions us \
          --report-file static_dgt_report.md
        ```

    *   **Column Binding Analysis (All CLS Types):**

        ```bash
        python main.py --phase analyze --analyze-type column-binding \
          --table-project-id my-data-project \
          --regions us \
          --verbose-bindings \
          --report-file column_binding_report.md
        ```

*   **Arguments:**

    *   `--phase analyze`: Specifies that the analyze phase should be run.
    *   `--analyze-type <TYPE>`: **(Optional)** Type of analysis to perform.
        Choices: `static-taxonomy` (default), `static-dgt`, `column-binding`.
    *   `--taxonomy-project-id <ID>`: **(Required for `static-taxonomy`)**
        Singular Google Cloud project ID containing Policy Tag taxonomies and V1
        Data Policies to scan.
    *   `--dgt-project-id <ID>`: **(Required for `static-dgt`)** Singular Google
        Cloud project ID containing global Data Governance Tag Keys and Tag
        Values to scan.
    *   `--data-policy-v2-project-ids <ID ...>`: **(Required for `static-dgt`)**
        One or more Google Cloud project IDs (space- or comma-separated) where
        regional V2 Data Policies are queried across `--regions` and matched to
        the Data Governance Tags in `--dgt-project-id`.
    *   `--table-project-id <ID>`: **(Required for `column-binding`)** Singular
        Google Cloud BigQuery data project ID whose regional
        `INFORMATION_SCHEMA` views are scanned for column bindings.
    *   `--regions <REGION ...>`: **(Required)** One or more regions to scan
        (e.g., `us`, `eu`, `us-central1`).
    *   `--verbose-bindings`: **(Optional)** For `column-binding`, lists bound
        columns in the report in addition to summary counts (capped at 1,000
        columns per tag or policy with an explicit truncation notice when
        capped; default: `False`).
    *   `--execution-project <ID>`: **(Optional)** The Google Cloud project ID
        to use for running BigQuery jobs (billing/job project). Defaults to
        `--table-project-id`. Useful if you want to run queries from a
        centralized project.
    *   `--report-file <PATH>`: **(Optional)** Output file for the
        human-readable Markdown report (`.md`). If omitted, the report is
        printed to `stdout`.
    *   `--log-file <PATH>`: **(Optional)** Output file for timestamped
        execution logs (`.log`).
    *   `--overwrite`: **(Optional)** Allow overwriting `--report-file` or
        `--log-file` if they already exist (default: `False`; prompts for
        confirmation on each existing file unless `--skip-confirmation` is also
        specified).
    *   `--skip-confirmation`: **(Optional)** Skip interactive file-overwrite
        confirmation prompts when `--overwrite` is also set (default: `False`).
    *   `--datacatalog-endpoint`, `--datapolicy-endpoint`,
        `--resourcemanager-endpoint`, `--bigquery-endpoint`, `--iam-endpoint`:
        **(Optional)** Custom API endpoint hostnames or `https://` URLs for
        Private Service Connect (PSC), mTLS / Context-Aware Access
        (`*.mtls.googleapis.com`), or VPC-SC restricted environments (note that
        `<region>-datacatalog.googleapis.com` does not serve Policy Tag Manager,
        and `<region>-bigquery.googleapis.com` requires Locational Endpoint
        project enrollment).

### Phase 1b: Plan (`--phase plan`)

*   **Purpose:** Generates a migration plan blueprint (JSON) and a
    human-readable summary report (Markdown) based on your existing Policy Tag
    taxonomy and V1 Data Policy setup (see the
    [Phase 1b Plan guide](phase_1b_plan.md) for mapping and validation details).
*   **Usage:**

    ```bash
    # Mode 1: Organization-Level Default Data Policy Project
    # Use Mode 1 when you want to manage all V2 Data Policies in a single
    # centralized governance project (central-dp-project) that is registered in
    # your Organization's `default_data_policy_projects` setting. BigQuery will
    # automatically evaluate policies from this central project across all data
    # tables in the organization (Recommended for centralized governance and
    # Cross-Region Replication / Disaster Recovery).
    python main.py --phase plan \
      --taxonomy-project-id my-taxonomy-project \
      --regions us-central1 eu \
      --target-dgt-project-id central-dgt-project \
      --target-default-dp-project-id central-dp-project \
      --plan-file migration_plan.json \
      --report-file plan_summary.md

    # Mode 2: Data Table Parent Project(s)
    # Use Mode 2 when you do NOT use Organization-level
    # `default_data_policy_projects`, or when your governed BigQuery tables live
    # in specific data projects (data-project-1, data-project-2) where each
    # table project should own its own regional V2 Data Policies referencing the
    # shared global Data Governance Tags in central-dgt-project.
    python main.py --phase plan \
      --taxonomy-project-id my-taxonomy-project \
      --regions us-central1 eu \
      --target-dgt-project-id central-dgt-project \
      --target-table-dp-project-ids data-project-1 data-project-2 \
      --collision-resolution from_region \
      --plan-file migration_plan.json \
      --report-file plan_summary.md
    ```

*   **Understanding How Data Policy Lookup Differs Between Policy Tags and Data
    Governance Tags (Why Mode 1 vs. Mode 2 Exists):**

    *   **Legacy Policy Tags (V1):** In the legacy Policy Tag model, a V1 Data
        Policy is attached directly to a regional Policy Tag inside the
        **taxonomy project**. When a table is queried, BigQuery looks up the
        Policy Tag and its V1 Data Policy directly in the taxonomy's project.
    *   **Data Governance Tags (V2):** In the new DGT model, Data Governance Tag
        Keys and Tag Values are global Cloud Resource Manager metadata resources
        created in `--target-dgt-project-id`. However, when a user queries a
        BigQuery table whose columns carry Data Governance Tags, **BigQuery does
        NOT look up V2 Data Policies in the project that owns the Data
        Governance Tags (`--target-dgt-project-id`)** (unless that project also
        happens to be one of the two lookup locations below). Instead, BigQuery
        only looks up V2 Data Policies in two places in the queried table's
        region:

        1.  **Organization-Level Default Data Policy Projects
            (`default_data_policy_projects` — Mode 1 via
            `--target-default-dp-project-id`, Recommended for centralized
            governance and Cross-Region Replication / Disaster Recovery):** A
            single centralized project per region registered at the Google Cloud
            Organization level via:

            ```sql
            ALTER ORGANIZATION SET OPTIONS (
              `region-<REGION>.default_data_policy_projects` = ['<PROJECT_ID>']
            );
            ```

            BigQuery checks the region's registered default project for V2 Data
            Policies matching the column's DGT on every query across the
            organization, and BigQuery Cross-Region Replication (CRR)
            automatically discovers and replicates V2 Data Policies from the
            organization's `default_data_policy_projects` to the secondary
            region when governed datasets are replicated—avoiding per-project
            policy duplication and drift across multiple data projects. For
            step-by-step instructions on registering a default Data Policy
            project, see
            [Configure a default data policy project](https://cloud.google.com/bigquery/docs/tags#configure-default-data-policy-project)
            and
            [Data management settings (`default_data_policy_projects`)](https://cloud.google.com/bigquery/docs/default-configuration#data-management-settings).
        2.  **The Queried Table's Parent Project (Mode 2 via
            `--target-table-dp-project-ids`):** The Google Cloud project that
            directly contains the BigQuery dataset and table being queried. If
            your organization has not configured `default_data_policy_projects`,
            V2 Data Policies **must** exist inside each BigQuery project that
            owns the governed tables; if you only created V2 Data Policies in a
            separate tag project without registering it in
            `default_data_policy_projects`, BigQuery would not find those
            policies at query time and **DGT-tagged columns would fail open!**
    *   Because of this architectural difference, `--phase plan` separates the
        target project for global Data Governance Tags
        (`--target-dgt-project-id`) from the target project(s) for regional V2
        Data Policies and requires you to explicitly choose either **Mode 1
        (`--target-default-dp-project-id`)** or **Mode 2
        (`--target-table-dp-project-ids`)**. For additional background, see
        [Use Data Governance Tags for column-level security and data masking](https://cloud.google.com/bigquery/docs/tags#data-governance-tags)
        and
        [Manage data policies](https://cloud.google.com/bigquery/docs/tags#manage-data-policies).

*   **Arguments:**

    *   `--phase plan`: Specifies that the plan phase should be run.
    *   `--taxonomy-project-id <ID>`: **(Required)** Singular Google Cloud
        source project ID containing Policy Tag taxonomies to migrate.
    *   `--regions <REGION ...>`: **(Required)** One or more regions to scan for
        policy tags.
    *   `--target-dgt-project-id <ID>`: **(Required)** The target Google Cloud
        project ID (e.g., `central-dgt-project`) where global Data Governance
        Tag Keys and Tag Values (`purpose=DATA_GOVERNANCE`) will be created.
        Specify the string project ID, not the numeric project number.
    *   `--target-default-dp-project-id <ID>`: **(Mutually Exclusive with
        `--target-table-dp-project-ids`; one of the two is Required)** **Mode 1
        (Organization-Level Default Data Policy Project Mode):** Singular target
        project ID where regional V2 Data Policies will be created. This project
        must be registered in your Organization's `default_data_policy_projects`
        setting via ``ALTER ORGANIZATION SET OPTIONS
        (\`region-<REGION>.default_data_policy_projects\` = ['<PROJECT_ID>']);``
        (see
        [Configure a default data policy project](https://cloud.google.com/bigquery/docs/tags#configure-default-data-policy-project)
        and
        [Data management settings (`default_data_policy_projects`)](https://cloud.google.com/bigquery/docs/default-configuration#data-management-settings))
        so BigQuery looks up policies in this central project regardless of
        which data project owns the queried table.
    *   `--target-table-dp-project-ids <ID ...>`: **(Mutually Exclusive with
        `--target-default-dp-project-id`; one of the two is Required)** **Mode 2
        (Data Table Parent Project Mode):** One or more target project IDs
        (space-separated or comma-separated) corresponding to the BigQuery data
        projects that own the tables bound to these tags. Regional V2 Data
        Policies are created in each specified table project.
    *   `--collision-resolution <counter|from_region>`: **(Optional)** Strategy
        for resolving DG Tag Key short name collisions when multiple regional
        taxonomies share the same display name. Because legacy Policy Tag
        taxonomies are regional while Resource Manager DG Tag Keys are global
        under `--target-dgt-project-id`, a collision occurs whenever two
        regional taxonomies in the source project have the same display name—for
        example, a taxonomy named `"Sensitive Data"` in `us` and another
        taxonomy named `"Sensitive Data"` in `eu` both sanitize to the short
        name `sensitive_data` under `central-dgt-project`. Choices:
        *   `counter` (default): Keeps the first key as `sensitive_data` and
            appends `-1`, `-2` to subsequent colliding keys
            (`central-dgt-project/sensitive_data`,
            `central-dgt-project/sensitive_data-1`).
        *   `from_region`: Appends `_from_<region>` to colliding keys
            (`central-dgt-project/sensitive_data_from_us`,
            `central-dgt-project/sensitive_data_from_eu`).
        *   In both modes, the source region is always recorded in the DG Tag
            Key's `description`.
    *   `--plan-file <PATH>`: **(Optional)** Output file for the
        machine-readable migration plan (`.json`). If omitted, the JSON plan is
        printed to `stdout`.
    *   `--report-file <PATH>`: **(Optional)** Output file for the
        human-readable summary report (`.md` Markdown). If omitted, the Markdown
        report is printed to `stdout`.
    *   `--log-file <PATH>`: **(Optional)** Output file for timestamped
        execution logs (`.log`).
    *   `--halt-on-error`: **(Optional)** Halt immediately on the first regional
        analysis error instead of recording the warning and continuing (default:
        `False`).
    *   `--overwrite`: **(Optional)** Allow overwriting existing `--plan-file`,
        `--report-file`, or `--log-file` (default: `False`; prompts for
        confirmation on each existing file unless `--skip-confirmation` is also
        specified).
    *   `--skip-confirmation`: **(Optional)** Skip interactive file-overwrite
        confirmation prompts when `--overwrite` is also set (default: `False`).

### Phase 2a: Create (`--phase create`)

*   **Purpose:** Executes the migration plan to create the new Data Governance
    Tag resources in Google Cloud (see the
    [Phase 2a Create guide](phase_2a_create.md) for topological creation order,
    idempotency, and propagation soak window details).
*   **Strongly Recommended — Run Dry-Run First (`--dry-run`):** Before creating
    resources in Google Cloud, always run `--phase create --dry-run` to preview
    which Tag Keys, Tag Values, and V2 Data Policies would be created vs.
    skipped (because they already exist in Google Cloud) and to detect any
    validation errors, quota limits, or missing parent dependencies without
    performing any mutations.
*   **Usage (Dry-Run Preview - Recommended First Step):**

    ```bash
    python main.py --phase create \
      --plan-file migration_plan.json \
      --all \
      --dry-run \
      --report-file create_dry_run_report.md
    ```

*   **Usage (Batch Execution Mode):**

    ```bash
    python main.py --phase create \
      --plan-file migration_plan.json \
      --all \
      --report-file create_report.md
    ```

*   **Usage (Individual Resource Mode):**

    ```bash
    python main.py --phase create \
      --plan-file migration_plan.json \
      --resource-name "my-gcp-project/sensitive_data/pii" \
      --resource-type "dg-tag-value"
    ```

*   **Arguments:**

    *   `--phase create`: **(Required)** Specifies that the create phase should
        be run.
    *   `--plan-file <PATH>`: **(Required)** Path to the machine-readable
        migration plan (`.json`) generated by `--phase plan`.
    *   `--all`: **(Optional)** Create all resources in the plan (default:
        `False`). You must specify either `--all` or `--resource-name` (mutually
        exclusive).
    *   `--resource-name <NAME>`: **(Optional)** Identifier of a single resource
        from `--plan-file` to create (default: `None`; mutually exclusive with
        `--all`):
        *   **For a DG Tag Key or Tag Value (`--resource-type dg-tag-key` or
            `dg-tag-value`):** Pass its `namespaced_name` from `plan.json`
            (e.g., `my-gcp-project/sensitive_data` or
            `my-gcp-project/sensitive_data/pii`).
        *   **For a V2 Data Policy (`--resource-type data-policy-v2`):** Always
            pass `<target_project_id>/<data_policy_id>` (e.g.,
            `data-project-1/migrated_raw_sensitive_data_ssn`) in both Mode 1
            (`--target-default-dp-project-id`) and Mode 2
            (`--target-table-dp-project-ids`). Passing a bare `<data_policy_id>`
            is rejected with a validation error before prompting.
    *   `--resource-type <TYPE>`: **(Optional)** Type of the individual resource
        to create (`dg-tag-key`, `dg-tag-value`, `data-policy-v2`; default:
        `None`). Required if `--resource-name` is specified.
    *   `--dry-run`: **(Optional, Strongly Recommended First)** Preview which
        resources would be created vs. skipped and report any potential
        validation issues, quota limits, or missing parent blockers without
        creating any resources in Google Cloud (default: `False`).
    *   `--allow-unresolved-plan-warnings`: **(Optional)** Allow proceeding with
        resource creation even if `--plan-file` still contains unresolved
        `[ACTION REQUIRED]` warnings (default: `False`, which blocks upfront
        with `BLOCKED_UNRESOLVED_PLAN_WARNINGS` and exit code `1`; when `True`,
        logs a warning and continues attempting all remaining valid resources
        when `--halt-on-error` is `False`, or halts on the first creation
        failure when `--halt-on-error` is `True`).
    *   `--halt-on-error`: **(Optional)** Halt execution immediately on the
        first resource creation failure (default: `False`, records the error and
        continues creating independent resources).
    *   `--skip-confirmation`: **(Optional)** Bypass interactive human
        confirmation prompts before creating resources in Google Cloud, and
        bypass interactive file-overwrite confirmation prompts when
        `--overwrite` is also set (default: `False`).
    *   `--report-file <PATH>`: **(Optional)** Output file for the
        human-readable creation (or dry-run) report in Markdown (`.md`) format.
        Records what was created (or would be created), what was skipped, any
        warnings, and any failed resources with error causes. Supported in both
        batch mode (`--all`) and individual mode (`--resource-name`). If
        omitted, the report is printed to `stdout` (default: `None`).
    *   `--log-file <PATH>`: **(Optional)** Output file for timestamped
        execution logs (`.log`). Captures runtime actions, created resources,
        and full error diagnostics / tracebacks (default: `None`, logs to
        `stderr` only).
    *   `--overwrite`: **(Optional)** Allow overwriting existing non-empty
        output files (`--report-file`, `--log-file`). Default: `False` (exits
        with an error if an output file already exists; when `--overwrite` is
        set, prompts interactively per existing file unless
        `--skip-confirmation` is also passed).

### Phase 2b: Delete (`--phase delete` - Individual Resources)

*   **Purpose:** Deletes a specific Data Governance Tag resource (Key, Value, or
    Data Policy) in Google Cloud using `plan.json` as an allowlist (see the
    [Phase 2b Delete guide](phase_2b_delete.md) for dependency checks and
    cleanup details).
*   **Strongly Recommended — Run Dry-Run First (`--dry-run`):** Before deleting
    a resource, run `--phase delete --dry-run` for a client-side preview of
    whether the target resource exists in Google Cloud and whether live child
    Tag Value dependencies, referencing V2 Data Policies in `plan.json`, or
    Fail-Open security risks (such as deleting a `_default_deny` policy) exist.
    Note that client-side `--dry-run` cannot discover BigQuery column bindings
    or out-of-plan V2 Data Policies in arbitrary projects; during live deletion,
    Cloud Resource Manager enforces global tag attachment integrity across all
    projects and rejects `tagValues.delete` with `400 FAILED_PRECONDITION` if
    any BigQuery column or V2 Data Policy in any project still references the
    Tag Value.
*   **Warning:** This operation is destructive. Ensure you are deleting the
    correct resource. Dependencies must be resolved manually. The tool does
    **not** perform cascade deletion or automatic detachment; GCP API calls will
    fail if dependencies are not resolved first.
*   **Deletion Dependencies & Blockers:**
    *   **Active Bindings:** A **Tag Value** cannot be deleted if it is
        currently attached (bound) to a BigQuery column or other GCP resource.
        You must first manually remove these bindings (e.g., by updating the
        BigQuery table schema to remove the tag).
    *   **Child Resources:** A **Tag Key** cannot be deleted if it still has
        child **Tag Values**. Similarly, a parent **Tag Value** cannot be
        deleted if it has child **Tag Values** (in hierarchical setups). You
        must manually delete the child resources first.
*   **Recommended Deletion Sequence (Bottom-Up):**
    1.  **Remove Bindings:** Ensure the tags are no longer bound to any BigQuery
        columns.
    2.  **Data Policies (V2):** Delete them first to remove references to the
        tags.
    3.  **Tag Values:** Delete them next (leaf values first if hierarchical).
    4.  **Tag Keys:** Delete them last, after all child values are removed.
*   **Safety Note (Why There Is No "Delete All" Option):** The tool
    intentionally does **not** provide a `--all` ("Delete All") flag in
    `--phase delete` for two reasons:
    1.  **Protecting Pre-Existing Customer Resources:** It prevents accidental
        mass destruction of pre-existing Data Governance Tag Keys, Tag Values,
        or V2 Data Policies that were created outside of the migration tool (for
        example, created manually by customers) whose names happen to collide
        with entity names in `migration_plan.json`.
    2.  **Avoiding Unnecessary Complexity:** Mass deletion of Data Governance
        Tag resources is not a required phase of a production PT-to-DGT
        migration, so keeping `--phase delete` scoped to individual resources
        avoids unnecessary bulk-deletion complexity in the tool.
*   **Crucial Safety Clarification:** The delete capability is strictly offered
    for testing and cleanup in **non-production environments**. It is **NOT**
    intended for deleting production Data Governance Tags, let alone doing
    production deletion at scale. Accidental deletion of production tags can
    instantly break Column-Level Security enforcement.
*   **Propagation Delay:** Deleting resources in GCP takes time to propagate.
    Recreating a resource with the *exact same name* immediately after deletion
    may fail. Allow a few minutes for propagation or use unique names for rapid
    testing.
*   **Usage:**

    ```bash
    # Dry-run preview (recommended first step)
    python main.py --phase delete \
      --plan-file migration_plan.json \
      --resource-name "my-gcp-project/sensitive_data/pii" \
      --resource-type "dg-tag-value" \
      --dry-run \
      --report-file delete_dry_run_report.md

    # Execute deletion of a Tag Value
    python main.py --phase delete \
      --plan-file migration_plan.json \
      --resource-name "my-gcp-project/sensitive_data/pii" \
      --resource-type "dg-tag-value" \
      --report-file delete_report.md

    # Execute deletion of a V2 Data Policy (always pass
    # <target_project_id>/<data_policy_id> in both Mode 1 and Mode 2, plus
    # --allow-fail-open-policy-delete after verifying zero bound columns)
    python main.py --phase delete \
      --plan-file migration_plan.json \
      --resource-name "data-project-1/migrated_raw_sensitive_data_ssn" \
      --resource-type "data-policy-v2" \
      --allow-fail-open-policy-delete \
      --report-file delete_policy_report.md
    ```

*   **Arguments:**

    *   `--phase delete`: **(Required)** Specifies that the delete phase should
        be run.
    *   `--plan-file <PATH>`: **(Required)** Path to the machine-readable
        migration plan (`.json`) generated by `--phase plan` (used as an
        allowlist of deletable resources).
    *   `--resource-name <NAME>`: **(Required)** Identifier of the single
        resource from `--plan-file` to delete:
        *   **For a DG Tag Key or Tag Value (`--resource-type dg-tag-key` or
            `dg-tag-value`):** Pass its `namespaced_name` from `plan.json`
            (e.g., `my-gcp-project/sensitive_data` or
            `my-gcp-project/sensitive_data/pii`).
        *   **For a V2 Data Policy (`--resource-type data-policy-v2`):** Always
            pass `<target_project_id>/<data_policy_id>` (e.g.,
            `data-project-1/migrated_raw_sensitive_data_ssn`) in both Mode 1
            (`--target-default-dp-project-id`) and Mode 2
            (`--target-table-dp-project-ids`). Passing a bare `<data_policy_id>`
            is rejected with a validation error before prompting.
    *   `--resource-type <TYPE>`: **(Required)** Type of the individual resource
        to delete (`dg-tag-key`, `dg-tag-value`, `data-policy-v2`).
    *   `--dry-run`: **(Optional, Strongly Recommended First)** Client-side
        preview checking whether the target resource exists, live child Tag
        Value dependencies, referencing V2 Data Policies in `plan.json`, and
        Fail-Open risks without deleting the resource (default: `False`; global
        BigQuery column bindings and out-of-plan V2 Data Policies across
        arbitrary projects are enforced server-side by Cloud Resource Manager
        during live deletion).
    *   `--allow-fail-open-policy-delete`: **(Required for live `data-policy-v2`
        deletion)** Explicitly authorizes live deletion of a V2 Data Policy
        after you confirm its Tag Value is no longer bound to any BigQuery
        columns (default: `False`; because BigQuery does not check active table
        column bindings when deleting tag-based V2 Data Policies, live
        `data-policy-v2` deletion is blocked with `BLOCKED` and exit code `1`
        unless this flag is set, even when `--skip-confirmation` is passed).
    *   `--halt-on-error`: **(Optional)** Accepted for CLI uniformity across
        phases (default: `False`); because `--phase delete` operates on a single
        resource, any API deletion failure raises immediately (and `main.py`
        exits with status code `1` after persisting `--report-file`, or when
        deletion is `BLOCKED`).
    *   `--skip-confirmation`: **(Optional)** Bypass the interactive
        confirmation prompt before deleting the resource in Google Cloud, and
        bypass interactive file-overwrite confirmation prompts when
        `--overwrite` is also set (default: `False`).
    *   `--report-file <PATH>`: **(Optional)** Output file for the Markdown
        (`.md`) deletion (or dry-run) status and dependency report. If omitted,
        the report is printed to `stdout` (default: `None`).
    *   `--log-file <PATH>`: **(Optional)** Output file for timestamped
        execution logs (`.log`; default: `None`, logs to `stderr` only).
    *   `--overwrite`: **(Optional)** Allow overwriting existing non-empty
        output files (`--report-file`, `--log-file`). Default: `False` (exits
        with an error if an output file already exists; when `--overwrite` is
        set, prompts interactively per existing file unless
        `--skip-confirmation` is also passed).

### Phase 3: Swap & Rollback (`--phase swap`)

*   **Purpose:** Atomically swaps Policy Tags and Data Governance Tags in
    BigQuery table schemas (`tables.patch`) across all tables discovered within
    the specified projects (`--table-project-ids`), datasets (`--dataset-ids`),
    and/or individual tables (`--table-ids`) based on the migration plan's
    `phase_3_binding_map` (see the
    [Phase 3 Swap and Rollback guide](phase_3_swap.md) for detailed workflows
    and operational runbooks). Supports two modes via `--swap-mode`:
    *   **Mode 1 (`--swap-mode pt-to-dgt`, default - Forward Migration):**
        Clears mapped Policy Tags (by setting `"policyTags": {"names": []}` in
        the table schema) and attaches mapped Data Governance Tags (by setting
        `"dataGovernanceTagsInfo"` in the table schema).
    *   **Mode 2 (`--swap-mode dgt-to-pt` - Automated Rollback to Policy
        Tags):** Clears mapped Data Governance Tags (by setting
        `"dataGovernanceTagsInfo": {"dataGovernanceTags": {}}` in the table
        schema) and restores the original Policy Tags (by setting
        `"policyTags": {"names": ["<source_policy_tag>"]}` in the table schema).
        Use Mode 2 to automatically revert tables back to Policy Tag protection
        if an issue is discovered after cutover.
*   **Crucial Pre-Production Safety Practice — Rehearse Forward Swap and
    Rollback in a Test Environment First:** Before running
    `--phase swap --swap-mode pt-to-dgt` in a production environment, always
    exercise the full round-trip sequence in a non-production test environment
    first: `pt-to-dgt (initial forward migration) -> dgt-to-pt (rollback to
    Policy Tags) -> pt-to-dgt (forward migration again)`. Avoid running
    `--swap-mode dgt-to-pt` for the very first time while responding to a live
    production issue; testing and confirming the `dgt-to-pt` rollback workflow
    in a test environment beforehand ensures there are no unexpected permission
    or operational issues if a production rollback is ever needed.
*   **Strongly Recommended — Run Dry-Run First (`--dry-run`):** Updating
    BigQuery table schemas in production is a high-risk operation. Always run
    `--phase swap --dry-run` (or `--phase swap --swap-mode dgt-to-pt --dry-run`
    before rolling back) first! In dry-run mode, no table schemas are modified
    and no backup files are written, while the tool still runs every safety
    check—including live Google Cloud DGT and V2 Data Policy enforcement parity
    verification, recursive schema anti-corruption verification, and full
    unified schema diff generation (`DRY_RUN_READY` vs.
    `BLOCKED_PARITY_DISCREPANCY`).
*   **Safety Safeguards (Shared Across Both Modes):**

    1.  **Pre-Swap Enforcement Parity Verification (Mode 1 `pt-to-dgt`):**
        Before modifying a table in forward migration mode, the tool verifies in
        live Google Cloud that every target Data Governance Tag Key
        (`purpose=DATA_GOVERNANCE`), Tag Value, and V2 Data Policy (Raw Reader
        Parity—including direct raw grants copied onto masked child tags—Default
        Deny Parity, and Migrated Masking rules and grantees, including ancestor
        hierarchy inheritance) exists and matches the source Policy Tag security
        security posture (checking per-tag-depth Raw Reader parity, Tag-Key-wide
        Classification-Only Default-Allow safety, and condition-bound V2
        policies), and queries `INFORMATION_SCHEMA.EFFECTIVE_PROJECT_OPTIONS`
        (unless `--skip-default-dp-org-check` is set) both to confirm Mode 1
        `--target-default-dp-project-id` registration in
        `default_data_policy_projects` and to check companion Data Policy
        projects (the table's parent project in Mode 1 and any Organization
        `default_data_policy_projects` entries in Mode 1 or Mode 2) for
        conflicting V2 Data Policies. If any discrepancy is detected that could
        cause **Access Leakage** (e.g., Fail-Open column or extra grantees) or
        **Access Blockage** (e.g., missing readers or unexpected policy on a
        classification-only tag), the swap for that table is **blocked by
        default** unless `--allow-parity-discrepancy` is passed. (In Mode 2
        `dgt-to-pt` rollback, forward DGT parity checks are skipped so tables
        can always be rolled back to Policy Tags even when target DGT or V2 Data
        Policy resources are missing or misconfigured.)
    2.  **Strict Schema Integrity Safeguard (Anti-Corruption Check) & Post-Patch
        Tag Verification:** Before calling `tables.patch`, the tool recursively
        validates the original and updated schema ASTs to guarantee that
        **only** the mapped `policyTags` and `dataGovernanceTagsInfo` fields on
        the target columns (including nested `RECORD` / `STRUCT` subfields) were
        modified—specifically, `policyTags: {"names": []}` and the mapped
        `dataGovernanceTagsInfo` in Mode 1 (`pt-to-dgt`), or
        `policyTags: {"names": ["<source_policy_tag>"]}` and
        `dataGovernanceTagsInfo: {"dataGovernanceTags": {}}` in Mode 2
        (`dgt-to-pt`). If any unintended schema change is detected (such as
        dropped/reordered columns or altered types, modes, descriptions, or
        unmapped tags), the tool reports schema corruption and **aborts
        immediately** without updating the table. Immediately after
        `tables.patch` returns, the tool also inspects the returned `Table`
        schema to confirm every swapped column carries the expected target tag;
        if BigQuery silently dropped the target tag (for example, on
        external/federated metadata table formats that strip Data Governance
        Tags during schema updates), the tool immediately issues a compensating
        `tables.patch` restoring the original column tags and marks the table
        `FAILED` so sensitive columns never remain unprotected.
    3.  **Automatic Restore-Ready Schema Backup (Fail-Safe Pre-Patch
        Requirement):** Before patching each table (in execution mode), a
        restore-ready pre-update table schema JSON is saved under mode, project,
        and dataset subdirectories inside `--backup-dir`:
        *   **Mode 1 (`pt-to-dgt`):** Saved to
            `schema_backups/pt_to_dgt/<project_id>/<dataset_id>/<table_id>.json`,
            including explicit
            `"dataGovernanceTagsInfo": {"dataGovernanceTags": {}}` on swapped
            leaf columns so `bq update` clears newly attached Data Governance
            Tags while restoring Policy Tags without violating BigQuery's
            single-tag-type column exclusivity.
        *   **Mode 2 (`dgt-to-pt` rollback):** Saved to
            `schema_backups/dgt_to_pt/<project_id>/<dataset_id>/<table_id>.json`,
            including explicit `"policyTags": {"names": []}` on swapped leaf
            columns so `bq update` clears restored Policy Tags if reverting the
            rollback, while ensuring a rollback in the same `--backup-dir` never
            overwrites the original pre-migration schema backup and dataset or
            table names containing `__` or `_rollback` never collide on disk.
        *   **Existing Backup File Protection (`--overwrite` and
            `--skip-confirmation`) & Fail-Fast Startup Writability Check:**
            Schema backup files follow the exact same `--overwrite` (default:
            `False`) and `--skip-confirmation` (default: `False`) safety rules
            as other output files. Furthermore, at startup (before resolving or
            inspecting any tables), the tool verifies that `--backup-dir` can be
            created and written to via a temporary probe file; if `--backup-dir`
            is not writable or if a target backup file already exists when
            `--overwrite` is `False`, the tool aborts **before** any table
            schema is modified—guaranteeing that no BigQuery table schema is
            ever patched without a verified local schema backup. When
            `--overwrite` is passed without `--skip-confirmation`, the tool
            prompts interactively before overwriting an existing backup file;
            passing both `--overwrite` and `--skip-confirmation` overwrites
            existing backup files without prompting.
    4.  **Pre-Swap `README.md` Acknowledgment, Schema Diff Logging &
        Human-in-the-Loop Confirmation:** In execution mode (when neither
        `--dry-run` nor `--skip-confirmation` is set), the tool first prompts
        the operator (`y/n`) to confirm they have thoroughly read and understood
        `README.md`—which discusses feature gaps between PT and DGT (if your
        workloads depend on any unsupported feature, you should not perform
        migration yet), limitations with the migration tool and platform, and
        how to perform a safe migration and avoid pitfalls—and warns that not
        reading and understanding `README.md` can result in security violations
        or production outages. Then, for each table, the unified schema diff is
        logged (and written to `--report-file` if specified), displayed on
        screen, and gated by an interactive human confirmation (`y/n`) prompt
        before patching (use `--skip-confirmation` for non-interactive runs).

*   **Usage Examples:**

    *   **Mode 1 (`pt-to-dgt`): Preview Schema Swaps and Parity Checks in
        Dry-Run Mode (Recommended First Step):**

        ```bash
        python main.py --phase swap \
          --swap-mode pt-to-dgt \
          --plan-file migration_plan.json \
          --regions us \
          --table-ids my-data-project.my_dataset.customers \
          --dry-run \
          --report-file swap_dry_run_report.md \
          --log-file swap_dry_run.log
        ```

    *   **Mode 1 (`pt-to-dgt`): Swap Specific Table(s) (Interactive Confirmation
        by Default):**

        ```bash
        python main.py --phase swap \
          --swap-mode pt-to-dgt \
          --plan-file migration_plan.json \
          --regions us \
          --table-ids my-data-project.my_dataset.customers \
          --backup-dir ./schema_backups \
          --report-file swap_report.md \
          --log-file swap.log
        ```

    *   **Mode 1 (`pt-to-dgt`): Swap Across Multiple Projects, Datasets, and
        Tables (All Matching Tables Within the Specified Scopes Are Migrated):**

        ```bash
        python main.py --phase swap \
          --plan-file migration_plan.json \
          --table-project-ids data-project-1 \
          --dataset-ids data-project-2.finance_ds data-project-2.hr_ds \
          --table-ids data-project-3.sales_ds.orders \
          --regions us \
          --backup-dir ./schema_backups \
          --report-file swap_report.md
        ```

    *   **Rollback Option A (Recommended - Automated Surgical Rollback via Mode
        2 `--swap-mode dgt-to-pt`):** Reverses only the mapped `policyTags` and
        `dataGovernanceTagsInfo` fields on the current live table schema (across
        single or multiple tables, datasets, or projects) while preserving any
        unrelated schema changes—such as newly added columns, type widening, or
        updated descriptions—made after the initial cutover:

        ```bash
        # 1. Recommended: Preview rollback diff in dry-run mode first
        python main.py --phase swap \
          --swap-mode dgt-to-pt \
          --plan-file migration_plan.json \
          --regions us \
          --table-ids my-data-project.my_dataset.customers \
          --dry-run \
          --report-file rollback_dry_run_report.md

        # 2. Execute automated rollback (with schema diff, anti-corruption check, and confirmation)
        python main.py --phase swap \
          --swap-mode dgt-to-pt \
          --plan-file migration_plan.json \
          --regions us \
          --table-ids my-data-project.my_dataset.customers \
          --backup-dir ./schema_backups \
          --report-file rollback_report.md \
          --log-file rollback.log
        ```

    *   **Rollback Option B (Manual Point-in-Time Schema Restore via `bq update`
        Without Using the Migration Tool):** Performs a direct manual table
        schema update using the `bq update` CLI and the restore-ready pre-swap
        backup file saved before cutover (which carries explicit empty
        `"dataGovernanceTagsInfo": {"dataGovernanceTags": {}}` on swapped leaf
        columns so BigQuery clears attached Data Governance Tags while restoring
        Policy Tags), without invoking the migration script (useful for
        immediate single-table recovery during the cutover window if
        `migration_plan.json` is unavailable, with the trade-off that it
        overwrites any unrelated schema changes made after the backup was
        captured):

        ```bash
        bq update my-data-project:my_dataset.customers \
          ./schema_backups/pt_to_dgt/my-data-project/my_dataset/customers.json
        ```

*   **Arguments:**

    *   `--phase swap`: **(Required)** Specifies that the swap phase should be
        run.
    *   `--swap-mode <pt-to-dgt|dgt-to-pt>`: **(Optional)** Swap direction.
        Choices: `pt-to-dgt` (Mode 1, default: forward migration from Policy
        Tags to Data Governance Tags) or `dgt-to-pt` (Mode 2: automated rollback
        from Data Governance Tags back to Policy Tags).
    *   `--plan-file <PATH>`: **(Required)** Path to the migration plan JSON
        file (`.json`) generated by `--phase plan`.
    *   `--table-project-ids <PROJECT_ID ...>`: **(At least one of
        `--table-project-ids`, `--dataset-ids`, or `--table-ids` is Required)**
        One or more standard project IDs (space- or comma-separated; legacy
        domain-scoped `example.com:project` IDs are not supported) to scan for
        datasets and tables with Policy Tags (Mode 1) or Data Governance Tags
        (Mode 2) (default: `None`).
    *   `--dataset-ids <DATASET ...>`: **(Optional)** One or more dot-separated
        dataset identifiers (`<project_id>.<dataset_id>`, space- or
        comma-separated; colon-separated and domain-scoped IDs are rejected) to
        scan for tables with Policy Tags (Mode 1) or Data Governance Tags
        (Mode 2) (default: `None`).
    *   `--table-ids <TABLE ...>`: **(Optional)** One or more dot-separated
        table identifiers (`<project_id>.<dataset_id>.<table_id>`, space- or
        comma-separated; colon-separated and domain-scoped IDs are rejected) to
        inspect and swap or roll back (default: `None`).
    *   `--regions <REGION ...>`: **(Required)** Restricts table discovery
        (including `INFORMATION_SCHEMA.COLUMN_FIELD_PATHS` pre-filtering when
        scanning `--table-project-ids`) and schema swapping strictly to datasets
        and tables located in the specified region(s) (space- or
        comma-separated, e.g., `us`, `eu`, `us-central1`) across all scope flags
        (`--table-project-ids`, `--dataset-ids`, and `--table-ids`).
    *   `--execution-project <ID>`: **(Optional)** Single Google Cloud project
        ID used to execute and bill BigQuery `INFORMATION_SCHEMA` query jobs
        (`COLUMN_FIELD_PATHS` pre-filtering and `EFFECTIVE_PROJECT_OPTIONS`
        checks) when the caller lacks `bigquery.jobs.create` in the target table
        project(s) (defaults to each scanned table project).
    *   `--dry-run`: **(Optional, Strongly Recommended First)** Preview all
        table / column swaps or rollbacks, unified schema diffs, anti-corruption
        checks, and live Google Cloud enforcement parity verification without
        updating any BigQuery table schemas or writing backup files (default:
        `False`).
    *   `--backup-dir <DIR>`: **(Optional)** Directory to save original table
        schema backup JSON files under
        `<backup_dir>/pt_to_dgt/<project>/<dataset>/<table>.json` and
        `<backup_dir>/dgt_to_pt/<project>/<dataset>/<table>.json` before
        patching (default: `schema_backups`). Verified writable at startup (when
        not `--dry-run`); if creating `--backup-dir` or writing a backup file
        fails (or is blocked by `--overwrite` protection), the tool aborts
        before modifying any table schema.
    *   `--skip-confirmation`: **(Optional)** Bypass the pre-swap limitations &
        checklist acknowledgment prompt, interactive confirmation prompts before
        updating each table schema, and interactive file/backup-overwrite
        confirmation prompts when `--overwrite` is also set (default: `False`).
    *   `--allow-parity-discrepancy`: **(Optional)** Allow proceeding with the
        schema swap even if pre-swap enforcement parity verification detects
        discrepancies between the source Policy Tag and target DGT / V2 Data
        Policies (default: `False`, blocks the swap when discrepancies exist).
    *   `--skip-default-dp-org-check`: **(Optional)** In forward `pt-to-dgt`
        swaps, skip querying `INFORMATION_SCHEMA.EFFECTIVE_PROJECT_OPTIONS` to
        inspect Organization `default_data_policy_projects` (verifying Mode 1
        central Data Policy project registration and checking Organization
        default Data Policy projects for conflicting V2 policies across Mode 1
        and Mode 2) when the executing principal lacks `bigquery.config.get` and
        you have verified the Organization setting manually (default: `False`;
        all other parity and Mode 1 table-project override checks still run).
    *   `--allow-unresolved-plan-warnings`: **(Optional)** In forward
        `pt-to-dgt` mode, allow proceeding even if `--plan-file` still contains
        unresolved `[ACTION REQUIRED]` warnings (default: `False`, blocks
        upfront with `BLOCKED_UNRESOLVED_PLAN_WARNINGS` and exit code `1`;
        `dgt-to-pt` rollback is never blocked by plan warnings).
    *   `--halt-on-error`: **(Optional)** Halt execution immediately on the
        first API error, parity block, or schema corruption safeguard (default:
        `False`).
    *   `--report-file <PATH>`: **(Optional)** Output file for the Markdown
        (`.md`) swap or dry-run report (includes summary counts, per-table
        status, parity discrepancies, rollback commands, and unified schema
        diffs). If omitted, the report is printed to `stdout` (default: `None`).
    *   `--log-file <PATH>`: **(Optional)** Output file for timestamped
        execution logs (`.log`; always logs full unified schema diffs and parity
        check results; default: `None`, logs to `stderr` only).
    *   `--overwrite`: **(Optional)** Allow overwriting existing non-empty
        output files (`--report-file`, `--log-file`, and schema backup JSON
        files in `--backup-dir`). Default: `False` (aborts if an output or
        backup file already exists; when `--overwrite` is set, prompts
        interactively per existing file unless `--skip-confirmation` is also
        passed).

## Migration Tool & Platform Limitations

Before running a production migration, review the following architectural
limitations and system design differences between Policy Tags (PT) and Data
Governance Tags (DGT). Unlike temporary feature gaps, these items reflect
platform design boundaries and system quotas. Customers affected by them must
understand the behavior and take the specified re-architecture or operational
actions before or during migration; if you choose not to take those actions,
treat the limitation as a migration blocker and hold off migration:

1.  **Google Cloud Organization Requirement, Inherited Ancestor IAM, Conditional
    IAM (CEL), and Privileged Access Manager (PAM):**
    *   **Organization Membership:** Data Governance Tags
        (`purpose = DATA_GOVERNANCE`) and V2 Data Policies require every
        participating tag, Data Policy, and BigQuery table project to belong to
        a Google Cloud Organization resource; standalone (organizationless)
        projects are not supported.
    *   **Policy Tags vs. Data Governance Tags IAM Evaluation:** In legacy
        Policy Tags, `Fine-Grained Reader` grants at Organization, Folder, or
        Project levels are inherited down the resource hierarchy, and IAM
        bindings can carry IAM Condition (CEL) expressions or temporary
        Privileged Access Manager (PAM) grants on ancestor resources. In Data
        Governance Tags, column access is evaluated strictly against the inline
        `grantees` list on each V2 Data Policy—ancestor IAM bindings are not
        inherited, CEL conditions are not supported on inline `grantees`, and
        ancestor PAM grants are not evaluated unless PAM grants temporary
        membership in a Google Group listed in `grantees`.
    *   **Action Required:** Convert ancestor-level `Fine-Grained Reader` grants
        into direct Taxonomy or Policy Tag grants before running `--phase plan`
        (or add those principals or Google Groups to V2 Data Policy `grantees`
        in `plan.json` before `--phase create`), and restructure any CEL
        conditional or PAM just-in-time grants around dedicated Google Groups
        before migrating affected tables. During `--phase analyze` and
        `--phase plan`, source IAM bindings carrying CEL conditions are omitted
        fail-closed with an `[ACTION REQUIRED]` warning rather than being
        promoted to permanent unconditional `grantees`.
2.  **Organization-Level Custom Roles (`organizations/<org>/roles/<role>`):**
    Project-level `roles/iam.roleViewer` cannot read organization-level custom
    roles; grant `roles/iam.organizationRoleViewer` to the user or service
    account principal running the migration script if your policy tags use
    custom organization roles. If a custom role lookup fails, the analyzer omits
    principals in that role (fail-closed) and records an `[ACTION REQUIRED]`
    warning (which propagates into `plan.json` during `--phase plan` and blocks
    `--phase create` and forward `--phase swap` until resolved or explicitly
    overridden).
3.  **Views, Authorized Views/Datasets/Routines, Materialized Views, Table
    Clones, Snapshots, and Time Travel:**
    *   **Views & Materialized Views (`VIEW`, `MATERIALIZED_VIEW`):**
        Automatically skipped during dataset and project scanning in
        `--phase swap`—meaning the tool inspects the BigQuery object type and
        passes over views and materialized views without calling `tables.patch`
        on them—because BigQuery enforces Column-Level Security on the
        underlying base tables.
    *   **Authorized Views, Authorized Datasets & Authorized Routines:** Unlike
        legacy Policy Tags, BigQuery V2 Data Policies on Data Governance Tags do
        **not** delegate column-level access through Authorized Views or
        Authorized Datasets—querying users receive `403 Access Denied` unless
        their own user or Google Group principal is granted access directly in
        V2 Data Policy `grantees` (`DR_WARN_04`). In addition, V2 Data Policy
        `grantees` reject BigQuery Authorized Routines (`400 Invalid Argument`,
        flagged with `[ACTION REQUIRED]` in `--phase plan`). Re-architect
        affected consumers to grant authorized end-user groups directly in
        `grantees` (or keep those specific base tables on Policy Tags until
        re-architected).
    *   **Table Clones & Cross-Project Copies (`bq cp`):** Table Clones are
        independent mutable `TABLE` resources whose schemas (including Policy
        Tags and Data Governance Tags) are copied at creation time;
        `--phase swap` discovers and swaps Table Clones alongside standard base
        tables. When using **Mode 2** (`--target-table-dp-project-ids` in
        `--phase plan`, where V2 Data Policies live in each table's parent
        project), ensure any destination project receiving a cross-project
        `bq cp`, `CREATE TABLE ... CLONE`, or `CREATE SNAPSHOT TABLE` already
        contains matching regional V2 Data Policies—otherwise the copied Data
        Governance Tag has no policies in the destination project and defaults
        to **Fail-Open (Default Allow)**.
    *   **Table Snapshots (`SNAPSHOT`) vs. Time Travel
        (`FOR SYSTEM_TIME AS OF`):** BigQuery provides two distinct historical
        data mechanisms:
        1.  **Time Travel (`FOR SYSTEM_TIME AS OF`):** Built-in automatic
            point-in-time query window (2 to 7 days) on standard tables. During
            the 2–7 day window after `--phase swap`, historical
            `FOR SYSTEM_TIME AS OF <pre_swap_timestamp>` queries evaluate
            **both** the historical Policy Tag and the current Data Governance
            Tag.
        2.  **Table Snapshots (`SNAPSHOT`):** Standalone, read-only table
            artifacts created explicitly (for example, via
            `CREATE SNAPSHOT TABLE` or `bq cp --snapshot`) that can be retained
            for arbitrary durations (months or years). Because Table Snapshots
            are immutable read-only artifacts whose schemas cannot be modified
            via `tables.patch`, `--phase swap` automatically skips `SNAPSHOT`
            tables during dataset and project discovery, and existing snapshots
            retain the Policy Tag bindings they had when the snapshot was
            created. See Item 6 in the
            [Customer Self-Protection Checklist](#customer-self-protection-checklist-operational-cutover-precautions)
            for mandatory retention rules before deleting legacy Policy Tags.
4.  **Scale, Quota & Organization Config Limits:**
    *   **Table Discovery Scale (`10,000+` Tables):** When running
        `--phase swap` across a project with thousands of tables where only a
        subset use Policy Tags or Data Governance Tags, the tool automatically
        pre-filters candidate tables in the required `--regions` via
        `region-<region>.INFORMATION_SCHEMA.COLUMN_FIELD_PATHS` (in both
        `pt-to-dgt` mode using `ARRAY_LENGTH(policy_tags) > 0` and `dgt-to-pt`
        mode using `ARRAY_LENGTH(data_governance_tags) > 0`) instead of
        inspecting every dataset and table sequentially.
    *   **`1,000` Tag Keys per Project & `1,000` Tag Values per Tag Key:**
        Google Cloud Resource Manager limits each project
        (`--target-dgt-project-id`) to **`1,000` total Tag Keys** (shared across
        standard IAM Tag Keys and `DATA_GOVERNANCE` Tag Keys in that project)
        and each Tag Key to **`1,000` Tag Values** across all hierarchy depths.
        Both `--phase plan` and `--phase create` validate these limits upfront.
    *   **`1,000` V2 Data Policies per `(Project, Region, DG Tag Key)` Limit:**
        BigQuery limits each project and region to **`1,000` V2 Data Policies
        associated with a single Data Governance Tag Key**. Because each
        access-controlled Policy Tag can generate multiple V2 Data Policies
        (default-deny, raw reader parity, and data masking policies), large
        taxonomies with hundreds of tags can approach this limit. Run
        `--phase plan` (`Phase 1b`) to verify exact counts; if exceeded,
        consolidate child reader grants onto parent tags, prune unused tags or
        obsolete masking policies, or split large taxonomies into smaller
        domain-specific taxonomies.
    *   **`500` Distinct IAM Principals & `100` Groups per V2 Data Policy:**
        BigQuery V2 Data Policies compile `grantees` into IAM v3 access policies
        supporting at most **`500` distinct IAM principals** and **`100`
        distinct `principalSet://` group principals** per V2 Data Policy
        (whereas legacy IAM v1 on Policy Tags allowed up to `1,500` principals).
        `--phase plan` and `--phase create` flag policies exceeding either limit
        with `[ACTION REQUIRED]`; consolidate individual user grants into Google
        Groups or combine narrow groups into parent groups before Phase 2a.
    *   **`1,000` Data Governance Tags per Table:** BigQuery limits each table
        to **`1,000` unique Data Governance Tags** on `tables.patch` updates
        (`--phase swap` aborts schemas exceeding `1,000` unique tags with
        `ABORTED_SCHEMA_CORRUPTION`) and **`1,000` total column tag bindings**
        in SQL `CREATE TABLE` DDL.
    *   **At Most `1` Central Project per Region in Organization
        `default_data_policy_projects` (Mode 1) & CRR Ordering:** BigQuery
        Organization settings (`ALTER ORGANIZATION SET OPTIONS`) accept at most
        **`1`** project in `default_data_policy_projects` per region; if that
        slot is already used by another central governance project, either share
        that project in Mode 1 (`--target-default-dp-project-id`) or use Mode 2
        (`--target-table-dp-project-ids`). In addition, always complete Phases
        1–3 in your primary region **before** enabling Cross-Region Replication
        on datasets (pre-existing secondary CRR replicas referencing a Data
        Governance Tag block `CreateDataPolicy` for that tag).
5.  **Custom Masking Routine Constraints (`data_masking_policy.routine`) &
    Multi-Routine Conflicts:**
    *   **Same-Project & Data-Type Constraints:** BigQuery Data Policy Service
        allows a V2 Data Policy in `<target_project_id>` to reference a global
        Data Governance Tag (`data_governance_tag.key`) owned by a different
        project (`--target-dgt-project-id`), but strictly requires any Custom
        Masking Routine
        (`projects/<routine_project>/datasets/<dataset>/routines/<routine>`) to
        reside in the **exact same project** as the V2 Data Policy (`400
        INVALID_ARGUMENT: All referenced resources must reside in the same
        project.`), and does not support custom masking routines on `GEOGRAPHY`
        columns.
    *   **Conflicting Custom Masking Routines at the Same Tag Depth:** Multiple
        predefined masking rules (`ALWAYS_NULL`, `DEFAULT_MASKING_VALUE`,
        `SHA256`, etc.) resolve automatically by restrictiveness. However, if a
        querying principal without unmasked (`RAW_DATA_ACCESS_POLICY`) access
        matches **two or more custom masking routine policies** at the winning
        tag depth, BigQuery fails the query closed (`Found multiple conflicting
        data policies with custom masking expressions.`). `--phase plan` flags
        direct overlapping grantees across sibling custom masking routine
        policies with `[ACTION REQUIRED]` (and emits an advisory warning when
        sibling custom masking routine policies use separate Google Groups whose
        memberships could overlap).
    *   **How the Tool Protects You on Cross-Project Routines:** During
        `--phase plan`, whenever `<routine_project> != <target_project_id>` (for
        example, in Mode 2 `--target-table-dp-project-ids` across multiple table
        projects, or in Mode 1 when `--target-default-dp-project-id` differs
        from the routine's project), the planner attaches an `[ACTION REQUIRED]`
        warning, and `--phase create` blocks by default
        (`BLOCKED_UNRESOLVED_PLAN_WARNINGS`) and validates same-project routine
        residency during pre-flight checks.
    *   **Action Required:** Before running `--phase create`, resolve any
        overlapping custom-routine grantees so each masked reader matches at
        most one custom masking routine per tag, and for cross-project routines
        either:
        1.  Create an equivalent `DATA_MASKING` routine in `<target_project_id>`
            (in the same region), update
            `api_payload.data_masking_policy.routine` on that entry in
            `plan.json` to
            `projects/<target_project_id>/datasets/<dataset>/routines/<routine>`,
            and clear its `[ACTION REQUIRED]` warning, or
        2.  If no tables in `<target_project_id>` use that Tag Value, remove
            that `<target_project_id>` entry from
            `phase_2_resource_manifest.data_policies_v1_to_data_policies_v2` in
            `plan.json`.
6.  **Legacy Domain-Scoped Projects (`example.com:my-project`) Not Supported:**
    *   **Limitation:** Legacy Google Cloud project IDs containing a domain
        prefix and colon (`:`, such as `example.com:my-project`) are not
        supported by this migration tool and are rejected across all phases
        (`Exit Code 2`). Only standard project IDs without colons (for example,
        `my-project`) are supported.

## Customer Self-Protection Checklist & Operational Cutover Precautions

Follow these operational steps before and during cutover to protect your
workloads against accidental access changes, stale snapshots, or broken
rollbacks:

1.  **Rehearse Full Round-Trip (`pt-to-dgt` -> `dgt-to-pt` -> `pt-to-dgt`) in a
    Test Environment & Always Run `--dry-run` First:** Before running
    `--phase swap` in production, rehearse the complete forward swap, rollback,
    and re-swap cycle in a non-production test environment, and always run
    `--dry-run` before executing `create`, `swap`, or `delete`.
2.  **Source Taxonomy Freeze Window Between Phase 1 (`plan`) and Phase 3
    (`swap`):** Phase 3 (`--phase swap`) validates live target DGTs and V2 Data
    Policies against the `plan.json` snapshot generated in Phase 1b (it does not
    re-query source Data Catalog Policy Tags). Freeze IAM and masking changes on
    source Policy Tags after generating `plan.json`, or re-run `--phase plan`
    and `--phase create` before `--phase swap` if source policies changed.
3.  **IAM & Tag Propagation Soak Window (Wait 5–7 Minutes Before Phase 3):**
    Google Cloud Resource Manager Tags and BigQuery V2 Data Policy `grantees`
    are eventually consistent (typically 1–7 minutes). Wait at least 5–7 minutes
    after `--phase create` completes before running `--phase swap` so queries on
    swapped tables immediately see the new policies.
4.  **Freeze Concurrent Table DDL (`ALTER TABLE`) During Phase 3 Cutover:**
    `--phase swap` performs an `etag`-checked read-modify-write cycle
    (`tables.get` -> validation -> backup write -> `tables.patch` with
    `If-Match`). If a concurrent `ALTER TABLE` modifies a table during an
    interactive confirmation prompt, `tables.patch` fails safely with
    `412 Precondition Failed` (`FAILED`), and retrying requires `--overwrite`
    (or a fresh `--backup-dir`) because the pre-patch backup file was already
    written. Pause concurrent `ALTER TABLE` schema changes on target tables
    during cutover, and pass `--skip-confirmation` when running multi-table
    batch swaps.
5.  **Cross-Field Invariants When Manually Editing `plan.json`:** If you
    customize a Tag Key or Tag Value `short_name` in `plan.json` before Phase 2,
    you must update all cross-referenced fields in lockstep (`api_payload`,
    `namespaced_name`, child `parent_namespaced_name`,
    `dg_tag_value_namespaced_name`, `data_governance_tag.key`/`value`, and every
    matching entry in `phase_3_binding_map`), and never remove the
    `_default_deny` suffix from default-deny policies. See the
    [Phase 1b Plan guide](phase_1b_plan.md) for the complete field dependency
    checklist.
6.  **Hold Off Deleting Legacy Policy Tag Taxonomies, Policy Tags, and V1 Data
    Policies If You Depend on Table Snapshots (`SNAPSHOT`) or Time Travel
    (`FOR SYSTEM_TIME AS OF`):**
    *   **Why:** Swapping a base table's schema in `--phase swap` only updates
        the live base table. Any existing **Table Snapshots (`SNAPSHOT`)**
        created before the swap are immutable read-only table artifacts that
        permanently retain their original Policy Tag bindings, and historical
        **Time Travel (`FOR SYSTEM_TIME AS OF`)** queries (up to 7 days) or
        emergency rollbacks (`--swap-mode dgt-to-pt`) depend on your original
        Policy Tags and V1 Data Policies remaining intact.
    *   **Self-Protection Rule:** If your workloads or compliance policies
        depend on pre-migration Table Snapshots or Time Travel, **HOLD OFF
        deleting your source Policy Tag taxonomies, Policy Tags, and V1 Data
        Policies** until:
        1.  Your dataset's full Time Travel window (up to 7 days after
            `--phase swap`) has elapsed and cutover is finalized, **AND**
        2.  All pre-migration Table Snapshots (`SNAPSHOT`) have either expired
            or been recreated from the newly migrated DGT base tables.
