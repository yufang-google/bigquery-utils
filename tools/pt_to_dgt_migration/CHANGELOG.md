# Changelog

**Phase Guides:** [Overview (`README.md`)](./README.md) |
[Phase 1a: Analyze](./phase_1a_analyze.md) |
[Phase 1b: Plan](./phase_1b_plan.md) | [Phase 2a: Create](./phase_2a_create.md)
| [Phase 2b: Delete](./phase_2b_delete.md) |
[Phase 3: Swap & Rollback](./phase_3_swap.md) | **Changelog**

All notable changes to the BigQuery Policy Tag to Data Governance Tag migration
tool are documented in this file.

This tool follows [Semantic Versioning](https://semver.org/)
(`MAJOR.MINOR.PATCH`):

*   **`MAJOR`** (`2.0.0`, `3.0.0`): Breaking CLI flag changes, workflow changes,
    or `plan.json` schema version upgrades (`metadata.schema_version`).
*   **`MINOR`** (`1.1.0`, `1.2.0`): Backward-compatible new features, flags, or
    migration helpers that keep existing `plan.json` files compatible.
*   **`PATCH`** (`1.0.1`, `1.0.2`): Backward-compatible bug fixes, guardrail
    improvements, and documentation updates.

Check your local script version at any time with:

```bash
python3 main.py --version
```

Each release is pinned with an immutable Git tag named
`pt-to-dgt-migration-v<MAJOR.MINOR.PATCH>` (for example,
`pt-to-dgt-migration-v1.0.0`) so you can compare versions or check out a
specific release snapshot.

## [1.0.0] - 2026-11-19

Initial Stage 1 release implementing the end-to-end 3-Phase migration workflow
(Analyze, Plan, Create, Delete, and Atomic Swap & Rollback) for migrating
BigQuery Column-Level Security from regional Data Catalog Policy Tags to global
Cloud Resource Manager Data Governance Tags and BigQuery V2 Data Policies.

### Added

*   **Phase 1a: Read-Only Discovery & Auditing (`--phase analyze`):**
    *   `--analyze-type static-taxonomy` (default): Discovers source Policy Tag
        taxonomies, hierarchical Policy Tags, fine-grained reader IAM bindings
        (including custom IAM role inspection), and V1 Data Policies across
        `--taxonomy-project-id` and `--regions`, classifying each taxonomy as
        Access Control (Default Deny) or Classification-Only (Default Allow).
    *   `--analyze-type static-dgt`: Inventories existing global Data Governance
        Tag Keys, hierarchical Tag Values, and regional BigQuery V2 Data
        Policies (with full grantee inspection) across `--dgt-project-id` and
        `--data-policy-v2-project-ids`.
    *   `--analyze-type column-binding`: Scans regional BigQuery
        `INFORMATION_SCHEMA.COLUMN_FIELD_PATHS` views across
        `--table-project-id` to inventory column-level attachments across Policy
        Tags, Data Governance Tags, and direct column-level Data Policies (with
        optional `--verbose-bindings` column listing capped at `1,000` columns
        per tag or policy with explicit truncation notices).
*   **Phase 1b: Deterministic Migration Planning (`--phase plan`):**
    *   Generates a machine-readable `plan.json` blueprint
        (`metadata.schema_version: 1`) and a Markdown summary report mapping
        each regional taxonomy 1:1 to a separate global Data Governance Tag Key
        (Separation-Only strategy for Cross-Region Replication compatibility).
    *   Supports both V2 Data Policy placement architectures via explicit,
        mutually exclusive flags: **Mode 1** (`--target-default-dp-project-id`
        for a single central Organization default Data Policy project) and
        **Mode 2** (`--target-table-dp-project-ids` for per-table-project V2
        Data Policies).
    *   Synthesizes a fail-closed `_default_deny` `RAW_DATA_ACCESS_POLICY`
        (`grantees: []`) on every Tag Value in an access-controlled taxonomy,
        maps taxonomy-level raw readers onto root Tag Values and masked non-root
        Tag Values for authorization parity, converts IAM v1 members to IAM v3
        V2 Data Policy `grantees`, and translates V1 masking and raw-access
        policies into V2 Data Policies.
    *   Detects and flags service quota limits (`1,000` Tag Keys per project,
        `1,000` Tag Values per Tag Key, `1,000` V2 Data Policies per Tag Key,
        `500` principals and `100` groups per V2 Data Policy), naming collisions
        (`--collision-resolution counter|from_region`), unsupported grantees,
        and Disaster Recovery prerequisites (`DR_WARN_01` through `DR_WARN_04`).
*   **Phase 2a: Idempotent Resource Provisioning (`--phase create`):**
    *   Creates global Data Governance Tag Keys, hierarchical Tag Values, and
        regional V2 Data Policies from `plan.json` in batch (`--all`) or
        single-resource (`--resource-type` + `--resource-name`) mode, skipping
        already-existing resources cleanly.
    *   Supports `--dry-run` preview and blocks upfront when `plan.json`
        contains unresolved `[ACTION REQUIRED]` warnings (unless overridden with
        `--allow-unresolved-plan-warnings`).
*   **Phase 2b: Safe Single-Resource Teardown (`--phase delete`):**
    *   Deletes one specified resource at a time (`dg-tag-key`, `dg-tag-value`,
        or `data-policy-v2`) with `--dry-run` preview and dependency checks,
        intentionally omitting bulk `--all` deletion.
    *   Requires explicit `--allow-fail-open-policy-delete` before deleting a
        live V2 Data Policy so columns cannot accidentally become Fail-Open.
*   **Phase 3: Atomic Table Schema Swap & Rollback (`--phase swap`):**
    *   Atomically swaps mapped Policy Tags with Data Governance Tags on
        BigQuery table schemas (including nested `RECORD` / `STRUCT` fields at
        any depth) via `--swap-mode pt-to-dgt` (forward cutover) and supports
        automated rollback to Policy Tags via `--swap-mode dgt-to-pt`.
    *   Includes `--dry-run` unified schema diff preview, pre-swap live
        enforcement parity verification (checking Tag Keys, Tag Values, V2 Data
        Policies, inline `grantees`, Organization `default_data_policy_projects`
        configuration, and companion project conflicts), recursive schema
        anti-corruption verification, restore-ready per-table JSON schema
        backups (`--backup-dir`), and post-patch verification with automatic
        compensating restore if target tags are not persisted.
*   **Cross-Phase CLI, Compatibility & Safety Guardrails:**
    *   Unified CLI (`main.py`) with `--version`, `--dry-run`, decoupled
        `--overwrite` and `--skip-confirmation`, `--halt-on-error`,
        `--execution-project`, `--log-file`, `--debug`, and custom HTTPS API
        endpoint flags for regional and VPC Service Controls environments.
    *   Automatic authenticated REST `/v2/` fallback when local Python SDK
        installations lack newer V2 Data Policy proto fields.
    *   Strict fail-closed input validation rejecting legacy domain-scoped (`:`)
        project IDs, non-HTTPS endpoints, and unsafe output symlinks.
*   **Documentation & Unit Tests:**
    *   Complete customer documentation suite (`README.md`,
        `phase_1a_analyze.md`, `phase_1b_plan.md`, `phase_2a_create.md`,
        `phase_2b_delete.md`, `phase_3_swap.md`, and `CHANGELOG.md`) plus unit
        test suites covering all modules.

### Known Limitations (Stage 1)

*   **Atomic Schema Swap Only:** Stage 1 replaces Policy Tags with Data
    Governance Tags atomically per column via `--phase swap`. Column-level
    coexistence (dual-binding via `--phase bind`) is planned for a future
    release.
*   **Workload & Platform Prerequisites:** Certain workloads (such as full-table
    overwrite load jobs, external tables, and full-rebuild tables with tagged
    nested `STRUCT` subfields) should hold off migrating until full platform
    support is available. See
    [Feature Gaps Between Policy Tags (PT) and Data Governance Tags (DGT)](./README.md#feature-gaps-between-policy-tags-pt-and-data-governance-tags-dgt)
    in `README.md` for the full pre-migration checklist.
