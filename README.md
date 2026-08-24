# chadlands-validator

Deterministic validation layer for the Chadlands Markdown Vault.

The validator has **no campaign intelligence**. It validates mechanically
provable invariants over files, metadata, declared state boundaries, and
reconciliation manifests. It never interprets prose, adjudicates evidence,
infers game state, or performs reconciliation. Its only vault write is the
generated health report.

## Build

```sh
cargo build --release
```

Requires Rust 1.70+. Pure Rust dependencies; no C libraries beyond the
default linker.

## Usage

### Synchronous check (workflow contract)

```sh
chadlands-validator check --vault /path/to/vault
chadlands-validator check --vault /path/to/vault --changed-files "30 World/People/Foo.md,40 Civilization/Institutions/Bar.md"
chadlands-validator check --vault /path/to/vault --no-report --format json
```

Exit codes:
- `0` — no ERROR findings
- `1` — ERROR findings present
- `2` — operational failure

### File-watch mode

```sh
chadlands-validator watch --vault /path/to/vault
chadlands-validator watch --vault /path/to/vault --debounce-ms 500
```

Debounced validation after curated vault files change. Regenerates the
health report. The report directory is excluded from triggers, so report
writes never recursively re-trigger validation.

### Print resolved boundary

```sh
chadlands-validator boundary --vault /path/to/vault
```

Prints the machine-readable current-state boundary as JSON (useful for
workflow consumption).

## Execution model

1. **File-watch mode** — debounced validation after curated vault files
   change; regenerates a durable health report; generated validator outputs
   do not recursively trigger validation.

2. **Synchronous workflow mode** — Chadlands mutating workflows explicitly
   invoke validation after writes. A workflow may claim clean completion
   only when validation succeeds for the exact resulting vault revision.

Validation is a full-vault scan each run (sub-100ms for 1700+ files in
release mode). Incremental validation is architecturally possible but not
yet implemented.

## State boundary

The validator reads the machine-readable current-state boundary from
`00 System/State Boundary.md` (configurable). If absent, it derives the
boundary from live runtime records and emits `CHAD-STATE-001` (WARN).

Required boundary keys:

```yaml
current_turn:
current_year:
last_resolved_year:
current_source_cursor:
canonical_materialized_cursor:
```

## Reconciliation manifests

Every reconciliation that advances `canonical_materialized_cursor` must
emit a machine-readable manifest:

```yaml
type: reconciliation-manifest
manifest_id: reconcile-2026-08-16
canonical_materialized_cursor: 2856
source_cursor: 2856
subjects:
  - path: 30 World/People/Tovan Dorn.md
    disposition: UPDATED
  - path: 40 Civilization/Institutions/Annual Reckoning.md
    disposition: REVIEWED — NO MATERIAL CHANGE
  - path: 30 World/Places/Skarn.md
    disposition: BLOCKED — EXTERNAL
    reason: collector has not delivered the raw packet
```

Each subject must have exactly one disposition:
- `UPDATED`
- `REVIEWED — NO MATERIAL CHANGE`
- `BLOCKED — EXTERNAL` (requires an explicit `reason`)

## Rule ID table

| Rule ID | Severity | Description |
|---------|----------|-------------|
| CHAD-YEAR-001 | ERROR | last_resolved_year exceeds highest Chronicle year |
| CHAD-YEAR-002 | ERROR | Resolved Chronicle year beyond declared boundary |
| CHAD-YEAR-003 | ERROR | Future evidence year value |
| CHAD-YEAR-004 | ERROR | Chronicle gap in resolved range |
| CHAD-YEAR-005 | WARN | Chronicle year field/filename mismatch |
| CHAD-FRESH-001 | ERROR | Active canonical reviewed_through below materialized cursor |
| CHAD-FRESH-002 | ERROR | Active canonical missing reviewed_through_cursor |
| CHAD-OWNER-001 | ERROR | Missing required structural field |
| CHAD-OWNER-002 | WARN | Unresolved value where schema permits |
| CHAD-OWNER-003 | ERROR | Unresolved value where schema requires resolution |
| CHAD-CURSOR-001 | ERROR | source_cursor exceeds reviewed_through_cursor |
| CHAD-CURSOR-002 | ERROR | Cursor beyond current_source_cursor (future) |
| CHAD-CURSOR-003 | ERROR | Canonical note at/above manifest frontier missing from manifest |
| CHAD-CURSOR-004 | ERROR | Manifest subject below frontier after claimed disposition |
| CHAD-CURSOR-005 | ERROR | Runtime materialization claim beyond canonical support |
| CHAD-CURSOR-006 | ERROR | Invalid/missing manifest disposition or duplicate subject |
| CHAD-CURSOR-007 | ERROR | BLOCKED — EXTERNAL without reason |
| CHAD-CURSOR-008 | ERROR | Manifest cursor exceeds evidence frontier |
| CHAD-CURSOR-009 | ERROR | Manifest subject path does not resolve |
| CHAD-IDENTITY-001 | ERROR | Duplicate canonical ID |
| CHAD-IDENTITY-002 | ERROR | Duplicate active canonical identity |
| CHAD-IDENTITY-003 | ERROR | Lead/owner equals second |
| CHAD-IDENTITY-004 | ERROR | Incompatible lifecycle/status (deceased + active) |
| CHAD-IDENTITY-005 | WARN | Name-collapse suspicion without alias declaration |
| CHAD-IDENTITY-006 | ERROR | Unresolved merge/alias collision |
| CHAD-SCHEMA-001 | ERROR | Unparseable/missing frontmatter (curated) |
| CHAD-SCHEMA-002 | ERROR/WARN | Missing required common field |
| CHAD-SCHEMA-003 | WARN | Status vocabulary violation |
| CHAD-SCHEMA-004 | ERROR | Lifecycle date ordering violation |
| CHAD-SCHEMA-005 | WARN | Missing required named section |
| CHAD-WORK-001 | ERROR | Multiple active workflows with same workflow_id |
| CHAD-LINK-001 | WARN | Broken wikilink in curated scope |
| CHAD-REF-001 | WARN | Unresolvable owner/authority reference |
| CHAD-PROT-001 | ERROR/WARN | Protected collector path modified |
| CHAD-STATE-001 | WARN | State boundary not exposed (derived) |
| CHAD-STATE-002 | WARN | Materialization frontier undeclared |
| CHAD-STATE-003 | ERROR | Boundary missing required key |
| CHAD-STATE-004 | ERROR | Boundary internal inconsistency |

## Configuration

Optional YAML config file (`--config`, or `00 System/Validation/validator.yml`
in the vault). All fields have sane Chadlands defaults.

```yaml
report_path: 00 System/Validation/Vault Health.md
boundary_path: 00 System/State Boundary.md
exclude_dirs: [.git, .obsidian, .trash, .OBSIDIANTEST]
protected_prefixes:
  - 70 Sources/Telegram
  - 70 Sources/Codex Snapshots
  - 70 Sources/Strategy Sessions/Raw Export
chronicle_dir: 20 Chronicle
chronicle_permitted_gaps: []
id_fields: [canonical_id, vault_node_id, permanent_registry_id]
unresolved_values: [MISSING, UNKNOWN, UNASSIGNED, BLOCKED]
required_fields:
  institution:
    - [owner, lead]
    - second
    - lifecycle
    - last_confirmed_year
    - reviewed_through_cursor
  project: [owner, lifecycle, status, reviewed_through_cursor]
  person: [status, last_confirmed_year, reviewed_through_cursor]
unresolved_permitted:
  institution: [owner, lead, second]
  project: [owner]
status_vocab:
  people: [active, last-confirmed, deceased, missing, protected, unknown, not-applicable]
  project: [draft, submitted, accepted, active, stalled, completed, failed, closed, superseded, unresolved]
  institution: [active, completed, closed, superseded, historical, deprecated, draft]
type_to_vocab_class:
  person: people
  god: people
  institution: institution
  service: institution
  project: project
  venture: project
  technology-node: project
required_sections:
  runtime-handoff: [Boundary]
severity_overrides: {}
max_findings_per_rule: 25
debounce_ms: 750
```

## Health report

Generated at `00 System/Validation/Vault Health.md` (configurable).
Machine-readable frontmatter plus compact findings grouped by severity
and rule ID. The report is valid only for `validated_revision`; workflows
must never treat an older green report as proof that subsequent writes are
healthy.

## Workflow contract

```
READ -> MUTATE -> VALIDATE -> READBACK/COMPLETE
```

If validation returns new ERRORs caused by the operation, repair them
before claiming completion. If ERRORs are pre-existing or outside
authorized scope, report them explicitly and finish as partial/debt-bearing.

## Non-goals

The validator does not:
- determine whether gameplay evidence is true
- infer whether a person remains alive, active, or in office
- advance `last_confirmed_year`
- infer lifecycle transitions
- choose between contradictory prose accounts
- promote proposals into results
- perform reconciliation
- repair files automatically
