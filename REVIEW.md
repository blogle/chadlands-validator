# Chadlands Validator — Independent Code Review

**Reviewer:** opencode (mimo-v2.5-pro)
**Date:** 2026-08-24
**Baseline:** origin/master (0eddb4b) vs HEAD (929c411)
**Diff scope:** 17 files changed, 5488 insertions(+), 10 deletions(-)

---

## 1. Verdict

**PASS WITH CONDITIONS**

The implementation is disciplined, deterministic, and architecturally sound. It correctly
distinguishes known/unknown/incomplete states, never mutates canonical records during
validation, and properly surfaces representation gaps rather than inventing state. The
source index bug (`parse(&rel)` instead of `parse(&raw)`) is masked by a fallback but
must be fixed before relying on frontmatter stripping in source files. The hardcoded
road-name lists are a maintainability risk that should be addressed before the technology
validation surface is trusted for autonomous reconciliation.

---

## 2. Score

```
Correctness / epistemic integrity:      21 / 25
Architecture / separation:             13 / 15
Determinism / data-boundary safety:     14 / 15
Rule / diagnostic design:               9 / 10
Migration quality:                      7 / 10
Tests:                                  7 / 10
Performance / scalability:              8 / 10
Maintainability / clarity:              4 / 5

TOTAL:                                  83 / 100
```

---

## 3. Declarative gates

| Gate | Result | Evidence | Notes |
|------|--------|----------|-------|
| G1 Deterministic execution | PASS | `source_index.rs:429-482` (normalize_text), `boundary.rs:52-59` (fnv1a). Two consecutive runs produce identical md5sum (`6e002c5265b82e06b8a5d66e2e63df5f`). No LLM/embedding/vector calls. | |
| G2 Normal validation non-mutating | PASS | `lib.rs:45-113` (validate writes only reports). `vault.rs:253` (evidence files read via probe, not written). Reports written to `00 System/Validation/` which is excluded from scanning (`vault.rs:155-164`). | |
| G3 Protected evidence immutable | PASS | `config.rs:248-255` (protected_prefixes). `rules/hygiene.rs:486-510` (CHAD-PROT-001). `migration.rs:192-213` (protected files skipped in plan/apply). Integration test `prot_001_changed_collector_path`. | |
| G4 Generated state non-authoritative | PASS | `report.rs:433-436` ("This report is non-authoritative and valid only for validated_revision"). Continuity report has `type: continuity-report` frontmatter. Reports excluded from vault scanning. | |
| G5 Negative conclusions require coverage | PASS | `continuity.rs:368-378` ("No overdue receipts detected among **0** machine-readable active roads. **Coverage incomplete:**..."). `continuity.rs:447-452` (capability: "No machine-readable capability records indexed. Dormancy analysis requires capability representation."). | |
| G6 Identity resolution deterministic/conservative | PASS | `source_index.rs:317-422` (exact match only: stable ID > title > alias). `source_index.rs:339-343` (ambiguous aliases excluded). Test `ambiguous_alias_resolves_to_none`. No fuzzy/edit-distance matching. | |
| G7 Materiality not inferred from prose | PASS | `source_index.rs:748-772` (seed_canonical_materiality uses only `source_cursor`, explicitly notes "reviewed_through_cursor is NOT materiality"). Receipt parsing is structured `[CL ...]` only. | |
| G8 Source chronology no epoch inference | PASS | `source_index.rs:520-599` (cursor epochs built only from explicit structured evidence: boundary, runtime records with cursor+turn+year). No wall-clock-to-game-year conversion. | |
| G9 Frontiers remain distinct | PASS | `continuity.rs:106-114` (boundary relationship classification: SOURCE FRONTIER vs STATE BOUNDARY vs CANONICAL MATERIALIZED). `cursor.rs:46-87` (CHAD-CURSOR-002 distinguishes stale boundary from genuinely unsupported cursor). | |
| G10 No destructive rollback on boundary failure | PASS | `cursor.rs:54-83` (CHAD-CURSOR-002 distinguishes "State Boundary may be stale" from "Correct the cursor"). Test `cursor_002_stale_boundary_remediation` verifies remediation text. | |
| G11 Representation gaps surfaced | PASS | `technology.rs:553-584` (TECH-MIG-004: "declares N child road(s) but resolves 0 machine-readable technology-road owners"). `continuity.rs:120-159` (receipt monitoring coverage: INCOMPLETE when road_count == 0). | |
| G12 Structured receipts optional | PASS | `source_index.rs:607-638` (receipt parsing is `[CL ...]` syntax, optional). Baseline architecture works with prose-only source (0 receipts parsed in production run). | |
| G13 Coverage extraction conservative | PASS | `source_index.rs:858-887` (proper-name candidates filtered by min_occurrences, min_distinct_messages, substring check, ALL-CAPS protocol filter). `coverage.rs:128-165` (CHAD-COVER-003 requires 10+ occurrences for lifecycle-shaped WARN). | |
| G14 Migration explicit/planned/safe/idempotent | PASS | `main.rs:74-88` (separate `MigrateFrontmatter` command with `--plan` and `--apply` flags). `migration.rs:192-213` (protected files excluded). `migration.rs:303-306` (YAML validity verified after changes). `migration.rs:312-316` (only removals implemented; transforms with `new_value.is_some()` skipped). | |
| G15 Performance architecture bounded | PASS | `vault.rs:197-213` (evidence files probed at 16KB, not fully read). `source_index.rs:1203-1239` (only configured direct_source_prefixes scanned). Production run: 2840 files, 4737 messages, 5519ms index duration. | |

---

## 4. Findings

### MAJOR — `parse(&rel)` passes file path instead of file content

**Evidence:**
- `source_index.rs:1230`: `let parsed = parse(&rel);`
- `source_index.rs:14`: `use crate::frontmatter::parse;`
- `frontmatter.rs:30-92`: `parse()` expects raw file content, not a path

**Problem:**
The `build()` function calls `parse(&rel)` where `rel` is a vault-relative path string
like `"70 Sources/Telegram/Player/2026/2026-01-01.md"`. The `frontmatter::parse()`
function expects raw Markdown content. Since the path string never starts with `---`,
`parse()` returns `has_block: false`, and the fallback `&raw` is used. The code works
by accident but the frontmatter is never actually stripped from source files before
message parsing.

**Why it matters:**
If a source file has frontmatter (which the production files do — they have
`type: telegram-chat-part` etc.), the frontmatter block is included in the message
body. This means message bodies contain frontmatter YAML, which could pollute
mention matching, receipt parsing, and coverage candidate extraction with YAML keys
and values.

**Recommended direction:**
Change line 1230 from `let parsed = parse(&rel);` to `let parsed = parse(&raw);`.

---

### MODERATE — Hardcoded road names duplicated across modules

**Evidence:**
- `source_index.rs:777-793`: `count_declared_roads()` with 6 lowercase road names
- `technology.rs:599-618`: `extract_road_names()` with 6 title-case road names

**Problem:**
The same 6 road names (Steam, Cold-Hardy Grain, Sampling & Error Bands, Irrigation,
Managed Woodland, Warehouse Receipts) are hardcoded in two separate functions with
different casing. If a new road is added to the canonical portfolio, both lists must
be updated independently.

**Why it matters:**
Silent divergence between the two lists would cause `declared_child_road_count` in the
source index to disagree with `extract_road_names()` in technology validation, producing
inconsistent coverage reports.

**Recommended direction:**
Extract the known-road list into a shared constant (or configuration). Use a single
normalization strategy for matching.

---

### MODERATE — Migration `--apply` ignores `--plan` flag semantics

**Evidence:**
- `main.rs:274-327`: The `plan` parameter is bound as `_plan` (unused)
- `migration.rs:272-339`: `apply()` always executes when called

**Problem:**
The CLI binds `plan: _plan` and only checks `apply_flag`. If a user passes both
`--plan` and `--apply`, the `--apply` path executes. The `--plan` flag is silently
ignored when `--apply` is present. This is not documented.

**Why it matters:**
Users may expect `--plan --apply` to show the plan first and then apply. Instead, it
applies directly. The current behavior is defensible (apply implies plan-then-execute)
but should be documented or the flags should be mutually exclusive.

**Recommended direction:**
Make `--plan` and `--apply` mutually exclusive via clap's `group` feature, or document
that `--apply` supersedes `--plan`.

---

### MINOR — Unused test helper `test_note` in technology.rs

**Evidence:**
- `technology.rs:697-708`: `fn test_note(path: &str, fm_text: &str, body: &str) -> Note`
- Compiler warning: `warning: function 'test_note' is never used`

**Problem:**
The test helper is defined but never called. The compiler emits a warning.

**Why it matters:**
Dead code in tests suggests incomplete test coverage for the technology rules.

**Recommended direction:**
Either add tests that use the helper, or remove it.

---

### MINOR — `MigrationAction::Transform` is defined but never applied

**Evidence:**
- `migration.rs:50`: `Transform(fn(&str) -> Option<String>)` variant
- `migration.rs:312-316`: `if change.new_value.is_some() { continue; }` skips non-removal changes

**Problem:**
The `Transform` variant exists in the enum but the apply function skips any change where
`new_value.is_some()`. The `MIG-RETRIEVAL-001` rule generates transforms (adding
`retrieval_tier`) but they are never applied.

**Why it matters:**
The migration plan reports 104 transforms that would be skipped on apply. This is
misleading — the plan suggests changes that cannot actually be executed.

**Recommended direction:**
Either implement transform application or mark transform-only rules as "plan-only" in
the plan output.

---

## 5. Architecture assessment

**Major modules:**
- `vault.rs` — Vault scanning, note parsing, fingerprinting
- `boundary.rs` — State boundary resolution (file → derive → validate)
- `source_index.rs` — Direct-source parsing, identity matching, mention tracking, receipt extraction, coverage candidates
- `technology.rs` — Technology structural rules (CHAD-TECH-001..010, TECH-MIG-*)
- `receipts.rs` — Receipt monitoring rules (CHAD-RECEIPT-001..006)
- `capability.rs` — Capability exploitation tracking (CHAD-CAP-001)
- `coverage.rs` — Coverage candidate rules (CHAD-COVER-001..004)
- `continuity.rs` — Continuity Report generation
- `migration.rs` — Frontmatter migration (plan/apply)
- `rules/` — Core validation rules (schema, year, cursor, freshness, identity, hygiene)
- `report.rs` — Vault Health report generation
- `config.rs` — Configuration with YAML override support
- `rules/meta.rs` — Rule metadata table (descriptions, remediation, priority)

**Ownership boundaries:**
Clean separation between vault indexing, source indexing, rule evaluation, and report
generation. Rules receive a `RuleContext` that provides read-only access to indexes.
No rule mutates the vault. The source index is built once and passed to rules that
need it.

**Duplicated sources of truth:**
The hardcoded road names in `source_index.rs` and `technology.rs` are the only
significant duplication. The identity normalization logic is centralized in
`source_index::normalize_text()` and used consistently.

**Coupling risks:**
The `technology.rs` module reaches into `ctx.index.notes` directly rather than using
the source index's pre-computed counts. This is acceptable since the source index
may not be available (it's `Option<&SourceIndex>` in the rule context).

**Extensibility:**
Adding a new deterministic rule requires: (1) implementing a check function, (2) adding
rule IDs to `rules/meta.rs`, (3) calling it from `rules::run_all()`. The architecture
cleanly supports this.

---

## 6. Test assessment

**Commands run:**
```
cargo test → 53 unit tests, 30 integration tests, 0 failures
```

**Well-covered invariants:**
- Identity normalization (case, possessives, dashes, curly apostrophes, backslash escapes)
- Ambiguous alias resolution (refuses to guess)
- Cursor epoch resolution
- Receipt parsing
- Protected path detection
- Boundary derivation from runtime records
- Year coverage rules
- Freshness rules
- Identity rules
- Schema/hygiene rules
- Stale boundary remediation (CHAD-CURSOR-002 distinguishes stale boundary)
- Canonical identity suppresses coverage candidates
- Materiality seeded from source_cursor

**Insufficiently tested:**
- The `parse(&rel)` bug (no test verifies frontmatter is stripped from source files)
- Technology rules (CHAD-TECH-001..010) have no integration tests
- Receipt monitoring rules (CHAD-RECEIPT-001..006) have no integration tests
- Capability rules (CHAD-CAP-001) have no integration tests
- Coverage rules (CHAD-COVER-001..004) have no integration tests
- Migration apply mode (no test verifies files are actually modified)
- Migration idempotence (no test verifies second run produces zero changes)
- Empty denominator behavior (0 roads → INCOMPLETE) tested only via production run
- `remove_yaml_field` with multi-line YAML values (lists, nested maps)

**Tests coupled to implementation:**
The `all_rule_ids_have_metadata` test in `rules/meta.rs` requires manual list updates
when adding new rules. This is a reasonable safety net but couples the test to the
metadata table rather than the rule implementation.

---

## 7. Performance assessment

```
representative vault size:     2840 files
source files/messages indexed: 236 files, 4737 messages
validation runtime:            ~5.5s (source index) + ~0.5s (vault scan + rules)
major observed cost centers:   source_index::build (5519ms), vault::scan
```

**Architecture:**
- Curated notes: full read + content hash
- Evidence/archive notes: 16KB probe (metadata hash only)
- Source files: full read (only configured direct_source_prefixes)
- Identity matching: O(messages × identities) with normalized string containment
- Coverage candidate extraction: O(messages × known_identities) for substring filtering

**Scaling risks:**
- The `known_normalized.iter().any(|k| k.len() > norm.len() && k.contains(&norm))` check
  in `extract_candidates` (`source_index.rs:866`) is O(candidates × known_identities).
  With 474 candidates and 113+ identities, this is ~53K string comparisons per message.
  At 4737 messages, this is ~250M comparisons. Currently acceptable but would degrade
  with larger vaults.
- The `vault_index.find_by_path()` method does a linear scan (`vault.rs:129-131`). With
  2840 notes, this is called once per identity (113 times) in `seed_canonical_materiality`.
  Acceptable but would benefit from a HashMap index.

**Measured vs speculative:**
The 5.5s source index duration is measured. The vault scan is fast (~0.5s). The total
validation time is ~6s, which is acceptable for a batch validator but would need
optimization for watch mode responsiveness.

---

## 8. Migration safety assessment

```
Can normal validation mutate canonical state?     NO — validation writes only reports
Can migration touch protected source?             NO — protected_prefixes checked in plan/apply
Is plan/apply separation real?                    YES — separate CLI commands, plan is default
Is apply idempotent?                              PARTIALLY — removals are idempotent; transforms
                                                  are skipped (not implemented)
Can unrelated Markdown body content change?       NO — remove_yaml_field operates only within
                                                  frontmatter fences
Can ambiguous fields be rewritten?                NO — only GeneratedDerived fields are removed;
                                                  transforms are skipped
Is there an auditable manifest?                   YES — plan output shows every file/field/action
```

**Weaknesses:**
- Transform application is not implemented, so the plan reports changes that cannot execute
- No test verifies migration idempotence
- No test verifies protected file exclusion in apply mode
- The `remove_yaml_field` function handles simple key-value pairs but may not handle
  complex multi-line YAML values (nested maps, block scalars) correctly

---

## 9. Top five remediation priorities

1. **Fix `parse(&rel)` → `parse(&raw)` in source_index.rs:1230**
   Severity: MAJOR
   Category: required before routine use
   The bug is masked by a fallback but means source file frontmatter is never stripped,
   potentially polluting mention matching and receipt parsing with YAML content.

2. **Extract hardcoded road names into shared constant**
   Severity: MODERATE
   Category: required before migration
   Duplicated lists in source_index.rs and technology.rs will diverge silently.

3. **Add integration tests for technology/receipt/capability/coverage rules**
   Severity: MODERATE
   Category: technical debt
   The new rule families have unit tests but no integration tests verifying end-to-end
   behavior against synthetic vaults.

4. **Implement transform application in migration or mark as plan-only**
   Severity: MINOR
   Category: technical debt
   The plan reports 104 transforms that cannot be applied. Either implement the transform
   path or clearly mark them as informational in the plan output.

5. **Add migration idempotence and protected-file tests**
   Severity: MINOR
   Category: technical debt
   No test verifies that apply is idempotent or that protected files are correctly
   excluded during apply.

---

## 10. Final trust statement

> **Would you trust this validator to guide an autonomous LLM reconciliation pass over the production Chadlands vault?**

**YES, WITH THESE CONDITIONS:**

The validator is architecturally sound, deterministic, and epistemically disciplined. It
correctly distinguishes known from unknown, surfaces representation gaps, and never
quietly manufactures state. The source index bug (finding #1) must be fixed before
trusting the source-parsing pipeline for autonomous action, as the current behavior
includes frontmatter YAML in message bodies. The hardcoded road names (finding #2) must
be consolidated before trusting the technology coverage surface for migration decisions.
With those two fixes, this validator is a trustworthy deterministic control plane for
autonomous reconciliation.
