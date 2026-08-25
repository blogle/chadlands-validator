//! Integration tests: build synthetic mini-vaults in tempdirs and validate
//! specific rules in isolation.

use std::fs;
use std::path::Path;

use chadlands_validator::config::Config;
use chadlands_validator::findings::Severity;
use chadlands_validator::validate;

fn write_note(root: &Path, rel: &str, content: &str) {
    let abs = root.join(rel);
    if let Some(parent) = abs.parent() {
        fs::create_dir_all(parent).unwrap();
    }
    fs::write(abs, content).unwrap();
}

fn mini_config() -> Config {
    let mut c = Config::default();
    // Suppress the boundary-missing WARN so tests focus on the rule under test.
    c.severity_overrides.insert(
        "CHAD-STATE-001".into(),
        chadlands_validator::findings::Severity::Info,
    );
    c
}

fn has_rule(findings: &[chadlands_validator::findings::Finding], rule: &str) -> bool {
    findings.iter().any(|f| f.rule == rule)
}

fn count_rule(findings: &[chadlands_validator::findings::Finding], rule: &str) -> usize {
    findings.iter().filter(|f| f.rule == rule).count()
}

// -----------------------------------------------------------------------
// Rule 1 — year coverage
// -----------------------------------------------------------------------

#[test]
fn year_001_resolved_beyond_chronicle() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_note(
        root,
        "60 Steering/Runtime/Reconciled Handoff.md",
        "---\ntype: runtime-handoff\nstatus: active\nretrieval_tier: runtime\nknowledge_scope: player-only\nsource_cursor: 100\nlast_resolved_year: 5\nturn: 6\nyear: 6\n---\n# Handoff\n",
    );
    // Only Chronicle years 1-3 exist; resolved claims 5.
    for y in 1..=3 {
        write_note(
            root,
            &format!("20 Chronicle/Year {y}.md"),
            &format!("---\ntype: chronicle-year\nstatus: resolved\nretrieval_tier: canonical\nyear: {y}\n---\n# Year {y}\n"),
        );
    }
    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    assert!(has_rule(&outcome.findings.items, "CHAD-YEAR-001"));
}

#[test]
fn year_004_gap_in_resolved_range() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_note(
        root,
        "60 Steering/Runtime/Reconciled Handoff.md",
        "---\ntype: runtime-handoff\nstatus: active\nretrieval_tier: runtime\nknowledge_scope: player-only\nsource_cursor: 100\nlast_resolved_year: 5\nturn: 6\nyear: 6\n---\n# Handoff\n",
    );
    // Years 1,2,4,5 present — year 3 is missing.
    for y in [1, 2, 4, 5] {
        write_note(
            root,
            &format!("20 Chronicle/Year {y}.md"),
            &format!("---\ntype: chronicle-year\nstatus: resolved\nretrieval_tier: canonical\nyear: {y}\n---\n# Year {y}\n"),
        );
    }
    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    assert!(has_rule(&outcome.findings.items, "CHAD-YEAR-004"));
}

#[test]
fn year_003_future_evidence_year() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_note(
        root,
        "60 Steering/Runtime/Opening Context Pack.md",
        "---\ntype: runtime-context-pack\nstatus: active\nretrieval_tier: runtime\nknowledge_scope: player-only\nsource_cursor: 100\ncurrent_year: 10\nturn: 10\nyear: 10\n---\n# Pack\n",
    );
    write_note(
        root,
        "30 World/People/Foo.md",
        "---\ntype: person\nstatus: active\nretrieval_tier: canonical\nlast_confirmed_year: 15\nreviewed_through_cursor: 100\n---\n# Foo\n",
    );
    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    assert!(has_rule(&outcome.findings.items, "CHAD-YEAR-003"));
}

// -----------------------------------------------------------------------
// Rule 2 — freshness
// -----------------------------------------------------------------------

#[test]
fn fresh_001_stale_canonical() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // Boundary with materialized cursor 200.
    write_note(
        root,
        "00 System/State Boundary.md",
        "---\ncurrent_turn: 5\ncurrent_year: 5\nlast_resolved_year: 4\ncurrent_source_cursor: 200\ncanonical_materialized_cursor: 200\n---\n# Boundary\n",
    );
    // Active canonical reviewed only through 100.
    write_note(
        root,
        "30 World/People/Stale.md",
        "---\ntype: person\nstatus: active\nretrieval_tier: canonical\nreviewed_through_cursor: 100\nlast_confirmed_year: 3\n---\n# Stale\n",
    );
    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    assert!(has_rule(&outcome.findings.items, "CHAD-FRESH-001"));
}

#[test]
fn fresh_002_missing_reviewed_cursor() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_note(
        root,
        "00 System/State Boundary.md",
        "---\ncurrent_turn: 5\ncurrent_year: 5\nlast_resolved_year: 4\ncurrent_source_cursor: 200\ncanonical_materialized_cursor: 200\n---\n# Boundary\n",
    );
    write_note(
        root,
        "30 World/People/NoCursor.md",
        "---\ntype: person\nstatus: active\nretrieval_tier: canonical\nlast_confirmed_year: 3\n---\n# NoCursor\n",
    );
    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    assert!(has_rule(&outcome.findings.items, "CHAD-FRESH-002"));
}

#[test]
fn fresh_blocked_external_passes() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_note(
        root,
        "00 System/State Boundary.md",
        "---\ncurrent_turn: 5\ncurrent_year: 5\nlast_resolved_year: 4\ncurrent_source_cursor: 200\ncanonical_materialized_cursor: 200\n---\n# Boundary\n",
    );
    write_note(
        root,
        "30 World/People/Blocked.md",
        "---\ntype: person\nstatus: active\nretrieval_tier: canonical\nreview_state: blocked-external\nlast_confirmed_year: 3\n---\n# Blocked\n",
    );
    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    assert!(!has_rule(&outcome.findings.items, "CHAD-FRESH-001"));
    assert!(!has_rule(&outcome.findings.items, "CHAD-FRESH-002"));
}

// -----------------------------------------------------------------------
// Rule 3 — owner completeness
// -----------------------------------------------------------------------

#[test]
fn owner_001_missing_required_field() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_note(
        root,
        "40 Civilization/Institutions/NoOwner.md",
        "---\ntype: institution\nstatus: active\nretrieval_tier: canonical\nlifecycle: standing\nlast_confirmed_year: 5\nreviewed_through_cursor: 100\n---\n# NoOwner\n",
    );
    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    // Missing owner/lead and second.
    assert!(count_rule(&outcome.findings.items, "CHAD-OWNER-001") >= 2);
}

#[test]
fn owner_002_unresolved_permitted() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_note(
        root,
        "40 Civilization/Institutions/Unres.md",
        "---\ntype: institution\nstatus: active\nretrieval_tier: canonical\nlifecycle: standing\nlast_confirmed_year: 5\nreviewed_through_cursor: 100\nowner: UNASSIGNED\nsecond: MISSING\n---\n# Unres\n",
    );
    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    assert!(has_rule(&outcome.findings.items, "CHAD-OWNER-002"));
    assert!(!has_rule(&outcome.findings.items, "CHAD-OWNER-003"));
}

// -----------------------------------------------------------------------
// Rule 4 — cursor consistency
// -----------------------------------------------------------------------

#[test]
fn cursor_001_source_exceeds_reviewed() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_note(
        root,
        "30 World/People/Bad.md",
        "---\ntype: person\nstatus: active\nretrieval_tier: canonical\nsource_cursor: 200\nreviewed_through_cursor: 100\nlast_confirmed_year: 5\n---\n# Bad\n",
    );
    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    assert!(has_rule(&outcome.findings.items, "CHAD-CURSOR-001"));
}

#[test]
fn cursor_003_manifest_missing_subject() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_note(
        root,
        "00 System/State Boundary.md",
        "---\ncurrent_turn: 5\ncurrent_year: 5\nlast_resolved_year: 4\ncurrent_source_cursor: 200\ncanonical_materialized_cursor: 200\n---\n# Boundary\n",
    );
    // Canonical note reviewed through 200 (at frontier).
    write_note(
        root,
        "30 World/People/Reviewed.md",
        "---\ntype: person\nstatus: active\nretrieval_tier: canonical\nreviewed_through_cursor: 200\nlast_confirmed_year: 5\n---\n# Reviewed\n",
    );
    // Manifest at cursor 200 that does NOT list the person.
    write_note(
        root,
        "00 System/Reconciliation Manifests/latest.md",
        "---\ntype: reconciliation-manifest\nmanifest_id: test\ncanonical_materialized_cursor: 200\nsource_cursor: 200\nsubjects:\n- path: 30 World/People/Other.md\n  disposition: UPDATED\n---\n# Manifest\n",
    );
    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    assert!(has_rule(&outcome.findings.items, "CHAD-CURSOR-003"));
}

#[test]
fn cursor_007_blocked_without_reason() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_note(
        root,
        "00 System/State Boundary.md",
        "---\ncurrent_turn: 5\ncurrent_year: 5\nlast_resolved_year: 4\ncurrent_source_cursor: 200\ncanonical_materialized_cursor: 200\n---\n# Boundary\n",
    );
    write_note(
        root,
        "00 System/Reconciliation Manifests/latest.md",
        "---\ntype: reconciliation-manifest\nmanifest_id: test\ncanonical_materialized_cursor: 200\nsource_cursor: 200\nsubjects:\n- path: 30 World/People/Foo.md\n  disposition: BLOCKED — EXTERNAL\n---\n# Manifest\n",
    );
    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    assert!(has_rule(&outcome.findings.items, "CHAD-CURSOR-007"));
}

// -----------------------------------------------------------------------
// Rule 5 — identity
// -----------------------------------------------------------------------

#[test]
fn identity_001_duplicate_canonical_id() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_note(
        root,
        "40 Civilization/Capabilities/Technology/Nodes/A.md",
        "---\ntype: technology-node\nstatus: active\nretrieval_tier: canonical\nvault_node_id: TN-001\n---\n# A\n",
    );
    write_note(
        root,
        "40 Civilization/Capabilities/Technology/Nodes/B.md",
        "---\ntype: technology-node\nstatus: active\nretrieval_tier: canonical\nvault_node_id: TN-001\n---\n# B\n",
    );
    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    assert!(has_rule(&outcome.findings.items, "CHAD-IDENTITY-001"));
}

#[test]
fn identity_003_lead_equals_second() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_note(
        root,
        "40 Civilization/Institutions/Same.md",
        "---\ntype: institution\nstatus: active\nretrieval_tier: canonical\nlead: Dorrin\nsecond: Dorrin\nlifecycle: standing\nlast_confirmed_year: 5\nreviewed_through_cursor: 100\n---\n# Same\n",
    );
    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    assert!(has_rule(&outcome.findings.items, "CHAD-IDENTITY-003"));
}

#[test]
fn identity_004_deceased_active() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_note(
        root,
        "30 World/People/Ghost.md",
        "---\ntype: person\nstatus: active\nretrieval_tier: canonical\nlife_status: deceased\nlast_confirmed_year: 5\nreviewed_through_cursor: 100\n---\n# Ghost\n",
    );
    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    assert!(has_rule(&outcome.findings.items, "CHAD-IDENTITY-004"));
}

// -----------------------------------------------------------------------
// Schema / hygiene
// -----------------------------------------------------------------------

#[test]
fn schema_001_missing_frontmatter() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_note(root, "30 World/People/Bare.md", "# No frontmatter here\n");
    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    assert!(has_rule(&outcome.findings.items, "CHAD-SCHEMA-001"));
}

#[test]
fn schema_003_status_vocab() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_note(
        root,
        "30 World/People/Bad.md",
        "---\ntype: person\nstatus: banana\nretrieval_tier: canonical\nlast_confirmed_year: 5\nreviewed_through_cursor: 100\n---\n# Bad\n",
    );
    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    assert!(has_rule(&outcome.findings.items, "CHAD-SCHEMA-003"));
}

#[test]
fn schema_004_year_ordering() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_note(
        root,
        "30 World/People/Backwards.md",
        "---\ntype: person\nstatus: active\nretrieval_tier: canonical\nfirst_known_year: 10\nlast_confirmed_year: 5\nreviewed_through_cursor: 100\n---\n# Backwards\n",
    );
    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    assert!(has_rule(&outcome.findings.items, "CHAD-SCHEMA-004"));
}

#[test]
fn work_001_duplicate_active_workflow() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_note(
        root,
        "00 System/Workflows/A.md",
        "---\ntype: system-workflow\nstatus: active\nworkflow_id: chadlands.foo\n---\n# A\n## Validation\nok\n",
    );
    write_note(
        root,
        "00 System/Workflows/B.md",
        "---\ntype: system-workflow\nstatus: active\nworkflow_id: chadlands.foo\n---\n# B\n## Validation\nok\n",
    );
    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    assert!(has_rule(&outcome.findings.items, "CHAD-WORK-001"));
}

#[test]
fn link_001_broken_wikilink() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_note(
        root,
        "30 World/Places/Here.md",
        "---\ntype: place\nstatus: active\nretrieval_tier: canonical\n---\n# Here\nSee [[30 World/Places/Nowhere]].\n",
    );
    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    assert!(has_rule(&outcome.findings.items, "CHAD-LINK-001"));
}

// -----------------------------------------------------------------------
// Protected paths
// -----------------------------------------------------------------------

#[test]
fn prot_001_changed_collector_path() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_note(
        root,
        "30 World/People/Foo.md",
        "---\ntype: person\nstatus: active\nretrieval_tier: canonical\n---\n# Foo\n",
    );
    let cfg = mini_config();
    let outcome = validate(root, &cfg, &["70 Sources/Telegram/foo.md".to_string()]).unwrap();
    assert!(has_rule(&outcome.findings.items, "CHAD-PROT-001"));
}

// -----------------------------------------------------------------------
// Boundary derivation
// -----------------------------------------------------------------------

#[test]
fn boundary_derives_from_runtime() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_note(
        root,
        "60 Steering/Runtime/Reconciled Handoff.md",
        "---\ntype: runtime-handoff\nstatus: active\nretrieval_tier: runtime\nknowledge_scope: player-only\nsource_cursor: 500\nlast_resolved_year: 8\nturn: 9\nyear: 9\n---\n# Handoff\n",
    );
    write_note(
        root,
        "60 Steering/Runtime/Opening Context Pack.md",
        "---\ntype: runtime-context-pack\nstatus: active\nretrieval_tier: runtime\nknowledge_scope: player-only\nsource_cursor: 550\nturn: 10\nyear: 10\n---\n# Pack\n",
    );
    let mut cfg = mini_config();
    // Suppress CHAD-STATE-001 so we can check the derived values.
    cfg.severity_overrides
        .insert("CHAD-STATE-001".into(), Severity::Info);
    let outcome = validate(root, &cfg, &[]).unwrap();
    assert_eq!(outcome.boundary.current_turn, Some(10));
    assert_eq!(outcome.boundary.current_year, Some(10));
    assert_eq!(outcome.boundary.last_resolved_year, Some(8));
    assert_eq!(outcome.boundary.current_source_cursor, Some(550));
    assert_eq!(outcome.boundary.canonical_materialized_cursor, Some(500));
}

// -----------------------------------------------------------------------
// Report generation
// -----------------------------------------------------------------------

#[test]
fn report_written_to_vault() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_note(
        root,
        "30 World/People/Foo.md",
        "---\ntype: person\nstatus: active\nretrieval_tier: canonical\nreviewed_through_cursor: 100\nlast_confirmed_year: 5\n---\n# Foo\n",
    );
    let cfg = mini_config();
    chadlands_validator::validate_and_report(root, &cfg, &[]).unwrap();
    let report = root.join(&cfg.report_path);
    assert!(report.exists());
    let content = fs::read_to_string(&report).unwrap();
    assert!(content.contains("type: validation-report"));
    assert!(content.contains("validated_revision:"));
}

// -----------------------------------------------------------------------
// Steering Pass 3 regression tests
// -----------------------------------------------------------------------

#[test]
fn materiality_seeded_from_source_cursor() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // Canonical record with source_cursor
    write_note(
        root,
        "40 Civilization/Projects/Test Project.md",
        "---\ntype: project\nstatus: active\nretrieval_tier: canonical\nsource_cursor: 4526\nreviewed_through_cursor: 4534\nlast_confirmed_year: 37\n---\n# Test Project\n",
    );
    write_note(
        root,
        "70 Sources/Telegram/Player/2026/2026-01-01.md",
        "---\ntype: telegram-chat-part\nsource: telegram\nstream: player\ndate: 2026-01-01\nfirst: 4600\nlast: 4600\ncount: 1\n---\n\n^telegram--100-4600\n**00:00 UTC** · the_mud_lounge_bot\n\nUnrelated source evidence.\n",
    );
    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    let report = outcome.continuity_report_markdown.unwrap();
    let row = report
        .lines()
        .find(|line| line.contains("Test Project"))
        .expect("project should be a resurfacing candidate");
    assert!(row.contains("cursor 4526"));
    assert!(!row.contains("| — | no mention"));
}

#[test]
fn canonical_identity_suppresses_coverage_candidate() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // Create a canonical record
    write_note(
        root,
        "40 Civilization/Capabilities/Technology/Nodes/Forge School.md",
        "---\ntype: technology-node\nstatus: superseded\nretrieval_tier: canonical\n---\n# Forge School\n",
    );
    // Create a source message mentioning "Forge School"
    write_note(
        root,
        "70 Sources/Telegram/Player/2026/2026-01-01.md",
        "---\ntype: telegram-chat-part\nsource: telegram\nstream: player\ndate: 2026-01-01\nfirst: 1\nlast: 1\ncount: 1\n---\n\n^telegram--100-1\n**00:00 UTC** · the_mud_lounge_bot\n\nForge School was discussed.\n",
    );
    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    // Forge School should NOT be a coverage candidate
    // because it's in the canonical identity universe
    let report = outcome.continuity_report_markdown.unwrap();
    assert!(!report.contains("Forge School"));
}

#[test]
fn schema_003_index_vocabulary() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // Index with provisional status should not trigger CHAD-SCHEMA-003
    write_note(
        root,
        "10 Origins/Forge Survival Index.md",
        "---\ntype: index\nstatus: provisional\nretrieval_tier: canonical\n---\n# Forge Survival Index\n",
    );
    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    assert!(!has_rule(&outcome.findings.items, "CHAD-SCHEMA-003"));
}

#[test]
fn schema_003_register_vocabulary() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // Register with in-progress status should not trigger CHAD-SCHEMA-003
    write_note(
        root,
        "30 World/Registers/Geographic Register.md",
        "---\ntype: register\nstatus: in-progress\nretrieval_tier: canonical\n---\n# Geographic Register\n",
    );
    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    assert!(!has_rule(&outcome.findings.items, "CHAD-SCHEMA-003"));
}

#[test]
fn schema_003_doctrine_vocabulary() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // Doctrine with standing status should not trigger CHAD-SCHEMA-003
    write_note(
        root,
        "50 Knowledge/Hoarback Non-Harm Doctrine.md",
        "---\ntype: doctrine\nstatus: standing\nretrieval_tier: canonical\n---\n# Hoarback Non-Harm Doctrine\n",
    );
    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    assert!(!has_rule(&outcome.findings.items, "CHAD-SCHEMA-003"));
}

#[test]
fn schema_003_person_unresolved() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // Person with unresolved status should not trigger CHAD-SCHEMA-003
    write_note(
        root,
        "30 World/People/Wynn Alder.md",
        "---\ntype: person\nstatus: unresolved\nretrieval_tier: canonical\n---\n# Wynn Alder\n",
    );
    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    assert!(!has_rule(&outcome.findings.items, "CHAD-SCHEMA-003"));
}

#[test]
fn cursor_002_stale_boundary_remediation() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // State Boundary with cursor 100
    write_note(
        root,
        "00 System/State Boundary.md",
        "---\ncurrent_turn: 5\ncurrent_year: 5\nlast_resolved_year: 4\ncurrent_source_cursor: 100\ncanonical_materialized_cursor: 100\n---\n# Boundary\n",
    );
    // Record with cursor 200 (ahead of boundary)
    write_note(
        root,
        "30 World/People/Ahead.md",
        "---\ntype: person\nstatus: active\nretrieval_tier: canonical\nsource_cursor: 200\nreviewed_through_cursor: 200\nlast_confirmed_year: 5\n---\n# Ahead\n",
    );
    // Source message with cursor 300 (ahead of record)
    write_note(
        root,
        "70 Sources/Telegram/Player/2026/2026-01-01.md",
        "---\ntype: telegram-chat-part\nsource: telegram\nstream: player\ndate: 2026-01-01\nfirst: 300\nlast: 300\ncount: 1\n---\n\n^telegram--100-300\n**00:00 UTC** · the_mud_lounge_bot\n\nTest message.\n",
    );
    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    // Should have CHAD-CURSOR-002 with stale boundary remediation
    let cursor_findings: Vec<_> = outcome
        .findings
        .items
        .iter()
        .filter(|f| f.rule == "CHAD-CURSOR-002")
        .collect();
    assert!(!cursor_findings.is_empty());
    assert!(cursor_findings[0]
        .message
        .contains("State Boundary may be stale"));
    assert!(outcome
        .report_markdown
        .contains("reconcile the State Boundary before altering the record"));
    assert!(!outcome
        .report_markdown
        .contains("Correct the cursor value to not exceed"));
}

#[test]
fn year_003_stale_boundary_keeps_error_but_avoids_downward_rewrite() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_note(
        root,
        "00 System/State Boundary.md",
        "---\ncurrent_turn: 38\ncurrent_year: 38\nlast_resolved_year: 38\ncurrent_source_cursor: 4664\ncanonical_materialized_cursor: 4534\n---\n# Boundary\n",
    );
    write_note(
        root,
        "60 Steering/Command Board.md",
        "---\ntype: runtime-context-pack\nstatus: active\nretrieval_tier: runtime\nyear: 39\nsource_cursor: 4717\n---\n# Command Board\n",
    );
    write_note(
        root,
        "70 Sources/Telegram/Player/2026/source.md",
        "---\ntype: telegram-chat-part\nsource: telegram\nstream: player\nfirst: 4741\nlast: 4741\ncount: 1\n---\n\n^telegram--100-4741\n**00:00 UTC** · the_mud_lounge_bot\n\nCollected evidence.\n",
    );

    let outcome = validate(root, &mini_config(), &[]).unwrap();
    let finding = outcome
        .findings
        .items
        .iter()
        .find(|finding| finding.rule == "CHAD-YEAR-003")
        .expect("future year remains fail-closed");
    assert_eq!(finding.severity, Severity::Error);
    assert!(finding.message.contains("boundary may be stale"));
    assert!(finding.message.contains("before altering the record year"));
    assert!(!finding.message.contains("must not exceed"));
    assert!(!outcome.report_markdown.contains("correct year to <= 38"));
}

#[test]
fn year_003_beyond_collected_evidence_remains_unsupported() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_note(
        root,
        "00 System/State Boundary.md",
        "---\ncurrent_turn: 38\ncurrent_year: 38\nlast_resolved_year: 38\ncurrent_source_cursor: 4664\ncanonical_materialized_cursor: 4534\n---\n# Boundary\n",
    );
    write_note(
        root,
        "60 Steering/Unsupported.md",
        "---\ntype: runtime-context-pack\nstatus: active\nretrieval_tier: runtime\nyear: 39\nsource_cursor: 4800\n---\n# Unsupported\n",
    );
    write_note(
        root,
        "70 Sources/Telegram/Player/2026/source.md",
        "---\ntype: telegram-chat-part\nsource: telegram\nstream: player\nfirst: 4741\nlast: 4741\ncount: 1\n---\n\n^telegram--100-4741\n**00:00 UTC** · the_mud_lounge_bot\n\nCollected evidence.\n",
    );

    let outcome = validate(root, &mini_config(), &[]).unwrap();
    let finding = outcome
        .findings
        .items
        .iter()
        .find(|finding| finding.rule == "CHAD-YEAR-003")
        .unwrap();
    assert!(finding.message.contains("unsupported"));
    assert!(finding.message.contains("correct the record"));
}

#[test]
fn tech_mig_004_preserves_declared_six_road_names() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_note(
        root,
        "40 Civilization/Projects/Portfolio.md",
        "---\ntype: project\nstatus: active\nretrieval_tier: canonical\nportfolio_id: frontier\nowner: Council\nlifecycle: active\nreviewed_through_cursor: 100\n---\n# Portfolio\n\nThe active six-road technology portfolio declares:\n\n1. Steam;\n2. cold-hardy grain;\n3. sampling and error bands;\n4. irrigation off gorge water;\n5. managed woodland;\n6. warehouse receipts.\n\n## Road Ownership\n\n| Road | Owner |\n|---|---|\n| Irrigation | Keeper |\n",
    );

    let outcome = validate(root, &mini_config(), &[]).unwrap();
    let finding = outcome
        .findings
        .items
        .iter()
        .find(|finding| finding.rule == "TECH-MIG-004")
        .expect("legacy portfolio debt should remain");
    for road in [
        "Steam",
        "Cold-Hardy Grain",
        "Sampling & Error Bands",
        "Irrigation off Gorge Water",
        "Managed Woodland",
        "Warehouse Receipts",
    ] {
        assert!(finding.message.contains(&format!("- {road}")));
    }
    assert!(!finding.message.contains("\n- Irrigation\n"));
}

#[test]
fn tech_mig_001_accepts_exactly_one_explicit_classification() {
    for field in [
        "portfolio_id: p",
        "road_id: r",
        "capability_id: c",
        "technology_class: historical-compatibility",
    ] {
        let dir = tempfile::tempdir().unwrap();
        write_note(
            dir.path(),
            "40 Civilization/Capabilities/Technology/Nodes/Legacy.md",
            &format!(
                "---\ntype: technology-node\nstatus: superseded\nretrieval_tier: canonical\n{field}\n---\n# Legacy\n"
            ),
        );
        let outcome = validate(dir.path(), &mini_config(), &[]).unwrap();
        assert!(
            !has_rule(&outcome.findings.items, "TECH-MIG-001"),
            "{field}"
        );
    }

    let dir = tempfile::tempdir().unwrap();
    write_note(
        dir.path(),
        "40 Civilization/Capabilities/Technology/Nodes/Legacy.md",
        "---\ntype: technology-node\nstatus: superseded\nretrieval_tier: canonical\n---\n# Legacy\n",
    );
    let outcome = validate(dir.path(), &mini_config(), &[]).unwrap();
    assert!(has_rule(&outcome.findings.items, "TECH-MIG-001"));
}

#[test]
fn cap_mig_001_detected() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    // Capability register with attained entries
    write_note(
        root,
        "40 Civilization/Capabilities/Technology/Attained Capability Register.md",
        "---\ntype: register\nstatus: active\nretrieval_tier: canonical\n---\n# Attained Capability Register\n\n## Attained\n- Water Power\n- Precision Gauges\n",
    );
    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    assert!(has_rule(&outcome.findings.items, "CAP-MIG-001"));
}
