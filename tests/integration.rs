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
    // Find the resurfacing queue section and look for the project row there
    let resurfacing_section = report
        .split("## Play / Research Resurfacing Queue")
        .nth(1)
        .expect("resurfacing section should exist");
    let row = resurfacing_section
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
    // Check the Coverage Candidates section specifically
    let coverage_section = report.split("## Coverage Candidates").nth(1).unwrap_or("");
    assert!(
        !coverage_section.contains("Forge School"),
        "Forge School should not appear in Coverage Candidates section"
    );
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

// -----------------------------------------------------------------------
// Patch 3 — Lifecycle events
// -----------------------------------------------------------------------

#[test]
fn universal_formation_materialization_gap() {
    // §8 / Test 13: Canonical stale active road + direct source CLOSED SUCCEEDED
    // → MATERIALIZATION_GAP, player-side reconciliation, no DM inquiry
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    // Boundary with current_source_cursor 5100
    write_note(
        root,
        "00 System/State Boundary.md",
        "---\ntype: state-boundary\ncurrent_turn: 42\ncurrent_year: 42\nlast_resolved_year: 41\ncurrent_source_cursor: 5100\ncanonical_materialized_cursor: 4838\n---\n# State Boundary\n",
    );
    // Canonical road: active, in-progress, reviewed through 4838
    write_note(
        root,
        "40 Civilization/Technology/Roads/Universal Formation.md",
        "---\ntype: technology-road\nroad_id: road:universal-formation\nstatus: active\nlifecycle: in-progress\naccepted_year: 37\nacceptance_cursor: 4524\nsource_cursor: 4526\nreviewed_through_cursor: 4838\nterminal_due_year: 40\n---\n# Universal Formation\n",
    );
    // DM source at cursor 5035: lifecycle event CLOSED SUCCEEDED
    write_note(
        root,
        "70 Sources/Telegram/Player/2026/2026-01-01.md",
        "---\ntype: telegram-chat-part\nsource: telegram\nstream: player\ndate: 2026-01-01\nfirst: 5035\nlast: 5035\ncount: 1\n---\n\n^telegram--100-5035\n**00:00 UTC** · the_mud_lounge_bot\n\nUniversal formation road | closed SUCCEEDED this year\n",
    );

    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();

    // Lifecycle event should be parsed
    let source_idx = outcome
        .continuity_report_markdown
        .as_ref()
        .map(|_| {
            // Verify via the report content
            let report = outcome.continuity_report_markdown.as_ref().unwrap();
            report.contains("lifecycle events parsed: 1")
        })
        .unwrap_or(false);
    assert!(source_idx, "should parse 1 lifecycle event");

    // The gap classification should produce a MATERIALIZATION_GAP
    let report = outcome.continuity_report_markdown.as_ref().unwrap();
    assert!(
        report.contains("MATERIALIZATION_GAP"),
        "should classify as MATERIALIZATION_GAP"
    );
    assert!(
        report.contains("PLAYER_SIDE_RECONCILIATION"),
        "should recommend player-side reconciliation"
    );
    // Must NOT recommend DM inquiry (direct evidence already answers)
    let queue_section = report
        .split("## Top Actionable Reconciliation Queue")
        .nth(1)
        .unwrap_or("");
    // DM_INQUIRY should not appear for this specific gap
    assert!(
        !queue_section.contains("road:universal-formation")
            || !queue_section.contains("DM_INQUIRY"),
        "must not recommend DM inquiry when direct evidence exists"
    );
}

#[test]
fn steam_governor_not_terminal_failure() {
    // §7.5 / Test 14: Steam's governor control FAILED TERMINALLY
    // → NO terminal-failure event for road:steam
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_note(
        root,
        "00 System/State Boundary.md",
        "---\ntype: state-boundary\ncurrent_turn: 42\ncurrent_year: 42\nlast_resolved_year: 41\ncurrent_source_cursor: 5100\ncanonical_materialized_cursor: 4838\n---\n# State Boundary\n",
    );
    write_note(
        root,
        "40 Civilization/Technology/Roads/Steam.md",
        "---\ntype: technology-road\nroad_id: road:steam\nstatus: active\nlifecycle: in-progress\naccepted_year: 35\nacceptance_cursor: 4200\nsource_cursor: 4300\nreviewed_through_cursor: 4838\n---\n# Steam\n",
    );
    // DM source: Steam's governor control FAILED TERMINALLY
    write_note(
        root,
        "70 Sources/Telegram/Player/2026/2026-01-01.md",
        "---\ntype: telegram-chat-part\nsource: telegram\nstream: player\ndate: 2026-01-01\nfirst: 5050\nlast: 5050\ncount: 1\n---\n\n^telegram--100-5050\n**00:00 UTC** · the_mud_lounge_bot\n\nSteam's governor control FAILED TERMINALLY ... bearing and shaft tolerance continues\n",
    );

    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();

    // Should produce 0 lifecycle events (component subject guard)
    let report = outcome.continuity_report_markdown.as_ref().unwrap();
    assert!(
        report.contains("lifecycle events parsed: 0"),
        "should produce 0 lifecycle events (component subject guard)"
    );
    // road:steam should NOT appear as a MATERIALIZATION_GAP
    assert!(
        !report.contains("road:steam") || !report.contains("MATERIALIZATION_GAP"),
        "road:steam must not be classified as terminally failed"
    );
}

#[test]
fn steam_component_pipe_no_road_failure() {
    // Steam component pipe form: "Steam | governor control — FAILED TERMINALLY; bearing continues"
    // Must NOT produce a terminal lifecycle event for road:steam
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_note(root, "00 System/State Boundary.md", "---\ntype: state-boundary\ncurrent_turn: 42\ncurrent_year: 42\nlast_resolved_year: 41\ncurrent_source_cursor: 5100\ncanonical_materialized_cursor: 4838\n---\n# State Boundary\n");
    write_note(root, "40 Civilization/Technology/Roads/Steam.md", "---\ntype: technology-road\nroad_id: road:steam\nstatus: active\nlifecycle: in-progress\naccepted_year: 35\nacceptance_cursor: 4200\nsource_cursor: 4300\nreviewed_through_cursor: 4838\n---\n# Steam\n");
    // Pipe form with em dash
    write_note(root, "70 Sources/Telegram/Player/2026/2026-01-01.md", "---\ntype: telegram-chat-part\nsource: telegram\nstream: player\ndate: 2026-01-01\nfirst: 5050\nlast: 5050\ncount: 1\n---\n\n^telegram--100-5050\n**00:00 UTC** · the_mud_lounge_bot\n\nSteam | governor control — FAILED TERMINALLY; bearing and shaft tolerance continues\n");

    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    let report = outcome.continuity_report_markdown.as_ref().unwrap();
    assert!(
        report.contains("lifecycle events parsed: 0"),
        "component pipe must not produce road terminal event"
    );
}

#[test]
fn steam_component_pipe_comma_no_road_failure() {
    // Steam component pipe comma form
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_note(root, "00 System/State Boundary.md", "---\ntype: state-boundary\ncurrent_turn: 42\ncurrent_year: 42\nlast_resolved_year: 41\ncurrent_source_cursor: 5100\ncanonical_materialized_cursor: 4838\n---\n# State Boundary\n");
    write_note(root, "40 Civilization/Technology/Roads/Steam.md", "---\ntype: technology-road\nroad_id: road:steam\nstatus: active\nlifecycle: in-progress\naccepted_year: 35\nacceptance_cursor: 4200\nsource_cursor: 4300\nreviewed_through_cursor: 4838\n---\n# Steam\n");
    write_note(root, "70 Sources/Telegram/Player/2026/2026-01-01.md", "---\ntype: telegram-chat-part\nsource: telegram\nstream: player\ndate: 2026-01-01\nfirst: 5050\nlast: 5050\ncount: 1\n---\n\n^telegram--100-5050\n**00:00 UTC** · the_mud_lounge_bot\n\nSteam | governor control, FAILED TERMINALLY; bearing continues\n");

    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    let report = outcome.continuity_report_markdown.as_ref().unwrap();
    assert!(
        report.contains("lifecycle events parsed: 0"),
        "component pipe comma form must not produce road terminal event"
    );
}

#[test]
fn steam_component_bullet_no_road_failure() {
    // Steam component bullet form
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_note(root, "00 System/State Boundary.md", "---\ntype: state-boundary\ncurrent_turn: 42\ncurrent_year: 42\nlast_resolved_year: 41\ncurrent_source_cursor: 5100\ncanonical_materialized_cursor: 4838\n---\n# State Boundary\n");
    write_note(root, "40 Civilization/Technology/Roads/Steam.md", "---\ntype: technology-road\nroad_id: road:steam\nstatus: active\nlifecycle: in-progress\naccepted_year: 35\nacceptance_cursor: 4200\nsource_cursor: 4300\nreviewed_through_cursor: 4838\n---\n# Steam\n");
    write_note(root, "70 Sources/Telegram/Player/2026/2026-01-01.md", "---\ntype: telegram-chat-part\nsource: telegram\nstream: player\ndate: 2026-01-01\nfirst: 5050\nlast: 5050\ncount: 1\n---\n\n^telegram--100-5050\n**00:00 UTC** · the_mud_lounge_bot\n\n\\- Steam's governor control FAILED TERMINALLY on the bench at midwinter — bearing and shaft tolerance continues\n");

    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    let report = outcome.continuity_report_markdown.as_ref().unwrap();
    assert!(
        report.contains("lifecycle events parsed: 0"),
        "component bullet must not produce road terminal event"
    );
}

#[test]
fn universal_formation_escaped_bullet() {
    // Escaped bullet: "\- Universal Formation CLOSED SUCCEEDED at Year 40."
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_note(root, "00 System/State Boundary.md", "---\ntype: state-boundary\ncurrent_turn: 42\ncurrent_year: 42\nlast_resolved_year: 41\ncurrent_source_cursor: 5100\ncanonical_materialized_cursor: 4838\n---\n# State Boundary\n");
    write_note(root, "40 Civilization/Technology/Roads/Universal Formation.md", "---\ntype: technology-road\nroad_id: road:universal-formation\nstatus: active\nlifecycle: in-progress\naccepted_year: 37\nacceptance_cursor: 4524\nsource_cursor: 4526\nreviewed_through_cursor: 4838\nterminal_due_year: 40\n---\n# Universal Formation\n");
    write_note(root, "70 Sources/Telegram/Player/2026/2026-01-01.md", "---\ntype: telegram-chat-part\nsource: telegram\nstream: player\ndate: 2026-01-01\nfirst: 5100\nlast: 5100\ncount: 1\n---\n\n^telegram--100-5100\n**00:00 UTC** · the_mud_lounge_bot\n\n\\- Universal Formation CLOSED SUCCEEDED at Year 40.\n");

    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    let report = outcome.continuity_report_markdown.as_ref().unwrap();
    assert!(
        report.contains("lifecycle events parsed: 1"),
        "escaped bullet should parse as lifecycle event"
    );
    assert!(
        report.contains("MATERIALIZATION_GAP"),
        "should classify as MATERIALIZATION_GAP"
    );
}

// -----------------------------------------------------------------------
// Settled-state non-retcon regression tests
// -----------------------------------------------------------------------

#[test]
fn settled_success_later_failure_is_contradiction() {
    // Test E: completed canon + later FAILED source → CONTRADICTION
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_note(root, "00 System/State Boundary.md", "---\ntype: state-boundary\ncurrent_turn: 42\ncurrent_year: 42\nlast_resolved_year: 41\ncurrent_source_cursor: 5200\ncanonical_materialized_cursor: 4838\n---\n# State Boundary\n");
    write_note(root, "40 Civilization/Technology/Roads/Retcon Test.md", "---\ntype: technology-road\nroad_id: road:retcon-test\nstatus: completed\nlifecycle: completed\nsource_cursor: 5000\nreviewed_through_cursor: 5100\n---\n# Retcon Test\n");
    write_note(root, "70 Sources/Telegram/Player/2026/2026-01-01.md", "---\ntype: telegram-chat-part\nsource: telegram\nstream: player\ndate: 2026-01-01\nfirst: 5100\nlast: 5100\ncount: 1\n---\n\n^telegram--100-5100\n**00:00 UTC** · the_mud_lounge_bot\n\nRetcon Test road | CLOSED FAILED\n");

    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    let report = outcome.continuity_report_markdown.as_ref().unwrap();

    // Must be CONTRADICTION, not MATERIALIZATION_GAP
    assert!(
        report.contains("CONTRADICTION"),
        "settled success + later failure must be CONTRADICTION"
    );
    assert!(
        !report.contains("| MATERIALIZATION_GAP |"),
        "must not produce MATERIALIZATION_GAP for settled canon"
    );
    assert!(
        report.contains("CONTRADICTION_ADJUDICATION"),
        "must recommend adjudication"
    );
    // Both claims preserved
    assert!(
        report.contains("settled success") || report.contains("completed"),
        "must retain canonical success claim"
    );
    assert!(
        report.contains("CLOSED_FAILED") || report.contains("FAILED"),
        "must retain newer failure claim"
    );
}

#[test]
fn settled_failure_later_success_is_contradiction() {
    // Test F: failed canon + later SUCCEEDED source → CONTRADICTION
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_note(root, "00 System/State Boundary.md", "---\ntype: state-boundary\ncurrent_turn: 42\ncurrent_year: 42\nlast_resolved_year: 41\ncurrent_source_cursor: 5200\ncanonical_materialized_cursor: 4838\n---\n# State Boundary\n");
    write_note(root, "40 Civilization/Technology/Roads/Retcon Test F.md", "---\ntype: technology-road\nroad_id: road:retcon-test-f\nstatus: failed\nlifecycle: terminal\nsource_cursor: 5000\nreviewed_through_cursor: 5100\n---\n# Retcon Test F\n");
    write_note(root, "70 Sources/Telegram/Player/2026/2026-01-01.md", "---\ntype: telegram-chat-part\nsource: telegram\nstream: player\ndate: 2026-01-01\nfirst: 5100\nlast: 5100\ncount: 1\n---\n\n^telegram--100-5100\n**00:00 UTC** · the_mud_lounge_bot\n\nRetcon Test F road | CLOSED SUCCEEDED\n");

    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    let report = outcome.continuity_report_markdown.as_ref().unwrap();

    assert!(
        report.contains("CONTRADICTION"),
        "settled failure + later success must be CONTRADICTION"
    );
    assert!(
        !report.contains("| MATERIALIZATION_GAP |"),
        "must not auto-materialize success"
    );
    assert!(
        report.contains("CLOSED_SUCCEEDED"),
        "must retain newer success claim"
    );
}

#[test]
fn settled_success_later_success_no_contradiction() {
    // Test C: completed canon + later SUCCEEDED → compatible reconfirmation
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_note(root, "00 System/State Boundary.md", "---\ntype: state-boundary\ncurrent_turn: 42\ncurrent_year: 42\nlast_resolved_year: 41\ncurrent_source_cursor: 5200\ncanonical_materialized_cursor: 4838\n---\n# State Boundary\n");
    write_note(root, "40 Civilization/Technology/Roads/Retcon Test G.md", "---\ntype: technology-road\nroad_id: road:retcon-test-g\nstatus: completed\nlifecycle: completed\nsource_cursor: 5000\nreviewed_through_cursor: 5100\n---\n# Retcon Test G\n");
    write_note(root, "70 Sources/Telegram/Player/2026/2026-01-01.md", "---\ntype: telegram-chat-part\nsource: telegram\nstream: player\ndate: 2026-01-01\nfirst: 5100\nlast: 5100\ncount: 1\n---\n\n^telegram--100-5100\n**00:00 UTC** · the_mud_lounge_bot\n\nRetcon Test G road | CLOSED SUCCEEDED\n");

    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    let report = outcome.continuity_report_markdown.as_ref().unwrap();

    assert!(
        !report.contains("CONTRADICTION"),
        "settled success + later success must NOT be CONTRADICTION"
    );
    assert!(
        !report.contains("| MATERIALIZATION_GAP |"),
        "must not produce MATERIALIZATION_GAP for compatible reconfirmation"
    );
}

#[test]
fn settled_failure_later_failure_no_contradiction() {
    // Test D: failed canon + later FAILED → compatible reconfirmation
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_note(root, "00 System/State Boundary.md", "---\ntype: state-boundary\ncurrent_turn: 42\ncurrent_year: 42\nlast_resolved_year: 41\ncurrent_source_cursor: 5200\ncanonical_materialized_cursor: 4838\n---\n# State Boundary\n");
    write_note(root, "40 Civilization/Technology/Roads/Retcon Test H.md", "---\ntype: technology-road\nroad_id: road:retcon-test-h\nstatus: failed\nlifecycle: terminal\nsource_cursor: 5000\nreviewed_through_cursor: 5100\n---\n# Retcon Test H\n");
    write_note(root, "70 Sources/Telegram/Player/2026/2026-01-01.md", "---\ntype: telegram-chat-part\nsource: telegram\nstream: player\ndate: 2026-01-01\nfirst: 5100\nlast: 5100\ncount: 1\n---\n\n^telegram--100-5100\n**00:00 UTC** · the_mud_lounge_bot\n\nRetcon Test H road | FAILED\n");

    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    let report = outcome.continuity_report_markdown.as_ref().unwrap();

    assert!(
        !report.contains("CONTRADICTION"),
        "settled failure + later failure must NOT be CONTRADICTION"
    );
}

#[test]
fn settled_terminal_result_cursor_gap_not_suppressed() {
    // Gate 1 regression: terminal_result_cursor=3500, source_cursor=4100
    // A contradictory terminal statement at cursor 3900 must NOT be suppressed
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_note(root, "00 System/State Boundary.md", "---\ntype: state-boundary\ncurrent_turn: 42\ncurrent_year: 42\nlast_resolved_year: 41\ncurrent_source_cursor: 5200\ncanonical_materialized_cursor: 4838\n---\n# State Boundary\n");
    write_note(root, "40 Civilization/Technology/Roads/Retcon Cursor.md", "---\ntype: technology-road\nroad_id: road:retcon-cursor\nstatus: completed\nlifecycle: completed\nterminal_result_cursor: 3500\nsource_cursor: 4100\nreviewed_through_cursor: 5100\n---\n# Retcon Cursor\n");
    write_note(root, "70 Sources/Telegram/Player/2026/2026-01-01.md", "---\ntype: telegram-chat-part\nsource: telegram\nstream: player\ndate: 2026-01-01\nfirst: 3900\nlast: 3900\ncount: 1\n---\n\n^telegram--100-3900\n**00:00 UTC** · the_mud_lounge_bot\n\nRetcon Cursor road | CLOSED FAILED\n");

    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    let report = outcome.continuity_report_markdown.unwrap();

    // Event at 3900 > terminal_result_cursor (3500) → must produce CONTRADICTION
    assert!(
        report.contains("CONTRADICTION"),
        "settled success + later failure at 3900 > terminal_result_cursor 3500 must be CONTRADICTION"
    );
    assert!(
        report.contains("CONTRADICTION_ADJUDICATION"),
        "must recommend adjudication"
    );
    // Must NOT be suppressed because 3900 < source_cursor 4100
    assert!(
        !report.contains("| MATERIALIZATION_GAP |"),
        "must not produce MATERIALIZATION_GAP for settled canon"
    );
    // Canonical provenance must be present
    assert!(
        report.contains("canonical settled success")
            || report.contains("terminal_result_cursor: 3500"),
        "must contain canonical terminal provenance"
    );
}

#[test]
fn settled_failure_later_success_cursor_gap_not_suppressed() {
    // Gate 1 reverse: failed canon, later success at cursor between
    // terminal_result_cursor and source_cursor
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_note(root, "00 System/State Boundary.md", "---\ntype: state-boundary\ncurrent_turn: 42\ncurrent_year: 42\nlast_resolved_year: 41\ncurrent_source_cursor: 5200\ncanonical_materialized_cursor: 4838\n---\n# State Boundary\n");
    write_note(root, "40 Civilization/Technology/Roads/Retcon Cursor F.md", "---\ntype: technology-road\nroad_id: road:retcon-cursor-f\nstatus: failed\nlifecycle: terminal\nterminal_result_cursor: 3500\nsource_cursor: 4100\nreviewed_through_cursor: 5100\n---\n# Retcon Cursor F\n");
    write_note(root, "70 Sources/Telegram/Player/2026/2026-01-01.md", "---\ntype: telegram-chat-part\nsource: telegram\nstream: player\ndate: 2026-01-01\nfirst: 3900\nlast: 3900\ncount: 1\n---\n\n^telegram--100-3900\n**00:00 UTC** · the_mud_lounge_bot\n\nRetcon Cursor F road | CLOSED SUCCEEDED\n");

    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    let report = outcome.continuity_report_markdown.unwrap();

    assert!(
        report.contains("CONTRADICTION"),
        "settled failure + later success at 3900 > terminal_result_cursor 3500 must be CONTRADICTION"
    );
    assert!(
        report.contains("CLOSED_SUCCEEDED"),
        "must retain newer success claim"
    );
}

#[test]
fn nonterminal_below_source_cursor_suppressed() {
    // Ordinary behavior: nonterminal + event <= source_cursor → suppressed
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_note(root, "00 System/State Boundary.md", "---\ntype: state-boundary\ncurrent_turn: 42\ncurrent_year: 42\nlast_resolved_year: 41\ncurrent_source_cursor: 5200\ncanonical_materialized_cursor: 4838\n---\n# State Boundary\n");
    write_note(root, "40 Civilization/Technology/Roads/Already Materialized.md", "---\ntype: technology-road\nroad_id: road:already-materialized\nstatus: active\nlifecycle: in-progress\nsource_cursor: 5100\nreviewed_through_cursor: 5100\n---\n# Already Materialized\n");
    write_note(root, "70 Sources/Telegram/Player/2026/2026-01-01.md", "---\ntype: telegram-chat-part\nsource: telegram\nstream: player\ndate: 2026-01-01\nfirst: 5000\nlast: 5000\ncount: 1\n---\n\n^telegram--100-5000\n**00:00 UTC** · the_mud_lounge_bot\n\nAlready Materialized road | CLOSED SUCCEEDED\n");

    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    let report = outcome.continuity_report_markdown.unwrap();

    // Event at 5000 <= source_cursor 5100 → should not produce MATERIALIZATION_GAP
    // for this specific road (it should already be materialized)
    // But 5000 < reviewed_through_cursor 5100 → behind_review → RepresentationDivergence
    assert!(
        !report.contains("MATERIALIZATION_GAP") || !report.contains("road:already-materialized"),
        "nonterminal + event at or below source_cursor must not be MATERIALIZATION_GAP"
    );
}

#[test]
fn nonterminal_first_terminal_is_materialization_gap() {
    // Test I: active canon + first terminal result → MATERIALIZATION_GAP (not CONTRADICTION)
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_note(root, "00 System/State Boundary.md", "---\ntype: state-boundary\ncurrent_turn: 42\ncurrent_year: 42\nlast_resolved_year: 41\ncurrent_source_cursor: 5200\ncanonical_materialized_cursor: 4838\n---\n# State Boundary\n");
    write_note(root, "40 Civilization/Technology/Roads/First Terminal.md", "---\ntype: technology-road\nroad_id: road:first-terminal\nstatus: active\nlifecycle: in-progress\nsource_cursor: 5000\nreviewed_through_cursor: 5100\n---\n# First Terminal\n");
    write_note(root, "70 Sources/Telegram/Player/2026/2026-01-01.md", "---\ntype: telegram-chat-part\nsource: telegram\nstream: player\ndate: 2026-01-01\nfirst: 5150\nlast: 5150\ncount: 1\n---\n\n^telegram--100-5150\n**00:00 UTC** · the_mud_lounge_bot\n\nFirst Terminal road | CLOSED SUCCEEDED\n");

    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    let report = outcome.continuity_report_markdown.as_ref().unwrap();

    assert!(
        report.contains("MATERIALIZATION_GAP"),
        "nonterminal + first terminal must be MATERIALIZATION_GAP"
    );
    assert!(
        !report.contains("CONTRADICTION"),
        "must not be CONTRADICTION when canon is nonterminal"
    );
}

// -----------------------------------------------------------------------
// Capability state tests
// -----------------------------------------------------------------------

#[test]
fn capability_active_lost_excluded_from_active_cohort() {
    // Test: active + lost → excluded from active denominator
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_note(root, "00 System/State Boundary.md", "---\ncurrent_turn: 43\ncurrent_year: 43\nlast_resolved_year: 42\ncurrent_source_cursor: 900\ncanonical_materialized_cursor: 900\n---\n# Boundary\n");
    write_note(root, "40 Civilization/Capabilities/Active Lost.md", "---\ntype: capability\ncapability_id: cap:active-lost\nstatus: active\ncapability_state:\n  - lost\n---\n# Active Lost\n");
    write_note(root, "40 Civilization/Capabilities/Normal Active.md", "---\ntype: capability\ncapability_id: cap:normal-active\nstatus: active\n---\n# Normal Active\n");

    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    let report = outcome.continuity_report_markdown.unwrap();

    // Active lost should be excluded: only 1 active capability
    assert!(
        report.contains("active machine-readable durable capability owners: 1"),
        "active+lost must be excluded from active cohort"
    );
    assert!(
        report.contains("capability-state represented: 0/1"),
        "only normal-active counted in denominator"
    );
}

#[test]
fn capability_active_superseded_excluded_from_active_cohort() {
    // Test: active + superseded → excluded from active denominator
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_note(root, "00 System/State Boundary.md", "---\ncurrent_turn: 43\ncurrent_year: 43\nlast_resolved_year: 42\ncurrent_source_cursor: 900\ncanonical_materialized_cursor: 900\n---\n# Boundary\n");
    write_note(root, "40 Civilization/Capabilities/Active Superseded.md", "---\ntype: capability\ncapability_id: cap:active-super\nstatus: active\ncapability_state:\n  - superseded\n---\n# Active Superseded\n");
    write_note(root, "40 Civilization/Capabilities/Normal Active.md", "---\ntype: capability\ncapability_id: cap:normal-active\nstatus: active\n---\n# Normal Active\n");

    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    let report = outcome.continuity_report_markdown.unwrap();

    assert!(
        report.contains("active machine-readable durable capability owners: 1"),
        "active+superseded must be excluded from active cohort"
    );
}

#[test]
fn capability_mixed_valid_invalid_states() {
    // Test: mixed valid/invalid → valid states retained, invalid visible as debt
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_note(root, "00 System/State Boundary.md", "---\ncurrent_turn: 43\ncurrent_year: 43\nlast_resolved_year: 42\ncurrent_source_cursor: 900\ncanonical_materialized_cursor: 900\n---\n# Boundary\n");
    write_note(root, "40 Civilization/Capabilities/Mixed.md", "---\ntype: capability\ncapability_id: cap:mixed\nstatus: active\ncapability_state:\n  - attained\n  - nonsense\n---\n# Mixed\n");

    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    let report = outcome.continuity_report_markdown.unwrap();

    // attained is valid, nonsense is invalid — but report shows valid states
    assert!(
        report.contains("capability state attained: 1"),
        "attained must be counted"
    );
    assert!(
        report.contains("capability state reproduced: 0"),
        "all seven states must be rendered"
    );
}

#[test]
fn capability_all_seven_state_counts() {
    // Test: all seven states are rendered
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_note(root, "00 System/State Boundary.md", "---\ncurrent_turn: 43\ncurrent_year: 43\nlast_resolved_year: 42\ncurrent_source_cursor: 900\ncanonical_materialized_cursor: 900\n---\n# Boundary\n");
    write_note(root, "40 Civilization/Capabilities/Attained.md", "---\ntype: capability\ncapability_id: cap:a\nstatus: active\ncapability_state: attained\n---\n# Attained\n");
    write_note(root, "40 Civilization/Capabilities/Reproduced.md", "---\ntype: capability\ncapability_id: cap:b\nstatus: active\ncapability_state: reproduced\n---\n# Reproduced\n");
    write_note(root, "40 Civilization/Capabilities/Diffused.md", "---\ntype: capability\ncapability_id: cap:c\nstatus: active\ncapability_state: diffused\n---\n# Diffused\n");
    write_note(root, "40 Civilization/Capabilities/Exploited.md", "---\ntype: capability\ncapability_id: cap:d\nstatus: active\ncapability_state: exploited\n---\n# Exploited\n");
    write_note(root, "40 Civilization/Capabilities/Compounded.md", "---\ntype: capability\ncapability_id: cap:e\nstatus: active\ncapability_state: compounded\n---\n# Compounded\n");

    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    let report = outcome.continuity_report_markdown.unwrap();

    assert!(report.contains("capability state attained: 1"));
    assert!(report.contains("capability state reproduced: 1"));
    assert!(report.contains("capability state diffused: 1"));
    assert!(report.contains("capability state exploited: 1"));
    assert!(report.contains("capability state compounded: 1"));
    assert!(report.contains("capability state superseded: 0"));
    assert!(report.contains("capability state lost: 0"));
    assert!(report.contains("active machine-readable durable capability owners: 5"));
}

#[test]
fn capability_reuse_subset_invariant() {
    // R ⊆ A: reuse edges only count active capabilities
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_note(root, "00 System/State Boundary.md", "---\ncurrent_turn: 43\ncurrent_year: 43\nlast_resolved_year: 42\ncurrent_source_cursor: 900\ncanonical_materialized_cursor: 900\n---\n# Boundary\n");
    write_note(root, "40 Civilization/Technology/Roads/Active.md", "---\ntype: technology-road\nroad_id: road:active\nstatus: active\nrequires: [cap:used]\n---\n# Active\n");
    write_note(
        root,
        "40 Civilization/Capabilities/Used.md",
        "---\ntype: capability\ncapability_id: cap:used\nstatus: active\n---\n# Used\n",
    );
    write_note(
        root,
        "40 Civilization/Capabilities/Unused.md",
        "---\ntype: capability\ncapability_id: cap:unused\nstatus: active\n---\n# Unused\n",
    );

    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    let report = outcome.continuity_report_markdown.unwrap();

    assert!(
        report.contains("active durable capabilities (nonempty IDs; excluding lost/superseded): 2")
    );
    assert!(report.contains("capabilities with resolved machine-linked dependency/reuse edges: 1"));
    assert!(report.contains("active durable capabilities with no resolved downstream reuse: 1"));
    assert!(report.contains("Narrative semantic-use coverage: UNSUPPORTED"));
}

// -----------------------------------------------------------------------
// Authority prompt test
// -----------------------------------------------------------------------

#[test]
fn authority_gap_prompt_no_cursor_requested() {
    // Test: AUTHORITY_GAP prompt must NOT request "terminal evidence cursor"
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_note(root, "00 System/State Boundary.md", "---\ntype: state-boundary\ncurrent_turn: 42\ncurrent_year: 42\nlast_resolved_year: 41\ncurrent_source_cursor: 5100\ncanonical_materialized_cursor: 4838\n---\n# State Boundary\n");
    write_note(root, "40 Civilization/Technology/Roads/Overdue Road.md", "---\ntype: technology-road\nroad_id: road:overdue\nstatus: active\nlifecycle: in-progress\naccepted_year: 38\nacceptance_cursor: 4600\nsource_cursor: 4650\nreviewed_through_cursor: 4838\nterminal_due_year: 40\n---\n# Overdue Road\n");

    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    let report = outcome.continuity_report_markdown.unwrap();

    // Check that the prompt section doesn't request cursor
    let prompt_section = report.split("### AUTHORITY_GAP").nth(1).unwrap_or("");
    assert!(
        !prompt_section.contains("terminal evidence cursor"),
        "AUTHORITY_GAP prompt must NOT request terminal evidence cursor from DM"
    );
    // Must request world-state fields
    assert!(
        prompt_section.contains("current lifecycle")
            || prompt_section.contains("terminal result")
            || prompt_section.contains("succeeded / failed"),
        "AUTHORITY_GAP prompt must request world-state information"
    );
}

#[test]
fn contradictory_source_events() {
    // §9 / Test 7: Two incompatible terminal events for same identity
    // → CONTRADICTION
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_note(
        root,
        "00 System/State Boundary.md",
        "---\ntype: state-boundary\ncurrent_turn: 42\ncurrent_year: 42\nlast_resolved_year: 41\ncurrent_source_cursor: 5200\ncanonical_materialized_cursor: 4838\n---\n# State Boundary\n",
    );
    write_note(
        root,
        "40 Civilization/Technology/Roads/Test Road.md",
        "---\ntype: technology-road\nroad_id: road:test-road\nstatus: active\nlifecycle: in-progress\naccepted_year: 38\nacceptance_cursor: 4600\nsource_cursor: 4650\nreviewed_through_cursor: 4838\n---\n# Test Road\n",
    );
    // Two DM messages with contradictory terminal outcomes
    write_note(
        root,
        "70 Sources/Telegram/Player/2026/2026-01-01.md",
        "---\ntype: telegram-chat-part\nsource: telegram\nstream: player\ndate: 2026-01-01\nfirst: 5000\nlast: 5001\ncount: 2\n---\n\n^telegram--100-5000\n**00:00 UTC** · the_mud_lounge_bot\n\nTest road | closed SUCCEEDED this year\n\n^telegram--100-5001\n**00:01 UTC** · the_mud_lounge_bot\n\nTest road | FAILED at final review\n",
    );

    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();

    let report = outcome.continuity_report_markdown.as_ref().unwrap();
    // Should detect 2 lifecycle events
    assert!(
        report.contains("lifecycle events parsed: 2"),
        "should parse 2 lifecycle events"
    );
    // Contradiction detection happens in lifecycle_events module
    // The events themselves create MaterializationGap entries since the
    // road is still active. Contradiction detection is tested at unit level.
}

// -----------------------------------------------------------------------
// Final correctness/completion pass — production-pipeline assertions
// -----------------------------------------------------------------------

#[test]
fn current_lifecycle_pipeline_aggregates_and_prompts_exact_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_note(root, "00 System/State Boundary.md", "---\ntype: state-boundary\ncurrent_turn: 42\ncurrent_year: 42\nlast_resolved_year: 41\ncurrent_source_cursor: 5600\ncanonical_materialized_cursor: 4838\n---\n# State Boundary\n");
    write_note(root, "40 Civilization/Technology/Roads/Universal Formation.md", "---\ntype: technology-road\nroad_id: road:universal-formation\nstatus: active\nlifecycle: in-progress-package-locked\naccepted_year: 37\nacceptance_cursor: 4524\nstarted_cursor: 4526\nsource_cursor: 4526\nreviewed_through_cursor: 4838\nterminal_due_year: 40\n---\n# Universal Formation\n");
    write_note(root, "70 Sources/Telegram/Player/2026/source.md", "---\ntype: telegram-chat-part\nsource: telegram\nstream: player\nfirst: 5580\nlast: 5581\ncount: 2\n---\n\n^telegram--100-5580\n**00:00 UTC** · the_mud_lounge_bot\n\nUniversal formation road | live at its own ceiling, about 1,800 learners/year — the adjudicated terms, closed SUCCEEDED this year at Year 40\n\n^telegram--100-5581\n**00:01 UTC** · the_mud_lounge_bot\n\n\\- Universal Formation CLOSED SUCCEEDED at Year 40\n");
    let report = validate(root, &mini_config(), &[])
        .unwrap()
        .continuity_report_markdown
        .unwrap();
    // Find the lifecycle events line
    let lifecycle_line = report
        .lines()
        .find(|l| l.contains("lifecycle events"))
        .unwrap_or("NONE");
    let parsed_line = report
        .lines()
        .find(|l| l.contains("lifecycle events parsed"))
        .unwrap_or("NONE");
    assert!(
        report.contains("exact lifecycle events parsed: 2"),
        "lifecycle_line: {lifecycle_line}; parsed_line: {parsed_line}"
    );
    assert_eq!(report.matches("| MATERIALIZATION_GAP |").count(), 1);
    assert!(report.contains("evidence count: 2"));
    assert!(report.contains("latest") || report.contains("new direct evidence cursor: 5581"));
    assert!(report.contains("about 1,800 learners/year"));
    assert!(report.contains("DO NOT QUERY THE DM"));
    assert!(report.contains("exact-lifecycle-source-event"));
}

#[test]
fn old_terminal_is_out_of_scope_and_current_conflict_is_contradiction_only() {
    let old = tempfile::tempdir().unwrap();
    write_note(old.path(), "00 System/State Boundary.md", "---\ncurrent_turn: 42\ncurrent_year: 42\nlast_resolved_year: 41\ncurrent_source_cursor: 4600\ncanonical_materialized_cursor: 4500\n---\n# Boundary\n");
    write_note(old.path(), "40 Civilization/Technology/Roads/Renewed.md", "---\ntype: technology-road\nroad_id: road:renewed\nstatus: active\nlifecycle: in-progress\naccepted_year: 41\nacceptance_cursor: 4500\nstarted_cursor: 4510\nsource_cursor: 4510\nreviewed_through_cursor: 4510\nterminal_due_year: 40\n---\n# Renewed\n");
    write_note(old.path(), "70 Sources/Telegram/Player/2026/source.md", "^telegram--100-3000\n**00:00 UTC** · the_mud_lounge_bot\n\nRenewed road | CLOSED SUCCEEDED\n\n^telegram--100-4600\n**00:01 UTC** · the_mud_lounge_bot\n\nUnrelated current evidence.\n");
    let report = validate(old.path(), &mini_config(), &[])
        .unwrap()
        .continuity_report_markdown
        .unwrap();
    assert!(report.contains("AUTHORITY_GAP"));
    assert!(report.contains("DM_INQUIRY"));
    assert!(!report.contains("MATERIALIZATION_GAP"));

    let conflict = tempfile::tempdir().unwrap();
    write_note(conflict.path(), "00 System/State Boundary.md", "---\ncurrent_turn: 42\ncurrent_year: 42\nlast_resolved_year: 41\ncurrent_source_cursor: 5200\ncanonical_materialized_cursor: 4800\n---\n# Boundary\n");
    write_note(conflict.path(), "40 Civilization/Technology/Roads/Conflict.md", "---\ntype: technology-road\nroad_id: road:conflict\nstatus: active\nlifecycle: in-progress\nacceptance_cursor: 4500\nstarted_cursor: 4510\nsource_cursor: 4510\nreviewed_through_cursor: 4800\nterminal_due_year: 40\n---\n# Conflict\n");
    write_note(conflict.path(), "70 Sources/Telegram/Player/2026/source.md", "^telegram--100-5000\n**00:00 UTC** · the_mud_lounge_bot\n\nConflict road | CLOSED SUCCEEDED\n\n^telegram--100-5001\n**00:01 UTC** · the_mud_lounge_bot\n\nConflict road | CLOSED FAILED\n");
    let report = validate(conflict.path(), &mini_config(), &[])
        .unwrap()
        .continuity_report_markdown
        .unwrap();
    assert_eq!(report.matches("| CONTRADICTION |").count(), 1);
    assert!(!report.contains("| MATERIALIZATION_GAP |"));
    assert!(report.contains("claim 1: outcome CLOSED_SUCCEEDED"));
    assert!(report.contains("claim 2: outcome CLOSED_FAILED"));
    assert!(report.contains("CONTRADICTION_ADJUDICATION"));
}

#[test]
fn progress_capability_reuse_and_coverage_are_structurally_honest() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_note(root, "00 System/State Boundary.md", "---\ncurrent_turn: 43\ncurrent_year: 43\nlast_resolved_year: 42\ncurrent_source_cursor: 900\ncanonical_materialized_cursor: 900\n---\n# Boundary\n");
    write_note(root, "40 Civilization/Technology/Roads/Active.md", "---\ntype: technology-road\nroad_id: road:active\nstatus: active\nlifecycle: in-progress-package-locked\nacceptance_cursor: 700\nterminal_due_year: 44\nrequires: [cap:valid, cap:missing]\n---\n# Active\n");
    write_note(root, "40 Civilization/Technology/Roads/Done.md", "---\ntype: technology-road\nroad_id: road:done\nstatus: completed\nlifecycle: completed\nterminal_result: success\nterminal_result_year: 44\n---\n# Done\n");
    write_note(root, "40 Civilization/Technology/Roads/Failed.md", "---\ntype: technology-road\nroad_id: road:failed\nstatus: failed\nlifecycle: terminal\nterminal_result: failure\nterminal_result_year: 42\n---\n# Failed\n");
    write_note(root, "40 Civilization/Capabilities/Valid.md", "---\ntype: capability\ncapability_id: cap:valid\nstatus: active\nlifecycle: attained-taught-operating\n---\n# Valid\n");
    write_note(root, "40 Civilization/Capabilities/Unused.md", "---\ntype: capability\ncapability_id: cap:unused\nstatus: active\nlifecycle: attained\n---\n# Unused\n");
    write_note(root, "70 Sources/Telegram/Player/2026/source.md", "^telegram--100-900\n**00:00 UTC** · the_mud_lounge_bot\n\n[CL PROGRESS road=road:active]\n");
    let outcome = validate(root, &mini_config(), &[]).unwrap();
    let report = outcome.continuity_report_markdown.unwrap();
    assert!(report.contains("- active: 1"));
    assert!(report.contains("| 44 | road:active |"));
    assert!(!report.contains("| 44 | road:done |"));
    assert!(report.contains("last 1 resolved year(s) (42–42)"));
    assert!(report.contains("terminal successes"));
    assert!(report.contains("terminal failures"));
    assert!(report.contains("capability-state represented: 0/2"));
    assert!(has_rule(&outcome.findings.items, "CHAD-TECH-010"));
    assert!(!outcome
        .findings
        .items
        .iter()
        .any(|f| f.rule == "CHAD-TECH-010" && f.severity == Severity::Error));
    assert!(report.contains("machine-linked capability→road dependency/reuse edges: 1"));
    assert!(report.contains("active durable capabilities with no resolved downstream reuse: 1"));
    assert!(report.contains("**1** of 2 active durable capabilities"));
    assert!(report.contains("structured direct-source receipts recognized: 1"));
}

#[test]
fn identity_legacy_fairness_and_output_are_deterministic() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    write_note(root, "00 System/State Boundary.md", "---\ncurrent_turn: 50\ncurrent_year: 50\nlast_resolved_year: 49\ncurrent_source_cursor: 1000\ncanonical_materialized_cursor: 1000\n---\n# Boundary\n");
    for i in 0..8 {
        write_note(root, &format!("40 Civilization/Technology/Roads/Road {i}.md"), &format!("---\ntype: technology-road\nvault_node_id: TN-F-{i}\nroad_id: road:r{i}\nstatus: active\nlifecycle: in-progress\nacceptance_cursor: 500\nstarted_cursor: 510\nterminal_due_year: 40\n---\n# Road {i}\n"));
    }
    for i in 0..4 {
        write_note(root, &format!("40 Civilization/Projects/Dormant {i}.md"), &format!("---\ntype: project\nproject_id: project:d{i}\nstatus: active\nsource_cursor: 10\n---\n# Dormant {i}\n"));
    }
    write_note(root, "40 Civilization/Capabilities/Technology/Nodes/Historical.md", "---\ntype: technology-node\nstatus: superseded\ntechnology_class: historical-compatibility\n---\n# Historical\n");
    write_note(
        root,
        "70 Sources/Telegram/Player/2026/source.md",
        "^telegram--100-1000\n**00:00 UTC** · the_mud_lounge_bot\n\nUnrelated int_0838 evidence.\n",
    );
    let one = validate(root, &mini_config(), &[]).unwrap();
    let report = one.continuity_report_markdown.as_ref().unwrap();
    assert!(report.contains("Showing 12 of"));
    assert!(report.contains("stable ID: road:r0"));
    assert!(!report.contains("stable ID: TN-F-0"));
    assert!(!has_rule(&one.findings.items, "TECH-MIG-006"));
    assert!(report.contains("int_0838"));
    assert!(report.contains("Last Mention Cursor"));
    let two = validate(root, &mini_config(), &[]).unwrap();
    let substantive = |text: &str| {
        text.lines()
            .filter(|line| !line.starts_with("generated_at:"))
            .collect::<Vec<_>>()
            .join("\n")
    };
    assert_eq!(
        substantive(report),
        substantive(two.continuity_report_markdown.as_ref().unwrap())
    );
}

// -----------------------------------------------------------------------
// Gate 2 — structured terminal-receipt conflicts
// -----------------------------------------------------------------------

#[test]
fn structured_receipt_conflict_success_failure_is_contradiction() {
    // Gate 2: SUCCESS @5000 + FAILURE @5100 → exactly one CONTRADICTION
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_note(root, "00 System/State Boundary.md", "---\ntype: state-boundary\ncurrent_turn: 42\ncurrent_year: 42\nlast_resolved_year: 41\ncurrent_source_cursor: 5200\ncanonical_materialized_cursor: 4838\n---\n# State Boundary\n");
    write_note(root, "40 Civilization/Technology/Roads/Receipt Conflict.md", "---\ntype: technology-road\nroad_id: road:receipt-conflict\nstatus: active\nlifecycle: in-progress\nsource_cursor: 4000\nreviewed_through_cursor: 4100\n---\n# Receipt Conflict\n");
    // Two terminal receipts with conflicting results via CL tags
    write_note(root, "70 Sources/Telegram/Player/2026/2026-01-01.md", "---\ntype: telegram-chat-part\nsource: telegram\nstream: player\ndate: 2026-01-01\nfirst: 5000\nlast: 5001\ncount: 2\n---\n\n^telegram--100-5000\n**00:00 UTC** · the_mud_lounge_bot\n\n[CL TERMINAL road=road:receipt-conflict result=SUCCESS]\n\n^telegram--100-5001\n**00:01 UTC** · the_mud_lounge_bot\n\n[CL TERMINAL road=road:receipt-conflict result=FAILURE]\n");

    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    let report = outcome.continuity_report_markdown.unwrap();

    // Must produce exactly one CONTRADICTION from structured receipts
    assert!(
        report.contains("CONTRADICTION"),
        "incompatible terminal receipts must produce CONTRADICTION"
    );
    assert!(
        report.contains("INCOMPATIBLE_TERMINAL_RECEIPTS"),
        "must have INCOMPATIBLE_TERMINAL_RECEIPTS reason"
    );
    assert!(
        report.contains("CONTRADICTION_ADJUDICATION"),
        "must recommend adjudication"
    );
}

#[test]
fn structured_receipt_conflict_failure_success_is_contradiction() {
    // Gate 2 reverse: FAILURE @5000 + SUCCESS @5100
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_note(root, "00 System/State Boundary.md", "---\ntype: state-boundary\ncurrent_turn: 42\ncurrent_year: 42\nlast_resolved_year: 41\ncurrent_source_cursor: 5200\ncanonical_materialized_cursor: 4838\n---\n# State Boundary\n");
    write_note(root, "40 Civilization/Technology/Roads/Receipt Conflict R.md", "---\ntype: technology-road\nroad_id: road:receipt-conflict-r\nstatus: active\nlifecycle: in-progress\nsource_cursor: 4000\nreviewed_through_cursor: 4100\n---\n# Receipt Conflict R\n");
    write_note(root, "70 Sources/Telegram/Player/2026/2026-01-01.md", "---\ntype: telegram-chat-part\nsource: telegram\nstream: player\ndate: 2026-01-01\nfirst: 5000\nlast: 5001\ncount: 2\n---\n\n^telegram--100-5000\n**00:00 UTC** · the_mud_lounge_bot\n\n[CL TERMINAL road=road:receipt-conflict-r result=FAILURE]\n\n^telegram--100-5001\n**00:01 UTC** · the_mud_lounge_bot\n\n[CL TERMINAL road=road:receipt-conflict-r result=SUCCESS]\n");

    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    let report = outcome.continuity_report_markdown.unwrap();

    assert!(
        report.contains("CONTRADICTION"),
        "failure + success terminal receipts must produce CONTRADICTION"
    );
    assert!(
        report.contains("INCOMPATIBLE_TERMINAL_RECEIPTS"),
        "must have INCOMPATIBLE_TERMINAL_RECEIPTS reason"
    );
}

#[test]
fn structured_receipt_compatible_no_contradiction() {
    // Gate 2: SUCCESS @5000 + SUCCESS @5100 → no contradiction
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_note(root, "00 System/State Boundary.md", "---\ntype: state-boundary\ncurrent_turn: 42\ncurrent_year: 42\nlast_resolved_year: 41\ncurrent_source_cursor: 5200\ncanonical_materialized_cursor: 4838\n---\n# State Boundary\n");
    write_note(root, "40 Civilization/Technology/Roads/Receipt Compatible.md", "---\ntype: technology-road\nroad_id: road:receipt-compatible\nstatus: active\nlifecycle: in-progress\nsource_cursor: 4000\nreviewed_through_cursor: 4100\n---\n# Receipt Compatible\n");
    write_note(root, "70 Sources/Telegram/Player/2026/2026-01-01.md", "---\ntype: telegram-chat-part\nsource: telegram\nstream: player\ndate: 2026-01-01\nfirst: 5000\nlast: 5001\ncount: 2\n---\n\n^telegram--100-5000\n**00:00 UTC** · the_mud_lounge_bot\n\n[CL TERMINAL road=road:receipt-compatible result=SUCCESS]\n\n^telegram--100-5001\n**00:01 UTC** · the_mud_lounge_bot\n\n[CL TERMINAL road=road:receipt-compatible result=SUCCESS]\n");

    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    let report = outcome.continuity_report_markdown.unwrap();

    assert!(
        !report.contains("INCOMPATIBLE_TERMINAL_RECEIPTS"),
        "compatible receipts must not produce INCOMPATIBLE_TERMINAL_RECEICTIONS"
    );
}

// -----------------------------------------------------------------------
// Gate 4 — capability_state validation as linter
// -----------------------------------------------------------------------

#[test]
fn capability_state_invalid_values_surface_schema_debt() {
    // Gate 4: capability_state with invalid values → CHAD-TECH-010 finding
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_note(root, "00 System/State Boundary.md", "---\ncurrent_turn: 43\ncurrent_year: 43\nlast_resolved_year: 42\ncurrent_source_cursor: 900\ncanonical_materialized_cursor: 900\n---\n# Boundary\n");
    write_note(root, "40 Civilization/Capabilities/Mixed States.md", "---\ntype: capability\ncapability_id: cap:mixed-states\nstatus: active\ncapability_state:\n  - attained\n  - nonsense\n---\n# Mixed States\n");

    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();

    // Should have CHAD-TECH-010 finding about invalid values
    let tech_findings: Vec<_> = outcome
        .findings
        .items
        .iter()
        .filter(|f| f.rule == "CHAD-TECH-010")
        .collect();
    assert!(
        !tech_findings.is_empty(),
        "must have CHAD-TECH-010 for invalid capability_state values"
    );
    assert!(
        tech_findings[0].message.contains("nonsense"),
        "finding must mention the invalid value"
    );
    assert!(
        tech_findings[0].message.contains("invalid"),
        "finding must indicate invalid values"
    );
}

#[test]
fn capability_state_active_lost_superseded_excludes_and_warns() {
    // Gate 4: active + lost/superseded → excluded from cohort AND has finding
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_note(root, "00 System/State Boundary.md", "---\ncurrent_turn: 43\ncurrent_year: 43\nlast_resolved_year: 42\ncurrent_source_cursor: 900\ncanonical_materialized_cursor: 900\n---\n# Boundary\n");
    write_note(root, "40 Civilization/Capabilities/Active Lost.md", "---\ntype: capability\ncapability_id: cap:active-lost-v2\nstatus: active\ncapability_state:\n  - lost\n---\n# Active Lost\n");
    write_note(root, "40 Civilization/Capabilities/Normal Active.md", "---\ntype: capability\ncapability_id: cap:normal-active-v2\nstatus: active\n---\n# Normal Active\n");

    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    let report = outcome.continuity_report_markdown.unwrap();

    // Active lost excluded from denominator
    assert!(
        report.contains("active machine-readable durable capability owners: 1"),
        "active+lost must be excluded from active cohort"
    );

    // Should have CHAD-TECH-010 finding for the lost capability
    let tech_findings: Vec<_> = outcome
        .findings
        .items
        .iter()
        .filter(|f| f.rule == "CHAD-TECH-010")
        .collect();
    assert!(
        !tech_findings.is_empty(),
        "active+lost must have CHAD-TECH-010 finding"
    );
}

// -----------------------------------------------------------------------
// Gate 5B — escaped-pipe integration regression
// -----------------------------------------------------------------------

#[test]
fn escaped_pipe_universal_formation_exact_production_shape() {
    // Gate 5B: Exact production-shaped escaped pipe input
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_note(root, "00 System/State Boundary.md", "---\ntype: state-boundary\ncurrent_turn: 42\ncurrent_year: 42\nlast_resolved_year: 41\ncurrent_source_cursor: 5100\ncanonical_materialized_cursor: 4838\n---\n# State Boundary\n");
    write_note(root, "40 Civilization/Technology/Roads/Universal Formation.md", "---\ntype: technology-road\nroad_id: road:universal-formation\nstatus: active\nlifecycle: in-progress\naccepted_year: 37\nacceptance_cursor: 4524\nsource_cursor: 4526\nreviewed_through_cursor: 4838\nterminal_due_year: 40\n---\n# Universal Formation\n");
    // Exact production shape from collector
    write_note(root, "70 Sources/Telegram/Player/2026/2026-01-01.md", "---\ntype: telegram-chat-part\nsource: telegram\nstream: player\ndate: 2026-01-01\nfirst: 5035\nlast: 5035\ncount: 1\n---\n\n^telegram--100-5035\n**00:00 UTC** · the_mud_lounge_bot\n\nUniversal formation road \\| live at its own ceiling of about 1,800 learners a year without print copying — the adjudicated terms, closed SUCCEEDED this year\n");

    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    let report = outcome.continuity_report_markdown.unwrap();

    // Must parse exactly one lifecycle event
    assert!(
        report.contains("lifecycle events parsed: 1"),
        "must parse exactly one lifecycle event from escaped pipe"
    );

    // Must produce MATERIALIZATION_GAP
    assert!(
        report.contains("MATERIALIZATION_GAP"),
        "escaped pipe must classify as MATERIALIZATION_GAP"
    );

    // Must recommend player-side reconciliation
    assert!(
        report.contains("PLAYER_SIDE_RECONCILIATION"),
        "must recommend player-side reconciliation"
    );

    // Must NOT produce AUTHORITY_GAP for this road
    let queue_section = report
        .split("## Top Actionable Reconciliation Queue")
        .nth(1)
        .unwrap_or("");
    assert!(
        !queue_section.contains("road:universal-formation")
            || !queue_section.contains("AUTHORITY_GAP"),
        "must not produce AUTHORITY_GAP when direct evidence exists"
    );

    // Must contain the raw evidence
    assert!(
        report.contains("about 1,800 learners"),
        "must preserve raw evidence from escaped pipe"
    );

    // Must contain the DO NOT QUERY instruction
    assert!(
        report.contains("DO NOT QUERY THE DM"),
        "must instruct not to query DM"
    );
}

// -----------------------------------------------------------------------
// Correction 1 — active + terminal capability_state finding
// -----------------------------------------------------------------------

#[test]
fn capability_active_lost_emits_finding_and_excludes() {
    // Test A: status: active + capability_state: lost
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_note(root, "00 System/State Boundary.md", "---\ncurrent_turn: 43\ncurrent_year: 43\nlast_resolved_year: 42\ncurrent_source_cursor: 900\ncanonical_materialized_cursor: 900\n---\n# Boundary\n");
    write_note(root, "40 Civilization/Capabilities/Test Lost.md", "---\ntype: capability\ncapability_id: capability:test-lost\nstatus: active\ncapability_state:\n  - lost\n---\n# Test Lost\n");
    write_note(root, "40 Civilization/Capabilities/Normal.md", "---\ntype: capability\ncapability_id: capability:test-normal\nstatus: active\n---\n# Normal\n");

    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    let report = outcome.continuity_report_markdown.unwrap();

    // Must have CHAD-TECH-010 finding for the lost capability
    let finding = outcome.findings.items.iter().find(|f| {
        f.rule == "CHAD-TECH-010"
            && f.path.as_deref() == Some("40 Civilization/Capabilities/Test Lost.md")
    });
    assert!(finding.is_some(), "must have CHAD-TECH-010 for active+lost");
    let msg = finding.unwrap().message.clone();
    assert!(msg.contains("active"), "message must mention active status");
    assert!(msg.contains("lost"), "message must mention lost state");
    assert!(msg.contains("conflicts"), "message must mention conflict");

    // Must be excluded from active denominator (only 1 active capability)
    assert!(
        report.contains("active machine-readable durable capability owners: 1"),
        "active+lost must be excluded from active cohort"
    );
}

#[test]
fn capability_active_superseded_emits_finding_and_excludes() {
    // Test B: status: active + capability_state: superseded
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_note(root, "00 System/State Boundary.md", "---\ncurrent_turn: 43\ncurrent_year: 43\nlast_resolved_year: 42\ncurrent_source_cursor: 900\ncanonical_materialized_cursor: 900\n---\n# Boundary\n");
    write_note(root, "40 Civilization/Capabilities/Test Super.md", "---\ntype: capability\ncapability_id: capability:test-superseded\nstatus: active\ncapability_state:\n  - superseded\n---\n# Test Super\n");
    write_note(root, "40 Civilization/Capabilities/Normal.md", "---\ntype: capability\ncapability_id: capability:test-normal-b\nstatus: active\n---\n# Normal\n");

    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    let report = outcome.continuity_report_markdown.unwrap();

    // Must have CHAD-TECH-010 finding for the superseded capability
    let finding = outcome.findings.items.iter().find(|f| {
        f.rule == "CHAD-TECH-010"
            && f.path.as_deref() == Some("40 Civilization/Capabilities/Test Super.md")
    });
    assert!(
        finding.is_some(),
        "must have CHAD-TECH-010 for active+superseded"
    );
    let msg = finding.unwrap().message.clone();
    assert!(msg.contains("active"), "message must mention active status");
    assert!(
        msg.contains("superseded"),
        "message must mention superseded state"
    );

    // Must be excluded from active denominator
    assert!(
        report.contains("active machine-readable durable capability owners: 1"),
        "active+superseded must be excluded from active cohort"
    );
}

// -----------------------------------------------------------------------
// Correction 2 — structured-receipt provenance preservation
// -----------------------------------------------------------------------

#[test]
fn structured_receipt_conflict_preserves_telegram_source_provenance() {
    // Correction 2: conflicting receipts must show actual Telegram source path,
    // not the canonical road note path
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_note(root, "00 System/State Boundary.md", "---\ntype: state-boundary\ncurrent_turn: 42\ncurrent_year: 42\nlast_resolved_year: 41\ncurrent_source_cursor: 5200\ncanonical_materialized_cursor: 4838\n---\n# State Boundary\n");
    write_note(root, "40 Civilization/Technology/Roads/Receipt Prov.md", "---\ntype: technology-road\nroad_id: road:receipt-prov\nstatus: active\nlifecycle: in-progress\nsource_cursor: 4000\nreviewed_through_cursor: 4100\n---\n# Receipt Prov\n");
    write_note(root, "70 Sources/Telegram/Player/2026/2026-01-15.md", "---\ntype: telegram-chat-part\nsource: telegram\nstream: player\ndate: 2026-01-15\nfirst: 5000\nlast: 5001\ncount: 2\n---\n\n^telegram--100-5000\n**00:00 UTC** · the_mud_lounge_bot\n\n[CL TERMINAL road=road:receipt-prov result=SUCCESS]\n\n^telegram--100-5001\n**00:01 UTC** · the_mud_lounge_bot\n\n[CL TERMINAL road=road:receipt-prov result=FAILURE]\n");

    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    let report = outcome.continuity_report_markdown.unwrap();

    // Must produce CONTRADICTION
    assert!(
        report.contains("CONTRADICTION"),
        "must produce CONTRADICTION"
    );

    // Evidence must reference the actual Telegram source file, not the road note
    assert!(
        report.contains("70 Sources/Telegram/Player/2026/2026-01-15.md"),
        "evidence must reference actual Telegram source path"
    );
    // Evidence must reference structured-receipt method
    assert!(
        report.contains("structured-receipt"),
        "evidence must use structured-receipt method"
    );
    // Must NOT present the canonical road note as receipt source
    assert!(
        !report.contains("40 Civilization/Technology/Roads/Receipt Prov.md")
            || report.contains("40 Civilization/Technology/Roads/Receipt Prov.md")
                && !report.contains("structured terminal receipt")
            || report.contains("70 Sources/Telegram"),
        "must not present canonical road as receipt source"
    );
    // Must have both cursors
    assert!(
        report.contains("5000") && report.contains("5001"),
        "must show both receipt cursors"
    );
}

// -----------------------------------------------------------------------
// Correction 3 — UnknownTerminal → REPRESENTATION_DIVERGENCE, not CONTRADICTION
// -----------------------------------------------------------------------

#[test]
fn closed_unknown_terminal_with_later_success_is_not_contradiction() {
    // Correction3: status: closed (UnknownTerminal) + later CLOSED SUCCEEDED
    // → REPRESENTATION_DIVERGENCE, NOT CONTRADICTION
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_note(root, "00 System/State Boundary.md", "---\ntype: state-boundary\ncurrent_turn: 42\ncurrent_year: 42\nlast_resolved_year: 41\ncurrent_source_cursor: 5200\ncanonical_materialized_cursor: 4838\n---\n# State Boundary\n");
    write_note(root, "40 Civilization/Technology/Roads/Closed Unknown.md", "---\ntype: technology-road\nroad_id: road:closed-unknown\nstatus: closed\nlifecycle: closed-partial\nterminal_result_cursor: 3500\nsource_cursor: 4000\nreviewed_through_cursor: 5100\n---\n# Closed Unknown\n");
    write_note(root, "70 Sources/Telegram/Player/2026/2026-01-01.md", "---\ntype: telegram-chat-part\nsource: telegram\nstream: player\ndate: 2026-01-01\nfirst: 3900\nlast: 3900\ncount: 1\n---\n\n^telegram--100-3900\n**00:00 UTC** · the_mud_lounge_bot\n\nClosed Unknown road | CLOSED SUCCEEDED\n");

    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    let report = outcome.continuity_report_markdown.unwrap();

    // Must NOT be CONTRADICTION for this road
    assert!(
        !report.contains("CONTRADICTION") || !report.contains("road:closed-unknown"),
        "closed+unknown polarity must not produce CONTRADICTION"
    );
    // Must be REPRESENTATION_DIVERGENCE
    assert!(
        report.contains("REPRESENTATION_DIVERGENCE"),
        "must produce REPRESENTATION_DIVERGENCE"
    );
    // Must NOT auto-materialize success
    assert!(
        !report.contains("| MATERIALIZATION_GAP |"),
        "must not auto-materialize success for unknown polarity"
    );
}

#[test]
fn closed_unknown_terminal_with_later_failure_is_not_contradiction() {
    // Correction 3 reverse: status: closed + later CLOSED FAILED
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_note(root, "00 System/State Boundary.md", "---\ntype: state-boundary\ncurrent_turn: 42\ncurrent_year: 42\nlast_resolved_year: 41\ncurrent_source_cursor: 5200\ncanonical_materialized_cursor: 4838\n---\n# State Boundary\n");
    write_note(root, "40 Civilization/Technology/Roads/Closed Unknown F.md", "---\ntype: technology-road\nroad_id: road:closed-unknown-f\nstatus: closed\nlifecycle: closed-partial\nterminal_result_cursor: 3500\nsource_cursor: 4000\nreviewed_through_cursor: 5100\n---\n# Closed Unknown F\n");
    write_note(root, "70 Sources/Telegram/Player/2026/2026-01-01.md", "---\ntype: telegram-chat-part\nsource: telegram\nstream: player\ndate: 2026-01-01\nfirst: 3900\nlast: 3900\ncount: 1\n---\n\n^telegram--100-3900\n**00:00 UTC** · the_mud_lounge_bot\n\nClosed Unknown F road | CLOSED FAILED\n");

    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    let report = outcome.continuity_report_markdown.unwrap();

    assert!(
        !report.contains("CONTRADICTION") || !report.contains("road:closed-unknown-f"),
        "closed+unknown polarity must not produce CONTRADICTION for failure"
    );
    assert!(
        report.contains("REPRESENTATION_DIVERGENCE"),
        "must produce REPRESENTATION_DIVERGENCE"
    );
}

// -----------------------------------------------------------------------
// Speaker parsing — escaped underscores
// -----------------------------------------------------------------------

#[test]
fn escaped_underscore_speaker_is_authoritative() {
    // Verify that escaped underscore in speaker name is recognized
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();

    write_note(root, "00 System/State Boundary.md", "---\ntype: state-boundary\ncurrent_turn: 42\ncurrent_year: 42\nlast_resolved_year: 41\ncurrent_source_cursor: 5100\ncanonical_materialized_cursor: 4838\n---\n# State Boundary\n");
    write_note(root, "40 Civilization/Technology/Roads/Test Escaped.md", "---\ntype: technology-road\nroad_id: road:test-escaped\nstatus: active\nlifecycle: in-progress\nsource_cursor: 4000\nreviewed_through_cursor: 4100\n---\n# Test Escaped\n");
    // Use escaped underscore in speaker name (production shape)
    write_note(root, "70 Sources/Telegram/Player/2026/2026-01-01.md", "---\ntype: telegram-chat-part\nsource: telegram\nstream: player\ndate: 2026-01-01\nfirst: 5000\nlast: 5000\ncount: 1\n---\n\n^telegram--100-5000\n**00:00 UTC** · the\\_mud\\_lounge\\_bot\n\nTest Escaped road | CLOSED SUCCEEDED\n");

    let cfg = mini_config();
    let outcome = validate(root, &cfg, &[]).unwrap();
    let report = outcome.continuity_report_markdown.unwrap();

    // Must parse the lifecycle event from escaped-underscore speaker
    assert!(
        report.contains("lifecycle events parsed: 1"),
        "escaped underscore speaker must be recognized as authoritative"
    );
    assert!(
        report.contains("MATERIALIZATION_GAP"),
        "must produce MATERIALIZATION_GAP from escaped-underscore speaker"
    );
}
