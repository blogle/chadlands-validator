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
    c.severity_overrides
        .insert("CHAD-STATE-001".into(), chadlands_validator::findings::Severity::Info);
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
    let outcome = validate(
        root,
        &cfg,
        &["70 Sources/Telegram/foo.md".to_string()],
    )
    .unwrap();
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
