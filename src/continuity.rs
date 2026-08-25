//! Continuity Report generator.
//!
//! Produces a bounded Markdown continuity surface under the validation-output
//! area. The report is compact and optimized for LLM/strategy consumption.
//! It is never a canonical truth owner.

use std::collections::HashSet;

use crate::boundary::{diagnose_source_frontiers, SourceFrontierRelationship, StateBoundary};
use crate::config::Config;
use crate::source_index::{resolve_cursor, SourceIndex};

/// Render the Continuity Report as Markdown.
pub fn render(boundary: &StateBoundary, source_index: &SourceIndex, config: &Config) -> String {
    let mut out = String::new();

    // Frontmatter
    out.push_str("---\n");
    out.push_str("type: continuity-report\n");
    out.push_str(&format!("generated_at: {}\n", chrono_utc_now()));
    out.push_str(&format!(
        "validated_revision: {}\n",
        yaml_escape(&boundary.vault_revision)
    ));
    out.push_str(&format!(
        "validator_build_revision: {}\n",
        yaml_escape(crate::BUILD_REVISION)
    ));
    out.push_str(&format!(
        "config_fingerprint: {}\n",
        yaml_escape(&config.fingerprint())
    ));
    out.push_str("---\n\n");

    out.push_str("# Continuity Report\n\n");

    // Boundary section
    render_boundary(&mut out, boundary, source_index, config);

    // Technology Monitoring Coverage (denominators)
    render_technology_coverage(&mut out, source_index, config);

    // Resurfacing Candidates
    render_resurfacing(&mut out, source_index, config);

    // Owed Technology Receipts
    render_receipts(&mut out, source_index, config);

    // Dormant Attained Capabilities
    render_capabilities(&mut out, source_index, config);

    // Coverage Candidates
    render_coverage(&mut out, source_index, config);

    // Source Index Metrics
    render_metrics(&mut out, source_index);

    out
}

fn render_boundary(
    out: &mut String,
    boundary: &StateBoundary,
    source_index: &SourceIndex,
    _config: &Config,
) {
    out.push_str("## Boundary\n\n");
    out.push_str(&format!(
        "- validator package version: `{}`\n",
        crate::VERSION
    ));
    out.push_str(&format!(
        "- validator build revision: `{}`\n",
        crate::BUILD_REVISION
    ));
    out.push_str(&format!(
        "- validated vault revision: `{}`\n",
        boundary.vault_revision
    ));
    out.push_str(&format!(
        "- State Boundary current_source_cursor: {}\n",
        opt_i64(boundary.current_source_cursor)
    ));
    out.push_str(&format!(
        "- maximum indexed direct Player cursor: {}\n",
        opt_i64(source_index.max_source_cursor)
    ));
    out.push_str(&format!(
        "- canonical_materialized_cursor: {}\n",
        opt_i64(boundary.canonical_materialized_cursor)
    ));
    out.push_str(&format!(
        "- current turn: {}\n",
        opt_i64(boundary.current_turn)
    ));
    out.push_str(&format!(
        "- current year: {}\n",
        opt_i64(boundary.current_year)
    ));
    out.push_str(&format!(
        "- last resolved year: {}\n",
        opt_i64(boundary.last_resolved_year)
    ));
    out.push_str(&format!(
        "- source-index coverage: {} files, {} messages\n",
        source_index.source_files_scanned,
        source_index.messages.len()
    ));

    // Classify boundary vs source frontier relationship
    let relationship = match diagnose_source_frontiers(
        boundary.current_source_cursor,
        source_index.max_source_cursor,
    ) {
        SourceFrontierRelationship::BoundaryTrailsCollectedEvidence => {
            "SOURCE FRONTIER > STATE BOUNDARY — boundary may be stale"
        }
        SourceFrontierRelationship::BoundaryAheadOfCollectedEvidence => {
            "SOURCE FRONTIER < STATE BOUNDARY — boundary ahead of indexed source"
        }
        SourceFrontierRelationship::Equal => "SOURCE FRONTIER == STATE BOUNDARY",
        SourceFrontierRelationship::BoundaryMissing => {
            "STATE BOUNDARY missing — source frontier known"
        }
        SourceFrontierRelationship::DirectFrontierUnknown => {
            "SOURCE FRONTIER unknown — no messages indexed"
        }
        SourceFrontierRelationship::Unknown => "UNKNOWN",
    };
    out.push_str(&format!("- boundary relationship: {relationship}\n"));

    out.push('\n');
}

fn render_technology_coverage(out: &mut String, source_index: &SourceIndex, _config: &Config) {
    let portfolio_count = source_index.portfolio_count;
    let road_count = source_index.road_count;
    let capability_count = source_index.capability_count;
    let legacy_node_count = source_index.legacy_node_count;
    let active_legacy_portfolios = source_index.active_legacy_portfolio_count;
    let declared_child_roads = source_index.declared_child_road_count;

    let receipt_coverage = if road_count > 0 {
        "COMPLETE"
    } else if legacy_node_count > 0 || active_legacy_portfolios > 0 {
        "INCOMPLETE"
    } else {
        "NONE"
    };

    let capability_coverage = if capability_count > 0 {
        "COMPLETE"
    } else {
        "INCOMPLETE"
    };

    out.push_str("## Technology Monitoring Coverage\n\n");
    out.push_str(&format!(
        "- machine-readable portfolios indexed: {portfolio_count}\n"
    ));
    out.push_str(&format!("- machine-readable roads indexed: {road_count}\n"));
    out.push_str(&format!(
        "- machine-readable durable capabilities indexed: {capability_count}\n"
    ));
    out.push_str(&format!(
        "- legacy technology nodes requiring classification: {legacy_node_count}\n"
    ));
    out.push_str(&format!(
        "- active legacy portfolios requiring decomposition: {active_legacy_portfolios}\n"
    ));
    out.push_str(&format!(
        "- declared current roads behind legacy representation: {declared_child_roads}\n"
    ));
    out.push_str(&format!(
        "- receipt monitoring coverage: {receipt_coverage}\n"
    ));
    out.push_str(&format!(
        "- capability dormancy coverage: {capability_coverage}\n"
    ));
    out.push('\n');
}

fn render_resurfacing(out: &mut String, source_index: &SourceIndex, config: &Config) {
    // Build resurfacing candidates: tracked entities exceeding dormancy threshold.
    // Exclude deceased/closed/historical/completed/superseded entities from
    // strategy resurfacing (activity data is preserved, just not presented).
    let terminal_statuses: HashSet<&str> = [
        "deceased",
        "closed",
        "completed",
        "superseded",
        "historical",
        "deprecated",
        "missing",
        "not-applicable",
    ]
    .iter()
    .copied()
    .collect();

    let mut candidates: Vec<ResurfacingCandidate> = Vec::new();
    let mut excluded_terminal = 0usize;

    for identity in &source_index.identities {
        // Check if entity is in a terminal state
        let is_terminal = identity
            .status
            .as_deref()
            .map(|s| terminal_statuses.contains(s))
            .unwrap_or(false)
            || identity
                .lifecycle
                .as_deref()
                .map(|l| {
                    l.starts_with("deceased")
                        || l.starts_with("closed")
                        || l.starts_with("completed")
                        || l.starts_with("historical")
                })
                .unwrap_or(false);

        if is_terminal {
            excluded_terminal += 1;
            continue;
        }

        let activity = source_index.activity.get(&identity.key);
        let last_mentioned = activity.and_then(|a| a.last_mentioned_cursor);
        let last_material = activity.and_then(|a| a.last_material_cursor);

        // Resolve year from cursor
        let last_mentioned_year =
            last_mentioned.and_then(|c| resolve_cursor(&source_index.cursor_epochs, c).1);
        let last_material_year =
            last_material.and_then(|c| resolve_cursor(&source_index.cursor_epochs, c).1);

        // Check dormancy
        let mut is_dormant = false;
        let mut dormancy_reason = String::new();

        // Material dormancy takes priority
        if let Some(threshold) = config.material_dormancy_years {
            if let (Some(last_year), Some(current_year)) = (
                last_material_year,
                source_index.cursor_epochs.last().and_then(|e| e.year),
            ) {
                let age = current_year - last_year;
                if age as f64 >= threshold {
                    is_dormant = true;
                    dormancy_reason = format!("{}yr since material", age);
                }
            }
        }

        // Mention dormancy (only if not already flagged by material)
        if !is_dormant {
            if let Some(threshold) = config.mention_dormancy_years {
                if let (Some(last_year), Some(current_year)) = (
                    last_mentioned_year,
                    source_index.cursor_epochs.last().and_then(|e| e.year),
                ) {
                    let age = current_year - last_year;
                    if age as f64 >= threshold {
                        is_dormant = true;
                        dormancy_reason = format!("{}yr since mention", age);
                    }
                }
            }
        }

        // No mention at all in indexed source (only if no material evidence either)
        if !is_dormant
            && last_mentioned.is_none()
            && last_material.is_none()
            && !source_index.messages.is_empty()
        {
            is_dormant = true;
            dormancy_reason = "no mention in indexed source".to_string();
        }

        // Has material evidence but no mention — still show but with different reason
        if !is_dormant
            && last_mentioned.is_none()
            && last_material.is_some()
            && !source_index.messages.is_empty()
        {
            is_dormant = true;
            dormancy_reason = "no mention in indexed source (material evidence exists)".to_string();
        }

        if is_dormant {
            candidates.push(ResurfacingCandidate {
                title: identity.title.clone(),
                type_name: identity.type_name.clone(),
                last_mentioned_cursor: last_mentioned,
                last_mentioned_year,
                last_material_cursor: last_material,
                last_material_year,
                dormancy: dormancy_reason,
                record_path: identity.note_path.clone(),
            });
        }
    }

    // Sort by last_mentioned_cursor ascending (oldest first)
    candidates.sort_by_key(|c| c.last_mentioned_cursor.unwrap_or(0));

    let total = candidates.len();
    let shown = candidates.len().min(config.max_resurfacing);
    let tracked_total = source_index.identities.len();

    out.push_str("## Resurfacing Candidates\n\n");
    out.push_str(&format!(
        "Tracked identities: {tracked_total} ({} excluded as terminal/deceased/historical)\n\n",
        excluded_terminal,
    ));

    if candidates.is_empty() {
        out.push_str("No active identities exceed the configured resurfacing threshold.\n\n");
        return;
    }

    out.push_str("| Entity | Type | Last Mention | Last Material | Dormancy | Record |\n");
    out.push_str("|---|---|---:|---:|---|---|\n");

    for c in candidates.iter().take(shown) {
        let last_material_display =
            format_material_cursor(c.last_material_cursor, c.last_material_year);
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | `{}` |\n",
            c.title,
            c.type_name,
            opt_i64(c.last_mentioned_year),
            last_material_display,
            c.dormancy,
            c.record_path,
        ));
    }

    if total > shown {
        out.push_str(&format!("\nShowing {shown} of {total}.\n"));
    }
    out.push('\n');
}

fn render_receipts(out: &mut String, source_index: &SourceIndex, config: &Config) {
    use crate::receipts::build_road_states;

    let road_states = build_road_states(&source_index.receipts);

    // Count machine-readable roads from identities
    let road_count = source_index
        .identities
        .iter()
        .filter(|id| config.road_types.contains(&id.type_name))
        .count();

    // Find roads with outstanding obligations
    let mut owed: Vec<ReceiptOwed> = Vec::new();

    for (road_id, state) in &road_states {
        if state.terminal {
            continue;
        }
        let mut unresolved: Vec<&String> = state
            .partial_components
            .iter()
            .filter(|c| !state.resolved_components.contains(*c))
            .collect();
        unresolved.sort();

        if !unresolved.is_empty() {
            owed.push(ReceiptOwed {
                road_id: road_id.clone(),
                lifecycle: "partial".to_string(),
                due: None,
                last_receipt: state.last_progress_at,
                severity: "ERROR".to_string(),
                detail: format!(
                    "unresolved PARTIAL components: {}",
                    unresolved
                        .iter()
                        .map(|s| s.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            });
        }

        if state.accepted_at.is_some() && state.last_progress_at.is_none() {
            owed.push(ReceiptOwed {
                road_id: road_id.clone(),
                lifecycle: "accepted".to_string(),
                due: None,
                last_receipt: state.accepted_at,
                severity: "WARN".to_string(),
                detail: "accepted with no progress receipt".to_string(),
            });
        }
    }

    owed.sort_by(|a, b| {
        (&a.road_id, &a.lifecycle, &a.severity, &a.detail).cmp(&(
            &b.road_id,
            &b.lifecycle,
            &b.severity,
            &b.detail,
        ))
    });

    let total = owed.len();
    let shown = owed.len().min(config.max_receipts);

    out.push_str("## Owed Technology Receipts\n\n");

    if road_count == 0 {
        out.push_str("No overdue receipts detected among **0** machine-readable active roads.\n\n");
        out.push_str(
            "**Coverage incomplete:** technology receipt monitoring requires \
             machine-readable road records. The current active technology \
             frontier may be represented as legacy aggregates/projects and \
             cannot yet be validated at road granularity.\n\n",
        );
        return;
    }

    if owed.is_empty() {
        out.push_str(&format!(
            "No overdue receipts detected among **{road_count}** monitored roads.\n\n"
        ));
        return;
    }

    out.push_str(&format!(
        "**{road_count}** roads monitored, **{total}** outstanding obligation(s):\n\n"
    ));
    out.push_str("| Road | Lifecycle | Due | Last Receipt | Severity | Detail |\n");
    out.push_str("|---|---|---:|---:|---|---|\n");

    for o in owed.iter().take(shown) {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} |\n",
            o.road_id,
            o.lifecycle,
            opt_i64(o.due),
            opt_i64(o.last_receipt),
            o.severity,
            o.detail,
        ));
    }

    if total > shown {
        out.push_str(&format!("\nShowing {shown} of {total}.\n"));
    }
    out.push('\n');
}

fn render_capabilities(out: &mut String, source_index: &SourceIndex, config: &Config) {
    let mut dormant: Vec<CapabilityDormant> = Vec::new();
    let mut total_capabilities = 0usize;

    for identity in &source_index.identities {
        if identity.type_name != "capability" {
            continue;
        }
        total_capabilities += 1;

        let activity = source_index.activity.get(&identity.key);
        let has_use = activity
            .as_ref()
            .map(|a| a.last_evidenced_use_cursor.is_some() || a.mention_count > 0)
            .unwrap_or(false);

        if !has_use {
            dormant.push(CapabilityDormant {
                title: identity.title.clone(),
                depth: None,
                last_evidenced_use: activity.and_then(|a| a.last_evidenced_use_cursor),
                use_classes: String::new(),
                record_path: identity.note_path.clone(),
            });
        }
    }

    let total = dormant.len();
    let shown = dormant.len().min(config.max_capabilities);

    out.push_str("## Dormant Attained Capabilities\n\n");
    out.push_str(&format!(
        "Durable capability records indexed: {total_capabilities}\n\n"
    ));

    if total_capabilities == 0 {
        out.push_str(
            "No machine-readable capability records indexed. \
             Dormancy analysis requires capability representation.\n\n",
        );
        return;
    }

    if dormant.is_empty() {
        out.push_str(&format!(
            "No dormant capabilities detected among {total_capabilities} indexed records.\n\n"
        ));
        return;
    }

    out.push_str(&format!(
        "**{total}** of {total_capabilities} capabilities have no evidenced use in indexed source:\n\n"
    ));
    out.push_str("| Capability | Depth | Last Evidenced Use | Evidence Types | Record |\n");
    out.push_str("|---|---|---:|---|---|\n");

    for d in dormant.iter().take(shown) {
        out.push_str(&format!(
            "| {} | {} | {} | {} | `{}` |\n",
            d.title,
            d.depth.as_deref().unwrap_or("—"),
            opt_i64(d.last_evidenced_use),
            if d.use_classes.is_empty() {
                "none".to_string()
            } else {
                d.use_classes.clone()
            },
            d.record_path,
        ));
    }

    if total > shown {
        out.push_str(&format!("\nShowing {shown} of {total}.\n"));
    }
    out.push('\n');
}

fn render_coverage(out: &mut String, source_index: &SourceIndex, config: &Config) {
    let total = source_index.candidates.len();
    let shown = total.min(config.max_coverage_candidates);

    // Count by signal type
    let stable_id_count = source_index
        .candidates
        .iter()
        .filter(|c| c.signal == "stable-id-syntax")
        .count();
    let proper_name_count = source_index
        .candidates
        .iter()
        .filter(|c| c.signal == "proper-name")
        .count();

    out.push_str("## Coverage Candidates\n\n");
    out.push_str(&format!(
        "Unresolved candidates: {total} ({stable_id_count} stable-ID, {proper_name_count} proper-name)\n\n"
    ));

    if source_index.candidates.is_empty() {
        out.push_str("No unresolved coverage candidates.\n\n");
        return;
    }

    out.push_str("| Candidate | Signal | Occurrences | Distinct Messages |\n");
    out.push_str("|---|---|---:|---:|\n");

    for c in source_index.candidates.iter().take(shown) {
        out.push_str(&format!(
            "| {} | {} | {} | {} |\n",
            c.text, c.signal, c.occurrences, c.distinct_messages,
        ));
    }

    if total > shown {
        out.push_str(&format!("\nShowing {shown} of {total}.\n"));
    }
    out.push('\n');
}

fn render_metrics(out: &mut String, source_index: &SourceIndex) {
    out.push_str("## Source Index Metrics\n\n");
    out.push_str(&format!(
        "- source files scanned: {}\n",
        source_index.source_files_scanned
    ));
    out.push_str(&format!(
        "- messages indexed: {}\n",
        source_index.messages.len()
    ));
    out.push_str(&format!(
        "- identity matches: {}\n",
        source_index.mentions.len()
    ));
    out.push_str(&format!(
        "- receipts parsed: {}\n",
        source_index.receipts.len()
    ));
    out.push_str(&format!(
        "- unresolved candidates: {}\n",
        source_index.candidates.len()
    ));
    out.push('\n');
}

// ---------------------------------------------------------------------------
// Helper types
// ---------------------------------------------------------------------------

struct ResurfacingCandidate {
    title: String,
    type_name: String,
    last_mentioned_cursor: Option<i64>,
    last_mentioned_year: Option<i64>,
    last_material_cursor: Option<i64>,
    last_material_year: Option<i64>,
    dormancy: String,
    record_path: String,
}

struct ReceiptOwed {
    road_id: String,
    lifecycle: String,
    due: Option<i64>,
    last_receipt: Option<i64>,
    severity: String,
    detail: String,
}

struct CapabilityDormant {
    title: String,
    depth: Option<String>,
    last_evidenced_use: Option<i64>,
    use_classes: String,
    record_path: String,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn opt_i64(v: Option<i64>) -> String {
    match v {
        Some(n) => n.to_string(),
        None => "—".to_string(),
    }
}

/// Format materiality using only values already established by source analysis.
/// The cursor remains visible even when an epoch mapping also supplies a year.
fn format_material_cursor(cursor: Option<i64>, year: Option<i64>) -> String {
    match (cursor, year) {
        (Some(cursor), Some(year)) => format!("cursor {cursor} / Year {year}"),
        (Some(cursor), None) => format!("cursor {cursor}"),
        (None, _) => "—".to_string(),
    }
}

fn yaml_escape(s: &str) -> String {
    let needs_quoting = s.contains(':')
        || s.contains('#')
        || s.contains('"')
        || s.contains('\\')
        || s.starts_with(' ')
        || s.ends_with(' ');
    if !needs_quoting {
        return s.to_string();
    }
    let escaped = s.replace('\\', "\\\\").replace('"', "\\\"");
    format!("\"{escaped}\"")
}

fn chrono_utc_now() -> String {
    // Use the time crate that's already a dependency
    time::OffsetDateTime::now_utc()
        .format(&time::format_description::well_known::Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn opt_i64_formatting() {
        assert_eq!(opt_i64(Some(42)), "42");
        assert_eq!(opt_i64(None), "—");
    }

    #[test]
    fn yaml_escape_basic() {
        assert_eq!(yaml_escape("hello"), "hello");
        assert_eq!(yaml_escape("has: colon"), "\"has: colon\"");
    }

    #[test]
    fn material_cursor_display_preserves_unmapped_cursor() {
        let rendered = format_material_cursor(Some(4526), None);
        assert!(rendered.contains("4526"));
        assert!(!rendered.contains('—'));
    }

    #[test]
    fn material_cursor_display_includes_cursor_and_mapped_year() {
        assert_eq!(
            format_material_cursor(Some(4526), Some(37)),
            "cursor 4526 / Year 37"
        );
    }
}
