//! Continuity Report generator.
//!
//! Produces a bounded Markdown continuity surface under the validation-output
//! area. The report is compact and optimized for LLM/strategy consumption.
//! It is never a canonical truth owner.

use std::collections::HashSet;

use crate::boundary::{diagnose_source_frontiers, SourceFrontierRelationship, StateBoundary};
use crate::config::Config;
use crate::findings::Findings;
use crate::frontmatter::parse_capability_states;
use crate::gaps;
use crate::source_index::{resolve_cursor, SourceIndex};
use crate::vault::VaultIndex;

/// Render the Continuity Report as Markdown.
pub fn render(
    boundary: &StateBoundary,
    source_index: &SourceIndex,
    config: &Config,
    vault_index: &VaultIndex,
    findings: &Findings,
) -> String {
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

    // Top Actionable Reconciliation Queue
    let resurfacing = project_resurfacing(source_index, config, vault_index);
    let mut classified = gaps::classify_gaps(findings, source_index, boundary, vault_index);
    classified.extend(resurfacing.iter().map(resurfacing_gap));
    classified.sort_by(|a, b| a.sort_key.cmp(&b.sort_key));

    render_actionable_queue(&mut out, &classified, config);

    // Technology Progress (§10)
    render_technology_progress(&mut out, source_index, config, vault_index, boundary);

    // Capability Progress & Reuse (§11-13)
    render_capability_progress(&mut out, source_index, config, vault_index, boundary);

    // Resurfacing Candidates
    render_resurfacing(&mut out, source_index, config, &resurfacing);

    // Owed Technology Receipts
    render_receipts(&mut out, source_index, config);

    // Capabilities With No Machine-Linked Downstream Use Evidence
    render_capabilities(&mut out, source_index, config, vault_index);

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

fn render_actionable_queue(out: &mut String, classified: &[gaps::GapCandidate], _config: &Config) {
    let queue = gaps::bounded_queue(classified, 8, 4);

    out.push_str("## Top Actionable Reconciliation Queue\n\n");

    if classified.is_empty() {
        out.push_str("No classified gaps.\n\n");
        return;
    }

    // Summary counts
    out.push_str("**Gap summary:**\n");
    for (kind, count) in &queue.counts {
        out.push_str(&format!("- {kind}: {count}\n"));
    }
    out.push_str(&format!("- total: {}\n\n", queue.total));

    if queue.queue.is_empty() {
        out.push_str("No actionable items in bounded queue.\n\n");
        return;
    }

    out.push_str(&format!(
        "Showing {} of {} actionable items (8 strict-priority + 4 fairness slots):\n\n",
        queue.shown, queue.total,
    ));

    out.push_str(
        "| # | Class | Item | Canonical Cursor | Evidence Cursor | Delta | Reason | Operation |\n",
    );
    out.push_str("|---|---|---|---:|---:|---:|---|---|\n");

    for (i, g) in queue.queue.iter().enumerate() {
        let path_display = g
            .record_path
            .as_ref()
            .map(|p| format!("`{}`", p.display()))
            .unwrap_or_else(|| "—".to_string());
        out.push_str(&format!(
            "| {} | {} | {} — {} | {} | {} | {} | {} | {} |\n",
            i + 1,
            g.kind.label(),
            g.title.chars().take(60).collect::<String>(),
            path_display,
            opt_i64(g.canonical_source_cursor),
            opt_i64(g.evidence_cursor),
            opt_i64(g.cursor_delta),
            g.reason_code,
            g.recommended_operation.label(),
        ));
    }

    out.push('\n');

    out.push_str("### Deterministic Action Prompts\n\n");
    let mut rendered = 0usize;
    for gap in &queue.queue {
        if let Some(prompt) = gaps::render_prompt(gap) {
            out.push_str(&prompt);
            out.push('\n');
            rendered += 1;
        }
    }
    if rendered == 0 {
        out.push_str("No bounded materialization, authority, or contradiction prompts.\n\n");
    }
}

// ---------------------------------------------------------------------------
// §10: Technology Progress
// ---------------------------------------------------------------------------

fn render_technology_progress(
    out: &mut String,
    _source_index: &SourceIndex,
    config: &Config,
    vault_index: &VaultIndex,
    boundary: &StateBoundary,
) {
    out.push_str("## Technology Progress\n\n");

    // Count roads by canonical high-level status. Lifecycle refines only the
    // closed/partial bucket; composite lifecycle strings never hide activity.
    let mut lifecycle_counts: std::collections::BTreeMap<&str, usize> =
        std::collections::BTreeMap::new();
    let mut terminal_with_year: Vec<(i64, String, &'static str)> = Vec::new();
    let mut upcoming_due: Vec<(i64, String)> = Vec::new();
    let mut terminal_total = 0usize;
    let mut terminal_unknown_year = 0usize;

    for note in &vault_index.notes {
        if !note.curated || note.parse_error.is_some() {
            continue;
        }
        let type_name = note.type_str().unwrap_or_default();
        if !config.road_types.contains(&type_name) {
            continue;
        }
        let fm = note.fm();
        let lifecycle = fm.get_str("lifecycle").unwrap_or_default();
        let status = note.status().unwrap_or_default();

        let bucket = match status.as_str() {
            "active" | "accepted" | "in-progress" => "active",
            "stalled" => "stalled",
            "completed" => "completed",
            "failed" => "failed",
            "closed" if lifecycle.contains("partial") => "closed/partial",
            "closed" => "closed/partial",
            "superseded" => "superseded",
            _ => "unknown",
        };
        *lifecycle_counts.entry(bucket).or_insert(0) += 1;

        if matches!(bucket, "active" | "stalled") {
            if let Some(year) = fm.get_i64("terminal_due_year") {
                upcoming_due.push((
                    year,
                    fm.get_str("road_id")
                        .unwrap_or_else(|| note.title().to_string()),
                ));
            }
        }

        if matches!(
            bucket,
            "completed" | "failed" | "closed/partial" | "superseded"
        ) {
            terminal_total += 1;
            // Try to resolve terminal year from frontmatter fields
            let terminal_year = fm
                .get_i64("terminal_year")
                .or_else(|| fm.get_i64("completed_year"))
                .or_else(|| fm.get_i64("closed_year"))
                // Existing exact semantic field retained for compatibility.
                .or_else(|| fm.get_i64("terminal_result_year"));
            let outcome = match bucket {
                "completed" => "success",
                "failed" => "failure",
                _ => "other",
            };
            if let Some(year) = terminal_year {
                terminal_with_year.push((year, fm.get_str("road_id").unwrap_or_default(), outcome));
            } else {
                terminal_unknown_year += 1;
            }
        }
    }

    // Lifecycle breakdown
    out.push_str("### Road Lifecycle Counts\n\n");
    for (bucket, count) in &lifecycle_counts {
        out.push_str(&format!("- {bucket}: {count}\n"));
    }
    out.push_str(&format!(
        "- total: {}\n",
        lifecycle_counts.values().sum::<usize>()
    ));
    out.push('\n');

    // Upcoming terminal years
    out.push_str("### Upcoming Terminal Years\n\n");
    if let Some(current_year) = boundary.current_year {
        let mut upcoming: Vec<_> = upcoming_due
            .iter()
            .filter(|(y, _)| *y >= current_year)
            .collect();
        upcoming.sort_by_key(|(y, id)| (*y, id.as_str()));
        if upcoming.is_empty() {
            out.push_str("No upcoming terminal years within indexed records.\n\n");
        } else {
            out.push_str("| Year | Road |\n|---:|---|\n");
            for (y, road_id) in upcoming.iter().take(12) {
                out.push_str(&format!("| {y} | {road_id} |\n"));
            }
            out.push('\n');
        }
    } else {
        out.push_str("Current year unknown — cannot compute upcoming terminal years.\n\n");
    }

    // Rolling windows (conservative: only count when year is deterministic)
    out.push_str("### Rolling Windows (deterministic year only)\n\n");
    if let Some(current_year) = boundary.last_resolved_year {
        let windows = [1, 3, 5];
        // Collect accepted-by-year and terminal-by-year
        let mut accepted_by_year: std::collections::BTreeMap<i64, usize> =
            std::collections::BTreeMap::new();
        for note in &vault_index.notes {
            if !note.curated || note.parse_error.is_some() {
                continue;
            }
            let type_name = note.type_str().unwrap_or_default();
            if !config.road_types.contains(&type_name) {
                continue;
            }
            let fm = note.fm();
            if let Some(year) = fm.get_i64("accepted_year") {
                *accepted_by_year.entry(year).or_insert(0) += 1;
            }
        }

        for &window in &windows {
            let start = current_year - window + 1;
            let accepted: usize = (start..=current_year)
                .map(|y| accepted_by_year.get(&y).copied().unwrap_or(0))
                .sum();
            let successes: usize = terminal_with_year
                .iter()
                .filter(|(y, _, outcome)| {
                    *y >= start && *y <= current_year && *outcome == "success"
                })
                .count();
            let failures = terminal_with_year
                .iter()
                .filter(|(y, _, outcome)| {
                    *y >= start && *y <= current_year && *outcome == "failure"
                })
                .count();
            let other = terminal_with_year
                .iter()
                .filter(|(y, _, outcome)| *y >= start && *y <= current_year && *outcome == "other")
                .count();
            out.push_str(&format!(
                "- last {window} resolved year(s) ({start}–{current_year}): \
                  {accepted} accepted, {successes} terminal successes, {failures} terminal failures, {other} terminal other\n"
            ));
        }
    } else {
        out.push_str("Current year unknown — rolling windows unavailable.\n");
    }
    out.push('\n');
    out.push_str(&format!(
        "- terminal-year coverage: {} / {terminal_total} known\n- terminal year unknown: {terminal_unknown_year}\n\n",
        terminal_total.saturating_sub(terminal_unknown_year)
    ));

    // Capacity-release: UNSUPPORTED (§14)
    out.push_str("### Capacity-Release Telemetry\n\n");
    out.push_str("capacity-release semantic telemetry: UNSUPPORTED\n");
    out.push_str("capacity-reinvestment semantic telemetry: UNSUPPORTED\n\n");
}

// ---------------------------------------------------------------------------
// §11-13: Capability Progress & Reuse
// ---------------------------------------------------------------------------

fn render_capability_progress(
    out: &mut String,
    _source_index: &SourceIndex,
    config: &Config,
    vault_index: &VaultIndex,
    boundary: &StateBoundary,
) {
    out.push_str("## Capability Progress\n\n");

    let active_capability_ids_set = active_capability_ids(config, vault_index);
    let total_capabilities = active_capability_ids_set.len();
    let mut state_represented = 0usize;
    let mut attainment_year_represented = 0usize;
    let mut attainment_cursor_represented = 0usize;
    let mut depth_represented = 0usize;
    let mut state_counts: std::collections::BTreeMap<&str, usize> =
        std::collections::BTreeMap::new();
    let mut attained_with_year: Vec<i64> = Vec::new();

    let reuse = build_reuse_projection(config, vault_index, &active_capability_ids_set);

    for note in &vault_index.notes {
        if !note.curated || note.parse_error.is_some() {
            continue;
        }
        let type_name = note.type_str().unwrap_or_default();
        if !config.capability_types.contains(&type_name) {
            continue;
        }
        let fm = note.fm();
        let cap_id = fm.get_str("capability_id").unwrap_or_default();
        if !active_capability_ids_set.contains(cap_id.trim()) {
            continue;
        }
        let parsed_state = parse_capability_states(&fm);
        let has_state_field = parsed_state.field_present;

        // Capability-state represented: field exists with at least one valid value
        if has_state_field && !parsed_state.valid.is_empty() {
            state_represented += 1;
        }

        // Attainment year
        if fm.get_i64("attained_year").is_some()
            && parsed_state
                .valid
                .iter()
                .any(|s| matches!(*s, "attained" | "reproduced" | "diffused"))
        {
            attainment_year_represented += 1;
            if let Some(y) = fm.get_i64("attained_year") {
                attained_with_year.push(y);
            }
        }

        // Attainment cursor
        if fm.get_i64("attainment_cursor").is_some() {
            attainment_cursor_represented += 1;
        }

        // Depth
        if fm.get_str("depth").is_some() {
            depth_represented += 1;
        }

        for state in &parsed_state.valid {
            *state_counts.entry(*state).or_insert(0) += 1;
        }
    }

    // Render capability representation denominators
    out.push_str("### Capability Representation\n\n");
    out.push_str(&format!(
        "- active machine-readable durable capability owners: {total_capabilities}\n"
    ));
    if total_capabilities > 0 {
        out.push_str(&format!(
            "- capability-state represented: {state_represented}/{total_capabilities}\n"
        ));
        for state in [
            "attained",
            "reproduced",
            "diffused",
            "exploited",
            "compounded",
            "superseded",
            "lost",
        ] {
            out.push_str(&format!(
                "- capability state {state}: {}\n",
                state_counts.get(state).copied().unwrap_or(0)
            ));
        }
        out.push_str(&format!(
            "- attainment year represented: {attainment_year_represented}/{total_capabilities}\n"
        ));
        out.push_str(&format!(
            "- attainment cursor represented: {attainment_cursor_represented}/{total_capabilities}\n"
        ));
        out.push_str(&format!(
            "- depth represented: {depth_represented}/{total_capabilities}\n"
        ));
    }
    out.push('\n');

    // Rolling windows for attained capabilities
    out.push_str("### Newly Attained Capabilities\n\n");
    if let Some(current_year) = boundary.last_resolved_year {
        let windows = [1, 3, 5];
        for &window in &windows {
            let start = current_year - window + 1;
            let count = attained_with_year
                .iter()
                .filter(|y| **y >= start && **y <= current_year)
                .count();
            out.push_str(&format!(
                "- last {window} resolved year(s) ({start}–{current_year}): {count} newly attained\n"
            ));
        }
    } else {
        out.push_str("Current year unknown — rolling windows unavailable.\n");
    }
    out.push('\n');

    // §13: Reuse telemetry
    out.push_str("### Machine-Linked Downstream Reuse\n\n");
    if total_capabilities > 0 {
        out.push_str(&format!(
            "- active durable capabilities (nonempty IDs; excluding lost/superseded): {total_capabilities}\n"
        ));
        out.push_str(&format!(
            "- capabilities with resolved machine-linked dependency/reuse edges: {}\n",
            reuse.capabilities_with_use.len()
        ));
        out.push_str(&format!(
            "- roads with >=1 resolved `requires` capability edge: {}\n",
            reuse.roads_with_requires
        ));
        out.push_str(&format!(
            "- roads with >=1 resolved `cheapened_by` capability edge: {}\n",
            reuse.roads_with_cheapener
        ));
        out.push_str(&format!(
            "- machine-linked capability→road dependency/reuse edges: {}\n",
            reuse.edge_count
        ));
        // R ⊆ A invariant: build_reuse_projection intersects with active_ids
        debug_assert!(
            reuse.capabilities_with_use.len() <= total_capabilities,
            "reuse set must be subset of active set"
        );
        let no_reuse = total_capabilities - reuse.capabilities_with_use.len();
        out.push_str(&format!(
            "- active durable capabilities with no resolved downstream reuse: {no_reuse}\n"
        ));
    } else {
        out.push_str("No machine-readable capability records indexed.\n");
    }
    out.push('\n');

    out.push_str(
        "> Resolved downstream reuse is counted only from explicit structured \
     `requires` and `cheapened_by` edges.\n\n",
    );
    out.push_str(
        "> Narrative semantic-use coverage: UNSUPPORTED. \
     This does not prove the capability was unused in-world.\n\n",
    );
}

fn render_technology_coverage(out: &mut String, source_index: &SourceIndex, _config: &Config) {
    let portfolio_count = source_index.portfolio_count;
    let road_count = source_index.road_count;
    let capability_count = source_index.capability_count;
    let legacy_node_count = source_index.legacy_node_count;
    let active_legacy_portfolios = source_index.active_legacy_portfolio_count;
    let declared_child_roads = source_index.declared_child_road_count;

    let total_roads = road_count + legacy_node_count + active_legacy_portfolios;

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
    out.push('\n');

    // Receipt-boundary coverage with explicit denominators
    out.push_str("### Receipt-Boundary Coverage\n\n");
    if road_count > 0 {
        out.push_str(&format!(
            "Road inventory coverage:\n{road_count} / {road_count} machine-readable road owners evaluated.\n\n"
        ));
        out.push_str(&format!(
            "Receipt-boundary coverage:\n{road_count} / {road_count} machine-readable road owners evaluated.\n\n"
        ));
        out.push_str(&format!(
            "structured direct-source receipts recognized: {}\n\n",
            source_index.receipts.len()
        ));
        out.push_str(&format!(
            "exact lifecycle events recognized: {}\n\n",
            source_index.lifecycle_events.len()
        ));
        out.push_str("Narrative direct-source receipt semantic coverage:\nUNSUPPORTED.\n\n");
    } else if legacy_node_count > 0 || active_legacy_portfolios > 0 {
        out.push_str(&format!(
            "Road inventory coverage:\n0 / {total_roads} technology objects have machine-readable road representation.\n\n"
        ));
        out.push_str("**Coverage incomplete:** technology receipt monitoring requires machine-readable road records. The current active technology frontier may be represented as legacy aggregates/projects and cannot yet be validated at road granularity.\n\n");
    } else {
        out.push_str("No technology objects indexed.\n\n");
    }

    // Capability coverage with explicit denominators
    out.push_str("### Capability Coverage\n\n");
    if capability_count > 0 {
        out.push_str(&format!(
            "Machine-readable capability-owner coverage:\n{capability_count} / {capability_count} capability owner records evaluated.\n\n"
        ));
        out.push_str("Machine-linked downstream-use coverage:\nsee reuse metrics below.\n\n");
        out.push_str("Narrative semantic-use coverage:\nUNSUPPORTED.\n\n");
    } else {
        out.push_str("No machine-readable capability records indexed.\n\n");
    }
}

fn project_resurfacing(
    source_index: &SourceIndex,
    config: &Config,
    vault_index: &VaultIndex,
) -> Vec<ResurfacingCandidate> {
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

    let frontier = source_index.max_source_cursor;

    let mut candidates: Vec<ResurfacingCandidate> = Vec::new();

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

        // Canonical source_cursor and reviewed_through_cursor from vault
        let canonical_source_cursor = vault_index
            .find_by_path(&identity.note_path)
            .and_then(|n| n.fm().get_i64("source_cursor"));
        let reviewed_through_cursor = vault_index
            .find_by_path(&identity.note_path)
            .and_then(|n| n.fm().get_i64("reviewed_through_cursor"));

        // Cursor deltas relative to frontier
        let mention_delta = match (frontier, last_mentioned) {
            (Some(f), Some(m)) if f >= m => Some(f - m),
            _ => None,
        };
        let material_delta = match (frontier, last_material) {
            (Some(f), Some(m)) if f >= m => Some(f - m),
            _ => None,
        };

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
                    dormancy_reason = format!("MATERIAL_DORMANCY: {age}yr since material");
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
                        dormancy_reason = format!("NO_EXACT_SOURCE_MENTION: {age}yr since mention");
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
            dormancy_reason = "NO_EXACT_SOURCE_MENTION: no mention in indexed source".to_string();
        }

        // Has material evidence but no mention — still show but with different reason
        if !is_dormant
            && last_mentioned.is_none()
            && last_material.is_some()
            && !source_index.messages.is_empty()
        {
            is_dormant = true;
            dormancy_reason =
                "NO_EXACT_SOURCE_MENTION: no mention in indexed source (material evidence exists)"
                    .to_string();
        }

        if is_dormant {
            candidates.push(ResurfacingCandidate {
                stable_id: identity
                    .canonical_id
                    .clone()
                    .unwrap_or_else(|| format!("path:{}", identity.note_path)),
                title: identity.title.clone(),
                type_name: identity.type_name.clone(),
                status: identity.status.clone(),
                lifecycle: identity.lifecycle.clone(),
                canonical_source_cursor,
                reviewed_through_cursor,
                last_mentioned_year,
                last_mentioned_cursor: last_mentioned,
                last_mentioned_method: activity
                    .and_then(|a| a.last_mentioned_source.as_ref())
                    .map(|s| s.kind.label().to_string()),
                last_material_cursor: last_material,
                last_material_year,
                last_material_method: activity
                    .and_then(|a| a.last_material_source.as_ref())
                    .map(|s| s.kind.label().to_string()),
                frontier,
                mention_delta,
                material_delta,
                dormancy: dormancy_reason,
                record_path: identity.note_path.clone(),
            });
        }
    }

    // Sort by material_cursor delta descending (most stale first),
    // then by mention delta, then by stable_id for determinism.
    candidates.sort_by(|a, b| {
        b.material_delta
            .unwrap_or(i64::MAX)
            .cmp(&a.material_delta.unwrap_or(i64::MAX))
            .then_with(|| {
                b.mention_delta
                    .unwrap_or(i64::MAX)
                    .cmp(&a.mention_delta.unwrap_or(i64::MAX))
            })
            .then_with(|| a.stable_id.cmp(&b.stable_id))
    });

    candidates
}

fn resurfacing_gap(candidate: &ResurfacingCandidate) -> gaps::GapCandidate {
    gaps::GapCandidate {
        kind: gaps::GapKind::ResurfacingCandidate,
        source_rule: None,
        stable_id: Some(candidate.stable_id.clone()),
        title: candidate.title.clone(),
        record_path: Some(std::path::PathBuf::from(&candidate.record_path)),
        record_type: Some(candidate.type_name.clone()),
        canonical_status: candidate.status.clone(),
        canonical_lifecycle: candidate.lifecycle.clone(),
        canonical_source_cursor: candidate.canonical_source_cursor,
        reviewed_through_cursor: candidate.reviewed_through_cursor,
        evidence_cursor: candidate
            .last_material_cursor
            .or(candidate.last_mentioned_cursor),
        evidence_kind: None,
        evidence_path: None,
        evidence_line: None,
        evidence: Vec::new(),
        accepted_year: None,
        acceptance_cursor: None,
        started_cursor: None,
        last_progress_cursor: None,
        last_progress_year: None,
        due_year: None,
        exact_fields_owed: Vec::new(),
        current_source_frontier: candidate.frontier,
        cursor_delta: candidate.material_delta.or(candidate.mention_delta),
        reason_code: candidate.dormancy.clone(),
        recommended_operation: gaps::RecommendedOperation::PlayOrResearchResurfacing,
        sort_key: (
            gaps::action_priority(
                gaps::GapKind::ResurfacingCandidate,
                None,
                &candidate.dormancy,
                None,
                None,
            ),
            -candidate
                .material_delta
                .or(candidate.mention_delta)
                .unwrap_or(0),
            0,
            candidate.stable_id.clone(),
            candidate.record_path.clone(),
        ),
    }
}

fn render_resurfacing(
    out: &mut String,
    source_index: &SourceIndex,
    config: &Config,
    candidates: &[ResurfacingCandidate],
) {
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
    let excluded_terminal = source_index
        .identities
        .iter()
        .filter(|identity| {
            identity
                .status
                .as_deref()
                .map(|s| terminal_statuses.contains(s))
                .unwrap_or(false)
        })
        .count();
    let total = candidates.len();
    let shown = candidates.len().min(config.max_resurfacing);
    let tracked_total = source_index.identities.len();

    out.push_str("## Play / Research Resurfacing Queue\n\n");
    out.push_str(&format!(
        "Tracked identities: {tracked_total} ({} excluded as terminal/deceased/historical)\n\n",
        excluded_terminal,
    ));

    if candidates.is_empty() {
        out.push_str("No active identities exceed the configured resurfacing threshold.\n\n");
        return;
    }

    out.push_str("| Stable ID | Entity | Type | Status | Lifecycle | Canonical Cursor | Reviewed Cursor | Last Mention Cursor | Last Material Cursor | Frontier | Mention Δ | Material Δ | Reason | Record |\n");
    out.push_str("|---|---|---|---|---|---:|---:|---:|---:|---:|---:|---|---|---|\n");

    for c in candidates.iter().take(shown) {
        out.push_str(&format!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | {} | `{}` |\n",
            c.stable_id,
            c.title,
            c.type_name,
            c.status.as_deref().unwrap_or("—"),
            c.lifecycle.as_deref().unwrap_or("—"),
            opt_i64(c.canonical_source_cursor),
            opt_i64(c.reviewed_through_cursor),
            format_cursor_method(
                c.last_mentioned_cursor,
                c.last_mentioned_year,
                c.last_mentioned_method.as_deref()
            ),
            format_cursor_method(
                c.last_material_cursor,
                c.last_material_year,
                c.last_material_method.as_deref()
            ),
            opt_i64(c.frontier),
            opt_i64(c.mention_delta),
            opt_i64(c.material_delta),
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

fn active_capability_ids(config: &Config, vault_index: &VaultIndex) -> HashSet<String> {
    vault_index
        .notes
        .iter()
        .filter(|n| {
            n.curated
                && n.parse_error.is_none()
                && config
                    .capability_types
                    .contains(&n.type_str().unwrap_or_default())
        })
        .filter(|n| matches!(n.status().as_deref(), Some("active")))
        .filter(|n| {
            // Exclude capabilities with terminal states that conflict with
            // active status (lost or superseded).
            let parsed_state = crate::frontmatter::parse_capability_states(&n.fm());
            !parsed_state.valid.contains(&"lost") && !parsed_state.valid.contains(&"superseded")
        })
        .filter_map(|n| {
            n.fm()
                .get_str("capability_id")
                .map(|id| id.trim().to_string())
        })
        .filter(|id| !id.is_empty())
        .collect()
}

fn render_capabilities(
    out: &mut String,
    _source_index: &SourceIndex,
    config: &Config,
    vault_index: &VaultIndex,
) {
    let mut dormant: Vec<CapabilityDormant> = Vec::new();
    let active_set = active_capability_ids(config, vault_index);
    let reuse = build_reuse_projection(config, vault_index, &active_set);
    let total_capabilities = active_set.len();
    for note in &vault_index.notes {
        if !note.curated
            || note.parse_error.is_some()
            || !config
                .capability_types
                .contains(&note.type_str().unwrap_or_default())
        {
            continue;
        }
        let cap_id = note
            .fm()
            .get_str("capability_id")
            .unwrap_or_default()
            .trim()
            .to_string();
        if !active_set.contains(&cap_id) {
            continue;
        }
        if !reuse.capabilities_with_use.contains(&cap_id) {
            dormant.push(CapabilityDormant {
                title: note.title().to_string(),
                capability_id: cap_id,
                depth: note.fm().get_str("depth"),
                edge_count: 0,
                record_path: note.path.clone(),
            });
        }
    }

    let total = dormant.len();
    let shown = dormant.len().min(config.max_capabilities);

    out.push_str("## Capabilities With No Machine-Linked Downstream Use Evidence\n\n");
    out.push_str(&format!(
        "Active durable capability owners (nonempty IDs; excluding lost/superseded): {total_capabilities}\n\n"
    ));

    if total_capabilities == 0 {
        out.push_str(
            "No machine-readable capability records indexed. \
             Capability use analysis requires capability representation.\n\n",
        );
        return;
    }

    if dormant.is_empty() {
        out.push_str(&format!(
            "All {total_capabilities} indexed capability records have machine-linked downstream use evidence.\n\n"
        ));
        return;
    }

    out.push_str(&format!(
        "**{total}** of {total_capabilities} active durable capabilities have no deterministic \
         machine-linked downstream-use evidence in indexed source:\n\n"
    ));
    out.push_str(
        "> No machine-linked downstream reuse edge is represented in the canonical structured graph. \
     Narrative semantic-use coverage is unsupported. This MUST NOT imply the capability was truly unused in the world.\n\n",
    );
    out.push_str(
        "| Capability ID | Capability | Depth | Resolved downstream edge count | Record |\n",
    );
    out.push_str("|---|---|---|---:|---|\n");

    for d in dormant.iter().take(shown) {
        out.push_str(&format!(
            "| {} | {} | {} | {} | `{}` |\n",
            d.capability_id,
            d.title,
            d.depth.as_deref().unwrap_or("—"),
            d.edge_count,
            d.record_path,
        ));
    }

    if total > shown {
        out.push_str(&format!("\nShowing {shown} of {total}.\n"));
    }
    out.push('\n');
}

#[derive(Default)]
struct CapabilityReuseProjection {
    capabilities_with_use: HashSet<String>,
    edge_count: usize,
    roads_with_requires: usize,
    roads_with_cheapener: usize,
}

fn build_reuse_projection(
    config: &Config,
    vault_index: &VaultIndex,
    active_ids: &HashSet<String>,
) -> CapabilityReuseProjection {
    let mut projection = CapabilityReuseProjection::default();
    for note in vault_index.notes.iter().filter(|n| {
        n.curated
            && n.parse_error.is_none()
            && config
                .road_types
                .contains(&n.type_str().unwrap_or_default())
    }) {
        let mut requires = false;
        let mut cheapener = false;
        for (field, flag) in [
            ("requires", &mut requires),
            ("cheapened_by", &mut cheapener),
        ] {
            for value in note.fm().get_list(field) {
                let id = value.trim();
                if active_ids.contains(id) {
                    projection.edge_count += 1;
                    projection.capabilities_with_use.insert(id.to_string());
                    *flag = true;
                }
            }
        }
        projection.roads_with_requires += usize::from(requires);
        projection.roads_with_cheapener += usize::from(cheapener);
    }
    projection
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
        "- structured direct-source receipts recognized: {}\n",
        source_index.receipts.len()
    ));
    out.push_str(&format!(
        "- exact lifecycle events parsed: {}\n",
        source_index.lifecycle_events.len()
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
    stable_id: String,
    title: String,
    type_name: String,
    status: Option<String>,
    lifecycle: Option<String>,
    canonical_source_cursor: Option<i64>,
    reviewed_through_cursor: Option<i64>,
    last_mentioned_cursor: Option<i64>,
    last_mentioned_year: Option<i64>,
    last_mentioned_method: Option<String>,
    last_material_cursor: Option<i64>,
    last_material_year: Option<i64>,
    last_material_method: Option<String>,
    frontier: Option<i64>,
    mention_delta: Option<i64>,
    material_delta: Option<i64>,
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
    capability_id: String,
    depth: Option<String>,
    edge_count: usize,
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

fn format_cursor_method(cursor: Option<i64>, year: Option<i64>, method: Option<&str>) -> String {
    let mut rendered = format_material_cursor(cursor, year);
    if let Some(method) = method {
        rendered.push_str(&format!(" [{method}]"));
    }
    rendered
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
