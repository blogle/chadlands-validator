//! Technology structural validation rules (CHAD-TECH-001..010).
//!
//! Validates portfolio, road, and capability records for structural
//! consistency: stable IDs, duplicate IDs, acceptance evidence, due
//! boundaries, terminal results, capability receipts, relationship
//! references, and portfolio child-road resolution.

use std::collections::{HashMap, HashSet};

use crate::domain;
use crate::findings::Finding;
use crate::rules::{finding, RuleContext};
use crate::vault::Note;

pub fn check(ctx: &RuleContext) -> Vec<Finding> {
    let mut out = Vec::new();
    check_road_ids(ctx, &mut out);
    check_portfolio_children(ctx, &mut out);
    check_relationships(ctx, &mut out);
    check_terminal_results(ctx, &mut out);
    check_capability_receipts(ctx, &mut out);
    check_attained_capabilities(ctx, &mut out);
    check_legacy_compatibility(ctx, &mut out);
    check_capability_migration(ctx, &mut out);
    out
}

// ---------------------------------------------------------------------------
// CHAD-TECH-001 / 002: road ID presence and uniqueness
// ---------------------------------------------------------------------------

fn check_road_ids(ctx: &RuleContext, out: &mut Vec<Finding>) {
    let mut seen_ids: HashMap<String, Vec<&Note>> = HashMap::new();

    for note in &ctx.index.notes {
        if !note.curated || note.parse_error.is_some() {
            continue;
        }
        let type_name = note.type_str().unwrap_or_default();
        if !ctx.config.road_types.contains(&type_name) {
            continue;
        }
        let fm = note.fm();
        let lifecycle = fm.get_str("lifecycle").unwrap_or_default();
        let is_active = lifecycle == "accepted"
            || lifecycle == "executing"
            || lifecycle == "progress"
            || note.status().as_deref() == Some("active");

        match fm.get_str("road_id") {
            Some(id) if !id.trim().is_empty() => {
                seen_ids
                    .entry(id.trim().to_string())
                    .or_default()
                    .push(note);
            }
            _ if is_active => {
                out.push(finding(
                    "CHAD-TECH-001",
                    ctx.sev("CHAD-TECH-001", crate::findings::Severity::Error),
                    Some(&note.path),
                    format!(
                        "accepted/executing technology road `{}` lacks a stable \
                         road_id. Add `road_id` to the frontmatter.",
                        note.title()
                    ),
                ));
            }
            _ => {}
        }
    }

    // CHAD-TECH-002: duplicate road_id
    for (id, notes) in &seen_ids {
        if notes.len() > 1 {
            let paths: Vec<&str> = notes.iter().map(|n| n.path.as_str()).collect();
            out.push(finding(
                "CHAD-TECH-002",
                ctx.sev("CHAD-TECH-002", crate::findings::Severity::Error),
                Some(&notes[0].path),
                format!(
                    "duplicate road_id `{id}`: {}. Each road_id must be unique.",
                    paths.join(", ")
                ),
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// CHAD-TECH-003: acceptance evidence
// ---------------------------------------------------------------------------

fn check_acceptance_evidence(ctx: &RuleContext, note: &Note, out: &mut Vec<Finding>) {
    let fm = note.fm();
    let lifecycle = fm.get_str("lifecycle").unwrap_or_default();
    if lifecycle != "accepted" && lifecycle != "executing" {
        return;
    }
    // Must have acceptance_year or acceptance_cursor
    let has_year = fm.get_i64("accepted_year").is_some();
    let has_cursor = fm.get_i64("acceptance_cursor").is_some();
    if !has_year && !has_cursor {
        out.push(finding(
            "CHAD-TECH-003",
            ctx.sev("CHAD-TECH-003", crate::findings::Severity::Error),
            Some(&note.path),
            format!(
                "accepted/executing road `{}` lacks acceptance evidence \
                 (accepted_year or acceptance_cursor). Add the acceptance \
                 metadata.",
                note.title()
            ),
        ));
    }
}

// ---------------------------------------------------------------------------
// CHAD-TECH-004: due boundary
// ---------------------------------------------------------------------------

fn check_due_boundary(ctx: &RuleContext, note: &Note, out: &mut Vec<Finding>) {
    let fm = note.fm();
    let lifecycle = fm.get_str("lifecycle").unwrap_or_default();
    if lifecycle != "accepted" && lifecycle != "executing" {
        return;
    }
    // If the road declares a terminal_due_year, it must be present
    // This is a structural check: the field should exist if the schema requires it
    // We don't enforce it universally — only when the road has a produces field
    // (indicating it's expected to produce something).
    let has_produces = !fm.get_list("produces").is_empty();
    if has_produces && fm.get_i64("terminal_due_year").is_none() {
        // This is a soft check — not all roads need a due year
        // Only warn if the road is actively executing
        if lifecycle == "executing" {
            out.push(finding(
                "CHAD-TECH-004",
                ctx.sev("CHAD-TECH-004", crate::findings::Severity::Warn),
                Some(&note.path),
                format!(
                    "executing road `{}` declares `produces` but has no \
                     `terminal_due_year`. Consider adding a due boundary.",
                    note.title()
                ),
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// CHAD-TECH-005: terminal result mapping
// ---------------------------------------------------------------------------

fn check_terminal_results(ctx: &RuleContext, out: &mut Vec<Finding>) {
    for note in &ctx.index.notes {
        if !note.curated || note.parse_error.is_some() {
            continue;
        }
        let type_name = note.type_str().unwrap_or_default();
        if !ctx.config.road_types.contains(&type_name) {
            continue;
        }
        let fm = note.fm();
        let lifecycle = fm.get_str("lifecycle").unwrap_or_default();
        let status = note.status().unwrap_or_default();

        let is_terminal = lifecycle == "completed"
            || lifecycle == "terminal"
            || status == "completed"
            || status == "superseded";

        if !is_terminal {
            // Also run acceptance checks for active roads
            check_acceptance_evidence(ctx, note, out);
            check_due_boundary(ctx, note, out);
            continue;
        }

        // Terminal road must have a result or receipt mapping
        let has_result = fm.get_str("result").is_some();
        let has_terminal_receipt =
            fm.get_str("terminal_result").is_some() || fm.get_str("receipt").is_some();
        let has_produces = !fm.get_list("produces").is_empty();

        if !has_result && !has_terminal_receipt && !has_produces {
            out.push(finding(
                "CHAD-TECH-005",
                ctx.sev("CHAD-TECH-005", crate::findings::Severity::Error),
                Some(&note.path),
                format!(
                    "road `{}` is terminal/completed but has no terminal \
                     result, receipt mapping, or produces declaration. Add \
                     `result` or `terminal_result` to the frontmatter.",
                    note.title()
                ),
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// CHAD-TECH-006: capability receipt → capability record
// ---------------------------------------------------------------------------

fn check_capability_receipts(ctx: &RuleContext, out: &mut Vec<Finding>) {
    let capability_ids = domain::canonical_capability_ids(ctx.index, ctx.config);

    for note in &ctx.index.notes {
        if !note.curated || note.parse_error.is_some() {
            continue;
        }
        if domain::kind_for_note(note, ctx.config) != domain::EntityKind::Road {
            continue;
        }
        let fm = note.fm();
        for cap_id in fm.get_list("produces") {
            let clean = cap_id.trim();
            if clean.is_empty() {
                continue;
            }
            if !capability_ids.contains(clean) {
                out.push(finding(
                    "CHAD-TECH-006",
                    ctx.sev("CHAD-TECH-006", crate::findings::Severity::Error),
                    Some(&note.path),
                    format!(
                        "road `{}` declares `produces: {clean}` but no \
                         corresponding durable capability record exists. \
                         Create the capability record or correct the reference.",
                        note.title()
                    ),
                ));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CHAD-TECH-007: road/capability relationship consistency
// ---------------------------------------------------------------------------

fn check_relationship_consistency(ctx: &RuleContext, note: &Note, out: &mut Vec<Finding>) {
    let road_ids = domain::canonical_road_ids(ctx.index, ctx.config);
    let portfolio_ids = domain::canonical_portfolio_ids(ctx.index, ctx.config);
    let fm = note.fm();

    if let Some(portfolio_id) = fm.get_str("portfolio_id") {
        if !portfolio_ids.contains(&portfolio_id) {
            out.push(finding(
                "CHAD-TECH-007",
                ctx.sev("CHAD-TECH-007", crate::findings::Severity::Error),
                Some(&note.path),
                format!(
                    "`portfolio_id` references `{portfolio_id}` but no \
                     portfolio record with that ID exists. Create the \
                     portfolio record or correct the reference.",
                ),
            ));
        }
    }

    for field in &["road_id", "produced_by_road_ids"] {
        for value in fm.get_list(field) {
            let clean = value.trim();
            if clean.is_empty() {
                continue;
            }
            if !road_ids.contains(clean) {
                out.push(finding(
                    "CHAD-TECH-007",
                    ctx.sev("CHAD-TECH-007", crate::findings::Severity::Error),
                    Some(&note.path),
                    format!(
                        "`{field}` references `{clean}` but no road record \
                         with that road_id exists. Create the road record or \
                         correct the reference.",
                    ),
                ));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CHAD-TECH-008: portfolio road_ids resolution
// ---------------------------------------------------------------------------

fn check_portfolio_children(ctx: &RuleContext, out: &mut Vec<Finding>) {
    // Collect all known road IDs
    let road_ids: HashSet<String> = ctx
        .index
        .notes
        .iter()
        .filter(|n| {
            n.curated
                && n.parse_error.is_none()
                && ctx
                    .config
                    .road_types
                    .iter()
                    .any(|t| n.type_str().as_deref() == Some(t.as_str()))
        })
        .filter_map(|n| n.fm().get_str("road_id").map(|s| s.trim().to_string()))
        .collect();

    for note in &ctx.index.notes {
        if !note.curated || note.parse_error.is_some() {
            continue;
        }
        let type_name = note.type_str().unwrap_or_default();
        if !ctx.config.portfolio_types.contains(&type_name) {
            continue;
        }
        let fm = note.fm();
        let child_ids = fm.get_list("road_ids");
        for child_id in child_ids {
            let clean = child_id.trim();
            if clean.is_empty() {
                continue;
            }
            if !road_ids.contains(clean) {
                out.push(finding(
                    "CHAD-TECH-008",
                    ctx.sev("CHAD-TECH-008", crate::findings::Severity::Error),
                    Some(&note.path),
                    format!(
                        "portfolio `{}` declares child road `{clean}` but no \
                         road record with that road_id exists. Create the road \
                         record or remove the reference.",
                        note.title()
                    ),
                ));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// CHAD-TECH-009: requires/cheapened_by/produces resolution
// ---------------------------------------------------------------------------

fn check_relationships(ctx: &RuleContext, out: &mut Vec<Finding>) {
    let capability_ids = domain::canonical_capability_ids(ctx.index, ctx.config);

    for note in &ctx.index.notes {
        if !note.curated || note.parse_error.is_some() {
            continue;
        }
        let kind = domain::kind_for_note(note, ctx.config);
        if !matches!(
            kind,
            domain::EntityKind::Road | domain::EntityKind::Capability
        ) {
            continue;
        }
        let fm = note.fm();
        for field in &["requires", "cheapened_by", "produces"] {
            for r in fm.get_list(field) {
                let clean = r.trim();
                if clean.is_empty() {
                    continue;
                }
                if !capability_ids.contains(clean) {
                    out.push(finding(
                        "CHAD-TECH-009",
                        ctx.sev("CHAD-TECH-009", crate::findings::Severity::Error),
                        Some(&note.path),
                        format!(
                            "`{field}` references `{clean}` but no capability \
                             record with that ID exists. Create the capability \
                             or correct the reference.",
                        ),
                    ));
                }
            }
        }
        check_relationship_consistency(ctx, note, out);
    }
}

// ---------------------------------------------------------------------------
// CHAD-TECH-010: attained capability required fields
// ---------------------------------------------------------------------------

fn check_attained_capabilities(ctx: &RuleContext, out: &mut Vec<Finding>) {
    for note in &ctx.index.notes {
        if !note.curated || note.parse_error.is_some() {
            continue;
        }
        if domain::kind_for_note(note, ctx.config) != domain::EntityKind::Capability {
            continue;
        }
        let lifecycle = note.fm().get_str("lifecycle").unwrap_or_default();
        let lower = lifecycle.to_ascii_lowercase();
        let is_attained =
            lower.starts_with("attained") || lower == "reproduced" || lower == "diffused";
        if !is_attained {
            continue;
        }

        let fm = note.fm();
        let has_depth = fm.get_str("depth").is_some();
        let has_custody = fm.get_str("custody").is_some();
        let has_owner = fm.get_str("owner").is_some() || fm.get_str("lead").is_some();

        if !has_depth || !has_custody || !has_owner {
            let missing: Vec<&str> = [
                (!has_depth).then_some("depth"),
                (!has_custody).then_some("custody"),
                (!has_owner).then_some("owner"),
            ]
            .into_iter()
            .flatten()
            .collect();

            out.push(finding(
                "CHAD-TECH-010",
                ctx.sev("CHAD-TECH-010", crate::findings::Severity::Warn),
                Some(&note.path),
                format!(
                    "attained capability `{}` is missing required fields: {}. \
                     Add them to the frontmatter.",
                    note.title(),
                    missing.join(", ")
                ),
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// Legacy compatibility (TECH-MIG-*)
// ---------------------------------------------------------------------------

fn check_legacy_compatibility(ctx: &RuleContext, out: &mut Vec<Finding>) {
    // TECH-MIG-001: legacy technology-node needs classification
    // Valid classifications: road_id, capability_id, portfolio_id,
    // or technology_class: historical-compatibility
    for note in &ctx.index.notes {
        if !note.curated || note.parse_error.is_some() {
            continue;
        }
        let type_name = note.type_str().unwrap_or_default();
        if !ctx
            .config
            .legacy_technology_types
            .iter()
            .any(|t| t == &type_name)
        {
            continue;
        }
        let fm = note.fm();
        let classifications = legacy_classifications(&fm);
        if classifications.len() != 1 {
            let detail = if classifications.is_empty() {
                "no valid classification is present".to_string()
            } else {
                format!(
                    "multiple classifications are present ({})",
                    classifications
                        .iter()
                        .map(|class| class.label())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            };
            out.push(finding(
                "TECH-MIG-001",
                ctx.sev("TECH-MIG-001", crate::findings::Severity::Warn),
                Some(&note.path),
                format!(
                    "legacy technology-node `{}` requires semantic \
                     classification as portfolio, road, capability, or \
                     historical compatibility object. Add road_id, \
                     capability_id, portfolio_id, or set \
                     `technology_class: historical-compatibility`. Exactly one \
                     classification path is allowed; {detail}.",
                    note.title(),
                ),
            ));
        }
    }

    // TECH-MIG-004: active legacy technology-bearing portfolio lacks
    // machine-readable child-road representation.
    // Detect projects that explicitly declare themselves as portfolios
    // or contain structured road lists but are not typed technology-portfolio.
    check_legacy_portfolios(ctx, out);
}

/// Detect active projects/institutions that carry technology portfolio
/// semantics but lack machine-readable portfolio representation.
///
/// Heuristic: look for notes that contain strong portfolio signals in
/// their body (e.g., "six-road", "road ownership", structured road lists)
/// or have portfolio-like frontmatter (road_ids, portfolio_id) but are
/// not typed as technology-portfolio.
fn check_legacy_portfolios(ctx: &RuleContext, out: &mut Vec<Finding>) {
    let modern = domain::count_entities(ctx.index, ctx.config);

    for note in &ctx.index.notes {
        if !note.curated || note.parse_error.is_some() {
            continue;
        }
        let kind = domain::kind_for_note(note, ctx.config);
        let execution = domain::execution_state_for_note(note);
        if !matches!(
            kind,
            domain::EntityKind::Project | domain::EntityKind::Venture
        ) {
            continue;
        }
        if domain::execution_state_for_kind(kind, execution) == domain::ExecutionState::Terminal {
            continue;
        }

        let fm = note.fm();
        let has_portfolio_id = fm.get_str("portfolio_id").is_some();
        let has_road_ids = !fm.get_list("road_ids").is_empty();
        let body_lower = note.body.to_ascii_lowercase();
        let has_portfolio_language = body_lower.contains("portfolio")
            && (body_lower.contains("road") || body_lower.contains("technology"));
        let has_road_list = body_lower.contains("road ownership")
            || body_lower.contains("road_ids")
            || body_lower.contains("six-road")
            || body_lower.contains("6-road");

        if (has_portfolio_id || has_road_ids || (has_portfolio_language && has_road_list))
            && modern.modern_road_count == 0
        {
            let declared_roads =
                crate::legacy_technology::extract_roads(&note.body, &fm.get_list("road_ids"));
            let road_list = if declared_roads.is_empty() {
                String::new()
            } else {
                format!(
                    "\n\nDeclared child roads:\n{}",
                    declared_roads
                        .iter()
                        .map(|road| format!("- {}", road.name))
                        .collect::<Vec<_>>()
                        .join("\n")
                )
            };
            out.push(finding(
                "TECH-MIG-004",
                ctx.sev("TECH-MIG-004", crate::findings::Severity::Warn),
                Some(&note.path),
                format!(
                    "active legacy technology-bearing portfolio `{}` \
                     declares {} child road(s) but resolves 0 \
                     machine-readable technology-road owners. \
                     Create durable technology-road records to enable \
                     road-level validation.{road_list}",
                    note.title(),
                    declared_roads.len(),
                ),
            ));
        }
    }

    if modern.legacy_entity_count > 0 {
        out.push(finding(
            "TECH-MIG-006",
            ctx.sev("TECH-MIG-006", crate::findings::Severity::Warn),
            None,
            format!(
                "legacy technology representation is not ratcheted to zero: \
                 {} legacy record(s) remain. Replace or migrate each legacy \
                 node to a modern portfolio, road, or capability record.",
                modern.legacy_entity_count,
            ),
        ));
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LegacyTechnologyClassification {
    Portfolio,
    Road,
    Capability,
    HistoricalCompatibility,
}

impl LegacyTechnologyClassification {
    fn label(self) -> &'static str {
        match self {
            Self::Portfolio => "portfolio",
            Self::Road => "road",
            Self::Capability => "capability",
            Self::HistoricalCompatibility => "historical compatibility",
        }
    }
}

fn nonempty(value: Option<String>) -> bool {
    value.map(|value| !value.trim().is_empty()).unwrap_or(false)
}

fn legacy_classifications(
    fm: &crate::frontmatter::FmView<'_>,
) -> Vec<LegacyTechnologyClassification> {
    let mut classes = Vec::new();
    if nonempty(fm.get_str("portfolio_id")) {
        classes.push(LegacyTechnologyClassification::Portfolio);
    }
    if nonempty(fm.get_str("road_id")) {
        classes.push(LegacyTechnologyClassification::Road);
    }
    if nonempty(fm.get_str("capability_id")) {
        classes.push(LegacyTechnologyClassification::Capability);
    }
    if fm
        .get_str("technology_class")
        .map(|value| value.trim() == "historical-compatibility")
        .unwrap_or(false)
    {
        classes.push(LegacyTechnologyClassification::HistoricalCompatibility);
    }
    classes
}

// ---------------------------------------------------------------------------
// CAP-MIG-001: capability representation migration debt
// ---------------------------------------------------------------------------

/// Detect when a canonical attained-capability inventory exists but lacks
/// machine-readable durable capability owners.
fn check_capability_migration(ctx: &RuleContext, out: &mut Vec<Finding>) {
    let capability_ids = domain::canonical_capability_ids(ctx.index, ctx.config);

    for note in &ctx.index.notes {
        if !note.curated || note.parse_error.is_some() {
            continue;
        }
        let kind = domain::kind_for_note(note, ctx.config);
        if !matches!(
            kind,
            domain::EntityKind::Register | domain::EntityKind::Index
        ) {
            continue;
        }
        let title_lower = note.title().to_ascii_lowercase();
        let is_capability_register = title_lower.contains("capability")
            || title_lower.contains("attained")
            || title_lower.contains("technology");

        if !is_capability_register {
            continue;
        }

        let body_lower = note.body.to_ascii_lowercase();
        let has_attained_entries = body_lower.contains("attained")
            || body_lower.contains("capability")
            || body_lower.contains("water power")
            || body_lower.contains("precision gauge");

        if has_attained_entries && capability_ids.is_empty() {
            out.push(finding(
                "CAP-MIG-001",
                ctx.sev("CAP-MIG-001", crate::findings::Severity::Warn),
                Some(&note.path),
                format!(
                    "canonical capability register `{}` contains attained \
                     capability entries but 0 machine-readable durable \
                     capability owners resolve. Create capability records \
                     with `type: capability` and `capability_id` to enable \
                     exploitation tracking.",
                    note.title()
                ),
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::frontmatter::{parse, FmView};
    use crate::vault::{Note, VaultIndex};

    fn classes(frontmatter: &str) -> Vec<LegacyTechnologyClassification> {
        let parsed = parse(frontmatter);
        legacy_classifications(&FmView::new(&parsed.value))
    }

    fn note_from_frontmatter(path: &str, frontmatter: &str) -> Note {
        let parsed = parse(frontmatter);
        Note {
            path: path.to_string(),
            frontmatter: parsed.value,
            body: String::new(),
            content_hash: 0,
            parse_error: None,
            has_frontmatter: parsed.has_block,
            curated: true,
        }
    }

    fn index_with_notes(notes: Vec<Note>) -> VaultIndex {
        VaultIndex {
            root: std::path::PathBuf::new(),
            notes,
            all_files: std::collections::HashSet::new(),
            file_hashes: Vec::new(),
        }
    }

    #[test]
    fn all_four_legacy_classification_paths_are_bounded() {
        assert_eq!(
            classes("---\nportfolio_id: p\n---\n"),
            vec![LegacyTechnologyClassification::Portfolio]
        );
        assert_eq!(
            classes("---\nroad_id: r\n---\n"),
            vec![LegacyTechnologyClassification::Road]
        );
        assert_eq!(
            classes("---\ncapability_id: c\n---\n"),
            vec![LegacyTechnologyClassification::Capability]
        );
        assert_eq!(
            classes("---\ntechnology_class: historical-compatibility\n---\n"),
            vec![LegacyTechnologyClassification::HistoricalCompatibility]
        );
    }

    #[test]
    fn superseded_status_alone_is_not_a_classification() {
        assert!(classes("---\ntype: technology-node\nstatus: superseded\n---\n").is_empty());
    }

    #[test]
    fn empty_or_conflicting_paths_are_not_exactly_one() {
        assert!(classes("---\nroad_id: \"\"\n---\n").is_empty());
        assert_eq!(
            classes("---\nroad_id: r\ntechnology_class: historical-compatibility\n---\n").len(),
            2
        );
    }

    #[test]
    fn count_entities_sums_modern_and_legacy_records() {
        let config = Config::default();
        let notes = vec![
            note_from_frontmatter(
                "portfolio.md",
                "---\ntype: technology-portfolio\nstatus: active\n---\n",
            ),
            note_from_frontmatter(
                "road.md",
                "---\ntype: technology-road\nstatus: active\n---\n",
            ),
            note_from_frontmatter("cap.md", "---\ntype: capability\nstatus: active\n---\n"),
            note_from_frontmatter(
                "legacy.md",
                "---\ntype: technology-node\nstatus: active\n---\n",
            ),
        ];
        let index = index_with_notes(notes);
        let summary = domain::count_entities(&index, &config);
        assert_eq!(summary.modern_portfolio_count, 1);
        assert_eq!(summary.modern_road_count, 1);
        assert_eq!(summary.modern_capability_count, 1);
        assert_eq!(summary.legacy_node_count, 1);
        assert_eq!(summary.modern_entity_count, 3);
        assert_eq!(summary.legacy_entity_count, 1);
    }
}
