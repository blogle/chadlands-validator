//! Technology structural validation rules (CHAD-TECH-001..010).
//!
//! Validates portfolio, road, and capability records for structural
//! consistency: stable IDs, duplicate IDs, acceptance evidence, due
//! boundaries, terminal results, capability receipts, relationship
//! references, and portfolio child-road resolution.

use std::collections::{HashMap, HashSet};

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
    // Collect all known capability IDs
    let capability_ids: HashSet<String> = ctx
        .index
        .notes
        .iter()
        .filter(|n| {
            n.curated
                && n.parse_error.is_none()
                && ctx
                    .config
                    .capability_types
                    .iter()
                    .any(|t| n.type_str().as_deref() == Some(t.as_str()))
        })
        .filter_map(|n| {
            n.fm()
                .get_str("capability_id")
                .map(|s| s.trim().to_string())
        })
        .collect();

    // Check roads that declare produces
    for note in &ctx.index.notes {
        if !note.curated || note.parse_error.is_some() {
            continue;
        }
        let type_name = note.type_str().unwrap_or_default();
        if !ctx.config.road_types.contains(&type_name) {
            continue;
        }
        let fm = note.fm();
        let produces = fm.get_list("produces");
        for cap_id in produces {
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

fn check_relationship_consistency(_ctx: &RuleContext, _note: &Note, _out: &mut Vec<Finding>) {
    // Placeholder for future relationship consistency checks
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
    // Collect all known capability IDs
    let capability_ids: HashSet<String> = ctx
        .index
        .notes
        .iter()
        .filter(|n| {
            n.curated
                && n.parse_error.is_none()
                && ctx
                    .config
                    .capability_types
                    .iter()
                    .any(|t| n.type_str().as_deref() == Some(t.as_str()))
        })
        .filter_map(|n| {
            n.fm()
                .get_str("capability_id")
                .map(|s| s.trim().to_string())
        })
        .collect();

    for note in &ctx.index.notes {
        if !note.curated || note.parse_error.is_some() {
            continue;
        }
        let type_name = note.type_str().unwrap_or_default();
        let is_tech = ctx.config.road_types.contains(&type_name)
            || ctx.config.capability_types.contains(&type_name);
        if !is_tech {
            continue;
        }
        let fm = note.fm();
        for field in &["requires", "cheapened_by", "produces"] {
            let refs = fm.get_list(field);
            for r in refs {
                let clean = r.trim();
                if clean.is_empty() {
                    continue;
                }
                if clean.starts_with("CAP-") && !capability_ids.contains(clean) {
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
        let type_name = note.type_str().unwrap_or_default();
        if !ctx.config.capability_types.contains(&type_name) {
            continue;
        }
        let fm = note.fm();
        let attainment = fm.get_str("attainment_state").unwrap_or_default();
        if attainment != "attained" && attainment != "reproduced" && attainment != "diffused" {
            continue;
        }
        // Attained capabilities should have depth and custody
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
    // Count machine-readable technology objects
    let mut portfolio_count = 0usize;
    let mut road_count = 0usize;
    let mut _capability_count = 0usize;
    let mut legacy_node_count = 0usize;

    for note in &ctx.index.notes {
        if !note.curated || note.parse_error.is_some() {
            continue;
        }
        let type_name = note.type_str().unwrap_or_default();
        if ctx.config.portfolio_types.contains(&type_name) {
            portfolio_count += 1;
        }
        if ctx.config.road_types.contains(&type_name) {
            road_count += 1;
        }
        if ctx.config.capability_types.contains(&type_name) {
            _capability_count += 1;
        }
        if ctx
            .config
            .legacy_technology_types
            .iter()
            .any(|t| t == &type_name)
        {
            legacy_node_count += 1;
        }
    }

    // Look for active projects that reference technology/road/portfolio
    // semantics in their body but are not machine-readable portfolios.
    for note in &ctx.index.notes {
        if !note.curated || note.parse_error.is_some() {
            continue;
        }
        let type_name = note.type_str().unwrap_or_default();
        // Only check project/venture types
        if type_name != "project" && type_name != "venture" {
            continue;
        }
        // Skip if already typed as a technology type
        if ctx.config.portfolio_types.contains(&type_name)
            || ctx.config.road_types.contains(&type_name)
        {
            continue;
        }
        let status = note.status().unwrap_or_default();
        if status == "completed"
            || status == "closed"
            || status == "superseded"
            || status == "failed"
        {
            continue;
        }

        let fm = note.fm();
        // Check for portfolio signals in frontmatter
        let has_portfolio_id = fm.get_str("portfolio_id").is_some();
        let has_road_ids = !fm.get_list("road_ids").is_empty();

        // Check body for strong portfolio signals
        let body_lower = note.body.to_ascii_lowercase();
        let has_portfolio_language = body_lower.contains("portfolio")
            && (body_lower.contains("road") || body_lower.contains("technology"));
        let has_road_list = body_lower.contains("road ownership")
            || body_lower.contains("road_ids")
            || (body_lower.contains("six-road") || body_lower.contains("6-road"));

        if has_portfolio_id || has_road_ids || (has_portfolio_language && has_road_list) {
            // This is a legacy technology-bearing portfolio
            if road_count == 0 {
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
    }

    // TECH-MIG-006: technology receipt/lifecycle monitoring coverage is
    // incomplete because active technology remains behind legacy representation.
    if road_count == 0 && (portfolio_count > 0 || legacy_node_count > 0) {
        // We have legacy technology objects but no machine-readable roads
        // This means receipt monitoring is incomplete
        // This is reported via the continuity report denominators,
        // not as a separate finding.
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
    // Count machine-readable capabilities
    let capability_count: usize = ctx
        .index
        .notes
        .iter()
        .filter(|n| {
            n.curated
                && n.parse_error.is_none()
                && ctx
                    .config
                    .capability_types
                    .iter()
                    .any(|t| n.type_str().as_deref() == Some(t.as_str()))
        })
        .count();

    if capability_count > 0 {
        return; // Machine-readable capabilities exist
    }

    // Look for canonical capability registers/inventories
    for note in &ctx.index.notes {
        if !note.curated || note.parse_error.is_some() {
            continue;
        }
        let type_name = note.type_str().unwrap_or_default();
        let title_lower = note.title().to_ascii_lowercase();

        // Check if this is a capability register/inventory
        let is_capability_register = (type_name == "register" || type_name == "index")
            && (title_lower.contains("capability")
                || title_lower.contains("attained")
                || title_lower.contains("technology"));

        if !is_capability_register {
            continue;
        }

        // Check if it contains attained capability entries
        let body_lower = note.body.to_ascii_lowercase();
        let has_attained_entries = body_lower.contains("attained")
            || body_lower.contains("capability")
            || body_lower.contains("water power")
            || body_lower.contains("precision gauge");

        if has_attained_entries {
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
            // One finding per register is sufficient
            return;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frontmatter::{parse, FmView};

    fn classes(frontmatter: &str) -> Vec<LegacyTechnologyClassification> {
        let parsed = parse(frontmatter);
        legacy_classifications(&FmView::new(&parsed.value))
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
}
