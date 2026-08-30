//! Coverage candidate rules (CHAD-COVER-001..004).
//!
//! Conservative deterministic candidate extraction from direct Player source.
//! Unknown candidates remain unresolved until LLM/human reconciliation.

use crate::findings::Finding;
use crate::rules::{finding, RuleContext};
use crate::source_index::SourceIndex;

pub fn check(ctx: &RuleContext, source_index: Option<&SourceIndex>) -> Vec<Finding> {
    let mut out = Vec::new();

    let source_index = match source_index {
        Some(si) => si,
        None => return out,
    };

    // CHAD-COVER-001: explicit stable ID in source with no canonical owner
    check_unresolved_stable_ids(ctx, source_index, &mut out);

    // CHAD-COVER-002: unresolved exact-name candidate repeats
    // CHAD-COVER-003: lifecycle-shaped candidate
    // CHAD-COVER-004: single weak proper-name candidate
    check_candidates(ctx, source_index, &mut out);

    out
}

/// CHAD-COVER-001: explicit stable durable object ID/lifecycle receipt has
/// no canonical owner.
fn check_unresolved_stable_ids(
    ctx: &RuleContext,
    source_index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    // Collect all known stable IDs from canonical records
    let known_ids: std::collections::HashSet<String> = ctx
        .index
        .notes
        .iter()
        .filter(|n| n.curated && n.parse_error.is_none())
        .flat_map(|n| {
            let fm = n.fm();
            let mut ids = Vec::new();
            for field in &ctx.config.id_fields {
                if let Some(v) = fm.get_str(field) {
                    ids.push(v.trim().to_string());
                }
            }
            // Also collect road_id, capability_id, portfolio_id
            for field in &["road_id", "capability_id", "portfolio_id"] {
                if let Some(v) = fm.get_str(field) {
                    ids.push(v.trim().to_string());
                }
            }
            ids
        })
        .filter(|s| !s.is_empty())
        .collect();

    // Check receipts for IDs that don't resolve
    for receipt in &source_index.receipts {
        for (key, value) in &receipt.fields {
            if key == "road" || key == "capability" || key == "id" || key == "portfolio" {
                let clean = value.trim();
                if clean.is_empty() {
                    continue;
                }
                // Must look like a stable ID
                if !looks_like_stable_id(clean) {
                    continue;
                }
                if !known_ids.contains(clean) {
                    out.push(finding(
                        "CHAD-COVER-001",
                        ctx.sev("CHAD-COVER-001", crate::findings::Severity::Warn),
                        None,
                        format!(
                            "structured receipt references `{clean}` (as `{key}`) \
                             but no canonical record with that stable ID exists. \
                             Create the canonical record or correct the receipt."
                        ),
                    ));
                }
            }
        }
    }
}

fn looks_like_stable_id(s: &str) -> bool {
    s.starts_with("road:")
        || s.starts_with("capability:")
        || s.starts_with("portfolio:")
        || s.starts_with("int-")
        || s.starts_with("int_")
        || s.starts_with("TR-")
        || s.starts_with("CAP-")
        || s.starts_with("TP-")
        || s.starts_with("TN-")
}

/// CHAD-COVER-002/003/004: check unresolved candidates.
///
/// Severity model:
/// - Stable-ID syntax with no canonical owner → WARN (high-confidence structural debt)
/// - Lifecycle-shaped candidate → WARN only with strong structural evidence
/// - Repeated proper-name → Continuity Report candidate only (not Vault Health WARN)
/// - Single weak proper-name → Continuity Report INFO only
fn check_candidates(ctx: &RuleContext, source_index: &SourceIndex, out: &mut Vec<Finding>) {
    for candidate in &source_index.candidates {
        match candidate.signal.as_str() {
            "stable-id-syntax" => {
                // High-confidence structural coverage debt → WARN
                if candidate.occurrences >= 2 {
                    out.push(finding(
                        "CHAD-COVER-002",
                        ctx.sev("CHAD-COVER-002", crate::findings::Severity::Warn),
                        None,
                        format!(
                            "unresolved stable-ID candidate `{}` appears {} \
                             times across {} distinct message(s). Create a \
                             canonical record or confirm it is a reference \
                             to an existing entity.",
                            candidate.text, candidate.occurrences, candidate.distinct_messages,
                        ),
                    ));
                }
            }
            "proper-name"
                if candidate.occurrences >= ctx.config.proper_name_min_occurrences
                    && candidate.distinct_messages
                        >= ctx.config.proper_name_min_distinct_messages =>
            {
                // Check if it looks lifecycle-shaped with strong structural evidence
                let lower = candidate.text.to_ascii_lowercase();
                let is_lifecycle = ctx
                    .config
                    .lifecycle_terms
                    .iter()
                    .any(|t| lower.contains(t.as_str()));

                if is_lifecycle && candidate.occurrences >= 10 {
                    // Lifecycle-shaped with high occurrence count → WARN
                    out.push(finding(
                        "CHAD-COVER-003",
                        ctx.sev("CHAD-COVER-003", crate::findings::Severity::Warn),
                        None,
                        format!(
                            "repeated lifecycle-shaped candidate `{}` \
                                 appears {} times across {} distinct message(s) \
                                 without materialization as a canonical record.",
                            candidate.text, candidate.occurrences, candidate.distinct_messages,
                        ),
                    ));
                }
                // Otherwise: Continuity Report candidate only.
                // Do NOT emit Vault Health WARN for generic proper-name
                // candidates. They appear in the Continuity Report's
                // Coverage Candidates section instead.
                // Single weak candidate: Continuity Report INFO only (no finding)
            }
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_like_stable_id_works() {
        assert!(looks_like_stable_id("TR-STEAM"));
        assert!(looks_like_stable_id("CAP-WATER-POWER"));
        assert!(looks_like_stable_id("TP-Y36-01"));
        assert!(looks_like_stable_id("TN-001"));
        assert!(looks_like_stable_id("int_0838"));
        assert!(!looks_like_stable_id("hello"));
        assert!(!looks_like_stable_id("Mara Kest"));
    }
}
