//! Capability exploitation tracking (CHAD-CAP-001).
//!
//! Tracks *evidenced use* of attained capabilities, never inferred absence.
//! Derives activity from structured receipts, canonical dependency
//! relationships, and configured machine-readable edges.

use std::collections::HashMap;

use crate::findings::Finding;
use crate::rules::{finding, RuleContext};
use crate::source_index::{resolve_cursor, SourceIndex};

/// Per-capability use activity.
#[derive(Debug, Clone, Default)]
pub struct CapabilityUseActivity {
    pub last_evidenced_use_cursor: Option<i64>,
    pub last_evidenced_use_year: Option<i64>,
    pub use_count: usize,
    pub use_classes: Vec<String>,
}

/// Check capability exploitation rules.
pub fn check(ctx: &RuleContext, source_index: Option<&SourceIndex>) -> Vec<Finding> {
    let mut out = Vec::new();

    let source_index = match source_index {
        Some(si) => si,
        None => return out,
    };

    // Build capability use activity from receipts and relationships
    let use_activity = build_capability_activity(ctx, source_index);

    // Check dormancy thresholds
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
        if attainment != "attained"
            && attainment != "reproduced"
            && attainment != "diffused"
            && attainment != "exploited"
        {
            continue;
        }

        let cap_id = fm
            .get_str("capability_id")
            .unwrap_or_else(|| note.title().to_string());

        let activity = use_activity.get(&cap_id);

        // Check if there's any evidenced use
        let has_use = activity
            .as_ref()
            .map(|a| a.last_evidenced_use_cursor.is_some() || a.use_count > 0)
            .unwrap_or(false);

        // Also check canonical dependency edges
        let has_canonical_use = check_canonical_use(ctx, &cap_id);

        if !has_use && !has_canonical_use {
            // Check if the capability has been dormant long enough
            if let Some(threshold_years) = ctx.config.capability_dormancy_years {
                // We need a year to compare against
                if let Some(current_year) = ctx.boundary.current_year {
                    // If the capability has no use at all, and we have enough
                    // context to determine dormancy, report it.
                    // We use attainment_year or last_confirmed_year as baseline.
                    let baseline_year = fm
                        .get_i64("attainment_year")
                        .or_else(|| fm.get_i64("last_confirmed_year"))
                        .or_else(|| fm.get_i64("accepted_year"));

                    if let Some(baseline) = baseline_year {
                        let age = current_year - baseline;
                        if age as f64 >= threshold_years {
                            out.push(finding(
                                "CHAD-CAP-001",
                                ctx.sev("CHAD-CAP-001", crate::findings::Severity::Warn),
                                Some(&note.path),
                                format!(
                                    "attained capability `{cap_id}` (depth: {}) \
                                     has no qualifying use evidenced in the \
                                     indexed direct/canonical machine-readable \
                                     evidence for {age} year(s) (threshold: \
                                     {threshold_years}).",
                                    fm.get_str("depth").unwrap_or_else(|| "unknown".to_string()),
                                ),
                            ));
                        }
                    }
                }
            }
        }
    }

    out
}

/// Build capability use activity from receipts and canonical relationships.
fn build_capability_activity(
    ctx: &RuleContext,
    source_index: &SourceIndex,
) -> HashMap<String, CapabilityUseActivity> {
    let mut activity: HashMap<String, CapabilityUseActivity> = HashMap::new();

    // From structured [CL USE ...] receipts
    for receipt in &source_index.receipts {
        if receipt.receipt_type != "USE" {
            continue;
        }
        if let Some(cap_id) = receipt.fields.get("capability") {
            let act = activity.entry(cap_id.clone()).or_default();
            act.use_count += 1;
            match act.last_evidenced_use_cursor {
                Some(c) if c >= receipt.cursor => {}
                _ => {
                    act.last_evidenced_use_cursor = Some(receipt.cursor);
                    // Resolve year from cursor
                    let (_, year) = resolve_cursor(&source_index.cursor_epochs, receipt.cursor);
                    act.last_evidenced_use_year = year;
                }
            }
            if let Some(kind) = receipt.fields.get("kind") {
                if !act.use_classes.contains(kind) {
                    act.use_classes.push(kind.clone());
                }
            }
        }
    }

    // From canonical road dependency relationships
    for note in &ctx.index.notes {
        if !note.curated || note.parse_error.is_some() {
            continue;
        }
        let type_name = note.type_str().unwrap_or_default();
        if !ctx.config.road_types.contains(&type_name) {
            continue;
        }
        let fm = note.fm();

        // requires → prerequisite use
        for cap_id in fm.get_list("requires") {
            let act = activity.entry(cap_id.trim().to_string()).or_default();
            if !act.use_classes.contains(&"PREREQUISITE".to_string()) {
                act.use_classes.push("PREREQUISITE".to_string());
            }
            act.use_count += 1;
        }

        // cheapened_by → cheapener use
        for cap_id in fm.get_list("cheapened_by") {
            let act = activity.entry(cap_id.trim().to_string()).or_default();
            if !act.use_classes.contains(&"CHEAPENER".to_string()) {
                act.use_classes.push("CHEAPENER".to_string());
            }
            act.use_count += 1;
        }
    }

    activity
}

/// Check if a capability has canonical use edges (dependency, cheapener).
fn check_canonical_use(ctx: &RuleContext, cap_id: &str) -> bool {
    for note in &ctx.index.notes {
        if !note.curated || note.parse_error.is_some() {
            continue;
        }
        let type_name = note.type_str().unwrap_or_default();
        if !ctx.config.road_types.contains(&type_name)
            && !ctx.config.capability_types.contains(&type_name)
        {
            continue;
        }
        let fm = note.fm();
        if fm
            .get_list("requires")
            .iter()
            .any(|r| r.trim() == cap_id)
        {
            return true;
        }
        if fm
            .get_list("cheapened_by")
            .iter()
            .any(|r| r.trim() == cap_id)
        {
            return true;
        }
        if fm
            .get_list("produces")
            .iter()
            .any(|r| r.trim() == cap_id)
        {
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_index::SpeakerClass;

    #[test]
    fn capability_activity_from_use_receipt() {
        let mut fields = HashMap::new();
        fields.insert("capability".to_string(), "CAP-WATER-POWER".to_string());
        fields.insert("kind".to_string(), "OPERATIONAL".to_string());
        let receipts = vec![crate::source_index::ParsedReceipt {
            receipt_type: "USE".to_string(),
            fields,
            source_file: "test.md".to_string(),
            cursor: 300,
            speaker: "bot".to_string(),
            speaker_class: SpeakerClass::Dm,
            line: 1,
        }];
        let _epochs: Vec<crate::source_index::CursorEpoch> = vec![];
        let mut activity: HashMap<String, CapabilityUseActivity> = HashMap::new();

        // Simulate the aggregation
        for receipt in &receipts {
            if receipt.receipt_type == "USE" {
                if let Some(cap_id) = receipt.fields.get("capability") {
                    let act = activity.entry(cap_id.clone()).or_default();
                    act.use_count += 1;
                    act.last_evidenced_use_cursor = Some(receipt.cursor);
                    if let Some(kind) = receipt.fields.get("kind") {
                        act.use_classes.push(kind.clone());
                    }
                }
            }
        }

        let act = activity.get("CAP-WATER-POWER").unwrap();
        assert_eq!(act.use_count, 1);
        assert_eq!(act.last_evidenced_use_cursor, Some(300));
        assert!(act.use_classes.contains(&"OPERATIONAL".to_string()));
    }
}
