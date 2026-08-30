//! Receipt monitoring rules (CHAD-RECEIPT-001..006).
//!
//! Deterministic detection of: accepted but never started, executing with
//! no progress, expected boundary due, missing promised receipt, PARTIAL
//! conflicts, and aggregate completeness.

use std::collections::{HashMap, HashSet};

use crate::findings::Finding;
use crate::rules::{finding, RuleContext};
use crate::source_index::{ParsedReceipt, SourceIndex};

/// Road receipt state derived from the receipt stream.
#[derive(Debug, Clone, Default)]
pub struct RoadReceiptState {
    pub accepted_at: Option<i64>,
    pub started_at: Option<i64>,
    pub last_progress_at: Option<i64>,
    pub terminal: bool,
    pub terminal_result: Option<String>,
    /// All terminal receipts in order (for conflict detection).
    pub terminal_receipts: Vec<TerminalReceipt>,
    pub partial_components: Vec<String>,
    pub resolved_components: HashSet<String>,
}

/// A single terminal receipt with its result and cursor.
#[derive(Debug, Clone)]
pub struct TerminalReceipt {
    pub result: Option<String>,
    pub cursor: i64,
    pub source_file: String,
    pub line: usize,
}

impl RoadReceiptState {
    /// Returns true if there are multiple terminal receipts with incompatible
    /// polarity (e.g. success + failure). Compatible repeated receipts
    /// (success + success) are not conflicts.
    pub fn has_terminal_conflict(&self) -> bool {
        if self.terminal_receipts.len() < 2 {
            return false;
        }
        let has_success = self.terminal_receipts.iter().any(|r| {
            matches!(
                r.result.as_deref(),
                Some("SUCCESS") | Some("COMPLETED") | Some("CLOSED_SUCCEEDED")
            )
        });
        let has_failure = self.terminal_receipts.iter().any(|r| {
            matches!(
                r.result.as_deref(),
                Some("FAILURE") | Some("FAILED") | Some("CLOSED_FAILED") | Some("TERMINAL")
            )
        });
        has_success && has_failure
    }
}

/// Build road receipt states from parsed receipts.
pub fn build_road_states(receipts: &[ParsedReceipt]) -> HashMap<String, RoadReceiptState> {
    let mut states: HashMap<String, RoadReceiptState> = HashMap::new();

    for receipt in receipts {
        let road_id = match receipt.fields.get("road") {
            Some(r) => r.clone(),
            None => continue,
        };

        let state = states.entry(road_id).or_default();

        match receipt.receipt_type.as_str() {
            "ACCEPT" => {
                state.accepted_at = Some(receipt.cursor);
            }
            "PROGRESS" => {
                if state.started_at.is_none() {
                    state.started_at = Some(receipt.cursor);
                }
                state.last_progress_at = Some(receipt.cursor);
            }
            "PARTIAL" => {
                if state.started_at.is_none() {
                    state.started_at = Some(receipt.cursor);
                }
                state.last_progress_at = Some(receipt.cursor);
                // Track partial components
                if let Some(components) = receipt.fields.get("components") {
                    for c in components.split(',') {
                        let clean = c.trim().to_string();
                        if !clean.is_empty() {
                            state.partial_components.push(clean);
                        }
                    }
                }
                // A PARTIAL result may name itself
                if let Some(result) = receipt.fields.get("result") {
                    if result.to_uppercase() == "PARTIAL" {
                        // The components field should list what's unresolved
                    }
                }
            }
            "TERMINAL" => {
                state.terminal = true;
                let result = receipt.fields.get("result").map(|s| s.to_uppercase());
                state.terminal_result = result.clone();
                state.terminal_receipts.push(TerminalReceipt {
                    result,
                    cursor: receipt.cursor,
                    source_file: receipt.source_file.clone(),
                    line: receipt.line,
                });
                if state.started_at.is_none() {
                    state.started_at = Some(receipt.cursor);
                }
                state.last_progress_at = Some(receipt.cursor);
                // A terminal receipt resolves all partial components
                state
                    .resolved_components
                    .extend(state.partial_components.iter().cloned());
            }
            _ => {}
        }
    }

    states
}

/// Check receipt monitoring rules.
pub fn check(ctx: &RuleContext, source_index: Option<&SourceIndex>) -> Vec<Finding> {
    let mut out = Vec::new();

    let source_index = match source_index {
        Some(si) => si,
        None => return out,
    };

    let road_states = build_road_states(&source_index.receipts);

    // Also check canonical road records for lifecycle state
    for note in &ctx.index.notes {
        if !note.curated || note.parse_error.is_some() {
            continue;
        }
        let type_name = note.type_str().unwrap_or_default();
        if !ctx.config.road_types.contains(&type_name) {
            continue;
        }
        let fm = note.fm();
        let road_id = fm.get_str("road_id").unwrap_or_default();
        if road_id.is_empty() {
            continue;
        }

        let lifecycle = fm.get_str("lifecycle").unwrap_or_default();
        let state = road_states.get(&road_id);

        // CHAD-RECEIPT-001: accepted but never started
        if lifecycle == "accepted" || lifecycle == "executing" {
            let has_start = state.as_ref().and_then(|s| s.started_at).is_some()
                || fm.get_i64("started_year").is_some()
                || fm.get_i64("started_cursor").is_some();

            if !has_start {
                out.push(finding(
                    "CHAD-RECEIPT-001",
                    ctx.sev("CHAD-RECEIPT-001", crate::findings::Severity::Warn),
                    Some(&note.path),
                    format!(
                        "road `{road_id}` is accepted/executing but has no \
                         start evidence in receipts or canonical fields."
                    ),
                ));
            }
        }

        // CHAD-RECEIPT-002: executing with no progress
        if lifecycle == "executing" {
            let has_progress = state.as_ref().and_then(|s| s.last_progress_at).is_some();
            if !has_progress {
                out.push(finding(
                    "CHAD-RECEIPT-002",
                    ctx.sev("CHAD-RECEIPT-002", crate::findings::Severity::Warn),
                    Some(&note.path),
                    format!(
                        "road `{road_id}` is executing but has no progress \
                         receipt in the indexed source."
                    ),
                ));
            }
        }

        // CHAD-RECEIPT-003/004: due boundary checks
        if let Some(due_year) = fm.get_i64("terminal_due_year") {
            if let Some(current_year) = ctx.boundary.current_year {
                if due_year < current_year {
                    // CHAD-RECEIPT-004: overdue
                    let is_terminal = state.as_ref().map(|s| s.terminal).unwrap_or(false)
                        || lifecycle == "completed"
                        || lifecycle == "terminal";
                    if !is_terminal {
                        out.push(finding(
                            "CHAD-RECEIPT-004",
                            ctx.sev("CHAD-RECEIPT-004", crate::findings::Severity::Error),
                            Some(&note.path),
                            format!(
                                "road `{road_id}` has terminal_due_year {due_year} \
                                 which has passed (current_year {current_year}) \
                                 but no terminal receipt exists."
                            ),
                        ));
                    }
                } else if due_year == current_year {
                    // CHAD-RECEIPT-003: boundary arriving
                    out.push(finding(
                        "CHAD-RECEIPT-003",
                        ctx.sev("CHAD-RECEIPT-003", crate::findings::Severity::Info),
                        Some(&note.path),
                        format!(
                            "road `{road_id}` has terminal_due_year {due_year} \
                             which is the current year. Receipt expected."
                        ),
                    ));
                }
            }
        }

        // CHAD-RECEIPT-005: terminal result conflicts with unresolved PARTIAL
        if let Some(state) = state {
            if state.terminal {
                let unresolved: Vec<&String> = state
                    .partial_components
                    .iter()
                    .filter(|c| !state.resolved_components.contains(*c))
                    .collect();
                if !unresolved.is_empty() {
                    out.push(finding(
                        "CHAD-RECEIPT-005",
                        ctx.sev("CHAD-RECEIPT-005", crate::findings::Severity::Error),
                        Some(&note.path),
                        format!(
                            "road `{road_id}` claims terminal result but has \
                             unresolved PARTIAL components: {}. Later receipts \
                             must resolve, supersede, or cancel them.",
                            unresolved
                                .iter()
                                .map(|s| s.as_str())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                    ));
                }
            }
        }
    }

    // CHAD-RECEIPT-006: portfolio complete return omits active child
    check_portfolio_completeness(ctx, source_index, &mut out);

    out
}

/// CHAD-RECEIPT-006: structured complete portfolio return that omits an
/// active expected child road.
fn check_portfolio_completeness(
    ctx: &RuleContext,
    source_index: &SourceIndex,
    out: &mut Vec<Finding>,
) {
    // Find PORTFOLIO receipts with complete=true
    for receipt in &source_index.receipts {
        if receipt.receipt_type != "PORTFOLIO" {
            continue;
        }
        let is_complete = receipt
            .fields
            .get("complete")
            .map(|s| s.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        if !is_complete {
            continue;
        }

        let portfolio_id = match receipt.fields.get("id") {
            Some(id) => id.clone(),
            None => continue,
        };

        // Get the declared roads in the return
        let declared_roads: HashSet<String> = receipt
            .fields
            .get("roads")
            .map(|r| r.split(',').map(|s| s.trim().to_string()).collect())
            .unwrap_or_default();

        // Find the portfolio note and its declared child roads
        let portfolio_note = ctx.index.notes.iter().find(|n| {
            n.curated
                && n.parse_error.is_none()
                && ctx
                    .config
                    .portfolio_types
                    .iter()
                    .any(|t| n.type_str().as_deref() == Some(t.as_str()))
                && n.fm()
                    .get_str("portfolio_id")
                    .map(|id| id == portfolio_id)
                    .unwrap_or(false)
        });

        if let Some(pnote) = portfolio_note {
            let expected_roads = pnote.fm().get_list("road_ids");
            for expected in expected_roads {
                let clean = expected.trim();
                if clean.is_empty() {
                    continue;
                }
                // Check if this road is active
                let road_note = ctx.index.notes.iter().find(|n| {
                    n.curated
                        && n.fm()
                            .get_str("road_id")
                            .map(|id| id == clean)
                            .unwrap_or(false)
                });
                let is_active = road_note
                    .map(|n| {
                        let lc = n.fm().get_str("lifecycle").unwrap_or_default();
                        lc == "accepted" || lc == "executing" || lc == "progress"
                    })
                    .unwrap_or(false);

                if is_active && !declared_roads.contains(clean) {
                    out.push(finding(
                        "CHAD-RECEIPT-006",
                        ctx.sev("CHAD-RECEIPT-006", crate::findings::Severity::Error),
                        Some(&pnote.path),
                        format!(
                            "portfolio `{portfolio_id}` structured return \
                             claims complete=true but omits active child road \
                             `{clean}`. Either include it in the return or \
                             close/mark it inactive."
                        ),
                    ));
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::source_index::SpeakerClass;

    fn make_receipt(receipt_type: &str, road: &str, cursor: i64) -> ParsedReceipt {
        let mut fields = HashMap::new();
        fields.insert("road".to_string(), road.to_string());
        ParsedReceipt {
            receipt_type: receipt_type.to_string(),
            fields,
            source_file: "test.md".to_string(),
            cursor,
            speaker: "bot".to_string(),
            speaker_class: SpeakerClass::Dm,
            line: 1,
        }
    }

    fn make_receipt_with_result(
        receipt_type: &str,
        road: &str,
        cursor: i64,
        result: &str,
    ) -> ParsedReceipt {
        let mut fields = HashMap::new();
        fields.insert("road".to_string(), road.to_string());
        fields.insert("result".to_string(), result.to_string());
        ParsedReceipt {
            receipt_type: receipt_type.to_string(),
            fields,
            source_file: "test.md".to_string(),
            cursor,
            speaker: "bot".to_string(),
            speaker_class: SpeakerClass::Dm,
            line: 1,
        }
    }

    #[test]
    fn road_state_basic_flow() {
        let receipts = vec![
            make_receipt("ACCEPT", "TR-STEAM", 100),
            make_receipt("PROGRESS", "TR-STEAM", 200),
            make_receipt("TERMINAL", "TR-STEAM", 300),
        ];
        let states = build_road_states(&receipts);
        let state = states.get("TR-STEAM").unwrap();
        assert_eq!(state.accepted_at, Some(100));
        assert_eq!(state.started_at, Some(200));
        assert_eq!(state.last_progress_at, Some(300));
        assert!(state.terminal);
    }

    #[test]
    fn partial_components_tracked() {
        let mut fields = HashMap::new();
        fields.insert("road".to_string(), "TR-STEAM".to_string());
        fields.insert("components".to_string(), "A, B, C".to_string());
        let receipts = vec![ParsedReceipt {
            receipt_type: "PARTIAL".to_string(),
            fields,
            source_file: "test.md".to_string(),
            cursor: 200,
            speaker: "bot".to_string(),
            speaker_class: SpeakerClass::Dm,
            line: 1,
        }];
        let states = build_road_states(&receipts);
        let state = states.get("TR-STEAM").unwrap();
        assert_eq!(state.partial_components.len(), 3);
    }

    #[test]
    fn incompatible_terminal_receipts_preserved() {
        // Success at 5000, failure at 5100 → conflict preserved
        let receipts = vec![
            make_receipt_with_result("TERMINAL", "TR-TEST", 5000, "SUCCESS"),
            make_receipt_with_result("TERMINAL", "TR-TEST", 5100, "FAILURE"),
        ];
        let states = build_road_states(&receipts);
        let state = states.get("TR-TEST").unwrap();
        assert!(
            state.has_terminal_conflict(),
            "success + failure must be detected as conflict"
        );
        assert_eq!(state.terminal_receipts.len(), 2);
    }

    #[test]
    fn compatible_terminal_receipts_no_conflict() {
        // Success at 5000, success at 5100 → no conflict
        let receipts = vec![
            make_receipt_with_result("TERMINAL", "TR-TEST", 5000, "SUCCESS"),
            make_receipt_with_result("TERMINAL", "TR-TEST", 5100, "SUCCESS"),
        ];
        let states = build_road_states(&receipts);
        let state = states.get("TR-TEST").unwrap();
        assert!(
            !state.has_terminal_conflict(),
            "success + success must not be conflict"
        );
    }

    #[test]
    fn failure_then_success_conflict() {
        // Failure at 5000, success at 5100 → conflict preserved
        let receipts = vec![
            make_receipt_with_result("TERMINAL", "TR-TEST", 5000, "FAILURE"),
            make_receipt_with_result("TERMINAL", "TR-TEST", 5100, "SUCCESS"),
        ];
        let states = build_road_states(&receipts);
        let state = states.get("TR-TEST").unwrap();
        assert!(
            state.has_terminal_conflict(),
            "failure + success must be detected as conflict"
        );
    }
}
