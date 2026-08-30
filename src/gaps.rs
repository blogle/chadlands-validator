//! Typed deterministic gap model (Patch 2).
//!
//! Classifies unresolved conditions into a small taxonomy of typed gaps
//! and produces a bounded priority queue for the Continuity Report.
//!
//! This module performs no semantic interpretation. It classifies
//! mechanically provable conditions from existing findings and source
//! index state.

use std::collections::BTreeMap;
use std::path::PathBuf;

use crate::boundary::StateBoundary;
use crate::findings::{Finding, Findings};
use crate::source_index::{ActivityEvidenceKind, SourceIndex};
use crate::vault::VaultIndex;

// ---------------------------------------------------------------------------
// Taxonomy
// ---------------------------------------------------------------------------

/// The class of an unresolved condition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum GapKind {
    /// Validator structural/state-boundary ERROR.
    StructuralError,
    /// Canonical state is stale relative to direct Player evidence.
    MaterializationGap,
    /// Road/result is due or overdue; no canonical receipt or recognized
    /// authoritative source terminal event.
    AuthorityGap,
    /// Two incompatible authoritative structured/recognized claims.
    Contradiction,
    /// Required structured representation is absent; question cannot be
    /// answered mechanically.
    SchemaGap,
    /// No correctness failure; entity eligible for play/research resurfacing.
    ResurfacingCandidate,
    /// Mechanically provable representation disagreement (e.g. boundary
    /// trails collected evidence).
    RepresentationDivergence,
}

impl GapKind {
    /// Strict priority ordering: lower is more urgent.
    pub fn priority_class(self) -> u8 {
        match self {
            Self::StructuralError => 0,
            Self::AuthorityGap => 1,
            Self::MaterializationGap => 2,
            Self::Contradiction => 3,
            Self::RepresentationDivergence => 4,
            Self::SchemaGap => 5,
            Self::ResurfacingCandidate => 6,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::StructuralError => "STRUCTURAL_ERROR",
            Self::MaterializationGap => "MATERIALIZATION_GAP",
            Self::AuthorityGap => "AUTHORITY_GAP",
            Self::Contradiction => "CONTRADICTION",
            Self::SchemaGap => "SCHEMA_GAP",
            Self::ResurfacingCandidate => "RESURFACING_CANDIDATE",
            Self::RepresentationDivergence => "REPRESENTATION_DIVERGENCE",
        }
    }
}

/// The recommended next operation for a gap.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecommendedOperation {
    /// Canonical owner can be updated from existing direct Player evidence.
    PlayerSideReconciliation,
    /// DM/world authority must provide information.
    DmInquiry,
    /// Conflicting claims require adjudication.
    ContradictionAdjudication,
    /// Schema/representation must be created or corrected.
    SchemaMaintenance,
    /// Optional: surface during play or research.
    PlayOrResearchResurfacing,
}

impl RecommendedOperation {
    pub fn label(self) -> &'static str {
        match self {
            Self::PlayerSideReconciliation => "PLAYER_SIDE_RECONCILIATION",
            Self::DmInquiry => "DM_INQUIRY",
            Self::ContradictionAdjudication => "CONTRADICTION_ADJUDICATION",
            Self::SchemaMaintenance => "SCHEMA_MAINTENANCE",
            Self::PlayOrResearchResurfacing => "PLAY_OR_RESEARCH_RESURFACING",
        }
    }
}

// ---------------------------------------------------------------------------
// Gap candidate
// ---------------------------------------------------------------------------

/// A single classified unresolved condition.
#[derive(Debug, Clone)]
pub struct GapCandidate {
    pub kind: GapKind,

    pub stable_id: Option<String>,
    pub title: String,
    pub record_path: Option<PathBuf>,
    pub record_type: Option<String>,

    pub canonical_status: Option<String>,
    pub canonical_lifecycle: Option<String>,

    pub canonical_source_cursor: Option<i64>,
    pub reviewed_through_cursor: Option<i64>,

    pub evidence_cursor: Option<i64>,
    pub evidence_kind: Option<ActivityEvidenceKind>,
    pub evidence_path: Option<String>,
    pub evidence_line: Option<usize>,

    pub current_source_frontier: Option<i64>,
    pub cursor_delta: Option<i64>,

    pub reason_code: String,
    pub recommended_operation: RecommendedOperation,

    /// Strict ordering key: (priority_class, negated_cursor_delta, due_year,
    /// stable_id, path). Lower is more urgent.
    pub sort_key: (u8, i64, i64, String, String),
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/// Classify findings and source-index state into typed gap candidates.
pub fn classify_gaps(
    findings: &Findings,
    source_index: &SourceIndex,
    boundary: &StateBoundary,
    vault_index: &VaultIndex,
) -> Vec<GapCandidate> {
    let mut gaps: Vec<GapCandidate> = Vec::new();

    // 1. Classify existing findings into gap kinds
    for f in &findings.items {
        if let Some(gap) = classify_finding(f, source_index, boundary) {
            gaps.push(gap);
        }
    }

    // 2. Detect representation divergence: boundary trails collected evidence
    if let (Some(bc), Some(df)) = (
        boundary.current_source_cursor,
        source_index.max_source_cursor,
    ) {
        if bc < df {
            gaps.push(GapCandidate {
                kind: GapKind::RepresentationDivergence,
                stable_id: None,
                title: "State Boundary trails collected direct-source evidence".to_string(),
                record_path: None,
                record_type: None,
                canonical_status: None,
                canonical_lifecycle: None,
                canonical_source_cursor: boundary.current_source_cursor,
                reviewed_through_cursor: None,
                evidence_cursor: source_index.max_source_cursor,
                evidence_kind: None,
                evidence_path: None,
                evidence_line: None,
                current_source_frontier: source_index.max_source_cursor,
                cursor_delta: source_index.max_source_cursor.map(|f| f - bc),
                reason_code: "STATE_BOUNDARY_STALE".to_string(),
                recommended_operation: RecommendedOperation::PlayerSideReconciliation,
                sort_key: (
                    GapKind::RepresentationDivergence.priority_class(),
                    -(source_index.max_source_cursor.unwrap_or(0) - bc),
                    0,
                    String::new(),
                    String::new(),
                ),
            });
        }
    }

    // 3. Lifecycle events: terminal events create MaterializationGap
    //    when the canonical state hasn't been updated to reflect them.
    //    §3: chronology-safe — event.cursor must exceed canonical
    //    source_cursor, and canonical must not already be terminal.
    for event in &source_index.lifecycle_events {
        if !event.outcome.is_terminal() {
            continue;
        }
        if let Some(identity) = source_index
            .identities
            .iter()
            .find(|id| id.key == event.identity_key)
        {
            // Check canonical state from vault frontmatter
            let note = vault_index.find_by_path(&identity.note_path);
            let (canonical_source_cursor, reviewed_through_cursor, is_canonical_terminal) =
                if let Some(n) = note {
                    let fm = n.fm();
                    let sc = fm.get_i64("source_cursor");
                    let rtc = fm.get_i64("reviewed_through_cursor");
                    let lifecycle = fm.get_str("lifecycle").unwrap_or_default();
                    let status = n.status().unwrap_or_default();
                    let terminal = lifecycle.starts_with("completed")
                        || lifecycle.starts_with("failed")
                        || lifecycle.starts_with("closed")
                        || lifecycle.starts_with("superseded")
                        || lifecycle == "terminal"
                        || status == "completed"
                        || status == "failed"
                        || status == "superseded";
                    (sc, rtc, terminal)
                } else {
                    (None, None, false)
                };

            // §3.1: Canonical already terminal at same/newer cursor → no gap
            if is_canonical_terminal {
                continue;
            }

            // §3.1: event.cursor must exceed canonical source_cursor
            // (the event is newer than what the canonical record represents)
            if let Some(canonical_sc) = canonical_source_cursor {
                if event.cursor <= canonical_sc {
                    continue;
                }
            }

            // §3.3: If event.cursor <= reviewed_through_cursor but
            // canonical is not terminal, this is a representation
            // contradiction — the record was reviewed past the
            // conflicting evidence. Surface as representation divergence.
            let is_behind_review = reviewed_through_cursor
                .map(|rtc| event.cursor <= rtc)
                .unwrap_or(false);

            let frontier = source_index.max_source_cursor;
            let cursor_delta = frontier.map(|f| f - event.cursor);

            if is_behind_review {
                gaps.push(GapCandidate {
                    kind: GapKind::RepresentationDivergence,
                    stable_id: Some(event.identity_key.clone()),
                    title: format!(
                        "{}: canonical reviewed past terminal event but state is {}",
                        identity.title,
                        identity
                            .lifecycle
                            .as_deref()
                            .or(identity.status.as_deref())
                            .unwrap_or("unknown")
                    ),
                    record_path: Some(std::path::PathBuf::from(&identity.note_path)),
                    record_type: Some(identity.type_name.clone()),
                    canonical_status: identity.status.clone(),
                    canonical_lifecycle: identity.lifecycle.clone(),
                    canonical_source_cursor,
                    reviewed_through_cursor,
                    evidence_cursor: Some(event.cursor),
                    evidence_kind: Some(event.evidence_kind),
                    evidence_path: Some(event.source_file.clone()),
                    evidence_line: Some(event.source_line),
                    current_source_frontier: frontier,
                    cursor_delta,
                    reason_code: "REVIEWED_PAST_TERMINAL_EVENT".to_string(),
                    recommended_operation: RecommendedOperation::SchemaMaintenance,
                    sort_key: (
                        GapKind::RepresentationDivergence.priority_class(),
                        -cursor_delta.unwrap_or(0),
                        0,
                        event.identity_key.clone(),
                        identity.note_path.clone(),
                    ),
                });
            } else {
                gaps.push(GapCandidate {
                    kind: GapKind::MaterializationGap,
                    stable_id: Some(event.identity_key.clone()),
                    title: format!(
                        "{}: direct source reports {} but canonical state is {}",
                        identity.title,
                        event.outcome.label(),
                        identity
                            .lifecycle
                            .as_deref()
                            .or(identity.status.as_deref())
                            .unwrap_or("unknown")
                    ),
                    record_path: Some(std::path::PathBuf::from(&identity.note_path)),
                    record_type: Some(identity.type_name.clone()),
                    canonical_status: identity.status.clone(),
                    canonical_lifecycle: identity.lifecycle.clone(),
                    canonical_source_cursor,
                    reviewed_through_cursor,
                    evidence_cursor: Some(event.cursor),
                    evidence_kind: Some(event.evidence_kind),
                    evidence_path: Some(event.source_file.clone()),
                    evidence_line: Some(event.source_line),
                    current_source_frontier: frontier,
                    cursor_delta,
                    reason_code: "LIFECYCLE_EVENT_NEWER_THAN_CANONICAL".to_string(),
                    recommended_operation: RecommendedOperation::PlayerSideReconciliation,
                    sort_key: (
                        GapKind::MaterializationGap.priority_class(),
                        -cursor_delta.unwrap_or(0),
                        0,
                        event.identity_key.clone(),
                        identity.note_path.clone(),
                    ),
                });
            }
        }
    }

    // 4. Suppress AuthorityGap for identities that have a terminal
    //    lifecycle event for the same current road lifecycle.
    //    §4: structured join via road_id, not substring matching.
    let lifecycle_identity_keys: std::collections::HashSet<&str> = source_index
        .lifecycle_events
        .iter()
        .filter(|e| e.outcome.is_terminal())
        .map(|e| e.identity_key.as_str())
        .collect();

    // Build a set of note paths that have terminal lifecycle events
    let lifecycle_note_paths: std::collections::HashSet<String> = source_index
        .lifecycle_events
        .iter()
        .filter(|e| e.outcome.is_terminal())
        .filter_map(|e| {
            source_index
                .identities
                .iter()
                .find(|id| id.key == e.identity_key)
                .map(|id| id.note_path.clone())
        })
        .collect();

    gaps.retain(|g| {
        if g.kind == GapKind::AuthorityGap {
            // Check stable_id match
            if let Some(stable_id) = &g.stable_id {
                if lifecycle_identity_keys.contains(stable_id.as_str()) {
                    return false;
                }
            }
            // Check structured path match
            if let Some(path) = &g.record_path {
                let path_str = path.to_string_lossy();
                if lifecycle_note_paths.contains(path_str.as_ref()) {
                    return false;
                }
            }
        }
        true
    });

    // Stable tie-breaking: sort by sort_key
    gaps.sort_by(|a, b| a.sort_key.cmp(&b.sort_key));

    gaps
}

fn classify_finding(
    f: &Finding,
    _source_index: &SourceIndex,
    _boundary: &StateBoundary,
) -> Option<GapCandidate> {
    let frontier = _source_index.max_source_cursor;

    let (kind, operation, reason) = match f.rule {
        // §6.4: State boundary structural errors → StructuralError
        "CHAD-STATE-001" | "CHAD-STATE-002" | "CHAD-STATE-003" | "CHAD-STATE-004" => (
            GapKind::StructuralError,
            RecommendedOperation::SchemaMaintenance,
            "STATE_BOUNDARY_DEFECT".to_string(),
        ),

        // §6.4: Cursor beyond evidence → RepresentationDivergence
        "CHAD-CURSOR-002" | "CHAD-CURSOR-005" => (
            GapKind::RepresentationDivergence,
            RecommendedOperation::SchemaMaintenance,
            "CURSOR_BEYOND_EVIDENCE".to_string(),
        ),

        // §6.2: Freshness failures → SchemaGap (stale review, not proof of
        // source evidence). Only upgrade to MaterializationGap if there is
        // independent lifecycle event evidence (handled in step 3).
        "CHAD-FRESH-001" | "CHAD-FRESH-002" => (
            GapKind::SchemaGap,
            RecommendedOperation::SchemaMaintenance,
            "STALE_REVIEW_FRONTIER".to_string(),
        ),

        // Overdue receipts → AuthorityGap
        "CHAD-RECEIPT-004" => (
            GapKind::AuthorityGap,
            RecommendedOperation::DmInquiry,
            "OVERDUE_RECEIPT".to_string(),
        ),

        // Acceptance boundary arriving → AuthorityGap (current year)
        "CHAD-RECEIPT-003" => (
            GapKind::AuthorityGap,
            RecommendedOperation::DmInquiry,
            "RECEIPT_BOUNDARY_ARRIVING".to_string(),
        ),

        // Technology schema gaps
        "CHAD-TECH-001" | "CHAD-TECH-002" | "CHAD-TECH-003" | "CHAD-TECH-004" | "CHAD-TECH-005"
        | "CHAD-TECH-006" | "CHAD-TECH-007" | "CHAD-TECH-008" | "CHAD-TECH-009"
        | "CHAD-TECH-010" => (
            GapKind::SchemaGap,
            RecommendedOperation::SchemaMaintenance,
            "TECHNOLOGY_SCHEMA_DEBT".to_string(),
        ),

        // Capability schema gaps
        "CHAD-CAP-001" => (
            GapKind::SchemaGap,
            RecommendedOperation::SchemaMaintenance,
            "CAPABILITY_USE_GAP".to_string(),
        ),

        // Migration debt
        "TECH-MIG-001" | "TECH-MIG-002" | "TECH-MIG-003" | "TECH-MIG-004" | "TECH-MIG-005"
        | "TECH-MIG-006" | "CAP-MIG-001" => (
            GapKind::SchemaGap,
            RecommendedOperation::SchemaMaintenance,
            "MIGRATION_DEBT".to_string(),
        ),

        // Owner/schema completeness
        "CHAD-OWNER-001" | "CHAD-OWNER-002" | "CHAD-OWNER-003" => (
            GapKind::SchemaGap,
            RecommendedOperation::SchemaMaintenance,
            "OWNER_SCHEMA_DEBT".to_string(),
        ),

        // §6.3: Identity findings → SchemaGap (structural debt, not world contradiction)
        "CHAD-IDENTITY-001" | "CHAD-IDENTITY-002" | "CHAD-IDENTITY-004" => (
            GapKind::SchemaGap,
            RecommendedOperation::SchemaMaintenance,
            "IDENTITY_SCHEMA_DEBT".to_string(),
        ),

        // §6.1: Schema structural — respect severity. Only ERROR-level
        // findings occupy StructuralError priority.
        "CHAD-SCHEMA-001" => (
            GapKind::StructuralError,
            RecommendedOperation::SchemaMaintenance,
            "SCHEMA_DEFECT".to_string(),
        ),
        "CHAD-SCHEMA-002" | "CHAD-SCHEMA-003" => {
            // These are typically WARN-level schema debt
            (
                GapKind::SchemaGap,
                RecommendedOperation::SchemaMaintenance,
                "SCHEMA_DEBT".to_string(),
            )
        }

        // Receipt conflicts → Contradiction
        "CHAD-RECEIPT-005" | "CHAD-RECEIPT-006" => (
            GapKind::Contradiction,
            RecommendedOperation::ContradictionAdjudication,
            "RECEIPT_CONTRADICTION".to_string(),
        ),

        _ => return None,
    };

    let evidence_cursor_val: Option<i64> = None;
    let cursor_delta = match (frontier, evidence_cursor_val) {
        (Some(f), Some(e)) => Some(f - e),
        _ => None,
    };

    let sort_key = (
        kind.priority_class(),
        -cursor_delta.unwrap_or(0),
        0,
        f.rule.to_string(),
        f.path.clone().unwrap_or_default(),
    );

    Some(GapCandidate {
        kind,
        stable_id: None,
        title: f.message.clone(),
        record_path: f.path.clone().map(PathBuf::from),
        record_type: None,
        canonical_status: None,
        canonical_lifecycle: None,
        canonical_source_cursor: None,
        reviewed_through_cursor: None,
        evidence_cursor: evidence_cursor_val,
        evidence_kind: None,
        evidence_path: None,
        evidence_line: None,
        current_source_frontier: frontier,
        cursor_delta,
        reason_code: reason,
        recommended_operation: operation,
        sort_key,
    })
}

// ---------------------------------------------------------------------------
// Bounded queue
// ---------------------------------------------------------------------------

/// Build a bounded actionable queue from classified gaps.
///
/// §7: Returns at most `max_strict + max_fairness` candidates.
/// Strict priority items fill first (up to max_strict).
/// Fairness items fill next (up to max_fairness).
/// Total shown = min(max_strict + max_fairness, total candidates).
/// Fairness never displaces strict.
pub fn bounded_queue<'a>(
    gaps: &'a [GapCandidate],
    max_strict: usize,
    max_fairness: usize,
) -> BoundedQueue<'a> {
    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    for g in gaps {
        *counts.entry(g.kind.label()).or_insert(0) += 1;
    }

    // Strict priority: everything except ResurfacingCandidate
    let strict: Vec<&GapCandidate> = gaps
        .iter()
        .filter(|g| g.kind != GapKind::ResurfacingCandidate)
        .collect();

    // Fairness: ResurfacingCandidate only
    let fairness: Vec<&GapCandidate> = gaps
        .iter()
        .filter(|g| g.kind == GapKind::ResurfacingCandidate)
        .collect();

    let strict_shown: Vec<&GapCandidate> = strict.into_iter().take(max_strict).collect();
    let fairness_shown: Vec<&GapCandidate> = fairness.into_iter().take(max_fairness).collect();

    let total = gaps.len();
    let shown = strict_shown.len() + fairness_shown.len();

    let mut queue: Vec<&GapCandidate> = strict_shown;
    queue.extend(fairness_shown);

    BoundedQueue {
        queue,
        total,
        shown,
        counts,
    }
}

/// The result of bounded queue construction.
pub struct BoundedQueue<'a> {
    pub queue: Vec<&'a GapCandidate>,
    pub total: usize,
    pub shown: usize,
    pub counts: BTreeMap<&'a str, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gap_kind_priority_ordering() {
        assert!(GapKind::StructuralError.priority_class() < GapKind::AuthorityGap.priority_class());
        assert!(
            GapKind::AuthorityGap.priority_class() < GapKind::MaterializationGap.priority_class()
        );
        assert!(
            GapKind::MaterializationGap.priority_class() < GapKind::Contradiction.priority_class()
        );
        assert!(
            GapKind::Contradiction.priority_class()
                < GapKind::RepresentationDivergence.priority_class()
        );
        assert!(
            GapKind::RepresentationDivergence.priority_class()
                < GapKind::SchemaGap.priority_class()
        );
        assert!(
            GapKind::SchemaGap.priority_class() < GapKind::ResurfacingCandidate.priority_class()
        );
    }

    #[test]
    fn bounded_queue_respects_limits() {
        let mut gaps = Vec::new();
        for i in 0..20 {
            gaps.push(GapCandidate {
                kind: GapKind::SchemaGap,
                stable_id: None,
                title: format!("gap {i}"),
                record_path: None,
                record_type: None,
                canonical_status: None,
                canonical_lifecycle: None,
                canonical_source_cursor: None,
                reviewed_through_cursor: None,
                evidence_cursor: None,
                evidence_kind: None,
                evidence_path: None,
                evidence_line: None,
                current_source_frontier: None,
                cursor_delta: None,
                reason_code: "TEST".to_string(),
                recommended_operation: RecommendedOperation::SchemaMaintenance,
                sort_key: (5, 0, 0, format!("{i:04}"), String::new()),
            });
        }
        let result = bounded_queue(&gaps, 8, 4);
        assert_eq!(result.shown, 8);
        assert_eq!(result.total, 20);
    }

    #[test]
    fn bounded_queue_strict_and_fairness_independent() {
        // §7: strict and fairness are independent allocations
        let mut gaps = Vec::new();
        // 10 strict gaps
        for i in 0..10 {
            gaps.push(GapCandidate {
                kind: GapKind::AuthorityGap,
                stable_id: None,
                title: format!("strict {i}"),
                record_path: None,
                record_type: None,
                canonical_status: None,
                canonical_lifecycle: None,
                canonical_source_cursor: None,
                reviewed_through_cursor: None,
                evidence_cursor: None,
                evidence_kind: None,
                evidence_path: None,
                evidence_line: None,
                current_source_frontier: None,
                cursor_delta: None,
                reason_code: "TEST".to_string(),
                recommended_operation: RecommendedOperation::DmInquiry,
                sort_key: (1, 0, 0, format!("{i:04}"), String::new()),
            });
        }
        // 6 resurfacing candidates
        for i in 0..6 {
            gaps.push(GapCandidate {
                kind: GapKind::ResurfacingCandidate,
                stable_id: None,
                title: format!("resurface {i}"),
                record_path: None,
                record_type: None,
                canonical_status: None,
                canonical_lifecycle: None,
                canonical_source_cursor: None,
                reviewed_through_cursor: None,
                evidence_cursor: None,
                evidence_kind: None,
                evidence_path: None,
                evidence_line: None,
                current_source_frontier: None,
                cursor_delta: None,
                reason_code: "TEST".to_string(),
                recommended_operation: RecommendedOperation::PlayOrResearchResurfacing,
                sort_key: (6, 0, 0, format!("{i:04}"), String::new()),
            });
        }
        let result = bounded_queue(&gaps, 8, 4);
        // 8 strict (capped) + 4 fairness (capped) = 12 shown
        assert_eq!(result.shown, 12);
        assert_eq!(result.total, 16);
    }
}
