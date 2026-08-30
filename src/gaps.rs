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
use crate::findings::{Finding, Findings, Severity};
use crate::lifecycle_events::{outcomes_compatible, SourceLifecycleEvent};
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

    /// Rule which produced this candidate, when it came from a finding.
    pub source_rule: Option<String>,

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
    pub evidence: Vec<GapEvidence>,

    pub accepted_year: Option<i64>,
    pub acceptance_cursor: Option<i64>,
    pub started_cursor: Option<i64>,
    pub last_progress_cursor: Option<i64>,
    pub last_progress_year: Option<i64>,
    pub due_year: Option<i64>,
    pub exact_fields_owed: Vec<String>,

    pub current_source_frontier: Option<i64>,
    pub cursor_delta: Option<i64>,

    pub reason_code: String,
    pub recommended_operation: RecommendedOperation,

    /// Strict ordering key: (priority_class, negated_cursor_delta, due_year,
    /// stable_id, path). Lower is more urgent.
    pub sort_key: (u8, i64, i64, String, String),
}

#[derive(Debug, Clone)]
pub struct GapEvidence {
    pub outcome: Option<String>,
    pub cursor: i64,
    pub kind: ActivityEvidenceKind,
    pub path: String,
    pub line: usize,
    pub raw_evidence: String,
}

impl GapEvidence {
    fn canonical(outcome: Option<String>, cursor: Option<i64>, path: &str, raw: String) -> Self {
        GapEvidence {
            outcome,
            cursor: cursor.unwrap_or(0),
            kind: ActivityEvidenceKind::CanonicalRecord,
            path: path.to_string(),
            line: 0,
            raw_evidence: raw,
        }
    }
}

fn lifecycle_evidence(event: &SourceLifecycleEvent) -> GapEvidence {
    GapEvidence {
        outcome: Some(event.outcome.label().to_string()),
        cursor: event.cursor,
        kind: event.evidence_kind,
        path: event.source_file.clone(),
        line: event.source_line,
        raw_evidence: event.raw_evidence.clone(),
    }
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
        if let Some(gap) = classify_finding(f, source_index, boundary, vault_index) {
            gaps.push(gap);
        }
    }

    // 2. Detect representation divergence: boundary trails collected evidence.
    // A cursor finding does not suppress this synthetic State Boundary signal;
    // ordinary candidate identity deduplication is the only suppression here.
    if let (Some(bc), Some(df)) = (
        boundary.current_source_cursor,
        source_index.max_source_cursor,
    ) {
        if bc < df {
            gaps.push(GapCandidate {
                kind: GapKind::RepresentationDivergence,
                source_rule: None,
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
                evidence: Vec::new(),
                accepted_year: None,
                acceptance_cursor: None,
                started_cursor: None,
                last_progress_cursor: None,
                last_progress_year: None,
                due_year: None,
                exact_fields_owed: Vec::new(),
                current_source_frontier: source_index.max_source_cursor,
                cursor_delta: source_index.max_source_cursor.map(|f| f - bc),
                reason_code: "STATE_BOUNDARY_STALE".to_string(),
                recommended_operation: RecommendedOperation::PlayerSideReconciliation,
                sort_key: (
                    action_priority(
                        GapKind::RepresentationDivergence,
                        None,
                        "STATE_BOUNDARY_STALE",
                        None,
                        boundary.current_year,
                    ),
                    -(source_index.max_source_cursor.unwrap_or(0) - bc),
                    0,
                    String::new(),
                    String::new(),
                ),
            });
        }
    }

    // 3. Select the one deterministic evidence set used by contradiction,
    // materialization, and authority suppression.
    let mut relevant_current_terminal_events = BTreeMap::new();
    for identity in &source_index.identities {
        let Some(note) = vault_index.find_by_path(&identity.note_path) else {
            continue;
        };
        let terminal = crate::lifecycle_events::select_current_unresolved_terminal_events(
            note,
            &identity.key,
            &source_index.lifecycle_events,
        );
        if !terminal.is_empty() {
            relevant_current_terminal_events.insert(identity.key.clone(), terminal);
        }
    }

    // 4. Check for incompatible structured terminal receipts.
    // If a road has both success and failure terminal receipts, that is a
    // contradiction regardless of lifecycle events.
    let receipt_states = crate::receipts::build_road_states(&source_index.receipts);
    for identity in &source_index.identities {
        let Some(note) = vault_index.find_by_path(&identity.note_path) else {
            continue;
        };
        let receipt_state = receipt_states.get(&identity.key);
        if let Some(state) = receipt_state {
            if state.has_terminal_conflict() {
                let fm = note.fm();
                let canonical_source_cursor = fm.get_i64("source_cursor");
                let reviewed_through_cursor = fm.get_i64("reviewed_through_cursor");
                let frontier = source_index.max_source_cursor;

                let evidence: Vec<GapEvidence> = state
                    .terminal_receipts
                    .iter()
                    .map(|r| GapEvidence {
                        outcome: r.result.clone(),
                        cursor: r.cursor,
                        kind: ActivityEvidenceKind::StructuredReceipt,
                        path: r.source_file.clone(),
                        line: r.line,
                        raw_evidence: format!(
                            "structured terminal receipt: {}",
                            r.result.as_deref().unwrap_or("—")
                        ),
                    })
                    .collect();

                let latest_cursor = state.terminal_receipts.iter().map(|r| r.cursor).max();
                let cursor_delta =
                    frontier.and_then(|f| latest_cursor.and_then(|lc| (f >= lc).then_some(f - lc)));

                gaps.push(GapCandidate {
                    kind: GapKind::Contradiction,
                    source_rule: None,
                    stable_id: Some(identity.key.clone()),
                    title: format!(
                        "{}: incompatible terminal receipts (success + failure)",
                        identity.title
                    ),
                    record_path: Some(PathBuf::from(&identity.note_path)),
                    record_type: Some(identity.type_name.clone()),
                    canonical_status: identity.status.clone(),
                    canonical_lifecycle: identity.lifecycle.clone(),
                    canonical_source_cursor,
                    reviewed_through_cursor,
                    evidence_cursor: latest_cursor,
                    evidence_kind: None,
                    evidence_path: None,
                    evidence_line: None,
                    evidence,
                    accepted_year: fm.get_i64("accepted_year"),
                    acceptance_cursor: fm.get_i64("acceptance_cursor"),
                    started_cursor: fm.get_i64("started_cursor"),
                    last_progress_cursor: fm.get_i64("last_progress_cursor"),
                    last_progress_year: fm.get_i64("last_progress_year"),
                    due_year: fm.get_i64("terminal_due_year"),
                    exact_fields_owed: Vec::new(),
                    current_source_frontier: frontier,
                    cursor_delta,
                    reason_code: "INCOMPATIBLE_TERMINAL_RECEIPTS".to_string(),
                    recommended_operation: RecommendedOperation::ContradictionAdjudication,
                    sort_key: (
                        action_priority(
                            GapKind::Contradiction,
                            None,
                            "INCOMPATIBLE_TERMINAL_RECEIPTS",
                            fm.get_i64("terminal_due_year"),
                            boundary.current_year,
                        ),
                        -cursor_delta.unwrap_or(0),
                        0,
                        identity.key.clone(),
                        identity.note_path.clone(),
                    ),
                });
            }
        }
    }

    // 5. Resolve current-lifecycle contradictions before materialization.
    for identity in &source_index.identities {
        let Some(note) = vault_index.find_by_path(&identity.note_path) else {
            continue;
        };
        let Some(terminal) = relevant_current_terminal_events.get(&identity.key) else {
            continue;
        };

        let conflict = terminal.iter().enumerate().find_map(|(i, a)| {
            terminal
                .iter()
                .skip(i + 1)
                .find(|b| !outcomes_compatible(a.outcome, b.outcome))
                .map(|b| (*a, *b))
        });
        let fm = note.fm();
        let canonical_source_cursor = fm.get_i64("source_cursor");
        let reviewed_through_cursor = fm.get_i64("reviewed_through_cursor");
        let frontier = source_index.max_source_cursor;
        let common = |evidence: Vec<GapEvidence>, latest: &SourceLifecycleEvent| {
            let cursor_delta =
                frontier.and_then(|f| (f >= latest.cursor).then_some(f - latest.cursor));
            (evidence, cursor_delta)
        };

        if let Some((a, b)) = conflict {
            let (evidence, cursor_delta) =
                common(vec![lifecycle_evidence(a), lifecycle_evidence(b)], b);
            gaps.push(GapCandidate {
                kind: GapKind::Contradiction,
                source_rule: None,
                stable_id: Some(identity.key.clone()),
                title: format!(
                    "{}: incompatible current-lifecycle claims {} vs {}",
                    identity.title,
                    a.outcome.label(),
                    b.outcome.label()
                ),
                record_path: Some(PathBuf::from(&identity.note_path)),
                record_type: Some(identity.type_name.clone()),
                canonical_status: identity.status.clone(),
                canonical_lifecycle: identity.lifecycle.clone(),
                canonical_source_cursor,
                reviewed_through_cursor,
                evidence_cursor: Some(b.cursor),
                evidence_kind: Some(b.evidence_kind),
                evidence_path: Some(b.source_file.clone()),
                evidence_line: Some(b.source_line),
                evidence,
                accepted_year: fm.get_i64("accepted_year"),
                acceptance_cursor: fm.get_i64("acceptance_cursor"),
                started_cursor: fm.get_i64("started_cursor"),
                last_progress_cursor: fm.get_i64("last_progress_cursor"),
                last_progress_year: fm.get_i64("last_progress_year"),
                due_year: fm.get_i64("terminal_due_year"),
                exact_fields_owed: Vec::new(),
                current_source_frontier: frontier,
                cursor_delta,
                reason_code: "INCOMPATIBLE_CURRENT_LIFECYCLE_TERMINAL_EVENTS".to_string(),
                recommended_operation: RecommendedOperation::ContradictionAdjudication,
                sort_key: (
                    action_priority(
                        GapKind::Contradiction,
                        None,
                        "INCOMPATIBLE_CURRENT_LIFECYCLE_TERMINAL_EVENTS",
                        fm.get_i64("terminal_due_year"),
                        boundary.current_year,
                    ),
                    -cursor_delta.unwrap_or(0),
                    0,
                    identity.key.clone(),
                    identity.note_path.clone(),
                ),
            });
            continue;
        }

        let latest = *terminal.last().expect("non-empty terminal evidence");
        let canonical_polarity =
            crate::lifecycle_events::CanonicalTerminalPolarity::from_note(note);

        // For settled terminal canon, use terminal_result_cursor as the
        // settlement boundary. For nonterminal, use source_cursor.
        let effective_boundary = if canonical_polarity.is_some() {
            fm.get_i64("terminal_result_cursor")
                .or(canonical_source_cursor)
        } else {
            canonical_source_cursor
        };

        // Skip when source is not newer than canonical settlement boundary.
        if effective_boundary
            .map(|c| latest.cursor <= c)
            .unwrap_or(false)
        {
            continue;
        }

        // Non-retcon invariant: settled canonical terminal state must not be
        // silently overwritten by a newer source event. When the canonical
        // terminal polarity is known and incompatible with the source outcome,
        // classify as CONTRADICTION and preserve both claims.
        // When polarity is UnknownTerminal (e.g. status=closed with no
        // controlled outcome), the canon expresses no binary claim, so a
        // later explicit result is REPRESENTATION_DIVERGENCE, not contradiction.
        if let Some(polarity) = canonical_polarity {
            match polarity {
                crate::lifecycle_events::CanonicalTerminalPolarity::UnknownTerminal => {
                    // Unknown polarity: later explicit terminal result is
                    // representation debt, not a contradiction
                    let evidence = terminal.iter().copied().map(lifecycle_evidence).collect();
                    let (evidence, cursor_delta) = common(evidence, latest);
                    gaps.push(GapCandidate {
                        kind: GapKind::RepresentationDivergence,
                        source_rule: None,
                        stable_id: Some(identity.key.clone()),
                        title: format!(
                            "{}: closed record lacks controlled terminal polarity; \
                             later source reports {}",
                            identity.title,
                            latest.outcome.label()
                        ),
                        record_path: Some(PathBuf::from(&identity.note_path)),
                        record_type: Some(identity.type_name.clone()),
                        canonical_status: identity.status.clone(),
                        canonical_lifecycle: identity.lifecycle.clone(),
                        canonical_source_cursor,
                        reviewed_through_cursor,
                        evidence_cursor: Some(latest.cursor),
                        evidence_kind: Some(latest.evidence_kind),
                        evidence_path: Some(latest.source_file.clone()),
                        evidence_line: Some(latest.source_line),
                        evidence,
                        accepted_year: fm.get_i64("accepted_year"),
                        acceptance_cursor: fm.get_i64("acceptance_cursor"),
                        started_cursor: fm.get_i64("started_cursor"),
                        last_progress_cursor: fm.get_i64("last_progress_cursor"),
                        last_progress_year: fm.get_i64("last_progress_year"),
                        due_year: fm.get_i64("terminal_due_year"),
                        exact_fields_owed: Vec::new(),
                        current_source_frontier: frontier,
                        cursor_delta,
                        reason_code: "CLOSED_NO_CONTROLLED_TERMINAL_POLARITY".to_string(),
                        recommended_operation: RecommendedOperation::SchemaMaintenance,
                        sort_key: (
                            action_priority(
                                GapKind::RepresentationDivergence,
                                None,
                                "CLOSED_NO_CONTROLLED_TERMINAL_POLARITY",
                                fm.get_i64("terminal_due_year"),
                                boundary.current_year,
                            ),
                            -cursor_delta.unwrap_or(0),
                            0,
                            identity.key.clone(),
                            identity.note_path.clone(),
                        ),
                    });
                    continue;
                }
                _ if !polarity.compatible_with(latest.outcome) => {
                    let mut evidence = terminal
                        .iter()
                        .copied()
                        .map(lifecycle_evidence)
                        .collect::<Vec<_>>();

                    // Gate 3: Add canonical terminal provenance as distinct evidence
                    let canonical_status_str = identity.status.clone();
                    let canonical_lifecycle_str = identity.lifecycle.clone();
                    let terminal_result = fm.get_str("terminal_result");
                    let terminal_result_cursor = fm.get_i64("terminal_result_cursor");
                    let canonical_source = fm.get_i64("source_cursor");
                    let canonical_raw = format!(
                        "canonical settled {}; status={}; lifecycle={}; terminal_result={}; \
                         terminal_result_cursor={}; source_cursor={}",
                        polarity.label(),
                        canonical_status_str.as_deref().unwrap_or("—"),
                        canonical_lifecycle_str.as_deref().unwrap_or("—"),
                        terminal_result.as_deref().unwrap_or("—"),
                        terminal_result_cursor
                            .map(|c| c.to_string())
                            .unwrap_or_else(|| "—".to_string()),
                        canonical_source
                            .map(|c| c.to_string())
                            .unwrap_or_else(|| "—".to_string()),
                    );
                    evidence.insert(
                        0,
                        GapEvidence::canonical(
                            Some(polarity.label().to_string()),
                            terminal_result_cursor,
                            &identity.note_path,
                            canonical_raw,
                        ),
                    );

                    let (evidence, cursor_delta) = common(evidence, latest);
                    gaps.push(GapCandidate {
                        kind: GapKind::Contradiction,
                        source_rule: None,
                        stable_id: Some(identity.key.clone()),
                        title: format!(
                            "{}: settled canonical {} contradicts later source {}",
                            identity.title,
                            polarity.label(),
                            latest.outcome.label()
                        ),
                        record_path: Some(PathBuf::from(&identity.note_path)),
                        record_type: Some(identity.type_name.clone()),
                        canonical_status: identity.status.clone(),
                        canonical_lifecycle: identity.lifecycle.clone(),
                        canonical_source_cursor,
                        reviewed_through_cursor,
                        evidence_cursor: Some(latest.cursor),
                        evidence_kind: Some(latest.evidence_kind),
                        evidence_path: Some(latest.source_file.clone()),
                        evidence_line: Some(latest.source_line),
                        evidence,
                        accepted_year: fm.get_i64("accepted_year"),
                        acceptance_cursor: fm.get_i64("acceptance_cursor"),
                        started_cursor: fm.get_i64("started_cursor"),
                        last_progress_cursor: fm.get_i64("last_progress_cursor"),
                        last_progress_year: fm.get_i64("last_progress_year"),
                        due_year: fm.get_i64("terminal_due_year"),
                        exact_fields_owed: Vec::new(),
                        current_source_frontier: frontier,
                        cursor_delta,
                        reason_code: "SETTLED_CANON_CONTRADICTS_LATER_SOURCE".to_string(),
                        recommended_operation: RecommendedOperation::ContradictionAdjudication,
                        sort_key: (
                            action_priority(
                                GapKind::Contradiction,
                                None,
                                "SETTLED_CANON_CONTRADICTS_LATER_SOURCE",
                                fm.get_i64("terminal_due_year"),
                                boundary.current_year,
                            ),
                            -cursor_delta.unwrap_or(0),
                            0,
                            identity.key.clone(),
                            identity.note_path.clone(),
                        ),
                    });
                    continue;
                }
                _ => {
                    // Compatible reconfirmation — no gap
                    continue;
                }
            }
        }

        // Canonical is nonterminal. Source supplies first terminal result.
        let evidence = terminal.iter().copied().map(lifecycle_evidence).collect();
        let (evidence, cursor_delta) = common(evidence, latest);
        let behind_review = reviewed_through_cursor
            .map(|c| latest.cursor <= c)
            .unwrap_or(false);
        let kind = if behind_review {
            GapKind::RepresentationDivergence
        } else {
            GapKind::MaterializationGap
        };
        gaps.push(GapCandidate {
            kind,
            source_rule: None,
            stable_id: Some(identity.key.clone()),
            title: format!(
                "{}: direct source reports {} but canonical state is {}",
                identity.title,
                latest.outcome.label(),
                identity
                    .lifecycle
                    .as_deref()
                    .or(identity.status.as_deref())
                    .unwrap_or("unknown")
            ),
            record_path: Some(PathBuf::from(&identity.note_path)),
            record_type: Some(identity.type_name.clone()),
            canonical_status: identity.status.clone(),
            canonical_lifecycle: identity.lifecycle.clone(),
            canonical_source_cursor,
            reviewed_through_cursor,
            evidence_cursor: Some(latest.cursor),
            evidence_kind: Some(latest.evidence_kind),
            evidence_path: Some(latest.source_file.clone()),
            evidence_line: Some(latest.source_line),
            evidence,
            accepted_year: fm.get_i64("accepted_year"),
            acceptance_cursor: fm.get_i64("acceptance_cursor"),
            started_cursor: fm.get_i64("started_cursor"),
            last_progress_cursor: fm.get_i64("last_progress_cursor"),
            last_progress_year: fm.get_i64("last_progress_year"),
            due_year: fm.get_i64("terminal_due_year"),
            exact_fields_owed: Vec::new(),
            current_source_frontier: frontier,
            cursor_delta,
            reason_code: if behind_review {
                "REVIEWED_PAST_TERMINAL_EVENT"
            } else {
                "LIFECYCLE_EVENT_NEWER_THAN_CANONICAL"
            }
            .to_string(),
            recommended_operation: if behind_review {
                RecommendedOperation::SchemaMaintenance
            } else {
                RecommendedOperation::PlayerSideReconciliation
            },
            sort_key: (
                action_priority(
                    kind,
                    None,
                    if behind_review {
                        "REVIEWED_PAST_TERMINAL_EVENT"
                    } else {
                        "LIFECYCLE_EVENT_NEWER_THAN_CANONICAL"
                    },
                    fm.get_i64("terminal_due_year"),
                    boundary.current_year,
                ),
                -cursor_delta.unwrap_or(0),
                0,
                identity.key.clone(),
                identity.note_path.clone(),
            ),
        });
    }

    gaps.retain(|g| {
        if g.kind == GapKind::AuthorityGap {
            // Check stable_id match
            if let Some(stable_id) = &g.stable_id {
                if relevant_current_terminal_events.contains_key(stable_id) {
                    return false;
                }
            }
            // Check structured path match
            if let Some(path) = &g.record_path {
                let path_str = path.to_string_lossy();
                if source_index.identities.iter().any(|id| {
                    id.note_path == path_str
                        && relevant_current_terminal_events.contains_key(&id.key)
                }) {
                    return false;
                }
            }
        }
        true
    });

    // Deterministic gap identity: repeated equivalent diagnostics collapse.
    gaps.sort_by(|a, b| a.sort_key.cmp(&b.sort_key));
    gaps.dedup_by(|a, b| {
        a.kind == b.kind
            && a.stable_id == b.stable_id
            && a.record_path == b.record_path
            && a.reason_code == b.reason_code
            && a.source_rule == b.source_rule
    });
    // Stable tie-breaking: sort by sort_key
    gaps.sort_by(|a, b| a.sort_key.cmp(&b.sort_key));

    gaps
}

fn classify_finding(
    f: &Finding,
    _source_index: &SourceIndex,
    _boundary: &StateBoundary,
    vault_index: &VaultIndex,
) -> Option<GapCandidate> {
    let frontier = _source_index.max_source_cursor;

    let (kind, operation, reason) = match f.rule {
        // §6.4: State boundary structural errors → StructuralError
        "CHAD-STATE-001" | "CHAD-STATE-002" | "CHAD-STATE-003" | "CHAD-STATE-004" => {
            if f.severity == Severity::Error {
                (
                    GapKind::StructuralError,
                    RecommendedOperation::SchemaMaintenance,
                    "STATE_BOUNDARY_DEFECT".to_string(),
                )
            } else {
                (
                    GapKind::SchemaGap,
                    RecommendedOperation::SchemaMaintenance,
                    "STATE_BOUNDARY_DEBT".to_string(),
                )
            }
        }

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
        "CHAD-SCHEMA-001" => {
            if f.severity == Severity::Error {
                (
                    GapKind::StructuralError,
                    RecommendedOperation::SchemaMaintenance,
                    "SCHEMA_DEFECT".to_string(),
                )
            } else {
                (
                    GapKind::SchemaGap,
                    RecommendedOperation::SchemaMaintenance,
                    "SCHEMA_DEBT".to_string(),
                )
            }
        }
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

    let note = f
        .path
        .as_deref()
        .and_then(|path| vault_index.find_by_path(path));
    let identity = f.path.as_deref().and_then(|path| {
        _source_index
            .identities
            .iter()
            .find(|id| id.note_path == path)
    });
    let fm = note.map(|n| n.fm());
    let due_year = fm.as_ref().and_then(|fm| fm.get_i64("terminal_due_year"));
    let receipt_states = crate::receipts::build_road_states(&_source_index.receipts);
    let receipt_state = identity.and_then(|id| receipt_states.get(&id.key));
    let sort_key = (
        action_priority(kind, Some(f.rule), &reason, due_year, None),
        -cursor_delta.unwrap_or(0),
        due_year.unwrap_or(i64::MAX),
        f.rule.to_string(),
        f.path.clone().unwrap_or_default(),
    );
    Some(GapCandidate {
        kind,
        source_rule: Some(f.rule.to_string()),
        stable_id: identity.map(|id| id.key.clone()),
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
        evidence: Vec::new(),
        accepted_year: fm.as_ref().and_then(|fm| fm.get_i64("accepted_year")),
        acceptance_cursor: fm
            .as_ref()
            .and_then(|fm| fm.get_i64("acceptance_cursor"))
            .or_else(|| receipt_state.and_then(|state| state.accepted_at)),
        started_cursor: fm
            .as_ref()
            .and_then(|fm| fm.get_i64("started_cursor"))
            .or_else(|| receipt_state.and_then(|state| state.started_at)),
        last_progress_cursor: fm
            .as_ref()
            .and_then(|fm| fm.get_i64("last_progress_cursor"))
            .or_else(|| receipt_state.and_then(|state| state.last_progress_at)),
        last_progress_year: fm.as_ref().and_then(|fm| fm.get_i64("last_progress_year")),
        due_year: fm.as_ref().and_then(|fm| fm.get_i64("terminal_due_year")),
        exact_fields_owed: if kind == GapKind::AuthorityGap {
            vec![
                "current lifecycle".to_string(),
                "succeeded / failed / stalled / continuing".to_string(),
                "terminal result if terminal".to_string(),
                "due boundary if still live".to_string(),
                "material intermediates owed".to_string(),
            ]
        } else {
            Vec::new()
        },
        current_source_frontier: frontier,
        cursor_delta,
        reason_code: reason,
        recommended_operation: operation,
        sort_key,
    })
}

/// Centralized action priority for all GapCandidates. Taxonomy and operational
/// ordering are separate. This is the single source of truth for queue ordering.
pub(crate) fn action_priority(
    kind: GapKind,
    source_rule: Option<&str>,
    reason_code: &str,
    due_year: Option<i64>,
    current_year: Option<i64>,
) -> u8 {
    match kind {
        GapKind::StructuralError => 0,
        GapKind::AuthorityGap => {
            let is_overdue = match (due_year, current_year) {
                (Some(due), Some(year)) => due < year,
                _ => source_rule == Some("CHAD-RECEIPT-004"),
            };
            if is_overdue {
                1
            } else {
                4
            }
        }
        GapKind::MaterializationGap => 2,
        GapKind::Contradiction => 3,
        GapKind::RepresentationDivergence => {
            if reason_code == "STATE_BOUNDARY_STALE" {
                5
            } else {
                6
            }
        }
        GapKind::ResurfacingCandidate => 7,
        GapKind::SchemaGap => 8,
    }
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

/// Pure deterministic prompt renderer. It consumes only the typed gap and its
/// retained evidence; it performs no search and cannot mutate canonical state.
pub fn render_prompt(gap: &GapCandidate) -> Option<String> {
    if !matches!(
        gap.kind,
        GapKind::MaterializationGap | GapKind::AuthorityGap | GapKind::Contradiction
    ) {
        return None;
    }
    let mut out = String::new();
    out.push_str(&format!(
        "### {} — {}\n\n",
        gap.kind.label(),
        gap.stable_id.as_deref().unwrap_or("unknown-id")
    ));
    out.push_str(&format!(
        "- canonical path: `{}`\n",
        gap.record_path
            .as_ref()
            .map(|p| p.display().to_string())
            .unwrap_or_else(|| "—".to_string())
    ));
    out.push_str(&format!(
        "- stable ID: {}\n",
        gap.stable_id.as_deref().unwrap_or("—")
    ));
    out.push_str(&format!(
        "- current status/lifecycle: {} / {}\n",
        gap.canonical_status.as_deref().unwrap_or("—"),
        gap.canonical_lifecycle.as_deref().unwrap_or("—")
    ));
    match gap.kind {
        GapKind::MaterializationGap => {
            out.push_str(
                "\n**DO NOT QUERY THE DM — DIRECT PLAYER EVIDENCE ALREADY ANSWERS THIS GAP.**\n\n",
            );
            out.push_str(&format!("- canonical source_cursor: {}\n- reviewed_through_cursor: {}\n- new direct evidence cursor: {}\n- evidence count: {}\n", display_i64(gap.canonical_source_cursor), display_i64(gap.reviewed_through_cursor), display_i64(gap.evidence_cursor), gap.evidence.len()));
            render_evidence(&mut out, &gap.evidence);
            out.push_str("\nReconcile only fields directly supported by the cited evidence.\nDo not invent capability, ownership, spending, follow-on work,\nresource effects, or new sovereign decisions.\n");
        }
        GapKind::AuthorityGap => {
            out.push_str("\n**INQUIRY ONLY**\n\n");
            out.push_str(&format!("- accepted year/cursor: {} / {}\n- started cursor: {}\n- last progress cursor/year: {} / {}\n- due boundary: {}\n- direct-source frontier: {}\n- exact fields owed: {}\n", display_i64(gap.accepted_year), display_i64(gap.acceptance_cursor), display_i64(gap.started_cursor), display_i64(gap.last_progress_cursor), display_i64(gap.last_progress_year), display_i64(gap.due_year), display_i64(gap.current_source_frontier), if gap.exact_fields_owed.is_empty() { "terminal result/outcome".to_string() } else { gap.exact_fields_owed.join(", ") }));
            out.push_str("\nRequest only the owed receipt fields. Do not create a new acceptance, repricing, spending, project, scope change, or sovereign authorization.\n");
        }
        GapKind::Contradiction => {
            out.push_str("\n**CORRECTION / ADJUDICATION ONLY**\n\n");
            render_evidence(&mut out, &gap.evidence);
            out.push_str("\nAdjudicate the incompatible authoritative claims. Do not choose a result without direct correction evidence.\n");
        }
        _ => unreachable!(),
    }
    Some(out)
}

fn render_evidence(out: &mut String, evidence: &[GapEvidence]) {
    for (index, item) in evidence.iter().enumerate() {
        out.push_str(&format!(
            "- claim {}: outcome {}; cursor {}; source `{}:{}`; method {}; evidence: `{}`\n",
            index + 1,
            item.outcome.as_deref().unwrap_or("—"),
            item.cursor,
            item.path,
            item.line,
            item.kind.label(),
            item.raw_evidence.replace('`', "'")
        ));
    }
}

fn display_i64(value: Option<i64>) -> String {
    value
        .map(|v| v.to_string())
        .unwrap_or_else(|| "—".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_policy_ordering() {
        // Overdue authority (CHAD-RECEIPT-004) outranks materialization
        assert!(
            action_priority(
                GapKind::AuthorityGap,
                Some("CHAD-RECEIPT-004"),
                "OVERDUE_RECEIPT",
                Some(37),
                Some(42),
            ) < action_priority(
                GapKind::MaterializationGap,
                None,
                "LIFECYCLE_EVENT_NEWER_THAN_CANONICAL",
                None,
                Some(42),
            )
        );
        // Current-year authority does NOT outrank materialization
        assert!(
            action_priority(
                GapKind::AuthorityGap,
                Some("CHAD-RECEIPT-003"),
                "RECEIPT_BOUNDARY_ARRIVING",
                Some(42),
                Some(42),
            ) > action_priority(
                GapKind::MaterializationGap,
                None,
                "LIFECYCLE_EVENT_NEWER_THAN_CANONICAL",
                None,
                Some(42),
            )
        );
        // StructuralError always first
        assert_eq!(
            action_priority(
                GapKind::StructuralError,
                None,
                "STATE_BOUNDARY_DEFECT",
                None,
                None
            ),
            0,
        );
        // Contradiction between materialization and current-year authority
        assert!(
            action_priority(GapKind::MaterializationGap, None, "X", None, None)
                < action_priority(GapKind::Contradiction, None, "X", None, None)
        );
        assert!(
            action_priority(GapKind::Contradiction, None, "X", None, None)
                < action_priority(
                    GapKind::AuthorityGap,
                    Some("CHAD-RECEIPT-003"),
                    "X",
                    None,
                    None,
                )
        );
        // SchemaGap after resurfacing
        assert!(
            action_priority(GapKind::ResurfacingCandidate, None, "X", None, None)
                < action_priority(GapKind::SchemaGap, None, "X", None, None)
        );
        // Overdue authority sorts by due_year ascending
        let a = action_priority(
            GapKind::AuthorityGap,
            Some("CHAD-RECEIPT-004"),
            "OVERDUE_RECEIPT",
            Some(37),
            Some(42),
        );
        let b = action_priority(
            GapKind::AuthorityGap,
            Some("CHAD-RECEIPT-004"),
            "OVERDUE_RECEIPT",
            Some(39),
            Some(42),
        );
        assert_eq!(a, b, "same priority class for overdue authority");
    }

    #[test]
    fn bounded_queue_respects_limits() {
        let mut gaps = Vec::new();
        for i in 0..20 {
            gaps.push(GapCandidate {
                kind: GapKind::SchemaGap,
                source_rule: None,
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
                evidence: Vec::new(),
                accepted_year: None,
                acceptance_cursor: None,
                started_cursor: None,
                last_progress_cursor: None,
                last_progress_year: None,
                due_year: None,
                exact_fields_owed: Vec::new(),
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
                source_rule: None,
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
                evidence: Vec::new(),
                accepted_year: None,
                acceptance_cursor: None,
                started_cursor: None,
                last_progress_cursor: None,
                last_progress_year: None,
                due_year: None,
                exact_fields_owed: Vec::new(),
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
                source_rule: None,
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
                evidence: Vec::new(),
                accepted_year: None,
                acceptance_cursor: None,
                started_cursor: None,
                last_progress_cursor: None,
                last_progress_year: None,
                due_year: None,
                exact_fields_owed: Vec::new(),
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
