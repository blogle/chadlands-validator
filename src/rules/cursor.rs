//! Rule 4 — cursor/materialization consistency.
//!
//! Makes "`cursor advanced` = `everything relevant was accounted for`"
//! mechanically checkable.

use std::collections::HashSet;

use crate::findings::{Finding, Severity};
use crate::manifest::{latest, Disposition};
use crate::rules::{finding, RuleContext};

/// Fields a runtime record can use to claim a materialization boundary.
const MATERIALIZATION_CLAIM_FIELDS: [&str; 2] =
    ["materialized_through_cursor", "reconciled_through_cursor"];

pub fn check(ctx: &RuleContext) -> Vec<Finding> {
    let mut out = Vec::new();
    let boundary = ctx.boundary;

    for note in &ctx.index.notes {
        if !note.curated || note.parse_error.is_some() {
            continue;
        }
        let fm = note.fm();
        let source = fm.get_i64("source_cursor");
        let reviewed = fm.get_i64("reviewed_through_cursor");

        // CHAD-CURSOR-001: material evidence newer than the checked frontier.
        if let (Some(s), Some(r)) = (source, reviewed) {
            if s > r {
                out.push(finding(
                    "CHAD-CURSOR-001",
                    ctx.sev("CHAD-CURSOR-001", Severity::Error),
                    Some(&note.path),
                    format!(
                        "source_cursor {s} exceeds reviewed_through_cursor {r}: \
                         the record claims material evidence from a range it \
                         has not reviewed. Either advance reviewed_through_cursor \
                         to {s} (after reviewing) or correct source_cursor."
                    ),
                ));
            }
        }

        // CHAD-CURSOR-002: future cursors.
        // Distinguish between:
        // - cursor > State Boundary but <= max direct-source cursor (stale boundary)
        // - cursor > max direct-source cursor (genuinely unsupported)
        if let Some(frontier) = boundary.current_source_cursor {
            for (field, value) in [("source_cursor", source), ("reviewed_through_cursor", reviewed)]
            {
                if let Some(v) = value {
                    if v > frontier {
                        // Check if the cursor is within the indexed direct-source range
                        let max_source = ctx
                            .source_index
                            .and_then(|si| si.max_source_cursor);
                        let in_source_range = max_source.map(|m| v <= m).unwrap_or(false);

                        let message = if in_source_range {
                            format!(
                                "`{field}: {v}` exceeds the authoritative \
                                 State Boundary current_source_cursor {frontier} \
                                 but is within the indexed direct-source frontier \
                                 ({max_source:?}). The State Boundary may be stale. \
                                 Determine whether the boundary needs updating before \
                                 altering the record."
                            )
                        } else {
                            format!(
                                "`{field}: {v}` exceeds both the authoritative \
                                 State Boundary current_source_cursor {frontier} \
                                 and the maximum indexed direct-source cursor \
                                 ({max_source:?}). Correct the cursor to not \
                                 exceed the actual evidence frontier."
                            )
                        };
                        out.push(finding(
                            "CHAD-CURSOR-002",
                            ctx.sev("CHAD-CURSOR-002", Severity::Error),
                            Some(&note.path),
                            message,
                        ));
                    }
                }
            }
        }

        // CHAD-CURSOR-005: runtime/handoff materialization claims beyond
        // canonical support.
        if let Some(canonical_frontier) = boundary.canonical_materialized_cursor {
            for field in MATERIALIZATION_CLAIM_FIELDS {
                if let Some(claim) = fm.get_i64(field) {
                    if claim > canonical_frontier {
                        out.push(finding(
                            "CHAD-CURSOR-005",
                            ctx.sev("CHAD-CURSOR-005", Severity::Error),
                            Some(&note.path),
                            format!(
                                "`{field}: {claim}` claims a newer materialization \
                                 boundary than canonical records support \
                                 (canonical_materialized_cursor {canonical_frontier}). \
                                 Ensure the handoff does not exceed the canonical frontier."
                            ),
                        ));
                    }
                }
            }
        }
    }

    // Manifest coverage: the frontier manifest must account for every
    // canonical record reviewed at/above its cursor.
    if let Some(m) = latest(ctx.manifests) {
        let cursor = m.materialized_cursor.unwrap();
        let subjects: HashSet<&str> = m.subjects.iter().map(|s| s.path.as_str()).collect();

        for note in &ctx.index.notes {
            if !note.curated || !note.is_canonical() || note.parse_error.is_some() {
                continue;
            }
            if let Some(r) = note.fm().get_i64("reviewed_through_cursor") {
                if r >= cursor && !subjects.contains(note.path.as_str()) {
                    out.push(finding(
                        "CHAD-CURSOR-003",
                        ctx.sev("CHAD-CURSOR-003", Severity::Error),
                        Some(&note.path),
                        format!(
                            "canonical record claims review through {r} (>= \
                             materialized cursor {cursor}) but has no disposition \
                             in reconciliation manifest `{}`. Add it as a subject \
                             with disposition UPDATED or REVIEWED — NO MATERIAL CHANGE.",
                            m.path
                        ),
                    ));
                }
            }
        }

        for s in &m.subjects {
            if matches!(s.disposition, Disposition::BlockedExternal | Disposition::Invalid(_)) {
                continue;
            }
            if let Some(note) = ctx.index.find_by_path(&s.path) {
                let r = note.fm().get_i64("reviewed_through_cursor");
                if r.map(|r| r < cursor).unwrap_or(true) {
                    out.push(finding(
                        "CHAD-CURSOR-004",
                        ctx.sev("CHAD-CURSOR-004", Severity::Error),
                        Some(&s.path),
                        format!(
                            "manifest `{}` dispositions this subject as {} through \
                             cursor {cursor}, but the note's reviewed_through_cursor \
                             is {}. Advance the note's reviewed_through_cursor or \
                             correct the manifest disposition.",
                            m.path,
                            s.disposition.label(),
                            r.map(|v| v.to_string())
                                .unwrap_or_else(|| "missing".to_string())
                        ),
                    ));
                }
            }
        }
    }

    out
}
