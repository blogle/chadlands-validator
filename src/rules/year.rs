//! Rule 1 — resolved-year coverage.
//!
//! The gameplay chronology (`last_resolved_year`) must not advance beyond
//! the Chronicle: every year in the claimed resolved range must have a
//! Chronicle year record, and no resolved Chronicle record may exist beyond
//! the declared resolved boundary. Future-dated evidence years are
//! contradictions.

use crate::boundary;
use crate::findings::Severity;
use crate::rules::{finding, RuleContext};
use crate::vault::Note;

/// Game-year fields that describe evidence/state and therefore may never
/// exceed the current year. Target/review fields are excluded by design.
const EVIDENCE_YEAR_FIELDS: [&str; 8] = [
    "year",
    "first_known_year",
    "last_confirmed_year",
    "accepted_year",
    "completed_year",
    "first_opened_year",
    "birth_year",
    "death_year",
];

/// Extract the Chronicle year: `year:` frontmatter wins, else the
/// `Year N.md` filename.
fn chronicle_year(note: &Note, chronicle_dir: &str) -> Option<i64> {
    let is_chronicle_type = note.type_str().as_deref() == Some("chronicle-year");
    let in_chronicle_dir = note.path.starts_with(&format!("{chronicle_dir}/"));
    if !is_chronicle_type && !in_chronicle_dir {
        return None;
    }
    if let Some(y) = note.fm().get_i64("year") {
        return Some(y);
    }
    let stem = note.title();
    stem.strip_prefix("Year ")
        .and_then(|rest| rest.trim().parse::<i64>().ok())
}

/// Filename-derived year, for mismatch detection.
fn filename_year(note: &Note, chronicle_dir: &str) -> Option<i64> {
    if !note.path.starts_with(&format!("{chronicle_dir}/")) {
        return None;
    }
    note.title()
        .strip_prefix("Year ")
        .and_then(|rest| rest.trim().parse::<i64>().ok())
}

pub fn check(ctx: &RuleContext) -> Vec<crate::findings::Finding> {
    let mut out = Vec::new();
    let config = ctx.config;
    let boundary = ctx.boundary;

    let mut years: Vec<(i64, &Note)> = Vec::new();
    for note in &ctx.index.notes {
        if !note.curated {
            continue;
        }
        if let Some(y) = chronicle_year(note, &config.chronicle_dir) {
            years.push((y, note));
        }
    }
    let highest = years.iter().map(|(y, _)| *y).max();

    // CHAD-YEAR-001: claimed resolution beyond the Chronicle.
    if let (Some(resolved), Some(highest)) = (boundary.last_resolved_year, highest) {
        if resolved > highest {
            out.push(finding(
                "CHAD-YEAR-001",
                ctx.sev("CHAD-YEAR-001", Severity::Error),
                None,
                format!(
                    "last_resolved_year {resolved} exceeds the highest Chronicle year \
                     record present ({highest}): Chronicle years {next}..={resolved} \
                     are missing. Create the missing Chronicle records or lower \
                     last_resolved_year to {highest}.",
                    next = highest + 1
                ),
            ));
        }
    } else if let (Some(resolved), None) = (boundary.last_resolved_year, highest) {
        out.push(finding(
            "CHAD-YEAR-001",
            ctx.sev("CHAD-YEAR-001", Severity::Error),
            None,
            format!(
                "last_resolved_year {} is claimed but no Chronicle year records \
                 exist at all. Create Chronicle year records for the resolved range.",
                resolved
            ),
        ));
    }

    // CHAD-YEAR-004: gaps inside the claimed resolved range.
    if let Some(resolved) = boundary.last_resolved_year {
        let present: std::collections::HashSet<i64> = years.iter().map(|(y, _)| *y).collect();
        for y in 1..=resolved.min(highest.unwrap_or(resolved)) {
            if !present.contains(&y) && !config.chronicle_permitted_gaps.contains(&y) {
                out.push(finding(
                    "CHAD-YEAR-004",
                    ctx.sev("CHAD-YEAR-004", Severity::Error),
                    None,
                    format!(
                        "Chronicle year {y} is missing inside the claimed resolved \
                         range 1..={resolved}. Create `20 Chronicle/Year {y}.md` or \
                         add {y} to chronicle_permitted_gaps in the validator config."
                    ),
                ));
            }
        }
    }

    // Per-year-note checks.
    for (year, note) in &years {
        // CHAD-YEAR-002: a resolved Chronicle record beyond the declared boundary.
        let resolved_status = note.status().as_deref() == Some("resolved")
            || note
                .fm()
                .get_str("lifecycle")
                .map(|l| l.contains("resolved-year"))
                .unwrap_or(false);
        if let Some(resolved) = boundary.last_resolved_year {
            if *year > resolved && resolved_status {
                out.push(finding(
                    "CHAD-YEAR-002",
                    ctx.sev("CHAD-YEAR-002", Severity::Error),
                    Some(&note.path),
                    format!(
                        "Chronicle year {year} is marked resolved but the declared \
                         last_resolved_year is {resolved}. Either advance \
                         last_resolved_year to {year} or mark this year as unresolved."
                    ),
                ));
            }
        }
        // CHAD-YEAR-005: frontmatter year disagrees with the filename.
        if let (Some(fy), Some(my)) = (filename_year(note, &config.chronicle_dir), Some(*year)) {
            if fy != my {
                out.push(finding(
                    "CHAD-YEAR-005",
                    ctx.sev("CHAD-YEAR-005", Severity::Warn),
                    Some(&note.path),
                    format!(
                        "Chronicle note filename says Year {fy} but frontmatter \
                         year is {my}. Align the frontmatter `year` field with \
                         the filename."
                    ),
                ));
            }
        }
    }

    // CHAD-YEAR-003: future evidence years.
    // When the record's source cursor is within the direct-source frontier
    // but ahead of the State Boundary, the boundary may be stale — do NOT
    // recommend changing the year downward until the boundary is reconciled.
    if let Some(current_year) = boundary.current_year {
        let max_source = ctx.source_index.and_then(|si| si.max_source_cursor);

        for note in &ctx.index.notes {
            if !note.curated || note.parse_error.is_some() {
                continue;
            }
            let note_source_cursor = note.fm().get_i64("source_cursor");

            for field in EVIDENCE_YEAR_FIELDS {
                if let Some(v) = note.fm().get_i64(field) {
                    if v > current_year {
                        // Diagnose whether the boundary may be stale
                        let diag = note_source_cursor
                            .map(|sc| {
                                boundary::diagnose_cursor(
                                    sc,
                                    boundary.current_source_cursor,
                                    max_source,
                                )
                            })
                            .unwrap_or(boundary::BoundaryDiagnosis::Unknown);

                        let message = if diag.boundary_may_be_stale() {
                            format!(
                                "`{field}: {v}` lies in the future (current_year \
                                 {current_year}), but the record's source evidence \
                                 (cursor {sc}) is within the collected direct-source \
                                 frontier and ahead of the State Boundary. The \
                                 authoritative boundary may be stale. Reconcile \
                                 the boundary before altering the record year.",
                                sc = note_source_cursor.unwrap(),
                            )
                        } else if diag.beyond_evidence() {
                            format!(
                                "`{field}: {v}` lies in the future (current_year \
                                 {current_year}) and its source evidence cursor \
                                 {sc} exceeds the collected direct-source frontier \
                                 ({max_source:?}). The evidence is unsupported; \
                                 confirm the source and correct the record as needed.",
                                sc = note_source_cursor.unwrap(),
                            )
                        } else if matches!(diag, boundary::BoundaryDiagnosis::Unknown) {
                            format!(
                                "`{field}: {v}` lies in the future (current_year \
                                 {current_year}), but the record's source cursor \
                                 association or boundary relationship is unknown. \
                                 Reconcile the source association and authoritative \
                                 boundary before altering the record year."
                            )
                        } else {
                            format!(
                                "`{field}: {v}` lies in the future (current_year \
                                 {current_year}). Evidence years must not exceed the \
                                 current year. Use target_year or next_review_year \
                                 for future plans."
                            )
                        };
                        out.push(finding(
                            "CHAD-YEAR-003",
                            ctx.sev("CHAD-YEAR-003", Severity::Error),
                            Some(&note.path),
                            message,
                        ));
                    }
                }
            }
        }
    }

    out
}
