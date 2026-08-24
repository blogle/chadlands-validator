//! Rule 2 — active canonical freshness.
//!
//! Every `status: active` + `retrieval_tier: canonical` record must carry
//! `reviewed_through_cursor >= canonical_materialized_cursor`, unless it is
//! explicitly marked BLOCKED — EXTERNAL. This distinguishes "reviewed and
//! unchanged" from "never reconciled". `source_cursor` and
//! `last_confirmed_year` are deliberately not required to advance.

use crate::findings::Severity;
use crate::rules::{finding, RuleContext};

pub fn check(ctx: &RuleContext) -> Vec<crate::findings::Finding> {
    let mut out = Vec::new();
    let frontier = match ctx.boundary.canonical_materialized_cursor {
        Some(c) => c,
        None => return out, // undeclared frontier: CHAD-STATE-002 already reported
    };

    for note in &ctx.index.notes {
        if !note.curated || !note.is_canonical() || !note.is_active() {
            continue;
        }
        if note.is_blocked_external() {
            continue;
        }
        match note.fm().get_i64("reviewed_through_cursor") {
            None => out.push(finding(
                "CHAD-FRESH-002",
                ctx.sev("CHAD-FRESH-002", Severity::Error),
                Some(&note.path),
                format!(
                    "active canonical record has no `reviewed_through_cursor`; \
                     cannot prove review against the materialization frontier \
                     {frontier}. Add reviewed_through_cursor after reviewing \
                     the record, or mark it BLOCKED — EXTERNAL."
                ),
            )),
            Some(c) if c < frontier => out.push(finding(
                "CHAD-FRESH-001",
                ctx.sev("CHAD-FRESH-001", Severity::Error),
                Some(&note.path),
                format!(
                    "active canonical record reviewed through {c}, below the \
                     materialization frontier {frontier}. The record is \
                     indistinguishable from 'never reconciled'. Reconcile \
                     through {frontier} or mark BLOCKED — EXTERNAL."
                ),
            )),
            _ => {}
        }
    }
    out
}
