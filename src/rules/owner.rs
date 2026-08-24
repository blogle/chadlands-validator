//! Rule 3 — canonical-owner completeness.
//!
//! Canonical record types carry required structural fields. Missing fields
//! are ERRORs. Explicitly unresolved values (MISSING, UNKNOWN, UNASSIGNED,
//! BLOCKED) are WARNs where the schema permits unresolved state, ERRORs
//! where it does not. The validator never demands invented values.

use crate::findings::{Finding, Severity};
use crate::rules::{finding, RuleContext};
use crate::vault::Note;

fn is_unresolved(config: &crate::config::Config, value: &str) -> bool {
    let v = value.trim().to_ascii_uppercase();
    config
        .unresolved_values
        .iter()
        .any(|u| u.eq_ignore_ascii_case(&v))
}

fn check_note(ctx: &RuleContext, note: &Note, out: &mut Vec<Finding>) {
    let type_name = match note.type_str() {
        Some(t) => t,
        None => return,
    };
    let requirements = match ctx.config.required_fields.get(&type_name) {
        Some(r) => r,
        None => return,
    };
    let permitted = ctx
        .config
        .unresolved_permitted
        .get(&type_name)
        .map(|v| v.as_slice())
        .unwrap_or(&[]);

    for req in requirements {
        let fm = note.fm();
        let present_key = req.alternatives.iter().find(|k| fm.has(k));
        match present_key {
            None => out.push(finding(
                "CHAD-OWNER-001",
                ctx.sev("CHAD-OWNER-001", Severity::Error),
                Some(&note.path),
                format!(
                    "canonical {type_name} is missing required structural field `{}`. \
                     Add it to the frontmatter.",
                    req.label()
                ),
            )),
            Some(key) => {
                if let Some(value) = fm.get_str(key) {
                    if is_unresolved(ctx.config, &value) {
                        let field_permitted =
                            permitted.iter().any(|p| p.eq_ignore_ascii_case(key));
                        if field_permitted {
                            out.push(finding(
                                "CHAD-OWNER-002",
                                ctx.sev("CHAD-OWNER-002", Severity::Warn),
                                Some(&note.path),
                                format!(
                                    "canonical {type_name} field `{key}` is explicitly \
                                     unresolved ({value}). Legal but debt-bearing; \
                                     resolve when evidence is available."
                                ),
                            ));
                        } else {
                            let valid = ctx
                                .config
                                .unresolved_values
                                .iter()
                                .map(|s| s.to_lowercase())
                                .collect::<Vec<_>>()
                                .join(", ");
                            out.push(finding(
                                "CHAD-OWNER-003",
                                ctx.sev("CHAD-OWNER-003", Severity::Error),
                                Some(&note.path),
                                format!(
                                    "canonical {type_name} field `{key}` is unresolved \
                                     ({value}) where the schema requires a resolved \
                                     value. Unresolved markers ({valid}) are only \
                                     permitted on: {}.",
                                    permitted.join(", ")
                                ),
                            ));
                        }
                    }
                }
            }
        }
    }
}

pub fn check(ctx: &RuleContext) -> Vec<Finding> {
    let mut out = Vec::new();
    for note in &ctx.index.notes {
        if !note.curated || !note.is_canonical() || note.parse_error.is_some() {
            continue;
        }
        check_note(ctx, note, &mut out);
    }
    out
}
