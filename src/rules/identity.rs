//! Rule 5 — contradiction and identity integrity over structured fields.
//!
//! Operates only on IDs, aliases, declared relationships, and status /
//! lifecycle values — never on prose semantics.

use std::collections::HashMap;

use crate::findings::{Finding, Severity};
use crate::rules::{finding, RuleContext};
use crate::vault::Note;

fn norm(s: &str) -> String {
    s.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
}

fn is_unresolved_marker(config: &crate::config::Config, value: &str) -> bool {
    config
        .unresolved_values
        .iter()
        .any(|u| u.eq_ignore_ascii_case(value.trim()))
        || value.trim().eq_ignore_ascii_case("missing-external-defect")
}

/// Fields that declare an alias/merge relationship, making an identity
/// collapse explicit rather than silent.
const ALIAS_FIELDS: [&str; 5] = ["aliases", "alias_of", "merged_from", "merged_into", "aka"];

pub fn check(ctx: &RuleContext) -> Vec<Finding> {
    let mut out = Vec::new();
    let curated: Vec<&Note> = ctx
        .index
        .notes
        .iter()
        .filter(|n| n.curated && n.parse_error.is_none())
        .collect();

    // CHAD-IDENTITY-001: duplicate canonical IDs.
    for field in &ctx.config.id_fields {
        let mut owners: HashMap<String, Vec<&Note>> = HashMap::new();
        for note in &curated {
            if let Some(v) = note.fm().get_str(field) {
                let v = v.trim().to_string();
                if v.is_empty() || is_unresolved_marker(ctx.config, &v) {
                    continue;
                }
                owners.entry(v).or_default().push(note);
            }
        }
        for (id, notes) in owners {
            if notes.len() > 1 {
                let paths: Vec<&str> = notes.iter().map(|n| n.path.as_str()).collect();
                out.push(finding(
                    "CHAD-IDENTITY-001",
                    ctx.sev("CHAD-IDENTITY-001", Severity::Error),
                    Some(&notes[0].path),
                    format!(
                        "canonical ID `{field}: {id}` is claimed by multiple records: \
                         {}. Each canonical ID must be unique. Resolve by removing \
                         the duplicate ID from one record.",
                        paths.join(", ")
                    ),
                ));
            }
        }
    }

    // CHAD-IDENTITY-002: duplicate active canonical identities.
    let mut by_identity: HashMap<(String, String), Vec<&Note>> = HashMap::new();
    for note in curated.iter().filter(|n| n.is_canonical()) {
        if let Some(t) = note.type_str() {
            by_identity
                .entry((t, norm(note.title())))
                .or_default()
                .push(note);
        }
    }
    for ((type_name, title), notes) in &by_identity {
        let active: Vec<&&Note> = notes.iter().filter(|n| n.is_active()).collect();
        if active.len() > 1 {
            let paths: Vec<&str> = active.iter().map(|n| n.path.as_str()).collect();
            out.push(finding(
                "CHAD-IDENTITY-002",
                ctx.sev("CHAD-IDENTITY-002", Severity::Error),
                Some(&active[0].path),
                format!(
                    "duplicate active canonical {type_name} identity `{title}`: \
                     {}. Merge, alias, or deactivate one record. Add an `aliases` \
                     or `alias_of` field to declare the relationship.",
                    paths.join(", ")
                ),
            ));
        }
    }

    for note in &curated {
        let fm = note.fm();

        // CHAD-IDENTITY-003: a record that is its own second.
        let lead = fm
            .get_str("lead")
            .or_else(|| fm.get_str("owner"));
        if let (Some(lead), Some(second)) = (lead, fm.get_str("second")) {
            if !is_unresolved_marker(ctx.config, &lead)
                && !is_unresolved_marker(ctx.config, &second)
                && norm(&lead) == norm(&second)
            {
                out.push(finding(
                    "CHAD-IDENTITY-003",
                    ctx.sev("CHAD-IDENTITY-003", Severity::Error),
                    Some(&note.path),
                    format!(
                        "lead/owner (`{lead}`) and second (`{second}`) are the \
                         same identity. Assign a different person as second."
                    ),
                ));
            }
        }

        // CHAD-IDENTITY-004: incompatible lifecycle/status combinations.
        let status = note.status().unwrap_or_default();
        let lifecycle = fm.get_str("lifecycle").unwrap_or_default();
        let life_status = fm.get_str("life_status").unwrap_or_default();
        let has_death_year = fm.get_i64("death_year").is_some();
        let claims_active = status == "active";
        let claims_dead = status == "deceased"
            || life_status == "deceased"
            || has_death_year
            || lifecycle.starts_with("deceased");
        if claims_active && (life_status == "deceased" || has_death_year) {
            out.push(finding(
                "CHAD-IDENTITY-004",
                ctx.sev("CHAD-IDENTITY-004", Severity::Error),
                Some(&note.path),
                format!(
                    "status is `active` but the record also declares death \
                     (life_status: `{life_status}`, death_year: {}). Set status \
                     to `deceased` or `last-confirmed`, or remove the death marker.",
                    fm.get_i64("death_year")
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| "none".to_string())
                ),
            ));
        } else if claims_dead && (claims_active || lifecycle.starts_with("active-")) {
            out.push(finding(
                "CHAD-IDENTITY-004",
                ctx.sev("CHAD-IDENTITY-004", Severity::Error),
                Some(&note.path),
                format!(
                    "record declares deceased state (status: `{status}`, life_status: \
                     `{life_status}`) alongside an active lifecycle (`{lifecycle}`). \
                     Set lifecycle to a non-active prefix or remove the deceased marker."
                ),
            ));
        }

        // CHAD-IDENTITY-006: alias/merge targets must resolve and must not
        // leave both sides active.
        for field in ["alias_of", "merged_into"] {
            if let Some(target) = fm.get_str(field) {
                let target_clean = target
                    .trim()
                    .trim_start_matches("[[")
                    .trim_end_matches("]]")
                    .split('|')
                    .next()
                    .unwrap_or("")
                    .split('#')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .to_string();
                if target_clean.is_empty() || is_unresolved_marker(ctx.config, &target_clean) {
                    continue;
                }
                let resolved = resolve_title(ctx, &target_clean);
                match resolved {
                    None => out.push(finding(
                        "CHAD-IDENTITY-006",
                        ctx.sev("CHAD-IDENTITY-006", Severity::Error),
                        Some(&note.path),
                        format!(
                            "`{field}` target `{target_clean}` does not resolve to \
                             any vault note. Correct the target path."
                        ),
                    )),
                    Some(target_note)
                        if target_note.is_active() && note.is_active() =>
                    {
                        out.push(finding(
                            "CHAD-IDENTITY-006",
                            ctx.sev("CHAD-IDENTITY-006", Severity::Error),
                            Some(&note.path),
                            format!(
                                "unresolved merge/alias collision: `{}` and `{field}` \
                                 target `{}` are both active. Deactivate one side \
                                 or fix the alias_of target.",
                                note.title(),
                                target_note.path
                            ),
                        ));
                    }
                    _ => {}
                }
            }
        }
    }

    // CHAD-IDENTITY-005: name collapse — a two-token person title whose
    // component tokens both exist as standalone person notes, without an
    // explicit alias/merge declaration.
    let person_titles: HashMap<String, &Note> = curated
        .iter()
        .filter(|n| matches!(n.type_str().as_deref(), Some("person") | Some("god")))
        .map(|n| (norm(n.title()), *n))
        .collect();
    for note in &curated {
        if !matches!(note.type_str().as_deref(), Some("person") | Some("god")) {
            continue;
        }
        let tokens: Vec<&str> = note.title().split_whitespace().collect();
        if tokens.len() != 2 {
            continue;
        }
        let fm = note.fm();
        if ALIAS_FIELDS.iter().any(|f| fm.has(f)) {
            continue;
        }
        let (a, b) = (norm(tokens[0]), norm(tokens[1]));
        if let (Some(first), Some(second)) = (person_titles.get(&a), person_titles.get(&b)) {
            out.push(finding(
                "CHAD-IDENTITY-005",
                ctx.sev("CHAD-IDENTITY-005", Severity::Warn),
                Some(&note.path),
                format!(
                    "identity `{}` looks like a collapse of distinct identities \
                     `{}` and `{}`. Declare an explicit `aliases` or `alias_of` \
                     field, or confirm the names are distinct.",
                    note.title(),
                    first.path,
                    second.path
                ),
            ));
        }
    }

    out
}

/// Resolve a title reference to a curated note.
fn resolve_title<'a>(ctx: &RuleContext<'a>, target: &str) -> Option<&'a Note> {
    let with_md = format!("{target}.md");
    for note in &ctx.index.notes {
        if !note.curated {
            continue;
        }
        if note.path == target || note.path == with_md {
            return Some(note);
        }
    }
    let target_norm = norm(target);
    ctx.index
        .notes
        .iter()
        .find(|n| n.curated && norm(n.title()) == target_norm)
}
