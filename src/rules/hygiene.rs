//! Additional cheap checks: parseability, required common fields, status
//! vocabularies, lifecycle date ordering, workflow uniqueness, required
//! sections, broken links in curated scopes, resolvable references, and
//! protected collector paths.

use std::collections::{HashMap, HashSet};

use crate::findings::{Finding, Severity};
use crate::rules::{finding, RuleContext};
use crate::vault::Note;

/// Ordered lifecycle year pairs: left must not exceed right.
const YEAR_ORDER_PAIRS: [(&str, &str); 3] = [
    ("first_known_year", "last_confirmed_year"),
    ("accepted_year", "completed_year"),
    ("birth_year", "first_known_year"),
];

const REF_FIELDS: [&str; 6] = [
    "owner",
    "lead",
    "second",
    "authoritative_owner",
    "parent",
    "supersedes",
];

pub fn check(ctx: &RuleContext) -> Vec<Finding> {
    let mut out = Vec::new();
    check_parse(ctx, &mut out);
    check_common_fields(ctx, &mut out);
    check_status_vocab(ctx, &mut out);
    check_year_ordering(ctx, &mut out);
    check_required_sections(ctx, &mut out);
    check_workflows(ctx, &mut out);
    check_links(ctx, &mut out);
    check_refs(ctx, &mut out);
    out
}

fn check_parse(ctx: &RuleContext, out: &mut Vec<Finding>) {
    for note in &ctx.index.notes {
        if let Some(err) = &note.parse_error {
            let sev = if note.curated {
                ctx.sev("CHAD-SCHEMA-001", Severity::Error)
            } else {
                ctx.sev("CHAD-SCHEMA-001", Severity::Info)
            };
            out.push(finding(
                "CHAD-SCHEMA-001",
                sev,
                Some(&note.path),
                format!(
                    "frontmatter is not parseable: {err}. Add valid YAML \
                     frontmatter between `---` fences."
                ),
            ));
        } else if note.curated && !note.has_frontmatter {
            out.push(finding(
                "CHAD-SCHEMA-001",
                ctx.sev("CHAD-SCHEMA-001", Severity::Error),
                Some(&note.path),
                "curated note has no YAML frontmatter block. Add `---` fences \
                 with at least `type` and `status`."
                    .to_string(),
            ));
        }
    }
}

fn check_common_fields(ctx: &RuleContext, out: &mut Vec<Finding>) {
    for note in &ctx.index.notes {
        if !note.curated || note.parse_error.is_some() {
            continue;
        }
        for field in ["type", "status"] {
            if !note.fm().has(field) {
                out.push(finding(
                    "CHAD-SCHEMA-002",
                    ctx.sev("CHAD-SCHEMA-002", Severity::Error),
                    Some(&note.path),
                    format!(
                        "curated note is missing required common field `{field}`. \
                         Add `{field}` to the frontmatter."
                    ),
                ));
            }
        }
        if !note.fm().has("retrieval_tier") {
            out.push(finding(
                "CHAD-SCHEMA-002",
                ctx.sev("CHAD-SCHEMA-002", Severity::Warn),
                Some(&note.path),
                "curated note is missing `retrieval_tier`. Valid values: \
                 runtime, canonical, evidence, archive, workflow."
                    .to_string(),
            ));
        }
        match note.tier().as_deref() {
            Some("runtime") if !note.fm().has("knowledge_scope") => out.push(finding(
                "CHAD-SCHEMA-002",
                ctx.sev("CHAD-SCHEMA-002", Severity::Error),
                Some(&note.path),
                "runtime record is missing `knowledge_scope`. Valid values: \
                 player-only, gigachad, chadlands-leadership, chadlands, \
                 coalition, public, unknown."
                    .to_string(),
            )),
            Some("workflow") if !note.fm().has("knowledge_scope") => out.push(finding(
                "CHAD-SCHEMA-002",
                ctx.sev("CHAD-SCHEMA-002", Severity::Warn),
                Some(&note.path),
                "workflow record is missing `knowledge_scope`. Valid values: \
                 player-only, gigachad, chadlands-leadership, chadlands, \
                 coalition, public, unknown."
                    .to_string(),
            )),
            _ => {}
        }
    }
}

fn check_status_vocab(ctx: &RuleContext, out: &mut Vec<Finding>) {
    for note in &ctx.index.notes {
        if !note.curated || note.parse_error.is_some() {
            continue;
        }
        let (Some(type_name), Some(status)) = (note.type_str(), note.status()) else {
            continue;
        };
        let Some(class) = ctx.config.type_to_vocab_class.get(&type_name) else {
            continue;
        };
        let Some(vocab) = ctx.config.status_vocab.get(class) else {
            continue;
        };
        if !vocab.iter().any(|v| v == &status) {
            out.push(finding(
                "CHAD-SCHEMA-003",
                ctx.sev("CHAD-SCHEMA-003", Severity::Warn),
                Some(&note.path),
                format!(
                    "status `{status}` is outside the bounded vocabulary for \
                     {type_name} ({class}). Valid values: {}. Set `status` to \
                     one of these, or add the type to type_to_vocab_class in \
                     the validator config.",
                    vocab.join(", ")
                ),
            ));
        }
    }
}

fn check_year_ordering(ctx: &RuleContext, out: &mut Vec<Finding>) {
    for note in &ctx.index.notes {
        if !note.curated || note.parse_error.is_some() {
            continue;
        }
        let fm = note.fm();
        for (a, b) in YEAR_ORDER_PAIRS {
            if let (Some(va), Some(vb)) = (fm.get_i64(a), fm.get_i64(b)) {
                if va > vb {
                    out.push(finding(
                        "CHAD-SCHEMA-004",
                        ctx.sev("CHAD-SCHEMA-004", Severity::Error),
                        Some(&note.path),
                        format!(
                            "lifecycle date ordering violated: `{a}: {va}` is after \
                             `{b}: {vb}`. Earlier dates must not exceed later dates."
                        ),
                    ));
                }
            }
        }
    }
}

fn check_required_sections(ctx: &RuleContext, out: &mut Vec<Finding>) {
    for note in &ctx.index.notes {
        if !note.curated || note.parse_error.is_some() {
            continue;
        }
        let Some(type_name) = note.type_str() else {
            continue;
        };
        let Some(required) = ctx.config.required_sections.get(&type_name) else {
            continue;
        };
        let headings: HashSet<String> = note.headings().into_iter().collect();
        for section in required {
            if !headings.contains(section) {
                out.push(finding(
                    "CHAD-SCHEMA-005",
                    ctx.sev("CHAD-SCHEMA-005", Severity::Warn),
                    Some(&note.path),
                    format!(
                        "{type_name} record is missing required section \
                         `## {section}`. Add the section to the note body."
                    ),
                ));
            }
        }
    }
}

fn check_workflows(ctx: &RuleContext, out: &mut Vec<Finding>) {
    let mut by_id: HashMap<String, Vec<&Note>> = HashMap::new();
    for note in &ctx.index.notes {
        if !note.curated || note.parse_error.is_some() {
            continue;
        }
        if let Some(id) = note.fm().get_str("workflow_id") {
            by_id.entry(id).or_default().push(note);
        }
    }
    for (id, notes) in by_id {
        let active: Vec<&&Note> = notes.iter().filter(|n| n.is_active()).collect();
        if active.len() > 1 {
            let paths: Vec<&str> = active.iter().map(|n| n.path.as_str()).collect();
            out.push(finding(
                "CHAD-WORK-001",
                ctx.sev("CHAD-WORK-001", Severity::Error),
                Some(&active[0].path),
                format!(
                    "workflow `{id}` has {} active definitions: {}. Only one \
                     workflow per workflow_id may be active. Deactivate the \
                     superseded definition.",
                    active.len(),
                    paths.join(", ")
                ),
            ));
        }
    }
}

// ---------------------------------------------------------------------------
// Links
// ---------------------------------------------------------------------------

fn strip_code_fences(body: &str) -> String {
    let mut out = String::with_capacity(body.len());
    let mut in_fence = false;
    for line in body.lines() {
        let t = line.trim_start();
        if t.starts_with("```") || t.starts_with("~~~") {
            in_fence = !in_fence;
            continue;
        }
        if !in_fence {
            out.push_str(line);
            out.push('\n');
        }
    }
    out
}

fn extract_wikilinks(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = body.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b'[' && bytes[i + 1] == b'[' {
            if let Some(end) = body[i + 2..].find("]]") {
                let inner = &body[i + 2..i + 2 + end];
                let target = inner
                    .split('|')
                    .next()
                    .unwrap_or("")
                    .split('#')
                    .next()
                    .unwrap_or("")
                    .trim();
                if !target.is_empty() {
                    out.push(target.to_string());
                }
                i += 2 + end + 2;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn extract_md_links(body: &str) -> Vec<String> {
    let mut out = Vec::new();
    let bytes = body.as_bytes();
    let mut i = 0;
    while i + 1 < bytes.len() {
        if bytes[i] == b']' && bytes[i + 1] == b'(' {
            if let Some(end) = body[i + 2..].find(')') {
                let inner = body[i + 2..i + 2 + end].trim();
                let target = inner.split_whitespace().next().unwrap_or("");
                let target = target.split('#').next().unwrap_or("").trim();
                if !target.is_empty()
                    && !target.starts_with("http://")
                    && !target.starts_with("https://")
                    && !target.starts_with("mailto:")
                    && !target.starts_with("obsidian://")
                {
                    out.push(target.replace("%20", " "));
                }
                i += 2 + end + 1;
                continue;
            }
        }
        i += 1;
    }
    out
}

fn resolve_link(
    ctx: &RuleContext,
    source: &Note,
    target: &str,
    basename_index: &HashMap<String, Vec<String>>,
) -> bool {
    let candidates: Vec<String> = if target.ends_with(".md") {
        vec![target.to_string()]
    } else {
        vec![format!("{target}.md"), target.to_string()]
    };
    for c in &candidates {
        if ctx.index.all_files.contains(c) {
            return true;
        }
    }
    if let Some(dir) = source.path.rsplit_once('/') {
        for c in &candidates {
            let joined = format!("{}/{c}", dir.0);
            if ctx.index.all_files.contains(&joined) {
                return true;
            }
            let mut stack: Vec<&str> = Vec::new();
            for part in joined.split('/') {
                match part {
                    ".." => {
                        stack.pop();
                    }
                    "." => {}
                    seg => stack.push(seg),
                }
            }
            let normalized = stack.join("/");
            if ctx.index.all_files.contains(&normalized) {
                return true;
            }
        }
    }
    let stem = target
        .rsplit('/')
        .next()
        .unwrap_or(target)
        .trim_end_matches(".md");
    if let Some(paths) = basename_index.get(stem) {
        if !paths.is_empty() {
            return true;
        }
    }
    false
}

fn check_links(ctx: &RuleContext, out: &mut Vec<Finding>) {
    let mut basename_index: HashMap<String, Vec<String>> = HashMap::new();
    for path in &ctx.index.all_files {
        let stem = path
            .rsplit('/')
            .next()
            .unwrap_or(path)
            .trim_end_matches(".md")
            .to_string();
        basename_index.entry(stem).or_default().push(path.clone());
    }

    for note in &ctx.index.notes {
        if !note.curated || note.parse_error.is_some() {
            continue;
        }
        let body = strip_code_fences(&note.body);
        let mut targets = extract_wikilinks(&body);
        targets.extend(extract_md_links(&body));
        targets.sort();
        targets.dedup();
        for target in targets {
            if !resolve_link(ctx, note, &target, &basename_index) {
                out.push(finding(
                    "CHAD-LINK-001",
                    ctx.sev("CHAD-LINK-001", Severity::Warn),
                    Some(&note.path),
                    format!(
                        "broken link target `{target}` in curated scope. \
                         Fix the link to match an existing note path, or \
                         remove the dead link."
                    ),
                ));
            }
        }
    }
}

fn check_refs(ctx: &RuleContext, out: &mut Vec<Finding>) {
    let mut titles: HashSet<String> = HashSet::new();
    for note in &ctx.index.notes {
        if note.curated {
            titles.insert(
                note.title()
                    .split_whitespace()
                    .collect::<Vec<_>>()
                    .join(" ")
                    .to_ascii_lowercase(),
            );
        }
    }
    for note in &ctx.index.notes {
        if !note.curated || note.parse_error.is_some() {
            continue;
        }
        let fm = note.fm();
        for field in REF_FIELDS {
            let Some(value) = fm.get_str(field) else {
                continue;
            };
            let v = value.trim();
            if v.is_empty()
                || ctx
                    .config
                    .unresolved_values
                    .iter()
                    .any(|u| u.eq_ignore_ascii_case(v))
            {
                continue;
            }
            if v.starts_with("[[") && v.ends_with("]]") {
                continue;
            }
            let tokens: Vec<&str> = v.split_whitespace().collect();
            let name_shaped = !tokens.is_empty()
                && tokens.len() <= 3
                && tokens
                    .iter()
                    .all(|t| t.chars().all(|c| c.is_alphabetic() || c == '-' || c == '\''));
            if !name_shaped {
                continue;
            }
            let norm = tokens.join(" ").to_ascii_lowercase();
            if !titles.contains(&norm) {
                out.push(finding(
                    "CHAD-REF-001",
                    ctx.sev("CHAD-REF-001", Severity::Warn),
                    Some(&note.path),
                    format!(
                        "`{field}: {v}` does not resolve to any curated note \
                         title. Correct the reference or create the referenced note."
                    ),
                ));
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Protected paths
// ---------------------------------------------------------------------------

pub fn check_protected_paths(
    changed_files: &[String],
    config: &crate::config::Config,
    severity: Severity,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for f in changed_files {
        let f = f.trim_start_matches("./");
        for prefix in &config.protected_prefixes {
            if f.starts_with(prefix.as_str()) {
                out.push(finding(
                    "CHAD-PROT-001",
                    config.severity_for("CHAD-PROT-001", severity),
                    Some(f),
                    format!(
                        "protected collector/source path `{f}` (under `{prefix}/`) \
                         was modified. Chadlands workflows may not write to \
                         collector-owned evidence. Revert the change."
                    ),
                ));
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wikilink_extraction() {
        let body = "See [[20 Chronicle/Year 28|Year 28]] and [[Sella#Orientation]]. \
                    Also [[00 System/Record Model]].";
        let links = extract_wikilinks(body);
        assert_eq!(
            links,
            vec![
                "20 Chronicle/Year 28".to_string(),
                "Sella".to_string(),
                "00 System/Record Model".to_string()
            ]
        );
    }

    #[test]
    fn md_link_extraction_skips_external() {
        let body = "[x](https://example.com) [y](../Foo.md#Anchor) [z](#local)";
        let links = extract_md_links(body);
        assert_eq!(links, vec!["../Foo.md".to_string()]);
    }

    #[test]
    fn code_fences_are_ignored() {
        let body = "[[Real Link]]\n```\n[[Example Placeholder]]\n```\n";
        let stripped = strip_code_fences(body);
        assert!(extract_wikilinks(&stripped) == vec!["Real Link".to_string()]);
    }
}
