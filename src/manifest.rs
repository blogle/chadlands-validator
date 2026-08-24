//! Reconciliation manifests: machine-readable coverage records emitted by
//! every reconciliation that advances `canonical_materialized_cursor`.
//!
//! Expected shape:
//!
//! ```yaml
//! type: reconciliation-manifest
//! manifest_id: reconcile-2026-08-16
//! canonical_materialized_cursor: 2856
//! source_cursor: 2856
//! subjects:
//!   - path: 30 World/People/Tovan Dorn.md
//!     disposition: UPDATED
//!   - path: 40 Civilization/Institutions/Annual Reckoning.md
//!     disposition: REVIEWED — NO MATERIAL CHANGE
//!   - path: 30 World/Places/Skarn.md
//!     disposition: BLOCKED — EXTERNAL
//!     reason: collector has not delivered the raw packet
//! ```

use std::collections::HashSet;

use yaml_rust2::Yaml;

use crate::findings::{Finding, Severity};
use crate::config::Config;
use crate::rules::finding;
use crate::vault::{Note, VaultIndex};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Disposition {
    Updated,
    ReviewedNoChange,
    BlockedExternal,
    Invalid(String),
}

impl Disposition {
    /// Normalize dash variants (—, –, -) and whitespace/case, then match.
    pub fn parse(raw: &str) -> Disposition {
        let norm: String = raw
            .chars()
            .map(|c| match c {
                '\u{2014}' | '\u{2013}' => '-',
                _ => c,
            })
            .collect::<String>()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ")
            .to_ascii_uppercase();
        match norm.as_str() {
            "UPDATED" => Disposition::Updated,
            "REVIEWED - NO MATERIAL CHANGE" => Disposition::ReviewedNoChange,
            "BLOCKED - EXTERNAL" => Disposition::BlockedExternal,
            _ => Disposition::Invalid(raw.to_string()),
        }
    }

    pub fn label(&self) -> &str {
        match self {
            Disposition::Updated => "UPDATED",
            Disposition::ReviewedNoChange => "REVIEWED — NO MATERIAL CHANGE",
            Disposition::BlockedExternal => "BLOCKED — EXTERNAL",
            Disposition::Invalid(_) => "<invalid>",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ManifestSubject {
    pub path: String,
    pub disposition: Disposition,
    pub reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Manifest {
    pub path: String,
    pub id: Option<String>,
    pub materialized_cursor: Option<i64>,
    pub source_cursor: Option<i64>,
    pub subjects: Vec<ManifestSubject>,
}

impl Manifest {
    fn from_note(note: &Note) -> Manifest {
        let fm = note.fm();
        let mut subjects = Vec::new();
        if let Yaml::Array(items) = &note.frontmatter["subjects"] {
            for item in items {
                let path = item["path"].as_str().unwrap_or_default().to_string();
                let disposition = item["disposition"]
                    .as_str()
                    .map(Disposition::parse)
                    .unwrap_or_else(|| Disposition::Invalid("<missing>".to_string()));
                let reason = item["reason"].as_str().map(String::from);
                subjects.push(ManifestSubject {
                    path,
                    disposition,
                    reason,
                });
            }
        }
        Manifest {
            path: note.path.clone(),
            id: fm.get_str("manifest_id"),
            materialized_cursor: fm.get_i64("canonical_materialized_cursor"),
            source_cursor: fm.get_i64("source_cursor"),
            subjects,
        }
    }
}

pub fn collect(index: &VaultIndex) -> Vec<Manifest> {
    index
        .notes
        .iter()
        .filter(|n| n.type_str().as_deref() == Some("reconciliation-manifest"))
        .map(Manifest::from_note)
        .collect()
}

/// The manifest that currently defines the materialization frontier.
pub fn latest(manifests: &[Manifest]) -> Option<&Manifest> {
    manifests
        .iter()
        .filter(|m| m.materialized_cursor.is_some())
        .max_by_key(|m| m.materialized_cursor.unwrap())
}

/// Per-manifest structural checks (vocabulary, reasons, duplicates,
/// resolvable subject paths, cursor sanity).
pub fn check_manifests(
    manifests: &[Manifest],
    index: &VaultIndex,
    current_source_cursor: Option<i64>,
    config: &Config,
) -> Vec<Finding> {
    let mut out = Vec::new();
    for m in manifests {
        let mut seen: HashSet<&str> = HashSet::new();
        for s in &m.subjects {
            if !seen.insert(s.path.as_str()) {
                out.push(finding(
                    "CHAD-CURSOR-006",
                    config.severity_for("CHAD-CURSOR-006", Severity::Error),
                    Some(&m.path),
                    format!(
                        "subject `{}` appears more than once in the manifest. \
                         Remove the duplicate entry.",
                        s.path
                    ),
                ));
            }
            if let Disposition::Invalid(raw) = &s.disposition {
                out.push(finding(
                    "CHAD-CURSOR-006",
                    config.severity_for("CHAD-CURSOR-006", Severity::Error),
                    Some(&m.path),
                    format!(
                        "subject `{}` has invalid disposition `{raw}`. Expected \
                         exactly one of: UPDATED, REVIEWED — NO MATERIAL CHANGE, \
                         BLOCKED — EXTERNAL.",
                        s.path
                    ),
                ));
            }
            if s.disposition == Disposition::BlockedExternal
                && s.reason.as_deref().map(str::trim).unwrap_or("").is_empty()
            {
                out.push(finding(
                    "CHAD-CURSOR-007",
                    config.severity_for("CHAD-CURSOR-007", Severity::Error),
                    Some(&m.path),
                    format!(
                        "subject `{}` is BLOCKED — EXTERNAL without an explicit \
                         reason. Add a `reason` field to the subject.",
                        s.path
                    ),
                ));
            }
            if !s.path.is_empty() && index.find_by_path(&s.path).is_none() {
                out.push(finding(
                    "CHAD-CURSOR-009",
                    config.severity_for("CHAD-CURSOR-009", Severity::Error),
                    Some(&m.path),
                    format!(
                        "subject path `{}` does not resolve to a vault note. \
                         Correct the path to match an existing note.",
                        s.path
                    ),
                ));
            }
            if s.path.is_empty() {
                out.push(finding(
                    "CHAD-CURSOR-006",
                    config.severity_for("CHAD-CURSOR-006", Severity::Error),
                    Some(&m.path),
                    "manifest subject is missing its `path`. Add a `path` field."
                        .to_string(),
                ));
            }
        }
        if m.materialized_cursor.is_none() {
            out.push(finding(
                "CHAD-CURSOR-006",
                config.severity_for("CHAD-CURSOR-006", Severity::Error),
                Some(&m.path),
                "reconciliation manifest has no `canonical_materialized_cursor`. \
                 Add it to the manifest frontmatter."
                    .to_string(),
            ));
        }
        if let (Some(mc), Some(csc)) = (m.materialized_cursor, current_source_cursor) {
            if mc > csc {
                out.push(finding(
                    "CHAD-CURSOR-008",
                    config.severity_for("CHAD-CURSOR-008", Severity::Error),
                    Some(&m.path),
                    format!(
                        "manifest materialized cursor {mc} exceeds the evidence \
                         the vault actually holds (current_source_cursor {csc}). \
                         Lower the manifest cursor to not exceed the evidence frontier."
                    ),
                ));
            }
        }
        if let (Some(mc), Some(sc)) = (m.materialized_cursor, m.source_cursor) {
            if mc > sc {
                out.push(finding(
                    "CHAD-CURSOR-008",
                    config.severity_for("CHAD-CURSOR-008", Severity::Error),
                    Some(&m.path),
                    format!(
                        "manifest materialized cursor {mc} exceeds its own covered \
                         evidence cursor {sc}. Ensure materialized_cursor <= source_cursor."
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
    fn disposition_parsing_normalizes_dashes() {
        assert_eq!(Disposition::parse("UPDATED"), Disposition::Updated);
        assert_eq!(
            Disposition::parse("REVIEWED — NO MATERIAL CHANGE"),
            Disposition::ReviewedNoChange
        );
        assert_eq!(
            Disposition::parse("reviewed - no material change"),
            Disposition::ReviewedNoChange
        );
        assert_eq!(
            Disposition::parse("BLOCKED – EXTERNAL"),
            Disposition::BlockedExternal
        );
        assert!(matches!(
            Disposition::parse("SKIPPED"),
            Disposition::Invalid(_)
        ));
    }
}
