//! State boundary resolution.
//!
//! Precedence:
//! 1. The dedicated boundary file (`boundary_path`) — authoritative.
//! 2. Reconciliation manifests define `canonical_materialized_cursor`.
//! 3. Derivation from live runtime records (handoff / context pack /
//!    checkpoints) — emits WARN CHAD-STATE-001 because the vault is not
//!    exposing the machine-readable boundary the contract requires.
//!
//! `vault_revision` combines git HEAD (when available) with a fingerprint of
//! every scanned validation input. Generated reports and validator config are
//! tracked separately and cannot change the validated vault revision.

use std::path::Path;
use std::process::Command;

use crate::config::Config;
use crate::findings::{Finding, Severity};
use crate::frontmatter::FmView;
use crate::manifest::Manifest;
use crate::rules::finding;
use crate::vault::{Note, VaultIndex};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoundarySource {
    File(String),
    Derived,
}

#[derive(Debug, Clone)]
pub struct StateBoundary {
    pub current_turn: Option<i64>,
    pub current_year: Option<i64>,
    pub last_resolved_year: Option<i64>,
    pub current_source_cursor: Option<i64>,
    pub canonical_materialized_cursor: Option<i64>,
    pub vault_revision: String,
    pub source: BoundarySource,
}

const REQUIRED_KEYS: [&str; 5] = [
    "current_turn",
    "current_year",
    "last_resolved_year",
    "current_source_cursor",
    "canonical_materialized_cursor",
];

/// FNV-1a 64-bit — stable across builds, no dependency.
pub fn fnv1a(data: &[u8], seed: u64) -> u64 {
    let mut h: u64 = seed;
    for b in data {
        h ^= u64::from(*b);
        h = h.wrapping_mul(0x0000_0100_0000_01B3);
    }
    h
}

fn git_revision(vault_root: &Path) -> Option<String> {
    let out = Command::new("git")
        .args(["-C", &vault_root.to_string_lossy(), "rev-parse", "HEAD"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let sha = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if sha.is_empty() {
        return None;
    }
    Some(sha)
}

pub fn vault_revision(vault_root: &Path, index: &VaultIndex) -> String {
    match git_revision(vault_root) {
        Some(sha) => format!("git:{sha}+vault:{}", index.fingerprint()),
        None => format!("wt:{}", index.fingerprint()),
    }
}

/// Resolve the current-state boundary, collecting structural findings.
pub fn resolve(
    index: &VaultIndex,
    config: &Config,
    manifests: &[Manifest],
) -> (StateBoundary, Vec<Finding>) {
    let mut findings = Vec::new();
    let revision = vault_revision(&index.root, index);

    let boundary_note = index.find_by_path(&config.boundary_path);
    let mut b = match boundary_note {
        Some(note) if note.parse_error.is_none() => {
            let fm = note.fm();
            let mut missing = Vec::new();
            for key in REQUIRED_KEYS {
                if fm.get_i64(key).is_none() {
                    missing.push(key);
                }
            }
            for key in &missing {
                findings.push(finding(
                    "CHAD-STATE-003",
                    config.severity_for("CHAD-STATE-003", Severity::Error),
                    Some(&config.boundary_path),
                    format!(
                        "state boundary is missing required key `{key}`. Add it \
                         to the frontmatter of `{}`.",
                        config.boundary_path
                    ),
                ));
            }
            StateBoundary {
                current_turn: fm.get_i64("current_turn"),
                current_year: fm.get_i64("current_year"),
                last_resolved_year: fm.get_i64("last_resolved_year"),
                current_source_cursor: fm.get_i64("current_source_cursor"),
                canonical_materialized_cursor: fm.get_i64("canonical_materialized_cursor"),
                vault_revision: revision.clone(),
                source: BoundarySource::File(config.boundary_path.clone()),
            }
        }
        Some(note) => {
            findings.push(finding(
                "CHAD-SCHEMA-001",
                config.severity_for("CHAD-SCHEMA-001", Severity::Error),
                Some(&config.boundary_path),
                format!(
                    "state boundary file does not parse: {}. Fix the YAML \
                     frontmatter.",
                    note.parse_error.clone().unwrap_or_default()
                ),
            ));
            derive(index, config, manifests, &revision, &mut findings)
        }
        None => derive(index, config, manifests, &revision, &mut findings),
    };

    // Internal consistency of the boundary itself.
    if let (Some(resolved), Some(current)) = (b.last_resolved_year, b.current_year) {
        if resolved > current {
            findings.push(finding(
                "CHAD-STATE-004",
                config.severity_for("CHAD-STATE-004", Severity::Error),
                None,
                format!(
                    "boundary is inconsistent: last_resolved_year {resolved} \
                     exceeds current_year {current}. Ensure \
                     last_resolved_year <= current_year."
                ),
            ));
        }
    }
    if let (Some(mat), Some(src)) = (b.canonical_materialized_cursor, b.current_source_cursor) {
        if mat > src {
            findings.push(finding(
                "CHAD-STATE-004",
                config.severity_for("CHAD-STATE-004", Severity::Error),
                None,
                format!(
                    "boundary is inconsistent: canonical_materialized_cursor {mat} \
                     exceeds current_source_cursor {src}. Ensure \
                     canonical_materialized_cursor <= current_source_cursor."
                ),
            ));
        }
    }
    if let BoundarySource::File(_) = b.source {
        // nothing extra
    } else if b.canonical_materialized_cursor.is_none() {
        findings.push(finding(
            "CHAD-STATE-002",
            config.severity_for("CHAD-STATE-002", Severity::Warn),
            None,
            "canonical_materialized_cursor is not declared anywhere: no \
             reconciliation manifest and no runtime handoff cursor; freshness \
             and manifest coverage rules cannot be fully evaluated. Create a \
             reconciliation manifest or add the cursor to the state boundary."
                .to_string(),
        ));
    }

    findings
        .sort_by(|a, b| (a.severity, a.priority, a.rule).cmp(&(b.severity, b.priority, b.rule)));
    b.vault_revision = revision;
    (b, findings)
}

fn derive(
    index: &VaultIndex,
    config: &Config,
    manifests: &[Manifest],
    revision: &str,
    findings: &mut Vec<Finding>,
) -> StateBoundary {
    findings.push(finding(
        "CHAD-STATE-001",
        config.severity_for("CHAD-STATE-001", Severity::Warn),
        None,
        format!(
            "no machine-readable state boundary at `{}`; deriving from live \
             runtime records. Create `{}` with the required keys to make the \
             claimed contract explicit.",
            config.boundary_path, config.boundary_path
        ),
    ));

    let runtime: Vec<&Note> = index.notes.iter().filter(|n| n.is_runtime()).collect();
    let get = |n: &Note, k: &str| FmView::new(&n.frontmatter).get_i64(k);

    let current_turn = runtime.iter().filter_map(|n| get(n, "turn")).max();
    let current_year = runtime.iter().filter_map(|n| get(n, "year")).max();
    let current_source_cursor = runtime.iter().filter_map(|n| get(n, "source_cursor")).max();
    let last_resolved_year = runtime
        .iter()
        .filter_map(|n| get(n, "last_resolved_year"))
        .max();

    let from_manifest = manifests.iter().filter_map(|m| m.materialized_cursor).max();
    let from_handoff = index
        .notes
        .iter()
        .filter(|n| n.type_str().as_deref() == Some("runtime-handoff"))
        .max_by_key(|n| get(n, "turn").unwrap_or(0))
        .and_then(|n| get(n, "source_cursor"));
    let canonical_materialized_cursor = from_manifest.or(from_handoff);

    StateBoundary {
        current_turn,
        current_year,
        last_resolved_year,
        current_source_cursor,
        canonical_materialized_cursor,
        vault_revision: revision.to_string(),
        source: BoundarySource::Derived,
    }
}

/// Classification of a cursor value relative to the State Boundary and
/// the indexed direct-source frontier. This is the single source of truth
/// for boundary diagnosis — all rules and renderers should use this
/// instead of duplicating cursor-vs-boundary comparisons.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BoundaryDiagnosis {
    /// Cursor is at or within the State Boundary.
    WithinBoundary,
    /// Cursor exceeds the State Boundary but is within the indexed
    /// direct-source frontier. The State Boundary may be stale.
    BoundaryTrailsCollectedEvidence,
    /// Cursor exceeds both the State Boundary and the direct-source
    /// frontier. The record's evidence is unsupported.
    BeyondCollectedEvidence,
    /// Boundary or frontier is unknown; cannot classify.
    Unknown,
}

impl BoundaryDiagnosis {
    /// Returns true if the cursor is ahead of the State Boundary but
    /// still within collected evidence (boundary may be stale).
    pub fn boundary_may_be_stale(self) -> bool {
        matches!(self, BoundaryDiagnosis::BoundaryTrailsCollectedEvidence)
    }

    /// Returns true if the cursor genuinely exceeds collected evidence.
    pub fn beyond_evidence(self) -> bool {
        matches!(self, BoundaryDiagnosis::BeyondCollectedEvidence)
    }
}

/// Classify a cursor value relative to the State Boundary and the
/// indexed direct-source frontier.
///
/// - `cursor`: the value being diagnosed
/// - `boundary_cursor`: `StateBoundary.current_source_cursor`
/// - `direct_frontier`: `SourceIndex.max_source_cursor`
pub fn diagnose_cursor(
    cursor: i64,
    boundary_cursor: Option<i64>,
    direct_frontier: Option<i64>,
) -> BoundaryDiagnosis {
    match (boundary_cursor, direct_frontier) {
        (Some(bc), Some(df)) => {
            // A frontier that predates the State Boundary is internally
            // inconsistent. Do not let either value manufacture a safe
            // classification until that discrepancy is resolved.
            if df < bc {
                BoundaryDiagnosis::Unknown
            } else if cursor <= bc {
                BoundaryDiagnosis::WithinBoundary
            } else if cursor <= df {
                BoundaryDiagnosis::BoundaryTrailsCollectedEvidence
            } else {
                BoundaryDiagnosis::BeyondCollectedEvidence
            }
        }
        (Some(bc), None) => {
            if cursor <= bc {
                BoundaryDiagnosis::WithinBoundary
            } else {
                BoundaryDiagnosis::Unknown
            }
        }
        // A direct-source frontier cannot substitute for a missing State
        // Boundary: the relationship being diagnosed is unknown.
        (None, Some(_)) => BoundaryDiagnosis::Unknown,
        (None, None) => BoundaryDiagnosis::Unknown,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceFrontierRelationship {
    BoundaryTrailsCollectedEvidence,
    Equal,
    BoundaryAheadOfCollectedEvidence,
    BoundaryMissing,
    DirectFrontierUnknown,
    Unknown,
}

pub fn diagnose_source_frontiers(
    boundary_cursor: Option<i64>,
    direct_frontier: Option<i64>,
) -> SourceFrontierRelationship {
    match (boundary_cursor, direct_frontier) {
        (Some(boundary), Some(frontier)) if boundary < frontier => {
            SourceFrontierRelationship::BoundaryTrailsCollectedEvidence
        }
        (Some(boundary), Some(frontier)) if boundary > frontier => {
            SourceFrontierRelationship::BoundaryAheadOfCollectedEvidence
        }
        (Some(_), Some(_)) => SourceFrontierRelationship::Equal,
        (None, Some(_)) => SourceFrontierRelationship::BoundaryMissing,
        (Some(_), None) => SourceFrontierRelationship::DirectFrontierUnknown,
        (None, None) => SourceFrontierRelationship::Unknown,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv_is_deterministic() {
        assert_eq!(fnv1a(b"hello", 0xcbf29ce484222325), 0xa430d84680aabd0b);
    }

    #[test]
    fn diagnose_cursor_within_boundary() {
        assert_eq!(
            diagnose_cursor(100, Some(200), Some(300)),
            BoundaryDiagnosis::WithinBoundary
        );
    }

    #[test]
    fn diagnose_cursor_boundary_trails() {
        assert_eq!(
            diagnose_cursor(250, Some(200), Some(300)),
            BoundaryDiagnosis::BoundaryTrailsCollectedEvidence
        );
    }

    #[test]
    fn diagnose_cursor_beyond_evidence() {
        assert_eq!(
            diagnose_cursor(350, Some(200), Some(300)),
            BoundaryDiagnosis::BeyondCollectedEvidence
        );
    }

    #[test]
    fn diagnose_cursor_missing_boundary_is_unknown() {
        assert_eq!(
            diagnose_cursor(100, None, Some(300)),
            BoundaryDiagnosis::Unknown
        );
    }

    #[test]
    fn diagnose_cursor_unknown_frontier() {
        assert_eq!(
            diagnose_cursor(100, Some(200), None),
            BoundaryDiagnosis::WithinBoundary
        );
        assert_eq!(
            diagnose_cursor(250, Some(200), None),
            BoundaryDiagnosis::Unknown
        );
    }

    #[test]
    fn diagnose_cursor_both_unknown() {
        assert_eq!(diagnose_cursor(100, None, None), BoundaryDiagnosis::Unknown);
    }

    #[test]
    fn diagnose_cursor_inconsistent_frontier_is_unknown() {
        assert_eq!(
            diagnose_cursor(100, Some(200), Some(150)),
            BoundaryDiagnosis::Unknown
        );
    }

    #[test]
    fn source_frontier_relationship_is_shared_and_typed() {
        assert_eq!(
            diagnose_source_frontiers(Some(4664), Some(4741)),
            SourceFrontierRelationship::BoundaryTrailsCollectedEvidence
        );
        assert_eq!(
            diagnose_source_frontiers(Some(4741), Some(4741)),
            SourceFrontierRelationship::Equal
        );
    }
}
