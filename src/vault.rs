//! Vault scanning: walks the vault, parses notes, classifies scope, and
//! hashes content for the revision fingerprint.
//!
//! Performance contract: curated notes are read fully (content-hashed);
//! evidence/archive notes are probed for their frontmatter head only and
//! fingerprinted by metadata, so a full run does not re-read hundreds of
//! megabytes of immutable collector data.

use std::collections::HashSet;
use std::io::Read;
use std::path::{Path, PathBuf};

use walkdir::WalkDir;
use yaml_rust2::Yaml;

use crate::boundary::fnv1a;
use crate::config::Config;
use crate::frontmatter::{parse, FmView};

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
/// Frontmatter probe size for evidence files; files whose frontmatter block
/// does not close within the probe are re-read fully.
const PROBE_BYTES: usize = 16 * 1024;

/// A single parsed Markdown note.
pub struct Note {
    /// Vault-relative path (forward slashes).
    pub path: String,
    pub frontmatter: Yaml,
    /// Body after the frontmatter fence. Retained only for curated notes.
    pub body: String,
    /// Stable FNV-1a content/metadata hash for the revision fingerprint.
    pub content_hash: u64,
    pub parse_error: Option<String>,
    pub has_frontmatter: bool,
    pub curated: bool,
}

impl Note {
    pub fn fm(&self) -> FmView<'_> {
        FmView::new(&self.frontmatter)
    }

    pub fn type_str(&self) -> Option<String> {
        self.fm().get_str("type")
    }

    pub fn status(&self) -> Option<String> {
        self.fm().get_str("status")
    }

    pub fn tier(&self) -> Option<String> {
        self.fm().get_str("retrieval_tier")
    }

    pub fn is_canonical(&self) -> bool {
        self.tier().as_deref() == Some("canonical")
    }

    pub fn is_runtime(&self) -> bool {
        self.tier().as_deref() == Some("runtime")
    }

    pub fn is_active(&self) -> bool {
        self.status().as_deref() == Some("active")
    }

    /// Note title: file stem.
    pub fn title(&self) -> &str {
        let stem = self.path.rsplit('/').next().unwrap_or(&self.path);
        stem.strip_suffix(".md").unwrap_or(stem)
    }

    /// True when the note declares an external review block, e.g.
    /// `review_state: blocked-external`, `blocked: external`, or a
    /// `freshness:` string beginning with `blocked-external`.
    pub fn is_blocked_external(&self) -> bool {
        let fm = self.fm();
        for key in ["review_state", "blocked", "review_blocked"] {
            if let Some(v) = fm.get_str(key) {
                let norm = v.trim().to_ascii_lowercase().replace('_', "-");
                if norm == "blocked-external" || norm == "external" {
                    return true;
                }
            }
        }
        if let Some(f) = fm.get_str("freshness") {
            if f.trim()
                .to_ascii_lowercase()
                .replace('_', "-")
                .starts_with("blocked-external")
            {
                return true;
            }
        }
        false
    }

    /// Headings (`# ...` at any depth) in the body, as trimmed text.
    pub fn headings(&self) -> Vec<String> {
        self.body
            .lines()
            .filter_map(|l| {
                let t = l.trim_start();
                let hashes = t.chars().take_while(|c| *c == '#').count();
                if hashes >= 1 && t.chars().nth(hashes) == Some(' ') {
                    Some(t[hashes..].trim().to_string())
                } else {
                    None
                }
            })
            .collect()
    }
}

/// Parsed vault: all notes plus scope classification.
pub struct VaultIndex {
    pub root: PathBuf,
    pub notes: Vec<Note>,
    /// Every scanned file (any extension, relative path), for link
    /// resolution against attachments as well as notes.
    pub all_files: HashSet<String>,
    /// (path, content_hash) for every scanned file, sorted by path. Drives
    /// the revision fingerprint.
    pub file_hashes: Vec<(String, u64)>,
}

impl VaultIndex {
    pub fn find_by_path(&self, path: &str) -> Option<&Note> {
        self.notes.iter().find(|n| n.path == path)
    }

    /// Deterministic fingerprint of the scanned vault state.
    pub fn fingerprint(&self) -> String {
        let mut h: u64 = FNV_OFFSET;
        for (path, hash) in &self.file_hashes {
            h = fnv1a(path.as_bytes(), h);
            h = fnv1a(b"\0", h);
            h = fnv1a(&hash.to_le_bytes(), h);
            h = fnv1a(b"\0", h);
        }
        format!("{h:016x}")
    }
}

fn is_excluded(rel: &Path, config: &Config) -> bool {
    rel.components().any(|c| {
        let s = c.as_os_str().to_string_lossy();
        config.exclude_dirs.iter().any(|e| e == &s)
    })
}

/// True when the relative path is the generated report or lives in the
/// generated report's directory (validator outputs must not be validated).
fn is_validator_output(rel: &Path, config: &Config) -> bool {
    let report = Path::new(&config.report_path);
    if rel == report {
        return true;
    }
    match report.parent() {
        Some(parent) if parent != Path::new("") => rel.starts_with(parent),
        _ => false,
    }
}

/// Curated scopes: everything except the evidence/archive tree and excluded
/// directories. `70 Sources/` is collector-owned evidence and is exempt from
/// schema/link/freshness checks (but still parsed for protected-path logic).
fn is_curated(rel: &Path) -> bool {
    !rel.starts_with(Path::new("70 Sources"))
}

fn metadata_hash(abs: &Path) -> u64 {
    match std::fs::metadata(abs) {
        Ok(m) => {
            let mut h = FNV_OFFSET;
            h = fnv1a(&m.len().to_le_bytes(), h);
            if let Ok(t) = m.modified() {
                if let Ok(d) = t.duration_since(std::time::UNIX_EPOCH) {
                    h = fnv1a(&d.as_secs().to_le_bytes(), h);
                    h = fnv1a(&d.subsec_nanos().to_le_bytes(), h);
                }
            }
            h
        }
        Err(_) => 0,
    }
}

/// Read the whole file and hash its content.
fn read_full(abs: &Path) -> Result<(String, u64), String> {
    let raw = std::fs::read_to_string(abs).map_err(|e| format!("read error: {e}"))?;
    let hash = fnv1a(raw.as_bytes(), FNV_OFFSET);
    Ok((raw, hash))
}

/// Evidence-tree probe: hash by metadata; read just enough to parse the
/// frontmatter (re-reading fully only when the block is unusually long).
fn read_probe(abs: &Path) -> Result<(String, u64), String> {
    let hash = metadata_hash(abs);
    let mut f = std::fs::File::open(abs).map_err(|e| format!("read error: {e}"))?;
    let mut buf = vec![0u8; PROBE_BYTES];
    let n = f.read(&mut buf).map_err(|e| format!("read error: {e}"))?;
    buf.truncate(n);
    let head = String::from_utf8_lossy(&buf).into_owned();
    // If it looks like frontmatter but the fence does not close in the
    // probe window, fall back to a full read so the parse is truthful.
    if head.starts_with("---") && !head[3..].contains("\n---") {
        let (raw, _) = read_full(abs)?;
        return Ok((raw, hash));
    }
    Ok((head, hash))
}

pub fn scan(vault_root: &Path, config: &Config) -> std::io::Result<VaultIndex> {
    let mut notes = Vec::new();
    let mut all_files = HashSet::new();
    let mut file_hashes: Vec<(String, u64)> = Vec::new();
    let mut entries: Vec<_> = WalkDir::new(vault_root)
        .into_iter()
        .filter_entry(|e| {
            if e.file_type().is_dir() {
                let name = e.file_name().to_string_lossy();
                return !config.exclude_dirs.iter().any(|x| x == &name);
            }
            true
        })
        .filter_map(|e| e.ok())
        .filter(|e| e.file_type().is_file())
        .collect();
    entries.sort_by_key(|e| e.path().to_path_buf());

    for entry in entries {
        let abs = entry.path();
        let rel = match abs.strip_prefix(vault_root) {
            Ok(r) => r.to_path_buf(),
            Err(_) => continue,
        };
        if is_excluded(&rel, config) || is_validator_output(&rel, config) {
            continue;
        }
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        let is_md = rel.extension().and_then(|e| e.to_str()) == Some("md");
        if !is_md {
            // Non-markdown (attachments, raw.html, document.json): metadata
            // fingerprint only.
            file_hashes.push((rel_str.clone(), metadata_hash(abs)));
            all_files.insert(rel_str);
            continue;
        }

        let curated = is_curated(&rel);
        let read_result = if curated { read_full(abs) } else { read_probe(abs) };
        match read_result {
            Ok((raw, hash)) => {
                file_hashes.push((rel_str.clone(), hash));
                all_files.insert(rel_str.clone());
                let fm = parse(&raw);
                notes.push(Note {
                    path: rel_str,
                    frontmatter: fm.value,
                    body: if curated { fm.body } else { String::new() },
                    content_hash: hash,
                    parse_error: fm.parse_error,
                    has_frontmatter: fm.has_block,
                    curated,
                });
            }
            Err(e) => {
                notes.push(Note {
                    path: rel_str,
                    frontmatter: Yaml::Null,
                    body: String::new(),
                    content_hash: 0,
                    parse_error: Some(e),
                    has_frontmatter: false,
                    curated,
                });
            }
        }
    }

    file_hashes.sort();
    Ok(VaultIndex {
        root: vault_root.to_path_buf(),
        notes,
        all_files,
        file_hashes,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_note(fm_text: &str, body: &str) -> Note {
        let fm = parse(&format!("---\n{fm_text}\n---\n{body}"));
        Note {
            path: "a.md".into(),
            frontmatter: fm.value,
            body: fm.body,
            content_hash: 0,
            parse_error: None,
            has_frontmatter: true,
            curated: true,
        }
    }

    #[test]
    fn headings_extracted() {
        let note = test_note("type: x", "# Title\n\n## Boundary\n\ntext\n### Sub\n");
        assert_eq!(note.headings(), vec!["Title", "Boundary", "Sub"]);
    }

    #[test]
    fn blocked_external_markers() {
        for marker in [
            "review_state: blocked-external",
            "blocked: external",
            "freshness: blocked-external-awaiting-collector",
        ] {
            assert!(test_note(marker, "").is_blocked_external(), "marker: {marker}");
        }
    }

    #[test]
    fn fingerprint_is_stable_and_order_independent() {
        // Same content in different scan order -> same fingerprint.
        let mut a = VaultIndex {
            root: PathBuf::new(),
            notes: Vec::new(),
            all_files: HashSet::new(),
            file_hashes: vec![
                ("a.md".to_string(), 1),
                ("b.md".to_string(), 2),
            ],
        };
        a.file_hashes.sort();
        let mut b = VaultIndex {
            root: PathBuf::new(),
            notes: Vec::new(),
            all_files: HashSet::new(),
            file_hashes: vec![
                ("b.md".to_string(), 2),
                ("a.md".to_string(), 1),
            ],
        };
        b.file_hashes.sort();
        assert_eq!(a.fingerprint(), b.fingerprint());
    }
}
