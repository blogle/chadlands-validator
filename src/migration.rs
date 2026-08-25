//! Frontmatter migration subsystem.
//!
//! Separate from normal validation. Provides `--plan` (dry-run) and `--apply`
//! modes for deterministic frontmatter cleanup. Only mechanically provable
//! transformations are applied automatically.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use yaml_rust2::Yaml;

use crate::config::Config;
use crate::frontmatter::parse;
use crate::vault::VaultIndex;

/// Classification of a frontmatter field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FieldClassification {
    /// Semantic state that must remain canonical.
    CanonicalSemantic,
    /// Can be derived deterministically by the validator.
    GeneratedDerived,
    /// Exact duplicate of another field.
    RedundantExact,
    /// Derivable from path but consumed by downstream tools.
    PathDerivableButConsumed,
    /// Legacy compatibility — keep until convergence.
    LegacyCompatibility,
    /// Unknown — default action is KEEP.
    Unknown,
}

/// A single migration rule.
#[derive(Debug, Clone)]
pub struct MigrationRule {
    pub id: String,
    pub description: String,
    pub field: String,
    pub classification: FieldClassification,
    pub action: MigrationAction,
}

#[derive(Debug, Clone)]
pub enum MigrationAction {
    /// Remove the field from frontmatter.
    Remove,
    /// Rename the field.
    Rename(String),
    /// Transform the value.
    Transform(fn(&str) -> Option<String>),
}

/// Result of a migration plan for a single file.
#[derive(Debug, Clone)]
pub struct MigrationFileResult {
    pub path: String,
    pub changes: Vec<MigrationChange>,
    pub skipped: bool,
    pub skip_reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct MigrationChange {
    pub rule_id: String,
    pub field: String,
    pub old_value: Option<String>,
    pub new_value: Option<String>,
}

/// The complete migration plan.
#[derive(Debug)]
pub struct MigrationPlan {
    pub files: Vec<MigrationFileResult>,
    pub total_changes: usize,
    pub total_files_affected: usize,
    pub total_files_skipped: usize,
}

/// Build a frontmatter inventory across the vault.
pub fn build_inventory(index: &VaultIndex) -> HashMap<String, FieldInventoryEntry> {
    let mut inventory: HashMap<String, FieldInventoryEntry> = HashMap::new();

    for note in &index.notes {
        if !note.curated || note.parse_error.is_some() {
            continue;
        }
        let type_name = note.type_str().unwrap_or_default();

        // Iterate over all YAML keys in the frontmatter
        if let Yaml::Hash(ref hash) = note.frontmatter {
            for (key, _value) in hash {
                if let Yaml::String(key_str) = key {
                    let entry = inventory
                        .entry(key_str.clone())
                        .or_insert_with(|| FieldInventoryEntry {
                            field: key_str.clone(),
                            count: 0,
                            types: HashSet::new(),
                            folders: HashSet::new(),
                            classification: classify_field(key_str),
                        });
                    entry.count += 1;
                    entry.types.insert(type_name.clone());
                    if let Some(folder) = note.path.rsplit_once('/').map(|(f, _)| f.to_string()) {
                        entry.folders.insert(folder);
                    }
                }
            }
        }
    }

    inventory
}

/// Classify a field based on name heuristics.
fn classify_field(field: &str) -> FieldClassification {
    match field {
        // Canonical semantic — must stay
        "type" | "status" | "lifecycle" | "result" | "canonical_id" | "aliases"
        | "source_cursor" | "reviewed_through_cursor" | "last_confirmed_year"
        | "owner" | "lead" | "second" | "custody" | "accepted_year"
        | "acceptance_cursor" | "started_year" | "started_cursor"
        | "target_year" | "next_review_year" | "terminal_due_year"
        | "portfolio_id" | "road_id" | "capability_id" | "produces"
        | "requires" | "cheapened_by" | "attainment_state" | "depth"
        | "knowledge_scope" => FieldClassification::CanonicalSemantic,

        // Generated/derived — can be removed once SourceIndex proves it
        "last_mentioned_cursor" | "last_mentioned_turn" | "last_mentioned_year"
        | "last_material_cursor" | "last_material_turn" | "last_material_year"
        | "last_evidenced_use_cursor" | "last_evidenced_use_turn"
        | "last_evidenced_use_year" | "mention_count" | "use_count"
        | "dormancy_age" | "dormant" | "overdue" | "candidate_score" => {
            FieldClassification::GeneratedDerived
        }

        // Path-derivable but consumed by MCP
        "retrieval_tier" => FieldClassification::PathDerivableButConsumed,

        // Legacy
        "vault_node_id" | "permanent_registry_id" | "freshness" => {
            FieldClassification::LegacyCompatibility
        }

        _ => FieldClassification::Unknown,
    }
}

/// Derive retrieval_tier from path and type when deterministically known.
/// Returns None if the value is ambiguous.
fn derive_retrieval_tier(path: &str, type_name: Option<&str>) -> Option<&'static str> {
    // Path-based derivation
    if path.starts_with("30 World/People/") { return Some("canonical"); }
    if path.starts_with("30 World/Places/") { return Some("canonical"); }
    if path.starts_with("30 World/Polities/") { return Some("canonical"); }
    if path.starts_with("30 World/Phenomena/") { return Some("canonical"); }
    if path.starts_with("30 World/Registers/") { return Some("evidence"); }
    if path.starts_with("40 Civilization/Projects/") { return Some("canonical"); }
    if path.starts_with("40 Civilization/Institutions/") { return Some("canonical"); }
    if path.starts_with("40 Civilization/Treaties/") { return Some("canonical"); }
    if path.starts_with("40 Civilization/Standing Documents/") { return Some("canonical"); }
    if path.starts_with("50 Knowledge/Superseded Beliefs/") { return Some("archive"); }
    if path.starts_with("50 Knowledge/Strategic Hypotheses/") { return Some("evidence"); }
    if path.starts_with("50 Knowledge/Investigations/") { return Some("evidence"); }

    // Type-based derivation for remaining paths
    match type_name? {
        "person" | "god" | "place" | "polity" | "faction" => Some("canonical"),
        "institution" | "service" | "project" | "venture" => Some("canonical"),
        "treaty" | "standing-document" | "constitutional-body" => Some("canonical"),
        "doctrine" | "policy" | "operational-service" => Some("canonical"),
        "investigation" | "hypothesis" | "phenomenon" => Some("evidence"),
        "register" | "ledger" | "instrument" | "mechanic" => Some("evidence"),
        "correction" | "bug-report" | "audit-report" => Some("evidence"),
        "technology-node" => Some("canonical"),
        _ => None, // ambiguous — leave as warning
    }
}

/// Build a migration plan: what would change if we applied the rules.
pub fn plan(
    index: &VaultIndex,
    config: &Config,
    _vault_root: &Path,
) -> MigrationPlan {
    let mut files = Vec::new();
    let mut total_changes = 0;
    let mut total_files_affected = 0;
    let mut total_files_skipped = 0;

    // Build the set of protected paths
    let protected: HashSet<&str> = config
        .protected_prefixes
        .iter()
        .map(|s| s.as_str())
        .collect();

    for note in &index.notes {
        if !note.curated || note.parse_error.is_some() {
            continue;
        }

        // Check protected paths
        if protected.iter().any(|p| note.path.starts_with(p)) {
            files.push(MigrationFileResult {
                path: note.path.clone(),
                changes: Vec::new(),
                skipped: true,
                skip_reason: Some("protected source path".to_string()),
            });
            total_files_skipped += 1;
            continue;
        }

        let mut changes = Vec::new();

        // Check for generated/derived fields that can be removed
        if let Yaml::Hash(ref hash) = note.frontmatter {
            for (key, _value) in hash {
                if let Yaml::String(key_str) = key {
                    let classification = classify_field(key_str);
                    if classification == FieldClassification::GeneratedDerived {
                        // Check if the SourceIndex can reproduce this
                        // For now, we only remove if the field is in the
                        // known generated set
                        changes.push(MigrationChange {
                            rule_id: "MIG-GEN-001".to_string(),
                            field: key_str.clone(),
                            old_value: Some("<present>".to_string()),
                            new_value: None, // would be removed
                        });
                    }
                }
            }
        }

        // MIG-RETRIEVAL-001: add missing retrieval_tier based on path/type
        if !note.fm().has("retrieval_tier") {
            if let Some(tier) = derive_retrieval_tier(&note.path, note.type_str().as_deref()) {
                changes.push(MigrationChange {
                    rule_id: "MIG-RETRIEVAL-001".to_string(),
                    field: "retrieval_tier".to_string(),
                    old_value: None,
                    new_value: Some(tier.to_string()),
                });
            }
        }

        if !changes.is_empty() {
            total_files_affected += 1;
            total_changes += changes.len();
        }

        files.push(MigrationFileResult {
            path: note.path.clone(),
            changes,
            skipped: false,
            skip_reason: None,
        });
    }

    MigrationPlan {
        files,
        total_changes,
        total_files_affected,
        total_files_skipped,
    }
}

/// Apply a migration plan. Returns the list of actually changed files.
/// Only applies changes that are mechanically provable.
pub fn apply(
    index: &VaultIndex,
    config: &Config,
    vault_root: &Path,
) -> Result<Vec<String>, String> {
    let plan = plan(index, config, vault_root);
    let mut changed_files = Vec::new();

    // Build the set of protected paths
    let protected: HashSet<&str> = config
        .protected_prefixes
        .iter()
        .map(|s| s.as_str())
        .collect();

    for file_result in &plan.files {
        if file_result.skipped || file_result.changes.is_empty() {
            continue;
        }

        // Protected check
        if protected.iter().any(|p| file_result.path.starts_with(p)) {
            continue;
        }

        let abs = vault_root.join(&file_result.path);
        let raw = match std::fs::read_to_string(&abs) {
            Ok(r) => r,
            Err(_) => continue,
        };

        let fm = parse(&raw);
        if !fm.has_block || fm.parse_error.is_some() {
            continue;
        }

        // For each change, remove the field from the YAML
        let mut new_raw = raw.clone();
        let mut any_change = false;

        for change in &file_result.changes {
            if change.new_value.is_some() {
                // Not a removal — skip for now
                continue;
            }
            // Remove the field line from the frontmatter
            if remove_yaml_field(&mut new_raw, &change.field) {
                any_change = true;
            }
        }

        if any_change {
            // Verify the result is still valid YAML
            let new_fm = parse(&new_raw);
            if new_fm.parse_error.is_some() {
                // YAML became invalid — skip this file
                continue;
            }

            // Write the file
            std::fs::write(&abs, &new_raw)
                .map_err(|e| format!("cannot write {}: {e}", file_result.path))?;
            changed_files.push(file_result.path.clone());
        }
    }

    Ok(changed_files)
}

/// Remove a top-level YAML field from a raw Markdown file.
/// Returns true if a change was made.
fn remove_yaml_field(raw: &mut String, field: &str) -> bool {
    let lines: Vec<&str> = raw.lines().collect();
    let mut result = Vec::new();
    let mut in_frontmatter = false;
    let mut found = false;
    let mut skip_next_indented = false;

    for (i, line) in lines.iter().enumerate() {
        let trimmed = line.trim();

        if i == 0 && trimmed == "---" {
            in_frontmatter = true;
            result.push(line.to_string());
            continue;
        }

        if in_frontmatter && trimmed == "---" {
            in_frontmatter = false;
            result.push(line.to_string());
            continue;
        }

        if !in_frontmatter {
            result.push(line.to_string());
            continue;
        }

        // Inside frontmatter
        if skip_next_indented {
            // Skip indented continuation lines (list items, multi-line values)
            if line.starts_with("  ") || line.starts_with("\t") || trimmed.starts_with("- ") {
                continue;
            } else {
                skip_next_indented = false;
            }
        }

        // Check if this line starts the field we want to remove
        if let Some(rest) = trimmed.strip_prefix(&format!("{field}:")) {
            // Check if it's an exact field match (not a prefix of another field)
            // e.g., "status:" should not match "status_detail:"
            let field_colon = format!("{field}:");
            if trimmed.starts_with(&field_colon) {
                found = true;
                // Check if the value continues on the next line (list or multi-line)
                let after_colon = rest.trim();
                if after_colon.is_empty() {
                    // Value might be on next line(s)
                    skip_next_indented = true;
                }
                continue;
            }
        }

        result.push(line.to_string());
    }

    if found {
        *raw = result.join("\n");
        // Ensure trailing newline
        if !raw.ends_with('\n') {
            raw.push('\n');
        }
    }

    found
}

/// Render a migration plan as Markdown for human/LLM review.
pub fn render_plan(plan: &MigrationPlan) -> String {
    let mut out = String::new();

    out.push_str("---\n");
    out.push_str("type: migration-plan\n");
    out.push_str(&format!(
        "generated_at: {}\n",
        time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "unknown".to_string())
    ));
    out.push_str("---\n\n");

    out.push_str("# Frontmatter Migration Plan\n\n");
    out.push_str(&format!(
        "**{}** changes across **{}** files ({} skipped).\n\n",
        plan.total_changes, plan.total_files_affected, plan.total_files_skipped,
    ));

    if plan.total_changes == 0 {
        out.push_str("No deterministic migrations available.\n");
        return out;
    }

    out.push_str("## Changes\n\n");
    out.push_str("| File | Rule | Field | Action |\n");
    out.push_str("|---|---|---|---|\n");

    for file in &plan.files {
        if file.skipped || file.changes.is_empty() {
            continue;
        }
        for change in &file.changes {
            let action = if change.new_value.is_some() {
                "transform"
            } else {
                "remove"
            };
            out.push_str(&format!(
                "| `{}` | {} | `{}` | {} |\n",
                file.path, change.rule_id, change.field, action,
            ));
        }
    }

    // Skipped files
    let skipped: Vec<&MigrationFileResult> =
        plan.files.iter().filter(|f| f.skipped).collect();
    if !skipped.is_empty() {
        out.push_str("\n## Skipped Files\n\n");
        for f in skipped {
            out.push_str(&format!(
                "- `{}` — {}\n",
                f.path,
                f.skip_reason.as_deref().unwrap_or("unknown")
            ));
        }
    }

    out
}

/// Frontmatter inventory entry.
#[derive(Debug)]
pub struct FieldInventoryEntry {
    pub field: String,
    pub count: usize,
    pub types: HashSet<String>,
    pub folders: HashSet<String>,
    pub classification: FieldClassification,
}

/// Render the frontmatter inventory as Markdown.
pub fn render_inventory(inventory: &HashMap<String, FieldInventoryEntry>) -> String {
    let mut out = String::new();

    out.push_str("---\n");
    out.push_str("type: frontmatter-inventory\n");
    out.push_str(&format!(
        "generated_at: {}\n",
        time::OffsetDateTime::now_utc()
            .format(&time::format_description::well_known::Rfc3339)
            .unwrap_or_else(|_| "unknown".to_string())
    ));
    out.push_str("---\n\n");

    out.push_str("# Frontmatter Inventory\n\n");
    out.push_str(&format!("**{}** distinct fields across the vault.\n\n", inventory.len()));

    out.push_str("| Field | Count | Types | Classification |\n");
    out.push_str("|---|---:|---|---|\n");

    let mut entries: Vec<&FieldInventoryEntry> = inventory.values().collect();
    entries.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.field.cmp(&b.field)));

    for entry in entries {
        let types: Vec<String> = entry.types.iter().take(3).cloned().collect();
        let types_str = if types.len() < entry.types.len() {
            format!("{} (+{})", types.join(", "), entry.types.len() - types.len())
        } else {
            types.join(", ")
        };
        out.push_str(&format!(
            "| `{}` | {} | {} | {:?} |\n",
            entry.field, entry.count, types_str, entry.classification,
        ));
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_field_known() {
        assert_eq!(
            classify_field("last_mentioned_cursor"),
            FieldClassification::GeneratedDerived
        );
        assert_eq!(
            classify_field("type"),
            FieldClassification::CanonicalSemantic
        );
        assert_eq!(
            classify_field("retrieval_tier"),
            FieldClassification::PathDerivableButConsumed
        );
        assert_eq!(
            classify_field("some_random_field"),
            FieldClassification::Unknown
        );
    }

    #[test]
    fn remove_yaml_field_basic() {
        let mut raw = "---\ntype: person\nstatus: active\nmention_count: 5\n---\nbody\n".to_string();
        assert!(remove_yaml_field(&mut raw, "mention_count"));
        assert!(!raw.contains("mention_count"));
        assert!(raw.contains("type: person"));
        assert!(raw.contains("status: active"));
    }

    #[test]
    fn remove_yaml_field_not_found() {
        let mut raw = "---\ntype: person\n---\nbody\n".to_string();
        assert!(!remove_yaml_field(&mut raw, "nonexistent"));
    }

    #[test]
    fn remove_yaml_field_preserves_body() {
        let mut raw = "---\ntype: person\nmention_count: 5\n---\n# Body\nSome text.\n".to_string();
        remove_yaml_field(&mut raw, "mention_count");
        assert!(raw.contains("# Body"));
        assert!(raw.contains("Some text."));
    }
}
