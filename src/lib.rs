//! chadlands-validator: a deterministic validation layer for the Chadlands
//! Markdown Vault.
//!
//! The validator has no campaign intelligence. It validates mechanically
//! provable invariants over files, metadata, declared state boundaries, and
//! reconciliation manifests. It never mutates canonical campaign records;
//! its only vault write is the generated health report.

pub mod boundary;
pub mod capability;
pub mod config;
pub mod continuity;
pub mod coverage;
pub mod findings;
pub mod frontmatter;
pub mod legacy_technology;
pub mod manifest;
pub mod migration;
pub mod receipts;
pub mod report;
pub mod rules;
pub mod source_index;
pub mod technology;
pub mod vault;
pub mod watch;

use std::path::Path;

use findings::{Findings, Severity};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Validator build fingerprint: git SHA of the validator source at
/// compile time. Used for delta provenance to distinguish validator
/// changes from vault changes.
pub const BUILD_REVISION: &str = env!("VALIDATOR_GIT_SHA");

pub struct ValidationOutcome {
    pub boundary: boundary::StateBoundary,
    pub findings: Findings,
    pub files_checked: usize,
    pub report_markdown: String,
    pub continuity_report_markdown: Option<String>,
}

/// Run a full validation over the vault.
///
/// `changed_files` is the synchronous-workflow contract: the exact files a
/// mutating workflow wrote. Any of them under a protected collector prefix
/// is CHAD-PROT-001 (ERROR).
pub fn validate(
    vault_root: &Path,
    config: &config::Config,
    changed_files: &[String],
) -> Result<ValidationOutcome, String> {
    validate_with_config_path(vault_root, config, changed_files, None)
}

/// Validate with an explicit config path (for report metadata).
pub fn validate_with_config_path(
    vault_root: &Path,
    config: &config::Config,
    changed_files: &[String],
    config_path: Option<&str>,
) -> Result<ValidationOutcome, String> {
    let index = vault::scan(vault_root, config)
        .map_err(|e| format!("cannot scan {}: {e}", vault_root.display()))?;

    let manifests = manifest::collect(&index);
    let (boundary, mut items) = boundary::resolve(&index, config, &manifests);
    items.extend(manifest::check_manifests(
        &manifests,
        &index,
        boundary.current_source_cursor,
        config,
    ));

    // Build source index for continuity analysis
    let source_idx = source_index::build(vault_root, &index, config, &boundary);

    let ctx = rules::RuleContext {
        index: &index,
        config,
        boundary: &boundary,
        manifests: &manifests,
        source_index: Some(&source_idx),
    };
    items.extend(rules::run_all(&ctx));
    items.extend(rules::hygiene::check_protected_paths(
        changed_files,
        config,
        Severity::Error,
    ));

    let findings = Findings::new(items);

    // Load previous report for change detection.
    let previous = report::PreviousReport::load(vault_root, &config.report_path);

    let report_markdown = report::render(
        &boundary,
        &findings,
        index.notes.len(),
        config,
        config_path,
        previous.as_ref(),
    );

    // Generate continuity report
    let continuity_markdown = continuity::render(&boundary, &source_idx, config);

    Ok(ValidationOutcome {
        boundary,
        findings,
        files_checked: index.notes.len(),
        report_markdown,
        continuity_report_markdown: Some(continuity_markdown),
    })
}

/// Validate and persist the durable health report.
pub fn validate_and_report(
    vault_root: &Path,
    config: &config::Config,
    changed_files: &[String],
) -> Result<ValidationOutcome, String> {
    validate_and_report_with_config_path(vault_root, config, changed_files, None)
}

/// Validate and persist with an explicit config path.
pub fn validate_and_report_with_config_path(
    vault_root: &Path,
    config: &config::Config,
    changed_files: &[String],
    config_path: Option<&str>,
) -> Result<ValidationOutcome, String> {
    let outcome = validate_with_config_path(vault_root, config, changed_files, config_path)?;
    report::write_report(vault_root, &config.report_path, &outcome.report_markdown)
        .map_err(|e| format!("cannot write report {}: {e}", config.report_path))?;
    // Write continuity report if available
    if let Some(ref continuity_md) = outcome.continuity_report_markdown {
        report::write_report(vault_root, &config.continuity_report_path, continuity_md).map_err(
            |e| {
                format!(
                    "cannot write continuity report {}: {e}",
                    config.continuity_report_path
                )
            },
        )?;
    }
    Ok(outcome)
}
