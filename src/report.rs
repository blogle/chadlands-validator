//! Durable, non-authoritative health report:
//! `00 System/Validation/Vault Health.md` by default.
//!
//! The report is the sole interface between the validator and the LLM.
//! Every finding message is self-contained (includes expected values and
//! remediation guidance). The report includes the relevant validator
//! configuration so the LLM never needs to read a separate config file.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::Path;

use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

use crate::boundary::StateBoundary;
use crate::config::Config;
use crate::domain;
use crate::findings::{Finding, Findings, Severity};
use crate::rules::meta;

fn yaml_escape(s: &str) -> String {
    let needs_quoting = s.contains(':')
        || s.contains('#')
        || s.contains('@')
        || s.contains('`')
        || s.contains('\n')
        || s.contains('\r')
        || s.contains('"')
        || s.contains('\\')
        || s.starts_with(' ')
        || s.ends_with(' ')
        || s == "true"
        || s == "false"
        || s == "null"
        || s == "~"
        || s.is_empty()
        // Numeric patterns that YAML parsers coerce to non-string types.
        || looks_like_number(s);
    if !needs_quoting {
        return s.to_string();
    }
    let escaped = s
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
        .replace('\r', "\\r");
    format!("\"{escaped}\"")
}

/// Detect strings that YAML would parse as numbers, booleans, or special
/// values rather than plain strings. Covers YAML 1.1 (used by yaml-rust2):
/// integers, floats, scientific notation, hex/octal/binary, underscores,
/// and special floats (.inf, .nan).
fn looks_like_number(s: &str) -> bool {
    if s.is_empty() {
        return false;
    }
    let lower = s.to_ascii_lowercase();

    // Special floats: .inf, -.inf, +.inf, .nan
    if lower == ".inf" || lower == "-.inf" || lower == "+.inf" || lower == ".nan" {
        return true;
    }

    let bytes = s.as_bytes();
    let mut i = 0;

    // Optional sign.
    if i < bytes.len() && (bytes[i] == b'-' || bytes[i] == b'+') {
        i += 1;
    }
    if i >= bytes.len() {
        return false;
    }

    // Hex: 0x..., octal: 0o..., binary: 0b...
    if bytes[i] == b'0' && i + 1 < bytes.len() {
        match bytes[i + 1] {
            b'x' | b'X' => {
                // Hex digits (allow underscores).
                i += 2;
                let mut has_hex = false;
                while i < bytes.len() {
                    if bytes[i].is_ascii_hexdigit() {
                        has_hex = true;
                    } else if bytes[i] == b'_' {
                        // underscore separator — skip
                    } else {
                        return false;
                    }
                    i += 1;
                }
                return has_hex;
            }
            b'o' | b'O' => {
                // Octal digits (allow underscores).
                i += 2;
                let mut has_oct = false;
                while i < bytes.len() {
                    if (b'0'..=b'7').contains(&bytes[i]) {
                        has_oct = true;
                    } else if bytes[i] == b'_' {
                        // skip
                    } else {
                        return false;
                    }
                    i += 1;
                }
                return has_oct;
            }
            b'b' | b'B' => {
                // Binary digits (allow underscores).
                i += 2;
                let mut has_bin = false;
                while i < bytes.len() {
                    if bytes[i] == b'0' || bytes[i] == b'1' {
                        has_bin = true;
                    } else if bytes[i] == b'_' {
                        // skip
                    } else {
                        return false;
                    }
                    i += 1;
                }
                return has_bin;
            }
            _ => {}
        }
    }

    // Decimal integer/float (allow underscores in digits).
    let mut has_digit = false;
    while i < bytes.len() {
        if bytes[i].is_ascii_digit() {
            has_digit = true;
        } else if bytes[i] == b'_' {
            // underscore separator — skip
        } else {
            break;
        }
        i += 1;
    }
    if !has_digit {
        return false;
    }

    // Optional decimal part.
    if i < bytes.len() && bytes[i] == b'.' {
        i += 1;
        while i < bytes.len() {
            if bytes[i].is_ascii_digit() {
                // ok
            } else if bytes[i] == b'_' {
                // skip
            } else {
                break;
            }
            i += 1;
        }
    }

    // Optional exponent.
    if i < bytes.len() && (bytes[i] == b'e' || bytes[i] == b'E') {
        i += 1;
        if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
            i += 1;
        }
        let mut has_exp_digit = false;
        while i < bytes.len() {
            if bytes[i].is_ascii_digit() {
                has_exp_digit = true;
            } else if bytes[i] == b'_' {
                // skip
            } else {
                return false;
            }
            i += 1;
        }
        if !has_exp_digit {
            return false;
        }
    }

    i == bytes.len()
}

fn fm_line(key: &str, value: Option<i64>) -> String {
    match value {
        Some(v) => format!("{key}: {v}\n"),
        None => format!("{key}: null\n"),
    }
}

fn fm_str(key: &str, value: &str) -> String {
    format!("{key}: {}\n", yaml_escape(value))
}

fn fm_list(key: &str, values: &[String]) -> String {
    if values.is_empty() {
        return format!("{key}: []\n");
    }
    let mut out = format!("{key}:\n");
    for v in values {
        out.push_str(&format!("  - {}\n", yaml_escape(v)));
    }
    out
}

/// Previous report frontmatter, parsed minimally for change detection.
pub struct PreviousReport {
    pub validated_revision: Option<String>,
    pub validator_build_revision: Option<String>,
    pub config_fingerprint: Option<String>,
    pub error_rules: BTreeMap<String, usize>,
    pub warn_rules: BTreeMap<String, usize>,
    pub info_rules: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DeltaBasis {
    NoPreviousReport,
    NotComparable,
    Comparable {
        vault_changed: bool,
    },
    BasisChanged {
        vault_changed: bool,
        validator_changed: bool,
        config_changed: bool,
    },
}

fn classify_delta_basis(
    previous: Option<&PreviousReport>,
    vault_revision: &str,
    validator_revision: &str,
    config_fingerprint: &str,
) -> DeltaBasis {
    let Some(previous) = previous else {
        return DeltaBasis::NoPreviousReport;
    };
    let (Some(previous_vault), Some(previous_validator), Some(previous_config)) = (
        previous.validated_revision.as_deref(),
        previous.validator_build_revision.as_deref(),
        previous.config_fingerprint.as_deref(),
    ) else {
        return DeltaBasis::NotComparable;
    };

    let vault_changed = previous_vault != vault_revision;
    let validator_changed = previous_validator != validator_revision;
    let config_changed = previous_config != config_fingerprint;
    if validator_changed || config_changed {
        DeltaBasis::BasisChanged {
            vault_changed,
            validator_changed,
            config_changed,
        }
    } else {
        DeltaBasis::Comparable { vault_changed }
    }
}

impl PreviousReport {
    /// Parse a previous report file. Returns None if the file doesn't exist
    /// or can't be parsed.
    pub fn load(vault_root: &Path, report_path: &str) -> Option<PreviousReport> {
        let abs = vault_root.join(report_path);
        let raw = std::fs::read_to_string(abs).ok()?;

        // Find the closing frontmatter fence (second `---` on its own line).
        // The first `---` is the opening fence at line 0; we need the second.
        let first_fence = raw.find("---\n").or_else(|| raw.find("---\r\n"))?;
        let after_first = &raw[first_fence + 3..];
        // Skip optional trailing newline after the first fence.
        let after_first = after_first.strip_prefix('\n').unwrap_or(after_first);
        let second_fence_rel = after_first
            .find("\n---")
            .or_else(|| after_first.find("\r\n---"))?;
        let fm_text = &after_first[..second_fence_rel];

        let validated_revision = fm_text
            .lines()
            .find(|l| l.starts_with("validated_revision:"))
            .map(|l| {
                l.trim_start_matches("validated_revision:")
                    .trim()
                    .trim_matches('"')
                    .to_string()
            });

        let validator_build_revision = fm_text
            .lines()
            .find(|l| l.starts_with("validator_build_revision:"))
            .map(|l| {
                l.trim_start_matches("validator_build_revision:")
                    .trim()
                    .trim_matches('"')
                    .to_string()
            });

        let config_fingerprint = fm_text
            .lines()
            .find(|l| l.starts_with("config_fingerprint:"))
            .map(|l| {
                l.trim_start_matches("config_fingerprint:")
                    .trim()
                    .trim_matches('"')
                    .to_string()
            });

        // Count findings by rule from the body, tracking severity sections.
        // after_first starts at raw[first_fence + 4] (past "---\n").
        // second_fence_rel points to "\n---" within after_first.
        // The body starts past "\n---\n" (5 chars) from that point.
        let body_start = first_fence + 4 + second_fence_rel + 5;
        let body = &raw[body_start..];
        let mut error_rules: BTreeMap<String, usize> = BTreeMap::new();
        let mut warn_rules: BTreeMap<String, usize> = BTreeMap::new();
        let mut info_rules: BTreeMap<String, usize> = BTreeMap::new();
        let mut current_rule: Option<String> = None;
        let mut current_section: Severity = Severity::Info; // default: unknown

        for line in body.lines() {
            let trimmed = line.trim_start();
            if trimmed.starts_with("## ERROR") {
                current_section = Severity::Error;
                continue;
            }
            if trimmed.starts_with("## WARN") {
                current_section = Severity::Warn;
                continue;
            }
            if trimmed.starts_with("## INFO") {
                current_section = Severity::Info;
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix("### ") {
                if let Some(rule_end) = rest.find(' ') {
                    current_rule = Some(rest[..rule_end].to_string());
                }
                continue;
            }
            if trimmed.starts_with("- `") && current_rule.is_some() {
                let rule = current_rule.clone().unwrap();
                match current_section {
                    Severity::Error => *error_rules.entry(rule).or_insert(0) += 1,
                    Severity::Warn => *warn_rules.entry(rule).or_insert(0) += 1,
                    Severity::Info => *info_rules.entry(rule).or_insert(0) += 1,
                }
            }
        }

        Some(PreviousReport {
            validated_revision,
            validator_build_revision,
            config_fingerprint,
            error_rules,
            warn_rules,
            info_rules,
        })
    }
}

pub fn render(
    boundary: &StateBoundary,
    findings: &Findings,
    files_checked: usize,
    index: &crate::vault::VaultIndex,
    config: &Config,
    config_path: Option<&str>,
    previous: Option<&PreviousReport>,
) -> String {
    let generated_at = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .unwrap_or_else(|_| "unknown".to_string());
    let status = if findings.errors() > 0 {
        "failed"
    } else {
        "passed"
    };

    // Change detection.
    let previous_revision = previous
        .and_then(|p| p.validated_revision.as_deref())
        .unwrap_or("none");
    let previous_validator_build = previous
        .and_then(|p| p.validator_build_revision.as_deref())
        .unwrap_or("none");
    let previous_config_fp = previous
        .and_then(|p| p.config_fingerprint.as_deref())
        .unwrap_or("none");

    let current_build_revision = crate::BUILD_REVISION;
    let current_config_fp = config.fingerprint();

    let delta_basis = classify_delta_basis(
        previous,
        &boundary.vault_revision,
        current_build_revision,
        &current_config_fp,
    );

    let (new_errors, resolved_errors, new_warnings, resolved_warnings, new_infos, resolved_infos) =
        if let Some(prev) = previous {
            let current_errors = rule_counts(findings, Severity::Error);
            let current_warnings = rule_counts(findings, Severity::Warn);
            let current_infos = rule_counts(findings, Severity::Info);
            let (ne, re) = delta(&prev.error_rules, &current_errors);
            let (nw, rw) = delta(&prev.warn_rules, &current_warnings);
            let (ni, ri) = delta(&prev.info_rules, &current_infos);
            (ne, re, nw, rw, ni, ri)
        } else {
            (0, 0, 0, 0, 0, 0)
        };

    let mut out = String::new();
    out.push_str("---\n");
    out.push_str("type: validation-report\n");
    out.push_str(&format!("status: {status}\n"));
    out.push_str(&format!(
        "validator_version: {}\n",
        yaml_escape(crate::VERSION)
    ));
    out.push_str(&format!(
        "validator_build_revision: {}\n",
        yaml_escape(current_build_revision)
    ));
    out.push_str(&format!(
        "config_fingerprint: {}\n",
        yaml_escape(&current_config_fp)
    ));
    out.push_str(&format!("generated_at: {}\n", yaml_escape(&generated_at)));
    out.push_str(&format!("validated_at: {}\n", yaml_escape(&generated_at)));
    out.push_str(&format!(
        "validated_revision: {}\n",
        yaml_escape(&boundary.vault_revision)
    ));
    out.push_str(&format!(
        "previous_revision: {}\n",
        yaml_escape(previous_revision)
    ));
    out.push_str(&format!(
        "previous_validator_build: {}\n",
        yaml_escape(previous_validator_build)
    ));
    out.push_str(&format!(
        "previous_config_fingerprint: {}\n",
        yaml_escape(previous_config_fp)
    ));
    if let Some(p) = config_path {
        out.push_str(&format!("validator_config_path: {}\n", yaml_escape(p)));
    }
    out.push('\n');
    out.push_str(&fm_line("current_turn", boundary.current_turn));
    out.push_str(&fm_line("current_year", boundary.current_year));
    out.push_str(&fm_line("last_resolved_year", boundary.last_resolved_year));
    out.push_str(&fm_line(
        "current_source_cursor",
        boundary.current_source_cursor,
    ));
    out.push_str(&fm_line(
        "canonical_materialized_cursor",
        boundary.canonical_materialized_cursor,
    ));
    out.push('\n');
    out.push_str(&format!("files_checked: {files_checked}\n"));
    out.push_str(&format!("errors: {}\n", findings.errors()));
    out.push_str(&format!("warnings: {}\n", findings.warnings()));
    out.push_str(&format!("infos: {}\n", findings.infos()));
    let entity_summary = domain::count_entities(index, config);
    out.push_str(&format!(
        "modern_entities: {}\n",
        entity_summary.modern_entity_count
    ));
    out.push_str(&format!(
        "legacy_entities: {}\n",
        entity_summary.legacy_entity_count
    ));
    let delta_status = match delta_basis {
        DeltaBasis::NoPreviousReport => "no-previous-report",
        DeltaBasis::NotComparable => "not-comparable",
        DeltaBasis::Comparable { .. } => "comparable",
        DeltaBasis::BasisChanged { .. } => "basis-changed",
    };
    out.push_str(&format!("delta_status: {delta_status}\n"));
    if matches!(delta_basis, DeltaBasis::Comparable { .. }) {
        out.push_str(&format!("new_errors: {new_errors}\n"));
        out.push_str(&format!("resolved_errors: {resolved_errors}\n"));
        out.push_str(&format!("new_warnings: {new_warnings}\n"));
        out.push_str(&format!("resolved_warnings: {resolved_warnings}\n"));
        out.push_str(&format!("new_infos: {new_infos}\n"));
        out.push_str(&format!("resolved_infos: {resolved_infos}\n"));
    } else {
        out.push_str("new_errors: null\nresolved_errors: null\n");
        out.push_str("new_warnings: null\nresolved_warnings: null\n");
        out.push_str("new_infos: null\nresolved_infos: null\n");
    }
    out.push('\n');

    // Relevant config values the LLM needs.
    out.push_str("# --- effective validator config ---\n");
    out.push_str(&fm_str("chronicle_dir", &config.chronicle_dir));
    out.push_str(&fm_list("protected_prefixes", &config.protected_prefixes));
    out.push_str(&fm_list("unresolved_values", &config.unresolved_values));
    out.push_str(&fm_list("id_fields", &config.id_fields));
    out.push_str("required_fields:\n");
    let mut rf_keys: Vec<&String> = config.required_fields.keys().collect();
    rf_keys.sort();
    for type_name in &rf_keys {
        let reqs = &config.required_fields[*type_name];
        out.push_str(&format!("  {}:\n", yaml_escape(type_name)));
        for r in reqs {
            if r.alternatives.len() == 1 {
                out.push_str(&format!("    - {}\n", yaml_escape(&r.alternatives[0])));
            } else {
                out.push_str(&format!(
                    "    - [{}]\n",
                    r.alternatives
                        .iter()
                        .map(|a| yaml_escape(a))
                        .collect::<Vec<_>>()
                        .join(", ")
                ));
            }
        }
    }
    out.push_str("status_vocab:\n");
    let mut sv_keys: Vec<&String> = config.status_vocab.keys().collect();
    sv_keys.sort();
    for class in sv_keys {
        let vocab = &config.status_vocab[class];
        out.push_str(&format!("  {}:\n", yaml_escape(class)));
        for v in vocab {
            out.push_str(&format!("    - {}\n", yaml_escape(v)));
        }
    }
    out.push_str("---\n\n");

    // Body.
    out.push_str("# Vault Health\n\n");
    out.push_str(&format!(
        "**{status}** — {} errors, {} warnings, {} infos across {} files at revision `{}`.\n\n",
        findings.errors(),
        findings.warnings(),
        findings.infos(),
        files_checked,
        boundary.vault_revision
    ));
    match delta_basis {
        DeltaBasis::NoPreviousReport => {
            out.push_str("> Delta: no previous report is available; no comparison was made.\n\n");
        }
        DeltaBasis::NotComparable => {
            out.push_str(
                "> Delta: **NOT COMPARABLE**. The previous report lacks complete vault, validator-build, or effective-config provenance; finding-count changes are not evidence of vault repair.\n\n",
            );
        }
        DeltaBasis::Comparable { vault_changed } => {
            out.push_str(&format!(
                "> Previous revision: `{previous_revision}`. Vault revision: {}. Delta: \
                 {new_errors} new / {resolved_errors} resolved errors, \
                 {new_warnings} new / {resolved_warnings} resolved warnings, \
                 {new_infos} new / {resolved_infos} resolved infos.\n\n",
                if vault_changed {
                    "changed"
                } else {
                    "unchanged"
                }
            ));
        }
        DeltaBasis::BasisChanged {
            vault_changed,
            validator_changed,
            config_changed,
        } => {
            out.push_str(&format!(
                "> Delta basis changed:\n> - vault revision: {}\n> - validator revision: {}\n> - config fingerprint: {}\n>\n> Finding-count changes ({new_errors}/{resolved_errors} errors, {new_warnings}/{resolved_warnings} warnings, {new_infos}/{resolved_infos} infos increased/decreased) may reflect validator/config changes rather than vault repair.\n\n",
                if vault_changed { "changed" } else { "unchanged" },
                if validator_changed { "changed" } else { "unchanged" },
                if config_changed { "changed" } else { "unchanged" },
            ));
        }
    }
    out.push_str(
        "> This report is non-authoritative and valid only for `validated_revision`. \
         An older green report is not proof that subsequent writes are healthy.\n\n",
    );

    for (severity, heading) in [
        (Severity::Error, "ERROR"),
        (Severity::Warn, "WARN"),
        (Severity::Info, "INFO"),
    ] {
        let by_rule: BTreeMap<&str, Vec<&Finding>> = {
            let mut m: BTreeMap<&str, Vec<&Finding>> = BTreeMap::new();
            for f in findings.items.iter().filter(|f| f.severity == severity) {
                m.entry(f.rule).or_default().push(f);
            }
            m
        };
        if by_rule.is_empty() {
            continue;
        }
        out.push_str(&format!("## {heading}\n\n"));
        for (rule, items) in by_rule {
            let m = meta::lookup(rule);
            out.push_str(&format!(
                "### {rule} — {} — {} finding(s)\n\n",
                m.description,
                items.len()
            ));
            out.push_str(&format!("> Remediation: {}\n\n", m.remediation));
            for f in &items {
                match &f.path {
                    Some(p) => out.push_str(&format!("- `{p}` — {}\n", f.message)),
                    None => out.push_str(&format!("- {}\n", f.message)),
                }
            }
            out.push('\n');
        }
    }

    if findings.items.is_empty() {
        out.push_str("No findings. The vault satisfies the mechanical contract it claims.\n");
    }
    out
}

fn rule_counts(findings: &Findings, severity: Severity) -> BTreeMap<String, usize> {
    let mut m: BTreeMap<String, usize> = BTreeMap::new();
    for f in findings.items.iter().filter(|f| f.severity == severity) {
        *m.entry(f.rule.to_string()).or_insert(0) += 1;
    }
    m
}

fn delta(prev: &BTreeMap<String, usize>, current: &BTreeMap<String, usize>) -> (usize, usize) {
    let mut new = 0usize;
    let mut resolved = 0usize;
    let all_rules: std::collections::HashSet<&str> = prev
        .keys()
        .chain(current.keys())
        .map(|s| s.as_str())
        .collect();
    for rule in all_rules {
        let p = prev.get(rule).copied().unwrap_or(0);
        let c = current.get(rule).copied().unwrap_or(0);
        if c > p {
            new += c - p;
        }
        if p > c {
            resolved += p - c;
        }
    }
    (new, resolved)
}

/// Write the report into the vault. The report directory is excluded from
/// scanning and watch triggers, so this never recursively re-triggers
/// validation.
pub fn write_report(vault_root: &Path, report_path: &str, content: &str) -> std::io::Result<()> {
    let abs = vault_root.join(report_path);
    if let Some(parent) = abs.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = abs.with_extension("md.tmp");
    let mut f = std::fs::File::create(&tmp)?;
    f.write_all(content.as_bytes())?;
    f.sync_all()?;
    std::fs::rename(&tmp, &abs)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn previous(
        vault: Option<&str>,
        validator: Option<&str>,
        config: Option<&str>,
    ) -> PreviousReport {
        PreviousReport {
            validated_revision: vault.map(str::to_string),
            validator_build_revision: validator.map(str::to_string),
            config_fingerprint: config.map(str::to_string),
            error_rules: BTreeMap::new(),
            warn_rules: BTreeMap::new(),
            info_rules: BTreeMap::new(),
        }
    }

    #[test]
    fn yaml_escape_numeric_strings() {
        // These should all be quoted (YAML would parse them as non-string).
        assert_eq!(yaml_escape("123"), "\"123\"");
        assert_eq!(yaml_escape("1.0"), "\"1.0\"");
        assert_eq!(yaml_escape("-1"), "\"-1\"");
        assert_eq!(yaml_escape("1e5"), "\"1e5\"");
        assert_eq!(yaml_escape("1_000_000"), "\"1_000_000\"");
        assert_eq!(yaml_escape("0x1A"), "\"0x1A\"");
        assert_eq!(yaml_escape("0o17"), "\"0o17\"");
        assert_eq!(yaml_escape("0b1010"), "\"0b1010\"");
        assert_eq!(yaml_escape(".inf"), "\".inf\"");
        assert_eq!(yaml_escape("-.inf"), "\"-.inf\"");
        assert_eq!(yaml_escape("+.inf"), "\"+.inf\"");
        assert_eq!(yaml_escape(".nan"), "\".nan\"");
        // Plain strings should not be quoted.
        assert_eq!(yaml_escape("hello"), "hello");
        assert_eq!(yaml_escape("abc123"), "abc123");
    }

    #[test]
    fn looks_like_number_edge_cases() {
        // YAML 1.1 special floats.
        assert!(looks_like_number(".inf"));
        assert!(looks_like_number("-.inf"));
        assert!(looks_like_number("+.inf"));
        assert!(looks_like_number(".nan"));
        // Hex, octal, binary.
        assert!(looks_like_number("0x1A"));
        assert!(looks_like_number("0xFF"));
        assert!(looks_like_number("0o17"));
        assert!(looks_like_number("0b1010"));
        // Underscores.
        assert!(looks_like_number("1_000_000"));
        assert!(looks_like_number("1_000.5"));
        // Not numbers.
        assert!(!looks_like_number("hello"));
        assert!(!looks_like_number("abc123"));
        assert!(!looks_like_number(""));
        assert!(!looks_like_number("0x")); // no digits after prefix
        assert!(!looks_like_number("0o")); // no digits after prefix
        assert!(!looks_like_number("0b")); // no digits after prefix
    }

    #[test]
    fn delta_basis_allows_vault_only_comparison() {
        let prior = previous(Some("vault-a"), Some("validator"), Some("config"));
        assert_eq!(
            classify_delta_basis(Some(&prior), "vault-b", "validator", "config"),
            DeltaBasis::Comparable {
                vault_changed: true
            }
        );
    }

    #[test]
    fn delta_basis_identifies_validator_only_change() {
        let prior = previous(Some("vault"), Some("validator-a"), Some("config"));
        assert_eq!(
            classify_delta_basis(Some(&prior), "vault", "validator-b", "config"),
            DeltaBasis::BasisChanged {
                vault_changed: false,
                validator_changed: true,
                config_changed: false,
            }
        );
    }

    #[test]
    fn delta_basis_identifies_config_only_change() {
        let prior = previous(Some("vault"), Some("validator"), Some("config-a"));
        assert_eq!(
            classify_delta_basis(Some(&prior), "vault", "validator", "config-b"),
            DeltaBasis::BasisChanged {
                vault_changed: false,
                validator_changed: false,
                config_changed: true,
            }
        );
    }

    #[test]
    fn delta_basis_rejects_old_report_without_fingerprints() {
        let prior = previous(Some("vault"), None, None);
        assert_eq!(
            classify_delta_basis(Some(&prior), "vault", "validator", "config"),
            DeltaBasis::NotComparable
        );
    }
}
