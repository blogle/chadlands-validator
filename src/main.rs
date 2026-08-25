//! chadlands-validator CLI.
//!
//! Modes:
//!   check    synchronous full validation (workflow contract)
//!   watch    debounced file-watch validation, regenerating the health report
//!   boundary print the resolved machine-readable current-state boundary
//!
//! Exit codes for `check`: 0 = no ERROR findings, 1 = ERROR findings,
//! 2 = operational failure.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{ArgGroup, Parser, Subcommand, ValueEnum};

use chadlands_validator::boundary::StateBoundary;
use chadlands_validator::config::Config;
use chadlands_validator::findings::{Findings, Severity};

#[derive(Parser)]
#[command(
    name = "chadlands-validator",
    version,
    about = "Deterministic validation layer for the Chadlands Markdown Vault"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, ValueEnum)]
enum Format {
    Text,
    Json,
}

#[derive(Subcommand)]
enum Commands {
    /// Validate the vault once, synchronously.
    Check {
        /// Vault root directory.
        #[arg(long, default_value = ".")]
        vault: PathBuf,
        /// Optional YAML config override.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Files the calling workflow wrote (protected-path enforcement).
        #[arg(long, value_delimiter = ',')]
        changed_files: Vec<String>,
        /// Do not write the durable health report into the vault.
        #[arg(long)]
        no_report: bool,
        /// Output format for findings.
        #[arg(long, value_enum, default_value_t = Format::Text)]
        format: Format,
    },
    /// Watch the vault and revalidate (debounced) after curated changes.
    Watch {
        #[arg(long, default_value = ".")]
        vault: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
        /// Debounce window in milliseconds.
        #[arg(long)]
        debounce_ms: Option<u64>,
    },
    /// Print the resolved current-state boundary as JSON.
    Boundary {
        #[arg(long, default_value = ".")]
        vault: PathBuf,
        #[arg(long)]
        config: Option<PathBuf>,
    },
    /// Deterministic frontmatter migration (separate from validation).
    #[command(group(ArgGroup::new("migration_mode").args(["plan", "apply"]).multiple(false)))]
    MigrateFrontmatter {
        /// Vault root directory.
        #[arg(long, default_value = ".")]
        vault: PathBuf,
        /// Optional YAML config override.
        #[arg(long)]
        config: Option<PathBuf>,
        /// Show what would change without modifying files.
        #[arg(long)]
        plan: bool,
        /// Apply the migration (mutates canonical records).
        #[arg(long)]
        r#apply: bool,
    },
}

fn json_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out
}

fn boundary_json(b: &StateBoundary) -> String {
    fn opt(key: &str, v: Option<i64>) -> String {
        match v {
            Some(i) => format!("\"{key}\": {i}, "),
            None => format!("\"{key}\": null, "),
        }
    }
    let source = match &b.source {
        chadlands_validator::boundary::BoundarySource::File(p) => format!("file:{p}"),
        chadlands_validator::boundary::BoundarySource::Derived => "derived".to_string(),
    };
    format!(
        "{{{}{}{}{}{}\"vault_revision\": \"{}\", \"source\": \"{}\"}}",
        opt("current_turn", b.current_turn),
        opt("current_year", b.current_year),
        opt("last_resolved_year", b.last_resolved_year),
        opt("current_source_cursor", b.current_source_cursor),
        opt(
            "canonical_materialized_cursor",
            b.canonical_materialized_cursor
        ),
        json_escape(&b.vault_revision),
        json_escape(&source),
    )
}

fn findings_json(findings: &Findings) -> String {
    let mut out = String::from("[");
    for (i, f) in findings.items.iter().enumerate() {
        if i > 0 {
            out.push(',');
        }
        let path = f
            .path
            .as_deref()
            .map(|p| format!("\"{}\"", json_escape(p)))
            .unwrap_or_else(|| "null".to_string());
        out.push_str(&format!(
            "{{\"rule\": \"{}\", \"severity\": \"{}\", \"path\": {}, \"message\": \"{}\"}}",
            f.rule,
            f.severity,
            path,
            json_escape(&f.message)
        ));
    }
    out.push(']');
    out
}

fn print_text(findings: &Findings, files_checked: usize, revision: &str) {
    println!("validated {} files at revision {}", files_checked, revision);
    println!(
        "{} errors, {} warnings, {} infos",
        findings.errors(),
        findings.warnings(),
        findings.infos()
    );
    for f in &findings.items {
        match &f.path {
            Some(p) => println!("{} {} {} — {}", f.severity, f.rule, p, f.message),
            None => println!("{} {} {}", f.severity, f.rule, f.message),
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Commands::Check {
            vault,
            config,
            changed_files,
            no_report,
            format,
        } => {
            let cfg = match Config::resolve(config.as_deref(), &vault) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("config error: {e}");
                    return ExitCode::from(2);
                }
            };
            let cfg_path = config
                .as_ref()
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| {
                    vault
                        .join("00 System/Validation/validator.yml")
                        .to_string_lossy()
                        .to_string()
                });
            let outcome = if no_report {
                chadlands_validator::validate_with_config_path(
                    &vault,
                    &cfg,
                    &changed_files,
                    Some(&cfg_path),
                )
            } else {
                chadlands_validator::validate_and_report_with_config_path(
                    &vault,
                    &cfg,
                    &changed_files,
                    Some(&cfg_path),
                )
            };
            match outcome {
                Ok(o) => {
                    match format {
                        Format::Text => {
                            print_text(&o.findings, o.files_checked, &o.boundary.vault_revision)
                        }
                        Format::Json => println!("{}", findings_json(&o.findings)),
                    }
                    if o.findings.errors() > 0 {
                        ExitCode::from(1)
                    } else {
                        ExitCode::SUCCESS
                    }
                }
                Err(e) => {
                    eprintln!("validation error: {e}");
                    ExitCode::from(2)
                }
            }
        }
        Commands::Watch {
            vault,
            config,
            debounce_ms,
        } => {
            let mut cfg = match Config::resolve(config.as_deref(), &vault) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("config error: {e}");
                    return ExitCode::from(2);
                }
            };
            if let Some(ms) = debounce_ms {
                cfg.debounce_ms = ms;
            }
            match chadlands_validator::watch::watch(&vault, &cfg) {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    eprintln!("watch error: {e}");
                    ExitCode::from(2)
                }
            }
        }
        Commands::Boundary { vault, config } => {
            let cfg = match Config::resolve(config.as_deref(), &vault) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("config error: {e}");
                    return ExitCode::from(2);
                }
            };
            let index = match chadlands_validator::vault::scan(&vault, &cfg) {
                Ok(i) => i,
                Err(e) => {
                    eprintln!("scan error: {e}");
                    return ExitCode::from(2);
                }
            };
            let manifests = chadlands_validator::manifest::collect(&index);
            let (boundary, _) = chadlands_validator::boundary::resolve(&index, &cfg, &manifests);
            println!("{}", boundary_json(&boundary));
            ExitCode::SUCCESS
        }
        Commands::MigrateFrontmatter {
            vault,
            config,
            plan: _plan,
            apply: apply_flag,
        } => {
            let cfg = match Config::resolve(config.as_deref(), &vault) {
                Ok(c) => c,
                Err(e) => {
                    eprintln!("config error: {e}");
                    return ExitCode::from(2);
                }
            };
            let index = match chadlands_validator::vault::scan(&vault, &cfg) {
                Ok(i) => i,
                Err(e) => {
                    eprintln!("scan error: {e}");
                    return ExitCode::from(2);
                }
            };

            if apply_flag {
                // Apply mode: execute the migration
                match chadlands_validator::migration::apply(&index, &cfg, &vault) {
                    Ok(changed) => {
                        if changed.is_empty() {
                            println!("migration applied: no files changed");
                        } else {
                            println!("migration applied: {} file(s) changed", changed.len());
                            for f in &changed {
                                println!("  {f}");
                            }
                        }
                        ExitCode::SUCCESS
                    }
                    Err(e) => {
                        eprintln!("migration error: {e}");
                        ExitCode::from(2)
                    }
                }
            } else {
                // Plan mode (default): show what would change
                let migration_plan = chadlands_validator::migration::plan(&index, &cfg, &vault);
                let plan_md = chadlands_validator::migration::render_plan(&migration_plan);
                println!("{plan_md}");
                ExitCode::SUCCESS
            }
        }
    }
}

// Keep Severity referenced for the json writer.
#[allow(dead_code)]
fn _sev_name(s: Severity) -> &'static str {
    s.label()
}
