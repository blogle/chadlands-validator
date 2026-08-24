//! File-watch mode: debounced validation after curated vault files change,
//! regenerating the durable health report. The report directory and other
//! validator outputs are excluded from the trigger set, so report writes
//! never recursively re-trigger validation.

use std::path::{Path, PathBuf};
use std::sync::mpsc::channel;
use std::time::Duration;

use notify::{EventKind, RecursiveMode, Watcher};

use crate::config::Config;
use crate::findings::Severity;
use crate::rules::hygiene::check_protected_paths;

fn interesting(path: &Path, vault_root: &Path, config: &Config) -> bool {
    if path.extension().and_then(|e| e.to_str()) != Some("md") {
        return false;
    }
    let rel = match path.strip_prefix(vault_root) {
        Ok(r) => r,
        Err(_) => return false,
    };
    for comp in rel.components() {
        let s = comp.as_os_str().to_string_lossy();
        if config.exclude_dirs.iter().any(|e| e == &s) {
            return false;
        }
    }
    let report = Path::new(&config.report_path);
    if rel == report {
        return false;
    }
    if let Some(parent) = report.parent() {
        if parent != Path::new("") && rel.starts_with(parent) {
            return false;
        }
    }
    true
}

fn now_hms() -> String {
    use time::macros::format_description;
    time::OffsetDateTime::now_utc()
        .format(format_description!("[hour]:[minute]:[second]"))
        .unwrap_or_default()
}

fn run_pass(vault_root: &Path, config: &Config, changed: &[String]) {
    match crate::validate_and_report(vault_root, config, changed) {
        Ok(outcome) => {
            let f = &outcome.findings;
            println!(
                "[{}] validated {} files at {}: {} errors, {} warnings, {} infos -> {}",
                now_hms(),
                outcome.files_checked,
                outcome.boundary.vault_revision,
                f.errors(),
                f.warnings(),
                f.infos(),
                config.report_path
            );
        }
        Err(e) => eprintln!("[{}] validation failed to run: {e}", now_hms()),
    }
}

fn collect(res: Option<notify::Result<notify::Event>>, acc: &mut Vec<PathBuf>) {
    if let Some(Ok(event)) = res {
        if matches!(
            event.kind,
            EventKind::Create(_) | EventKind::Modify(_) | EventKind::Remove(_)
        ) {
            for p in event.paths {
                acc.push(p);
            }
        }
    }
}

pub fn watch(vault_root: &Path, config: &Config) -> Result<(), String> {
    let (tx, rx) = channel();
    let mut watcher = notify::recommended_watcher(move |res| {
        let _ = tx.send(res);
    })
    .map_err(|e| format!("cannot start watcher: {e}"))?;
    watcher
        .watch(vault_root, RecursiveMode::Recursive)
        .map_err(|e| format!("cannot watch {}: {e}", vault_root.display()))?;

    println!(
        "chadlands-validator watching {} (debounce {}ms, report `{}`)",
        vault_root.display(),
        config.debounce_ms,
        config.report_path
    );
    run_pass(vault_root, config, &[]);

    loop {
        // Block for the first event, then debounce: wait until the event
        // stream has been quiet for the debounce window.
        let first = rx.recv();
        if first.is_err() {
            return Err("watcher channel closed".to_string());
        }
        let mut changed: Vec<PathBuf> = Vec::new();
        collect(first.ok(), &mut changed);
        loop {
            match rx.recv_timeout(Duration::from_millis(config.debounce_ms)) {
                Ok(res) => collect(Some(res), &mut changed),
                Err(_) => break, // quiet window reached
            }
        }

        let touched: Vec<String> = changed
            .iter()
            .filter(|p| interesting(p, vault_root, config))
            .filter_map(|p| p.strip_prefix(vault_root).ok())
            .map(|p| p.to_string_lossy().replace('\\', "/"))
            .collect();
        if touched.is_empty() {
            continue;
        }

        // In watch mode the actor is unknown: protected-path writes are WARN.
        let protected: Vec<String> = touched
            .iter()
            .filter(|p| {
                config
                    .protected_prefixes
                    .iter()
                    .any(|pre| p.starts_with(pre.as_str()))
            })
            .cloned()
            .collect();
        if !protected.is_empty() {
            for finding in check_protected_paths(&protected, config, Severity::Warn) {
                eprintln!(
                    "[{}] {} {} {}",
                    now_hms(),
                    finding.rule,
                    finding.path.unwrap_or_default(),
                    finding.message
                );
            }
        }

        run_pass(vault_root, config, &[]);
    }
}
