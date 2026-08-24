//! Findings model: stable rule IDs, three severities, machine-readable.

use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Error = 0,
    Warn = 1,
    Info = 2,
}

impl Severity {
    pub fn parse(s: &str) -> Option<Severity> {
        match s.trim().to_ascii_lowercase().as_str() {
            "error" => Some(Severity::Error),
            "warn" | "warning" => Some(Severity::Warn),
            "info" => Some(Severity::Info),
            _ => None,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Severity::Error => "ERROR",
            Severity::Warn => "WARN",
            Severity::Info => "INFO",
        }
    }
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.label())
    }
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub rule: &'static str,
    pub severity: Severity,
    /// Vault-relative path of the offending note, when there is one.
    pub path: Option<String>,
    /// Self-contained message: includes what was expected, what was found,
    /// and valid values where applicable.
    pub message: String,
    /// One-line remediation hint: the canonical fix for this finding.
    pub remediation: &'static str,
    /// Dependency order: lower numbers should be fixed first.
    pub priority: u8,
}

impl Finding {
    pub fn new(
        rule: &'static str,
        severity: Severity,
        path: Option<&str>,
        message: String,
        remediation: &'static str,
        priority: u8,
    ) -> Self {
        Finding {
            rule,
            severity,
            path: path.map(String::from),
            message,
            remediation,
            priority,
        }
    }
}

/// A set of findings with severity accounting.
pub struct Findings {
    pub items: Vec<Finding>,
}

impl Findings {
    pub fn new(items: Vec<Finding>) -> Self {
        let mut f = Findings { items };
        f.sort();
        f
    }

    /// Sort by (severity, dependency priority, rule, path) so the LLM
    /// fixes prerequisites before downstream rules.
    fn sort(&mut self) {
        self.items.sort_by(|a, b| {
            (
                a.severity,
                a.priority,
                a.rule,
                a.path.clone().unwrap_or_default(),
            )
                .cmp(&(
                    b.severity,
                    b.priority,
                    b.rule,
                    b.path.clone().unwrap_or_default(),
                ))
        });
    }

    pub fn errors(&self) -> usize {
        self.items.iter().filter(|f| f.severity == Severity::Error).count()
    }

    pub fn warnings(&self) -> usize {
        self.items.iter().filter(|f| f.severity == Severity::Warn).count()
    }

    pub fn infos(&self) -> usize {
        self.items.iter().filter(|f| f.severity == Severity::Info).count()
    }
}
