//! Validation rules. Each rule module is pure: it reads the index, the
//! boundary, and manifests, and returns findings. No rule mutates the vault.

pub mod cursor;
pub mod freshness;
pub mod hygiene;
pub mod identity;
pub mod meta;
pub mod owner;
pub mod year;

use crate::boundary::StateBoundary;
use crate::config::Config;
use crate::findings::{Finding, Severity};
use crate::manifest::Manifest;
use crate::source_index::SourceIndex;
use crate::vault::VaultIndex;

pub struct RuleContext<'a> {
    pub index: &'a VaultIndex,
    pub config: &'a Config,
    pub boundary: &'a StateBoundary,
    pub manifests: &'a [Manifest],
    pub source_index: Option<&'a SourceIndex>,
}

impl<'a> RuleContext<'a> {
    pub fn sev(&self, rule: &'static str, default: Severity) -> Severity {
        self.config.severity_for(rule, default)
    }
}

/// Convenience constructor: looks up remediation and priority from the
/// rule metadata table automatically.
pub fn finding(
    rule: &'static str,
    severity: Severity,
    path: Option<&str>,
    message: String,
) -> Finding {
    let m = meta::lookup(rule);
    Finding::new(rule, severity, path, message, m.remediation, m.priority)
}

pub fn run_all(ctx: &RuleContext) -> Vec<Finding> {
    let mut out = Vec::new();
    out.extend(year::check(ctx));
    out.extend(freshness::check(ctx));
    out.extend(owner::check(ctx));
    out.extend(cursor::check(ctx));
    out.extend(identity::check(ctx));
    out.extend(hygiene::check(ctx));
    // New technology/continuity rules
    out.extend(crate::technology::check(ctx));
    out.extend(crate::receipts::check(ctx, ctx.source_index));
    out.extend(crate::capability::check(ctx, ctx.source_index));
    out.extend(crate::coverage::check(ctx, ctx.source_index));
    out
}
