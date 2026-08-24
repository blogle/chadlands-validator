//! Validator configuration: baked-in Chadlands defaults plus an optional
//! YAML override file (`--config`, default discovery at
//! `00 System/Validation/validator.yml` inside the vault).

use std::collections::HashMap;
use std::path::Path;

use yaml_rust2::{Yaml, YamlLoader};

use crate::findings::Severity;
use crate::frontmatter::FmView;

/// A required field: either one key, or any one of several alternatives
/// (e.g. `owner/lead`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FieldRequirement {
    pub alternatives: Vec<String>,
}

impl FieldRequirement {
    pub fn single(name: &str) -> Self {
        FieldRequirement {
            alternatives: vec![name.to_string()],
        }
    }

    pub fn label(&self) -> String {
        self.alternatives.join("/")
    }

    pub fn satisfied_by(&self, has: &dyn Fn(&str) -> bool) -> bool {
        self.alternatives.iter().any(|a| has(a))
    }
}

#[derive(Debug, Clone)]
pub struct Config {
    pub report_path: String,
    pub boundary_path: String,
    pub exclude_dirs: Vec<String>,
    pub protected_prefixes: Vec<String>,
    pub chronicle_dir: String,
    pub chronicle_permitted_gaps: Vec<i64>,
    pub id_fields: Vec<String>,
    pub unresolved_values: Vec<String>,
    /// Required structural fields by canonical record type.
    pub required_fields: HashMap<String, Vec<FieldRequirement>>,
    /// Fields where an explicit unresolved marker (MISSING/UNKNOWN/...) is
    /// legal-but-WARN; on other required fields an unresolved marker is an
    /// ERROR.
    pub unresolved_permitted: HashMap<String, Vec<String>>,
    pub status_vocab: HashMap<String, Vec<String>>,
    pub type_to_vocab_class: HashMap<String, String>,
    pub required_sections: HashMap<String, Vec<String>>,
    pub severity_overrides: HashMap<String, Severity>,
    pub max_findings_per_rule: usize,
    pub debounce_ms: u64,
}

impl Default for Config {
    fn default() -> Self {
        let mut required_fields: HashMap<String, Vec<FieldRequirement>> = HashMap::new();
        let institution_req = vec![
            FieldRequirement {
                alternatives: vec!["owner".into(), "lead".into()],
            },
            FieldRequirement::single("second"),
            FieldRequirement::single("lifecycle"),
            FieldRequirement::single("last_confirmed_year"),
            FieldRequirement::single("reviewed_through_cursor"),
        ];
        required_fields.insert("institution".into(), institution_req.clone());
        required_fields.insert("service".into(), institution_req);
        let project_req = vec![
            FieldRequirement::single("owner"),
            FieldRequirement::single("lifecycle"),
            FieldRequirement::single("status"),
            FieldRequirement::single("reviewed_through_cursor"),
        ];
        required_fields.insert("project".into(), project_req.clone());
        required_fields.insert("venture".into(), project_req);
        let person_req = vec![
            FieldRequirement::single("status"),
            FieldRequirement::single("last_confirmed_year"),
            FieldRequirement::single("reviewed_through_cursor"),
        ];
        required_fields.insert("person".into(), person_req.clone());
        required_fields.insert("god".into(), person_req);

        let mut unresolved_permitted: HashMap<String, Vec<String>> = HashMap::new();
        for t in ["institution", "service"] {
            unresolved_permitted.insert(
                t.into(),
                vec!["owner".into(), "lead".into(), "second".into()],
            );
        }
        unresolved_permitted.insert("project".into(), vec!["owner".into()]);
        unresolved_permitted.insert("venture".into(), vec!["owner".into()]);

        let mut status_vocab: HashMap<String, Vec<String>> = HashMap::new();
        status_vocab.insert(
            "people".into(),
            vec![
                "active".into(),
                "last-confirmed".into(),
                "deceased".into(),
                "missing".into(),
                "protected".into(),
                "unknown".into(),
                "not-applicable".into(),
            ],
        );
        status_vocab.insert(
            "project".into(),
            vec![
                "draft".into(),
                "submitted".into(),
                "accepted".into(),
                "active".into(),
                "stalled".into(),
                "completed".into(),
                "failed".into(),
                "closed".into(),
                "superseded".into(),
                "unresolved".into(),
            ],
        );
        status_vocab.insert(
            "institution".into(),
            vec![
                "active".into(),
                "completed".into(),
                "closed".into(),
                "superseded".into(),
                "historical".into(),
                "deprecated".into(),
                "draft".into(),
            ],
        );

        let mut type_to_vocab_class: HashMap<String, String> = HashMap::new();
        for (t, c) in [
            ("person", "people"),
            ("god", "people"),
            ("institution", "institution"),
            ("service", "institution"),
            ("index", "institution"),
            ("register", "institution"),
            ("ledger", "institution"),
            ("doctrine", "institution"),
            ("policy", "institution"),
            ("project", "project"),
            ("venture", "project"),
            ("technology-node", "project"),
        ] {
            type_to_vocab_class.insert(t.into(), c.into());
        }

        let mut required_sections: HashMap<String, Vec<String>> = HashMap::new();
        required_sections.insert("runtime-handoff".into(), vec!["Boundary".into()]);

        Config {
            report_path: "00 System/Validation/Vault Health.md".into(),
            boundary_path: "00 System/State Boundary.md".into(),
            exclude_dirs: vec![
                ".git".into(),
                ".obsidian".into(),
                ".trash".into(),
                ".OBSIDIANTEST".into(),
            ],
            protected_prefixes: vec![
                "70 Sources/Telegram".into(),
                "70 Sources/Telegram Export".into(),
                "70 Sources/Codex Snapshots".into(),
                "70 Sources/Strategy Sessions/Raw Export".into(),
                "70 Sources/Legacy Source Pack".into(),
                "70 Sources/Player Relays".into(),
            ],
            chronicle_dir: "20 Chronicle".into(),
            chronicle_permitted_gaps: Vec::new(),
            id_fields: vec![
                "canonical_id".into(),
                "vault_node_id".into(),
                "permanent_registry_id".into(),
            ],
            unresolved_values: vec![
                "MISSING".into(),
                "UNKNOWN".into(),
                "UNASSIGNED".into(),
                "BLOCKED".into(),
            ],
            required_fields,
            unresolved_permitted,
            status_vocab,
            type_to_vocab_class,
            required_sections,
            severity_overrides: HashMap::new(),
            max_findings_per_rule: 25,
            debounce_ms: 750,
        }
    }
}

fn yaml_str_list(v: &Yaml) -> Vec<String> {
    match v {
        Yaml::Array(items) => items
            .iter()
            .filter_map(|i| i.as_str().map(String::from))
            .collect(),
        Yaml::String(s) => vec![s.clone()],
        _ => Vec::new(),
    }
}

fn field_requirements(v: &Yaml) -> Vec<FieldRequirement> {
    match v {
        Yaml::Array(items) => items
            .iter()
            .map(|i| match i {
                Yaml::String(s) => FieldRequirement::single(s),
                Yaml::Array(alts) => FieldRequirement {
                    alternatives: yaml_str_list(&Yaml::Array(alts.clone())),
                },
                _ => FieldRequirement {
                    alternatives: Vec::new(),
                },
            })
            .filter(|r| !r.alternatives.is_empty())
            .collect(),
        Yaml::String(s) => vec![FieldRequirement::single(s)],
        _ => Vec::new(),
    }
}

impl Config {
    /// Load overrides from a YAML file; absent keys keep defaults.
    pub fn load(path: &Path) -> Result<Config, String> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| format!("cannot read config {}: {e}", path.display()))?;
        let docs = YamlLoader::load_from_str(&text)
            .map_err(|e| format!("cannot parse config {}: {e}", path.display()))?;
        let doc = docs.into_iter().next().unwrap_or(Yaml::Null);
        let fm = FmView::new(&doc);
        let mut cfg = Config::default();

        if let Some(v) = fm.get_str("report_path") {
            cfg.report_path = v;
        }
        if let Some(v) = fm.get_str("boundary_path") {
            cfg.boundary_path = v;
        }
        if let Some(v) = fm.get_str("chronicle_dir") {
            cfg.chronicle_dir = v;
        }
        if let Some(d) = doc["exclude_dirs"].as_vec() {
            cfg.exclude_dirs = d.iter().filter_map(|y| y.as_str().map(String::from)).collect();
        }
        if let Some(d) = doc["protected_prefixes"].as_vec() {
            cfg.protected_prefixes =
                d.iter().filter_map(|y| y.as_str().map(String::from)).collect();
        }
        if let Some(d) = doc["chronicle_permitted_gaps"].as_vec() {
            cfg.chronicle_permitted_gaps = d.iter().filter_map(|y| y.as_i64()).collect();
        }
        if let Some(d) = doc["id_fields"].as_vec() {
            cfg.id_fields = d.iter().filter_map(|y| y.as_str().map(String::from)).collect();
        }
        if let Some(d) = doc["unresolved_values"].as_vec() {
            cfg.unresolved_values =
                d.iter().filter_map(|y| y.as_str().map(String::from)).collect();
        }
        if let Yaml::Hash(h) = &doc["required_fields"] {
            for (k, v) in h {
                if let Some(t) = k.as_str() {
                    cfg.required_fields.insert(t.to_string(), field_requirements(v));
                }
            }
        }
        if let Yaml::Hash(h) = &doc["unresolved_permitted"] {
            for (k, v) in h {
                if let Some(t) = k.as_str() {
                    cfg.unresolved_permitted.insert(t.to_string(), yaml_str_list(v));
                }
            }
        }
        if let Yaml::Hash(h) = &doc["status_vocab"] {
            for (k, v) in h {
                if let Some(t) = k.as_str() {
                    cfg.status_vocab.insert(t.to_string(), yaml_str_list(v));
                }
            }
        }
        if let Yaml::Hash(h) = &doc["type_to_vocab_class"] {
            for (k, v) in h {
                if let (Some(t), Some(c)) = (k.as_str(), v.as_str()) {
                    cfg.type_to_vocab_class.insert(t.to_string(), c.to_string());
                }
            }
        }
        if let Yaml::Hash(h) = &doc["required_sections"] {
            for (k, v) in h {
                if let Some(t) = k.as_str() {
                    cfg.required_sections.insert(t.to_string(), yaml_str_list(v));
                }
            }
        }
        if let Yaml::Hash(h) = &doc["severity_overrides"] {
            for (k, v) in h {
                if let (Some(rule), Some(sev)) = (k.as_str(), v.as_str()) {
                    if let Some(s) = Severity::parse(sev) {
                        cfg.severity_overrides.insert(rule.to_string(), s);
                    }
                }
            }
        }
        if let Some(n) = doc["max_findings_per_rule"].as_i64() {
            if n > 0 {
                cfg.max_findings_per_rule = n as usize;
            }
        }
        if let Some(n) = doc["debounce_ms"].as_i64() {
            if n >= 0 {
                cfg.debounce_ms = n as u64;
            }
        }
        Ok(cfg)
    }

    /// Load from an explicit path, else the vault-default location, else
    /// built-in defaults.
    pub fn resolve(explicit: Option<&Path>, vault_root: &Path) -> Result<Config, String> {
        if let Some(p) = explicit {
            return Config::load(p);
        }
        let default_path = vault_root.join("00 System/Validation/validator.yml");
        if default_path.exists() {
            Config::load(&default_path)
        } else {
            Ok(Config::default())
        }
    }

    pub fn severity_for(&self, rule: &'static str, default: Severity) -> Severity {
        self.severity_overrides
            .get(rule)
            .copied()
            .unwrap_or(default)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_have_spec_required_fields() {
        let c = Config::default();
        let inst = &c.required_fields["institution"];
        assert!(inst
            .iter()
            .any(|r| r.alternatives == vec!["owner".to_string(), "lead".to_string()]));
        assert!(inst.iter().any(|r| r.alternatives == ["second"]));
        assert!(c.required_fields.contains_key("project"));
        assert!(c.required_fields.contains_key("person"));
        assert!(c.status_vocab["people"].contains(&"last-confirmed".to_string()));
    }

    #[test]
    fn yaml_override_merges() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("validator.yml");
        std::fs::write(
            &p,
            "debounce_ms: 200\nseverity_overrides:\n  CHAD-LINK-001: info\nrequired_sections:\n  runtime-context-pack: [Boundary]\n",
        )
        .unwrap();
        let c = Config::load(&p).unwrap();
        assert_eq!(c.debounce_ms, 200);
        assert_eq!(
            c.severity_for("CHAD-LINK-001", Severity::Warn),
            Severity::Info
        );
        assert_eq!(
            c.required_sections["runtime-context-pack"],
            vec!["Boundary".to_string()]
        );
        // Untouched defaults survive.
        assert_eq!(c.chronicle_dir, "20 Chronicle");
    }
}
