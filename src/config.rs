//! Validator configuration: baked-in Chadlands defaults plus an optional
//! YAML override file (`--config`, default discovery at
//! `00 System/Validation/validator.yml` inside the vault).

use std::collections::HashMap;
use std::path::Path;

use yaml_rust2::{Yaml, YamlLoader};

use crate::boundary::fnv1a;
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
    pub continuity_report_path: String,
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
    // --- Source index configuration ---
    pub direct_source_prefixes: Vec<String>,
    pub player_speakers: Vec<String>,
    pub dm_speakers: Vec<String>,
    // --- Identity configuration ---
    pub tracked_types: Vec<String>,
    pub ignored_aliases: Vec<String>,
    // --- Continuity thresholds ---
    pub mention_dormancy_years: Option<f64>,
    pub mention_dormancy_turns: Option<i64>,
    pub material_dormancy_years: Option<f64>,
    pub material_dormancy_turns: Option<i64>,
    pub capability_dormancy_years: Option<f64>,
    // --- Continuity rendered limits ---
    pub max_resurfacing: usize,
    pub max_receipts: usize,
    pub max_capabilities: usize,
    pub max_coverage_candidates: usize,
    pub max_legacy_debt: usize,
    // --- Technology configuration ---
    pub portfolio_types: Vec<String>,
    pub road_types: Vec<String>,
    pub capability_types: Vec<String>,
    pub legacy_technology_types: Vec<String>,
    // --- Receipt authority ---
    pub receipt_authority_player: Vec<String>,
    pub receipt_authority_dm: Vec<String>,
    // --- Coverage configuration ---
    pub proper_name_min_occurrences: usize,
    pub proper_name_min_distinct_messages: usize,
    pub lifecycle_terms: Vec<String>,
    pub role_phrases: Vec<String>,
    // --- Frontmatter migration ---
    pub migration_rules: Vec<String>,
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
                "unresolved".into(),
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
        status_vocab.insert(
            "index".into(),
            vec![
                "active".into(),
                "active-navigation-current".into(),
                "completed".into(),
                "closed".into(),
                "superseded".into(),
                "historical".into(),
                "deprecated".into(),
                "draft".into(),
                "provisional".into(),
            ],
        );
        status_vocab.insert(
            "register".into(),
            vec![
                "active".into(),
                "in-progress".into(),
                "completed".into(),
                "closed".into(),
                "superseded".into(),
                "historical".into(),
                "deprecated".into(),
                "draft".into(),
            ],
        );
        status_vocab.insert(
            "doctrine".into(),
            vec![
                "active".into(),
                "standing".into(),
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
            ("index", "index"),
            ("register", "register"),
            ("ledger", "register"),
            ("doctrine", "doctrine"),
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
            continuity_report_path: "00 System/Validation/Continuity Report.md".into(),
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
            // Source index
            direct_source_prefixes: vec!["70 Sources/Telegram/Player".into()],
            player_speakers: vec![],
            dm_speakers: vec!["the_mud_lounge_bot".into()],
            // Identity
            tracked_types: vec![
                "person".into(),
                "institution".into(),
                "project".into(),
                "venture".into(),
                "technology-road".into(),
                "capability".into(),
                "technology-portfolio".into(),
                "place".into(),
                "polity".into(),
            ],
            ignored_aliases: Vec::new(),
            // Continuity thresholds
            mention_dormancy_years: Some(2.0),
            mention_dormancy_turns: None,
            material_dormancy_years: Some(3.0),
            material_dormancy_turns: None,
            capability_dormancy_years: Some(3.0),
            // Continuity rendered limits
            max_resurfacing: 12,
            max_receipts: 12,
            max_capabilities: 10,
            max_coverage_candidates: 20,
            max_legacy_debt: 20,
            // Technology
            portfolio_types: vec!["technology-portfolio".into()],
            road_types: vec!["technology-road".into()],
            capability_types: vec!["capability".into()],
            legacy_technology_types: vec!["technology-node".into()],
            // Receipt authority
            receipt_authority_player: vec!["ACCEPT".into(), "PROGRESS".into(), "PARTIAL".into()],
            receipt_authority_dm: vec![
                "ACCEPT".into(),
                "PROGRESS".into(),
                "PARTIAL".into(),
                "TERMINAL".into(),
                "USE".into(),
                "PORTFOLIO".into(),
            ],
            // Coverage
            proper_name_min_occurrences: 2,
            proper_name_min_distinct_messages: 2,
            lifecycle_terms: vec![
                "executing".into(),
                "accepted".into(),
                "priced".into(),
                "completed".into(),
                "terminal".into(),
            ],
            role_phrases: vec![
                "lead".into(),
                "owner".into(),
                "second".into(),
                "custodian".into(),
            ],
            // Migration
            migration_rules: Vec::new(),
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
            cfg.exclude_dirs = d
                .iter()
                .filter_map(|y| y.as_str().map(String::from))
                .collect();
        }
        if let Some(d) = doc["protected_prefixes"].as_vec() {
            cfg.protected_prefixes = d
                .iter()
                .filter_map(|y| y.as_str().map(String::from))
                .collect();
        }
        if let Some(d) = doc["chronicle_permitted_gaps"].as_vec() {
            cfg.chronicle_permitted_gaps = d.iter().filter_map(|y| y.as_i64()).collect();
        }
        if let Some(d) = doc["id_fields"].as_vec() {
            cfg.id_fields = d
                .iter()
                .filter_map(|y| y.as_str().map(String::from))
                .collect();
        }
        if let Some(d) = doc["unresolved_values"].as_vec() {
            cfg.unresolved_values = d
                .iter()
                .filter_map(|y| y.as_str().map(String::from))
                .collect();
        }
        if let Yaml::Hash(h) = &doc["required_fields"] {
            for (k, v) in h {
                if let Some(t) = k.as_str() {
                    cfg.required_fields
                        .insert(t.to_string(), field_requirements(v));
                }
            }
        }
        if let Yaml::Hash(h) = &doc["unresolved_permitted"] {
            for (k, v) in h {
                if let Some(t) = k.as_str() {
                    cfg.unresolved_permitted
                        .insert(t.to_string(), yaml_str_list(v));
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
                    cfg.required_sections
                        .insert(t.to_string(), yaml_str_list(v));
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
        // --- Source index ---
        if let Some(v) = fm.get_str("continuity_report_path") {
            cfg.continuity_report_path = v;
        }
        if let Some(d) = doc["direct_source_prefixes"].as_vec() {
            cfg.direct_source_prefixes = d
                .iter()
                .filter_map(|y| y.as_str().map(String::from))
                .collect();
        }
        if let Some(d) = doc["player_speakers"].as_vec() {
            cfg.player_speakers = d
                .iter()
                .filter_map(|y| y.as_str().map(String::from))
                .collect();
        }
        if let Some(d) = doc["dm_speakers"].as_vec() {
            cfg.dm_speakers = d
                .iter()
                .filter_map(|y| y.as_str().map(String::from))
                .collect();
        }
        // --- Identity ---
        if let Some(d) = doc["tracked_types"].as_vec() {
            cfg.tracked_types = d
                .iter()
                .filter_map(|y| y.as_str().map(String::from))
                .collect();
        }
        if let Some(d) = doc["ignored_aliases"].as_vec() {
            cfg.ignored_aliases = d
                .iter()
                .filter_map(|y| y.as_str().map(String::from))
                .collect();
        }
        // --- Continuity thresholds ---
        if let Some(v) = doc["mention_dormancy_years"].as_f64() {
            cfg.mention_dormancy_years = Some(v);
        }
        if let Some(v) = doc["mention_dormancy_turns"].as_i64() {
            cfg.mention_dormancy_turns = Some(v);
        }
        if let Some(v) = doc["material_dormancy_years"].as_f64() {
            cfg.material_dormancy_years = Some(v);
        }
        if let Some(v) = doc["material_dormancy_turns"].as_i64() {
            cfg.material_dormancy_turns = Some(v);
        }
        if let Some(v) = doc["capability_dormancy_years"].as_f64() {
            cfg.capability_dormancy_years = Some(v);
        }
        // --- Continuity rendered limits ---
        if let Some(n) = doc["max_resurfacing"].as_i64() {
            if n > 0 {
                cfg.max_resurfacing = n as usize;
            }
        }
        if let Some(n) = doc["max_receipts"].as_i64() {
            if n > 0 {
                cfg.max_receipts = n as usize;
            }
        }
        if let Some(n) = doc["max_capabilities"].as_i64() {
            if n > 0 {
                cfg.max_capabilities = n as usize;
            }
        }
        if let Some(n) = doc["max_coverage_candidates"].as_i64() {
            if n > 0 {
                cfg.max_coverage_candidates = n as usize;
            }
        }
        if let Some(n) = doc["max_legacy_debt"].as_i64() {
            if n > 0 {
                cfg.max_legacy_debt = n as usize;
            }
        }
        // --- Technology ---
        if let Some(d) = doc["portfolio_types"].as_vec() {
            cfg.portfolio_types = d
                .iter()
                .filter_map(|y| y.as_str().map(String::from))
                .collect();
        }
        if let Some(d) = doc["road_types"].as_vec() {
            cfg.road_types = d
                .iter()
                .filter_map(|y| y.as_str().map(String::from))
                .collect();
        }
        if let Some(d) = doc["capability_types"].as_vec() {
            cfg.capability_types = d
                .iter()
                .filter_map(|y| y.as_str().map(String::from))
                .collect();
        }
        if let Some(d) = doc["legacy_technology_types"].as_vec() {
            cfg.legacy_technology_types = d
                .iter()
                .filter_map(|y| y.as_str().map(String::from))
                .collect();
        }
        // --- Receipt authority ---
        if let Some(d) = doc["receipt_authority_player"].as_vec() {
            cfg.receipt_authority_player = d
                .iter()
                .filter_map(|y| y.as_str().map(String::from))
                .collect();
        }
        if let Some(d) = doc["receipt_authority_dm"].as_vec() {
            cfg.receipt_authority_dm = d
                .iter()
                .filter_map(|y| y.as_str().map(String::from))
                .collect();
        }
        // --- Coverage ---
        if let Some(n) = doc["proper_name_min_occurrences"].as_i64() {
            if n > 0 {
                cfg.proper_name_min_occurrences = n as usize;
            }
        }
        if let Some(n) = doc["proper_name_min_distinct_messages"].as_i64() {
            if n > 0 {
                cfg.proper_name_min_distinct_messages = n as usize;
            }
        }
        if let Some(d) = doc["lifecycle_terms"].as_vec() {
            cfg.lifecycle_terms = d
                .iter()
                .filter_map(|y| y.as_str().map(String::from))
                .collect();
        }
        if let Some(d) = doc["role_phrases"].as_vec() {
            cfg.role_phrases = d
                .iter()
                .filter_map(|y| y.as_str().map(String::from))
                .collect();
        }
        // --- Migration ---
        if let Some(d) = doc["migration_rules"].as_vec() {
            cfg.migration_rules = d
                .iter()
                .filter_map(|y| y.as_str().map(String::from))
                .collect();
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

    /// Deterministic fingerprint of the effective configuration.
    /// Covers all fields that affect validation output. Used for
    /// delta provenance: changes to config produce a different fingerprint.
    pub fn fingerprint(&self) -> String {
        fn frame(target: &mut Vec<u8>, key: &str, value: &[u8]) {
            target.extend_from_slice(&(key.len() as u64).to_le_bytes());
            target.extend_from_slice(key.as_bytes());
            target.extend_from_slice(&(value.len() as u64).to_le_bytes());
            target.extend_from_slice(value);
        }
        fn strings(values: &[String]) -> Vec<u8> {
            let mut out = Vec::new();
            for value in values {
                frame(&mut out, "item", value.as_bytes());
            }
            out
        }
        fn integers(values: &[i64]) -> Vec<u8> {
            let mut out = Vec::new();
            for value in values {
                frame(&mut out, "item", &value.to_le_bytes());
            }
            out
        }
        fn string_map(values: &HashMap<String, String>) -> Vec<u8> {
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort();
            let mut out = Vec::new();
            for key in keys {
                frame(&mut out, key, values[key].as_bytes());
            }
            out
        }
        fn list_map(values: &HashMap<String, Vec<String>>) -> Vec<u8> {
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort();
            let mut out = Vec::new();
            for key in keys {
                frame(&mut out, key, &strings(&values[key]));
            }
            out
        }

        let mut data = b"chadlands-validator-config-v1".to_vec();
        macro_rules! text {
            ($field:ident) => {
                frame(&mut data, stringify!($field), self.$field.as_bytes())
            };
        }
        macro_rules! list {
            ($field:ident) => {
                frame(&mut data, stringify!($field), &strings(&self.$field))
            };
        }
        macro_rules! number {
            ($field:ident) => {
                frame(
                    &mut data,
                    stringify!($field),
                    &(self.$field as u64).to_le_bytes(),
                )
            };
        }

        text!(report_path);
        text!(boundary_path);
        text!(continuity_report_path);
        list!(exclude_dirs);
        list!(protected_prefixes);
        text!(chronicle_dir);
        frame(
            &mut data,
            "chronicle_permitted_gaps",
            &integers(&self.chronicle_permitted_gaps),
        );
        list!(id_fields);
        list!(unresolved_values);

        let mut required_keys: Vec<_> = self.required_fields.keys().collect();
        required_keys.sort();
        let mut required = Vec::new();
        for key in required_keys {
            let mut requirements = Vec::new();
            for requirement in &self.required_fields[key] {
                frame(
                    &mut requirements,
                    "requirement",
                    &strings(&requirement.alternatives),
                );
            }
            frame(&mut required, key, &requirements);
        }
        frame(&mut data, "required_fields", &required);
        frame(
            &mut data,
            "unresolved_permitted",
            &list_map(&self.unresolved_permitted),
        );
        frame(&mut data, "status_vocab", &list_map(&self.status_vocab));
        frame(
            &mut data,
            "type_to_vocab_class",
            &string_map(&self.type_to_vocab_class),
        );
        frame(
            &mut data,
            "required_sections",
            &list_map(&self.required_sections),
        );

        let mut severity_keys: Vec<_> = self.severity_overrides.keys().collect();
        severity_keys.sort();
        let mut severities = Vec::new();
        for key in severity_keys {
            frame(
                &mut severities,
                key,
                self.severity_overrides[key].label().as_bytes(),
            );
        }
        frame(&mut data, "severity_overrides", &severities);

        number!(max_findings_per_rule);
        number!(debounce_ms);
        list!(direct_source_prefixes);
        list!(player_speakers);
        list!(dm_speakers);
        list!(tracked_types);
        list!(ignored_aliases);

        for (key, value) in [
            ("mention_dormancy_years", self.mention_dormancy_years),
            ("material_dormancy_years", self.material_dormancy_years),
            ("capability_dormancy_years", self.capability_dormancy_years),
        ] {
            match value {
                Some(value) => frame(
                    &mut data,
                    key,
                    &[b"some:".as_slice(), &value.to_bits().to_le_bytes()].concat(),
                ),
                None => frame(&mut data, key, b"none"),
            }
        }
        for (key, value) in [
            ("mention_dormancy_turns", self.mention_dormancy_turns),
            ("material_dormancy_turns", self.material_dormancy_turns),
        ] {
            match value {
                Some(value) => frame(
                    &mut data,
                    key,
                    &[b"some:".as_slice(), &value.to_le_bytes()].concat(),
                ),
                None => frame(&mut data, key, b"none"),
            }
        }

        number!(max_resurfacing);
        number!(max_receipts);
        number!(max_capabilities);
        number!(max_coverage_candidates);
        number!(max_legacy_debt);
        list!(portfolio_types);
        list!(road_types);
        list!(capability_types);
        list!(legacy_technology_types);
        list!(receipt_authority_player);
        list!(receipt_authority_dm);
        number!(proper_name_min_occurrences);
        number!(proper_name_min_distinct_messages);
        list!(lifecycle_terms);
        list!(role_phrases);
        list!(migration_rules);

        format!("{:016x}", fnv1a(&data, 0xcbf29ce484222325))
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

    #[test]
    fn fingerprint_is_stable_and_distinguishes_none_from_zero() {
        let base = Config::default();
        assert_eq!(base.fingerprint(), base.clone().fingerprint());

        let mut none = base.clone();
        none.mention_dormancy_turns = None;
        let mut zero = base.clone();
        zero.mention_dormancy_turns = Some(0);
        assert_ne!(none.fingerprint(), zero.fingerprint());
    }

    #[test]
    fn fingerprint_covers_all_previously_omitted_effective_fields() {
        let base = Config::default();
        let expected = base.fingerprint();
        macro_rules! changes {
            ($mutation:expr) => {{
                let mut changed = base.clone();
                $mutation(&mut changed);
                assert_ne!(expected, changed.fingerprint());
            }};
        }

        changes!(|config: &mut Config| config.chronicle_permitted_gaps.push(99));
        changes!(|config: &mut Config| config
            .unresolved_permitted
            .entry("person".into())
            .or_default()
            .push("owner".into()));
        changes!(|config: &mut Config| {
            config
                .type_to_vocab_class
                .insert("new".into(), "project".into());
        });
        changes!(|config: &mut Config| config
            .required_sections
            .entry("new".into())
            .or_default()
            .push("Boundary".into()));
        changes!(|config: &mut Config| config.max_resurfacing += 1);
        changes!(|config: &mut Config| config.max_receipts += 1);
        changes!(|config: &mut Config| config.max_capabilities += 1);
        changes!(|config: &mut Config| config.max_coverage_candidates += 1);
        changes!(|config: &mut Config| config.max_legacy_debt += 1);
        changes!(|config: &mut Config| config.proper_name_min_occurrences += 1);
        changes!(|config: &mut Config| config.proper_name_min_distinct_messages += 1);
    }
}
