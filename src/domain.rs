use std::collections::HashSet;

use crate::config::Config;
use crate::vault::{Note, VaultIndex};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum EntityKind {
    Portfolio,
    Road,
    Capability,
    Project,
    Venture,
    Institution,
    Service,
    Person,
    Place,
    Polity,
    Node,
    Register,
    Index,
    Unknown,
}

impl EntityKind {
    pub fn label(self) -> &'static str {
        match self {
            Self::Portfolio => "portfolio",
            Self::Road => "road",
            Self::Capability => "capability",
            Self::Project => "project",
            Self::Venture => "venture",
            Self::Institution => "institution",
            Self::Service => "service",
            Self::Person => "person",
            Self::Place => "place",
            Self::Polity => "polity",
            Self::Node => "node",
            Self::Register => "register",
            Self::Index => "index",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Representation {
    Modern,
    Legacy,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ExecutionState {
    Draft,
    Priced,
    Accepted,
    InProgress,
    Terminal,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Outcome {
    Succeeded,
    Failed,
    ClosedPartial,
    Superseded,
    Unknown,
}

pub fn kind_for_note(note: &Note, config: &Config) -> EntityKind {
    let type_name = note.type_str().unwrap_or_default();
    if config.portfolio_types.contains(&type_name) {
        return EntityKind::Portfolio;
    }
    if config.road_types.contains(&type_name) {
        return EntityKind::Road;
    }
    if config.capability_types.contains(&type_name) {
        return EntityKind::Capability;
    }
    if config.legacy_technology_types.contains(&type_name) {
        return EntityKind::Node;
    }
    match type_name.as_str() {
        "project" => EntityKind::Project,
        "venture" => EntityKind::Venture,
        "institution" => EntityKind::Institution,
        "service" | "operational-service" => EntityKind::Service,
        "person" | "god" => EntityKind::Person,
        "place" => EntityKind::Place,
        "polity" | "faction" => EntityKind::Polity,
        "register" | "ledger" => EntityKind::Register,
        "index" => EntityKind::Index,
        _ => EntityKind::Unknown,
    }
}

pub fn representation_for_kind(kind: EntityKind) -> Representation {
    match kind {
        EntityKind::Portfolio | EntityKind::Road | EntityKind::Capability => Representation::Modern,
        EntityKind::Node => Representation::Legacy,
        _ => Representation::Unknown,
    }
}

pub fn representation_for_note(note: &Note, config: &Config) -> Representation {
    representation_for_kind(kind_for_note(note, config))
}

pub fn execution_state_for_note(note: &Note) -> ExecutionState {
    let status = note.status().unwrap_or_default();
    match status.as_str() {
        "draft" | "pricing" | "proposed" => ExecutionState::Draft,
        "priced" => ExecutionState::Priced,
        "accepted" | "active" | "stalled" | "in-progress" => ExecutionState::Accepted,
        "completed" | "closed" | "failed" | "superseded" | "resolved" => ExecutionState::Terminal,
        _ => ExecutionState::Unknown,
    }
}

pub fn outcome_for_note(note: &Note) -> Outcome {
    let status = note.status().unwrap_or_default();
    let lifecycle = note.fm().get_str("lifecycle").unwrap_or_default();
    let lifecycle = lifecycle.to_ascii_lowercase();

    match status.as_str() {
        "completed" => Outcome::Succeeded,
        "failed" => Outcome::Failed,
        "superseded" => Outcome::Superseded,
        "closed" => {
            if lifecycle.contains("partial") {
                Outcome::ClosedPartial
            } else {
                Outcome::Failed
            }
        }
        _ => Outcome::Unknown,
    }
}

pub fn execution_state_for_kind(kind: EntityKind, state: ExecutionState) -> ExecutionState {
    if kind == EntityKind::Unknown {
        return state;
    }
    state
}

pub fn outcome_for_kind(kind: EntityKind, outcome: Outcome) -> Outcome {
    if kind == EntityKind::Unknown {
        return outcome;
    }
    outcome
}

pub struct EntitySummary {
    pub modern_portfolio_count: usize,
    pub modern_road_count: usize,
    pub modern_capability_count: usize,
    pub legacy_node_count: usize,
    pub modern_entity_count: usize,
    pub legacy_entity_count: usize,
}

pub fn count_entities(index: &VaultIndex, config: &Config) -> EntitySummary {
    let mut modern_portfolio_count = 0usize;
    let mut modern_road_count = 0usize;
    let mut modern_capability_count = 0usize;
    let mut legacy_node_count = 0usize;

    for note in &index.notes {
        if !note.curated || note.parse_error.is_some() {
            continue;
        }
        let kind = kind_for_note(note, config);
        match kind {
            EntityKind::Portfolio => modern_portfolio_count += 1,
            EntityKind::Road => modern_road_count += 1,
            EntityKind::Capability => modern_capability_count += 1,
            EntityKind::Node => legacy_node_count += 1,
            _ => {}
        }
    }

    EntitySummary {
        modern_portfolio_count,
        modern_road_count,
        modern_capability_count,
        legacy_node_count,
        modern_entity_count: modern_portfolio_count + modern_road_count + modern_capability_count,
        legacy_entity_count: legacy_node_count,
    }
}

pub fn canonical_road_ids(index: &VaultIndex, config: &Config) -> HashSet<String> {
    index
        .notes
        .iter()
        .filter(|n| n.curated && n.parse_error.is_none())
        .filter(|n| kind_for_note(n, config) == EntityKind::Road)
        .filter_map(|n| n.fm().get_str("road_id"))
        .collect()
}

pub fn canonical_capability_ids(index: &VaultIndex, config: &Config) -> HashSet<String> {
    index
        .notes
        .iter()
        .filter(|n| n.curated && n.parse_error.is_none())
        .filter(|n| kind_for_note(n, config) == EntityKind::Capability)
        .filter_map(|n| n.fm().get_str("capability_id"))
        .collect()
}

pub fn canonical_portfolio_ids(index: &VaultIndex, config: &Config) -> HashSet<String> {
    index
        .notes
        .iter()
        .filter(|n| n.curated && n.parse_error.is_none())
        .filter(|n| kind_for_note(n, config) == EntityKind::Portfolio)
        .filter_map(|n| n.fm().get_str("portfolio_id"))
        .collect()
}

pub fn all_canonical_ids(index: &VaultIndex, config: &Config) -> HashSet<String> {
    let mut ids = HashSet::new();
    for note in index
        .notes
        .iter()
        .filter(|n| n.curated && n.parse_error.is_none())
    {
        let fm = note.fm();
        for field in &config.id_fields {
            if let Some(v) = fm.get_str(field) {
                ids.insert(v);
            }
        }
        for field in &["road_id", "capability_id", "portfolio_id"] {
            if let Some(v) = fm.get_str(field) {
                ids.insert(v);
            }
        }
    }
    ids
}

pub fn has_canonical_id(note: &Note, config: &Config) -> bool {
    let fm = note.fm();
    for field in &config.id_fields {
        if fm.get_str(field).is_some() {
            return true;
        }
    }
    for field in &["road_id", "capability_id", "portfolio_id"] {
        if fm.get_str(field).is_some() {
            return true;
        }
    }
    false
}

pub fn has_ledger_id(note: &Note) -> bool {
    note.fm()
        .get_str("acceptance_id")
        .or_else(|| note.fm().get_str("ledger_id"))
        .or_else(|| note.fm().get_str("manifest_id"))
        .is_some()
}

pub fn has_player_reference(note: &Note) -> bool {
    note.fm().get_str("acceptance_id").is_some()
        || note.fm().get_str("proposal_id").is_some()
        || note.fm().get_str("player_reference").is_some()
}

pub fn requires_canonical_id(kind: EntityKind, execution: ExecutionState) -> bool {
    matches!(
        (kind, execution),
        (
            EntityKind::Portfolio | EntityKind::Road | EntityKind::Capability,
            ExecutionState::Accepted | ExecutionState::InProgress | ExecutionState::Terminal
        )
    )
}

pub fn requires_ledger_id(kind: EntityKind, execution: ExecutionState) -> bool {
    matches!(
        (kind, execution),
        (
            EntityKind::Portfolio | EntityKind::Road | EntityKind::Capability,
            ExecutionState::Accepted | ExecutionState::InProgress | ExecutionState::Terminal
        )
    )
}

pub fn requires_player_reference(kind: EntityKind, execution: ExecutionState) -> bool {
    matches!(
        (kind, execution),
        (
            EntityKind::Portfolio | EntityKind::Road | EntityKind::Capability,
            ExecutionState::Draft
                | ExecutionState::Priced
                | ExecutionState::Accepted
                | ExecutionState::InProgress
        )
    )
}
