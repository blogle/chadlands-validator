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
        .filter_map(|n| n.fm().get_str("road_id").map(|id| id.trim().to_string()))
        .filter(|id| !id.is_empty())
        .collect()
}

pub fn canonical_capability_ids(index: &VaultIndex, config: &Config) -> HashSet<String> {
    index
        .notes
        .iter()
        .filter(|n| n.curated && n.parse_error.is_none())
        .filter(|n| kind_for_note(n, config) == EntityKind::Capability)
        .filter_map(|n| {
            n.fm()
                .get_str("capability_id")
                .map(|id| id.trim().to_string())
        })
        .filter(|id| !id.is_empty())
        .collect()
}

pub fn canonical_portfolio_ids(index: &VaultIndex, config: &Config) -> HashSet<String> {
    index
        .notes
        .iter()
        .filter(|n| n.curated && n.parse_error.is_none())
        .filter(|n| kind_for_note(n, config) == EntityKind::Portfolio)
        .filter_map(|n| {
            n.fm()
                .get_str("portfolio_id")
                .map(|id| id.trim().to_string())
        })
        .filter(|id| !id.is_empty())
        .collect()
}
