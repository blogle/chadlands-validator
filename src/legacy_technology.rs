//! Bounded Chadlands compatibility adapter for the legacy six-road portfolio.
//!
//! Campaign-specific names live here rather than in generic validation rules.
//! Extraction is deterministic and retains the authority of the structure that
//! supplied each road name.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RoadNameSource {
    OtherConfiguredStructure,
    OwnershipTable,
    ExplicitChildIdentifier,
    DeclaredRoadList,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtractedRoad {
    pub name: String,
    pub source: RoadNameSource,
}

struct RoadDefinition {
    name: &'static str,
    identifiers: &'static [&'static str],
    labels: &'static [&'static str],
}

const ROADS: &[RoadDefinition] = &[
    RoadDefinition {
        name: "Steam",
        identifiers: &["steam"],
        labels: &["steam"],
    },
    RoadDefinition {
        name: "Cold-Hardy Grain",
        identifiers: &["cold-hardy-grain", "cold_hardy_grain"],
        labels: &["cold-hardy grain", "cold hardy grain"],
    },
    RoadDefinition {
        name: "Sampling & Error Bands",
        identifiers: &["sampling-and-error-bands", "sampling_error_bands"],
        labels: &["sampling and error bands", "sampling & error bands"],
    },
    RoadDefinition {
        name: "Irrigation off Gorge Water",
        identifiers: &["irrigation-off-gorge-water", "irrigation_off_gorge_water"],
        labels: &["irrigation off gorge water", "irrigation"],
    },
    RoadDefinition {
        name: "Managed Woodland",
        identifiers: &["managed-woodland", "managed_woodland"],
        labels: &["managed woodland"],
    },
    RoadDefinition {
        name: "Warehouse Receipts",
        identifiers: &["warehouse-receipts", "warehouse_receipts"],
        labels: &["warehouse receipts"],
    },
];

fn normalize(value: &str) -> String {
    value
        .to_ascii_lowercase()
        .replace('&', "and")
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { ' ' })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn is_numbered_item(line: &str) -> bool {
    let trimmed = line.trim_start();
    let digit_count = trimmed.chars().take_while(|c| c.is_ascii_digit()).count();
    digit_count > 0
        && matches!(
            trimmed.as_bytes().get(digit_count).copied(),
            Some(b'.' | b')')
        )
}

fn matches_definition(value: &str, definition: &RoadDefinition) -> bool {
    let normalized = normalize(value);
    definition
        .labels
        .iter()
        .map(|label| normalize(label))
        .any(|label| normalized == label || normalized.contains(&label))
}

fn candidate_for_line(line: &str) -> Option<usize> {
    let mut candidates: Vec<(usize, usize)> = ROADS
        .iter()
        .enumerate()
        .filter(|(_, definition)| matches_definition(line, definition))
        .map(|(index, definition)| {
            let longest = definition
                .labels
                .iter()
                .map(|label| normalize(label).len())
                .max()
                .unwrap_or(0);
            (index, longest)
        })
        .collect();
    candidates.sort_by_key(|(index, length)| (std::cmp::Reverse(*length), *index));
    candidates.first().map(|(index, _)| *index)
}

fn record_candidate(
    selected: &mut [Option<RoadNameSource>],
    road_index: usize,
    source: RoadNameSource,
) {
    if selected[road_index]
        .map(|current| source > current)
        .unwrap_or(true)
    {
        selected[road_index] = Some(source);
    }
}

/// Extract configured Chadlands legacy roads with explicit source precedence:
/// declared road list > explicit child identifiers > ownership table > other.
pub fn extract_roads(body: &str, road_ids: &[String]) -> Vec<ExtractedRoad> {
    let mut selected = vec![None; ROADS.len()];

    for line in body.lines().filter(|line| is_numbered_item(line)) {
        if let Some(index) = candidate_for_line(line) {
            record_candidate(&mut selected, index, RoadNameSource::DeclaredRoadList);
        }
    }

    for road_id in road_ids {
        let normalized_id = normalize(road_id);
        for (index, definition) in ROADS.iter().enumerate() {
            if definition
                .identifiers
                .iter()
                .any(|candidate| normalize(candidate) == normalized_id)
            {
                record_candidate(
                    &mut selected,
                    index,
                    RoadNameSource::ExplicitChildIdentifier,
                );
            }
        }
    }

    for line in body
        .lines()
        .filter(|line| line.trim_start().starts_with('|'))
    {
        if let Some(index) = candidate_for_line(line) {
            record_candidate(&mut selected, index, RoadNameSource::OwnershipTable);
        }
    }

    let normalized_body = normalize(body);
    for (index, definition) in ROADS.iter().enumerate() {
        if normalized_body.contains(&normalize(definition.name)) {
            record_candidate(
                &mut selected,
                index,
                RoadNameSource::OtherConfiguredStructure,
            );
        }
    }

    ROADS
        .iter()
        .zip(selected)
        .filter_map(|(definition, source)| {
            source.map(|source| ExtractedRoad {
                name: definition.name.to_string(),
                source,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_list_wins_over_shorter_ownership_label() {
        let body = "The six roads are:\n\n1. Steam;\n2. cold-hardy grain;\n3. sampling and error bands;\n4. irrigation off gorge water;\n5. managed woodland;\n6. warehouse receipts.\n\n| Road | Owner |\n|---|---|\n| Irrigation | Keeper |\n";
        let roads = extract_roads(body, &[]);

        assert_eq!(
            roads
                .iter()
                .map(|road| road.name.as_str())
                .collect::<Vec<_>>(),
            vec![
                "Steam",
                "Cold-Hardy Grain",
                "Sampling & Error Bands",
                "Irrigation off Gorge Water",
                "Managed Woodland",
                "Warehouse Receipts",
            ]
        );
        assert_eq!(
            roads
                .iter()
                .find(|road| road.name == "Irrigation off Gorge Water")
                .map(|road| road.source),
            Some(RoadNameSource::DeclaredRoadList)
        );
    }

    #[test]
    fn explicit_identifier_outranks_ownership_table() {
        let roads = extract_roads(
            "| Road | Owner |\n|---|---|\n| Irrigation | Keeper |\n",
            &["irrigation-off-gorge-water".to_string()],
        );
        assert_eq!(roads[0].name, "Irrigation off Gorge Water");
        assert_eq!(roads[0].source, RoadNameSource::ExplicitChildIdentifier);
    }
}
