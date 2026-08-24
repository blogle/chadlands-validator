//! Static rule metadata: human-readable descriptions, remediation hints,
//! and dependency ordering for report generation.

use std::collections::HashMap;
use std::sync::LazyLock;

/// Metadata for a single validation rule.
pub struct RuleMeta {
    pub id: &'static str,
    /// One-line description shown in report headings.
    pub description: &'static str,
    /// One-line remediation hint: the canonical fix.
    pub remediation: &'static str,
    /// Dependency order: lower numbers should be fixed first. Rules with
    /// the same order are peers.
    pub priority: u8,
}

macro_rules! rule {
    ($id:expr, $desc:expr, $rem:expr, $pri:expr) => {
        RuleMeta {
            id: $id,
            description: $desc,
            remediation: $rem,
            priority: $pri,
        }
    };
}

/// All known rules, in dependency order.
static RULES: &[RuleMeta] = &[
    // --- 1: parse/structural prerequisites ---
    rule!(
        "CHAD-SCHEMA-001",
        "unparseable or missing frontmatter",
        "Add valid YAML frontmatter between `---` fences with at least `type` and `status`.",
        1
    ),
    rule!(
        "CHAD-SCHEMA-002",
        "missing required common field",
        "Add the missing field. Valid `status` values depend on the record type (see CHAD-SCHEMA-003).",
        2
    ),
    rule!(
        "CHAD-SCHEMA-003",
        "status vocabulary violation",
        "Set `status` to one of the bounded values for the record's type class.",
        3
    ),
    rule!(
        "CHAD-SCHEMA-004",
        "lifecycle date ordering violation",
        "Ensure earlier dates (first_known_year, birth_year) do not exceed later dates (last_confirmed_year, completed_year).",
        3
    ),
    rule!(
        "CHAD-SCHEMA-005",
        "missing required named section",
        "Add the required `## Heading` section to the record body.",
        4
    ),
    // --- 2: state boundary ---
    rule!(
        "CHAD-STATE-001",
        "state boundary not exposed (derived from runtime)",
        "Create `00 System/State Boundary.md` with the required keys: current_turn, current_year, last_resolved_year, current_source_cursor, canonical_materialized_cursor.",
        10
    ),
    rule!(
        "CHAD-STATE-002",
        "canonical materialization frontier undeclared",
        "Create a reconciliation manifest or add `canonical_materialized_cursor` to the state boundary.",
        10
    ),
    rule!(
        "CHAD-STATE-003",
        "state boundary missing required key",
        "Add the missing key to the state boundary file.",
        10
    ),
    rule!(
        "CHAD-STATE-004",
        "state boundary internal inconsistency",
        "Ensure last_resolved_year <= current_year and canonical_materialized_cursor <= current_source_cursor.",
        10
    ),
    // --- 3: year coverage ---
    rule!(
        "CHAD-YEAR-001",
        "last_resolved_year exceeds highest Chronicle year",
        "Create Chronicle year records for the missing years, or lower last_resolved_year to match the highest existing Chronicle year.",
        20
    ),
    rule!(
        "CHAD-YEAR-002",
        "resolved Chronicle year beyond declared boundary",
        "Either advance last_resolved_year in the boundary, or mark the Chronicle year as unresolved.",
        20
    ),
    rule!(
        "CHAD-YEAR-003",
        "future evidence year value",
        "Correct the year field to not exceed current_year, or move the field to a target/review field if it describes a future plan.",
        20
    ),
    rule!(
        "CHAD-YEAR-004",
        "Chronicle gap in resolved range",
        "Create the missing Chronicle year record, or add the year to chronicle_permitted_gaps in the validator config.",
        20
    ),
    rule!(
        "CHAD-YEAR-005",
        "Chronicle year field/filename mismatch",
        "Align the frontmatter `year` field with the filename `Year N.md`.",
        21
    ),
    // --- 4: cursor hygiene ---
    rule!(
        "CHAD-CURSOR-001",
        "source_cursor exceeds reviewed_through_cursor",
        "Either advance reviewed_through_cursor past source_cursor (after actually reviewing the range), or correct source_cursor.",
        30
    ),
    rule!(
        "CHAD-CURSOR-002",
        "cursor beyond current_source_cursor (future cursor)",
        "Correct the cursor value to not exceed the vault's actual evidence frontier.",
        30
    ),
    rule!(
        "CHAD-CURSOR-003",
        "canonical note at/above manifest frontier missing from manifest",
        "Add the note as a subject to the reconciliation manifest with disposition UPDATED or REVIEWED — NO MATERIAL CHANGE.",
        31
    ),
    rule!(
        "CHAD-CURSOR-004",
        "manifest subject below frontier after claimed disposition",
        "Advance the note's reviewed_through_cursor to at least the manifest's materialized_cursor, or correct the manifest disposition.",
        31
    ),
    rule!(
        "CHAD-CURSOR-005",
        "runtime materialization claim beyond canonical support",
        "Ensure the runtime handoff's materialization cursor does not exceed the canonical_materialized_cursor in the boundary.",
        31
    ),
    rule!(
        "CHAD-CURSOR-006",
        "invalid or duplicate manifest subject/disposition",
        "Fix the manifest: each subject needs a unique path and exactly one of UPDATED, REVIEWED — NO MATERIAL CHANGE, BLOCKED — EXTERNAL.",
        31
    ),
    rule!(
        "CHAD-CURSOR-007",
        "BLOCKED — EXTERNAL without reason",
        "Add a `reason` field to the BLOCKED — EXTERNAL subject in the manifest.",
        31
    ),
    rule!(
        "CHAD-CURSOR-008",
        "manifest cursor exceeds evidence frontier",
        "Ensure the manifest's materialized_cursor does not exceed current_source_cursor or its own source_cursor.",
        31
    ),
    rule!(
        "CHAD-CURSOR-009",
        "manifest subject path does not resolve",
        "Correct the path in the manifest to match an existing vault note.",
        31
    ),
    // --- 5: freshness (depends on cursor/boundary) ---
    rule!(
        "CHAD-FRESH-001",
        "active canonical reviewed_through below materialized cursor",
        "Reconcile the record through the current materialization frontier, or mark it BLOCKED — EXTERNAL with a reason.",
        40
    ),
    rule!(
        "CHAD-FRESH-002",
        "active canonical missing reviewed_through_cursor",
        "Add reviewed_through_cursor after reviewing the record against the current evidence frontier.",
        40
    ),
    // --- 6: owner completeness ---
    rule!(
        "CHAD-OWNER-001",
        "missing required structural field",
        "Add the missing field to the canonical record's frontmatter.",
        50
    ),
    rule!(
        "CHAD-OWNER-002",
        "unresolved value where schema permits",
        "The field is explicitly unresolved (MISSING/UNKNOWN/UNASSIGNED/BLOCKED). Resolve it when evidence is available.",
        51
    ),
    rule!(
        "CHAD-OWNER-003",
        "unresolved value where schema requires resolution",
        "The field must be resolved. Set it to a concrete value from the available evidence.",
        51
    ),
    // --- 7: identity ---
    rule!(
        "CHAD-IDENTITY-001",
        "duplicate canonical ID",
        "Ensure each canonical ID (vault_node_id, canonical_id, permanent_registry_id) is unique across the vault.",
        60
    ),
    rule!(
        "CHAD-IDENTITY-002",
        "duplicate active canonical identity",
        "Merge, alias, or deactivate one of the duplicate records. Add an `aliases` or `alias_of` field to declare the relationship.",
        60
    ),
    rule!(
        "CHAD-IDENTITY-003",
        "lead/owner equals second",
        "Assign a different identity as second, or document why the same person serving both roles is intentional.",
        60
    ),
    rule!(
        "CHAD-IDENTITY-004",
        "incompatible lifecycle/status (deceased + active)",
        "Set status to deceased/last-confirmed, or remove the death_year/life_status: deceased marker if the person is active.",
        60
    ),
    rule!(
        "CHAD-IDENTITY-005",
        "name-collapse suspicion without alias declaration",
        "Add an `aliases`, `alias_of`, or `merged_from` field to declare the identity relationship, or confirm the names are distinct.",
        61
    ),
    rule!(
        "CHAD-IDENTITY-006",
        "unresolved merge/alias collision",
        "Resolve the alias: deactivate one side, or fix the alias_of target to point to the correct note.",
        61
    ),
    // --- 8: workflow ---
    rule!(
        "CHAD-WORK-001",
        "multiple active workflows with same workflow_id",
        "Deactivate the superseded workflow definition; only one workflow per workflow_id may be active.",
        70
    ),
    // --- 9: links and refs ---
    rule!(
        "CHAD-LINK-001",
        "broken wikilink in curated scope",
        "Fix the link target to match an existing note path, or remove the dead link.",
        80
    ),
    rule!(
        "CHAD-REF-001",
        "unresolvable owner/authority reference",
        "Correct the reference to match an existing curated note title, or create the referenced note.",
        80
    ),
    // --- 10: protected paths ---
    rule!(
        "CHAD-PROT-001",
        "protected collector path modified by workflow",
        "Revert the change to the collector-owned path. Chadlands workflows may not write to 70 Sources/ evidence trees.",
        90
    ),
];

/// HashMap for O(1) lookup by rule ID.
static RULE_MAP: LazyLock<HashMap<&'static str, &'static RuleMeta>> = LazyLock::new(|| {
    let mut m = HashMap::with_capacity(RULES.len());
    for r in RULES {
        m.insert(r.id, r);
    }
    m
});

/// Look up metadata for a rule ID. Returns a default for unknown rules.
pub fn lookup(rule_id: &str) -> &'static RuleMeta {
    RULE_MAP.get(rule_id).copied().unwrap_or(&RuleMeta {
        id: "",
        description: "unknown rule",
        remediation: "See the validator README for rule documentation.",
        priority: 127,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_rule_ids_have_metadata() {
    // Collect every rule ID used in Finding::new / finding() calls across
    // the codebase. If a new rule is added but not in RULES, this test fails.
    // *** UPDATE THIS LIST WHEN ADDING NEW RULES ***
    let used_rules: Vec<&str> = vec![
            "CHAD-SCHEMA-001",
            "CHAD-SCHEMA-002",
            "CHAD-SCHEMA-003",
            "CHAD-SCHEMA-004",
            "CHAD-SCHEMA-005",
            "CHAD-STATE-001",
            "CHAD-STATE-002",
            "CHAD-STATE-003",
            "CHAD-STATE-004",
            "CHAD-YEAR-001",
            "CHAD-YEAR-002",
            "CHAD-YEAR-003",
            "CHAD-YEAR-004",
            "CHAD-YEAR-005",
            "CHAD-CURSOR-001",
            "CHAD-CURSOR-002",
            "CHAD-CURSOR-003",
            "CHAD-CURSOR-004",
            "CHAD-CURSOR-005",
            "CHAD-CURSOR-006",
            "CHAD-CURSOR-007",
            "CHAD-CURSOR-008",
            "CHAD-CURSOR-009",
            "CHAD-FRESH-001",
            "CHAD-FRESH-002",
            "CHAD-OWNER-001",
            "CHAD-OWNER-002",
            "CHAD-OWNER-003",
            "CHAD-IDENTITY-001",
            "CHAD-IDENTITY-002",
            "CHAD-IDENTITY-003",
            "CHAD-IDENTITY-004",
            "CHAD-IDENTITY-005",
            "CHAD-IDENTITY-006",
            "CHAD-WORK-001",
            "CHAD-LINK-001",
            "CHAD-REF-001",
            "CHAD-PROT-001",
        ];
        for rule_id in used_rules {
            let m = lookup(rule_id);
            assert_eq!(
                m.id, rule_id,
                "rule {rule_id} is in the codebase but missing from RULES metadata"
            );
        }
    }

    #[test]
    fn lookup_returns_default_for_unknown() {
        let m = lookup("CHAD-NONEXISTENT-999");
        assert_eq!(m.id, "");
        assert_eq!(m.description, "unknown rule");
        assert_eq!(m.priority, 127);
    }
}
