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
        "Reconcile the source association and State Boundary first. If the evidence is confirmed unsupported, correct the record rather than changing its year downward solely because it is ahead of current_year.",
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
        "If the cursor exceeds collected authoritative source, correct the record. If it is within collected source but ahead of State Boundary, reconcile the State Boundary before altering the record.",
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
    // --- 11: technology structural ---
    rule!(
        "CHAD-TECH-001",
        "accepted/executing road lacks stable road_id",
        "Add `road_id` to the frontmatter of the accepted/executing technology road.",
        62
    ),
    rule!(
        "CHAD-TECH-002",
        "duplicate road_id",
        "Ensure each road_id is unique across the vault. Remove the duplicate from one record.",
        62
    ),
    rule!(
        "CHAD-TECH-003",
        "accepted road lacks acceptance evidence",
        "Add `accepted_year` or `acceptance_cursor` to the road's frontmatter.",
        62
    ),
    rule!(
        "CHAD-TECH-004",
        "executing road missing due boundary",
        "Add `terminal_due_year` to the road's frontmatter.",
        62
    ),
    rule!(
        "CHAD-TECH-005",
        "terminal road has no result/receipt mapping",
        "Add `result` or `terminal_result` to the frontmatter of the completed road.",
        62
    ),
    rule!(
        "CHAD-TECH-006",
        "produces references missing capability record",
        "Create the durable capability record or correct the `produces` reference.",
        62
    ),
    rule!(
        "CHAD-TECH-007",
        "road/capability relationship disagreement",
        "Reconcile the explicit machine-readable relationship between road and capability records.",
        62
    ),
    rule!(
        "CHAD-TECH-008",
        "portfolio references unresolved child road",
        "Create the road record or remove the road_id from the portfolio's `road_ids`.",
        62
    ),
    rule!(
        "CHAD-TECH-009",
        "requires/cheapened_by/produces references unresolved capability",
        "Create the capability record or correct the reference.",
        62
    ),
    rule!(
        "CHAD-TECH-010",
        "active durable capability missing structured capability_state",
        "Add a supported `capability_state` only when canonical structured evidence establishes it; do not infer it from lifecycle prose.",
        63
    ),
    // --- 12: receipt monitoring ---
    rule!(
        "CHAD-RECEIPT-001",
        "accepted road has no start evidence",
        "Add start evidence via a structured receipt or canonical `started_year`/`started_cursor` field.",
        64
    ),
    rule!(
        "CHAD-RECEIPT-002",
        "executing road has no progress receipt",
        "Add a structured [CL PROGRESS ...] receipt or advance the road's canonical progress fields.",
        64
    ),
    rule!(
        "CHAD-RECEIPT-003",
        "expected receipt boundary arriving",
        "The terminal_due_year is the current year. Prepare the terminal receipt.",
        64
    ),
    rule!(
        "CHAD-RECEIPT-004",
        "promised receipt boundary passed without receipt",
        "Provide the overdue terminal receipt or update the road's due boundary.",
        64
    ),
    rule!(
        "CHAD-RECEIPT-005",
        "terminal result conflicts with unresolved PARTIAL",
        "Resolve, supersede, or cancel the unresolved PARTIAL components before claiming terminal success.",
        64
    ),
    rule!(
        "CHAD-RECEIPT-006",
        "complete portfolio return omits active child road",
        "Include the active child road in the return or close/mark it inactive.",
        64
    ),
    // --- 13: capability exploitation ---
    rule!(
        "CHAD-CAP-001",
        "attained capability exceeds evidenced-use dormancy threshold",
        "No qualifying use is evidenced in the indexed direct/canonical machine-readable evidence. Review capability relevance.",
        65
    ),
    // --- 14: coverage candidates ---
    rule!(
        "CHAD-COVER-001",
        "structured receipt references missing canonical owner",
        "Create the canonical record for the referenced stable ID or correct the receipt.",
        66
    ),
    rule!(
        "CHAD-COVER-002",
        "unresolved candidate repeats across messages",
        "Consider creating a canonical record for this repeatedly-mentioned entity.",
        67
    ),
    rule!(
        "CHAD-COVER-003",
        "lifecycle-shaped candidate persists without materialization",
        "This candidate appears to be a durable object. Create a canonical record or confirm it is transient.",
        67
    ),
    rule!(
        "CHAD-COVER-004",
        "single weak proper-name candidate",
        "Low priority. Monitor for repeated appearances.",
        68
    ),
    // --- 15: legacy technology migration ---
    rule!(
        "TECH-MIG-001",
        "legacy technology-node requires semantic classification",
        "Add road_id, capability_id, portfolio_id, or set `technology_class: historical-compatibility` to classify the legacy record.",
        69
    ),
    rule!(
        "TECH-MIG-002",
        "technology summary row lacks resolvable owner",
        "Create or link a durable technology record that owns this summary entry.",
        69
    ),
    rule!(
        "TECH-MIG-003",
        "portfolio does not declare resolvable child road_ids",
        "Add `road_ids` to the portfolio frontmatter listing its child roads.",
        69
    ),
    rule!(
        "TECH-MIG-004",
        "active legacy technology-bearing portfolio lacks machine-readable child-road representation",
        "Create durable technology-road records to enable road-level validation.",
        69
    ),
    rule!(
        "TECH-MIG-005",
        "technology road declared by authoritative surface has no machine-readable road owner",
        "Create a technology-road record with the appropriate road_id.",
        69
    ),
    rule!(
        "TECH-MIG-006",
        "technology receipt/lifecycle monitoring coverage incomplete",
        "Active technology remains behind legacy representation. Create road/capability records.",
        69
    ),
    // --- 16: capability migration ---
    rule!(
        "CAP-MIG-001",
        "canonical capability register lacks machine-readable durable capability owners",
        "Create capability records with `type: capability` and `capability_id` to enable exploitation tracking.",
        69
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
            "CHAD-TECH-001",
            "CHAD-TECH-002",
            "CHAD-TECH-003",
            "CHAD-TECH-004",
            "CHAD-TECH-005",
            "CHAD-TECH-006",
            "CHAD-TECH-007",
            "CHAD-TECH-008",
            "CHAD-TECH-009",
            "CHAD-TECH-010",
            "CHAD-RECEIPT-001",
            "CHAD-RECEIPT-002",
            "CHAD-RECEIPT-003",
            "CHAD-RECEIPT-004",
            "CHAD-RECEIPT-005",
            "CHAD-RECEIPT-006",
            "CHAD-CAP-001",
            "CHAD-COVER-001",
            "CHAD-COVER-002",
            "CHAD-COVER-003",
            "CHAD-COVER-004",
            "TECH-MIG-001",
            "TECH-MIG-002",
            "TECH-MIG-003",
            "TECH-MIG-004",
            "TECH-MIG-005",
            "TECH-MIG-006",
            "CAP-MIG-001",
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
