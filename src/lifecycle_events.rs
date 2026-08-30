//! Conservative direct-source lifecycle event parser (Patch 3, §7).
//!
//! Parses narrow machine-like lifecycle patterns from authoritative DM
//! source. Does NOT perform general NLP. False negatives are correct.
//!
//! Authority: only DM/world speaker classes produce lifecycle events.
//! Identity: must resolve to exactly one known identity (no fuzzy).
//! Subject: identity must be the explicit subject of the structure.

use crate::config::Config;
use crate::source_index::{
    normalize_text, ActivityEvidenceKind, KnownIdentity, SourceMessage, SpeakerClass,
};

/// Controlled lifecycle outcome vocabulary. Smallest set required by
/// observed authoritative source.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SourceLifecycleOutcome {
    Accepted,
    Running,
    Stalled,
    ClosedSucceeded,
    ClosedFailed,
    Failed,
    TerminalFailed,
    Completed,
}

impl SourceLifecycleOutcome {
    pub fn label(self) -> &'static str {
        match self {
            Self::Accepted => "ACCEPTED",
            Self::Running => "RUNNING",
            Self::Stalled => "STALLED",
            Self::ClosedSucceeded => "CLOSED_SUCCEEDED",
            Self::ClosedFailed => "CLOSED_FAILED",
            Self::Failed => "FAILED",
            Self::TerminalFailed => "TERMINAL_FAILED",
            Self::Completed => "COMPLETED",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::ClosedSucceeded
                | Self::ClosedFailed
                | Self::Failed
                | Self::TerminalFailed
                | Self::Completed
        )
    }
}

/// A recognized lifecycle event from direct source.
#[derive(Debug, Clone)]
pub struct SourceLifecycleEvent {
    pub identity_key: String,
    pub cursor: i64,
    pub outcome: SourceLifecycleOutcome,
    pub source_file: String,
    pub source_line: usize,
    pub evidence_kind: ActivityEvidenceKind,
}

/// Parse lifecycle events from authoritative source messages.
pub fn parse_lifecycle_events(
    messages: &[SourceMessage],
    identities: &[KnownIdentity],
    config: &Config,
) -> Vec<SourceLifecycleEvent> {
    let mut events = Vec::new();

    for msg in messages {
        if !is_authoritative_speaker(msg, config) {
            continue;
        }

        for line in msg.body.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            if has_negation(trimmed) {
                continue;
            }

            if let Some(event) = try_parse_pipe_row(trimmed, msg, identities) {
                events.push(event);
                continue;
            }

            if let Some(event) = try_parse_bullet_line(trimmed, msg, identities) {
                events.push(event);
            }
        }
    }

    events
}

fn is_authoritative_speaker(msg: &SourceMessage, config: &Config) -> bool {
    match msg.speaker_class {
        SpeakerClass::Dm => true,
        SpeakerClass::Player => false,
        SpeakerClass::Unknown => {
            let lower = msg.speaker.to_ascii_lowercase();
            config
                .dm_speakers
                .iter()
                .any(|s| s.eq_ignore_ascii_case(&lower))
        }
    }
}

fn has_negation(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    [
        "not completed",
        "never accepted",
        "does not mean failed",
        "did not fail",
        "not stalled",
        "has not closed",
        "has not failed",
        "was not",
        "is not",
        "never completed",
        "not succeeded",
    ]
    .iter()
    .any(|n| lower.contains(n))
}

/// Pipe/table row: `<subject> | <state content>`
fn try_parse_pipe_row(
    line: &str,
    msg: &SourceMessage,
    identities: &[KnownIdentity],
) -> Option<SourceLifecycleEvent> {
    let pipe_pos = line.find('|')?;
    let subject = line[..pipe_pos].trim();
    let state_cell = line[pipe_pos + 1..].trim();

    let identity = resolve_complete_subject(subject, identities)?;
    let outcome = parse_lifecycle_phrase(state_cell)?;

    Some(SourceLifecycleEvent {
        identity_key: identity.key.clone(),
        cursor: msg.cursor,
        outcome,
        source_file: msg.file.clone(),
        source_line: msg.line,
        evidence_kind: ActivityEvidenceKind::ExactLifecycleSourceEvent,
    })
}

/// Bullet/state line: `- <subject> <LIFECYCLE PHRASE> ...`
///
/// The subject is the text before the first recognized lifecycle phrase.
/// The lifecycle phrase must follow the subject with only bounded
/// punctuation/whitespace.
fn try_parse_bullet_line(
    line: &str,
    msg: &SourceMessage,
    identities: &[KnownIdentity],
) -> Option<SourceLifecycleEvent> {
    let content = line
        .strip_prefix("- ")
        .or_else(|| line.strip_prefix("– "))
        .or_else(|| line.strip_prefix("* "))
        .unwrap_or(line);

    // Find the lifecycle phrase boundary: the subject is everything
    // before the first controlled lifecycle keyword.
    let (subject, remainder) = split_at_lifecycle_phrase(content)?;

    let subject = subject.trim();
    if subject.is_empty() {
        return None;
    }

    let identity = resolve_complete_subject(subject, identities)?;
    let outcome = parse_lifecycle_phrase(remainder)?;

    Some(SourceLifecycleEvent {
        identity_key: identity.key.clone(),
        cursor: msg.cursor,
        outcome,
        source_file: msg.file.clone(),
        source_line: msg.line,
        evidence_kind: ActivityEvidenceKind::ExactLifecycleSourceEvent,
    })
}

/// Split content at the first recognized lifecycle phrase.
/// Returns (subject_before, lifecycle_phrase_and_rest).
fn split_at_lifecycle_phrase(content: &str) -> Option<(&str, &str)> {
    // Ordered by length descending so "closed succeeded" matches before "succeeded"
    let phrases = [
        "closed succeeded",
        "closed failed",
        "failed terminally",
        "terminal failure",
        "closed success",
        "closed failure",
        "in progress",
        "accepted",
        "running",
        "stalled",
        "completed",
        "succeeded",
        "failed",
    ];

    let lower = content.to_ascii_lowercase();
    for phrase in &phrases {
        if let Some(pos) = lower.find(phrase) {
            // The phrase must follow the subject with only bounded
            // punctuation/whitespace. Check that the character before
            // the phrase is a word boundary (space, dash, pipe, start).
            if pos > 0 {
                let prev = content.as_bytes()[pos - 1];
                if prev.is_ascii_alphanumeric() {
                    continue; // Not a word boundary — skip
                }
            }
            return Some((&content[..pos], &content[pos..]));
        }
    }
    None
}

/// Resolve a complete subject string to exactly one known identity.
///
/// Priority: stable ID > exact title > exact alias.
/// Uses `normalize_text` from the source index for consistency.
/// Ambiguous (0 or >1 matches) = None (fail closed).
fn resolve_complete_subject<'a>(
    subject: &str,
    identities: &'a [KnownIdentity],
) -> Option<&'a KnownIdentity> {
    let subject_norm = normalize_text(subject);

    // 1. Exact stable ID match
    let mut id_matches: Vec<&KnownIdentity> = identities
        .iter()
        .filter(|id| {
            if let Some(cid) = &id.canonical_id {
                subject_norm == normalize_text(cid)
            } else {
                false
            }
        })
        .collect();
    if id_matches.len() == 1 {
        return id_matches.pop();
    }
    if id_matches.len() > 1 {
        return None;
    }

    // 2. Exact title match
    let mut title_matches: Vec<&KnownIdentity> = identities
        .iter()
        .filter(|id| subject_norm == normalize_text(&id.title))
        .collect();
    if title_matches.len() == 1 {
        return title_matches.pop();
    }
    if title_matches.len() > 1 {
        return None;
    }

    // 3. Exact alias match (including structural aliases)
    let mut alias_matches: Vec<&KnownIdentity> = Vec::new();
    for id in identities {
        for alias in effective_aliases(id) {
            if subject_norm == normalize_text(&alias)
                && !alias_matches.iter().any(|m| m.key == id.key)
            {
                alias_matches.push(id);
            }
        }
    }
    if alias_matches.len() == 1 {
        return alias_matches.pop();
    }

    // 0 or >1 matches → no event
    None
}

/// Compute effective aliases for an identity, including type-aware
/// structural aliases.
///
/// For `technology-road` type: adds `<title> road`.
/// For `technology-portfolio` type: adds `<title> portfolio`.
fn effective_aliases(id: &KnownIdentity) -> Vec<String> {
    let mut aliases: Vec<String> = id.aliases.clone();

    // Type-aware structural aliases (§2.5)
    match id.type_name.as_str() {
        "technology-road" => {
            aliases.push(format!("{} road", id.title));
        }
        "technology-portfolio" => {
            aliases.push(format!("{} portfolio", id.title));
        }
        "capability" => {
            aliases.push(format!("{} capability", id.title));
        }
        _ => {}
    }

    aliases
}

/// Parse a lifecycle phrase from text. Returns the outcome if the text
/// starts with a recognized controlled phrase.
fn parse_lifecycle_phrase(text: &str) -> Option<SourceLifecycleOutcome> {
    let trimmed = text.trim();
    let lower = trimmed.to_ascii_lowercase();

    // Check exact prefix matches (ordered longest-first)
    if lower.starts_with("closed succeeded") {
        return Some(SourceLifecycleOutcome::ClosedSucceeded);
    }
    if lower.starts_with("closed failed") {
        return Some(SourceLifecycleOutcome::ClosedFailed);
    }
    if lower.starts_with("failed terminally") || lower.starts_with("terminal failure") {
        return Some(SourceLifecycleOutcome::TerminalFailed);
    }
    if lower.starts_with("completed") || lower.starts_with("succeeded") {
        return Some(SourceLifecycleOutcome::Completed);
    }
    if lower.starts_with("failed") {
        return Some(SourceLifecycleOutcome::Failed);
    }
    if lower.starts_with("stalled") {
        return Some(SourceLifecycleOutcome::Stalled);
    }
    if lower.starts_with("running") || lower.starts_with("in progress") {
        return Some(SourceLifecycleOutcome::Running);
    }
    if lower.starts_with("accepted") {
        return Some(SourceLifecycleOutcome::Accepted);
    }

    None
}

/// Detect contradictions between lifecycle events for the same identity.
pub fn detect_contradictions(events: &[SourceLifecycleEvent]) -> Vec<Contradiction> {
    use std::collections::HashMap;

    let mut by_identity: HashMap<String, Vec<&SourceLifecycleEvent>> = HashMap::new();
    for e in events {
        by_identity
            .entry(e.identity_key.clone())
            .or_default()
            .push(e);
    }

    let mut contradictions = Vec::new();

    for (key, evts) in &by_identity {
        let terminal: Vec<&&SourceLifecycleEvent> =
            evts.iter().filter(|e| e.outcome.is_terminal()).collect();
        if terminal.len() < 2 {
            continue;
        }

        for i in 0..terminal.len() {
            for j in (i + 1)..terminal.len() {
                if !outcomes_compatible(terminal[i].outcome, terminal[j].outcome) {
                    contradictions.push(Contradiction {
                        identity_key: key.clone(),
                        event_a: (*terminal[i]).clone(),
                        event_b: (*terminal[j]).clone(),
                    });
                }
            }
        }
    }

    contradictions
}

/// Conservative compatibility mapping (§5.1).
///
/// Failures are compatible with failures. Successes are compatible
/// with successes. Mixed polarity is contradictory.
fn outcomes_compatible(a: SourceLifecycleOutcome, b: SourceLifecycleOutcome) -> bool {
    if a == b {
        return true;
    }
    let a_polarity = outcome_polarity(a);
    let b_polarity = outcome_polarity(b);
    a_polarity == b_polarity
}

fn outcome_polarity(o: SourceLifecycleOutcome) -> OutcomePolarity {
    match o {
        SourceLifecycleOutcome::Completed | SourceLifecycleOutcome::ClosedSucceeded => {
            OutcomePolarity::Success
        }
        SourceLifecycleOutcome::Failed
        | SourceLifecycleOutcome::TerminalFailed
        | SourceLifecycleOutcome::ClosedFailed => OutcomePolarity::Failure,
        SourceLifecycleOutcome::Accepted
        | SourceLifecycleOutcome::Running
        | SourceLifecycleOutcome::Stalled => OutcomePolarity::NonTerminal,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum OutcomePolarity {
    Success,
    Failure,
    NonTerminal,
}

/// A contradiction between two lifecycle events.
#[derive(Debug)]
pub struct Contradiction {
    pub identity_key: String,
    pub event_a: SourceLifecycleEvent,
    pub event_b: SourceLifecycleEvent,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_msg(
        cursor: i64,
        speaker: &str,
        speaker_class: SpeakerClass,
        body: &str,
    ) -> SourceMessage {
        SourceMessage {
            file: "test.md".to_string(),
            cursor,
            timestamp: None,
            speaker: speaker.to_string(),
            speaker_class,
            body: body.to_string(),
            line: 1,
        }
    }

    fn make_identity(key: &str, title: &str, type_name: &str, aliases: Vec<&str>) -> KnownIdentity {
        KnownIdentity {
            key: key.to_string(),
            canonical_id: Some(key.to_string()),
            title: title.to_string(),
            aliases: aliases.into_iter().map(String::from).collect(),
            note_path: format!("{}.md", title),
            type_name: type_name.to_string(),
            status: Some("active".to_string()),
            lifecycle: Some("in-progress".to_string()),
        }
    }

    #[test]
    fn exact_pipe_subject_resolves() {
        let msgs = vec![make_msg(
            5035,
            "the_mud_lounge_bot",
            SpeakerClass::Dm,
            "Universal formation | closed SUCCEEDED this year",
        )];
        let ids = vec![make_identity(
            "road:universal-formation",
            "Universal formation",
            "technology-road",
            vec![],
        )];
        let events = parse_lifecycle_events(&msgs, &ids, &Config::default());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, SourceLifecycleOutcome::ClosedSucceeded);
    }

    #[test]
    fn structural_alias_road_type_resolves() {
        // "Universal formation road" should resolve via structural alias
        // for technology-road type
        let msgs = vec![make_msg(
            5035,
            "the_mud_lounge_bot",
            SpeakerClass::Dm,
            "Universal formation road | closed SUCCEEDED this year",
        )];
        let ids = vec![make_identity(
            "road:universal-formation",
            "Universal formation",
            "technology-road",
            vec![],
        )];
        let events = parse_lifecycle_events(&msgs, &ids, &Config::default());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, SourceLifecycleOutcome::ClosedSucceeded);
    }

    #[test]
    fn bullet_subject_resolves() {
        let msgs = vec![make_msg(
            5100,
            "the_mud_lounge_bot",
            SpeakerClass::Dm,
            "- Steam power FAILED at the boundary",
        )];
        let ids = vec![make_identity(
            "road:steam",
            "Steam power",
            "technology-road",
            vec![],
        )];
        let events = parse_lifecycle_events(&msgs, &ids, &Config::default());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, SourceLifecycleOutcome::Failed);
    }

    #[test]
    fn steam_governor_no_terminal_event() {
        // §2.2/§7.5: "Steam's governor control FAILED TERMINALLY"
        // Subject resolves to "Steam's governor control" which is NOT
        // a known identity → no event (general subject semantics, not blacklist)
        let msgs = vec![make_msg(
            5100,
            "the_mud_lounge_bot",
            SpeakerClass::Dm,
            "Steam's governor control FAILED TERMINALLY ... bearing and shaft tolerance continues",
        )];
        let ids = vec![make_identity(
            "road:steam",
            "Steam",
            "technology-road",
            vec![],
        )];
        let events = parse_lifecycle_events(&msgs, &ids, &Config::default());
        assert_eq!(events.len(), 0);
    }

    #[test]
    fn broad_substring_does_not_create_event() {
        // §2.2: "<Road> ... unrelated component failed later"
        // The subject "Steam power" is resolved, but "failed" appears
        // in a different clause. The split_at_lifecycle_phrase should
        // only match if "failed" directly follows the subject.
        let msgs = vec![make_msg(
            5100,
            "the_mud_lounge_bot",
            SpeakerClass::Dm,
            "- Steam power had issues. The valve failed later.",
        )];
        let ids = vec![make_identity(
            "road:steam",
            "Steam power",
            "technology-road",
            vec![],
        )];
        let events = parse_lifecycle_events(&msgs, &ids, &Config::default());
        // "Steam power had issues" — "had" is not a lifecycle phrase,
        // and "failed later" is in a separate sentence after a period.
        assert_eq!(events.len(), 0);
    }

    #[test]
    fn player_speaker_ignored() {
        let msgs = vec![make_msg(
            5035,
            "player1",
            SpeakerClass::Player,
            "Universal formation CLOSED SUCCEEDED",
        )];
        let ids = vec![make_identity(
            "road:universal-formation",
            "Universal formation",
            "technology-road",
            vec![],
        )];
        let events = parse_lifecycle_events(&msgs, &ids, &Config::default());
        assert_eq!(events.len(), 0);
    }

    #[test]
    fn negation_suppresses_event() {
        let msgs = vec![make_msg(
            5035,
            "the_mud_lounge_bot",
            SpeakerClass::Dm,
            "Universal formation not completed yet",
        )];
        let ids = vec![make_identity(
            "road:universal-formation",
            "Universal formation",
            "technology-road",
            vec![],
        )];
        let events = parse_lifecycle_events(&msgs, &ids, &Config::default());
        assert_eq!(events.len(), 0);
    }

    #[test]
    fn ambiguous_alias_no_event() {
        let msgs = vec![make_msg(
            5035,
            "the_mud_lounge_bot",
            SpeakerClass::Dm,
            "Forge CLOSED SUCCEEDED",
        )];
        let ids = vec![
            make_identity(
                "road:forge-a",
                "Forge Alpha",
                "technology-road",
                vec!["Forge"],
            ),
            make_identity(
                "road:forge-b",
                "Forge Beta",
                "technology-road",
                vec!["Forge"],
            ),
        ];
        let events = parse_lifecycle_events(&msgs, &ids, &Config::default());
        assert_eq!(events.len(), 0);
    }

    #[test]
    fn duplicate_title_no_event() {
        let msgs = vec![make_msg(
            5035,
            "the_mud_lounge_bot",
            SpeakerClass::Dm,
            "Test Road CLOSED SUCCEEDED",
        )];
        let ids = vec![
            make_identity("road:a", "Test Road", "technology-road", vec![]),
            make_identity("road:b", "Test Road", "technology-road", vec![]),
        ];
        let events = parse_lifecycle_events(&msgs, &ids, &Config::default());
        assert_eq!(events.len(), 0);
    }

    #[test]
    fn contradiction_detected() {
        let events = vec![
            SourceLifecycleEvent {
                identity_key: "road:test".to_string(),
                cursor: 5000,
                outcome: SourceLifecycleOutcome::ClosedSucceeded,
                source_file: "a.md".to_string(),
                source_line: 1,
                evidence_kind: ActivityEvidenceKind::ExactLifecycleSourceEvent,
            },
            SourceLifecycleEvent {
                identity_key: "road:test".to_string(),
                cursor: 5100,
                outcome: SourceLifecycleOutcome::Failed,
                source_file: "b.md".to_string(),
                source_line: 1,
                evidence_kind: ActivityEvidenceKind::ExactLifecycleSourceEvent,
            },
        ];
        let contradictions = detect_contradictions(&events);
        assert_eq!(contradictions.len(), 1);
    }

    #[test]
    fn compatible_failure_no_contradiction() {
        // §5.1: CLOSED_FAILED and FAILED have compatible polarity
        let events = vec![
            SourceLifecycleEvent {
                identity_key: "road:test".to_string(),
                cursor: 5000,
                outcome: SourceLifecycleOutcome::ClosedFailed,
                source_file: "a.md".to_string(),
                source_line: 1,
                evidence_kind: ActivityEvidenceKind::ExactLifecycleSourceEvent,
            },
            SourceLifecycleEvent {
                identity_key: "road:test".to_string(),
                cursor: 5100,
                outcome: SourceLifecycleOutcome::Failed,
                source_file: "b.md".to_string(),
                source_line: 1,
                evidence_kind: ActivityEvidenceKind::ExactLifecycleSourceEvent,
            },
        ];
        let contradictions = detect_contradictions(&events);
        assert_eq!(contradictions.len(), 0);
    }

    #[test]
    fn compatible_success_no_contradiction() {
        // §5.1: COMPLETED and CLOSED_SUCCEEDED have compatible polarity
        let events = vec![
            SourceLifecycleEvent {
                identity_key: "road:test".to_string(),
                cursor: 5000,
                outcome: SourceLifecycleOutcome::Completed,
                source_file: "a.md".to_string(),
                source_line: 1,
                evidence_kind: ActivityEvidenceKind::ExactLifecycleSourceEvent,
            },
            SourceLifecycleEvent {
                identity_key: "road:test".to_string(),
                cursor: 5100,
                outcome: SourceLifecycleOutcome::ClosedSucceeded,
                source_file: "b.md".to_string(),
                source_line: 1,
                evidence_kind: ActivityEvidenceKind::ExactLifecycleSourceEvent,
            },
        ];
        let contradictions = detect_contradictions(&events);
        assert_eq!(contradictions.len(), 0);
    }

    #[test]
    fn same_outcome_no_contradiction() {
        let events = vec![
            SourceLifecycleEvent {
                identity_key: "road:test".to_string(),
                cursor: 5000,
                outcome: SourceLifecycleOutcome::ClosedSucceeded,
                source_file: "a.md".to_string(),
                source_line: 1,
                evidence_kind: ActivityEvidenceKind::ExactLifecycleSourceEvent,
            },
            SourceLifecycleEvent {
                identity_key: "road:test".to_string(),
                cursor: 5100,
                outcome: SourceLifecycleOutcome::ClosedSucceeded,
                source_file: "b.md".to_string(),
                source_line: 1,
                evidence_kind: ActivityEvidenceKind::ExactLifecycleSourceEvent,
            },
        ];
        let contradictions = detect_contradictions(&events);
        assert_eq!(contradictions.len(), 0);
    }
}
