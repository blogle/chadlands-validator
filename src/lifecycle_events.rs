//! Conservative direct-source lifecycle event parser (Patch 3, §7).
//!
//! Parses narrow machine-like lifecycle patterns from authoritative DM
//! source. Does NOT perform general NLP. False negatives are correct.
//!
//! Authority: only DM/world speaker classes produce lifecycle events.
//! Identity: must resolve to exactly one known identity (no fuzzy).
//! Subject: identity must be the explicit subject of the structure.

use crate::config::Config;
use crate::source_index::{ActivityEvidenceKind, KnownIdentity, SourceMessage, SpeakerClass};

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

    /// Is this a terminal outcome?
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
///
/// Returns events for exactly-resolved identities only. Ambiguous or
/// unresolvable patterns produce no events (fail closed).
pub fn parse_lifecycle_events(
    messages: &[SourceMessage],
    identities: &[KnownIdentity],
    config: &Config,
) -> Vec<SourceLifecycleEvent> {
    let mut events = Vec::new();

    for msg in messages {
        // §7.2 Authority restriction: only DM speakers
        if !is_authoritative_speaker(msg, config) {
            continue;
        }

        for line in msg.body.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }

            // §7.6 Negation/quoted-context fail closed
            if has_negation(trimmed) {
                continue;
            }

            // Try pipe/table row pattern
            if let Some(event) = try_parse_pipe_row(trimmed, msg, identities) {
                events.push(event);
                continue;
            }

            // Try bullet/state-change line pattern
            if let Some(event) = try_parse_bullet_line(trimmed, msg, identities) {
                events.push(event);
                continue;
            }
        }
    }

    events
}

/// Check if the message speaker is an authoritative DM/world source.
fn is_authoritative_speaker(msg: &SourceMessage, config: &Config) -> bool {
    match msg.speaker_class {
        SpeakerClass::Dm => true,
        SpeakerClass::Player => false,
        SpeakerClass::Unknown => {
            // Fall back to config lists
            let lower = msg.speaker.to_ascii_lowercase();
            config
                .dm_speakers
                .iter()
                .any(|s| s.eq_ignore_ascii_case(&lower))
        }
    }
}

/// §7.6 Detect obvious local negation around a lifecycle claim.
fn has_negation(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    let negations = [
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
    ];
    negations.iter().any(|n| lower.contains(n))
}

/// §7.5 Steam governor hard negative: lines containing component/intermediate
/// language that should NOT classify the whole road as failed.
fn is_component_subject(line: &str) -> bool {
    let lower = line.to_ascii_lowercase();
    // Component/intermediate indicators
    let component_signals = [
        "governor control",
        "bearing and shaft",
        "shaft tolerance",
        "component",
        "intermediate",
        "subassembly",
        "mechanism",
        "valve",
        "gear train",
        "flywheel",
    ];
    component_signals.iter().any(|s| lower.contains(s))
}

/// Try to parse a pipe/table row:
/// `Universal formation road | ... closed SUCCEEDED this year`
fn try_parse_pipe_row(
    line: &str,
    msg: &SourceMessage,
    identities: &[KnownIdentity],
) -> Option<SourceLifecycleEvent> {
    // Must contain a pipe separator
    let pipe_pos = line.find('|')?;
    let subject_part = line[..pipe_pos].trim();
    let rest = line[pipe_pos + 1..].trim();

    // Try to resolve the subject to exactly one identity
    let identity = resolve_identity(subject_part, identities)?;

    // Parse the lifecycle outcome from the rest
    let outcome = parse_lifecycle_keywords(rest)?;

    Some(SourceLifecycleEvent {
        identity_key: identity.key.clone(),
        cursor: msg.cursor,
        outcome,
        source_file: msg.file.clone(),
        source_line: msg.line,
        evidence_kind: ActivityEvidenceKind::ExactLifecycleSourceEvent,
    })
}

/// Try to parse a bullet/state-change line:
/// `- Universal formation CLOSED SUCCEEDED at its ceiling ...`
fn try_parse_bullet_line(
    line: &str,
    msg: &SourceMessage,
    identities: &[KnownIdentity],
) -> Option<SourceLifecycleEvent> {
    // Must start with a bullet marker or be a bare state-change line
    let content = line
        .strip_prefix("- ")
        .or_else(|| line.strip_prefix("– "))
        .or_else(|| line.strip_prefix("* "))
        .unwrap_or(line);

    // §7.5 Steam governor guard: reject component subjects
    if is_component_subject(content) {
        return None;
    }

    // Try to find an identity at the start of the content
    let identity = resolve_identity_at_start(content, identities)?;

    // Parse lifecycle keywords after the identity
    let after_identity = &content[identity.title.len()..];
    let outcome = parse_lifecycle_keywords(after_identity)?;

    Some(SourceLifecycleEvent {
        identity_key: identity.key.clone(),
        cursor: msg.cursor,
        outcome,
        source_file: msg.file.clone(),
        source_line: msg.line,
        evidence_kind: ActivityEvidenceKind::ExactLifecycleSourceEvent,
    })
}

/// Resolve a subject string to exactly one known identity.
/// Priority: stable ID > exact title > exact alias.
/// Ambiguous = None (fail closed).
fn resolve_identity<'a>(
    subject: &str,
    identities: &'a [KnownIdentity],
) -> Option<&'a KnownIdentity> {
    let norm = normalize_lifecycle_text(subject);

    // 1. Exact stable ID match
    let mut id_matches: Vec<&KnownIdentity> = identities
        .iter()
        .filter(|id| {
            if let Some(cid) = &id.canonical_id {
                norm == normalize_lifecycle_text(cid)
            } else {
                false
            }
        })
        .collect();
    if id_matches.len() == 1 {
        return id_matches.pop();
    }
    if id_matches.len() > 1 {
        return None; // Ambiguous
    }

    // 2. Exact title match
    let mut title_matches: Vec<&KnownIdentity> = identities
        .iter()
        .filter(|id| norm == normalize_lifecycle_text(&id.title))
        .collect();
    if title_matches.len() == 1 {
        return title_matches.pop();
    }
    if title_matches.len() > 1 {
        return None; // Ambiguous
    }

    // 3. Exact alias match
    let mut alias_matches: Vec<&KnownIdentity> = identities
        .iter()
        .filter(|id| {
            id.aliases
                .iter()
                .any(|a| norm == normalize_lifecycle_text(a))
        })
        .collect();
    if alias_matches.len() == 1 {
        return alias_matches.pop();
    }

    // Ambiguous or no match
    None
}

/// Resolve an identity at the start of a line content.
/// The identity name must be a prefix of the content.
fn resolve_identity_at_start<'a>(
    content: &str,
    identities: &'a [KnownIdentity],
) -> Option<&'a KnownIdentity> {
    let content_norm = normalize_lifecycle_text(content);

    // Try stable IDs first
    for id in identities {
        if let Some(cid) = &id.canonical_id {
            let cid_norm = normalize_lifecycle_text(cid);
            if content_norm.starts_with(&cid_norm) {
                return Some(id);
            }
        }
    }

    // Try titles (longest first for greedy match)
    let mut sorted: Vec<&KnownIdentity> = identities.iter().collect();
    sorted.sort_by_key(|a| std::cmp::Reverse(a.title.len()));

    for id in sorted {
        let title_norm = normalize_lifecycle_text(&id.title);
        if title_norm.len() >= 3 && content_norm.starts_with(&title_norm) {
            return Some(id);
        }
    }

    // Try aliases — collect all matches, return None if ambiguous
    let mut alias_matches: Vec<&KnownIdentity> = Vec::new();
    for id in identities {
        for alias in &id.aliases {
            let alias_norm = normalize_lifecycle_text(alias);
            if alias_norm.len() >= 3
                && content_norm.starts_with(&alias_norm)
                && !alias_matches.iter().any(|m| m.key == id.key)
            {
                alias_matches.push(id);
            }
        }
    }
    if alias_matches.len() == 1 {
        return alias_matches.pop();
    }
    // Ambiguous or no match
    None
}

/// Normalize text for lifecycle matching: lowercase, collapse whitespace,
/// strip possessives.
fn normalize_lifecycle_text(s: &str) -> String {
    let lower = s.to_ascii_lowercase();
    // Strip possessive 's at word boundaries
    let mut out = String::with_capacity(lower.len());
    let chars: Vec<char> = lower.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\''
            && i + 1 < chars.len()
            && chars[i + 1] == 's'
            && i > 0
            && chars[i - 1].is_alphabetic()
            && (i + 2 >= chars.len() || !chars[i + 2].is_alphabetic())
        {
            i += 2;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Parse lifecycle keywords from text. Returns the first recognized outcome.
fn parse_lifecycle_keywords(text: &str) -> Option<SourceLifecycleOutcome> {
    let lower = text.to_ascii_lowercase();

    // Order matters: check more specific patterns first
    if lower.contains("closed succeeded") || lower.contains("closed success") {
        return Some(SourceLifecycleOutcome::ClosedSucceeded);
    }
    if lower.contains("closed failed") || lower.contains("closed failure") {
        return Some(SourceLifecycleOutcome::ClosedFailed);
    }
    if lower.contains("failed terminally") || lower.contains("terminal failure") {
        return Some(SourceLifecycleOutcome::TerminalFailed);
    }
    if lower.contains("completed") || lower.contains("succeeded") || lower.contains("success") {
        return Some(SourceLifecycleOutcome::Completed);
    }
    if lower.contains("failed") || lower.contains("failure") {
        return Some(SourceLifecycleOutcome::Failed);
    }
    if lower.contains("stalled") || lower.contains("stalled out") {
        return Some(SourceLifecycleOutcome::Stalled);
    }
    if lower.contains("running") || lower.contains("in progress") || lower.contains("executing") {
        return Some(SourceLifecycleOutcome::Running);
    }
    if lower.contains("accepted") || lower.contains("approved") {
        return Some(SourceLifecycleOutcome::Accepted);
    }

    None
}

/// Detect contradictions between lifecycle events for the same identity.
///
/// Two events are contradictory if they are both terminal and have
/// incompatible outcomes (e.g. ClosedSucceeded vs Failed).
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

        // Check for incompatible terminal outcomes
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

/// Are two terminal outcomes compatible? Same outcome is compatible.
/// Different terminal outcomes are contradictory unless explicit
/// supersession metadata exists (not implemented — fail closed).
fn outcomes_compatible(a: SourceLifecycleOutcome, b: SourceLifecycleOutcome) -> bool {
    a == b
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

    fn make_identity(key: &str, title: &str, aliases: Vec<&str>) -> KnownIdentity {
        KnownIdentity {
            key: key.to_string(),
            canonical_id: Some(key.to_string()),
            title: title.to_string(),
            aliases: aliases.into_iter().map(String::from).collect(),
            note_path: format!("{}.md", title),
            type_name: "technology-road".to_string(),
            status: Some("active".to_string()),
            lifecycle: Some("in-progress".to_string()),
        }
    }

    #[test]
    fn parse_pipe_row_closed_succeeded() {
        let msgs = vec![make_msg(
            5035,
            "the_mud_lounge_bot",
            SpeakerClass::Dm,
            "Universal formation road | closed SUCCEEDED this year",
        )];
        let ids = vec![make_identity(
            "road:universal-formation",
            "Universal formation",
            vec![],
        )];
        let config = Config::default();
        let events = parse_lifecycle_events(&msgs, &ids, &config);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, SourceLifecycleOutcome::ClosedSucceeded);
        assert_eq!(events[0].cursor, 5035);
    }

    #[test]
    fn parse_bullet_line_failed() {
        let msgs = vec![make_msg(
            5100,
            "the_mud_lounge_bot",
            SpeakerClass::Dm,
            "- Steam power FAILED at the boundary",
        )];
        let ids = vec![make_identity("road:steam", "Steam power", vec![])];
        let config = Config::default();
        let events = parse_lifecycle_events(&msgs, &ids, &config);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].outcome, SourceLifecycleOutcome::Failed);
    }

    #[test]
    fn steam_governor_not_terminal_failure() {
        // §7.5 Hard negative: Steam's governor control FAILED TERMINALLY
        // should NOT classify road:steam as terminally failed
        let msgs = vec![make_msg(
            5100,
            "the_mud_lounge_bot",
            SpeakerClass::Dm,
            "Steam's governor control FAILED TERMINALLY ... bearing and shaft tolerance continues",
        )];
        let ids = vec![make_identity("road:steam", "Steam", vec![])];
        let config = Config::default();
        let events = parse_lifecycle_events(&msgs, &ids, &config);
        // Should produce NO events because of component subject detection
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
            vec![],
        )];
        let config = Config::default();
        let events = parse_lifecycle_events(&msgs, &ids, &config);
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
            vec![],
        )];
        let config = Config::default();
        let events = parse_lifecycle_events(&msgs, &ids, &config);
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
            make_identity("road:forge-a", "Forge Alpha", vec!["Forge"]),
            make_identity("road:forge-b", "Forge Beta", vec!["Forge"]),
        ];
        let config = Config::default();
        let events = parse_lifecycle_events(&msgs, &ids, &config);
        // Ambiguous alias → no event
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
