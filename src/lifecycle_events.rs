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
    /// Bounded direct-source fragment. This preserves useful evidence without
    /// interpreting incidental facts (years, quantities, capacity, etc.).
    pub raw_evidence: String,
}

const MAX_RAW_EVIDENCE_CHARS: usize = 320;

fn bounded_evidence(text: &str) -> String {
    text.trim().chars().take(MAX_RAW_EVIDENCE_CHARS).collect()
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
            let structural = unescape_markdown_structure(trimmed);

            if let Some(event) = try_parse_pipe_row(&structural, msg, identities) {
                events.push(event);
                continue;
            }

            if let Some(event) = try_parse_bullet_line(&structural, msg, identities) {
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

fn unescape_markdown_structure(line: &str) -> String {
    let mut result = String::with_capacity(line.len());
    let mut chars = line.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch == '\\' {
            if let Some(next @ ('|' | '-' | '*')) = chars.peek().copied() {
                result.push(next);
                chars.next();
                continue;
            }
        }
        result.push(ch);
    }
    result
}

fn token_boundary(text: &str, start: usize, end: usize) -> bool {
    text[..start]
        .chars()
        .next_back()
        .map(|c| !c.is_ascii_alphanumeric() && c != '_')
        .unwrap_or(true)
        && text[end..]
            .chars()
            .next()
            .map(|c| !c.is_ascii_alphanumeric() && c != '_')
            .unwrap_or(true)
}

fn local_negation(text: &str, phrase_start: usize) -> bool {
    let lower = text[..phrase_start].to_ascii_lowercase();
    let trimmed = lower.trim_end();
    // Check bounded immediate constructions ending at the lifecycle phrase.
    // Negation must be a complete word/phrase at the boundary, not a substring.
    // The character immediately before the negation word must be a non-alphanumeric
    // boundary (or the start of the string).
    let negation_words: &[&str] = &[
        "not", "never", "isn't", "wasn't", "doesn't", "didn't", "hasn't", "haven't", "can't",
        "cannot",
    ];
    // Also handle multi-word negations: "did not", "has not", "have not",
    // "is not", "was not" — check the two-word form ending at the phrase.
    let multi_word_negations: &[&str] = &["did not", "has not", "have not", "is not", "was not"];

    // Check multi-word negations first (they are longer and more specific)
    for neg in multi_word_negations {
        if trimmed.ends_with(neg) {
            // Verify boundary: char before negation start must be non-alnum
            let neg_start = trimmed.len() - neg.len();
            if neg_start == 0 {
                return true;
            }
            if let Some(c) = trimmed.chars().nth(neg_start - 1) {
                if !c.is_ascii_alphanumeric() && c != '_' {
                    return true;
                }
            }
        }
    }

    // Check single-word negations
    for neg in negation_words {
        // Must be preceded by a boundary char or be at start
        if trimmed.ends_with(neg) {
            let neg_start = trimmed.len() - neg.len();
            if neg_start == 0 {
                return true;
            }
            if let Some(c) = trimmed.chars().nth(neg_start - 1) {
                if !c.is_ascii_alphanumeric() && c != '_' {
                    return true;
                }
            }
        }
    }

    false
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
    let outcome = parse_structured_state_cell(state_cell)?;

    Some(SourceLifecycleEvent {
        identity_key: identity.key.clone(),
        cursor: msg.cursor,
        outcome,
        source_file: msg.file.clone(),
        source_line: msg.line,
        evidence_kind: ActivityEvidenceKind::ExactLifecycleSourceEvent,
        raw_evidence: bounded_evidence(state_cell),
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
        raw_evidence: bounded_evidence(remainder),
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
            let end = pos + phrase.len();
            // The phrase must follow the subject with only bounded
            // punctuation/whitespace. Check that the character before
            // the phrase is a word boundary (space, dash, pipe, start).
            if !token_boundary(&lower, pos, end) || local_negation(&lower, pos) {
                continue;
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
    if lower.starts_with("closed succeeded") && token_boundary(&lower, 0, "closed succeeded".len())
    {
        return Some(SourceLifecycleOutcome::ClosedSucceeded);
    }
    if lower.starts_with("closed failed") && token_boundary(&lower, 0, "closed failed".len()) {
        return Some(SourceLifecycleOutcome::ClosedFailed);
    }
    if (lower.starts_with("failed terminally") && token_boundary(&lower, 0, 16))
        || (lower.starts_with("terminal failure") && token_boundary(&lower, 0, 16))
    {
        return Some(SourceLifecycleOutcome::TerminalFailed);
    }
    if (lower.starts_with("completed") && token_boundary(&lower, 0, 9))
        || (lower.starts_with("succeeded") && token_boundary(&lower, 0, 9))
    {
        return Some(SourceLifecycleOutcome::Completed);
    }
    if lower.starts_with("failed") && token_boundary(&lower, 0, 6) {
        return Some(SourceLifecycleOutcome::Failed);
    }
    if lower.starts_with("stalled") && token_boundary(&lower, 0, 7) {
        return Some(SourceLifecycleOutcome::Stalled);
    }
    if (lower.starts_with("running") && token_boundary(&lower, 0, 7))
        || (lower.starts_with("in progress") && token_boundary(&lower, 0, 11))
    {
        return Some(SourceLifecycleOutcome::Running);
    }
    if lower.starts_with("accepted") && token_boundary(&lower, 0, 8) {
        return Some(SourceLifecycleOutcome::Accepted);
    }

    None
}

/// Parse the state cell of an exact-subject pipe row. Unlike prose parsing,
/// the controlled phrase may occur later in this one bounded cell. Multiple
/// distinct outcomes or local negation fail closed.
///
/// For pipe rows, the lifecycle phrase must either begin the state cell
/// or follow an approved road-level result lead-in. This prevents
/// component descriptions (e.g. "governor control — FAILED TERMINALLY")
/// from being misattributed to the parent road.
fn parse_structured_state_cell(text: &str) -> Option<SourceLifecycleOutcome> {
    let lower = text.to_ascii_lowercase();
    let trimmed = lower.trim();
    let phrases = [
        ("closed succeeded", SourceLifecycleOutcome::ClosedSucceeded),
        ("closed success", SourceLifecycleOutcome::ClosedSucceeded),
        ("closed failed", SourceLifecycleOutcome::ClosedFailed),
        ("closed failure", SourceLifecycleOutcome::ClosedFailed),
        ("failed terminally", SourceLifecycleOutcome::TerminalFailed),
        ("terminal failure", SourceLifecycleOutcome::TerminalFailed),
        ("completed", SourceLifecycleOutcome::Completed),
        ("succeeded", SourceLifecycleOutcome::Completed),
        ("failed", SourceLifecycleOutcome::Failed),
        ("stalled", SourceLifecycleOutcome::Stalled),
        ("running", SourceLifecycleOutcome::Running),
        ("in progress", SourceLifecycleOutcome::Running),
        ("accepted", SourceLifecycleOutcome::Accepted),
    ];
    let mut found = Vec::new();
    for (phrase, outcome) in phrases {
        let mut pos = 0;
        while let Some(relative) = trimmed[pos..].find(phrase) {
            let start = pos + relative;
            let end = start + phrase.len();
            if token_boundary(trimmed, start, end)
                && pipe_row_state_cell_valid(trimmed, start)
                && !local_negation(trimmed, start)
            {
                if !found.contains(&outcome) {
                    found.push(outcome);
                }
                break;
            }
            pos = end;
        }
    }
    // Longer phrases can also contain a shorter phrase (e.g. closed failed).
    let has_closed_failed = found.contains(&SourceLifecycleOutcome::ClosedFailed);
    let has_terminal_failed = found.contains(&SourceLifecycleOutcome::TerminalFailed);
    let has_closed_succeeded = found.contains(&SourceLifecycleOutcome::ClosedSucceeded);
    found.retain(|outcome| match outcome {
        SourceLifecycleOutcome::Failed => !has_closed_failed && !has_terminal_failed,
        SourceLifecycleOutcome::Completed => !has_closed_succeeded,
        _ => true,
    });
    (found.len() == 1).then(|| found[0])
}

/// Approved road-level result lead-ins for pipe-row state cells.
/// The lifecycle phrase must begin the cell or follow one of these.
const APPROVED_PIPE_ROW_LEAD_INS: &[&str] = &[
    "the adjudicated terms,",
    "status:",
    "result:",
    "terminal result:",
    "road status:",
    "road result:",
];

/// Check whether the lifecycle phrase position is valid in a pipe-row state cell.
/// Valid when: phrase at position 0, or preceding text matches an approved lead-in.
fn pipe_row_state_cell_valid(text: &str, phrase_start: usize) -> bool {
    if phrase_start == 0 {
        return true;
    }
    let before = text[..phrase_start].trim_end();
    APPROVED_PIPE_ROW_LEAD_INS
        .iter()
        .any(|lead| before.ends_with(lead))
}

/// Canonical floor for selecting evidence about the current road incarnation.
/// Acceptance/start evidence takes precedence; otherwise use the strongest
/// available canonical cursor boundary and do not infer one from prose.
/// For settled terminal canon, uses terminal_result_cursor as the floor
/// (since that is the settlement point being challenged).
pub fn current_lifecycle_floor(note: &crate::vault::Note) -> Option<i64> {
    let fm = note.fm();
    let incarnation = [
        fm.get_i64("acceptance_cursor"),
        fm.get_i64("started_cursor"),
    ]
    .into_iter()
    .flatten()
    .max();

    // For settled terminal canon, use terminal_result_cursor as floor
    let terminal_polarity = CanonicalTerminalPolarity::from_note(note);
    if terminal_polarity.is_some() {
        let settlement_floor = fm.get_i64("terminal_result_cursor");
        return incarnation
            .or(settlement_floor)
            .or_else(|| fm.get_i64("source_cursor"));
    }

    incarnation.or_else(|| fm.get_i64("source_cursor"))
}

/// Select terminal source claims that can still be unresolved for the current
/// incarnation of one canonical identity.
///
/// For nonterminal canonical state: event must be > source_cursor.
/// For settled terminal canonical state: event must be > settlement_cursor,
/// where settlement_cursor = terminal_result_cursor if present, otherwise
/// source_cursor. This prevents a blind window where contradictory terminal
/// evidence between terminal_result_cursor and source_cursor is silently
/// suppressed.
pub fn select_current_unresolved_terminal_events<'a>(
    note: &crate::vault::Note,
    identity_key: &str,
    events: &'a [SourceLifecycleEvent],
) -> Vec<&'a SourceLifecycleEvent> {
    let floor = current_lifecycle_floor(note);
    let fm = note.fm();
    let source_cursor = fm.get_i64("source_cursor");
    let terminal_polarity = CanonicalTerminalPolarity::from_note(note);

    // For settled terminal canon, use terminal_result_cursor as the settlement
    // boundary. The terminal receipt provenance is what is being challenged.
    // For nonterminal canon, use source_cursor (ordinary materialization check).
    let settlement_cursor = if terminal_polarity.is_some() {
        fm.get_i64("terminal_result_cursor")
    } else {
        None
    }
    .or(source_cursor);

    let mut selected: Vec<&SourceLifecycleEvent> = events
        .iter()
        .filter(|event| event.identity_key == identity_key)
        .filter(|event| event.outcome.is_terminal())
        .filter(|event| floor.map(|f| event.cursor >= f).unwrap_or(true))
        .filter(|event| {
            settlement_cursor
                .map(|cursor| event.cursor > cursor)
                .unwrap_or(true)
        })
        .collect();
    selected.sort_by_key(|event| {
        (
            event.cursor,
            event.source_file.as_str(),
            event.source_line,
            event.outcome.label(),
            event.raw_evidence.as_str(),
        )
    });
    selected
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
pub fn outcomes_compatible(a: SourceLifecycleOutcome, b: SourceLifecycleOutcome) -> bool {
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

/// Polarity of a canonical settled terminal state derived from structured
/// frontmatter fields only. Never inferred from prose.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanonicalTerminalPolarity {
    /// status == completed
    Success,
    /// status == failed
    Failure,
    /// status == closed or superseded (terminal but polarity unknown)
    UnknownTerminal,
}

impl CanonicalTerminalPolarity {
    /// Resolve canonical terminal polarity from structured frontmatter.
    /// Returns None when the record is nonterminal.
    pub fn from_note(note: &crate::vault::Note) -> Option<Self> {
        let status = note.status().unwrap_or_default();
        match status.as_str() {
            "completed" => Some(Self::Success),
            "failed" => Some(Self::Failure),
            "closed" | "superseded" => Some(Self::UnknownTerminal),
            _ => {
                let lifecycle = note.fm().get_str("lifecycle").unwrap_or_default();
                if lifecycle.starts_with("completed") {
                    Some(Self::Success)
                } else if lifecycle.starts_with("failed") {
                    Some(Self::Failure)
                } else if lifecycle.starts_with("closed") || lifecycle.starts_with("superseded") {
                    Some(Self::UnknownTerminal)
                } else {
                    None
                }
            }
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::Success => "settled success",
            Self::Failure => "settled failure",
            Self::UnknownTerminal => "settled terminal (unknown polarity)",
        }
    }

    /// Whether this polarity is compatible with a source lifecycle outcome.
    pub fn compatible_with(self, outcome: SourceLifecycleOutcome) -> bool {
        match self {
            Self::Success => matches!(
                outcome,
                SourceLifecycleOutcome::Completed | SourceLifecycleOutcome::ClosedSucceeded
            ),
            Self::Failure => matches!(
                outcome,
                SourceLifecycleOutcome::Failed
                    | SourceLifecycleOutcome::TerminalFailed
                    | SourceLifecycleOutcome::ClosedFailed
            ),
            Self::UnknownTerminal => false,
        }
    }
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
                raw_evidence: "success".to_string(),
            },
            SourceLifecycleEvent {
                identity_key: "road:test".to_string(),
                cursor: 5100,
                outcome: SourceLifecycleOutcome::Failed,
                source_file: "b.md".to_string(),
                source_line: 1,
                evidence_kind: ActivityEvidenceKind::ExactLifecycleSourceEvent,
                raw_evidence: "failure".to_string(),
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
                raw_evidence: "closed failed".to_string(),
            },
            SourceLifecycleEvent {
                identity_key: "road:test".to_string(),
                cursor: 5100,
                outcome: SourceLifecycleOutcome::Failed,
                source_file: "b.md".to_string(),
                source_line: 1,
                evidence_kind: ActivityEvidenceKind::ExactLifecycleSourceEvent,
                raw_evidence: "failed".to_string(),
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
                raw_evidence: "completed".to_string(),
            },
            SourceLifecycleEvent {
                identity_key: "road:test".to_string(),
                cursor: 5100,
                outcome: SourceLifecycleOutcome::ClosedSucceeded,
                source_file: "b.md".to_string(),
                source_line: 1,
                evidence_kind: ActivityEvidenceKind::ExactLifecycleSourceEvent,
                raw_evidence: "closed succeeded".to_string(),
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
                raw_evidence: "closed succeeded".to_string(),
            },
            SourceLifecycleEvent {
                identity_key: "road:test".to_string(),
                cursor: 5100,
                outcome: SourceLifecycleOutcome::ClosedSucceeded,
                source_file: "b.md".to_string(),
                source_line: 1,
                evidence_kind: ActivityEvidenceKind::ExactLifecycleSourceEvent,
                raw_evidence: "closed succeeded".to_string(),
            },
        ];
        let contradictions = detect_contradictions(&events);
        assert_eq!(contradictions.len(), 0);
    }

    // --- CanonicalTerminalPolarity tests ---

    use crate::frontmatter::parse;
    use crate::vault::Note;

    fn polarity_note(status: &str, lifecycle: &str) -> Note {
        let raw = format!(
            "---\ntype: technology-road\nstatus: {status}\nlifecycle: {lifecycle}\n---\n# Test\n"
        );
        let parsed = parse(&raw);
        Note {
            path: "test.md".to_string(),
            frontmatter: parsed.value,
            body: String::new(),
            content_hash: 0,
            parse_error: None,
            has_frontmatter: parsed.has_block,
            curated: true,
        }
    }

    #[test]
    fn polarity_completed_is_success() {
        let note = polarity_note("completed", "completed");
        assert_eq!(
            CanonicalTerminalPolarity::from_note(&note),
            Some(CanonicalTerminalPolarity::Success)
        );
    }

    #[test]
    fn polarity_failed_is_failure() {
        let note = polarity_note("failed", "terminal");
        assert_eq!(
            CanonicalTerminalPolarity::from_note(&note),
            Some(CanonicalTerminalPolarity::Failure)
        );
    }

    #[test]
    fn polarity_closed_is_unknown() {
        let note = polarity_note("closed", "closed");
        assert_eq!(
            CanonicalTerminalPolarity::from_note(&note),
            Some(CanonicalTerminalPolarity::UnknownTerminal)
        );
    }

    #[test]
    fn polarity_active_is_nonterminal() {
        let note = polarity_note("active", "in-progress");
        assert_eq!(CanonicalTerminalPolarity::from_note(&note), None);
    }

    #[test]
    fn polarity_success_compatible_with_succeeded() {
        assert!(CanonicalTerminalPolarity::Success
            .compatible_with(SourceLifecycleOutcome::ClosedSucceeded));
        assert!(
            CanonicalTerminalPolarity::Success.compatible_with(SourceLifecycleOutcome::Completed)
        );
    }

    #[test]
    fn polarity_success_incompatible_with_failed() {
        assert!(!CanonicalTerminalPolarity::Success.compatible_with(SourceLifecycleOutcome::Failed));
        assert!(!CanonicalTerminalPolarity::Success
            .compatible_with(SourceLifecycleOutcome::ClosedFailed));
    }

    #[test]
    fn polarity_failure_compatible_with_failed() {
        assert!(CanonicalTerminalPolarity::Failure.compatible_with(SourceLifecycleOutcome::Failed));
        assert!(CanonicalTerminalPolarity::Failure
            .compatible_with(SourceLifecycleOutcome::ClosedFailed));
        assert!(CanonicalTerminalPolarity::Failure
            .compatible_with(SourceLifecycleOutcome::TerminalFailed));
    }

    #[test]
    fn polarity_failure_incompatible_with_succeeded() {
        assert!(!CanonicalTerminalPolarity::Failure
            .compatible_with(SourceLifecycleOutcome::ClosedSucceeded));
        assert!(
            !CanonicalTerminalPolarity::Failure.compatible_with(SourceLifecycleOutcome::Completed)
        );
    }

    #[test]
    fn polarity_unknown_incompatible_with_any_outcome() {
        assert!(!CanonicalTerminalPolarity::UnknownTerminal
            .compatible_with(SourceLifecycleOutcome::ClosedSucceeded));
        assert!(!CanonicalTerminalPolarity::UnknownTerminal
            .compatible_with(SourceLifecycleOutcome::Failed));
    }

    // --- Negation tests ---

    #[test]
    fn negation_not_completed() {
        let msgs = vec![make_msg(
            5035,
            "the_mud_lounge_bot",
            SpeakerClass::Dm,
            "Test Road not completed yet",
        )];
        let ids = vec![make_identity(
            "road:test",
            "Test Road",
            "technology-road",
            vec![],
        )];
        let events = parse_lifecycle_events(&msgs, &ids, &Config::default());
        assert_eq!(events.len(), 0);
    }

    #[test]
    fn negation_never_completed() {
        let msgs = vec![make_msg(
            5035,
            "the_mud_lounge_bot",
            SpeakerClass::Dm,
            "Test Road never completed",
        )];
        let ids = vec![make_identity(
            "road:test",
            "Test Road",
            "technology-road",
            vec![],
        )];
        let events = parse_lifecycle_events(&msgs, &ids, &Config::default());
        assert_eq!(events.len(), 0);
    }

    #[test]
    fn negation_did_not_fail() {
        let msgs = vec![make_msg(
            5035,
            "the_mud_lounge_bot",
            SpeakerClass::Dm,
            "Test Road did not fail",
        )];
        let ids = vec![make_identity(
            "road:test",
            "Test Road",
            "technology-road",
            vec![],
        )];
        let events = parse_lifecycle_events(&msgs, &ids, &Config::default());
        assert_eq!(events.len(), 0);
    }

    #[test]
    fn negation_not_succeeded() {
        let msgs = vec![make_msg(
            5035,
            "the_mud_lounge_bot",
            SpeakerClass::Dm,
            "Test Road not succeeded",
        )];
        let ids = vec![make_identity(
            "road:test",
            "Test Road",
            "technology-road",
            vec![],
        )];
        let events = parse_lifecycle_events(&msgs, &ids, &Config::default());
        assert_eq!(events.len(), 0);
    }

    #[test]
    fn negation_without_does_not_negate() {
        let msgs = vec![make_msg(
            5035,
            "the_mud_lounge_bot",
            SpeakerClass::Dm,
            "Universal formation road | live at its own ceiling without print copying — the adjudicated terms, closed SUCCEEDED this year",
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
    fn negation_status_not_completed() {
        // "status: not completed" should be suppressed
        let msgs = vec![make_msg(
            5035,
            "the_mud_lounge_bot",
            SpeakerClass::Dm,
            "Test Road | status: not completed",
        )];
        let ids = vec![make_identity(
            "road:test",
            "Test Road",
            "technology-road",
            vec![],
        )];
        let events = parse_lifecycle_events(&msgs, &ids, &Config::default());
        assert_eq!(events.len(), 0);
    }

    #[test]
    fn negation_work_not_completed() {
        // "work not completed" should be suppressed
        let msgs = vec![make_msg(
            5035,
            "the_mud_lounge_bot",
            SpeakerClass::Dm,
            "Test Road work not completed",
        )];
        let ids = vec![make_identity(
            "road:test",
            "Test Road",
            "technology-road",
            vec![],
        )];
        let events = parse_lifecycle_events(&msgs, &ids, &Config::default());
        assert_eq!(events.len(), 0);
    }

    // --- Settled-terminal evidence boundary tests ---

    #[test]
    fn settled_terminal_event_between_result_and_source_cursor_is_relevant() {
        // Gate 1 regression: terminal_result_cursor=3500, source_cursor=4100
        // A contradictory event at 3900 should NOT be suppressed
        let note = {
            let raw = "---\ntype: technology-road\nroad_id: road:test\nstatus: completed\nlifecycle: completed\nterminal_result_cursor: 3500\nsource_cursor: 4100\n---\n# Test\n";
            let parsed = crate::frontmatter::parse(raw);
            Note {
                path: "40 Civilization/Technology/Roads/Test Road.md".to_string(),
                frontmatter: parsed.value,
                body: String::new(),
                content_hash: 0,
                parse_error: None,
                has_frontmatter: parsed.has_block,
                curated: true,
            }
        };
        let events = vec![
            SourceLifecycleEvent {
                identity_key: "road:test".to_string(),
                cursor: 3900,
                outcome: SourceLifecycleOutcome::ClosedFailed,
                source_file: "test.md".to_string(),
                source_line: 1,
                evidence_kind: ActivityEvidenceKind::ExactLifecycleSourceEvent,
                raw_evidence: "CLOSED FAILED".to_string(),
            },
            SourceLifecycleEvent {
                identity_key: "road:test".to_string(),
                cursor: 4200,
                outcome: SourceLifecycleOutcome::ClosedSucceeded,
                source_file: "test2.md".to_string(),
                source_line: 1,
                evidence_kind: ActivityEvidenceKind::ExactLifecycleSourceEvent,
                raw_evidence: "CLOSED SUCCEEDED".to_string(),
            },
        ];
        let selected = select_current_unresolved_terminal_events(&note, "road:test", &events);
        // Event at 3900 > terminal_result_cursor (3500) → should be selected
        // Event at 4200 > source_cursor (4100) → should be selected
        assert_eq!(selected.len(), 2, "both events should be selected");
        assert_eq!(selected[0].cursor, 3900);
        assert_eq!(selected[1].cursor, 4200);
    }

    #[test]
    fn nonterminal_event_at_or_below_source_cursor_suppressed() {
        // Nonterminal canon: event <= source_cursor should be suppressed
        let note = {
            let raw = "---\ntype: technology-road\nroad_id: road:test\nstatus: active\nlifecycle: in-progress\nsource_cursor: 4100\n---\n# Test\n";
            let parsed = crate::frontmatter::parse(raw);
            Note {
                path: "test.md".to_string(),
                frontmatter: parsed.value,
                body: String::new(),
                content_hash: 0,
                parse_error: None,
                has_frontmatter: parsed.has_block,
                curated: true,
            }
        };
        let events = vec![SourceLifecycleEvent {
            identity_key: "road:test".to_string(),
            cursor: 4000,
            outcome: SourceLifecycleOutcome::ClosedSucceeded,
            source_file: "test.md".to_string(),
            source_line: 1,
            evidence_kind: ActivityEvidenceKind::ExactLifecycleSourceEvent,
            raw_evidence: "CLOSED SUCCEEDED".to_string(),
        }];
        let selected = select_current_unresolved_terminal_events(&note, "road:test", &events);
        assert!(
            selected.is_empty(),
            "event at or below source_cursor should be suppressed for nonterminal"
        );
    }

    #[test]
    fn settled_terminal_event_at_settlement_cursor_suppressed() {
        // Event exactly at terminal_result_cursor should be suppressed
        let note = {
            let raw = "---\ntype: technology-road\nroad_id: road:test\nstatus: completed\nlifecycle: completed\nterminal_result_cursor: 3500\nsource_cursor: 4100\n---\n# Test\n";
            let parsed = crate::frontmatter::parse(raw);
            Note {
                path: "test.md".to_string(),
                frontmatter: parsed.value,
                body: String::new(),
                content_hash: 0,
                parse_error: None,
                has_frontmatter: parsed.has_block,
                curated: true,
            }
        };
        let events = vec![SourceLifecycleEvent {
            identity_key: "road:test".to_string(),
            cursor: 3500,
            outcome: SourceLifecycleOutcome::ClosedSucceeded,
            source_file: "test.md".to_string(),
            source_line: 1,
            evidence_kind: ActivityEvidenceKind::ExactLifecycleSourceEvent,
            raw_evidence: "CLOSED SUCCEEDED".to_string(),
        }];
        let selected = select_current_unresolved_terminal_events(&note, "road:test", &events);
        assert!(
            selected.is_empty(),
            "event exactly at settlement cursor should be suppressed"
        );
    }
}
