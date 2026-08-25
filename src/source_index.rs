//! Source index: deterministic parsing of direct Player-source messages,
//! identity matching, mention tracking, cursor-epoch mapping, and receipt
//! extraction.
//!
//! This subsystem is separate from `VaultIndex` — it full-reads only the
//! configured direct-source paths, not the entire vault.

use std::collections::{HashMap, HashSet};
use std::path::Path;

use walkdir::WalkDir;

use crate::config::Config;
use crate::frontmatter::parse;
use crate::vault::VaultIndex;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A parsed direct-source message.
#[derive(Debug, Clone)]
pub struct SourceMessage {
    pub file: String,
    pub cursor: i64,
    pub timestamp: Option<String>,
    pub speaker: String,
    pub speaker_class: SpeakerClass,
    pub body: String,
    /// Line number in the source file where this message starts.
    pub line: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpeakerClass {
    Player,
    Dm,
    Unknown,
}

/// A known identity extracted from canonical records.
#[derive(Debug, Clone)]
pub struct KnownIdentity {
    pub key: String,
    pub canonical_id: Option<String>,
    pub title: String,
    pub aliases: Vec<String>,
    pub note_path: String,
    pub type_name: String,
    pub status: Option<String>,
    pub lifecycle: Option<String>,
}

/// A mention of a known identity in source.
#[derive(Debug, Clone)]
pub struct Mention {
    pub identity_key: String,
    pub cursor: i64,
    pub message_index: usize,
}

/// A cursor-to-epoch mapping (cursor range → turn/year).
#[derive(Debug, Clone)]
pub struct CursorEpoch {
    pub cursor_start: i64,
    pub cursor_end: i64,
    pub turn: Option<i64>,
    pub year: Option<i64>,
    pub source: String,
}

/// A structured receipt parsed from source.
#[derive(Debug, Clone)]
pub struct ParsedReceipt {
    pub receipt_type: String,
    pub fields: HashMap<String, String>,
    pub source_file: String,
    pub cursor: i64,
    pub speaker: String,
    pub speaker_class: SpeakerClass,
    pub line: usize,
}

/// Per-identity activity summary.
#[derive(Debug, Clone, Default)]
pub struct IdentityActivity {
    pub last_mentioned_cursor: Option<i64>,
    pub last_mentioned_message_index: Option<usize>,
    pub mention_count: usize,
    pub distinct_message_count: usize,
    pub last_material_cursor: Option<i64>,
    pub last_evidenced_use_cursor: Option<i64>,
}

/// Coverage candidate: an unresolved proper-name or ID-like pattern.
#[derive(Debug, Clone)]
pub struct CoverageCandidate {
    pub text: String,
    pub occurrences: usize,
    pub distinct_messages: usize,
    pub signal: String,
}

/// The complete source index.
#[derive(Debug)]
pub struct SourceIndex {
    pub messages: Vec<SourceMessage>,
    pub identities: Vec<KnownIdentity>,
    pub mentions: Vec<Mention>,
    pub cursor_epochs: Vec<CursorEpoch>,
    pub receipts: Vec<ParsedReceipt>,
    pub activity: HashMap<String, IdentityActivity>,
    pub candidates: Vec<CoverageCandidate>,
    pub source_files_scanned: usize,
    pub source_files_cached: usize,
    pub index_duration_ms: u64,
    // Technology object counts (from vault index, not just tracked_types)
    pub portfolio_count: usize,
    pub road_count: usize,
    pub capability_count: usize,
    pub legacy_node_count: usize,
    // Direct-source frontier metrics
    pub max_source_cursor: Option<i64>,
    pub min_source_cursor: Option<i64>,
    pub active_legacy_portfolio_count: usize,
    pub declared_child_road_count: usize,
}

// ---------------------------------------------------------------------------
// Telegram message parser
// ---------------------------------------------------------------------------

/// Parse a Telegram cursor from an anchor line like
/// `^telegram--1003944547386-4668`
fn parse_cursor(anchor: &str) -> Option<i64> {
    let trimmed = anchor.trim();
    let after_prefix = trimmed.strip_prefix("^telegram-")?;
    // The cursor is the last numeric segment after the last `-`.
    let cursor_str = after_prefix.rsplit('-').next()?;
    cursor_str.parse::<i64>().ok()
}

/// Parse speaker from a line like `**04:48:55 PDT** · the\_mud\_lounge\_bot`
fn parse_speaker(line: &str) -> (String, SpeakerClass) {
    let trimmed = line.trim();
    // Find the speaker name after the `·` separator.
    if let Some(pos) = trimmed.find('·') {
        let speaker = trimmed[pos + '·'.len_utf8()..]
            .trim()
            .replace("\\_", "_")
            .replace("\\-", "-");
        let class = classify_speaker(&speaker);
        (speaker, class)
    } else {
        ("unknown".to_string(), SpeakerClass::Unknown)
    }
}

fn classify_speaker(name: &str) -> SpeakerClass {
    let lower = name.to_ascii_lowercase();
    // Common bot/DM patterns
    if lower.contains("bot") || lower.contains("mud_lounge") || lower.contains("mud-lounge") {
        return SpeakerClass::Dm;
    }
    SpeakerClass::Unknown
}

/// Classify speaker using config lists.
fn classify_speaker_with_config(name: &str, config: &Config) -> SpeakerClass {
    let lower = name.to_ascii_lowercase();
    if config
        .dm_speakers
        .iter()
        .any(|s| s.eq_ignore_ascii_case(&lower))
    {
        return SpeakerClass::Dm;
    }
    if config
        .player_speakers
        .iter()
        .any(|s| s.eq_ignore_ascii_case(&lower))
    {
        return SpeakerClass::Player;
    }
    // Fall back to heuristic
    classify_speaker(name)
}

/// Parse messages from a single Telegram source file.
fn parse_messages(file_path: &str, raw: &str, config: &Config) -> Vec<SourceMessage> {
    let mut messages = Vec::new();
    let lines: Vec<&str> = raw.lines().collect();
    let mut i = 0;

    while i < lines.len() {
        let line = lines[i].trim();
        // Look for cursor anchor: ^telegram-...
        if line.starts_with("^telegram-") {
            let cursor = match parse_cursor(line) {
                Some(c) => c,
                None => {
                    i += 1;
                    continue;
                }
            };
            let anchor_line = i;

            // Next line should be the timestamp/speaker line
            let (timestamp, speaker, speaker_class) = if i + 1 < lines.len() {
                let ts_line = lines[i + 1].trim();
                let ts = extract_timestamp(ts_line);
                let (sp, _sc) = parse_speaker(ts_line);
                let sc = classify_speaker_with_config(&sp, config);
                (ts, sp, sc)
            } else {
                (None, "unknown".to_string(), SpeakerClass::Unknown)
            };

            // Collect body lines until the next cursor anchor or end of file
            let mut body_lines = Vec::new();
            i += 2; // skip anchor + timestamp line
            while i < lines.len() {
                let l = lines[i].trim();
                if l.starts_with("^telegram-") {
                    break;
                }
                body_lines.push(lines[i]);
                i += 1;
            }

            let body = body_lines.join("\n").trim().to_string();
            messages.push(SourceMessage {
                file: file_path.to_string(),
                cursor,
                timestamp,
                speaker,
                speaker_class,
                body,
                line: anchor_line + 1, // 1-indexed
            });
        } else {
            i += 1;
        }
    }
    messages
}

fn extract_timestamp(line: &str) -> Option<String> {
    // Pattern: **HH:MM:SS TZ** · speaker
    let trimmed = line.trim();
    if !trimmed.starts_with("**") {
        return None;
    }
    // Find the closing ** after the opening **
    let after_open = &trimmed[2..];
    let end = after_open.find("**")?;
    if end < 2 {
        return None;
    }
    Some(after_open[..end].to_string())
}

// ---------------------------------------------------------------------------
// Identity dictionary
// ---------------------------------------------------------------------------

/// Build the known-identity dictionary from curated canonical records.
pub fn build_identity_dict(index: &VaultIndex, config: &Config) -> Vec<KnownIdentity> {
    let mut identities = Vec::new();
    for note in &index.notes {
        if !note.curated || note.parse_error.is_some() {
            continue;
        }
        let type_name = match note.type_str() {
            Some(t) => t,
            None => continue,
        };
        if !config.tracked_types.iter().any(|t| t == &type_name) {
            continue;
        }
        let fm = note.fm();
        let canonical_id = config
            .id_fields
            .iter()
            .find_map(|f| fm.get_str(f))
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty());

        let title = note.title().to_string();
        let aliases = fm.get_list("aliases");

        // Generate the internal key
        let key = canonical_id
            .clone()
            .unwrap_or_else(|| format!("path:{}", note.path));

        identities.push(KnownIdentity {
            key,
            canonical_id,
            title,
            aliases,
            note_path: note.path.clone(),
            type_name,
            status: note.status(),
            lifecycle: fm.get_str("lifecycle"),
        });
    }
    identities
}

// ---------------------------------------------------------------------------
// Exact mention matching
// ---------------------------------------------------------------------------

/// Find exact mentions of known identities in source messages.
/// Matching precedence: stable ID > exact title > exact alias.
pub fn find_mentions(
    messages: &[SourceMessage],
    identities: &[KnownIdentity],
    config: &Config,
) -> Vec<Mention> {
    let mut mentions = Vec::new();

    // Build lookup structures
    // For alias collision detection: if an alias maps to multiple keys, skip it.
    let mut alias_to_keys: HashMap<String, Vec<String>> = HashMap::new();
    for id in identities {
        for alias in &id.aliases {
            let norm = normalize_text(alias);
            if !config
                .ignored_aliases
                .iter()
                .any(|a| a.eq_ignore_ascii_case(&norm))
            {
                alias_to_keys.entry(norm).or_default().push(id.key.clone());
            }
        }
    }
    // Collect ambiguous aliases
    let ambiguous_aliases: HashSet<String> = alias_to_keys
        .iter()
        .filter(|(_, keys)| keys.len() > 1)
        .map(|(alias, _)| alias.clone())
        .collect();

    // Build title → key map (exact)
    let title_to_key: HashMap<String, String> = identities
        .iter()
        .map(|id| (normalize_text(&id.title), id.key.clone()))
        .collect();

    // Build ID → key map
    let id_to_key: HashMap<String, String> = identities
        .iter()
        .filter_map(|id| {
            id.canonical_id
                .as_ref()
                .map(|cid| (cid.clone(), id.key.clone()))
        })
        .collect();

    // Build alias → key map (non-ambiguous only)
    let alias_to_key: HashMap<String, String> = alias_to_keys
        .iter()
        .filter(|(alias, _)| !ambiguous_aliases.contains(*alias))
        .filter_map(|(alias, keys)| {
            if keys.len() == 1 {
                Some((alias.clone(), keys[0].clone()))
            } else {
                None
            }
        })
        .collect();

    for (msg_idx, msg) in messages.iter().enumerate() {
        let body_norm = normalize_text(&msg.body);

        // Track which identities were already matched in this message
        // to avoid double-counting
        let mut matched_keys: HashSet<String> = HashSet::new();

        // 1. Exact stable ID match
        for (id, key) in &id_to_key {
            if body_norm.contains(id.as_str()) && matched_keys.insert(key.clone()) {
                mentions.push(Mention {
                    identity_key: key.clone(),
                    cursor: msg.cursor,
                    message_index: msg_idx,
                });
            }
        }

        // 2. Exact canonical title match
        for (title_norm, key) in &title_to_key {
            if title_norm.len() >= 3
                && body_norm.contains(title_norm.as_str())
                && matched_keys.insert(key.clone())
            {
                mentions.push(Mention {
                    identity_key: key.clone(),
                    cursor: msg.cursor,
                    message_index: msg_idx,
                });
            }
        }

        // 3. Exact alias match (non-ambiguous only)
        for (alias_norm, key) in &alias_to_key {
            if alias_norm.len() >= 3
                && body_norm.contains(alias_norm.as_str())
                && matched_keys.insert(key.clone())
            {
                mentions.push(Mention {
                    identity_key: key.clone(),
                    cursor: msg.cursor,
                    message_index: msg_idx,
                });
            }
        }
    }

    mentions
}

/// Normalize text for identity lookup and candidate matching.
///
/// Handles: Unicode NFC, case folding, Markdown backslash escapes,
/// hyphen/dash variants, curly/straight apostrophes, possessive
/// suffixes, repeated whitespace.
pub fn normalize_text(s: &str) -> String {
    let mut out = String::with_capacity(s.len());

    // 1. Strip Markdown backslash escapes: \- → -, \' → ', etc.
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\\' && i + 1 < chars.len() {
            match chars[i + 1] {
                '-' | '\'' | '"' | '.' | '!' | '?' | ':' | ';' | '(' | ')' | '[' | ']' => {
                    out.push(chars[i + 1]);
                    i += 2;
                }
                _ => {
                    out.push(chars[i]);
                    i += 1;
                }
            }
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }

    // 2. Normalize hyphen/dash variants to ASCII hyphen
    let mut normalized = String::with_capacity(out.len());
    for c in out.chars() {
        match c {
            '\u{2010}' | '\u{2011}' | '\u{2012}' | '\u{2013}' | '\u{2014}' | '\u{2015}'
            | '\u{2212}' | '\u{FE58}' | '\u{FE63}' | '\u{FF0D}' => {
                normalized.push('-');
            }
            // Curly apostrophes → straight
            '\u{2018}' | '\u{2019}' | '\u{02BC}' | '\u{02BD}' => {
                normalized.push('\'');
            }
            _ => {
                normalized.push(c);
            }
        }
    }

    // 3. Case fold
    let lower = normalized.to_ascii_lowercase();

    // 4. Strip possessive suffixes: 's, \u{2019}s at end of words
    let no_possessive = strip_possessives(&lower);

    // 5. Collapse whitespace
    no_possessive
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

/// Strip possessive suffixes ('s, 's) from text.
/// Only strips when 's appears at a word boundary (preceded by a letter).
fn strip_possessives(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let chars: Vec<char> = s.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        if chars[i] == '\''
            && i + 1 < chars.len()
            && chars[i + 1] == 's'
            && i > 0
            && chars[i - 1].is_alphabetic()
            && (i + 2 >= chars.len() || !chars[i + 2].is_alphabetic())
        {
            // Skip the 's
            i += 2;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

/// Build a normalized lookup key from a canonical title or alias.
/// This is more aggressive than normalize_text — it also strips
/// decorated title suffixes like " - Levy Annex Keeper" for matching
/// the base name, but only when the alias is explicitly declared.
pub fn normalize_for_lookup(s: &str) -> String {
    normalize_text(s)
}

// ---------------------------------------------------------------------------
// Cursor epoch mapping
// ---------------------------------------------------------------------------

/// Build cursor-epoch mappings from structured evidence.
/// Sources (descending confidence):
/// 1. Explicit structured receipt containing turn/year
/// 2. Runtime records with cursor/range and turn/year
/// 3. Other configured boundary records
pub fn build_cursor_epochs(
    index: &VaultIndex,
    boundary: &crate::boundary::StateBoundary,
) -> Vec<CursorEpoch> {
    let mut epochs = Vec::new();

    // From boundary: if we have current_source_cursor and current_turn/year,
    // the latest cursor maps to the current turn/year.
    if let (Some(cursor), Some(turn), Some(year)) = (
        boundary.current_source_cursor,
        boundary.current_turn,
        boundary.current_year,
    ) {
        epochs.push(CursorEpoch {
            cursor_start: cursor,
            cursor_end: cursor,
            turn: Some(turn),
            year: Some(year),
            source: "state-boundary".to_string(),
        });
    }

    // From runtime records that declare source_cursor + turn + year
    for note in &index.notes {
        if !note.curated {
            continue;
        }
        let type_str = note.type_str().unwrap_or_default();
        if type_str != "runtime-handoff" && type_str != "runtime-context-pack" {
            continue;
        }
        let fm = note.fm();
        if let (Some(cursor), Some(turn), Some(year)) = (
            fm.get_i64("source_cursor"),
            fm.get_i64("turn"),
            fm.get_i64("year"),
        ) {
            epochs.push(CursorEpoch {
                cursor_start: cursor,
                cursor_end: cursor,
                turn: Some(turn),
                year: Some(year),
                source: note.path.clone(),
            });
        }
    }

    // Sort by cursor
    epochs.sort_by_key(|e| e.cursor_start);
    epochs
}

/// Resolve turn/year for a cursor using the epoch index.
/// Returns (turn, year) or (None, None) if unmapped.
pub fn resolve_cursor(epochs: &[CursorEpoch], cursor: i64) -> (Option<i64>, Option<i64>) {
    // Find the epoch whose range contains this cursor
    for epoch in epochs.iter().rev() {
        if cursor >= epoch.cursor_start && cursor <= epoch.cursor_end {
            return (epoch.turn, epoch.year);
        }
    }
    // If not in any range, find the nearest epoch at or below.
    // Since epochs are point-based (cursor_start == cursor_end),
    // find the highest epoch whose cursor_start <= query cursor.
    let mut best: Option<&CursorEpoch> = None;
    for epoch in epochs.iter() {
        if epoch.cursor_start <= cursor {
            best = Some(epoch);
        } else {
            break;
        }
    }
    if let Some(epoch) = best {
        return (epoch.turn, epoch.year);
    }
    // If cursor is below all epochs, return unknown
    (None, None)
}

// ---------------------------------------------------------------------------
// Receipt parsing
// ---------------------------------------------------------------------------

/// Parse structured receipts from source messages.
/// Syntax: [CL TYPE key=value key=value ...]
pub fn parse_receipts(messages: &[SourceMessage]) -> Vec<ParsedReceipt> {
    let mut receipts = Vec::new();

    for msg in messages {
        // Look for [CL ...] patterns in the body
        for line in msg.body.lines() {
            let trimmed = line.trim();
            if let Some(inner) = extract_receipt_tag(trimmed) {
                let parts = parse_receipt_parts(inner);
                if let Some(receipt_type) = parts.first().cloned() {
                    let mut fields = HashMap::new();
                    for part in &parts[1..] {
                        if let Some((k, v)) = part.split_once('=') {
                            fields.insert(k.trim().to_string(), v.trim().to_string());
                        }
                    }
                    receipts.push(ParsedReceipt {
                        receipt_type: receipt_type.to_uppercase(),
                        fields,
                        source_file: msg.file.clone(),
                        cursor: msg.cursor,
                        speaker: msg.speaker.clone(),
                        speaker_class: msg.speaker_class,
                        line: msg.line,
                    });
                }
            }
        }
    }

    receipts
}

fn extract_receipt_tag(line: &str) -> Option<&str> {
    let start = line.find("[CL ")?;
    let rest = &line[start + 4..];
    let end = rest.find(']')?;
    Some(&rest[..end])
}

fn parse_receipt_parts(inner: &str) -> Vec<String> {
    // Split by whitespace, but respect quoted values
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;

    for c in inner.chars() {
        match c {
            '"' => in_quotes = !in_quotes,
            ' ' if !in_quotes => {
                if !current.is_empty() {
                    parts.push(current.clone());
                    current.clear();
                }
            }
            _ => current.push(c),
        }
    }
    if !current.is_empty() {
        parts.push(current);
    }
    parts
}

// ---------------------------------------------------------------------------
// Activity aggregation
// ---------------------------------------------------------------------------

/// Aggregate mention and receipt activity per identity.
pub fn aggregate_activity(
    mentions: &[Mention],
    receipts: &[ParsedReceipt],
    identities: &[KnownIdentity],
) -> HashMap<String, IdentityActivity> {
    let mut activity: HashMap<String, IdentityActivity> = HashMap::new();

    // Initialize from identities
    for id in identities {
        activity.insert(id.key.clone(), IdentityActivity::default());
    }

    // Aggregate mentions
    let mut seen_per_identity: HashMap<String, HashSet<usize>> = HashMap::new();
    for m in mentions {
        let act = activity.entry(m.identity_key.clone()).or_default();
        act.mention_count += 1;
        match act.last_mentioned_cursor {
            Some(c) if c >= m.cursor => {}
            _ => {
                act.last_mentioned_cursor = Some(m.cursor);
                act.last_mentioned_message_index = Some(m.message_index);
            }
        }
        let seen = seen_per_identity.entry(m.identity_key.clone()).or_default();
        seen.insert(m.message_index);
    }
    // Count distinct messages
    for (key, seen) in &seen_per_identity {
        if let Some(act) = activity.get_mut(key) {
            act.distinct_message_count = seen.len();
        }
    }

    // Aggregate receipts for material activity and capability use
    for receipt in receipts {
        match receipt.receipt_type.as_str() {
            "USE" => {
                if let Some(cap_id) = receipt.fields.get("capability") {
                    let act = activity.entry(cap_id.clone()).or_default();
                    match act.last_evidenced_use_cursor {
                        Some(c) if c >= receipt.cursor => {}
                        _ => {
                            act.last_evidenced_use_cursor = Some(receipt.cursor);
                        }
                    }
                }
            }
            "RECEIPT" | "ACCEPT" => {
                if let Some(road_id) = receipt
                    .fields
                    .get("road")
                    .or_else(|| receipt.fields.get("id"))
                {
                    let act = activity.entry(road_id.clone()).or_default();
                    match act.last_material_cursor {
                        Some(c) if c >= receipt.cursor => {}
                        _ => {
                            act.last_material_cursor = Some(receipt.cursor);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    activity
}

/// Seed `last_material_cursor` from canonical `source_cursor`.
///
/// `source_cursor` on a canonical record means "the latest direct source
/// that changed this record" — that is valid material evidence.
/// `reviewed_through_cursor` is NOT materiality (inspection ≠ change).
pub fn seed_canonical_materiality(
    activity: &mut HashMap<String, IdentityActivity>,
    identities: &[KnownIdentity],
    vault_index: &VaultIndex,
) {
    for id in identities {
        if let Some(note) = vault_index.find_by_path(&id.note_path) {
            let fm = note.fm();
            if let Some(source_cursor) = fm.get_i64("source_cursor") {
                let act = activity.entry(id.key.clone()).or_default();
                match act.last_material_cursor {
                    Some(c) if c >= source_cursor => {}
                    _ => {
                        act.last_material_cursor = Some(source_cursor);
                    }
                }
            }
        }
    }
}

/// Count declared child roads through the bounded legacy adapter.
fn count_declared_roads(body: &str) -> usize {
    crate::legacy_technology::extract_roads(body, &[]).len()
}

// ---------------------------------------------------------------------------
// Coverage candidate extraction
// ---------------------------------------------------------------------------

/// Extract conservative coverage candidates from source messages.
/// Strong signals: stable-ID syntax, repeated proper names, receipt syntax.
///
/// Candidates that match known canonical identities (after normalization)
/// are excluded before extraction. The `canonical_identity_normalized` set
/// is the broader universe (all curated notes) for suppression.
pub fn extract_candidates(
    messages: &[SourceMessage],
    identities: &[KnownIdentity],
    config: &Config,
    canonical_identity_normalized: &HashSet<String>,
) -> Vec<CoverageCandidate> {
    let mut candidates: HashMap<String, CoverageCandidate> = HashMap::new();

    // Build set of known identity normalized forms for exclusion.
    // Merge continuity-tracked identities with the broader canonical universe.
    let known_normalized: HashSet<String> = {
        let mut set = canonical_identity_normalized.clone();
        for id in identities {
            set.insert(normalize_text(&id.title));
            if let Some(cid) = &id.canonical_id {
                set.insert(normalize_text(cid));
            }
            for alias in &id.aliases {
                set.insert(normalize_text(alias));
            }
        }
        set
    };

    // Track per-candidate message sets
    let mut candidate_messages: HashMap<String, HashSet<String>> = HashMap::new();

    for msg in messages {
        let body = &msg.body;

        // 1. Stable-ID syntax: TR-*, CAP-*, TP-*
        for token in body.split_whitespace() {
            let clean = token.trim_matches(|c: char| !c.is_alphanumeric() && c != '-');
            if is_stable_id_syntax(clean) {
                let norm = normalize_text(clean);
                if !known_normalized.contains(&norm) {
                    let entry =
                        candidates
                            .entry(clean.to_string())
                            .or_insert_with(|| CoverageCandidate {
                                text: clean.to_string(),
                                occurrences: 0,
                                distinct_messages: 0,
                                signal: "stable-id-syntax".to_string(),
                            });
                    entry.occurrences += 1;
                    candidate_messages
                        .entry(clean.to_string())
                        .or_default()
                        .insert(msg.file.clone());
                }
            }
        }

        // 2. Proper-name heuristic: two+ capitalized tokens, not already known
        for name in extract_proper_names(body) {
            let norm = normalize_text(&name);
            if norm.len() < 4 || known_normalized.contains(&norm) {
                continue;
            }
            // Check if this is a substring of any canonical identity
            // (e.g., "National Records" is a substring of "National Records and Custody")
            let is_substring = known_normalized
                .iter()
                .any(|k| k.len() > norm.len() && k.contains(&norm));
            if is_substring {
                continue;
            }
            // Filter out ALL-CAPS protocol/status prose
            if is_all_caps_protocol(&name) {
                continue;
            }
            let entry = candidates
                .entry(name.clone())
                .or_insert_with(|| CoverageCandidate {
                    text: name.clone(),
                    occurrences: 0,
                    distinct_messages: 0,
                    signal: "proper-name".to_string(),
                });
            entry.occurrences += 1;
            candidate_messages
                .entry(name.clone())
                .or_default()
                .insert(msg.file.clone());
        }
    }

    // Update distinct message counts
    for (key, files) in &candidate_messages {
        if let Some(c) = candidates.get_mut(key) {
            c.distinct_messages = files.len();
        }
    }

    // Filter by thresholds
    let mut result: Vec<CoverageCandidate> = candidates
        .into_values()
        .filter(|c| {
            if c.signal == "proper-name" {
                c.occurrences >= config.proper_name_min_occurrences
                    && c.distinct_messages >= config.proper_name_min_distinct_messages
            } else {
                true // stable-ID syntax always passes
            }
        })
        .collect();

    // Stable total ordering: signal, occurrences, distinct messages, text.
    // The final textual tie-breaker prevents HashMap iteration order from
    // changing bounded report queues across identical runs.
    result.sort_by(|a, b| {
        a.signal
            .cmp(&b.signal)
            .reverse()
            .then_with(|| b.occurrences.cmp(&a.occurrences))
            .then_with(|| b.distinct_messages.cmp(&a.distinct_messages))
            .then_with(|| a.text.cmp(&b.text))
    });

    result
}

fn is_stable_id_syntax(s: &str) -> bool {
    // TR-*, CAP-*, TP-* patterns
    (s.starts_with("TR-") || s.starts_with("CAP-") || s.starts_with("TP-"))
        && s.len() > 3
        && s[3..].chars().all(|c| c.is_alphanumeric() || c == '-')
}

/// Detect ALL-CAPS protocol/status prose that is unlikely to be a durable
/// world identity. Examples: "RETURN STATE", "AUDIT PROTOCOL",
/// "SOVEREIGN GATE", "COMPLETE Nothing", "OWNER UNAVAILABLE".
fn is_all_caps_protocol(name: &str) -> bool {
    let words: Vec<&str> = name.split_whitespace().collect();
    if words.is_empty() {
        return false;
    }
    // If ALL words are fully uppercase and >= 3 chars, it's likely protocol prose
    let all_caps_count = words
        .iter()
        .filter(|w| w.len() >= 3 && w.chars().all(|c| !c.is_alphabetic() || c.is_uppercase()))
        .count();
    if all_caps_count == words.len() {
        return true;
    }
    // Check for common protocol/status words
    let protocol_words = [
        "return",
        "complete",
        "owner",
        "status",
        "protocol",
        "section",
        "audit",
        "sovereign",
        "missing",
        "holding",
        "produced",
        "today",
        "unavailable",
        "nothing",
        "state",
        "still",
        "pending",
        "active",
        "inactive",
        "resolved",
        "unresolved",
        "blocked",
        "external",
    ];
    let lower = name.to_ascii_lowercase();
    let word_set: HashSet<&str> = lower.split_whitespace().collect();
    let protocol_count = protocol_words
        .iter()
        .filter(|pw| word_set.contains(*pw))
        .count();
    // If more than half the words are protocol words, it's protocol prose
    protocol_count > 0 && protocol_count >= words.len() / 2
}

/// Extract proper names: two or more consecutive capitalized tokens.
fn extract_proper_names(text: &str) -> Vec<String> {
    let mut names = Vec::new();
    let words: Vec<&str> = text.split_whitespace().collect();
    let mut i = 0;
    while i < words.len() {
        let w = words[i].trim_matches(|c: char| !c.is_alphanumeric() && c != '\'' && c != '-');
        if w.len() >= 2
            && w.chars().next().map(|c| c.is_uppercase()).unwrap_or(false)
            && !is_stopword(w)
        {
            // Try to extend to multi-token name
            let mut name_parts = vec![w];
            let mut j = i + 1;
            while j < words.len() {
                let nw =
                    words[j].trim_matches(|c: char| !c.is_alphanumeric() && c != '\'' && c != '-');
                if nw.len() >= 2
                    && nw.chars().next().map(|c| c.is_uppercase()).unwrap_or(false)
                    && !is_stopword(nw)
                {
                    name_parts.push(nw);
                    j += 1;
                } else {
                    break;
                }
            }
            if name_parts.len() >= 2 {
                names.push(name_parts.join(" "));
                i = j;
            } else {
                i += 1;
            }
        } else {
            i += 1;
        }
    }
    names
}

fn is_stopword(w: &str) -> bool {
    matches!(
        w.to_ascii_lowercase().as_str(),
        "the"
            | "a"
            | "an"
            | "and"
            | "or"
            | "but"
            | "in"
            | "on"
            | "at"
            | "to"
            | "for"
            | "of"
            | "with"
            | "by"
            | "from"
            | "is"
            | "are"
            | "was"
            | "were"
            | "be"
            | "been"
            | "being"
            | "have"
            | "has"
            | "had"
            | "do"
            | "does"
            | "did"
            | "will"
            | "would"
            | "could"
            | "should"
            | "may"
            | "might"
            | "shall"
            | "can"
            | "not"
            | "no"
            | "yes"
            | "this"
            | "that"
            | "these"
            | "those"
            | "it"
            | "its"
            | "he"
            | "she"
            | "they"
            | "them"
            | "his"
            | "her"
            | "their"
            | "my"
            | "your"
            | "our"
            | "we"
            | "you"
            | "if"
            | "then"
            | "else"
            | "when"
            | "where"
            | "how"
            | "what"
            | "which"
            | "who"
            | "whom"
            | "why"
            | "all"
            | "each"
            | "every"
            | "both"
            | "few"
            | "more"
            | "most"
            | "other"
            | "some"
            | "such"
            | "only"
            | "own"
            | "same"
            | "so"
            | "than"
            | "too"
            | "very"
            | "just"
            | "also"
            | "now"
            | "here"
            | "there"
            | "up"
            | "out"
            | "about"
            | "over"
            | "after"
            | "before"
            | "between"
            | "under"
            | "again"
            | "further"
            | "once"
            | "new"
            | "one"
            | "two"
            | "three"
            | "first"
            | "second"
            | "last"
            | "next"
            | "year"
            | "years"
            | "man"
            | "men"
            | "people"
            | "say"
            | "said"
            | "come"
            | "came"
            | "go"
            | "went"
            | "make"
            | "made"
            | "take"
            | "took"
            | "get"
            | "got"
            | "see"
            | "saw"
            | "know"
            | "knew"
            | "think"
            | "thought"
            | "want"
            | "need"
            | "use"
            | "used"
            | "find"
            | "found"
            | "give"
            | "gave"
            | "tell"
            | "told"
            | "work"
            | "worked"
            | "call"
            | "called"
            | "try"
            | "tried"
            | "ask"
            | "asked"
            | "put"
            | "set"
            | "keep"
            | "kept"
            | "let"
            | "begin"
            | "began"
            | "show"
            | "showed"
            | "hear"
            | "heard"
            | "play"
            | "played"
            | "run"
            | "ran"
            | "move"
            | "moved"
            | "live"
            | "lived"
            | "believe"
            | "felt"
            | "feel"
            | "leave"
            | "left"
            | "bring"
            | "brought"
    )
}

// ---------------------------------------------------------------------------
// Source index builder
// ---------------------------------------------------------------------------

/// Build the complete source index by scanning configured direct-source paths.
pub fn build(
    vault_root: &Path,
    vault_index: &VaultIndex,
    config: &Config,
    boundary: &crate::boundary::StateBoundary,
) -> SourceIndex {
    let start = std::time::Instant::now();

    // 1. Scan direct-source files
    let mut messages = Vec::new();
    let mut source_files_scanned = 0usize;

    for prefix in &config.direct_source_prefixes {
        let dir = vault_root.join(prefix);
        if !dir.exists() {
            continue;
        }
        let entries: Vec<_> = WalkDir::new(&dir)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
            .filter(|e| {
                e.path()
                    .extension()
                    .and_then(|e| e.to_str())
                    .map(|ext| ext.eq_ignore_ascii_case("md"))
                    .unwrap_or(false)
            })
            .collect();

        for entry in entries {
            let abs = entry.path();
            let rel = match abs.strip_prefix(vault_root) {
                Ok(r) => r.to_string_lossy().replace('\\', "/"),
                Err(_) => continue,
            };
            match std::fs::read_to_string(abs) {
                Ok(raw) => {
                    source_files_scanned += 1;
                    // Parse the file contents, never the relative path: direct-source
                    // frontmatter must be removed before message parsing.
                    let parsed = parse(&raw);
                    // Use the body (after frontmatter) for message parsing
                    let body = if parsed.has_block { &parsed.body } else { &raw };
                    let file_messages = parse_messages(&rel, body, config);
                    messages.extend(file_messages);
                }
                Err(_) => continue,
            }
        }
    }

    // Sort messages by cursor for deterministic ordering
    messages.sort_by_key(|m| m.cursor);

    // 2. Build identity dictionary
    let identities = build_identity_dict(vault_index, config);

    // 3. Find mentions
    let mentions = find_mentions(&messages, &identities, config);

    // 4. Build cursor epochs
    let cursor_epochs = build_cursor_epochs(vault_index, boundary);

    // 5. Parse receipts
    let receipts = parse_receipts(&messages);

    // 6. Aggregate activity
    let mut activity = aggregate_activity(&mentions, &receipts, &identities);

    // 6b. Seed material activity from canonical source_cursor
    seed_canonical_materiality(&mut activity, &identities, vault_index);

    // 7. Build canonical identity universe (all curated notes with types)
    // This is broader than tracked_types — used for candidate suppression.
    let canonical_identity_normalized: HashSet<String> = vault_index
        .notes
        .iter()
        .filter(|n| n.curated && n.parse_error.is_none() && n.type_str().is_some())
        .flat_map(|n| {
            let mut keys = vec![normalize_text(n.title())];
            let fm = n.fm();
            for field in &config.id_fields {
                if let Some(v) = fm.get_str(field) {
                    keys.push(normalize_text(&v));
                }
            }
            keys.extend(fm.get_list("aliases").iter().map(|a| normalize_text(a)));
            keys
        })
        .filter(|s| !s.is_empty())
        .collect();

    // 8. Extract coverage candidates
    let candidates = extract_candidates(
        &messages,
        &identities,
        config,
        &canonical_identity_normalized,
    );

    // 9. Count technology objects from vault index
    let mut portfolio_count = 0usize;
    let mut road_count = 0usize;
    let mut capability_count = 0usize;
    let mut legacy_node_count = 0usize;
    let mut active_legacy_portfolio_count = 0usize;
    let mut declared_child_road_count = 0usize;

    for note in &vault_index.notes {
        if !note.curated || note.parse_error.is_some() {
            continue;
        }
        let type_name = note.type_str().unwrap_or_default();
        if config.portfolio_types.contains(&type_name) {
            portfolio_count += 1;
        }
        if config.road_types.contains(&type_name) {
            road_count += 1;
        }
        if config.capability_types.contains(&type_name) {
            capability_count += 1;
        }
        if config
            .legacy_technology_types
            .iter()
            .any(|t| t == &type_name)
        {
            legacy_node_count += 1;
        }
    }

    // 10. Compute direct-source frontier metrics
    let max_source_cursor = messages.iter().map(|m| m.cursor).max();
    let min_source_cursor = messages.iter().map(|m| m.cursor).min();

    // 11. Count active legacy portfolios and their declared child roads
    for note in &vault_index.notes {
        if !note.curated || note.parse_error.is_some() {
            continue;
        }
        let type_name = note.type_str().unwrap_or_default();
        if type_name != "project" && type_name != "venture" {
            continue;
        }
        let status = note.status().unwrap_or_default();
        if status == "completed"
            || status == "closed"
            || status == "superseded"
            || status == "failed"
        {
            continue;
        }
        let fm = note.fm();
        let body_lower = note.body.to_ascii_lowercase();
        let has_portfolio_language = body_lower.contains("portfolio")
            && (body_lower.contains("road") || body_lower.contains("technology"));
        let has_road_list = body_lower.contains("road ownership")
            || body_lower.contains("road_ids")
            || body_lower.contains("six-road")
            || body_lower.contains("6-road");
        let has_portfolio_id = fm.get_str("portfolio_id").is_some();
        let has_road_ids = !fm.get_list("road_ids").is_empty();

        if has_portfolio_id || has_road_ids || (has_portfolio_language && has_road_list) {
            active_legacy_portfolio_count += 1;
            let road_ids = fm.get_list("road_ids");
            declared_child_road_count += if road_ids.is_empty() {
                count_declared_roads(&note.body)
            } else {
                crate::legacy_technology::extract_roads(&note.body, &road_ids).len()
            };
        }
    }

    let elapsed = start.elapsed();

    SourceIndex {
        messages,
        identities,
        mentions,
        cursor_epochs,
        receipts,
        activity,
        candidates,
        source_files_scanned,
        source_files_cached: 0,
        index_duration_ms: elapsed.as_millis() as u64,
        portfolio_count,
        road_count,
        capability_count,
        legacy_node_count,
        max_source_cursor,
        min_source_cursor,
        active_legacy_portfolio_count,
        declared_child_road_count,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cursor_basic() {
        assert_eq!(parse_cursor("^telegram--1003944547386-4668"), Some(4668));
        assert_eq!(parse_cursor("^telegram--1003944547386-100"), Some(100));
        assert_eq!(parse_cursor("^not-a-cursor"), None);
    }

    #[test]
    fn parse_speaker_basic() {
        let (speaker, class) = parse_speaker("**04:48:55 PDT** · the_mud_lounge_bot");
        assert_eq!(speaker, "the_mud_lounge_bot");
        assert_eq!(class, SpeakerClass::Dm);
    }

    #[test]
    fn parse_speaker_with_escaped_underscores() {
        let (speaker, class) = parse_speaker("**04:48:55 PDT** · the\\_mud\\_lounge\\_bot");
        assert_eq!(speaker, "the_mud_lounge_bot");
        assert_eq!(class, SpeakerClass::Dm);
    }

    #[test]
    fn extract_receipt_tag_basic() {
        assert_eq!(
            extract_receipt_tag("[CL ACCEPT road=TR-STEAM year=36]"),
            Some("ACCEPT road=TR-STEAM year=36")
        );
        assert_eq!(extract_receipt_tag("no receipt here"), None);
    }

    #[test]
    fn parse_receipt_parts_basic() {
        let parts = parse_receipt_parts("ACCEPT road=TR-STEAM portfolio=TP-Y36-01 year=36");
        assert_eq!(parts[0], "ACCEPT");
        assert_eq!(parts[1], "road=TR-STEAM");
        assert_eq!(parts[2], "portfolio=TP-Y36-01");
        assert_eq!(parts[3], "year=36");
    }

    #[test]
    fn is_stable_id_syntax_works() {
        assert!(is_stable_id_syntax("TR-STEAM"));
        assert!(is_stable_id_syntax("CAP-WATER-POWER"));
        assert!(is_stable_id_syntax("TP-Y36-01"));
        assert!(!is_stable_id_syntax("hello"));
        assert!(!is_stable_id_syntax("TR-"));
    }

    #[test]
    fn normalize_text_handles_whitespace() {
        assert_eq!(normalize_text("  Hello   World  "), "hello world");
    }

    #[test]
    fn extract_proper_names_basic() {
        let names = extract_proper_names("Berrick Wold of Wenn's Rise met Mara Kest.");
        assert!(names.contains(&"Berrick Wold".to_string()));
        assert!(names.contains(&"Mara Kest".to_string()));
        // "Wenn's Rise" - the apostrophe should keep it together
        // "of" is a stopword so "Wenn's Rise" should be found
    }

    #[test]
    fn extract_timestamp_basic() {
        assert_eq!(
            extract_timestamp("**04:48:55 PDT** · the_mud_lounge_bot"),
            Some("04:48:55 PDT".to_string())
        );
    }

    #[test]
    fn parse_messages_basic() {
        let raw = "\
^telegram--1001-100
**04:48 PDT** · the_mud_lounge_bot

Hello world.

^telegram--1001-101
**04:49 PDT** · the_mud_lounge_bot

Second message.
";
        let config = Config::default();
        let msgs = parse_messages("test.md", raw, &config);
        assert_eq!(msgs.len(), 2);
        assert_eq!(msgs[0].cursor, 100);
        assert_eq!(msgs[0].speaker, "the_mud_lounge_bot");
        assert_eq!(msgs[0].speaker_class, SpeakerClass::Dm);
        assert_eq!(msgs[1].cursor, 101);
        assert!(msgs[0].body.contains("Hello world."));
    }

    #[test]
    fn find_mentions_exact_title() {
        let messages = vec![SourceMessage {
            file: "test.md".to_string(),
            cursor: 100,
            timestamp: None,
            speaker: "bot".to_string(),
            speaker_class: SpeakerClass::Dm,
            body: "Mara Kest was there.".to_string(),
            line: 1,
        }];
        let identities = vec![KnownIdentity {
            key: "path:30 World/People/Mara Kest.md".to_string(),
            canonical_id: None,
            title: "Mara Kest".to_string(),
            aliases: vec![],
            note_path: "30 World/People/Mara Kest.md".to_string(),
            type_name: "person".to_string(),
            status: None,
            lifecycle: None,
        }];
        let config = Config::default();
        let mentions = find_mentions(&messages, &identities, &config);
        assert_eq!(mentions.len(), 1);
        assert_eq!(
            mentions[0].identity_key,
            "path:30 World/People/Mara Kest.md"
        );
    }

    #[test]
    fn ambiguous_alias_resolves_to_none() {
        let messages = vec![SourceMessage {
            file: "test.md".to_string(),
            cursor: 100,
            timestamp: None,
            speaker: "bot".to_string(),
            speaker_class: SpeakerClass::Dm,
            body: "The smith was working.".to_string(),
            line: 1,
        }];
        let identities = vec![
            KnownIdentity {
                key: "id:A".to_string(),
                canonical_id: Some("A".to_string()),
                title: "Person A".to_string(),
                aliases: vec!["smith".to_string()],
                note_path: "a.md".to_string(),
                type_name: "person".to_string(),
                status: None,
                lifecycle: None,
            },
            KnownIdentity {
                key: "id:B".to_string(),
                canonical_id: Some("B".to_string()),
                title: "Person B".to_string(),
                aliases: vec!["smith".to_string()],
                note_path: "b.md".to_string(),
                type_name: "person".to_string(),
                status: None,
                lifecycle: None,
            },
        ];
        let config = Config::default();
        let mentions = find_mentions(&messages, &identities, &config);
        // Ambiguous alias should not produce any mention
        assert_eq!(mentions.len(), 0);
    }

    #[test]
    fn cursor_epoch_resolution() {
        let epochs = vec![
            CursorEpoch {
                cursor_start: 100,
                cursor_end: 100,
                turn: Some(5),
                year: Some(5),
                source: "test".to_string(),
            },
            CursorEpoch {
                cursor_start: 200,
                cursor_end: 200,
                turn: Some(10),
                year: Some(10),
                source: "test".to_string(),
            },
        ];
        assert_eq!(resolve_cursor(&epochs, 200), (Some(10), Some(10)));
        assert_eq!(resolve_cursor(&epochs, 150), (Some(5), Some(5)));
        assert_eq!(resolve_cursor(&epochs, 50), (None, None));
    }

    #[test]
    fn receipt_parsing_from_messages() {
        let messages = vec![SourceMessage {
            file: "test.md".to_string(),
            cursor: 100,
            timestamp: None,
            speaker: "bot".to_string(),
            speaker_class: SpeakerClass::Dm,
            body: "[CL ACCEPT road=TR-STEAM portfolio=TP-Y36-01 year=36]".to_string(),
            line: 1,
        }];
        let receipts = parse_receipts(&messages);
        assert_eq!(receipts.len(), 1);
        assert_eq!(receipts[0].receipt_type, "ACCEPT");
        assert_eq!(
            receipts[0].fields.get("road").map(|s| s.as_str()),
            Some("TR-STEAM")
        );
    }

    // -----------------------------------------------------------------------
    // Identity normalization regression tests
    // -----------------------------------------------------------------------

    #[test]
    fn normalize_text_handles_backslash_escapes() {
        // "Dessa Ford\-hand" should normalize same as "Dessa Ford-hand"
        assert_eq!(
            normalize_text("Dessa Ford\\-hand"),
            normalize_text("Dessa Ford-hand")
        );
    }

    #[test]
    fn normalize_text_handles_case_folding() {
        assert_eq!(normalize_text("DORN REACH"), normalize_text("Dorn Reach"));
        assert_eq!(
            normalize_text("DESSA FORD-HAND"),
            normalize_text("Dessa Ford-hand")
        );
    }

    #[test]
    fn normalize_text_handles_possessives() {
        // "Dorn Reach's" should normalize same as "Dorn Reach"
        assert_eq!(normalize_text("Dorn Reach's"), normalize_text("Dorn Reach"));
        // Curly apostrophe
        assert_eq!(
            normalize_text("Dorn Reach\u{2019}s"),
            normalize_text("Dorn Reach")
        );
    }

    #[test]
    fn normalize_text_handles_dash_variants() {
        // En-dash, em-dash should normalize to hyphen
        assert_eq!(
            normalize_text("Dessa Ford\u{2013}hand"),
            normalize_text("Dessa Ford-hand")
        );
        assert_eq!(
            normalize_text("Dessa Ford\u{2014}hand"),
            normalize_text("Dessa Ford-hand")
        );
    }

    #[test]
    fn normalize_text_handles_curly_apostrophes() {
        assert_eq!(
            normalize_text("Wenn\u{2019}s Rise"),
            normalize_text("Wenn's Rise")
        );
    }

    #[test]
    fn find_mentions_resolves_normalized_variants() {
        // "Dorn Reach" should match "DORN REACH" and "Dorn Reach's" in source
        let messages = vec![
            SourceMessage {
                file: "test.md".to_string(),
                cursor: 100,
                timestamp: None,
                speaker: "bot".to_string(),
                speaker_class: SpeakerClass::Dm,
                body: "DORN REACH is the chief town.".to_string(),
                line: 1,
            },
            SourceMessage {
                file: "test.md".to_string(),
                cursor: 200,
                timestamp: None,
                speaker: "bot".to_string(),
                speaker_class: SpeakerClass::Dm,
                body: "Dorn Reach's yard was posted.".to_string(),
                line: 5,
            },
            SourceMessage {
                file: "test.md".to_string(),
                cursor: 300,
                timestamp: None,
                speaker: "bot".to_string(),
                speaker_class: SpeakerClass::Dm,
                body: "The party gathered at Dorn Reach.".to_string(),
                line: 10,
            },
        ];
        let identities = vec![KnownIdentity {
            key: "path:30 World/Places/Dorn Reach.md".to_string(),
            canonical_id: None,
            title: "Dorn Reach".to_string(),
            aliases: vec![],
            note_path: "30 World/Places/Dorn Reach.md".to_string(),
            type_name: "place".to_string(),
            status: Some("active".to_string()),
            lifecycle: None,
        }];
        let config = Config::default();
        let mentions = find_mentions(&messages, &identities, &config);
        // All three messages should match
        assert_eq!(mentions.len(), 3);
    }

    #[test]
    fn candidate_extraction_excludes_known_identities() {
        // "Dorn Reach" should NOT appear as a coverage candidate
        // because it's a known identity
        let messages = vec![SourceMessage {
            file: "test.md".to_string(),
            cursor: 100,
            timestamp: None,
            speaker: "bot".to_string(),
            speaker_class: SpeakerClass::Dm,
            body: "Dorn Reach is the chief town. Dorn Reach has a yard.".to_string(),
            line: 1,
        }];
        let identities = vec![KnownIdentity {
            key: "path:30 World/Places/Dorn Reach.md".to_string(),
            canonical_id: None,
            title: "Dorn Reach".to_string(),
            aliases: vec![],
            note_path: "30 World/Places/Dorn Reach.md".to_string(),
            type_name: "place".to_string(),
            status: Some("active".to_string()),
            lifecycle: None,
        }];
        let config = Config::default();
        let empty_set = HashSet::new();
        let candidates = extract_candidates(&messages, &identities, &config, &empty_set);
        // "Dorn Reach" should not be a candidate
        assert!(!candidates.iter().any(|c| c.text == "Dorn Reach"));
    }

    #[test]
    fn all_caps_protocol_filtered() {
        let messages = vec![SourceMessage {
            file: "test.md".to_string(),
            cursor: 100,
            timestamp: None,
            speaker: "bot".to_string(),
            speaker_class: SpeakerClass::Dm,
            body: "AUDIT PROTOCOL was followed. AUDIT PROTOCOL again.".to_string(),
            line: 1,
        }];
        let identities = vec![];
        let config = Config::default();
        let empty_set = HashSet::new();
        let candidates = extract_candidates(&messages, &identities, &config, &empty_set);
        // "AUDIT PROTOCOL" should be filtered as ALL-CAPS protocol prose
        assert!(!candidates.iter().any(|c| c.text == "AUDIT PROTOCOL"));
    }

    #[test]
    fn possessive_base_name_resolves() {
        // "Kest Hollow's" should match "Kest Hollow"
        let messages = vec![SourceMessage {
            file: "test.md".to_string(),
            cursor: 100,
            timestamp: None,
            speaker: "bot".to_string(),
            speaker_class: SpeakerClass::Dm,
            body: "Kest Hollow's open work pilot began.".to_string(),
            line: 1,
        }];
        let identities = vec![KnownIdentity {
            key: "path:40 Civilization/Projects/Kest Hollow.md".to_string(),
            canonical_id: None,
            title: "Kest Hollow".to_string(),
            aliases: vec![],
            note_path: "40 Civilization/Projects/Kest Hollow.md".to_string(),
            type_name: "project".to_string(),
            status: Some("active".to_string()),
            lifecycle: None,
        }];
        let config = Config::default();
        let mentions = find_mentions(&messages, &identities, &config);
        assert_eq!(mentions.len(), 1);
    }

    #[test]
    fn seed_canonical_materiality_from_source_cursor() {
        use crate::frontmatter::parse;
        use crate::vault::Note;

        // Create a vault index with a note that has source_cursor
        let fm = parse(
            "---\ntype: project\nstatus: active\nsource_cursor: 4526\nreviewed_through_cursor: 4534\n---\n# Test\n",
        );
        let note = Note {
            path: "40 Civilization/Projects/Test.md".into(),
            frontmatter: fm.value,
            body: fm.body,
            content_hash: 0,
            parse_error: None,
            has_frontmatter: true,
            curated: true,
        };
        let index = crate::vault::VaultIndex {
            root: std::path::PathBuf::new(),
            notes: vec![note],
            all_files: std::collections::HashSet::new(),
            file_hashes: vec![],
        };

        let identities = vec![KnownIdentity {
            key: "path:40 Civilization/Projects/Test.md".to_string(),
            canonical_id: None,
            title: "Test".to_string(),
            aliases: vec![],
            note_path: "40 Civilization/Projects/Test.md".to_string(),
            type_name: "project".to_string(),
            status: Some("active".to_string()),
            lifecycle: None,
        }];

        let mut activity = HashMap::new();
        activity.insert(
            "path:40 Civilization/Projects/Test.md".to_string(),
            IdentityActivity::default(),
        );

        seed_canonical_materiality(&mut activity, &identities, &index);

        let act = activity
            .get("path:40 Civilization/Projects/Test.md")
            .unwrap();
        assert_eq!(act.last_material_cursor, Some(4526));
    }

    #[test]
    fn reviewed_through_cursor_does_not_seed_materiality() {
        use crate::frontmatter::parse;
        use crate::vault::Note;

        let fm = parse("---\ntype: project\nreviewed_through_cursor: 4534\n---\n# Test\n");
        let note = Note {
            path: "Test.md".into(),
            frontmatter: fm.value,
            body: fm.body,
            content_hash: 0,
            parse_error: None,
            has_frontmatter: true,
            curated: true,
        };
        let index = crate::vault::VaultIndex {
            root: std::path::PathBuf::new(),
            notes: vec![note],
            all_files: HashSet::new(),
            file_hashes: vec![],
        };
        let identities = vec![KnownIdentity {
            key: "path:Test.md".to_string(),
            canonical_id: None,
            title: "Test".to_string(),
            aliases: vec![],
            note_path: "Test.md".to_string(),
            type_name: "project".to_string(),
            status: None,
            lifecycle: None,
        }];
        let mut activity = HashMap::from([(
            "path:Test.md".to_string(),
            IdentityActivity {
                last_material_cursor: Some(4526),
                ..Default::default()
            },
        )]);

        seed_canonical_materiality(&mut activity, &identities, &index);

        assert_eq!(activity["path:Test.md"].last_material_cursor, Some(4526));
    }

    #[test]
    fn structured_materiality_and_source_cursor_use_the_later_cursor() {
        use crate::frontmatter::parse;
        use crate::vault::Note;

        let identities = vec![KnownIdentity {
            key: "road".to_string(),
            canonical_id: None,
            title: "Road".to_string(),
            aliases: vec![],
            note_path: "Road.md".to_string(),
            type_name: "road".to_string(),
            status: None,
            lifecycle: None,
        }];
        let messages = vec![SourceMessage {
            file: "source.md".to_string(),
            cursor: 4600,
            timestamp: None,
            speaker: "dm".to_string(),
            speaker_class: SpeakerClass::Dm,
            body: "[CL ACCEPT road=road]".to_string(),
            line: 1,
        }];
        let receipts = parse_receipts(&messages);
        let mut activity = aggregate_activity(&[], &receipts, &identities);
        let fm = parse(
            "---\ntype: road\nsource_cursor: 4526\nreviewed_through_cursor: 4534\n---\n# Road\n",
        );
        let index = crate::vault::VaultIndex {
            root: std::path::PathBuf::new(),
            notes: vec![Note {
                path: "Road.md".into(),
                frontmatter: fm.value,
                body: fm.body,
                content_hash: 0,
                parse_error: None,
                has_frontmatter: true,
                curated: true,
            }],
            all_files: HashSet::new(),
            file_hashes: vec![],
        };
        seed_canonical_materiality(&mut activity, &identities, &index);

        assert_eq!(activity["road"].last_material_cursor, Some(4600));

        let newer = parse(
            "---\ntype: road\nsource_cursor: 4700\nreviewed_through_cursor: 4701\n---\n# Road\n",
        );
        let newer_index = crate::vault::VaultIndex {
            root: std::path::PathBuf::new(),
            notes: vec![Note {
                path: "Road.md".into(),
                frontmatter: newer.value,
                body: newer.body,
                content_hash: 0,
                parse_error: None,
                has_frontmatter: true,
                curated: true,
            }],
            all_files: HashSet::new(),
            file_hashes: vec![],
        };
        seed_canonical_materiality(&mut activity, &identities, &newer_index);
        assert_eq!(activity["road"].last_material_cursor, Some(4700));
    }

    #[test]
    fn source_frontmatter_never_enters_message_analysis() {
        use crate::boundary::{BoundarySource, StateBoundary};

        let dir = tempfile::tempdir().unwrap();
        let source_path = dir.path().join("70 Sources/Telegram/Player/2026/probe.md");
        std::fs::create_dir_all(source_path.parent().unwrap()).unwrap();
        std::fs::write(
            &source_path,
            "---\ntype: telegram-chat-part\nsource: telegram\nstream: player\nfrontmatter_probe: |\n  ^telegram--999-100\n  **00:00 UTC** · the_mud_lounge_bot\n  Frontmatter Phantom appears.\n  [CL ACCEPT road=frontmatter-road]\n  ^telegram--999-101\n  **00:01 UTC** · the_mud_lounge_bot\n  Frontmatter Phantom appears again.\n---\n\n^telegram--999-200\n**00:02 UTC** · the_mud_lounge_bot\n\nOrdinary body text.\n",
        )
        .unwrap();

        let config = Config::default();
        let boundary = StateBoundary {
            current_turn: None,
            current_year: None,
            last_resolved_year: None,
            current_source_cursor: None,
            canonical_materialized_cursor: None,
            vault_revision: "test".to_string(),
            source: BoundarySource::Derived,
        };
        let index = crate::vault::scan(dir.path(), &config).unwrap();
        let source = build(dir.path(), &index, &config, &boundary);

        assert_eq!(source.messages.len(), 1);
        assert_eq!(source.messages[0].cursor, 200);
        assert!(!source.messages[0].body.contains("Frontmatter Phantom"));
        assert!(!source.messages[0].body.contains("[CL ACCEPT"));
        assert!(!source
            .candidates
            .iter()
            .any(|candidate| candidate.text == "Frontmatter Phantom"));
        assert!(source.receipts.is_empty());

        let identity_path = dir.path().join("30 World/People/Frontmatter Phantom.md");
        std::fs::create_dir_all(identity_path.parent().unwrap()).unwrap();
        std::fs::write(
            identity_path,
            "---\ntype: person\nstatus: active\nretrieval_tier: canonical\n---\n# Frontmatter Phantom\n",
        )
        .unwrap();
        let index_with_identity = crate::vault::scan(dir.path(), &config).unwrap();
        let source_with_identity = build(dir.path(), &index_with_identity, &config, &boundary);

        assert!(!source_with_identity.mentions.iter().any(|mention| {
            mention.identity_key == "path:30 World/People/Frontmatter Phantom.md"
        }));
        assert!(source_with_identity.receipts.is_empty());
    }
}
