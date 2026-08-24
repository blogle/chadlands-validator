//! YAML frontmatter extraction and typed access.
//!
//! Vault notes start with a `---` fence, a YAML mapping, and a closing `---`.
//! This module parses that block with yaml-rust2 and exposes forgiving typed
//! accessors (unquoted scalars arrive as Integer/Real/String depending on the
//! parser's guess; we coerce).

use yaml_rust2::{Yaml, YamlLoader};

/// A parsed frontmatter block: the YAML value plus the body that follows it.
pub struct Frontmatter {
    pub value: Yaml,
    pub body: String,
    pub parse_error: Option<String>,
    pub has_block: bool,
}

impl Frontmatter {
    pub fn empty(body: String, has_block: bool, parse_error: Option<String>) -> Self {
        Frontmatter {
            value: Yaml::Null,
            body,
            parse_error,
            has_block,
        }
    }
}

/// Split a raw note into frontmatter + body and parse the YAML.
pub fn parse(raw: &str) -> Frontmatter {
    let text = raw.strip_prefix('\u{feff}').unwrap_or(raw);
    if !text.starts_with("---") {
        return Frontmatter::empty(raw.to_string(), false, None);
    }
    // First line must be exactly `---` (allow trailing whitespace).
    let first_line_end = match text.find('\n') {
        Some(i) => i,
        None => return Frontmatter::empty(raw.to_string(), false, None),
    };
    if text[..first_line_end].trim() != "---" {
        return Frontmatter::empty(raw.to_string(), false, None);
    }
    let after_first = &text[first_line_end + 1..];

    // Find the closing fence: a line that is exactly `---`.
    let mut close_start = None;
    let mut close_end = None;
    let mut pos = 0usize;
    for line in after_first.split_inclusive('\n') {
        let trimmed = line.trim_end_matches(['\n', '\r']);
        if trimmed.trim_end() == "---" {
            close_start = Some(pos);
            close_end = Some(pos + line.len());
            break;
        }
        pos += line.len();
    }
    let (cs, ce) = match (close_start, close_end) {
        (Some(s), Some(e)) => (s, e),
        _ => {
            return Frontmatter::empty(
                raw.to_string(),
                true,
                Some("frontmatter opening fence has no closing fence".to_string()),
            )
        }
    };

    let yaml_text = &after_first[..cs];
    let body = after_first[ce..].to_string();

    match YamlLoader::load_from_str(yaml_text) {
        Ok(docs) => {
            let value = docs.into_iter().next().unwrap_or(Yaml::Null);
            if matches!(value, Yaml::Hash(_) | Yaml::Null) {
                Frontmatter {
                    value,
                    body,
                    parse_error: None,
                    has_block: true,
                }
            } else {
                Frontmatter::empty(
                    body,
                    true,
                    Some("frontmatter is not a YAML mapping".to_string()),
                )
            }
        }
        Err(e) => Frontmatter::empty(body, true, Some(format!("yaml parse error: {e}"))),
    }
}

/// Typed view over a frontmatter mapping.
pub struct FmView<'a> {
    pub value: &'a Yaml,
}

impl<'a> FmView<'a> {
    pub fn new(value: &'a Yaml) -> Self {
        FmView { value }
    }

    fn get(&self, key: &str) -> Option<&'a Yaml> {
        match self.value {
            Yaml::Hash(h) => h.get(&Yaml::String(key.to_string())),
            _ => None,
        }
    }

    pub fn has(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    /// Raw string form of a scalar value.
    pub fn get_str(&self, key: &str) -> Option<String> {
        match self.get(key)? {
            Yaml::String(s) => Some(s.clone()),
            Yaml::Integer(i) => Some(i.to_string()),
            Yaml::Real(r) => Some(r.clone()),
            Yaml::Boolean(b) => Some(b.to_string()),
            _ => None,
        }
    }

    /// Coerce to i64 from Integer, Real, or numeric String.
    pub fn get_i64(&self, key: &str) -> Option<i64> {
        match self.get(key)? {
            Yaml::Integer(i) => Some(*i),
            Yaml::Real(r) => r.parse::<f64>().ok().map(|f| f as i64),
            Yaml::String(s) => s.trim().parse::<i64>().ok(),
            _ => None,
        }
    }

    /// List of strings (or single scalar treated as one-element list).
    pub fn get_list(&self, key: &str) -> Vec<String> {
        match self.get(key) {
            Some(Yaml::Array(items)) => items
                .iter()
                .filter_map(|y| match y {
                    Yaml::String(s) => Some(s.clone()),
                    Yaml::Integer(i) => Some(i.to_string()),
                    Yaml::Real(r) => Some(r.clone()),
                    _ => None,
                })
                .collect(),
            Some(Yaml::String(s)) => vec![s.clone()],
            _ => Vec::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_basic_frontmatter() {
        let raw = "---\ntype: person\nstatus: active\nreviewed_through_cursor: 2153\ntags:\n- a\n- b\n---\n# Body\n";
        let fm = parse(raw);
        assert!(fm.parse_error.is_none());
        assert!(fm.has_block);
        let v = FmView::new(&fm.value);
        assert_eq!(v.get_str("type").as_deref(), Some("person"));
        assert_eq!(v.get_i64("reviewed_through_cursor"), Some(2153));
        assert_eq!(v.get_list("tags"), vec!["a", "b"]);
        assert_eq!(fm.body, "# Body\n");
    }

    #[test]
    fn no_frontmatter() {
        let fm = parse("# Just a body\n");
        assert!(!fm.has_block);
        assert!(fm.parse_error.is_none());
    }

    #[test]
    fn unclosed_frontmatter_is_error() {
        let fm = parse("---\ntype: person\n# never closed\n");
        assert!(fm.has_block);
        assert!(fm.parse_error.is_some());
    }

    #[test]
    fn bad_yaml_is_error() {
        let fm = parse("---\n: : :\n  - [unclosed\n---\nbody\n");
        assert!(fm.parse_error.is_some());
    }

    #[test]
    fn numeric_string_coerces_to_i64() {
        let fm = parse("---\nsource_cursor: \"2435\"\n---\n");
        let v = FmView::new(&fm.value);
        assert_eq!(v.get_i64("source_cursor"), Some(2435));
    }
}
