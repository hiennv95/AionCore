//! Redaction and a serialized-size budget for tool input/output that leaves the host for a client (L03.IO).
//!
//! This bounds a COPY on its way out. What is persisted, and what the agent sees, stays raw: nothing
//! here rewrites agent context. Every node that is kept debits the budget by its exact compact-JSON size
//! (strings by their escaped length plus quotes, keys by key plus colon and comma, numbers/null/bool by
//! their text, containers by their brackets and commas), so the OUTPUT never serializes to more than
//! `max_bytes` whatever the shape: a million `null`s, empty strings or `[]`s are cut like a long string.
//! Depth is bounded too, and the result is always valid JSON.
//!
//! What is and is not bounded: the work to PRODUCE the copy stops at the budget (a huge string is
//! scanned only up to it). Freeing the owned input afterwards, and building it before this call (the
//! event is serialized to a `Value` first), still cost the full input. So this bounds the wire and
//! the memory the client receives, not the host's own handling of a payload it already holds.
//!
//! Secret-named keys are masked with the shared key rule ([`crate::redact::should_redact_key`]) plus a few
//! more names (cookies, private keys, credentials). Strings are masked textually, WITHOUT re-parsing or
//! re-serializing them: `Bearer` tokens, `sk-` keys (at a word boundary, so `disk-cache.rs` stays), URL
//! passwords (`scheme://user:pw@host`), `--name value` flags, and `name=value` / `"name":"value"` pairs for
//! secret names (also camelCase `accessToken`, and escaped `\"name\":\"value\"`), which also catches
//! secrets inside JSON text and inside a cut-off JSON prefix. An object `{"name": <secret name>, "value": ..}`
//! masks its `value`. This is defence in depth, not a promise that no secret remains.

use serde_json::{Map, Number, Value, json};

use crate::redact::should_redact_key;

/// Proposed per-field budget, in bytes of compact JSON, for a tool payload sent to a client. Not an owner decision.
pub const TOOL_FIELD_MAX_BYTES: usize = 64 * 1024;
/// Nesting beyond this is replaced by a marker string.
pub const TOOL_MAX_DEPTH: usize = 16;
const DEPTH_MARKER: &str = "[too deep]";
const REDACTED: &str = "[redacted]";

/// Limits for one bounded traversal. `max_bytes` is the serialized (compact JSON) size of what is kept.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    pub max_bytes: usize,
    pub max_depth: usize,
}

impl Limits {
    /// The budget for payloads sent to a client in a stream or a list.
    pub const BOUNDED: Self = Self {
        max_bytes: TOOL_FIELD_MAX_BYTES,
        max_depth: TOOL_MAX_DEPTH,
    };
    /// Redact only: for an explicit full fetch of one message. Depth stays bounded. This is NOT bounded
    /// in size by design (the existing full-fetch contract): the caller's memory is the limit.
    pub const UNBOUNDED_BYTES: Self = Self {
        // serde_json refuses input deeper than 128, so stored rows cannot be deeper than this.
        max_bytes: usize::MAX,
        max_depth: 130,
    };
}

/// A value after redaction and bounding, and whether anything was cut.
#[derive(Debug, Clone, PartialEq)]
pub struct Bounded {
    pub value: Value,
    pub truncated: bool,
}

struct Budget {
    left: usize,
    truncated: bool,
}

impl Budget {
    /// Debits `cost`; false (and `truncated`) when it does not fit.
    fn take(&mut self, cost: usize) -> bool {
        if cost <= self.left {
            self.left -= cost;
            true
        } else {
            self.truncated = true;
            false
        }
    }
}

/// Redacts and bounds any JSON value. The result serializes to at most `limits.max_bytes` bytes
/// (compact), except that a budget too small for even `null` yields `null`.
pub fn redact_and_bound(value: Value, limits: Limits) -> Bounded {
    let mut budget = Budget {
        left: limits.max_bytes,
        truncated: false,
    };
    let value = walk(value, limits.max_depth, &mut budget);
    Bounded {
        value,
        truncated: budget.truncated,
    }
}

/// Redacts and bounds plain text to `limits.max_bytes` of escaped JSON string; the cut is on a character boundary.
pub fn redact_and_bound_text(text: &str, limits: Limits) -> (String, bool) {
    let mut budget = Budget {
        left: limits.max_bytes,
        truncated: false,
    };
    let out = bound_string(text, &mut budget);
    (out, budget.truncated)
}

fn walk(value: Value, depth: usize, budget: &mut Budget) -> Value {
    match value {
        Value::Null => take_or_null(budget, 4, Value::Null),
        Value::Bool(b) => take_or_null(budget, if b { 4 } else { 5 }, Value::Bool(b)),
        Value::Number(n) => {
            let cost = number_len(&n);
            take_or_null(budget, cost, Value::Number(n))
        }
        Value::String(text) => Value::String(bound_string(&text, budget)),
        Value::Array(items) => {
            if depth == 0 {
                return depth_marker(budget);
            }
            if !budget.take(2) {
                return Value::Null;
            }
            let mut out = Vec::new();
            for item in items {
                let start = budget.left;
                // A comma before every item but the first, then the item itself (which debits its own size).
                if !out.is_empty() && !budget.take(1) {
                    break;
                }
                let after_comma = budget.left;
                let kept = walk(item, depth - 1, budget);
                if budget.left == after_comma {
                    // The item did not fit at all: drop it and its comma, so the output stays exact.
                    budget.left = start;
                    break;
                }
                out.push(kept);
            }
            Value::Array(out)
        }
        Value::Object(map) => {
            if depth == 0 {
                return depth_marker(budget);
            }
            if !budget.take(2) {
                return Value::Null;
            }
            // `{"name": "API_KEY", "value": "..."}` (env lists, HAR headers): the name says the value is secret.
            let value_is_secret = ["name", "key"]
                .iter()
                .any(|k| map.get(*k).and_then(Value::as_str).is_some_and(is_secret_key));
            let mut out = Map::new();
            for (key, value) in map {
                // A key's serialized length is at least its byte length: a key that cannot fit ends the object
                // here, before any per-character work (counting, lowercasing) on a huge key.
                if key.len() + 4 > budget.left {
                    budget.truncated = true;
                    break;
                }
                let start = budget.left;
                // `"key":`, preceded by a comma for every entry but the first.
                if !budget.take(escaped_len(&key) + 2 + 1 + usize::from(!out.is_empty())) {
                    break;
                }
                let after_key = budget.left;
                let value = if is_secret_key(&key) || (value_is_secret && key == "value") {
                    secret_summary(value, budget)
                } else {
                    walk(value, depth - 1, budget)
                };
                if budget.left == after_key {
                    budget.left = start;
                    break;
                }
                out.insert(key, value);
            }
            Value::Object(out)
        }
    }
}

fn take_or_null(budget: &mut Budget, cost: usize, value: Value) -> Value {
    if budget.take(cost) { value } else { Value::Null }
}

fn depth_marker(budget: &mut Budget) -> Value {
    budget.truncated = true;
    if budget.take(DEPTH_MARKER.len() + 2) {
        Value::String(DEPTH_MARKER.to_owned())
    } else {
        Value::Null
    }
}

fn number_len(n: &Number) -> usize {
    n.to_string().len()
}

/// A value under a secret-named key: its size class only, in O(1) (the shared summary counts characters,
/// which would walk a huge string). Costs what it serializes to.
fn secret_summary(value: Value, budget: &mut Budget) -> Value {
    let summary = match &value {
        Value::String(text) => json!({"redacted": true, "bytes": text.len()}),
        Value::Object(map) => json!({"redacted": true, "keys": map.len()}),
        Value::Array(items) => json!({"redacted": true, "items": items.len()}),
        _ => json!({"redacted": true}),
    };
    drop(value);
    let cost = summary.to_string().len();
    if budget.take(cost) { summary } else { Value::Null }
}

/// Length of `text` as a JSON string body (without quotes).
fn escaped_len(text: &str) -> usize {
    text.chars().map(char_cost).sum()
}

fn char_cost(c: char) -> usize {
    match c {
        '"' | '\\' | '\n' | '\r' | '\t' | '\u{8}' | '\u{c}' => 2,
        c if (c as u32) < 0x20 => 6,
        c => c.len_utf8(),
    }
}

/// Redacts and cuts `text` to what the budget affords as a JSON string (quotes included). Scans no
/// further than the budget allows.
fn bound_string(text: &str, budget: &mut Budget) -> String {
    let room = budget.left.saturating_sub(2);
    let cut = prefix_within(text, room);
    if cut < text.len() {
        budget.truncated = true;
    }
    // Redaction can change the length a little, so measure again after it.
    let redacted = redact_secrets(&text[..cut]);
    let end = prefix_within(&redacted, room);
    if end < redacted.len() {
        budget.truncated = true;
    }
    let out = &redacted[..end];
    // `take` cannot fail here (the cost is within `room`), but a budget below 2 yields an empty string for free.
    let _ = budget.take(escaped_len(out) + 2);
    out.to_owned()
}

/// The longest prefix of `text`, on a char boundary, whose escaped length is at most `room`. Stops
/// scanning as soon as the room is used up.
fn prefix_within(text: &str, room: usize) -> usize {
    let mut used = 0usize;
    for (index, c) in text.char_indices() {
        used = used.saturating_add(char_cost(c));
        if used > room {
            return index;
        }
    }
    text.len()
}

/// Object keys whose value is masked: the shared rule, plus names it does not cover.
fn is_secret_key(key: &str) -> bool {
    if should_redact_key(key) {
        return true;
    }
    let key = key.to_ascii_lowercase();
    key.contains("cookie")
        || key.contains("credential")
        || key.contains("private_key")
        || key.contains("private-key")
        || key.contains("passphrase")
        || key.contains("api-key")
        || key.contains("authorization")
}

/// Masks secrets in free text: bearer tokens, `sk-` keys, URL passwords, and secret `name=value` pairs.
pub fn redact_secrets(text: &str) -> String {
    redact_assignments(&redact_url_passwords(&redact_prefixed(
        &redact_prefixed(text, "bearer ", true),
        "sk-",
        false,
    )))
}

/// Masks the password of `scheme://user:password@host`. The authority runs to the first `/`, `?`, `#` or
/// delimiter, and its LAST `@` ends the user info, so an unencoded `@` in the password is masked too.
fn redact_url_passwords(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut from = 0;
    while let Some(p) = text[from..].find("://") {
        let host_start = from + p + 3;
        let authority_end = text[host_start..]
            .find(|c: char| matches!(c, '/' | '?' | '#') || is_delimiter(c))
            .map_or(text.len(), |q| host_start + q);
        let authority = &text[host_start..authority_end];
        if let Some(at) = authority.rfind('@')
            && let Some(colon) = authority[..at].find(':')
            && colon + 1 < at
        {
            out.push_str(&text[copied..host_start + colon + 1]);
            out.push_str(REDACTED);
            copied = host_start + at;
        }
        // Each authority scan stops at a `/`, which every later `://` contains: linear overall.
        from = host_start;
    }
    out.push_str(&text[copied..]);
    out
}

/// A quote at `at`, possibly escaped (`\"`, `\\\"` in JSON printed inside JSON): the index after it,
/// the number of backslashes before it, and the quote character.
fn quote_at(bytes: &[u8], at: usize) -> Option<(usize, usize, u8)> {
    let backslashes = bytes.get(at..)?.iter().take_while(|b| **b == b'\\').count();
    match bytes.get(at + backslashes) {
        Some(q @ (b'"' | b'\'')) => Some((at + backslashes + 1, backslashes, *q)),
        _ => None,
    }
}

/// The index of the quote closing a value opened by `quote` after `backslashes` backslashes: the first
/// such quote preceded by exactly as many. A quote escaped one level deeper does not close it.
fn closing_quote(bytes: &[u8], from: usize, backslashes: usize, quote: u8) -> Option<usize> {
    let mut run = 0;
    for (offset, b) in bytes[from..].iter().enumerate() {
        if *b == b'\\' {
            run += 1;
            continue;
        }
        if *b == quote && run == backslashes {
            return Some(from + offset);
        }
        run = 0;
    }
    None
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric()
}

fn is_delimiter(c: char) -> bool {
    c.is_whitespace() || matches!(c, '"' | '\'' | ',' | ';' | '}' | ']' | ')')
}

/// End of an unquoted value starting at `start`: the first `stop` character, with an existing `[redacted]`
/// placeholder skipped as one unit (its closing `]` is itself a delimiter, so scanning into it would cut it
/// in half and make masking grow `[redacted]]` each time text passes another filter).
fn value_end(text: &str, start: usize, stop: impl Fn(char) -> bool) -> usize {
    let mut i = start;
    while i < text.len() {
        if text[i..].starts_with(REDACTED) {
            i += REDACTED.len();
            continue;
        }
        let c = text[i..].chars().next().unwrap_or(' ');
        if stop(c) {
            break;
        }
        i += c.len_utf8();
    }
    i
}

/// Replaces the secret after `prefix` (matched case-insensitively, only at a word boundary) up to the next
/// delimiter. `keep_prefix` keeps the original prefix text (`Bearer`); otherwise it is rewritten (`sk-`).
fn redact_prefixed(text: &str, prefix: &str, keep_prefix: bool) -> String {
    let lower = text.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut copied = 0;
    let mut i = 0;
    while i + prefix.len() <= bytes.len() {
        if !bytes[i..].starts_with(prefix.as_bytes()) || (i > 0 && is_word_byte(bytes[i - 1])) {
            i += 1;
            continue;
        }
        let secret_start = i + prefix.len();
        let secret_end = value_end(text, secret_start, is_delimiter);
        // Nothing there, or already masked: leave it (masking is idempotent).
        if secret_end == secret_start || &text[secret_start..secret_end] == REDACTED {
            i = secret_end.max(secret_start);
            continue;
        }
        out.push_str(&text[copied..i]);
        out.push_str(if keep_prefix { &text[i..secret_start] } else { prefix });
        out.push_str(REDACTED);
        copied = secret_end;
        i = secret_end;
    }
    out.push_str(&text[copied..]);
    out
}

const SECRET_NAMES: [&str; 14] = [
    "api_key",
    "api-key",
    "apikey",
    "access_key",
    "secret_key",
    "private_key",
    "private-key",
    "secret",
    "token",
    "password",
    "passwd",
    "passphrase",
    "authorization",
    "cookie",
];

/// Masks the value of `name=value`, `name: value` and JSON `"name":"value"` pairs whose name is a secret
/// word. A value is a quoted string or runs to the next delimiter; an `authorization` value (`Basic abc`)
/// also runs across spaces.
pub fn redact_assignments(text: &str) -> String {
    // ASCII lowercasing keeps byte offsets identical, so offsets found in `lower` index `text`.
    let lower = text.to_ascii_lowercase();
    let bytes = lower.as_bytes();
    let mut out = String::with_capacity(text.len());
    let mut i = 0;
    let mut copied = 0;
    let original = text.as_bytes();
    while i < bytes.len() {
        // A word boundary, or a camelCase one (`accessToken`, `dbPassword`).
        let before_ok = i == 0
            || !is_word_byte(bytes[i - 1])
            || (original[i].is_ascii_uppercase() && original[i - 1].is_ascii_lowercase());
        let name = before_ok
            .then(|| SECRET_NAMES.iter().find(|n| bytes[i..].starts_with(n.as_bytes())))
            .flatten();
        let Some(name) = name else {
            i += 1;
            continue;
        };
        let name_end = i + name.len();
        let mut j = name_end;
        // A closing quote of a JSON key: `"token":`, also escaped (`\"token\":`).
        if let Some((after, _, _)) = quote_at(bytes, j) {
            j = after;
        }
        let quoted_name = j > name_end;
        while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
            j += 1;
        }
        let assignment = j < bytes.len() && (bytes[j] == b'=' || bytes[j] == b':');
        // `--password value`: a command-line flag followed by its value.
        let flag = !assignment
            && !quoted_name
            && j > name_end
            && i >= 2
            && &bytes[i - 2..i] == b"--"
            && bytes.get(j).is_some_and(|b| *b != b'-');
        if !assignment && !flag {
            i += name.len();
            continue;
        }
        if assignment {
            j += 1;
            while j < bytes.len() && (bytes[j] == b' ' || bytes[j] == b'\t') {
                j += 1;
            }
        }
        let start = j;
        let across_spaces = *name == "authorization";
        let end = match (quote_at(bytes, j), bytes.get(j)) {
            (Some((after, backslashes, quote)), _) => {
                closing_quote(bytes, after, backslashes, quote).map_or(bytes.len(), |p| p + 1)
            }
            (None, Some(_)) => value_end(text, j, |c: char| {
                if across_spaces {
                    matches!(c, '\n' | '\r' | '"' | '\'' | ',' | ';' | '}' | ']')
                } else {
                    is_delimiter(c)
                }
            }),
            (None, None) => j,
        };
        // Nothing there, or already masked: leave it (masking is idempotent).
        if end == start || &text[start..end] == REDACTED {
            i = end.max(j.max(i + name.len()));
            continue;
        }
        out.push_str(&text[copied..start]);
        out.push_str(REDACTED);
        copied = end;
        i = end;
    }
    out.push_str(&text[copied..]);
    out
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;

    #[test]
    fn secrets_are_masked_in_keys_and_strings() {
        let out = redact_and_bound(
            json!({"command": "curl -H 'Authorization: Bearer abc.def' https://x", "env": {"A": "b"}, "auth_token": "zzz", "note": "key sk-live_ABC and API_KEY=hunter2 done"}),
            Limits::BOUNDED,
        );
        let text = out.value.to_string();
        for leaked in ["abc.def", "zzz", "sk-live_ABC", "hunter2", "\"A\""] {
            assert!(!text.contains(leaked), "{leaked} leaked: {text}");
        }
        assert!(text.contains("curl -H"));
        assert!(!out.truncated);
    }

    #[test]
    fn assignments_mask_quoted_and_bare_values() {
        assert_eq!(redact_assignments("password: \"p w\" ok"), "password: [redacted] ok");
        assert_eq!(redact_assignments("x token=abc,y"), "x token=[redacted],y");
        assert_eq!(
            redact_assignments("mytoken=abc"),
            "mytoken=abc",
            "a longer word is not a secret name"
        );
        assert_eq!(redact_assignments("password"), "password");
        assert_eq!(redact_assignments("token = "), "token = ");
    }

    fn serialized(value: &Value) -> usize {
        serde_json::to_string(value).unwrap().len()
    }

    #[test]
    fn a_huge_string_is_cut_on_a_character_boundary_within_the_budget() {
        let out = redact_and_bound(
            json!("é".repeat(100_000)),
            Limits {
                max_bytes: 1001,
                max_depth: 4,
            },
        );
        let Value::String(s) = &out.value else {
            panic!("string expected")
        };
        assert!(serialized(&out.value) <= 1001);
        assert!(s.chars().all(|c| c == 'é'), "no half character");
        assert!(out.truncated);
        // 4-byte characters: the cut still lands on a boundary.
        let out = redact_and_bound(
            json!("😀".repeat(10)),
            Limits {
                max_bytes: 7,
                max_depth: 4,
            },
        );
        assert_eq!(out.value, json!("😀"));
        assert!(out.truncated);
    }

    /// The serialized size is the budget, whatever the shape (the lead review: nulls, empty strings,
    /// empty arrays, numbers and escaping used to cost nothing).
    #[test]
    fn adversarial_shapes_stay_within_the_serialized_budget() {
        let n = 3_000_000;
        let cases: Vec<(&str, Value)> = vec![
            ("nulls", Value::Array(vec![Value::Null; n])),
            ("bools", Value::Array(vec![Value::Bool(false); n])),
            ("numbers", Value::Array((0..n as u64).map(|i| json!(i)).collect())),
            ("empty strings", Value::Array(vec![json!(""); n])),
            ("empty arrays", Value::Array(vec![json!([]); n])),
            ("empty objects", Value::Array(vec![json!({}); n])),
            (
                "one-byte keys",
                Value::Object((0..200_000).map(|i| (format!("{i}"), Value::Null)).collect()),
            ),
            ("escape heavy", json!("\"\n\\".repeat(500_000))),
            ("control chars", json!("\u{1}".repeat(500_000))),
            (
                "wide objects",
                Value::Array(
                    (0..100_000)
                        .map(|i| json!({"i": i, "name": format!("row-{i}")}))
                        .collect(),
                ),
            ),
            ("secret huge", json!({"api_key": "k".repeat(2_000_000), "n": 1})),
        ];
        for (name, value) in cases {
            let out = redact_and_bound(value, Limits::BOUNDED);
            let size = serialized(&out.value);
            assert!(size <= TOOL_FIELD_MAX_BYTES, "{name}: serialized {size} > budget");
            assert!(out.truncated || name == "secret huge", "{name}: cut but not flagged");
            serde_json::from_str::<Value>(&serde_json::to_string(&out.value).unwrap()).expect("valid json");
        }
    }

    #[test]
    fn a_secret_summary_does_not_scan_the_whole_value() {
        let started = std::time::Instant::now();
        let out = redact_and_bound(json!({"password": "x".repeat(50_000_000)}), Limits::BOUNDED);
        assert_eq!(out.value["password"]["redacted"], true);
        assert_eq!(out.value["password"]["bytes"], 50_000_000);
        assert!(started.elapsed().as_millis() < 500, "took {:?}", started.elapsed());
    }

    #[test]
    fn a_deep_payload_is_cut_not_recursed() {
        let mut deep = json!("leaf");
        // serde_json itself refuses input deeper than 128, so this only guards values built in code.
        for _ in 0..500 {
            deep = json!({ "a": deep });
        }
        let out = redact_and_bound(deep, Limits::BOUNDED);
        assert!(out.truncated);
        assert!(out.value.to_string().contains(DEPTH_MARKER));
        assert!(serialized(&out.value) <= TOOL_FIELD_MAX_BYTES);
    }

    #[test]
    fn a_budget_that_fits_the_value_exactly_keeps_everything() {
        let value = json!({"a": [1, null, true, "x\"y"], "b": {}});
        let size = serialized(&value);
        let out = redact_and_bound(
            value.clone(),
            Limits {
                max_bytes: size,
                max_depth: 8,
            },
        );
        assert_eq!(
            out,
            Bounded {
                value: value.clone(),
                truncated: false
            }
        );
        let tight = redact_and_bound(
            value,
            Limits {
                max_bytes: size - 1,
                max_depth: 8,
            },
        );
        assert!(tight.truncated);
        assert!(serialized(&tight.value) < size);
    }

    #[test]
    fn secrets_inside_json_text_and_cut_json_are_masked() {
        for leaked in [
            r#"Response: {"access_token":"abc123"}"#,
            "{\"a\":1}\n{\"password\": \"hunter2\"}",
            r#"{"client_secret":"zzz"} trailing"#,
        ] {
            let out = redact_secrets(leaked);
            assert!(
                !out.contains("abc123") && !out.contains("hunter2") && !out.contains("zzz"),
                "{out}"
            );
        }
        // A JSON output longer than the budget no longer parses after the cut: it must still be masked.
        let big = format!("{{\"token\":\"SECRETTAIL\",\"pad\":\"{}\"}}", "x".repeat(200_000));
        let out = redact_and_bound(json!(big), Limits::BOUNDED);
        assert!(!out.value.to_string().contains("SECRETTAIL"));
    }

    #[test]
    fn header_style_secrets_are_masked_including_basic_credentials() {
        let out =
            redact_secrets("curl -H 'X-Api-Key: abc' -H 'Authorization: Basic dXNlcjpwYXNz' -H \"Cookie: sid=1\" url");
        for leaked in ["abc'", "dXNlcjpwYXNz", "sid=1"] {
            assert!(!out.contains(leaked), "{leaked} leaked: {out}");
        }
        assert!(out.contains("curl -H") && out.ends_with("url"), "{out}");
    }

    #[test]
    fn ordinary_words_and_paths_are_not_mangled() {
        for text in [
            "src/disk-cache.rs",
            "task-runner --flag",
            "tokenizer.rs",
            "the passwords list",
            "ask-me",
        ] {
            assert_eq!(redact_secrets(text), text);
        }
        assert_eq!(redact_secrets("key sk-live_ABC here"), "key sk-[redacted] here");
        assert_eq!(redact_secrets("Bearer abc.def x"), "Bearer [redacted] x");
        assert_eq!(redact_secrets("bearer abc"), "bearer [redacted]");
    }

    #[test]
    fn json_text_keeps_its_formatting() {
        let pretty = "{\n  \"b\": 1,\n  \"a\": \"x\"\n}";
        assert_eq!(redact_and_bound(json!(pretty), Limits::BOUNDED).value, json!(pretty));
    }

    #[test]
    fn more_secret_key_names_are_masked() {
        let out = redact_and_bound(
            json!({"Cookie": "a", "set-cookie": "b", "x-api-key": "c", "private_key": "d", "credentials": "e", "proxy-authorization": "f", "ok": "visible"}),
            Limits::BOUNDED,
        );
        let text = out.value.to_string();
        for leaked in ["\"a\"", "\"b\"", "\"c\"", "\"d\"", "\"e\"", "\"f\""] {
            assert!(!text.contains(&format!(":{leaked}")), "leaked {leaked}: {text}");
        }
        assert!(text.contains("visible"));
    }

    #[test]
    fn a_key_larger_than_the_budget_is_cut_before_any_per_character_work() {
        let mut map = serde_json::Map::new();
        map.insert("ok".into(), json!(1));
        map.insert("z".repeat(5_000_000), json!("v")); // keys iterate in order: "ok" first
        let out = redact_and_bound(Value::Object(map), Limits::BOUNDED);
        assert!(out.truncated);
        assert_eq!(out.value, json!({"ok": 1}));
        assert!(out.value.to_string().len() <= TOOL_FIELD_MAX_BYTES);
    }

    #[test]
    fn masking_is_idempotent_so_text_that_passes_two_filters_is_not_mangled() {
        // The placeholder ends in `]`, a delimiter: masking masked text must not grow `[redacted]]`.
        for text in [
            r#"curl -H "Authorization: Bearer SECRETVALUE123" https://x"#,
            "Authorization: Basic dXNlcjpwYXNz",
            "token=abc password: hunter2 sk-live_ABC",
            r#"{"access_token":"abc","n":1}"#,
            "psql postgres://admin:URL1@db:5432/app --password FLAG1",
            "key=[redacted] and Bearer [redacted] and token: [redacted]",
        ] {
            let once = redact_secrets(text);
            assert_eq!(redact_secrets(&once), once, "second pass changed: {once}");
            assert_eq!(
                redact_secrets(&redact_secrets(&once)),
                once,
                "third pass changed: {once}"
            );
            assert!(!once.contains("]]"), "doubled bracket in {once}");
        }
        let through_the_sanitizer = redact_and_bound(
            json!({"command": "curl -H \"Authorization: Bearer SECRETVALUE123\" x"}),
            Limits::BOUNDED,
        )
        .value;
        let again = redact_and_bound(through_the_sanitizer.clone(), Limits::BOUNDED).value;
        assert_eq!(again, through_the_sanitizer);
    }

    #[test]
    fn a_small_payload_is_unchanged() {
        let value = json!({"command": "ls -la", "n": 3, "ok": true, "items": ["a", "b"]});
        let out = redact_and_bound(value.clone(), Limits::BOUNDED);
        assert_eq!(
            out,
            Bounded {
                value,
                truncated: false
            }
        );
    }

    #[test]
    fn unbounded_bytes_still_redacts() {
        let long = format!("{} password=hunter2", "x".repeat(200_000));
        let out = redact_and_bound(json!(long), Limits::UNBOUNDED_BYTES);
        assert!(!out.truncated);
        assert!(!out.value.to_string().contains("hunter2"));
        assert!(out.value.to_string().len() > 200_000);
    }

    /// Second review (L03.IO): secret forms the textual rules missed. Each value must not survive.
    #[test]
    fn camel_case_escaped_flag_and_url_secrets_are_masked() {
        let leaks = [
            // camelCase names in JSON text (API responses): the name starts at a lower-to-upper boundary.
            (r#"{"accessToken":"CAMEL1","n":1}"#, "CAMEL1"),
            (r#"{"clientSecret": "CAMEL2"}"#, "CAMEL2"),
            ("dbPassword=CAMEL3 next", "CAMEL3"),
            // JSON that is itself escaped text (a JSON string printed inside JSON or a log).
            (r#"{\"access_token\":\"ESC1\",\"n\":1}"#, "ESC1"),
            (r#"{\\\"password\\\":\\\"ESC2\\\"}"#, "ESC2"),
            // An escaped quote inside a quoted secret does not end it.
            (r#"{"password":"ab\"ESC3","n":1}"#, "ESC3"),
            // Command-line flags whose value is the next word.
            ("mysql --password FLAG1 db", "FLAG1"),
            ("gh auth login --token FLAG2", "FLAG2"),
            // Credentials in a URL, including an unencoded `@` in the password.
            ("psql postgres://admin:URL1@db:5432/app", "URL1"),
            ("git clone https://u:p@URL2@host/x", "URL2"),
        ]
        .into_iter()
        .filter_map(|(text, leaked)| {
            let out = redact_secrets(text);
            out.contains(leaked).then(|| format!("{leaked}: {out}"))
        })
        .collect::<Vec<_>>();
        assert!(leaks.is_empty(), "leaked:\n{}", leaks.join("\n"));
        assert_eq!(
            redact_secrets("mysql --password FLAG1 db"),
            "mysql --password [redacted] db"
        );
        assert_eq!(
            redact_secrets("postgres://admin:URL1@db:5432/app"),
            "postgres://admin:[redacted]@db:5432/app"
        );
    }

    #[test]
    fn the_new_rules_leave_ordinary_text_alone() {
        for text in [
            "mytoken=abc",
            "see https://example.com/a:b@c?x=1",
            "mail user@example.com",
            "a://b",
            "run --password-file /etc/pw",
            "pass --no-password here",
            "the tokenizer splits text",
            r#"{\"n\":1}"#,
        ] {
            assert_eq!(redact_secrets(text), text);
        }
    }

    /// Env lists and HAR headers carry the secret NAME in one field and the value in another.
    #[test]
    fn a_name_value_object_with_a_secret_name_masks_its_value() {
        let out = redact_and_bound(
            json!({"spec": {"containers": [{"vars": [
                {"name": "GITHUB_TOKEN", "value": "NV1"},
                {"name": "HOME", "value": "/root"},
            ]}]}, "har": [{"name": "Authorization", "value": "Basic NV2"}, {"key": "api_key", "value": "NV3"}]}),
            Limits::BOUNDED,
        );
        let text = out.value.to_string();
        for leaked in ["NV1", "NV2", "NV3"] {
            assert!(!text.contains(leaked), "{leaked} leaked: {text}");
        }
        assert!(text.contains("/root") && text.contains("GITHUB_TOKEN"), "{text}");
        assert!(serialized(&out.value) <= TOOL_FIELD_MAX_BYTES);
    }

    /// The textual rules stay linear on input built to make them rescan (the full fetch redacts
    /// without a byte budget, so the whole text is scanned). Quadratic work on 1 MB would take minutes.
    #[test]
    fn textual_rules_stay_linear_on_adversarial_text() {
        let n = 1_000_000;
        for text in [
            "://".repeat(n / 3),
            format!("x://{}", "u:p".repeat(n / 3)),
            "--token ".repeat(n / 8),
            "token=\\".repeat(n / 7),
            format!("password:\"{}", "\\\"".repeat(n / 2)),
            "aToken:".repeat(n / 7),
            "\\".repeat(n),
        ] {
            let started = std::time::Instant::now();
            let _ = redact_and_bound(json!(text), Limits::UNBOUNDED_BYTES);
            assert!(started.elapsed().as_secs() < 5, "took {:?}", started.elapsed());
        }
    }

    #[test]
    fn text_helper_reports_truncation() {
        let (text, cut) = redact_and_bound_text(
            "abcdef",
            Limits {
                max_bytes: 5,
                max_depth: 1,
            },
        );
        assert_eq!((text.as_str(), cut), ("abc", true));
    }
}
