//! Secret redaction for text and JSON that leaves the host (diagnostics, handoff excerpts).

use serde_json::{Value, json};

/// Redacts secret-named keys and secret-looking strings anywhere in `value`.
pub fn redact_value(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let redacted = object
                .into_iter()
                .map(|(key, value)| {
                    let value = if should_redact_key(&key) {
                        redacted_secret_summary(value)
                    } else {
                        redact_value(value)
                    };
                    (key, value)
                })
                .collect();
            Value::Object(redacted)
        }
        Value::Array(items) => Value::Array(items.into_iter().map(redact_value).collect()),
        Value::String(text) => Value::String(redact_text(&text)),
        other => other,
    }
}

fn should_redact_key(key: &str) -> bool {
    let key = key.to_ascii_lowercase();
    matches!(
        key.as_str(),
        "api_key"
            | "apikey"
            | "access_key"
            | "secret_key"
            | "aws_access_key_id"
            | "aws_secret_access_key"
            | "authorization"
            | "headers"
            | "env"
    ) || key.contains("secret")
        || key.contains("token")
        || key.contains("password")
}

fn redacted_secret_summary(value: Value) -> Value {
    match value {
        Value::String(text) => json!({
            "redacted": true,
            "chars": text.chars().count(),
        }),
        Value::Object(object) => json!({
            "redacted": true,
            "keys": object.len(),
        }),
        Value::Array(items) => json!({
            "redacted": true,
            "items": items.len(),
        }),
        _ => json!({
            "redacted": true,
        }),
    }
}

/// Redacts `sk-…` keys and bearer tokens in `text` (JSON text is redacted structurally).
pub fn redact_text(text: &str) -> String {
    if let Ok(parsed @ (Value::Object(_) | Value::Array(_))) = serde_json::from_str::<Value>(text)
        && let Ok(redacted) = serde_json::to_string(&redact_value(parsed))
    {
        return redacted;
    }
    let text = redact_prefixed_secret(text, "sk-", "sk-REDACTED");
    let text = redact_prefixed_secret(&text, "Bearer ", "Bearer REDACTED");
    redact_prefixed_secret(&text, "bearer ", "bearer REDACTED")
}

fn redact_prefixed_secret(text: &str, prefix: &str, replacement: &str) -> String {
    let mut output = String::with_capacity(text.len());
    let mut offset = 0;
    while let Some(relative_start) = text[offset..].find(prefix) {
        let start = offset + relative_start;
        output.push_str(&text[offset..start]);
        output.push_str(replacement);
        let secret_start = start + prefix.len();
        let secret_end = text[secret_start..]
            .char_indices()
            .find_map(|(index, ch)| is_secret_delimiter(ch).then_some(secret_start + index))
            .unwrap_or(text.len());
        offset = secret_end;
    }
    output.push_str(&text[offset..]);
    output
}

fn is_secret_delimiter(ch: char) -> bool {
    ch.is_whitespace() || matches!(ch, '"' | '\'' | ',' | '}' | ']' | ';')
}
