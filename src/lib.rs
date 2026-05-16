//! # trace-redact
//!
//! Walk a `serde_json::Value` (agent trace, OTel span attributes) and
//! redact sensitive values in place. Two layers of detection:
//!
//! 1. **Key-name match** — fields named `api_key`, `token`,
//!    `authorization`, `password`, etc., are replaced regardless of
//!    value shape.
//! 2. **Value-pattern match** — string values that look like API keys,
//!    bearer tokens, emails, phone numbers, or SSNs are replaced.
//!
//! ## Example
//!
//! ```
//! use trace_redact::redact;
//! use serde_json::{json, Value};
//!
//! let mut v: Value = json!({
//!     "model": "claude-sonnet-4-5",
//!     "headers": { "authorization": "Bearer sk-live-AAAABBBBCCCCDDDD" },
//!     "user_email": "jane@example.com",
//! });
//! redact(&mut v);
//! assert_eq!(v["headers"]["authorization"], json!("[REDACTED]"));
//! ```

#![deny(missing_docs)]

use serde_json::Value;

/// Replacement token written into redacted slots.
pub const REPLACEMENT: &str = "[REDACTED]";

/// Field-name list (lowercased) that always triggers redaction.
const SENSITIVE_KEYS: &[&str] = &[
    "api_key",
    "apikey",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "authorization",
    "password",
    "secret",
    "x-api-key",
    "anthropic-api-key",
    "openai-api-key",
];

/// Walk `v` and redact in place.
pub fn redact(v: &mut Value) {
    match v {
        Value::Object(map) => {
            let keys: Vec<String> = map.keys().cloned().collect();
            for k in keys {
                if is_sensitive_key(&k) {
                    if let Some(slot) = map.get_mut(&k) {
                        *slot = Value::String(REPLACEMENT.to_string());
                    }
                    continue;
                }
                if let Some(slot) = map.get_mut(&k) {
                    redact(slot);
                }
            }
        }
        Value::Array(items) => {
            for item in items.iter_mut() {
                redact(item);
            }
        }
        Value::String(s) => {
            if looks_sensitive(s) {
                *v = Value::String(REPLACEMENT.to_string());
            }
        }
        _ => {}
    }
}

fn is_sensitive_key(k: &str) -> bool {
    let lk = k.to_ascii_lowercase();
    SENSITIVE_KEYS.iter().any(|s| *s == lk)
}

/// True for strings that pattern-match an API key, bearer token, email,
/// phone, or SSN.
pub fn looks_sensitive(s: &str) -> bool {
    is_api_keyish(s)
        || s.starts_with("Bearer ")
        || is_email(s)
        || is_ssn(s)
        || is_phone(s)
}

fn is_api_keyish(s: &str) -> bool {
    // Common prefixes followed by 16+ url-safe chars.
    let prefixes = ["sk-", "ghp_", "xoxb-", "sk_live_", "sk_test_", "rk_live_"];
    if prefixes.iter().any(|p| s.starts_with(p)) {
        let tail_len = s.split_once(|c: char| c == '-' || c == '_')
            .map(|(_, t)| t.len())
            .unwrap_or(0);
        return tail_len >= 16;
    }
    false
}

fn is_email(s: &str) -> bool {
    let parts: Vec<&str> = s.split('@').collect();
    parts.len() == 2 && !parts[0].is_empty() && parts[1].contains('.')
}

fn is_ssn(s: &str) -> bool {
    s.len() == 11
        && s.chars().enumerate().all(|(i, c)| match i {
            3 | 6 => c == '-',
            _ => c.is_ascii_digit(),
        })
}

fn is_phone(s: &str) -> bool {
    let digits: String = s.chars().filter(|c| c.is_ascii_digit()).collect();
    (10..=12).contains(&digits.len()) && s.chars().any(|c| c == '-' || c == '(' || c == ' ')
}
