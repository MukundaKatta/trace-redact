use serde_json::json;
use trace_redact::{redact, REPLACEMENT};

#[test]
fn redacts_known_key_names() {
    let mut v = json!({
        "api_key": "anything",
        "authorization": "Bearer x",
        "Password": "y",
        "innocent": "z",
    });
    redact(&mut v);
    assert_eq!(v["api_key"], json!(REPLACEMENT));
    assert_eq!(v["authorization"], json!(REPLACEMENT));
    assert_eq!(v["Password"], json!(REPLACEMENT));
    assert_eq!(v["innocent"], json!("z"));
}

#[test]
fn redacts_api_key_pattern_in_value() {
    let mut v = json!({ "note": "sk-live-AAAABBBBCCCCDDDD" });
    redact(&mut v);
    assert_eq!(v["note"], json!(REPLACEMENT));
}

#[test]
fn redacts_emails_and_ssns() {
    let mut v = json!({
        "email": "jane@example.com",
        "ssn": "123-45-6789",
    });
    redact(&mut v);
    assert_eq!(v["email"], json!(REPLACEMENT));
    assert_eq!(v["ssn"], json!(REPLACEMENT));
}

#[test]
fn descends_nested_objects_and_arrays() {
    let mut v = json!({
        "spans": [
            { "headers": { "Authorization": "Bearer x" } },
            { "ok": true }
        ]
    });
    redact(&mut v);
    assert_eq!(v["spans"][0]["headers"]["Authorization"], json!(REPLACEMENT));
}

#[test]
fn leaves_safe_strings_alone() {
    let mut v = json!({ "model": "claude-sonnet-4-5" });
    redact(&mut v);
    assert_eq!(v["model"], json!("claude-sonnet-4-5"));
}
