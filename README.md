# trace-redact

[![crates.io](https://img.shields.io/crates/v/trace-redact.svg)](https://crates.io/crates/trace-redact)

Walk a `serde_json::Value` (agent trace, span attributes) and redact
sensitive fields in place. Key-name match (`api_key`, `authorization`,
…) plus value-pattern match (API keys, bearer tokens, emails, SSNs).

```rust
use trace_redact::redact;
use serde_json::json;
let mut v = json!({
    "headers": { "authorization": "Bearer sk-live-AAAABBBBCCCCDDDD" },
    "email": "jane@example.com",
});
redact(&mut v);
```

MIT or Apache-2.0.
