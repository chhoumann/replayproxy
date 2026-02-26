use serde_json::Value;

use crate::storage::Recording;

const LEGACY_REDACTION_PLACEHOLDER: &str = "[REDACTED]";

pub(crate) fn scrub_recording_for_legacy_redaction(recording: &mut Recording) -> bool {
    let mut changed = false;

    changed |= scrub_headers(&mut recording.request_headers);
    changed |= scrub_headers(&mut recording.response_headers);

    let (request_body, request_changed) = scrub_json_body(&recording.request_body);
    if request_changed {
        recording.request_body = request_body;
        changed = true;
    }

    let (response_body, response_changed) = scrub_json_body(&recording.response_body);
    if response_changed {
        recording.response_body = response_body;
        changed = true;
    }

    changed
}

fn scrub_headers(headers: &mut [(String, Vec<u8>)]) -> bool {
    let mut changed = false;
    let placeholder = LEGACY_REDACTION_PLACEHOLDER.as_bytes();
    for (name, value) in headers {
        if !is_sensitive_key(name) {
            continue;
        }
        if value.as_slice() == placeholder {
            continue;
        }
        *value = placeholder.to_vec();
        changed = true;
    }
    changed
}

fn scrub_json_body(body: &[u8]) -> (Vec<u8>, bool) {
    let mut parsed: Value = match serde_json::from_slice(body) {
        Ok(value) => value,
        Err(_) => return (body.to_vec(), false),
    };

    let changed = scrub_json_value(&mut parsed);
    if !changed {
        return (body.to_vec(), false);
    }

    match serde_json::to_vec(&parsed) {
        Ok(redacted) => (redacted, true),
        Err(_) => (body.to_vec(), false),
    }
}

fn scrub_json_value(value: &mut Value) -> bool {
    match value {
        Value::Object(map) => {
            let mut changed = false;
            for (key, nested) in map {
                if is_sensitive_key(key) {
                    let replacement = Value::String(LEGACY_REDACTION_PLACEHOLDER.to_owned());
                    if *nested != replacement {
                        *nested = replacement;
                        changed = true;
                    }
                    continue;
                }
                changed |= scrub_json_value(nested);
            }
            changed
        }
        Value::Array(values) => {
            let mut changed = false;
            for nested in values {
                changed |= scrub_json_value(nested);
            }
            changed
        }
        _ => false,
    }
}

fn is_sensitive_key(value: &str) -> bool {
    let normalized = normalize_key(value);
    if normalized.is_empty() {
        return false;
    }

    matches!(
        normalized.as_str(),
        "authorization"
            | "proxyauthorization"
            | "cookie"
            | "setcookie"
            | "apikey"
            | "xapikey"
            | "accesstoken"
            | "refreshtoken"
            | "idtoken"
            | "authtoken"
            | "secret"
            | "clientsecret"
            | "password"
            | "passwd"
            | "pwd"
    ) || normalized.ends_with("token")
        || normalized.ends_with("secret")
        || normalized.ends_with("apikey")
        || normalized.ends_with("password")
}

fn normalize_key(value: &str) -> String {
    value
        .bytes()
        .filter(|byte| byte.is_ascii_alphanumeric())
        .map(|byte| byte.to_ascii_lowercase() as char)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::scrub_recording_for_legacy_redaction;
    use crate::storage::Recording;
    use serde_json::Value;

    #[test]
    fn scrub_recording_redacts_sensitive_headers_and_json_keys() {
        let mut recording = Recording {
            match_key: "match".to_owned(),
            request_method: "POST".to_owned(),
            request_uri: "/v1/chat/completions".to_owned(),
            request_headers: vec![
                ("Authorization".to_owned(), b"Bearer super-secret".to_vec()),
                ("x-api-key".to_owned(), b"abc123".to_vec()),
                ("x-request-id".to_owned(), b"safe".to_vec()),
            ],
            request_body:
                br#"{"token":"secret-token","safe":"ok","nested":{"client_secret":"keep-out"}}"#
                    .to_vec(),
            response_status: 200,
            response_headers: vec![
                ("set-cookie".to_owned(), b"session=abc".to_vec()),
                ("content-type".to_owned(), b"application/json".to_vec()),
            ],
            response_body: br#"{"access_token":"abc","message":"ok"}"#.to_vec(),
            created_at_unix_ms: 0,
        };

        let changed = scrub_recording_for_legacy_redaction(&mut recording);
        assert!(changed);

        assert_eq!(recording.request_headers[0].1, b"[REDACTED]".to_vec());
        assert_eq!(recording.request_headers[1].1, b"[REDACTED]".to_vec());
        assert_eq!(recording.request_headers[2].1, b"safe".to_vec());
        assert_eq!(recording.response_headers[0].1, b"[REDACTED]".to_vec());
        assert_eq!(
            recording.response_headers[1].1,
            b"application/json".to_vec()
        );

        let request_json: Value = serde_json::from_slice(&recording.request_body).unwrap();
        assert_eq!(
            request_json.pointer("/token").and_then(Value::as_str),
            Some("[REDACTED]")
        );
        assert_eq!(
            request_json
                .pointer("/nested/client_secret")
                .and_then(Value::as_str),
            Some("[REDACTED]")
        );
        assert_eq!(
            request_json.pointer("/safe").and_then(Value::as_str),
            Some("ok")
        );

        let response_json: Value = serde_json::from_slice(&recording.response_body).unwrap();
        assert_eq!(
            response_json
                .pointer("/access_token")
                .and_then(Value::as_str),
            Some("[REDACTED]")
        );
        assert_eq!(
            response_json.pointer("/message").and_then(Value::as_str),
            Some("ok")
        );
    }

    #[test]
    fn scrub_recording_leaves_non_json_payloads_unchanged() {
        let mut recording = Recording {
            match_key: "match".to_owned(),
            request_method: "POST".to_owned(),
            request_uri: "/v1/chat/completions".to_owned(),
            request_headers: vec![("content-type".to_owned(), b"text/plain".to_vec())],
            request_body: b"token=plain-text-value".to_vec(),
            response_status: 200,
            response_headers: vec![],
            response_body: b"plain text response".to_vec(),
            created_at_unix_ms: 0,
        };

        let changed = scrub_recording_for_legacy_redaction(&mut recording);
        assert!(!changed);
        assert_eq!(recording.request_body, b"token=plain-text-value".to_vec());
        assert_eq!(recording.response_body, b"plain text response".to_vec());
    }
}
