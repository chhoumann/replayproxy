use regex::Regex;
use serde_json::Value;
use std::sync::OnceLock;

use crate::storage::Recording;

const LEGACY_REDACTION_PLACEHOLDER: &str = "[REDACTED]";
const FORM_URLENCODED_CONTENT_TYPE: &str = "application/x-www-form-urlencoded";

pub(crate) fn scrub_recording_for_legacy_redaction(recording: &mut Recording) -> bool {
    let mut changed = false;

    changed |= scrub_headers(&mut recording.request_headers);
    changed |= scrub_headers(&mut recording.response_headers);

    let (request_body, request_changed) =
        scrub_body(&recording.request_body, &recording.request_headers);
    if request_changed {
        recording.request_body = request_body;
        changed = true;
    }

    let (response_body, response_changed) =
        scrub_body(&recording.response_body, &recording.response_headers);
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

fn scrub_body(body: &[u8], headers: &[(String, Vec<u8>)]) -> (Vec<u8>, bool) {
    let (json_body, json_changed) = scrub_json_body(body);
    if json_changed {
        return (json_body, true);
    }

    if is_form_urlencoded_body(headers) {
        let (form_body, form_changed) = scrub_form_urlencoded_body(body);
        if form_changed {
            return (form_body, true);
        }
    }

    scrub_plaintext_key_value_body(body)
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

fn is_form_urlencoded_body(headers: &[(String, Vec<u8>)]) -> bool {
    headers.iter().any(|(name, value)| {
        name.eq_ignore_ascii_case("content-type")
            && std::str::from_utf8(value)
                .ok()
                .and_then(|content_type| content_type.split(';').next())
                .map(|mime| {
                    mime.trim()
                        .eq_ignore_ascii_case(FORM_URLENCODED_CONTENT_TYPE)
                })
                .unwrap_or(false)
    })
}

fn scrub_form_urlencoded_body(body: &[u8]) -> (Vec<u8>, bool) {
    let text = match std::str::from_utf8(body) {
        Ok(value) => value,
        Err(_) => return (body.to_vec(), false),
    };

    let mut changed = false;
    let mut redacted = String::with_capacity(text.len());
    for (index, pair) in text.split('&').enumerate() {
        if index > 0 {
            redacted.push('&');
        }

        let Some((raw_key, raw_value)) = pair.split_once('=') else {
            redacted.push_str(pair);
            continue;
        };

        if !is_sensitive_key(&decode_form_component(raw_key)) {
            redacted.push_str(pair);
            continue;
        }

        if decode_form_component(raw_value) == LEGACY_REDACTION_PLACEHOLDER {
            redacted.push_str(pair);
            continue;
        }

        changed = true;
        redacted.push_str(raw_key);
        redacted.push('=');
        redacted.push_str(&encode_form_component(LEGACY_REDACTION_PLACEHOLDER));
    }

    if !changed {
        return (body.to_vec(), false);
    }

    (redacted.into_bytes(), true)
}

fn scrub_plaintext_key_value_body(body: &[u8]) -> (Vec<u8>, bool) {
    let text = match std::str::from_utf8(body) {
        Ok(value) => value,
        Err(_) => return (body.to_vec(), false),
    };

    let mut changed = false;
    let redacted =
        plaintext_key_value_regex().replace_all(text, |captures: &regex::Captures<'_>| {
            let key = captures.name("key").map_or("", |group| group.as_str());
            let value = captures.name("value").map_or("", |group| group.as_str());
            if !is_sensitive_key(key) || value == LEGACY_REDACTION_PLACEHOLDER {
                return captures
                    .get(0)
                    .map_or(String::new(), |group| group.as_str().to_owned());
            }

            changed = true;
            format!(
                "{}{}{}{}",
                captures.name("prefix").map_or("", |group| group.as_str()),
                key,
                captures
                    .name("separator")
                    .map_or("=", |group| group.as_str()),
                LEGACY_REDACTION_PLACEHOLDER
            )
        });

    if !changed {
        return (body.to_vec(), false);
    }

    (redacted.into_owned().into_bytes(), true)
}

fn plaintext_key_value_regex() -> &'static Regex {
    static REGEX: OnceLock<Regex> = OnceLock::new();
    REGEX.get_or_init(|| {
        Regex::new(
            r"(?P<prefix>^|[?&;,\s])(?P<key>[A-Za-z0-9_.-]+)(?P<separator>\s*=\s*)(?P<value>[^\s&;,]*)",
        )
        .expect("plain-text key/value regex should compile")
    })
}

fn decode_form_component(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            }
            b'%' if index + 2 < bytes.len() => {
                let high = hex_nibble(bytes[index + 1]);
                let low = hex_nibble(bytes[index + 2]);
                if let (Some(high), Some(low)) = (high, low) {
                    decoded.push((high << 4) | low);
                    index += 3;
                } else {
                    decoded.push(bytes[index]);
                    index += 1;
                }
            }
            byte => {
                decoded.push(byte);
                index += 1;
            }
        }
    }

    String::from_utf8_lossy(&decoded).into_owned()
}

fn hex_nibble(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'a'..=b'f' => Some(value - b'a' + 10),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

fn encode_form_component(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'*') {
            encoded.push(char::from(byte));
            continue;
        }
        if byte == b' ' {
            encoded.push('+');
            continue;
        }

        const HEX: &[u8; 16] = b"0123456789ABCDEF";
        encoded.push('%');
        encoded.push(char::from(HEX[(byte >> 4) as usize]));
        encoded.push(char::from(HEX[(byte & 0x0F) as usize]));
    }
    encoded
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
    fn scrub_recording_redacts_form_urlencoded_payloads() {
        let mut recording = Recording {
            match_key: "match".to_owned(),
            request_method: "POST".to_owned(),
            request_uri: "/v1/chat/completions".to_owned(),
            request_headers: vec![(
                "content-type".to_owned(),
                b"application/x-www-form-urlencoded; charset=utf-8".to_vec(),
            )],
            request_body: b"%61%70%69%5f%6b%65%79=plain&safe=ok".to_vec(),
            response_status: 200,
            response_headers: vec![(
                "content-type".to_owned(),
                b"application/x-www-form-urlencoded".to_vec(),
            )],
            response_body: b"client_secret=super+secret&message=ok".to_vec(),
            created_at_unix_ms: 0,
        };

        let changed = scrub_recording_for_legacy_redaction(&mut recording);
        assert!(changed);
        assert_eq!(
            recording.request_body,
            b"%61%70%69%5f%6b%65%79=%5BREDACTED%5D&safe=ok".to_vec()
        );
        assert_eq!(
            recording.response_body,
            b"client_secret=%5BREDACTED%5D&message=ok".to_vec()
        );
    }

    #[test]
    fn scrub_recording_redacts_plain_text_key_value_payloads() {
        let mut recording = Recording {
            match_key: "match".to_owned(),
            request_method: "POST".to_owned(),
            request_uri: "/v1/chat/completions".to_owned(),
            request_headers: vec![("content-type".to_owned(), b"text/plain".to_vec())],
            request_body: b"token=plain-text-value safe=ok password = hunter2".to_vec(),
            response_status: 200,
            response_headers: vec![],
            response_body: b"api_key=resp-secret;message=ok".to_vec(),
            created_at_unix_ms: 0,
        };

        let changed = scrub_recording_for_legacy_redaction(&mut recording);
        assert!(changed);
        assert_eq!(
            recording.request_body,
            b"token=[REDACTED] safe=ok password = [REDACTED]".to_vec()
        );
        assert_eq!(
            recording.response_body,
            b"api_key=[REDACTED];message=ok".to_vec()
        );
    }

    #[test]
    fn scrub_recording_leaves_non_matching_plain_text_payloads_unchanged() {
        let mut recording = Recording {
            match_key: "match".to_owned(),
            request_method: "POST".to_owned(),
            request_uri: "/v1/chat/completions".to_owned(),
            request_headers: vec![("content-type".to_owned(), b"text/plain".to_vec())],
            request_body: b"plain text request body".to_vec(),
            response_status: 200,
            response_headers: vec![],
            response_body: b"plain text response without assignments".to_vec(),
            created_at_unix_ms: 0,
        };

        let changed = scrub_recording_for_legacy_redaction(&mut recording);
        assert!(!changed);
        assert_eq!(recording.request_body, b"plain text request body".to_vec());
        assert_eq!(
            recording.response_body,
            b"plain text response without assignments".to_vec()
        );
    }
}
