use std::{borrow::Cow, collections::HashSet};

use sha2::{Digest as _, Sha256};

use crate::config::{QueryMatchMode, RouteMatchConfig};

/// Computes the match key used for caching/replay lookups.
///
/// # Normalization pipeline (v1)
///
/// The match key is a SHA-256 hash over the *normalized* request dimensions. Normalization is
/// deterministic and is shared by all routes.
///
/// Included dimensions are controlled by `route_match`:
/// - `method`: uppercased (ASCII) HTTP method
/// - `path`: `Uri::path()` as-is (scheme/authority are ignored)
/// - `query`:
///   - `ignore`: excluded
///   - `exact`: parsed as raw `name=value` pairs (no percent-decoding), sorted by name then value,
///     with repeated keys preserved
///   - `subset`: excluded from the hash; subset filtering is applied during recording lookup
/// - `headers`: case-insensitive names, compared/serialized lowercased; values are raw bytes;
///   selected via allowlist and/or ignore list; sorted by name then value bytes
/// - `body`: raw bytes as received
///
/// Notes:
/// - This currently ignores `route_match.body_json` (JSONPath) until JSON field matching is
///   implemented.
pub fn compute_match_key(
    route_match: Option<&RouteMatchConfig>,
    method: &hyper::Method,
    uri: &hyper::Uri,
    headers: &hyper::HeaderMap,
    body: &[u8],
) -> String {
    let match_cfg = effective_match_config(route_match);

    let mut hasher = Sha256::new();

    if match_cfg.method {
        hash_tagged_str(&mut hasher, b"method", normalized_method(method).as_ref());
    }

    if match_cfg.path {
        hash_tagged_str(&mut hasher, b"path", uri.path());
    }

    match match_cfg.query {
        QueryMatchMode::Ignore | QueryMatchMode::Subset => {}
        QueryMatchMode::Exact => {
            let mut params = query_params_sorted(uri.query());
            hash_len_prefixed(&mut hasher, b"query");
            hash_len_prefixed(&mut hasher, params.len().to_string().as_bytes());
            for (name, value) in params.drain(..) {
                hash_len_prefixed(&mut hasher, name.as_bytes());
                hash_len_prefixed(&mut hasher, value.as_bytes());
            }
        }
    }

    if match_cfg.headers_enabled {
        let mut normalized = normalized_headers_sorted(headers, &match_cfg);
        hash_len_prefixed(&mut hasher, b"headers");
        hash_len_prefixed(&mut hasher, normalized.len().to_string().as_bytes());
        for (name, value) in normalized.drain(..) {
            hash_len_prefixed(&mut hasher, name.as_bytes());
            hash_len_prefixed(&mut hasher, &value);
        }
    }

    hash_tagged_bytes(&mut hasher, b"body", body);

    let digest = hasher.finalize();
    hex_encode(&digest)
}

#[derive(Debug, Clone)]
struct EffectiveMatchConfig {
    method: bool,
    path: bool,
    query: QueryMatchMode,
    headers_include_lc: HashSet<String>,
    headers_ignore_lc: HashSet<String>,
    headers_enabled: bool,
}

fn effective_match_config(route_match: Option<&RouteMatchConfig>) -> EffectiveMatchConfig {
    let Some(route_match) = route_match else {
        return EffectiveMatchConfig {
            method: true,
            path: true,
            query: QueryMatchMode::Exact,
            headers_include_lc: HashSet::new(),
            headers_ignore_lc: HashSet::new(),
            headers_enabled: false,
        };
    };

    let headers_include_lc: HashSet<String> = route_match
        .headers
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect();
    let headers_ignore_lc: HashSet<String> = route_match
        .headers_ignore
        .iter()
        .map(|name| name.to_ascii_lowercase())
        .collect();

    let headers_enabled = !(headers_include_lc.is_empty() && headers_ignore_lc.is_empty());

    EffectiveMatchConfig {
        method: route_match.method,
        path: route_match.path,
        query: route_match.query,
        headers_include_lc,
        headers_ignore_lc,
        headers_enabled,
    }
}

fn normalized_method(method: &hyper::Method) -> Cow<'_, str> {
    let method = method.as_str();
    if method.bytes().any(|byte| byte.is_ascii_lowercase()) {
        return Cow::Owned(method.to_ascii_uppercase());
    }
    Cow::Borrowed(method)
}

fn query_params_sorted(query: Option<&str>) -> Vec<(&str, &str)> {
    let mut out = Vec::new();
    let Some(query) = query else { return out };

    for segment in query.split('&') {
        if segment.is_empty() {
            continue;
        }
        let mut parts = segment.splitn(2, '=');
        let name = parts.next().unwrap_or_default();
        let value = parts.next().unwrap_or_default();
        out.push((name, value));
    }

    out.sort_unstable_by(|(a_name, a_value), (b_name, b_value)| {
        a_name.cmp(b_name).then_with(|| a_value.cmp(b_value))
    });
    out
}

pub(crate) fn query_params_match(
    mode: QueryMatchMode,
    recorded_query: Option<&str>,
    request_query: Option<&str>,
) -> bool {
    match mode {
        QueryMatchMode::Ignore => true,
        QueryMatchMode::Exact => {
            query_params_sorted(recorded_query) == query_params_sorted(request_query)
        }
        QueryMatchMode::Subset => {
            let required = query_params_sorted(recorded_query);
            let candidate = query_params_sorted(request_query);

            let mut required_idx = 0;
            let mut candidate_idx = 0;
            while required_idx < required.len() && candidate_idx < candidate.len() {
                match required[required_idx].cmp(&candidate[candidate_idx]) {
                    std::cmp::Ordering::Less => return false,
                    std::cmp::Ordering::Equal => {
                        required_idx += 1;
                        candidate_idx += 1;
                    }
                    std::cmp::Ordering::Greater => {
                        candidate_idx += 1;
                    }
                }
            }
            required_idx == required.len()
        }
    }
}

fn normalized_headers_sorted(
    headers: &hyper::HeaderMap,
    match_cfg: &EffectiveMatchConfig,
) -> Vec<(String, Vec<u8>)> {
    let include_all_except_ignored =
        match_cfg.headers_include_lc.is_empty() && !match_cfg.headers_ignore_lc.is_empty();

    let mut out = Vec::new();
    for (name, value) in headers.iter() {
        let name_lc = name.as_str().to_ascii_lowercase();

        if match_cfg.headers_ignore_lc.contains(&name_lc) {
            continue;
        }

        if include_all_except_ignored || match_cfg.headers_include_lc.contains(&name_lc) {
            out.push((name_lc, value.as_bytes().to_vec()));
        }
    }

    out.sort_unstable_by(|(a_name, a_value), (b_name, b_value)| {
        a_name
            .cmp(b_name)
            .then_with(|| a_value.as_slice().cmp(b_value.as_slice()))
    });
    out
}

fn hash_tagged_str(hasher: &mut Sha256, tag: &[u8], value: &str) {
    hash_tagged_bytes(hasher, tag, value.as_bytes());
}

fn hash_tagged_bytes(hasher: &mut Sha256, tag: &[u8], value: &[u8]) {
    hash_len_prefixed(hasher, tag);
    hash_len_prefixed(hasher, value);
}

fn hash_len_prefixed(hasher: &mut Sha256, value: &[u8]) {
    hasher.update(u64::try_from(value.len()).unwrap_or(u64::MAX).to_le_bytes());
    hasher.update(value);
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = vec![0u8; bytes.len() * 2];
    for (idx, byte) in bytes.iter().copied().enumerate() {
        out[idx * 2] = HEX[(byte >> 4) as usize];
        out[idx * 2 + 1] = HEX[(byte & 0x0f) as usize];
    }
    // Safety: HEX digits are valid UTF-8.
    unsafe { String::from_utf8_unchecked(out) }
}

#[cfg(test)]
mod tests {
    use super::{compute_match_key, query_params_match};
    use crate::config::QueryMatchMode;

    #[test]
    fn match_key_ignores_authority_and_scheme() {
        let method = hyper::Method::POST;
        let a: hyper::Uri = "http://127.0.0.1:1/api/hello?x=1".parse().unwrap();
        let b: hyper::Uri = "https://example.com/api/hello?x=1".parse().unwrap();
        let body = br#"{"a":1}"#;

        assert_eq!(
            compute_match_key(None, &method, &a, &hyper::HeaderMap::new(), body),
            compute_match_key(None, &method, &b, &hyper::HeaderMap::new(), body)
        );
    }

    #[test]
    fn match_key_sorts_query_params() {
        let method = hyper::Method::GET;
        let a: hyper::Uri = "http://example.com/api/hello?b=2&a=1&a=0".parse().unwrap();
        let b: hyper::Uri = "http://example.com/api/hello?a=0&a=1&b=2".parse().unwrap();

        assert_eq!(
            compute_match_key(None, &method, &a, &hyper::HeaderMap::new(), b""),
            compute_match_key(None, &method, &b, &hyper::HeaderMap::new(), b"")
        );
    }

    #[test]
    fn match_key_sorts_and_normalizes_selected_headers() {
        let route_match: crate::config::RouteMatchConfig = toml::from_str(
            r#"
method = true
path = true
headers = ["X-A", "x-b"]
"#,
        )
        .unwrap();

        let method = hyper::Method::GET;
        let uri: hyper::Uri = "http://example.com/api/hello".parse().unwrap();

        let mut a = hyper::HeaderMap::new();
        a.insert("X-A", hyper::header::HeaderValue::from_static("1"));
        a.insert("X-B", hyper::header::HeaderValue::from_static("2"));

        let mut b = hyper::HeaderMap::new();
        b.insert("x-b", hyper::header::HeaderValue::from_static("2"));
        b.insert("x-a", hyper::header::HeaderValue::from_static("1"));

        assert_eq!(
            compute_match_key(Some(&route_match), &method, &uri, &a, b""),
            compute_match_key(Some(&route_match), &method, &uri, &b, b"")
        );
    }

    #[test]
    fn match_key_changes_when_body_changes() {
        let method = hyper::Method::POST;
        let uri: hyper::Uri = "http://example.com/api/hello?x=1".parse().unwrap();
        let headers = hyper::HeaderMap::new();

        assert_ne!(
            compute_match_key(None, &method, &uri, &headers, b"a"),
            compute_match_key(None, &method, &uri, &headers, b"b")
        );
    }

    #[test]
    fn match_key_changes_when_query_changes_in_exact_mode() {
        let method = hyper::Method::GET;
        let headers = hyper::HeaderMap::new();
        let a: hyper::Uri = "http://example.com/api/hello?x=1".parse().unwrap();
        let b: hyper::Uri = "http://example.com/api/hello?x=2".parse().unwrap();

        assert_ne!(
            compute_match_key(None, &method, &a, &headers, b""),
            compute_match_key(None, &method, &b, &headers, b"")
        );
    }

    #[test]
    fn match_key_ignores_query_when_configured() {
        let route_match: crate::config::RouteMatchConfig =
            toml::from_str("query = \"ignore\"\n").unwrap();

        let method = hyper::Method::GET;
        let headers = hyper::HeaderMap::new();
        let a: hyper::Uri = "http://example.com/api/hello?x=1".parse().unwrap();
        let b: hyper::Uri = "http://example.com/api/hello?x=2".parse().unwrap();

        assert_eq!(
            compute_match_key(Some(&route_match), &method, &a, &headers, b""),
            compute_match_key(Some(&route_match), &method, &b, &headers, b"")
        );
    }

    #[test]
    fn match_key_ignores_query_bytes_in_subset_mode() {
        let route_match: crate::config::RouteMatchConfig =
            toml::from_str("query = \"subset\"\n").unwrap();

        let method = hyper::Method::GET;
        let headers = hyper::HeaderMap::new();
        let a: hyper::Uri = "http://example.com/api/hello?x=1".parse().unwrap();
        let b: hyper::Uri = "http://example.com/api/hello?x=2&y=3".parse().unwrap();

        assert_eq!(
            compute_match_key(Some(&route_match), &method, &a, &headers, b""),
            compute_match_key(Some(&route_match), &method, &b, &headers, b"")
        );
    }

    #[test]
    fn query_subset_mode_is_order_insensitive_and_allows_extras() {
        assert!(query_params_match(
            QueryMatchMode::Subset,
            Some("b=2&a=1"),
            Some("c=3&a=1&b=2")
        ));
    }

    #[test]
    fn query_subset_mode_respects_repeated_key_multiplicity() {
        assert!(query_params_match(
            QueryMatchMode::Subset,
            Some("a=1&a=1"),
            Some("a=1&b=2&a=1")
        ));
        assert!(!query_params_match(
            QueryMatchMode::Subset,
            Some("a=1&a=1"),
            Some("a=1&b=2")
        ));
    }

    #[test]
    fn match_key_respects_disabled_method_dimension() {
        let route_match: crate::config::RouteMatchConfig =
            toml::from_str("method = false\n").unwrap();

        let uri: hyper::Uri = "http://example.com/api/hello?x=1".parse().unwrap();
        let headers = hyper::HeaderMap::new();

        assert_eq!(
            compute_match_key(Some(&route_match), &hyper::Method::GET, &uri, &headers, b""),
            compute_match_key(
                Some(&route_match),
                &hyper::Method::POST,
                &uri,
                &headers,
                b""
            )
        );
    }

    #[test]
    fn match_key_is_lowercase_hex_sha256() {
        let key = compute_match_key(
            None,
            &hyper::Method::GET,
            &"http://example.com/api/hello?x=1".parse().unwrap(),
            &hyper::HeaderMap::new(),
            b"",
        );

        assert_eq!(key.len(), 64);
        assert!(
            key.bytes()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f')),
            "key should be lowercase hex, got: {key}"
        );
    }
}
