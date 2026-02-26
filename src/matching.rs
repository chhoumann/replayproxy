use std::{borrow::Cow, collections::HashSet};

use serde_json::Value;
use serde_json_path::JsonPath;
use sha2::{Digest as _, Sha256};

use crate::config::{QueryMatchMode, RouteMatchConfig};

const QUERY_NORM_FINGERPRINT_PREFIX: &str = "h1|";
const QUERY_PARAM_FINGERPRINT_LEN: usize = 64;

#[derive(Debug)]
pub enum MatchKeyError {
    InvalidJsonBody(serde_json::Error),
    InvalidJsonPath {
        expression: String,
        source: serde_json_path::ParseError,
    },
    SerializeJsonNode {
        expression: String,
        source: serde_json::Error,
    },
}

impl MatchKeyError {
    pub(crate) fn kind(&self) -> &'static str {
        match self {
            Self::InvalidJsonBody(_) => "invalid_json_body",
            Self::InvalidJsonPath { .. } => "invalid_json_path",
            Self::SerializeJsonNode { .. } => "serialize_json_node",
        }
    }
}

impl std::fmt::Display for MatchKeyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidJsonBody(_) => write!(f, "parse request body as JSON for matching"),
            Self::InvalidJsonPath { .. } => write!(f, "parse JSONPath expression for matching"),
            Self::SerializeJsonNode { .. } => {
                write!(f, "serialize JSONPath result for matching")
            }
        }
    }
}

impl std::error::Error for MatchKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidJsonBody(source) => Some(source),
            Self::InvalidJsonPath { source, .. } => Some(source),
            Self::SerializeJsonNode { source, .. } => Some(source),
        }
    }
}

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
/// - `body`: raw bytes as received (or selected JSONPath values when `body_json` is configured)
pub fn compute_match_key(
    route_match: Option<&RouteMatchConfig>,
    method: &hyper::Method,
    uri: &hyper::Uri,
    headers: &hyper::HeaderMap,
    body: &[u8],
) -> Result<String, MatchKeyError> {
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

    if match_cfg.body_json.is_empty() {
        hash_tagged_bytes(&mut hasher, b"body", body);
    } else {
        hash_json_fields(&mut hasher, &match_cfg.body_json, body)?;
    }

    let digest = hasher.finalize();
    Ok(hex_encode(&digest))
}

#[derive(Debug, Clone)]
struct EffectiveMatchConfig {
    method: bool,
    path: bool,
    query: QueryMatchMode,
    headers_include_lc: HashSet<String>,
    headers_ignore_lc: HashSet<String>,
    headers_enabled: bool,
    body_json: Vec<String>,
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
            body_json: Vec::new(),
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
        body_json: route_match.body_json.clone(),
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

pub(crate) fn query_param_count(query: Option<&str>) -> usize {
    query
        .map(|query| {
            query
                .split('&')
                .filter(|segment| !segment.is_empty())
                .count()
        })
        .unwrap_or(0)
}

pub(crate) fn stored_query_norm_param_count(stored_query_norm: &str) -> usize {
    if let Some(query_fingerprints) = stored_query_norm.strip_prefix(QUERY_NORM_FINGERPRINT_PREFIX)
    {
        return query_param_count(Some(query_fingerprints));
    }
    query_param_count(Some(stored_query_norm))
}

pub(crate) fn query_param_fingerprint_counts(query: Option<&str>) -> Vec<(String, usize)> {
    let mut grouped: Vec<(String, usize)> = Vec::new();
    for (name, value) in query_params_sorted(query) {
        let fingerprint = query_param_fingerprint(name, value);
        if let Some((prev_fingerprint, count)) = grouped.last_mut()
            && prev_fingerprint == &fingerprint
        {
            *count += 1;
        } else {
            grouped.push((fingerprint, 1));
        }
    }
    grouped
}

pub(crate) fn stored_query_norm_fingerprints(stored_query_norm: &str) -> Vec<String> {
    let normalized = normalize_stored_query_norm_to_fingerprint(stored_query_norm);
    let Some(segments) = normalized.strip_prefix(QUERY_NORM_FINGERPRINT_PREFIX) else {
        return Vec::new();
    };
    if segments.is_empty() {
        return Vec::new();
    }
    segments
        .split('&')
        .filter(|segment| !segment.is_empty())
        .map(str::to_owned)
        .collect()
}

fn normalized_query_from_sorted(sorted: &[(&str, &str)]) -> String {
    let mut normalized = String::new();
    for (idx, (name, value)) in sorted.iter().enumerate() {
        if idx > 0 {
            normalized.push('&');
        }
        normalized.push_str(name);
        normalized.push('=');
        normalized.push_str(value);
    }
    normalized
}

fn query_param_fingerprint(name: &str, value: &str) -> String {
    let mut hasher = Sha256::new();
    hash_len_prefixed(&mut hasher, b"query_param_fingerprint_v1");
    hash_len_prefixed(&mut hasher, name.as_bytes());
    hash_len_prefixed(&mut hasher, value.as_bytes());
    let digest = hasher.finalize();
    hex_encode(&digest)
}

fn is_query_param_fingerprint_segment(segment: &str) -> bool {
    segment.len() == QUERY_PARAM_FINGERPRINT_LEN
        && segment.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn normalized_query_fingerprint_from_segments(segments: &[&str]) -> String {
    let mut normalized = String::from(QUERY_NORM_FINGERPRINT_PREFIX);
    for (idx, segment) in segments.iter().enumerate() {
        if idx > 0 {
            normalized.push('&');
        }
        normalized.push_str(segment);
    }
    normalized
}

fn normalized_query_fingerprint_from_sorted(sorted: &[(&str, &str)]) -> String {
    let digests: Vec<String> = sorted
        .iter()
        .map(|(name, value)| query_param_fingerprint(name, value))
        .collect();
    let digest_segments: Vec<&str> = digests.iter().map(String::as_str).collect();
    normalized_query_fingerprint_from_segments(&digest_segments)
}

fn append_subset_query_candidates<'a>(
    grouped: &[(&'a str, &'a str, usize)],
    group_idx: usize,
    current: &mut Vec<(&'a str, &'a str)>,
    out: &mut Vec<String>,
) {
    if group_idx == grouped.len() {
        out.push(normalized_query_from_sorted(current));
        return;
    }

    let (name, value, count) = grouped[group_idx];
    for selected in 0..=count {
        for _ in 0..selected {
            current.push((name, value));
        }
        append_subset_query_candidates(grouped, group_idx + 1, current, out);
        for _ in 0..selected {
            current.pop();
        }
    }
}

fn append_subset_query_fingerprint_candidates<'a>(
    grouped: &'a [(String, usize)],
    group_idx: usize,
    current: &mut Vec<&'a str>,
    out: &mut Vec<String>,
) {
    if group_idx == grouped.len() {
        out.push(normalized_query_fingerprint_from_segments(
            current.as_slice(),
        ));
        return;
    }

    let (digest, count) = (&grouped[group_idx].0, grouped[group_idx].1);
    for selected in 0..=count {
        for _ in 0..selected {
            current.push(digest.as_str());
        }
        append_subset_query_fingerprint_candidates(grouped, group_idx + 1, current, out);
        for _ in 0..selected {
            current.pop();
        }
    }
}

fn grouped_query_params<'a>(sorted: Vec<(&'a str, &'a str)>) -> Vec<(&'a str, &'a str, usize)> {
    let mut grouped = Vec::new();
    for (name, value) in sorted {
        if let Some((prev_name, prev_value, prev_count)) = grouped.last_mut()
            && *prev_name == name
            && *prev_value == value
        {
            *prev_count += 1;
        } else {
            grouped.push((name, value, 1usize));
        }
    }
    grouped
}

fn subset_query_candidate_count(grouped: &[(&str, &str, usize)], limit: usize) -> Option<usize> {
    let mut candidate_count = 1usize;
    for (_, _, multiplicity) in grouped {
        let factor = multiplicity.checked_add(1)?;
        candidate_count = candidate_count.checked_mul(factor)?;
        if candidate_count > limit {
            return None;
        }
    }
    Some(candidate_count)
}

#[derive(Debug, Clone, Default)]
pub(crate) struct ParsedSubsetQuery<'a> {
    sorted: Vec<(&'a str, &'a str)>,
    query_param_fingerprints: Vec<String>,
}

impl<'a> ParsedSubsetQuery<'a> {
    pub(crate) fn from_query(query: Option<&'a str>) -> Self {
        let sorted = query_params_sorted(query);
        let query_param_fingerprints = sorted
            .iter()
            .map(|(name, value)| query_param_fingerprint(name, value))
            .collect();
        Self {
            sorted,
            query_param_fingerprints,
        }
    }
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn normalized_query(query: Option<&str>) -> String {
    normalized_query_from_sorted(&query_params_sorted(query))
}

pub(crate) fn normalized_query_fingerprint(query: Option<&str>) -> String {
    normalized_query_fingerprint_from_sorted(&query_params_sorted(query))
}

pub(crate) fn normalize_stored_query_norm_to_fingerprint(stored_query_norm: &str) -> String {
    if let Some(query_fingerprints) = stored_query_norm.strip_prefix(QUERY_NORM_FINGERPRINT_PREFIX)
    {
        if query_fingerprints.is_empty() {
            return QUERY_NORM_FINGERPRINT_PREFIX.to_owned();
        }

        let mut normalized = String::from(QUERY_NORM_FINGERPRINT_PREFIX);
        for (idx, segment) in query_fingerprints.split('&').enumerate() {
            if !is_query_param_fingerprint_segment(segment) {
                return normalized_query_fingerprint(Some(stored_query_norm));
            }
            if idx > 0 {
                normalized.push('&');
            }
            normalized.push_str(&segment.to_ascii_lowercase());
        }
        return normalized;
    }

    normalized_query_fingerprint(Some(stored_query_norm))
}

#[cfg_attr(not(test), allow(dead_code))]
pub(crate) fn subset_query_candidate_normalizations_with_limit(
    query: Option<&str>,
    max_candidates: usize,
) -> Option<Vec<String>> {
    let sorted = query_params_sorted(query);
    if sorted.is_empty() {
        return (max_candidates >= 1).then_some(vec![String::new()]);
    }

    let grouped = grouped_query_params(sorted);
    let candidate_count = subset_query_candidate_count(&grouped, max_candidates)?;

    let mut out = Vec::with_capacity(candidate_count);
    let mut current = Vec::new();
    append_subset_query_candidates(&grouped, 0, &mut current, &mut out);
    Some(out)
}

pub(crate) fn subset_query_candidate_fingerprints_with_limit(
    query: Option<&str>,
    max_candidates: usize,
) -> Option<Vec<String>> {
    let sorted = query_params_sorted(query);
    if sorted.is_empty() {
        return (max_candidates >= 1).then_some(vec![QUERY_NORM_FINGERPRINT_PREFIX.to_owned()]);
    }

    let grouped = grouped_query_params(sorted);
    let candidate_count = subset_query_candidate_count(&grouped, max_candidates)?;

    let grouped_digests: Vec<(String, usize)> = grouped
        .iter()
        .map(|(name, value, multiplicity)| (query_param_fingerprint(name, value), *multiplicity))
        .collect();
    let mut out = Vec::with_capacity(candidate_count);
    let mut current = Vec::new();
    append_subset_query_fingerprint_candidates(&grouped_digests, 0, &mut current, &mut out);
    Some(out)
}

#[cfg_attr(not(test), allow(dead_code))]
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
        QueryMatchMode::Subset => subset_query_matches_parsed_request(
            recorded_query,
            &ParsedSubsetQuery::from_query(request_query),
        ),
    }
}

pub(crate) fn subset_query_matches_parsed_request(
    recorded_query: Option<&str>,
    request_query: &ParsedSubsetQuery<'_>,
) -> bool {
    subset_query_matches_sorted(
        &query_params_sorted(recorded_query),
        request_query.sorted.as_slice(),
    )
}

pub(crate) fn subset_normalized_query_matches_parsed_request(
    recorded_query_norm: Option<&str>,
    request_query: &ParsedSubsetQuery<'_>,
) -> bool {
    subset_normalized_query_matches_sorted_or_fallback(recorded_query_norm, request_query)
}

fn subset_normalized_query_matches_sorted_or_fallback(
    recorded_query_norm: Option<&str>,
    request_query: &ParsedSubsetQuery<'_>,
) -> bool {
    let Some(recorded_query_norm) = recorded_query_norm else {
        return true;
    };

    if let Some(required_query_fingerprints) =
        recorded_query_norm.strip_prefix(QUERY_NORM_FINGERPRINT_PREFIX)
    {
        return subset_query_fingerprint_matches_parsed_request(
            required_query_fingerprints,
            request_query.query_param_fingerprints.as_slice(),
        );
    }

    subset_legacy_normalized_query_matches_sorted_or_fallback(
        recorded_query_norm,
        request_query.sorted.as_slice(),
    )
}

fn subset_query_fingerprint_matches_parsed_request(
    required_query_fingerprints: &str,
    candidate_query_fingerprints: &[String],
) -> bool {
    let mut candidate_idx = 0usize;
    if required_query_fingerprints.is_empty() {
        return true;
    }

    for required in required_query_fingerprints.split('&') {
        if !is_query_param_fingerprint_segment(required) {
            return false;
        }
        while candidate_idx < candidate_query_fingerprints.len()
            && !candidate_query_fingerprints[candidate_idx].eq_ignore_ascii_case(required)
        {
            candidate_idx += 1;
        }
        if candidate_idx == candidate_query_fingerprints.len() {
            return false;
        }
        candidate_idx += 1;
    }
    true
}

fn subset_legacy_normalized_query_matches_sorted_or_fallback(
    recorded_query_norm: &str,
    candidate: &[(&str, &str)],
) -> bool {
    let mut candidate_idx = 0usize;
    let mut previous_required = None;

    for segment in recorded_query_norm.split('&') {
        if segment.is_empty() {
            continue;
        }

        let mut parts = segment.splitn(2, '=');
        let required = (
            parts.next().unwrap_or_default(),
            parts.next().unwrap_or_default(),
        );

        if previous_required.is_some_and(|previous| required < previous) {
            return subset_query_matches_sorted(
                &query_params_sorted(Some(recorded_query_norm)),
                candidate,
            );
        }
        previous_required = Some(required);

        while candidate_idx < candidate.len() && candidate[candidate_idx] < required {
            candidate_idx += 1;
        }
        if candidate_idx == candidate.len() || candidate[candidate_idx] != required {
            return false;
        }
        candidate_idx += 1;
    }

    true
}

fn subset_query_matches_sorted(required: &[(&str, &str)], candidate: &[(&str, &str)]) -> bool {
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

fn hash_json_fields(
    hasher: &mut Sha256,
    body_json_paths: &[String],
    body: &[u8],
) -> Result<(), MatchKeyError> {
    let json: Value = serde_json::from_slice(body).map_err(MatchKeyError::InvalidJsonBody)?;

    hash_len_prefixed(hasher, b"body_json");
    hash_len_prefixed(hasher, body_json_paths.len().to_string().as_bytes());

    for expression in body_json_paths {
        let path =
            JsonPath::parse(expression).map_err(|source| MatchKeyError::InvalidJsonPath {
                expression: expression.clone(),
                source,
            })?;
        let values = path.query(&json).all();

        hash_len_prefixed(hasher, expression.as_bytes());
        hash_len_prefixed(hasher, values.len().to_string().as_bytes());
        for value in values {
            let encoded =
                serde_json::to_vec(value).map_err(|source| MatchKeyError::SerializeJsonNode {
                    expression: expression.clone(),
                    source,
                })?;
            hash_len_prefixed(hasher, &encoded);
        }
    }

    Ok(())
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
    use std::time::Instant;

    use super::{
        MatchKeyError, ParsedSubsetQuery, compute_match_key,
        normalize_stored_query_norm_to_fingerprint, normalized_query, normalized_query_fingerprint,
        query_param_count, query_params_match, stored_query_norm_param_count,
        subset_normalized_query_matches_parsed_request,
        subset_query_candidate_fingerprints_with_limit,
        subset_query_candidate_normalizations_with_limit, subset_query_matches_parsed_request,
    };
    use crate::config::{QueryMatchMode, RouteMatchConfig};
    use serde_json::Value;
    use serde_json_path::JsonPath;

    fn key(
        route_match: Option<&RouteMatchConfig>,
        method: &hyper::Method,
        uri: &hyper::Uri,
        headers: &hyper::HeaderMap,
        body: &[u8],
    ) -> String {
        compute_match_key(route_match, method, uri, headers, body).expect("match key should hash")
    }

    #[test]
    fn match_key_ignores_authority_and_scheme() {
        let method = hyper::Method::POST;
        let a: hyper::Uri = "http://127.0.0.1:1/api/hello?x=1".parse().unwrap();
        let b: hyper::Uri = "https://example.com/api/hello?x=1".parse().unwrap();
        let body = br#"{"a":1}"#;

        assert_eq!(
            key(None, &method, &a, &hyper::HeaderMap::new(), body),
            key(None, &method, &b, &hyper::HeaderMap::new(), body)
        );
    }

    #[test]
    fn match_key_sorts_query_params() {
        let method = hyper::Method::GET;
        let a: hyper::Uri = "http://example.com/api/hello?b=2&a=1&a=0".parse().unwrap();
        let b: hyper::Uri = "http://example.com/api/hello?a=0&a=1&b=2".parse().unwrap();

        assert_eq!(
            key(None, &method, &a, &hyper::HeaderMap::new(), b""),
            key(None, &method, &b, &hyper::HeaderMap::new(), b"")
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
            key(Some(&route_match), &method, &uri, &a, b""),
            key(Some(&route_match), &method, &uri, &b, b"")
        );
    }

    #[test]
    fn match_key_ignores_unselected_headers_when_allowlist_is_set() {
        let route_match: crate::config::RouteMatchConfig = toml::from_str(
            r#"
method = true
path = true
headers = ["X-A"]
"#,
        )
        .unwrap();

        let method = hyper::Method::GET;
        let uri: hyper::Uri = "http://example.com/api/hello".parse().unwrap();

        let mut a = hyper::HeaderMap::new();
        a.insert("X-A", hyper::header::HeaderValue::from_static("1"));
        a.insert(
            "X-Request-Id",
            hyper::header::HeaderValue::from_static("aaa"),
        );

        let mut b = hyper::HeaderMap::new();
        b.insert("x-a", hyper::header::HeaderValue::from_static("1"));
        b.insert(
            "x-request-id",
            hyper::header::HeaderValue::from_static("bbb"),
        );

        assert_eq!(
            key(Some(&route_match), &method, &uri, &a, b""),
            key(Some(&route_match), &method, &uri, &b, b"")
        );
    }

    #[test]
    fn match_key_changes_when_selected_header_is_missing() {
        let route_match: crate::config::RouteMatchConfig = toml::from_str(
            r#"
method = true
path = true
headers = ["X-A", "X-B"]
"#,
        )
        .unwrap();

        let method = hyper::Method::GET;
        let uri: hyper::Uri = "http://example.com/api/hello".parse().unwrap();

        let mut with_b = hyper::HeaderMap::new();
        with_b.insert("X-A", hyper::header::HeaderValue::from_static("1"));
        with_b.insert("X-B", hyper::header::HeaderValue::from_static("2"));

        let mut missing_b = hyper::HeaderMap::new();
        missing_b.insert("X-A", hyper::header::HeaderValue::from_static("1"));

        assert_ne!(
            key(Some(&route_match), &method, &uri, &with_b, b""),
            key(Some(&route_match), &method, &uri, &missing_b, b"")
        );
    }

    #[test]
    fn match_key_ignores_explicitly_ignored_headers() {
        let route_match: crate::config::RouteMatchConfig = toml::from_str(
            r#"
method = true
path = true
headers_ignore = ["Date", "X-Request-Id"]
"#,
        )
        .unwrap();

        let method = hyper::Method::GET;
        let uri: hyper::Uri = "http://example.com/api/hello".parse().unwrap();

        let mut a = hyper::HeaderMap::new();
        a.insert(
            "accept",
            hyper::header::HeaderValue::from_static("application/json"),
        );
        a.insert(
            "date",
            hyper::header::HeaderValue::from_static("Mon, 01 Jan 2024 00:00:00 GMT"),
        );
        a.insert(
            "x-request-id",
            hyper::header::HeaderValue::from_static("req-a"),
        );

        let mut b = hyper::HeaderMap::new();
        b.insert(
            "Accept",
            hyper::header::HeaderValue::from_static("application/json"),
        );
        b.insert(
            "Date",
            hyper::header::HeaderValue::from_static("Tue, 02 Jan 2024 00:00:00 GMT"),
        );
        b.insert(
            "X-Request-Id",
            hyper::header::HeaderValue::from_static("req-b"),
        );

        assert_eq!(
            key(Some(&route_match), &method, &uri, &a, b""),
            key(Some(&route_match), &method, &uri, &b, b"")
        );
    }

    #[test]
    fn match_key_changes_when_body_changes() {
        let method = hyper::Method::POST;
        let uri: hyper::Uri = "http://example.com/api/hello?x=1".parse().unwrap();
        let headers = hyper::HeaderMap::new();

        assert_ne!(
            key(None, &method, &uri, &headers, b"a"),
            key(None, &method, &uri, &headers, b"b")
        );
    }

    #[test]
    fn match_key_empty_body_is_stable() {
        let method = hyper::Method::POST;
        let uri: hyper::Uri = "http://example.com/api/hello".parse().unwrap();
        let headers = hyper::HeaderMap::new();
        let body = b"";

        let first = key(None, &method, &uri, &headers, body);
        let second = key(None, &method, &uri, &headers, body);

        assert_eq!(first, second, "empty body should hash deterministically");
    }

    #[test]
    fn match_key_large_body_detects_byte_changes() {
        let method = hyper::Method::POST;
        let uri: hyper::Uri = "http://example.com/api/large".parse().unwrap();
        let headers = hyper::HeaderMap::new();

        let base_body = vec![0xff_u8; 1_000_000];
        let mut variant_body = base_body.clone();
        variant_body[base_body.len() / 2] ^= 0x01;

        assert_eq!(
            key(None, &method, &uri, &headers, &base_body),
            key(None, &method, &uri, &headers, &base_body),
            "re-hashing the same large body should remain stable"
        );
        assert_ne!(
            key(None, &method, &uri, &headers, &base_body),
            key(None, &method, &uri, &headers, &variant_body),
            "single-byte change in large body must change the key"
        );
    }

    #[test]
    fn match_key_changes_when_query_changes_in_exact_mode() {
        let method = hyper::Method::GET;
        let headers = hyper::HeaderMap::new();
        let a: hyper::Uri = "http://example.com/api/hello?x=1".parse().unwrap();
        let b: hyper::Uri = "http://example.com/api/hello?x=2".parse().unwrap();

        assert_ne!(
            key(None, &method, &a, &headers, b""),
            key(None, &method, &b, &headers, b"")
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
            key(Some(&route_match), &method, &a, &headers, b""),
            key(Some(&route_match), &method, &b, &headers, b"")
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
            key(Some(&route_match), &method, &a, &headers, b""),
            key(Some(&route_match), &method, &b, &headers, b"")
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
    fn parsed_subset_query_matcher_matches_direct_subset_api() {
        let request_query = Some("c=3&a=1&b=2&a=1");
        let parsed = ParsedSubsetQuery::from_query(request_query);

        let cases = [
            (None, true),
            (Some("a=1"), true),
            (Some("a=1&a=1&b=2"), true),
            (Some("a=1&a=1&a=1"), false),
            (Some("d=4"), false),
        ];

        for (recorded_query, expected) in cases {
            assert_eq!(
                subset_query_matches_parsed_request(recorded_query, &parsed),
                expected
            );
            assert_eq!(
                query_params_match(QueryMatchMode::Subset, recorded_query, request_query),
                expected
            );
        }
    }

    #[test]
    fn normalized_subset_query_matcher_matches_legacy_subset_api() {
        let request_query = Some("c=3&a=1&b=2&a=1");
        let parsed = ParsedSubsetQuery::from_query(request_query);

        let cases = [
            (None, true),
            (Some("a=1"), true),
            (Some("a=1&a=1&b=2"), true),
            (Some("a=1&a=1&a=1"), false),
            (Some("d=4"), false),
            // Unsorted recorded input should preserve legacy behavior via fallback.
            (Some("b=2&a=1"), true),
        ];

        for (recorded_query_norm, expected) in cases {
            assert_eq!(
                subset_normalized_query_matches_parsed_request(recorded_query_norm, &parsed),
                expected
            );
            assert_eq!(
                subset_query_matches_parsed_request(recorded_query_norm, &parsed),
                expected
            );
        }
    }

    #[test]
    fn normalized_subset_query_matcher_supports_fingerprint_format() {
        let request_query = Some("c=3&a=1&b=2&a=1");
        let parsed = ParsedSubsetQuery::from_query(request_query);

        let cases = [
            (normalize_stored_query_norm_to_fingerprint(""), true),
            (normalize_stored_query_norm_to_fingerprint("a=1"), true),
            (
                normalize_stored_query_norm_to_fingerprint("a=1&a=1&b=2"),
                true,
            ),
            (
                normalize_stored_query_norm_to_fingerprint("a=1&a=1&a=1"),
                false,
            ),
            (normalize_stored_query_norm_to_fingerprint("d=4"), false),
        ];

        for (recorded_query_norm, expected) in cases {
            assert_eq!(
                subset_normalized_query_matches_parsed_request(Some(&recorded_query_norm), &parsed),
                expected
            );
        }
    }

    #[test]
    #[ignore = "benchmark-style profiling; run explicitly with --ignored --nocapture"]
    fn perf_normalized_subset_query_matcher_vs_legacy_sorting() {
        let request_query = Some("a=1&a=1&b=2&c=3&d=4&e=5&f=6&g=7&h=8&i=9&j=10&k=11&l=12");
        let parsed = ParsedSubsetQuery::from_query(request_query);
        let iterations = std::env::var("REPLAYPROXY_PERF_MATCHING_ITERS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .filter(|value| *value > 0)
            .unwrap_or(300);

        let mut recorded_queries: Vec<String> = (0..2_000)
            .map(|idx| format!("a=1&a=1&bucket={}&c=3&g=7&token={idx}", idx % 64))
            .collect();
        *recorded_queries.last_mut().unwrap() =
            "a=1&a=1&b=2&c=3&d=4&e=5&f=6&g=7&h=8&i=9&j=10&k=11&l=12".to_owned();
        let recorded_query_fingerprints: Vec<String> = recorded_queries
            .iter()
            .map(|recorded_query| normalize_stored_query_norm_to_fingerprint(recorded_query))
            .collect();

        let legacy_started = Instant::now();
        let mut legacy_matches = 0usize;
        for _ in 0..iterations {
            for recorded_query in &recorded_queries {
                if subset_query_matches_parsed_request(Some(recorded_query.as_str()), &parsed) {
                    legacy_matches += 1;
                }
            }
        }
        let legacy_elapsed = legacy_started.elapsed();

        let optimized_started = Instant::now();
        let mut optimized_matches = 0usize;
        for _ in 0..iterations {
            for recorded_query in &recorded_query_fingerprints {
                if subset_normalized_query_matches_parsed_request(
                    Some(recorded_query.as_str()),
                    &parsed,
                ) {
                    optimized_matches += 1;
                }
            }
        }
        let optimized_elapsed = optimized_started.elapsed();

        assert_eq!(legacy_matches, optimized_matches);

        let legacy_ms = legacy_elapsed.as_secs_f64() * 1_000.0;
        let optimized_ms = optimized_elapsed.as_secs_f64() * 1_000.0;
        let speedup = legacy_ms / optimized_ms.max(f64::EPSILON);
        eprintln!(
            "perf_subset_matching legacy_ms={legacy_ms:.2} optimized_ms={optimized_ms:.2} speedup={speedup:.2}x iterations={} dataset={}",
            iterations,
            recorded_queries.len(),
        );
    }

    #[test]
    fn normalized_query_is_sorted_and_stable() {
        assert_eq!(normalized_query(Some("b=2&a=1&&a")), "a=&a=1&b=2");
        assert_eq!(normalized_query(Some("a&b=2&a=1")), "a=&a=1&b=2");
    }

    #[test]
    fn normalized_query_fingerprint_obscures_raw_values() {
        let fingerprint = normalized_query_fingerprint(Some("token=secret&a=1"));
        assert!(fingerprint.starts_with("h1|"));
        assert!(!fingerprint.contains("token"));
        assert!(!fingerprint.contains("secret"));
        assert!(!fingerprint.contains("a=1"));
    }

    #[test]
    fn subset_query_candidate_normalizations_cover_multiplicity() {
        let mut actual =
            subset_query_candidate_normalizations_with_limit(Some("b=2&a=1&a=1"), usize::MAX)
                .unwrap();
        actual.sort_unstable();

        let mut expected = vec![
            "".to_owned(),
            "a=1".to_owned(),
            "a=1&a=1".to_owned(),
            "b=2".to_owned(),
            "a=1&b=2".to_owned(),
            "a=1&a=1&b=2".to_owned(),
        ];
        expected.sort_unstable();

        assert_eq!(actual, expected);
    }

    #[test]
    fn subset_query_candidate_normalizations_with_limit_returns_none_when_limit_exceeded() {
        assert!(subset_query_candidate_normalizations_with_limit(Some("a=1&b=2&c=3"), 7).is_none());
    }

    #[test]
    fn subset_query_candidate_normalizations_with_limit_allows_exact_limit() {
        let mut actual =
            subset_query_candidate_normalizations_with_limit(Some("a=1&b=2&c=3"), 8).unwrap();
        actual.sort_unstable();

        let mut expected = vec![
            "".to_owned(),
            "a=1".to_owned(),
            "b=2".to_owned(),
            "c=3".to_owned(),
            "a=1&b=2".to_owned(),
            "a=1&c=3".to_owned(),
            "b=2&c=3".to_owned(),
            "a=1&b=2&c=3".to_owned(),
        ];
        expected.sort_unstable();

        assert_eq!(actual, expected);
    }

    #[test]
    fn subset_query_candidate_fingerprints_cover_multiplicity() {
        let mut actual =
            subset_query_candidate_fingerprints_with_limit(Some("b=2&a=1&a=1"), usize::MAX)
                .unwrap();
        actual.sort_unstable();

        let mut expected = vec![
            normalize_stored_query_norm_to_fingerprint(""),
            normalize_stored_query_norm_to_fingerprint("a=1"),
            normalize_stored_query_norm_to_fingerprint("a=1&a=1"),
            normalize_stored_query_norm_to_fingerprint("b=2"),
            normalize_stored_query_norm_to_fingerprint("a=1&b=2"),
            normalize_stored_query_norm_to_fingerprint("a=1&a=1&b=2"),
        ];
        expected.sort_unstable();

        assert_eq!(actual, expected);
    }

    #[test]
    fn query_param_count_ignores_empty_segments() {
        assert_eq!(query_param_count(None), 0);
        assert_eq!(query_param_count(Some("")), 0);
        assert_eq!(query_param_count(Some("&&a=1&&b=2&")), 2);
    }

    #[test]
    fn stored_query_norm_param_count_supports_fingerprint_and_legacy_formats() {
        assert_eq!(stored_query_norm_param_count("a=1&b=2"), 2);
        assert_eq!(
            stored_query_norm_param_count(&normalized_query_fingerprint(Some("a=1&b=2&c=3"))),
            3
        );
    }

    #[test]
    fn match_key_respects_disabled_method_dimension() {
        let route_match: crate::config::RouteMatchConfig =
            toml::from_str("method = false\n").unwrap();

        let uri: hyper::Uri = "http://example.com/api/hello?x=1".parse().unwrap();
        let headers = hyper::HeaderMap::new();

        assert_eq!(
            key(Some(&route_match), &hyper::Method::GET, &uri, &headers, b""),
            key(
                Some(&route_match),
                &hyper::Method::POST,
                &uri,
                &headers,
                b""
            )
        );
    }

    #[test]
    fn body_json_matching_ignores_unselected_fields() {
        let route_match: RouteMatchConfig = toml::from_str(
            r#"
body_json = ["$.model", "$.messages[*].role"]
"#,
        )
        .unwrap();

        let method = hyper::Method::POST;
        let uri: hyper::Uri = "http://example.com/api/hello".parse().unwrap();
        let headers = hyper::HeaderMap::new();
        let a = br#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"a"}],"temperature":0.2}"#;
        let b = br#"{"model":"gpt-4o-mini","messages":[{"role":"user","content":"b"}],"temperature":0.9}"#;

        assert_eq!(
            key(Some(&route_match), &method, &uri, &headers, a),
            key(Some(&route_match), &method, &uri, &headers, b)
        );
    }

    #[test]
    fn body_json_matching_tracks_nested_array_changes() {
        let route_match: RouteMatchConfig = toml::from_str(
            r#"
body_json = ["$.payload.items[*].id"]
"#,
        )
        .unwrap();

        let method = hyper::Method::POST;
        let uri: hyper::Uri = "http://example.com/api/hello".parse().unwrap();
        let headers = hyper::HeaderMap::new();
        let a = br#"{"payload":{"items":[{"id":1},{"id":2}]}}"#;
        let b = br#"{"payload":{"items":[{"id":1},{"id":3}]}}"#;

        assert_ne!(
            key(Some(&route_match), &method, &uri, &headers, a),
            key(Some(&route_match), &method, &uri, &headers, b)
        );
    }

    #[test]
    fn body_json_matching_returns_error_for_invalid_json() {
        let route_match: RouteMatchConfig = toml::from_str(
            r#"
body_json = ["$.model"]
"#,
        )
        .unwrap();

        let err = compute_match_key(
            Some(&route_match),
            &hyper::Method::POST,
            &"http://example.com/api/hello".parse().unwrap(),
            &hyper::HeaderMap::new(),
            br#"{"model":"gpt-4o-mini""#,
        )
        .unwrap_err();

        assert!(matches!(err, MatchKeyError::InvalidJsonBody(_)));
        assert!(err.to_string().contains("parse request body as JSON"));
    }

    #[test]
    fn body_json_matching_returns_error_for_invalid_jsonpath() {
        let route_match: RouteMatchConfig = toml::from_str(
            r#"
body_json = ["$["]
"#,
        )
        .unwrap();

        let err = compute_match_key(
            Some(&route_match),
            &hyper::Method::POST,
            &"http://example.com/api/hello".parse().unwrap(),
            &hyper::HeaderMap::new(),
            br#"{"model":"gpt-4o-mini"}"#,
        )
        .unwrap_err();

        assert!(matches!(err, MatchKeyError::InvalidJsonPath { .. }));
        assert!(err.to_string().contains("parse JSONPath expression"));
    }

    #[test]
    fn match_key_error_messages_do_not_include_sensitive_inputs() {
        let secret = "sk-live-super-secret";
        let invalid_body = format!(r#"{{"token":"{secret}""#);
        let route_match: RouteMatchConfig = toml::from_str(
            r#"
body_json = ["$.token"]
"#,
        )
        .unwrap();
        let body_err = compute_match_key(
            Some(&route_match),
            &hyper::Method::POST,
            &"http://example.com/api/hello".parse().unwrap(),
            &hyper::HeaderMap::new(),
            invalid_body.as_bytes(),
        )
        .unwrap_err();
        assert_eq!(body_err.kind(), "invalid_json_body");
        assert!(!body_err.to_string().contains(secret));

        let path_err = MatchKeyError::InvalidJsonPath {
            expression: format!("$['{secret}']"),
            source: JsonPath::parse("$[").unwrap_err(),
        };
        assert_eq!(path_err.kind(), "invalid_json_path");
        assert!(!path_err.to_string().contains(secret));

        let serialize_err = MatchKeyError::SerializeJsonNode {
            expression: format!("$['{secret}']"),
            source: serde_json::from_str::<Value>("not-json").unwrap_err(),
        };
        assert_eq!(serialize_err.kind(), "serialize_json_node");
        assert!(!serialize_err.to_string().contains(secret));
    }

    #[test]
    fn match_key_is_lowercase_hex_sha256() {
        let key = key(
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
