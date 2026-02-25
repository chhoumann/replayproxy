use sha2::{Digest as _, Sha256};

pub fn compute_match_key(method: &hyper::Method, uri: &hyper::Uri, body: &[u8]) -> String {
    let mut hasher = Sha256::new();

    hasher.update(method.as_str().as_bytes());
    hasher.update(b"\n");

    if let Some(path_and_query) = uri.path_and_query() {
        hasher.update(path_and_query.as_str().as_bytes());
    } else {
        hasher.update(uri.path().as_bytes());
    }
    hasher.update(b"\n");

    hasher.update(body);

    let digest = hasher.finalize();
    hex_encode(&digest)
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
    use super::compute_match_key;

    #[test]
    fn match_key_ignores_authority_and_scheme() {
        let method = hyper::Method::POST;
        let a: hyper::Uri = "http://127.0.0.1:1/api/hello?x=1".parse().unwrap();
        let b: hyper::Uri = "https://example.com/api/hello?x=1".parse().unwrap();
        let body = br#"{"a":1}"#;

        assert_eq!(
            compute_match_key(&method, &a, body),
            compute_match_key(&method, &b, body)
        );
    }
}
