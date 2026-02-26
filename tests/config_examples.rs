use std::{fs, path::PathBuf};

use replayproxy::config::Config;

#[test]
fn bundled_example_configs_parse_and_include_match_plus_redaction() {
    let examples_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples");
    let entries = fs::read_dir(&examples_dir).expect("examples directory should exist");

    let mut parsed_count = 0usize;
    let mut has_match_plus_redaction = false;

    for entry in entries {
        let entry = entry.expect("directory entry should be readable");
        let path = entry.path();
        if path.extension().and_then(|ext| ext.to_str()) != Some("toml") {
            continue;
        }

        let config = Config::from_path(&path)
            .unwrap_or_else(|err| panic!("example config {} should parse: {err}", path.display()));
        parsed_count += 1;
        if config
            .routes
            .iter()
            .any(|route| route.match_.is_some() && route.redact.is_some())
        {
            has_match_plus_redaction = true;
        }
    }

    assert!(
        parsed_count >= 1,
        "expected at least one TOML example config"
    );
    assert!(
        has_match_plus_redaction,
        "expected at least one example route with both `[routes.match]` and `[routes.redact]`"
    );
}
