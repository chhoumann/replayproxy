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

#[test]
fn llm_example_config_references_existing_lua_transform_scripts() {
    let examples_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("examples");
    let llm_config_path = examples_dir.join("replayproxy.llm-redacted.toml");
    let config = Config::from_path(&llm_config_path).unwrap_or_else(|err| {
        panic!(
            "example config {} should parse: {err}",
            llm_config_path.display()
        )
    });
    let route = config
        .routes
        .iter()
        .find(|route| route.name.as_deref() == Some("openai-chat"))
        .expect("llm example should contain openai-chat route");
    let transform = route
        .transform
        .as_ref()
        .expect("openai-chat route should include [routes.transform]");

    let on_request = transform
        .on_request
        .as_deref()
        .expect("openai-chat route should configure on_request script");
    let on_response = transform
        .on_response
        .as_deref()
        .expect("openai-chat route should configure on_response script");
    assert_eq!(on_request, "scripts/llm_on_request.lua");
    assert_eq!(on_response, "scripts/llm_on_response.lua");

    let on_request_path = llm_config_path
        .parent()
        .expect("example config should have parent directory")
        .join(on_request);
    let on_response_path = llm_config_path
        .parent()
        .expect("example config should have parent directory")
        .join(on_response);
    assert!(
        on_request_path.is_file(),
        "on_request script should exist: {}",
        on_request_path.display()
    );
    assert!(
        on_response_path.is_file(),
        "on_response script should exist: {}",
        on_response_path.display()
    );
}
