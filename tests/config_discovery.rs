use std::{
    ffi::OsStr,
    fs,
    path::Path,
    process::{Command, Output},
};

use tempfile::tempdir;

fn write_valid_config(path: &Path, storage_path: &Path, listen_port: u16) {
    let config = format!(
        r#"
[proxy]
listen = "127.0.0.1:{listen_port}"

[storage]
path = "{}"
active_session = "default"
"#,
        storage_path.display()
    );
    fs::write(path, config).expect("config should be written");
}

fn run_replayproxy<I, S>(args: I, cwd: &Path, home: &Path) -> Output
where
    I: IntoIterator<Item = S>,
    S: AsRef<OsStr>,
{
    Command::new(env!("CARGO_BIN_EXE_replayproxy"))
        .args(args)
        .env("HOME", home)
        .current_dir(cwd)
        .output()
        .expect("replayproxy command should execute")
}

fn assert_success(output: &Output) {
    assert!(
        output.status.success(),
        "expected success\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn config_discovery_prefers_project_then_home_then_override() {
    let sandbox = tempdir().expect("tempdir should be created");
    let project_dir = sandbox.path().join("project");
    let home_dir = sandbox.path().join("home");
    let storage_dir = sandbox.path().join("storage");
    fs::create_dir_all(&project_dir).expect("project dir should be created");
    fs::create_dir_all(home_dir.join(".replayproxy")).expect("home config dir should be created");
    fs::create_dir_all(&storage_dir).expect("storage dir should be created");

    let project_config = project_dir.join("replayproxy.toml");
    let home_config = home_dir.join(".replayproxy").join("config.toml");
    let override_config = sandbox.path().join("override.toml");

    write_valid_config(&project_config, &storage_dir.join("project"), 4101);
    fs::write(
        &home_config,
        r#"
[proxy]
listen = "127.0.0.1:0"
unknown_key = "invalid"
"#,
    )
    .expect("home config should be written");

    let prefers_project = run_replayproxy(["session", "list"], &project_dir, &home_dir);
    assert_success(&prefers_project);

    fs::remove_file(&project_config).expect("project config should be removed");
    write_valid_config(&home_config, &storage_dir.join("home"), 4102);

    let falls_back_to_home = run_replayproxy(["session", "list"], &project_dir, &home_dir);
    assert_success(&falls_back_to_home);

    fs::write(
        &project_config,
        r#"
[proxy]
listen = "not-an-address"
"#,
    )
    .expect("project config should be rewritten as invalid");
    fs::write(
        &home_config,
        r#"
[proxy]
listen = "also-invalid"
"#,
    )
    .expect("home config should be rewritten as invalid");
    write_valid_config(&override_config, &storage_dir.join("override"), 4103);

    let without_override = run_replayproxy(["session", "list"], &project_dir, &home_dir);
    assert!(
        !without_override.status.success(),
        "expected failure without override\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&without_override.stdout),
        String::from_utf8_lossy(&without_override.stderr)
    );
    assert!(
        String::from_utf8_lossy(&without_override.stderr).contains("project ./replayproxy.toml"),
        "stderr should indicate the project source\nstderr:\n{}",
        String::from_utf8_lossy(&without_override.stderr)
    );

    let with_override = run_replayproxy(
        [
            OsStr::new("session"),
            OsStr::new("--config"),
            override_config.as_os_str(),
            OsStr::new("list"),
        ],
        &project_dir,
        &home_dir,
    );
    assert_success(&with_override);
}
