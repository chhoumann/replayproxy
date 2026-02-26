use std::{
    ffi::OsStr,
    fs,
    path::Path,
    process::{Command, Output},
};

use replayproxy::config::Config;
use tempfile::tempdir;

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
fn preset_import_copies_bundled_file_to_home_presets_dir() {
    let sandbox = tempdir().expect("tempdir should be created");
    let project_dir = sandbox.path().join("project");
    let home_dir = sandbox.path().join("home");
    fs::create_dir_all(&project_dir).expect("project dir should be created");
    fs::create_dir_all(&home_dir).expect("home dir should be created");

    let output = run_replayproxy(["preset", "import", "openai"], &project_dir, &home_dir);
    assert_success(&output);

    let imported_path = home_dir
        .join(".replayproxy")
        .join("presets")
        .join("openai.toml");
    assert!(
        imported_path.is_file(),
        "imported preset path should exist: {}",
        imported_path.display()
    );

    let imported_bytes = fs::read(&imported_path).expect("imported preset should be readable");
    let bundled_bytes = &include_bytes!("../presets/openai.toml")[..];
    assert_eq!(imported_bytes.as_slice(), bundled_bytes);

    Config::from_path(&imported_path).expect("imported preset config should parse");
}

#[test]
fn preset_import_overwrites_existing_file() {
    let sandbox = tempdir().expect("tempdir should be created");
    let project_dir = sandbox.path().join("project");
    let home_dir = sandbox.path().join("home");
    fs::create_dir_all(&project_dir).expect("project dir should be created");
    fs::create_dir_all(&home_dir).expect("home dir should be created");

    let first = run_replayproxy(["preset", "import", "anthropic"], &project_dir, &home_dir);
    assert_success(&first);

    let imported_path = home_dir
        .join(".replayproxy")
        .join("presets")
        .join("anthropic.toml");
    fs::write(&imported_path, "not a valid preset").expect("preset file should be writable");

    let second = run_replayproxy(["preset", "import", "anthropic"], &project_dir, &home_dir);
    assert_success(&second);
    assert!(
        String::from_utf8_lossy(&second.stdout).contains("updated existing preset file"),
        "stdout should indicate overwrite\nstdout:\n{}",
        String::from_utf8_lossy(&second.stdout)
    );

    Config::from_path(&imported_path).expect("overwritten preset config should parse");
}

#[test]
fn preset_import_unknown_name_shows_available_presets() {
    let sandbox = tempdir().expect("tempdir should be created");
    let project_dir = sandbox.path().join("project");
    let home_dir = sandbox.path().join("home");
    fs::create_dir_all(&project_dir).expect("project dir should be created");
    fs::create_dir_all(&home_dir).expect("home dir should be created");

    let output = run_replayproxy(
        ["preset", "import", "does-not-exist"],
        &project_dir,
        &home_dir,
    );
    assert!(
        !output.status.success(),
        "expected failure for unknown preset\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("unknown preset `does-not-exist`"),
        "stderr should include unknown preset message\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("available:"),
        "stderr should include available preset names\nstderr:\n{stderr}"
    );
    assert!(
        stderr.contains("openai"),
        "stderr should list bundled presets\nstderr:\n{stderr}"
    );
}

#[test]
fn preset_list_shows_names_and_descriptions() {
    let sandbox = tempdir().expect("tempdir should be created");
    let project_dir = sandbox.path().join("project");
    let home_dir = sandbox.path().join("home");
    fs::create_dir_all(&project_dir).expect("project dir should be created");
    fs::create_dir_all(&home_dir).expect("home dir should be created");

    let output = run_replayproxy(["preset", "list"], &project_dir, &home_dir);
    assert_success(&output);

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("name\tdescription"),
        "stdout should include table header\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains("openai"),
        "stdout should include openai preset\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains("anthropic"),
        "stdout should include anthropic preset\nstdout:\n{stdout}"
    );
}
