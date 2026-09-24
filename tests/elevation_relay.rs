//! End-to-end checks for the --elevate relay. These run the real binary: the
//! caller is started with --elevate, it relaunches the same command through the
//! shell, and the child's output has to come back through the named pipes
//! together with its exit code.
//!
//! DISK_CLEANER_ELEVATION_VERB=open replaces the UAC consent prompt with a plain
//! launch, so the launch and relay path is exercised without a prompt (or admin
//! rights). Everything except the consent prompt itself is the production path.
#![cfg(windows)]

use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_disk-cleaner"))
}

/// A private directory per test run; the CLI keeps its plan and index files
/// relative to the working directory, so tests must not share one.
fn scratch(name: &str) -> PathBuf {
    let unique = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    let dir = std::env::temp_dir().join(format!(
        "disk-cleaner-it-{}-{name}-{unique}",
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create scratch directory");
    dir
}

#[test]
fn elevated_child_reports_through_the_relay() {
    let cwd = scratch("relay");
    let output = Command::new(binary())
        .args(["doctor", "--json", "--elevate"])
        .current_dir(&cwd)
        .env("DISK_CLEANER_ELEVATION_VERB", "open")
        .output()
        .expect("run disk-cleaner");
    let stdout = String::from_utf8(output.stdout).expect("relayed stdout is UTF-8");
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(
        output.status.success(),
        "relay run failed ({:?}): {stderr}",
        output.status.code()
    );
    let value: serde_json::Value =
        serde_json::from_str(&stdout).expect("stdout carries exactly the child's JSON");
    assert_eq!(
        value["cwd"].as_str().unwrap_or_default(),
        cwd.to_string_lossy(),
        "the elevated child has to run in the caller's directory"
    );
    // Progress and warnings belong to stderr: an agent parses stdout.
    assert!(stderr.contains("请求管理员权限"), "stderr: {stderr}");
    assert!(!stdout.contains("请求管理员权限"), "stdout: {stdout}");
    // Without a consent prompt the child keeps whatever token the caller has, so
    // an unelevated runner gets the warning and an elevated runner (CI) does not.
    match value["administrator"].as_bool() {
        Some(false) => assert!(stderr.contains("没有拿到管理员权限"), "stderr: {stderr}"),
        Some(true) => assert!(!stderr.contains("没有拿到管理员权限"), "stderr: {stderr}"),
        other => panic!("administrator is not a boolean: {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&cwd);
}

#[test]
fn child_arguments_with_spaces_and_unicode_survive_the_relaunch() {
    let cwd = scratch("quote");
    let scope = cwd.join("a b 中文 Δ");
    std::fs::create_dir_all(&scope).expect("create scope");
    std::fs::write(scope.join("hello 世界.txt"), vec![b'x'; 4096]).expect("write sample file");
    let output = Command::new(binary())
        .args(["scan"])
        .arg(&scope)
        .args([
            "--backend",
            "fs",
            "--no-save",
            "--json",
            "--min-size",
            "0",
            "--elevate",
        ])
        .current_dir(&cwd)
        .env("DISK_CLEANER_ELEVATION_VERB", "open")
        .output()
        .expect("run disk-cleaner");
    let stdout = String::from_utf8(output.stdout).expect("relayed stdout is UTF-8");
    assert!(
        output.status.success(),
        "relay run failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let value: serde_json::Value = serde_json::from_str(&stdout).expect("relayed JSON");
    let reported = value["scope"].as_str().unwrap_or_default();
    assert!(
        reported.contains("a b 中文 Δ"),
        "scope lost its quoting: {reported}"
    );
    let rows = value["rows"].as_array().expect("rows");
    assert!(
        rows.iter()
            .filter_map(|row| row["name"].as_str())
            .any(|name| name.contains("hello 世界.txt")),
        "the sample file is missing from the relayed report: {rows:?}"
    );
    let _ = std::fs::remove_dir_all(&cwd);
}

#[test]
fn child_failures_come_back_with_the_childs_exit_code() {
    let cwd = scratch("failure");
    let missing = cwd.join("missing-scope");
    let output = Command::new(binary())
        .arg("scan")
        .arg(&missing)
        .arg("--elevate")
        .current_dir(&cwd)
        .env("DISK_CLEANER_ELEVATION_VERB", "open")
        .output()
        .expect("run disk-cleaner");
    assert_eq!(
        output.status.code(),
        Some(1),
        "the caller adopts the child's code"
    );
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    assert!(stderr.contains("ERROR"), "stderr: {stderr}");
    assert!(stderr.contains("missing-scope"), "stderr: {stderr}");
    let _ = std::fs::remove_dir_all(&cwd);
}

#[test]
fn a_child_that_cannot_open_the_pipes_falls_back_to_files() {
    let cwd = scratch("fallback");
    let fallback = cwd.join("fallback");
    let output = Command::new(binary())
        .args([
            "--elevation-stdout",
            r"\\.\pipe\disk-cleaner-test-missing-stdout",
            "--elevation-stderr",
            r"\\.\pipe\disk-cleaner-test-missing-stderr",
        ])
        .arg("--elevation-fallback")
        .arg(&fallback)
        .args(["doctor", "--json"])
        .current_dir(&cwd)
        .output()
        .expect("run disk-cleaner");
    assert!(
        output.status.success(),
        "child failed: {:?}",
        output.status.code()
    );
    assert!(
        output.stdout.is_empty(),
        "the fallback must not write to the console"
    );
    let stdout = std::fs::read_to_string(fallback.join("stdout.txt")).expect("fallback stdout");
    assert!(stdout.contains("\"administrator\""), "stdout: {stdout}");
    let stderr = std::fs::read_to_string(fallback.join("stderr.txt")).expect("fallback stderr");
    assert!(stderr.contains("命名管道"), "stderr: {stderr}");
    let _ = std::fs::remove_dir_all(&cwd);
}
