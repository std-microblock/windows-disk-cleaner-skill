use std::{path::Path, process::Command};
fn cli() -> Command {
    Command::new(env!("CARGO_BIN_EXE_disk-cleaner"))
}
#[test]
fn doctor_never_elevates_and_reports_manual_mode() {
    let out = cli().args(["doctor", "--json"]).output().unwrap();
    assert!(out.status.success());
    let json: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(json["elevation"].as_str().unwrap().starts_with("manual:"));
}
#[test]
fn ordinary_scan_reports_time_and_modification_semantics() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("one.txt"), b"one").unwrap();
    let out = cli()
        .arg("scan")
        .arg(dir.path())
        .args([
            "--backend",
            "fs",
            "--no-save",
            "--no-git",
            "--min-size",
            "0",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let j: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert!(j["report_ready_ms"].is_u64());
    assert_eq!(
        j["rows"][0]["modified_semantics"],
        "latest_descendant_file_last_write"
    );
    assert!(j["rows"][0]["modified_utc"].is_string());
    assert_eq!(j["rows"][1]["modified_semantics"], "file_last_write");
    assert_eq!(
        j["rows"][1]["oldest_modified_utc"],
        j["rows"][1]["latest_modified_utc"]
    );
    assert_eq!(
        j["rows"][0]["modified_utc"],
        j["rows"][0]["latest_modified_utc"]
    );
}
#[test]
fn there_is_no_headless_delete_or_yes_flag() {
    for args in [
        &["delete", "C:/example"][..],
        &["show-rm", "--yes"][..],
        &["rm", "--execute", "C:/example"][..],
    ] {
        let out = cli().args(args).output().unwrap();
        assert!(!out.status.success());
    }
}
#[test]
fn rm_only_stages_exact_path() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("precious.txt");
    let plan = dir.path().join("clean-targets.json");
    std::fs::write(&file, b"valuable").unwrap();
    let out = cli()
        .arg("--plan")
        .arg(&plan)
        .args(["rm", "-f"])
        .arg(&file)
        .args(["-reason", "test staging only"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert_eq!(std::fs::read(&file).unwrap(), b"valuable");
    let j: serde_json::Value = serde_json::from_slice(&std::fs::read(plan).unwrap()).unwrap();
    assert_eq!(j["targets"].as_array().unwrap().len(), 1);
}
#[test]
fn no_admin_fast_scan_returns_guidance_without_launching_uac() {
    if disk_cleaner::platform::elevation::is_elevated() {
        return;
    }
    let current = std::env::current_dir().unwrap();
    let volume = disk_cleaner::platform::volume_info(Path::new(&current)).unwrap();
    if !["NTFS", "ReFS"].contains(&volume.filesystem.as_str()) {
        return;
    }
    let out = cli()
        .arg("scan")
        .arg(current)
        .args(["--backend", "auto", "--no-save", "--no-git"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("请 agent 自行"), "{err}");
    assert!(!String::from_utf8_lossy(&out.stdout).contains("fs-enumerate"));
}

#[test]
fn directory_and_folded_rows_report_latest_and_oldest_file_times_not_directory_time() {
    use std::{fs::{File,FileTimes},time::{Duration,SystemTime}};
    let dir=tempfile::tempdir().unwrap();let nested=dir.path().join("nested");std::fs::create_dir(&nested).unwrap();
    let old=dir.path().join("old.txt");let new=nested.join("new.txt");std::fs::write(&old,b"old").unwrap();std::fs::write(&new,b"new").unwrap();
    for (file,seconds) in [(&old,946684800),(&new,1577836800)] {
        File::options().write(true).open(file).unwrap().set_times(FileTimes::new().set_modified(SystemTime::UNIX_EPOCH+Duration::from_secs(seconds))).unwrap();
    }
    let out=cli().arg("scan").arg(dir.path()).args(["--backend","fs","--no-save","--no-git","--min-size","1GiB","--json"]).output().unwrap();
    assert!(out.status.success(),"{}",String::from_utf8_lossy(&out.stderr));
    let j:serde_json::Value=serde_json::from_slice(&out.stdout).unwrap();
    for row in j["rows"].as_array().unwrap(){
        assert_eq!(row["oldest_modified_utc"],"2000-01-01T00:00:00.000Z");
        assert_eq!(row["latest_modified_utc"],"2020-01-01T00:00:00.000Z");
        assert_eq!(row["modified_utc"],row["latest_modified_utc"]);
    }
    assert_eq!(j["rows"][1]["kind"],"folded");
}
