use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;

/// These are tests of the policy layer.
///
/// The policy layer defines what commands are allowed at all.
/// Think echo, ls, cat, grep, at this early stage.
/// This is the first line of defence against bad actors or maligned agents.
/// Policy is essentially simple input validation. No deeper than that.

#[test]
fn permitted_cmd_allowed() {
    let log_file = "test_run.log";
    let _ = fs::remove_file(log_file);

    let mut cmd = Command::cargo_bin("capsule").unwrap();
    cmd.env("CAPSULE_LOG", log_file)
        .arg("echo")
        .arg("hello")
        .assert()
        .success()
        .stdout("hello\n");

    let log = fs::read_to_string(log_file).unwrap();
    assert!(
        log.contains("\"cmd\":[\"echo\",\"hello\"]"),
        "audit log did not contain InvocationStart; got:\n{}",
        log
    );
}

#[test]
fn policy_rejects_non_permitted_cmd() {
    let log_file = "test_run.log";
    let _ = fs::remove_file(log_file);

    let mut cmd = Command::cargo_bin("capsule").unwrap();
    cmd.env("CAPSULE_LOG", log_file)
        .arg("ls")
        .arg("-l")
        .assert()
        .failure()
        .stderr(predicate::str::contains("not allowed by policy"));

    let log = fs::read_to_string(log_file).unwrap();
    assert!(
        log.contains("\"type\":\"invocation_end\"") && log.contains("\"status\":1"),
        "log didn’t record policy rejection: got\n{}",
        log
    );
}
