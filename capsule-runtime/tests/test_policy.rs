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
    // Invoke the CLI
    let mut cmd = Command::cargo_bin("capsule").unwrap();
    cmd.arg("echo").arg("hello");
    cmd.assert().success().stdout("hello\n");

    // Check that the audit log was written and contains our command
    let log = fs::read_to_string("capsule.log").expect("failed to read capsule.log");
    assert!(
        log.contains("echo hello"),
        "audit log did not contain expected entry; got:\n{}",
        log
    );
}

#[test]
fn policy_rejects_non_permitted_cmd() {
    // attempt to run `ls` → policy should block it before we ever exec()
    let mut cmd = Command::cargo_bin("capsule").unwrap();
    cmd.arg("ls").arg("-l");
    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("not allowed by policy"));

    let log = fs::read_to_string("capsule.log").unwrap();
    assert!(
        log.contains("ERROR: command 'ls' rejected by policy"),
        "log didn’t record policy rejection: got\n{}",
        log
    );
}
