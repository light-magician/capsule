use assert_cmd::Command;
use std::fs;

#[test]
fn echo_allowed_and_logged() {
    // Invoke the CLI
    let mut cmd = Command::cargo_bin("capsule-runtime").unwrap();
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
