use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
/// End-to-end Merkle-chain logging test:
///
/// 1. **Clean slate:** remove any existing `test_run.log` so prior runs don’t interfere.
/// 2. **Instrumented run:** invoke `capsule echo test` with `CAPSULE_LOG="test_run.log"`, expecting success.
/// 3. **Log sanity check:** read `test_run.log`, split into lines, and assert at least two entries
///    (an `InvocationStart` and an `InvocationEnd`).
/// 4. **Tamper:** modify the very first record’s `prev_hash` to an invalid value (`deadbeef…`).
/// 5. **Verify:** invoke `capsule verify` pointing at the same log file; it must fail with a
///    “failed hash” error indicating the chain is broken at entry #0.
///
/// This ensures our Blake3-chained audit log is (a) being written, and (b) actually detects tampering.
#[test]
fn invocation_logs_chain() {
    // 1) ensure a clean slate
    let log_file = "test_run.log";
    let _ = fs::remove_file(log_file);

    // 2) run the CLI with our custom log
    let mut cmd = Command::cargo_bin("capsule").unwrap();
    cmd.env("CAPSULE_LOG", log_file)
        .arg("echo")
        .arg("test")
        .assert()
        .success();

    // 3) inspect the new log
    let log = fs::read_to_string(log_file).unwrap();
    let lines: Vec<_> = log.lines().collect();
    assert!(
        lines.len() >= 2,
        "expected at least start+end, got {}",
        lines.len()
    );

    // 4) tamper the first entry…
    let mut tampered = String::new();
    for (i, &line) in lines.iter().enumerate() {
        if i == 0 {
            let broken = line.replacen("\"prev_hash\":\"", "\"prev_hash\":\"deadbeef", 1);
            tampered.push_str(&broken);
        } else {
            tampered.push_str(line);
        }
        tampered.push('\n');
    }
    fs::write(log_file, &tampered).unwrap();

    // 5) verify should now fail
    let mut verify = Command::cargo_bin("capsule").unwrap();
    verify
        .env("CAPSULE_LOG", log_file)
        .arg("verify")
        .assert()
        .failure()
        .stderr(predicate::str::contains("failed hash"));
}
