// tests/log_verification.rs

use capsule_runtime::log::verify;
use capsule_runtime::runtime::run_command;
use std::{fs, path::Path};

#[test]
fn test_audit_log_hash_chain_valid() {
    // 1. Clean up any old state
    let _ = fs::remove_file("capsule.log");

    // 2. Create an (empty) policy file so run_command can find it.
    //    Our Policy impl ignores its contents anyway.
    fs::write("capsule.yaml", "").unwrap();

    // 3. Invoke the “echo hello” through the library
    run_command(
        Path::new("capsule.yaml"),
        vec!["echo".into(), "hello".into()],
    )
    .expect("run_command failed");

    // 4. Sanity: the log file must exist
    let log_path = Path::new("capsule.log");
    assert!(log_path.exists(), "capsule.log was not created");

    // 5. Verify Merkle‐chain integrity
    verify(log_path).expect("hash chain verification failed");
}
