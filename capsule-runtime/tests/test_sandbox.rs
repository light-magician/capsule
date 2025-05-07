use capsule_runtime::sandbox::apply_seccomp;
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::Command;

#[test]
/// Verifies that our “echo-only” seccomp profile will trap attempts
/// to fork or clone a shell process.
///
/// This test does the following:
/// 1. Launches `/bin/sh -c "echo hi"` under a child process.
/// 2. In the child’s pre-exec phase, installs the echo-only seccomp filter
///    via `apply_seccomp_echo_only()`.  That profile allows only the minimal
///    syscalls needed by a plain `echo` (read, write, exit, etc.).
/// 3. Since `/bin/sh` internally calls `fork`/`clone` (not permitted),
///    the kernel delivers `SIGSYS` and kills the child.
/// 4. We assert that `status.signal()` returns `Some(libc::SIGSYS)`,
///    proving that seccomp blocked the forbidden syscall.
///
/// If the filter were too permissive (or not installed), the shell
/// would survive and we’d see `status.code() == Some(0)` instead.
fn sandbox_blocks_shell_fork() {
    let mut cmd = Command::new("/bin/sh");

    // pre_exec is unsafe, so call it inside an unsafe block
    unsafe {
        cmd.pre_exec(|| {
            apply_seccomp()
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
        });
    }

    let status = cmd.status().expect("failed to spawn /bin/sh");
    assert_eq!(
        status.signal(),
        Some(libc::SIGSYS),
        "expected SIGSYS from seccomp, got {:?}",
        status
    );
}
