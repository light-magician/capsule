use chrono::Local;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::net::UnixListener;

/// Daemon-side RPC logger: bind socket, accept requests, append JSON to log
pub fn start_rpc_logger() -> io::Result<()> {
    // TODO: think about best practices for location for this
    let sock_path = "/tmp/capsule-logger.sock";
    // remove stale socket if present
    let _ = fs::remove_file(sock_path);
    let listener = UnixListener::bind(sock_path)?;
    for stream in listener.incoming() {
        if let Ok(mut s) = stream {
            // TODO: likely should not be expandable buf
            let mut buf = Vec::new();
            s.read_to_end(&mut buf)?;
            // TODO: log file might belong in /var/log/capsule.log
            // but capsule will not have those permissions by default
            // will need to think of where to put it, if left in tmp
            // it will be wiped every restart of container
            let ts = Local::now().format("%Y-%m-%d %H:%M:%S");
            let mut logf = OpenOptions::new()
                .create(true)
                .append(true)
                .open("/tmp/capsule.log")?;
            writeln!(logf, "{} (RPC) {}", ts, String::from_utf8_lossy(&buf)).ok();
        }
    }
    Ok(())
}
