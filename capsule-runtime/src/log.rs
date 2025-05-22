use chrono::Local;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::os::unix::net::UnixListener;

use crate::constants::{self, OUT_LOG};
/// Daemon-side RPC logger: bind socket, accept requests, append JSON to log
pub fn start_rpc_logger() -> io::Result<()> {
    // TODO: think about best practices for location for this
    // remove stale socket if present
    let _ = fs::remove_file(constants::LOGGER_SOCKET_PATH);

    let listener = UnixListener::bind(constants::LOGGER_SOCKET_PATH)?;
    for conn in listener.incoming() {
        match conn {
            Ok(mut sock) => {
                let mut buf = String::new();
                // read until client closes write-half
                if sock.read_to_string(&mut buf).is_ok() {
                    let mut file = OpenOptions::new().create(true).append(true).open(OUT_LOG)?;
                    writeln!(file, "{}", buf.trim_end()).ok();
                }
            }
            Err(e) => eprintln!("logger accept error: {}", e),
        }
    }
    Ok(())
}
