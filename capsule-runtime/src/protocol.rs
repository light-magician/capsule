use byteorder::{BigEndian, ReadBytesExt, WriteBytesExt};
use serde::{Deserialize, Serialize};
use std::io::{self, Read, Write};

/// Client→Daemon request: a command (binary + args) to run.
#[derive(Serialize, Deserialize, Debyg)]
pub struct Request {
    pub cmd: Vec<String>,
}

/// Which stream we’re carrying in a ResponseFrame.
#[derive(Serialize, Deserialize, Debug)]
pub enum Stream {
    Stdout,
    Stderr,
    ExitCode(i32),
}

/// Daemon→Client frames: carries stdout/stderr chunks or exit code (§3).
#[derive(Serialize, Deserialize, Debug)]
pub struct ResponseFrame {
    pub channel: Stream,
    /// `Some(data)` for Stdout/Stderr; `None` for ExitCode.
    pub data: Option<Vec<u8>>,
}

/// Serialize `msg` to JSON, prefix with its BE-u32 length, and write to `writer`.
pub fn write_frame<T: Serialize, W: Write>(writer: &mut W, msg: &T) -> io::Result<()> {
    // Serialize to JSON bytes
    let payload = serde_json::to_vec(msg).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    // Write 4-byte big-endian length
    writer.write_u32::<BigEndian>(payload.len() as u32)?;
    // Write the actual JSON payload
    writer.write_all(&payload)?;
    writer.flush()?;
    Ok(())
}

/// Read a single length-prefixed JSON frame from `reader` and deserialize to T.
pub fn read_frame<R: Read, T: for<'de> Deserialize<'de>>(reader: &mut R) -> io::Result<T> {
    // Read 4-byte big-endian length
    let len = reader.read_u32::<BigEndian>()?;
    let mut buf = vec![0u8; len as usize];
    // Read the JSON payload in full
    reader.read_exact(&mut buf)?;
    // Deserialize from JSON
    let msg = serde_json::from_slice(&buf).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    Ok(msg)
}
