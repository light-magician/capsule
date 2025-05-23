/// TODO: everything in the tmp directory is "temporary"
/// I don't think that it is persisted beyond sessions
/// would be better to place critical logs in the
// this is the process ID associated with the daemon
pub const PID_FILE: &str = "/tmp/capsule.pid";
// here is where the daemon will output info about its status
pub const OUT_LOG: &str = "/tmp/capsule.out";
// daemon can send info about errors that occur here
pub const ERR_LOG: &str = "/tmp/capsule.err";
// this socket is where the daemon will liesten for incoming reqs
pub const SOCKET_PATH: &str = "/tmp/capsule.sock";
// the socket associated with the logging, different from that of daemon
pub const LOGGER_SOCKET_PATH: &str = "/tmp/capsule-logger.sock";
// command audits
pub const AUDIT_LOG: &str = "/tmp/audit.log";
