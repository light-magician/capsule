/// TODO: everything in the tmp directory is "temporary"
/// this dir will have to be updated to var/ or some other
/// permanent directory in the future
pub const SYSLOG_PATH: &str = "/tmp/capsule_syscalls.log";
/// path to capsule events log file
/// an event is a summary of some window of syscalls
pub const EVENTLOG_PATH: &str = "/tmp/capsule_events.log";
