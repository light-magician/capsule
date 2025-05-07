/// simple policy: to only allow a specific set of commands
pub struct Policy;
/// defines a minimal policy of accepted commands
/// Facilitates "is this command permitted at all?"
///     before diving into the syscalls that underly it
impl Policy {
    /// returns true if `cmd` is exactly "echo"
    pub fn validate_call(cmd: &str, _args: &[&str]) -> bool {
        cmd == "echo"
    }
}
