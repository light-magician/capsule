/// simple policy: to only allow a specific set of commands
/// defines a minimal policy of accepted commands
/// Facilitates "is this command permitted at all?"
///     before diving into the syscalls that underly it
use std::path::Path;
pub enum Policy {
    Unrestricted,
    EchoOnly,
    DenyAll,
}

impl Policy {
    /// Build from CLI arg.  Omitted or `"none"` → Unrestricted.
    pub fn from_arg(arg: Option<&str>) -> Self {
        match arg {
            None | Some("none") => Policy::Unrestricted,
            // TODO: later parse JSON/YAML files here.
            _ => Policy::EchoOnly,
        }
    }

    /// Authorise a command line *before* we install seccomp.
    pub fn validate_call(&self, cmd: &str, _args: &[&str]) -> bool {
        match self {
            Policy::Unrestricted => true,
            Policy::EchoOnly => cmd == "echo",
            Policy::DenyAll => false,
        }
    }
}
