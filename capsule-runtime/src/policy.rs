//! Demo policy: default = EchoOnly (only `echo …` is allowed)

#[derive(Clone, Copy)]
pub enum Policy {
    EchoOnly,
    Unrestricted,
}

impl Policy {
    pub fn from_arg(arg: Option<&str>) -> Self {
        match arg {
            Some("unrestricted") => Policy::Unrestricted,
            _ => Policy::EchoOnly, // default
        }
    }
    pub fn validate(&self, cmd: &str) -> bool {
        match self {
            Policy::Unrestricted => true,
            Policy::EchoOnly => cmd == "echo",
        }
    }
}
