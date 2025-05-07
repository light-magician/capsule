// src/policy.rs
/// A trivial policy: only allow the program named `"echo"`.
pub struct Policy;

impl Policy {
    /// Returns true if `program` == `"echo"`.  All args are ignored.
    pub fn validate(&self, program: &str, _args: &[String]) -> bool {
        program == "echo"
    }
}
