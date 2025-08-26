// Universal syscall representation
pub mod syscall_event;
// Domain-specific event types
pub mod process_event;
pub mod domain_event;

// Re-export commonly used types
pub use syscall_event::{SyscallEvent, SyscallCategory, ProcessSyscall, FileIoSyscall, NetworkSyscall, CredentialSyscall, MemorySyscall, SignalSyscall};
pub use process_event::{ProcessEvent, ProcessEventType};
pub use domain_event::DomainEvent;
