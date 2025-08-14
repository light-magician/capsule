#![no_std]

/// This is a syscall event.
///
/// This structure is how we expect to pass syscall data
/// from kernelspace to userspace via the ring buffer
/// and is thus shared by both kernelspace and userspace.
#[repr(C)]
pub struct Event {
    pub ktime_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub sysno: i32,
    pub arg0: u64,
    pub arg1: u64,
    pub arg2: u64,
}
