#![no_std]

#[repr(C)]
pub struct ExecEvent {
    pub pid: u32,
    pub tgid: u32,
    pub ts_ns: u64,
    pub sys_id: i64,
    pub comm: [u8; 16],
}
