#![no_std]

#[cfg(feature = "user")]
extern crate alloc;
#[cfg(feature = "user")]
use alloc::{string::String, vec::Vec};

/// This is a syscall event.
///
/// This structure is how we expect to pass syscall data
/// from kernelspace to userspace via the ring buffer
/// and is thus shared by both kernelspace and userspace.
///
/// arg0, arg1, arg2 are raw pointer values
/// TODO: expand to support more arguments.
/// phase is 0 = enter, 1 = exit
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RawSyscallEvent {
    pub ktime_ns: u64,
    pub pid: u32,
    pub tid: u32,
    pub sysno: i32,
    pub arg0: u64, // raw pointer
    pub arg1: u64, // raw pointer
    pub arg2: u64, // raw pointer
    pub phase: u8, // 0=enter, 1=exit
    pub _pad: [u8; 7],
}

#[cfg(feature = "user")]
#[derive(Debug, Clone, Default)]
pub enum SyscallEnrichment {
    #[default]
    None,
    Exec {
        filename: String,
        argv: Vec<String>,
        envp: Vec<String>,
        dirfd: Option<i32>, // for execveat
        flags: Option<i32>, // for execveat
    },
    Open {
        pathname: String,
        flags: u32,
        mode: u32,
    },
    Clone {
        flags: u64,
        flags_decoded: Vec<String>,
        stack_ptr: Option<u64>,
        parent_tid_ptr: Option<u64>,
        child_tid_ptr: Option<u64>,
        tls_ptr: Option<u64>, // for clone3
    },
    Exit {
        status: i32,
        is_group: bool, // true for exit_group, false for exit
    },
    Wait {
        pid: i32,
        status_ptr: Option<u64>,
        options: u32,
        options_decoded: Vec<String>,
        rusage_ptr: Option<u64>, // for wait4
    },
    Kill {
        pid: i32,
        signal: i32,
        signal_name: String,
        is_thread: bool,         // true for tkill/tgkill, false for kill
        target_tid: Option<i32>, // for tgkill
    },
    ProcessInfo {
        result: u32,
        info_type: String, // "pid", "ppid", "tid", "uid", etc.
    },
    Memory {
        addr: u64,
        length: Option<u64>,
        prot: Option<i32>,
        prot_decoded: Vec<String>,
        flags: Option<i32>,
        flags_decoded: Vec<String>,
    },
    FileIo {
        fd: i32,
        buffer_ptr: Option<u64>,
        count: Option<u64>,
        offset: Option<u64>,
        pathname: Option<String>, // for openat
        flags: Option<i32>,
        mode: Option<u32>,
    },
}

/// Enriched syscall with userspace context and human-readable information
#[cfg(feature = "user")]
#[derive(Debug, Clone)]
pub struct EnrichedSyscall {
    // Raw kernel data
    pub raw: RawSyscallEvent,

    // Syscall identification
    pub syscall_name: String,
    pub syscall_enum: Option<Aarch64Syscalls>,

    // Enriched data (populated in userspace)
    pub enrichment: SyscallEnrichment,
}

#[cfg(feature = "user")]
impl EnrichedSyscall {
    /// Create a new enriched syscall from raw data
    pub fn new(raw: RawSyscallEvent) -> Self {
        let syscall_enum = Aarch64Syscalls::from_sysno(raw.sysno);
        let syscall_name = syscall_enum
            .map(|s| s.name().to_string())
            .unwrap_or_else(|| format!("syscall_{}", raw.sysno));

        Self {
            raw,
            syscall_name,
            syscall_enum,
            enrichment: SyscallEnrichment::None,
        }
    }

    /// Check if this syscall should be enriched (is process-related)
    pub fn should_enrich(&self) -> bool {
        self.syscall_enum
            .map(|s| s.is_process_related())
            .unwrap_or(false)
    }

    /// Get the phase as human-readable string
    pub fn phase_name(&self) -> &'static str {
        match self.raw.phase {
            PHASE_ENTER => "enter",
            PHASE_EXIT => "exit",
            PHASE_TASK_EXIT => "task_exit",
            _ => "unknown",
        }
    }
}

/// Phases for ProcEvent::phase
pub const PHASE_ENTER: u8 = 0;
pub const PHASE_EXIT: u8 = 1;
pub const PHASE_TASK_EXIT: u8 = 2;

/// ProcEvent is a process related event.
#[repr(C)]
#[derive(Copy, Clone)]
pub struct ProcEvent {
    // kernel monotonic timestamp
    pub ts_ns: u64,
    // task (thread) ID and thread group id
    pub pid: u32,
    pub tgid: u32,
    // syscall number (x86_64). For sched_exit this will be 0
    pub sysno: u32, // 0 = sys_enter, 1 = sys_exit, 2 = sched_process_exit
    pub phase: u8,
    pub _pad: [u8; 3],
}

/// scope modes (shared so userspace and kernelspace agree)
pub const MODE_ALL: u32 = 0;
pub const MODE_CGROUP: u32 = 0;

/// ARM64/AArch64 syscall numbers for process-related syscalls
/// Based on include/uapi/asm-generic/unistd.h from Linux kernel
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(i32)]
pub enum Aarch64Syscalls {
    // Process management
    Exit = 93,
    ExitGroup = 94,
    Waitid = 95,
    Clone = 220,
    Execve = 221,
    Wait4 = 260,
    Execveat = 281,
    Clone3 = 435,

    // Signal management
    Kill = 129,
    Tkill = 130,
    Tgkill = 131,

    // Process info
    GetPid = 172,
    GetPpid = 173,
    GetTid = 178,
    GetUid = 174,
    GetEuid = 175,
    GetGid = 176,
    GetEgid = 177,

    // Process control
    SetPgid = 154,
    GetPgid = 155,
    GetSid = 156,
    SetSid = 157,
    Prctl = 167,

    // Memory management (process-related)
    Brk = 214,
    Mmap = 222,
    Munmap = 215,
    Mprotect = 226,

    // File operations (commonly used by processes)
    Openat = 56,
    Close = 57,
    Read = 63,
    Write = 64,

    // Other important syscalls
    Ioctl = 29,
    Ptrace = 117,
}

impl Aarch64Syscalls {
    /// Convert from syscall number to enum variant
    pub fn from_sysno(sysno: i32) -> Option<Self> {
        match sysno {
            93 => Some(Self::Exit),
            94 => Some(Self::ExitGroup),
            95 => Some(Self::Waitid),
            220 => Some(Self::Clone),
            221 => Some(Self::Execve),
            260 => Some(Self::Wait4),
            281 => Some(Self::Execveat),
            435 => Some(Self::Clone3),
            129 => Some(Self::Kill),
            130 => Some(Self::Tkill),
            131 => Some(Self::Tgkill),
            172 => Some(Self::GetPid),
            173 => Some(Self::GetPpid),
            178 => Some(Self::GetTid),
            174 => Some(Self::GetUid),
            175 => Some(Self::GetEuid),
            176 => Some(Self::GetGid),
            177 => Some(Self::GetEgid),
            154 => Some(Self::SetPgid),
            155 => Some(Self::GetPgid),
            156 => Some(Self::GetSid),
            157 => Some(Self::SetSid),
            167 => Some(Self::Prctl),
            214 => Some(Self::Brk),
            222 => Some(Self::Mmap),
            215 => Some(Self::Munmap),
            226 => Some(Self::Mprotect),
            56 => Some(Self::Openat),
            57 => Some(Self::Close),
            63 => Some(Self::Read),
            64 => Some(Self::Write),
            29 => Some(Self::Ioctl),
            117 => Some(Self::Ptrace),
            _ => None,
        }
    }

    /// Get human-readable name for the syscall
    pub fn name(&self) -> &'static str {
        match self {
            Self::Exit => "exit",
            Self::ExitGroup => "exit_group",
            Self::Waitid => "waitid",
            Self::Clone => "clone",
            Self::Execve => "execve",
            Self::Wait4 => "wait4",
            Self::Execveat => "execveat",
            Self::Clone3 => "clone3",
            Self::Kill => "kill",
            Self::Tkill => "tkill",
            Self::Tgkill => "tgkill",
            Self::GetPid => "getpid",
            Self::GetPpid => "getppid",
            Self::GetTid => "gettid",
            Self::GetUid => "getuid",
            Self::GetEuid => "geteuid",
            Self::GetGid => "getgid",
            Self::GetEgid => "getegid",
            Self::SetPgid => "setpgid",
            Self::GetPgid => "getpgid",
            Self::GetSid => "getsid",
            Self::SetSid => "setsid",
            Self::Prctl => "prctl",
            Self::Brk => "brk",
            Self::Mmap => "mmap",
            Self::Munmap => "munmap",
            Self::Mprotect => "mprotect",
            Self::Openat => "openat",
            Self::Close => "close",
            Self::Read => "read",
            Self::Write => "write",
            Self::Ioctl => "ioctl",
            Self::Ptrace => "ptrace",
        }
    }

    /// Check if this syscall is process-related
    pub fn is_process_related(&self) -> bool {
        matches!(
            self,
            Self::Exit
                | Self::ExitGroup
                | Self::Waitid
                | Self::Clone
                | Self::Execve
                | Self::Wait4
                | Self::Execveat
                | Self::Clone3
                | Self::Kill
                | Self::Tkill
                | Self::Tgkill
                | Self::GetPid
                | Self::GetPpid
                | Self::GetTid
                | Self::GetUid
                | Self::GetEuid
                | Self::GetGid
                | Self::GetEgid
                | Self::SetPgid
                | Self::GetPgid
                | Self::GetSid
                | Self::SetSid
                | Self::Prctl
        )
    }
}
