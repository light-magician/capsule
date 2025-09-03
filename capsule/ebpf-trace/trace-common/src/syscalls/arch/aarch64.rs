/// AArch64 syscall numbers for process-related syscalls
/// Based on cat include/uapi/asm-generic/unistd.h from Linux kernel
use crate::syscalls::Sys;
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
    pub fn map_sysno(sysno: i32) -> Option<Self> {
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

// Free-function mapper used by resolve_sys()
#[inline]
pub fn map_sysno(n: i32) -> Option<Sys> {
    Some(match n {
        // Process management
        93 => Sys::Exit,
        94 => Sys::ExitGroup,
        95 => Sys::Waitid,
        220 => Sys::Clone,
        221 => Sys::Execve,
        260 => Sys::Wait4,
        281 => Sys::Execveat,
        435 => Sys::Clone3,

        // Signals
        129 => Sys::Kill,
        130 => Sys::Tkill,
        131 => Sys::Tgkill,

        // IDs / info
        172 => Sys::GetPid,
        173 => Sys::GetPpid,
        178 => Sys::GetTid,
        174 => Sys::GetUid,
        175 => Sys::GetEuid,
        176 => Sys::GetGid,
        177 => Sys::GetEgid,

        // Control
        167 => Sys::Prctl,

        // Cred set
        146 => Sys::Setuid,
        144 => Sys::Setgid,

        _ => return None,
    })
}
