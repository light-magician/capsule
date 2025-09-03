pub mod arch;

/// Arch-agnostic semantic syscall identifiers (process-first set)
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Sys {
    // Process mgmt
    Exit,
    ExitGroup,
    Waitid,
    Wait4,
    Clone,
    Clone3,
    Fork,  // x86_64 only
    Vfork, // x86_64 only
    Execve,
    Execveat,

    // Signals / control / info
    Kill,
    Tkill,
    Tgkill,
    Prctl,

    // Cred / ids (add more as needed)
    Setuid,
    Setgid,
    GetPid,
    GetPpid,
    GetTid,
    GetUid,
    GetEuid,
    GetGid,
    GetEgid,

    // Fallback
    Unknown(i32),
}

impl Sys {
    #[inline]
    pub fn name(self) -> &'static str {
        use Sys::*;
        match self {
            Exit => "exit",
            ExitGroup => "exit_group",
            Waitid => "waitid",
            Wait4 => "wait4",
            Clone => "clone",
            Clone3 => "clone3",
            Fork => "fork",
            Vfork => "vfork",
            Execve => "execve",
            Execveat => "execveat",
            Kill => "kill",
            Tkill => "tkill",
            Tgkill => "tgkill",
            Prctl => "prctl",
            Setuid => "setuid",
            Setgid => "setgid",
            GetPid => "getpid",
            GetPpid => "getppid",
            GetTid => "gettid",
            GetUid => "getuid",
            GetEuid => "geteuid",
            GetGid => "getgid",
            GetEgid => "getegid",
            Unknown(_) => "unknown",
        }
    }

    #[inline]
    pub fn is_process_related(self) -> bool {
        use Sys::*;
        matches!(
            self,
            Exit | ExitGroup
                | Waitid
                | Wait4
                | Clone
                | Clone3
                | Fork
                | Vfork
                | Execve
                | Execveat
                | Kill
                | Tkill
                | Tgkill
                | Prctl
                | GetPid
                | GetPpid
                | GetTid
                | GetUid
                | GetEuid
                | GetGid
                | GetEgid
                | Setuid
                | Setgid
        )
    }
}

/// Resolve an arch + numeric `sysno` to the semantic `Sys`.
#[inline]
pub fn resolve_sys(arch: arch::Arch, sysno: i32) -> Sys {
    arch.map_sysno(sysno).unwrap_or(Sys::Unknown(sysno))
}

