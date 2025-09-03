pub mod aarch64;
pub mod x86_64;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Arch {
    Aarch64,
    X86_64,
    Unknown,
}

impl Arch {
    pub const SUPPORTED: &'static [Arch] = &[Arch::Aarch64, Arch::X86_64];

    #[inline]
    pub fn current() -> Arch {
        #[cfg(target_arch = "aarch64")]
        { Arch::Aarch64 }
        #[cfg(target_arch = "x86_64")]
        { Arch::X86_64 }
        #[cfg(not(any(target_arch = "aarch64", target_arch = "x86_64")))]
        { Arch::Unknown }
    }

    #[inline]
    pub fn map_sysno(self, sysno: i32) -> Option<crate::syscalls::Sys> {
        match self {
            Arch::Aarch64 => crate::syscalls::arch::aarch64::map_sysno(sysno),
            Arch::X86_64 => crate::syscalls::arch::x86_64::map_sysno(sysno),
            Arch::Unknown => None,
        }
    }
}
