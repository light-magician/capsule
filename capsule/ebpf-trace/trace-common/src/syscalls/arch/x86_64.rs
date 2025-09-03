//! Placeholder x86_64 map; fill after verification.

use crate::syscalls::Sys;

#[inline]
pub fn map_sysno(_n: i32) -> Option<Sys> {
    None
}

