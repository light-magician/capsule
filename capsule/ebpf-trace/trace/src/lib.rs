use std::{process::Command, thread, time::Duration};

use anyhow::{anyhow, Result};
use aya::{
    maps::{HashMap as AyaHashMap, MapData, RingBuf},
    programs::{RawTracePoint, TracePoint},
    Ebpf,
};
use trace_common::{Aarch64Syscalls, EnrichedSyscall, RawSyscallEvent, SyscallEnrichment};
use log::{debug, warn};

pub fn remove_locked_mem_limit() -> Result<()> {
    // rlimit bump
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }
    Ok(())
}

pub fn setup_ebpf() -> Result<Ebpf> {
    // load BPF
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/trace"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }
    Ok(ebpf)
}

pub fn attach_tp(ebpf: &mut Ebpf, prog_name: &str, cat: &str, evt: &str) -> Result<()> {
    eprintln!("[attach-tp] {prog_name} -> {cat}:{evt}");
    let prog: &mut TracePoint = ebpf
        .program_mut(prog_name)
        .ok_or_else(|| anyhow!("program not found: {prog_name}"))?
        .try_into()?;
    prog.load()?;
    prog.attach(cat, evt)?;
    Ok(())
}

pub fn attach_raw(ebpf: &mut Ebpf, prog_name: &str, tp_name: &str) -> Result<()> {
    eprintln!("[attach-raw] {prog_name} -> {tp_name}");
    let prog: &mut RawTracePoint = ebpf
        .program_mut(prog_name)
        .ok_or_else(|| anyhow!("program not found: {prog_name}"))?
        .try_into()?;
    prog.load()?;
    prog.attach(tp_name)?;
    Ok(())
}

pub fn attach_tracepoints(ebpf: &mut Ebpf) -> Result<()> {
    // attach programs
    attach_tp(ebpf, "sched_fork", "sched", "sched_process_fork")?;
    attach_tp(ebpf, "sched_exit", "sched", "sched_process_exit")?;
    attach_raw(ebpf, "sys_enter", "sys_enter")?;
    attach_raw(ebpf, "sys_exit", "sys_exit")?;
    Ok(())
}

pub fn connect_ebpf_bridge(ebpf: &mut Ebpf) -> Result<AyaHashMap<&mut MapData, u32, u8>> {
    // open WATCHED_TGIDS
    eprintln!("[map] opening WATCHED_TGIDS");
    let watched_map = ebpf
        .map_mut("WATCHED_TGIDS")
        .ok_or_else(|| anyhow!("map not found: WATCHED_TGIDS"))?;
    let watched: AyaHashMap<_, u32, u8> = AyaHashMap::try_from(watched_map)?;
    Ok(watched)
}

pub fn parse_cmd(cmd_str: &str) -> Command {
    cmd_str
        .split_whitespace()
        .collect::<Vec<&str>>()
        .split_first()
        .map(|(cmd, args)| {
            args.iter().fold(Command::new(cmd), |mut command, &arg| {
                command.arg(arg);
                command
            })
        })
        .expect("empty command string")
}

pub fn execute_cmd_and_seed_cmd_pid(
    cmd_str: &str,
    watched: &mut AyaHashMap<&mut MapData, u32, u8>,
) -> Result<u32> {
    eprintln!("[spawn] launching: {cmd_str}");
    // parse and spawn command
    let child = parse_cmd(&cmd_str).spawn()?;
    // get childs PID
    let child_tgid: u32 = child.id() as u32;
    // Stop ASAP to minimize the pre-seed window
    unsafe {
        libc::kill(child_tgid as i32, libc::SIGSTOP);
    }
    // set child PID for tracking in the kernel bridge
    eprintln!("[seed] child TGID={child_tgid}");
    watched.insert(child_tgid, 1, 0)?;

    // Resume the child
    eprintln!("[resume] SIGCONT -> {child_tgid}");
    unsafe {
        libc::kill(child_tgid as i32, libc::SIGCONT);
    }
    Ok(child_tgid)
}

pub fn verify_child_tracked(
    watched: &mut AyaHashMap<&mut MapData, u32, u8>,
    child_tgid: u32,
) -> Result<()> {
    for i in 0..50 {
        match watched.get(&child_tgid, 0) {
            Ok(_) => {
                eprintln!("[verify] child TGID present in kernel bridge");
                return Ok(());
            }
            Err(aya::maps::MapError::KeyNotFound) => thread::sleep(Duration::from_millis(5)),
            Err(e) => return Err(e.into()),
        }
    }
    Err(anyhow!("failed to find child TGID in 50 iterations"))
}

pub fn connect_events_ringbuf(ebpf: &mut Ebpf) -> Result<RingBuf<&mut MapData>> {
    // open EVENTS ring buffer
    eprintln!("[map] opening EVENTS ring buffer");
    let events_map = ebpf
        .map_mut("EVENTS")
        .ok_or_else(|| anyhow!("map not found: EVENTS"))?;
    let ring_buf = RingBuf::try_from(events_map)?;
    Ok(ring_buf)
}

/// Enrichment function that converts RawSyscallEvent to EnrichedSyscall with lookups
pub fn enrich_syscall(raw: RawSyscallEvent) -> EnrichedSyscall {
    let mut enriched = EnrichedSyscall::new(raw);
    
    // Only enrich process-related syscalls
    if !enriched.should_enrich() {
        return enriched;
    }
    
    // Perform syscall-specific enrichment based on syscall type
    if let Some(syscall_enum) = enriched.syscall_enum {
        enriched.enrichment = match syscall_enum {
            Aarch64Syscalls::Exit => {
                SyscallEnrichment::Exit {
                    status: raw.arg0 as i32,
                    is_group: false,
                }
            }
            Aarch64Syscalls::ExitGroup => {
                SyscallEnrichment::Exit {
                    status: raw.arg0 as i32,
                    is_group: true,
                }
            }
            Aarch64Syscalls::Clone => {
                let flags = raw.arg0;
                SyscallEnrichment::Clone {
                    flags,
                    flags_decoded: decode_clone_flags(flags),
                    stack_ptr: if raw.arg1 != 0 { Some(raw.arg1) } else { None },
                    parent_tid_ptr: if raw.arg2 != 0 { Some(raw.arg2) } else { None },
                    child_tid_ptr: None, // arg3 would be in additional args
                    tls_ptr: None,
                }
            }
            Aarch64Syscalls::Execve => {
                // For now, just mark as exec - memory reading will be added later
                SyscallEnrichment::Exec {
                    filename: format!("<ptr:0x{:x}>", raw.arg0),
                    argv: vec![format!("<argv_ptr:0x{:x}>", raw.arg1)],
                    envp: vec![format!("<envp_ptr:0x{:x}>", raw.arg2)],
                    dirfd: None,
                    flags: None,
                }
            }
            Aarch64Syscalls::Execveat => {
                SyscallEnrichment::Exec {
                    filename: format!("<ptr:0x{:x}>", raw.arg1),
                    argv: vec![format!("<argv_ptr:0x{:x}>", raw.arg2)],
                    envp: vec![], // arg2 in execveat
                    dirfd: Some(raw.arg0 as i32),
                    flags: None, // Would be in additional args
                }
            }
            Aarch64Syscalls::Kill => {
                let signal = raw.arg1 as i32;
                SyscallEnrichment::Kill {
                    pid: raw.arg0 as i32,
                    signal,
                    signal_name: signal_name(signal),
                    is_thread: false,
                    target_tid: None,
                }
            }
            Aarch64Syscalls::Tkill => {
                let signal = raw.arg1 as i32;
                SyscallEnrichment::Kill {
                    pid: raw.arg0 as i32,
                    signal,
                    signal_name: signal_name(signal),
                    is_thread: true,
                    target_tid: None,
                }
            }
            Aarch64Syscalls::Tgkill => {
                let signal = raw.arg2 as i32;
                SyscallEnrichment::Kill {
                    pid: raw.arg0 as i32,
                    signal,
                    signal_name: signal_name(signal),
                    is_thread: true,
                    target_tid: Some(raw.arg1 as i32),
                }
            }
            Aarch64Syscalls::GetPid => {
                SyscallEnrichment::ProcessInfo {
                    result: raw.arg0 as u32,
                    info_type: "pid".to_string(),
                }
            }
            Aarch64Syscalls::GetPpid => {
                SyscallEnrichment::ProcessInfo {
                    result: raw.arg0 as u32,
                    info_type: "ppid".to_string(),
                }
            }
            Aarch64Syscalls::GetTid => {
                SyscallEnrichment::ProcessInfo {
                    result: raw.arg0 as u32,
                    info_type: "tid".to_string(),
                }
            }
            Aarch64Syscalls::Wait4 => {
                SyscallEnrichment::Wait {
                    pid: raw.arg0 as i32,
                    status_ptr: if raw.arg1 != 0 { Some(raw.arg1) } else { None },
                    options: raw.arg2 as u32,
                    options_decoded: decode_wait_options(raw.arg2 as u32),
                    rusage_ptr: None, // Would be in additional args
                }
            }
            Aarch64Syscalls::Waitid => {
                SyscallEnrichment::Wait {
                    pid: raw.arg1 as i32,
                    status_ptr: if raw.arg2 != 0 { Some(raw.arg2) } else { None },
                    options: raw.arg0 as u32, // idtype is in arg0 for waitid
                    options_decoded: vec![format!("idtype={}", raw.arg0)],
                    rusage_ptr: None,
                }
            }
            _ => SyscallEnrichment::None,
        };
    }
    
    enriched
}

/// Decode clone flags into human-readable strings
fn decode_clone_flags(flags: u64) -> Vec<String> {
    let mut decoded = Vec::new();
    
    if flags & 0x00000100 != 0 { decoded.push("CLONE_VM".to_string()); }
    if flags & 0x00000200 != 0 { decoded.push("CLONE_FS".to_string()); }
    if flags & 0x00000400 != 0 { decoded.push("CLONE_FILES".to_string()); }
    if flags & 0x00000800 != 0 { decoded.push("CLONE_SIGHAND".to_string()); }
    if flags & 0x00010000 != 0 { decoded.push("CLONE_THREAD".to_string()); }
    if flags & 0x00004000 != 0 { decoded.push("CLONE_VFORK".to_string()); }
    if flags & 0x00008000 != 0 { decoded.push("CLONE_PARENT".to_string()); }
    
    if decoded.is_empty() {
        decoded.push(format!("0x{:x}", flags));
    }
    
    decoded
}

/// Convert signal number to human-readable name
fn signal_name(signal: i32) -> String {
    match signal {
        1 => "SIGHUP".to_string(),
        2 => "SIGINT".to_string(),
        3 => "SIGQUIT".to_string(),
        9 => "SIGKILL".to_string(),
        15 => "SIGTERM".to_string(),
        17 => "SIGCHLD".to_string(),
        18 => "SIGCONT".to_string(),
        19 => "SIGSTOP".to_string(),
        _ => format!("SIG{}", signal),
    }
}

/// Decode wait options into human-readable strings
fn decode_wait_options(options: u32) -> Vec<String> {
    let mut decoded = Vec::new();
    
    if options & 0x00000001 != 0 { decoded.push("WNOHANG".to_string()); }
    if options & 0x00000002 != 0 { decoded.push("WUNTRACED".to_string()); }
    if options & 0x00000008 != 0 { decoded.push("WCONTINUED".to_string()); }
    
    if decoded.is_empty() && options == 0 {
        decoded.push("0".to_string());
    } else if decoded.is_empty() {
        decoded.push(format!("0x{:x}", options));
    }
    
    decoded
}

#[cfg(test)]
mod tests {
    use super::*;
    use trace_common::{PHASE_ENTER, PHASE_EXIT};
    
    ///NOTE: In these tests, syscall numbers MUST match aarch64 values for proper 
    ///      enum mapping, but other values (PIDs, addresses, etc.) are just for 
    ///      testing data structure transformations
    
    #[test]
    fn test_enrich_exit_syscall() {
        let raw = RawSyscallEvent {
            ktime_ns: 1234567890,
            pid: 1000,
            tid: 1001,
            sysno: 93, // exit on aarch64
            arg0: 42,  // exit status
            arg1: 0,
            arg2: 0,
            phase: PHASE_ENTER,
            _pad: [0; 7],
        };

        let enriched = enrich_syscall(raw);
        
        assert_eq!(enriched.syscall_name, "exit");
        assert_eq!(enriched.syscall_enum, Some(Aarch64Syscalls::Exit));
        
        match enriched.enrichment {
            SyscallEnrichment::Exit { status, is_group } => {
                assert_eq!(status, 42);
                assert_eq!(is_group, false);
            }
            _ => panic!("Expected Exit enrichment"),
        }
    }

    #[test]
    fn test_enrich_clone_syscall() {
        let raw = RawSyscallEvent {
            ktime_ns: 1234567890,
            pid: 1000,
            tid: 1001,
            sysno: 220, // clone on aarch64
            arg0: 0x00000100 | 0x00000200, // CLONE_VM | CLONE_FS
            arg1: 0x7fff12340000, // stack pointer
            arg2: 0x7fff12350000, // parent tid ptr
            phase: PHASE_ENTER,
            _pad: [0; 7],
        };

        let enriched = enrich_syscall(raw);
        
        assert_eq!(enriched.syscall_name, "clone");
        
        match enriched.enrichment {
            SyscallEnrichment::Clone { flags, flags_decoded, stack_ptr, parent_tid_ptr, .. } => {
                assert_eq!(flags, 0x00000100 | 0x00000200);
                assert!(flags_decoded.contains(&"CLONE_VM".to_string()));
                assert!(flags_decoded.contains(&"CLONE_FS".to_string()));
                assert_eq!(stack_ptr, Some(0x7fff12340000));
                assert_eq!(parent_tid_ptr, Some(0x7fff12350000));
            }
            _ => panic!("Expected Clone enrichment"),
        }
    }

    #[test]
    fn test_enrich_kill_syscall() {
        let raw = RawSyscallEvent {
            ktime_ns: 1234567890,
            pid: 1000,
            tid: 1001,
            sysno: 129, // kill on aarch64
            arg0: 1234,  // target pid
            arg1: 9,     // SIGKILL
            arg2: 0,
            phase: PHASE_ENTER,
            _pad: [0; 7],
        };

        let enriched = enrich_syscall(raw);
        
        assert_eq!(enriched.syscall_name, "kill");
        
        match enriched.enrichment {
            SyscallEnrichment::Kill { pid, signal, signal_name, is_thread, target_tid } => {
                assert_eq!(pid, 1234);
                assert_eq!(signal, 9);
                assert_eq!(signal_name, "SIGKILL");
                assert_eq!(is_thread, false);
                assert_eq!(target_tid, None);
            }
            _ => panic!("Expected Kill enrichment"),
        }
    }

    #[test]
    fn test_non_process_syscall_not_enriched() {
        let raw = RawSyscallEvent {
            ktime_ns: 1234567890,
            pid: 1000,
            tid: 1001,
            sysno: 999, // Unknown syscall
            arg0: 1,
            arg1: 2,
            arg2: 3,
            phase: PHASE_ENTER,
            _pad: [0; 7],
        };

        let enriched = enrich_syscall(raw);
        
        assert_eq!(enriched.syscall_name, "syscall_999");
        assert_eq!(enriched.syscall_enum, None);
        
        match enriched.enrichment {
            SyscallEnrichment::None => {},
            _ => panic!("Expected no enrichment for unknown syscall"),
        }
    }

    #[test]
    fn test_decode_clone_flags() {
        let flags = decode_clone_flags(0x00000100 | 0x00000200 | 0x00010000);
        assert!(flags.contains(&"CLONE_VM".to_string()));
        assert!(flags.contains(&"CLONE_FS".to_string()));
        assert!(flags.contains(&"CLONE_THREAD".to_string()));
        assert_eq!(flags.len(), 3);
    }

    #[test]
    fn test_signal_names() {
        assert_eq!(signal_name(9), "SIGKILL");
        assert_eq!(signal_name(15), "SIGTERM");
        assert_eq!(signal_name(2), "SIGINT");
        assert_eq!(signal_name(999), "SIG999");
    }
}
