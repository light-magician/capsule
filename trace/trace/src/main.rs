use anyhow::{anyhow, Result};
use aya::{maps::HashMap as AyaHashMap, programs::TracePoint, Ebpf};
#[rustfmt::skip]
use log::{debug, warn};
use std::{process::Command, thread, time::Duration};

/// helper for attaching to tracepoints
fn attach_tp(ebpf: &mut Ebpf, prog_name: &str, cat: &str, evt: &str) -> Result<()> {
    eprintln!("[attach] {prog_name} -> {cat}:{evt}");
    // FIX: convert &mut Program -> &mut TracePoint via try_into()
    let prog: &mut TracePoint = ebpf
        .program_mut(prog_name)
        .ok_or_else(|| anyhow!("program not found: {prog_name}"))?
        .try_into()?;
    prog.load()?;
    prog.attach(cat, evt)?;
    Ok(())
}

fn main() -> Result<()> {
    env_logger::init();

    // Bump the memlock rlimit (needed for older kernels)
    let rlim = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };
    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlim) };
    if ret != 0 {
        debug!("remove limit on locked memory failed, ret is: {ret}");
    }

    // Load eBPF program from embedded bytes
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/trace"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    // attach all programs (sched first, then raw_syscalls)
    attach_tp(
        &mut ebpf,
        "tp_sched_process_fork",
        "sched",
        "sched_process_fork",
    )?;
    attach_tp(
        &mut ebpf,
        "tp_sched_process_exit",
        "sched",
        "sched_process_exit",
    )?;
    attach_tp(&mut ebpf, "tp_sys_enter_raw", "raw_syscalls", "sys_enter")?;
    attach_tp(&mut ebpf, "tp_sys_exit_raw", "raw_syscalls", "sys_exit")?;

    eprintln!("[map] opening WATCHED_PIDS");

    // FIX: unwrap the Map first, then TryFrom<&mut Map> -> AyaHashMap<&mut MapData, K, V>
    let watched_map = ebpf
        .map_mut("WATCHED_PIDS")
        .ok_or_else(|| anyhow!("map not found: WATCHED_PIDS"))?;
    let mut watched: AyaHashMap<_, u32, u8> = AyaHashMap::try_from(watched_map)?;

    // seed our thread group ID so the fork hook auto-adds the child
    let self_tgid = unsafe { libc::getpid() as u32 };
    eprintln!("[seed] add self tgid={self_tgid} to WATCHED_PIDS");
    watched.insert(self_tgid, 1, 0)?;

    // spawn the target command
    eprintln!("[spawn] launching: ls -la");
    let mut child = Command::new("ls").arg("-la").spawn()?;
    let child_tgid = child.id();
    eprintln!("[spawn] child tgid(pid)={child_tgid}");

    // prove coordination: poll the BPF map until fork hook adds child TGID
    let child_tgid_u32 = child_tgid as u32;
    let mut found = false;
    for i in 0..200 {
        // FIX: aya::maps::HashMap::get returns Result<V, MapError>, not Option
        match watched.get(&child_tgid_u32, 0) {
            Ok(_v) => {
                eprintln!("[verify] child TGID {child_tgid_u32} is present (iteration {i}) ✅");
                found = true;
                break;
            }
            Err(aya::maps::MapError::KeyNotFound) => {
                // not yet present
            }
            Err(e) => return Err(e.into()),
        }
        thread::sleep(Duration::from_millis(10));
    }
    if !found {
        eprintln!("[verify] child TGID {child_tgid_u32} NOT observed within timeout ❌");
        eprintln!("         (sched_process_fork not attached, or map name mismatch)");
    }

    let status = child.wait()?;
    eprintln!("[done] child exited with {status}");
    Ok(())
}
