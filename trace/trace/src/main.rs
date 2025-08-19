use std::{process::Command, thread, time::Duration};

use anyhow::{anyhow, Result};
use aya::{
    maps::{HashMap as AyaHashMap, MapData},
    programs::{RawTracePoint, TracePoint},
    Ebpf,
};
use log::{debug, warn};

fn remove_locked_mem_limit() -> Result<()> {
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

fn setup_ebpf() -> Result<Ebpf> {
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

fn attach_tp(ebpf: &mut Ebpf, prog_name: &str, cat: &str, evt: &str) -> Result<()> {
    eprintln!("[attach-tp] {prog_name} -> {cat}:{evt}");
    let prog: &mut TracePoint = ebpf
        .program_mut(prog_name)
        .ok_or_else(|| anyhow!("program not found: {prog_name}"))?
        .try_into()?;
    prog.load()?;
    prog.attach(cat, evt)?;
    Ok(())
}

fn attach_raw(ebpf: &mut Ebpf, prog_name: &str, tp_name: &str) -> Result<()> {
    eprintln!("[attach-raw] {prog_name} -> {tp_name}");
    let prog: &mut RawTracePoint = ebpf
        .program_mut(prog_name)
        .ok_or_else(|| anyhow!("program not found: {prog_name}"))?
        .try_into()?;
    prog.load()?;
    prog.attach(tp_name)?;
    Ok(())
}

fn attach_tracepoints(ebpf: &mut Ebpf) {
    // attach programs
    // TODO: can do the fail pattern with the Result
    attach_tp(ebpf, "sched_fork", "sched", "sched_process_fork");
    attach_tp(ebpf, "sched_exit", "sched", "sched_process_exit");
    attach_raw(ebpf, "sys_enter", "sys_enter");
    attach_raw(ebpf, "sys_exit", "sys_exit");
}

fn connect_ebpf_bridge(ebpf: &mut Ebpf) -> Result<AyaHashMap<&mut MapData, u32, u8>> {
    // open WATCHED_PIDS
    eprintln!("[map] opening WATCHED_PIDS");
    // TODO; proper fail if we do not find the bridge
    let watched_map = ebpf
        .map_mut("WATCHED_PIDS")
        .ok_or_else(|| anyhow!("map not found: WATCHED_PIDS"))?;
    let watched: AyaHashMap<_, u32, u8> = AyaHashMap::try_from(watched_map)?;
    Ok(watched)
}

/// helper to split a command string into
/// cmd arg arg arg
fn parse_cmd(cmd_str: &str) -> Command {
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

fn execute_cmd_and_seed_cmd_pid(
    cmd_str: &str,
    watched: &mut AyaHashMap<&mut MapData, u32, u8>,
) -> Result<u32> {
    /*
    TODO refactor to zero-race gate:
    Replace Version A with a hard gate using fork/exec:

    - Parent: fork(); get child's PID immediately; insert PID into WATCHED_PIDS; send SIGCONT.
    - Child: raise(SIGSTOP) right after fork (before exec), then exec("ls","-la").
    - Implementation: use `nix` crate (`unistd::fork`, `sys::signal::kill`, `unistd::execvp`).
    - Benefit: guarantees no syscalls from the target before it’s in WATCHED_PIDS.
    */

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

fn main() -> Result<()> {
    env_logger::init();

    remove_locked_mem_limit();

    // load BPF
    let mut ebpf = Ebpf::load(aya::include_bytes_aligned!(concat!(
        env!("OUT_DIR"),
        "/trace"
    )))?;
    if let Err(e) = aya_log::EbpfLogger::init(&mut ebpf) {
        warn!("failed to initialize eBPF logger: {e}");
    }

    attach_tracepoints(&mut ebpf);

    let mut watched = connect_ebpf_bridge(&mut ebpf)
        .and_then(|mut map| {
            map.insert(1, 1, 0)?;
            map.remove(&1)?;
            Ok(map)
        })
        .expect("connection to kernel bridge failed");

    // TODO: change to take actual command from program startup
    execute_cmd_and_seed_cmd_pid("ls -la", &mut watched)
        .and_then(|child_pid| {
            for i in 0..50 {
                match watched.get(&child_pid, 0) {
                    Ok(_) => {
                        eprintln!("[verify] child TGID present in kernel bridge");
                        return Ok(());
                    }
                    Err(aya::maps::MapError::KeyNotFound) => {
                        thread::sleep(Duration::from_millis(5))
                    }
                    Err(e) => return Err(e.into()),
                }
            }
            Err(anyhow!("failed to find child TGID in 50 iterations"))
        })
        .expect("failed to find the child TGID in the kernel bridge in 50 iterations");

    // Child process handling moved to execute_cmd_and_seed_cmd_pid function
    Ok(())
}
