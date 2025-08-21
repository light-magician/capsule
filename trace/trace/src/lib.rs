use std::{process::Command, thread, time::Duration};

use anyhow::{anyhow, Result};
use aya::{
    maps::{HashMap as AyaHashMap, MapData},
    programs::{RawTracePoint, TracePoint},
    Ebpf,
};
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
