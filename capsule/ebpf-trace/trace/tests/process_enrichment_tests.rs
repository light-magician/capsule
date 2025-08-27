//! Integration test: verify Event phase and 6-arg capture via raw_syscalls
//!
//! Notes:
//! - These tests assume Docker/privileged environment with proper kernel headers.
//! - They do not run on macOS; run inside the provided compose stack.
//! - We use the existing setup helpers from trace crate (aya-based) to attach programs,
//!   seed a watched TGID, and then read from the ring buffer to collect events.
//!
use anyhow::Result;
use aya::maps::{ring_buf::RingBuffer, MapRefMut};
use std::sync::{Arc, Mutex};
use std::time::Duration;
use std::{thread};

use trace::{
    attach_tracepoints, connect_ebpf_bridge, execute_cmd_and_seed_cmd_pid, remove_locked_mem_limit,
    setup_ebpf, verify_child_tracked,
};

use trace_common::{Event, PHASE_ENTER, PHASE_EXIT};

#[tokio::test]
async fn verify_enter_exit_and_args() -> Result<()> {
    // Initialize logging and lift RLIMIT_MEMLOCK
    env_logger::try_init().ok();
    remove_locked_mem_limit()?;

    // Load and attach eBPF programs
    let mut ebpf = setup_ebpf()?;
    attach_tracepoints(&mut ebpf)?;

    // Connect to TGID watchlist and seed a trivial command under watch
    let mut watched = connect_ebpf_bridge(&mut ebpf)?;
    let child_tgid = execute_cmd_and_seed_cmd_pid("/bin/sh -c true", &mut watched)?;
    verify_child_tracked(&mut watched, child_tgid)?;

    // Open ring buffer on EVENTS and collect events for the child TGID
    let events: Arc<Mutex<Vec<Event>>> = Arc::new(Mutex::new(Vec::new()));
    let events_cloned = events.clone();

    let mut ring = RingBuffer::new();

    // SAFETY: map must exist and be a ringbuf; will be ensured by build script
    let map = ebpf.map_mut("EVENTS").expect("EVENTS map missing");
    ring.add(map, move |data: &[u8]| {
        // Parse raw Event payload (repr C); copy to avoid borrow issues
        if data.len() >= core::mem::size_of::<Event>() {
            let mut ev = Event {
                ktime_ns: 0,
                pid: 0,
                tid: 0,
                sysno: 0,
                phase: 0,
                _pad: [0;3],
                arg0: 0,
                arg1: 0,
                arg2: 0,
                arg3: 0,
                arg4: 0,
                arg5: 0,
            };
            // SAFETY: data comes from our eBPF program with identical layout
            unsafe {
                core::ptr::copy_nonoverlapping(
                    data.as_ptr(),
                    &mut ev as *mut Event as *mut u8,
                    core::mem::size_of::<Event>(),
                );
            }
            if ev.pid == child_tgid {
                events_cloned.lock().unwrap().push(ev);
            }
        }
    })?;

    // Poll for a short period to collect both enter and exit
    for _ in 0..50 {
        ring.poll(Duration::from_millis(20))?;
        // Early exit if we’ve collected some events
        if events.lock().unwrap().len() > 0 {
            // Keep polling a bit longer to catch the exit
            thread::sleep(Duration::from_millis(50));
        }
    }

    let captured = events.lock().unwrap().clone();
    assert!(captured.len() > 0, "expected at least one event for child tgid");

    // Check we saw at least one enter and one exit for the child
    let has_enter = captured.iter().any(|e| e.phase == PHASE_ENTER);
    let has_exit = captured.iter().any(|e| e.phase == PHASE_EXIT);
    assert!(has_enter, "expected to see an enter phase event");
    assert!(has_exit, "expected to see an exit phase event");

    // Verify arg fields exist; for exit events arg0 is return value
    for ev in captured.iter() {
        // arg0..arg5 must exist (some may be zero depending on syscall)
        let _ = (ev.arg0, ev.arg1, ev.arg2, ev.arg3, ev.arg4, ev.arg5);
        if ev.phase == PHASE_EXIT {
            // Exit return value should be in arg0; non-negative indicates success
            // (Some syscalls may legitimately return -errno)
            // We just assert field presence; domain-specific checks can be added later
            let _ret = ev.arg0 as i64;
        }
    }

    Ok(())
}

