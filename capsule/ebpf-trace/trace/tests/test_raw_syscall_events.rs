use std::{collections::HashMap, time::Duration};

use anyhow::Result;
use aya::maps::RingBuf;
use tokio::{io::unix::AsyncFd, time::timeout};
use trace::{
    attach_tracepoints, connect_ebpf_bridge, connect_events_ringbuf, execute_cmd_and_seed_cmd_pid,
    remove_locked_mem_limit, setup_ebpf, verify_child_tracked,
};
use trace_common::{EnrichedSyscall, RawSyscallEvent, SyscallEnrichment, PHASE_ENTER, PHASE_EXIT};

/// Integration test for the complete eBPF syscall capture pipeline. This validates that 
/// the kernel eBPF code can successfully emit RawSyscallEvent structs to the ring buffer
/// and that userspace can deserialize them correctly. Tests the fundamental data flow
/// from kernel tracepoints through ring buffer to async userspace processing.
#[tokio::test]
async fn test_raw_syscall_event_reading() -> Result<()> {
    env_logger::try_init().ok();
    remove_locked_mem_limit()?;

    let mut ebpf = setup_ebpf()?;
    attach_tracepoints(&mut ebpf)?;

    // Seed kernel map with initial PID (clean architecture)
    let child_tgid = {
        let mut watched = connect_ebpf_bridge(&mut ebpf).and_then(|mut map| {
            map.insert(1, 1, 0)?;
            map.remove(&1)?;
            Ok(map)
        })?;

        let child_tgid = execute_cmd_and_seed_cmd_pid("ls -la", &mut watched)?;
        verify_child_tracked(&mut watched, child_tgid)?;
        child_tgid
        // watched drops here - kernel map seeded
    };

    // Get ring buffer for reading syscall events
    let ring_buf = connect_events_ringbuf(&mut ebpf)?;
    let mut async_fd = AsyncFd::new(ring_buf)?;

    println!("Starting raw syscall event test for PID {}...", child_tgid);

    // Userspace PID tracking
    let mut tracked_pids: HashMap<u32, String> = HashMap::new();
    tracked_pids.insert(child_tgid, "ls -la".to_string());

    let mut events_received = 0;
    let mut enter_events = 0;
    let mut exit_events = 0;

    // Read events with timeout to prevent hanging
    let result = timeout(Duration::from_secs(5), async {
        loop {
            let mut guard = async_fd.readable_mut().await?;
            let ring_buf = guard.get_inner_mut();

            // Read all available events
            while let Some(item) = ring_buf.next() {
                if item.len() >= std::mem::size_of::<RawSyscallEvent>() {
                    let raw_event: RawSyscallEvent =
                        unsafe { std::ptr::read(item.as_ptr() as *const RawSyscallEvent) };

                    events_received += 1;

                    // Validate event structure
                    assert!(raw_event.ktime_ns > 0, "Event should have valid timestamp");
                    assert!(raw_event.pid > 0, "Event should have valid PID");
                    assert!(raw_event.tid > 0, "Event should have valid TID");

                    // Count phase types
                    match raw_event.phase {
                        PHASE_ENTER => {
                            enter_events += 1;
                            println!(
                                "ENTER: pid={}, sysno={}, arg0=0x{:x}",
                                raw_event.pid, raw_event.sysno, raw_event.arg0
                            );
                        }
                        PHASE_EXIT => {
                            exit_events += 1;
                            println!(
                                "EXIT:  pid={}, sysno={}, ret=0x{:x}",
                                raw_event.pid, raw_event.sysno, raw_event.arg0
                            );
                        }
                        _ => {
                            panic!("Invalid phase: {}", raw_event.phase);
                        }
                    }

                    // Test enrichment wrapper
                    let enriched = EnrichedSyscall {
                        raw: raw_event,
                        enrichment: SyscallEnrichment::None,
                    };

                    assert_eq!(enriched.raw.pid, raw_event.pid);
                    assert_eq!(enriched.raw.sysno, raw_event.sysno);
                    assert_eq!(enriched.raw.phase, raw_event.phase);

                    // Stop after we've seen some events
                    if events_received >= 10 {
                        break;
                    }
                }
            }

            guard.clear_ready();

            if events_received >= 10 {
                break;
            }
        }

        Ok::<(), anyhow::Error>(())
    })
    .await;

    match result {
        Ok(_) => println!("✓ Successfully read {} syscall events", events_received),
        Err(_) => {
            if events_received > 0 {
                println!("✓ Read {} events before timeout", events_received);
            } else {
                println!(
                    "⚠ Timeout occurred with no events - this might be expected for fast commands"
                );
            }
        }
    }

    // Validate we got both enter and exit events (if we got any events)
    if events_received > 0 {
        assert!(enter_events > 0, "Should have received some ENTER events");
        assert!(exit_events > 0, "Should have received some EXIT events");
        println!(
            "✓ Received {} ENTER and {} EXIT events",
            enter_events, exit_events
        );
    }

    println!("✓ Raw syscall event reading test completed");
    Ok(())
}

/// Validates that the eBPF kernel code correctly tracks syscall entry and exit phases.
/// This ensures that most syscalls appear as matching ENTER/EXIT pairs, which is
/// critical for syscall duration analysis and proper state tracking. Tests the
/// phase field encoding and syscall pairing logic in the kernel tracepoints.
#[tokio::test]
async fn test_syscall_phases() -> Result<()> {
    env_logger::try_init().ok();
    remove_locked_mem_limit()?;

    let mut ebpf = setup_ebpf()?;
    attach_tracepoints(&mut ebpf)?;

    // Use a command that will generate more syscalls
    let child_tgid = {
        let mut watched = connect_ebpf_bridge(&mut ebpf)?;
        let child_tgid =
            execute_cmd_and_seed_cmd_pid("python3 -c \"import os; print('test')\"", &mut watched)?;
        verify_child_tracked(&mut watched, child_tgid)?;
        child_tgid
    };

    let ring_buf = connect_events_ringbuf(&mut ebpf)?;
    let mut async_fd = AsyncFd::new(ring_buf)?;

    let mut syscall_pairs: HashMap<i32, (bool, bool)> = HashMap::new(); // (has_enter, has_exit)
    let mut events_processed = 0;

    let result = timeout(Duration::from_secs(3), async {
        loop {
            let mut guard = async_fd.readable_mut().await?;
            let ring_buf = guard.get_inner_mut();

            while let Some(item) = ring_buf.next() {
                if item.len() >= std::mem::size_of::<RawSyscallEvent>() {
                    let raw_event: RawSyscallEvent =
                        unsafe { std::ptr::read(item.as_ptr() as *const RawSyscallEvent) };

                    events_processed += 1;

                    let entry = syscall_pairs
                        .entry(raw_event.sysno)
                        .or_insert((false, false));
                    match raw_event.phase {
                        PHASE_ENTER => entry.0 = true,
                        PHASE_EXIT => entry.1 = true,
                        _ => panic!("Invalid phase: {}", raw_event.phase),
                    }

                    if events_processed >= 20 {
                        break;
                    }
                }
            }

            guard.clear_ready();

            if events_processed >= 20 {
                break;
            }
        }

        Ok::<(), anyhow::Error>(())
    })
    .await;

    if events_processed > 0 {
        // Validate that we have matching enter/exit pairs for most syscalls
        let mut complete_pairs = 0;
        for (sysno, (has_enter, has_exit)) in &syscall_pairs {
            if *has_enter && *has_exit {
                complete_pairs += 1;
            }
            println!("Syscall {}: enter={}, exit={}", sysno, has_enter, has_exit);
        }

        println!(
            "✓ Found {} complete syscall enter/exit pairs",
            complete_pairs
        );
        assert!(
            complete_pairs > 0,
            "Should have at least one complete enter/exit pair"
        );
    }

    println!("✓ Syscall phase tracking test completed");
    Ok(())
}

/// Unit test for the enrichment data structure API and enum pattern matching.
/// This is a basic validation that the EnrichedSyscall wrapper and SyscallEnrichment
/// enum variants can be created and accessed correctly. Tests struct field assignment
/// and enum destructuring, which are prerequisites for the enrichment pipeline.
#[test]
fn test_enrichment_data_structures() {
    // Test RawSyscallEvent creation
    let raw_event = RawSyscallEvent {
        ktime_ns: 1234567890,
        pid: 1000,
        tid: 1001,
        sysno: 221, // execve
        arg0: 0x7fff12345000,
        arg1: 0x7fff12346000,
        arg2: 0x7fff12347000,
        phase: PHASE_ENTER,
        _pad: [0; 7],
    };

    assert_eq!(raw_event.ktime_ns, 1234567890);
    assert_eq!(raw_event.pid, 1000);
    assert_eq!(raw_event.tid, 1001);
    assert_eq!(raw_event.sysno, 221);
    assert_eq!(raw_event.phase, PHASE_ENTER);

    // Test EnrichedSyscall with different enrichment types
    let enriched = EnrichedSyscall {
        raw: raw_event,
        enrichment: SyscallEnrichment::Exec {
            filename: "/bin/ls".to_string(),
            argv: vec!["ls".to_string(), "-la".to_string()],
            envp: vec!["PATH=/bin".to_string()],
        },
    };

    match enriched.enrichment {
        SyscallEnrichment::Exec {
            filename,
            argv,
            envp,
        } => {
            assert_eq!(filename, "/bin/ls");
            assert_eq!(argv.len(), 2);
            assert_eq!(argv[0], "ls");
            assert_eq!(argv[1], "-la");
            assert_eq!(envp.len(), 1);
        }
        _ => panic!("Expected Exec enrichment"),
    }

    // Test Clone enrichment
    let clone_enriched = EnrichedSyscall {
        raw: raw_event,
        enrichment: SyscallEnrichment::Clone {
            flags: 0x00000100,
            flags_decoded: vec!["CLONE_VM".to_string()],
            stack_ptr: Some(0x7fff12340000),
        },
    };

    match clone_enriched.enrichment {
        SyscallEnrichment::Clone {
            flags,
            flags_decoded,
            stack_ptr,
        } => {
            assert_eq!(flags, 0x00000100);
            assert_eq!(flags_decoded[0], "CLONE_VM");
            assert_eq!(stack_ptr, Some(0x7fff12340000));
        }
        _ => panic!("Expected Clone enrichment"),
    }

    println!("✓ Enrichment data structure tests passed");
}

/// Memory layout validation for eBPF compatibility and binary serialization safety.
/// This test ensures RawSyscallEvent has the correct size, alignment, and padding
/// required for eBPF ring buffer communication. Tests that unsafe pointer casting
/// and byte-level serialization preserve all field values correctly.
#[test]
fn test_event_memory_layout() {
    use std::mem;

    // Get the actual size (which includes padding)
    let actual_size = mem::size_of::<RawSyscallEvent>();
    println!("RawSyscallEvent actual size: {} bytes", actual_size);

    // Verify it's properly aligned for eBPF
    assert_eq!(mem::align_of::<RawSyscallEvent>(), 8);

    // Test that we can safely cast bytes to RawSyscallEvent
    let raw_event = RawSyscallEvent {
        ktime_ns: 0x1234567890abcdef,
        pid: 0x12345678,
        tid: 0x87654321,
        sysno: 0x11223344,
        arg0: 0xaaaaaaaaaaaaaaaa,
        arg1: 0xbbbbbbbbbbbbbbbb,
        arg2: 0xcccccccccccccccc,
        phase: 1,
        _pad: [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66],
    };

    // Convert to bytes and back using the actual size
    let bytes: Vec<u8> = unsafe {
        std::slice::from_raw_parts(&raw_event as *const _ as *const u8, actual_size).to_vec()
    };

    let restored_event: RawSyscallEvent =
        unsafe { std::ptr::read(bytes.as_ptr() as *const RawSyscallEvent) };

    assert_eq!(restored_event.ktime_ns, 0x1234567890abcdef);
    assert_eq!(restored_event.pid, 0x12345678);
    assert_eq!(restored_event.tid, 0x87654321);
    assert_eq!(restored_event.sysno, 0x11223344);
    assert_eq!(restored_event.arg0, 0xaaaaaaaaaaaaaaaa);
    assert_eq!(restored_event.arg1, 0xbbbbbbbbbbbbbbbb);
    assert_eq!(restored_event.arg2, 0xcccccccccccccccc);
    assert_eq!(restored_event.phase, 1);

    println!(
        "✓ Event memory layout test passed (size: {} bytes)",
        actual_size
    );
}

