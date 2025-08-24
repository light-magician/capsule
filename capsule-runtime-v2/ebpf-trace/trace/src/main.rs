use anyhow::Result;
use trace::{
    attach_tracepoints, connect_ebpf_bridge, execute_cmd_and_seed_cmd_pid, remove_locked_mem_limit,
    setup_ebpf, verify_child_tracked,
};

fn main() -> Result<()> {
    env_logger::init();

    remove_locked_mem_limit()?;

    // load BPF
    let mut ebpf = setup_ebpf()?;
    // TODO: verify that the programs are attached
    attach_tracepoints(&mut ebpf)?;

    let mut watched = connect_ebpf_bridge(&mut ebpf)
        .and_then(|mut map| {
            map.insert(1, 1, 0)?;
            map.remove(&1)?;
            Ok(map)
        })?;

    // TODO: change to take actual command from program startup
    let child_tgid = execute_cmd_and_seed_cmd_pid("ls -la", &mut watched)?;
    verify_child_tracked(&mut watched, child_tgid)?;

    Ok(())
}
