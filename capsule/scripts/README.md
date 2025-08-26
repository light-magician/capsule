# Test Scripts for Capsule Monitor

## test_agent.py

A comprehensive test script that simulates an AI agent performing various system operations. This script creates many subprocesses to test the live monitoring capabilities of `capsule monitor`.

### What it does:

1. **System Exploration** - `whoami`, `pwd`, `uname`, `env`
2. **File Operations** - `ls`, `find`, `grep`  
3. **Process Monitoring** - `ps`, `top`
4. **Network Operations** - `netstat`, `ping`
5. **Development Tools** - `git`, `python3`, `cargo` version checks
6. **Parallel Operations** - Multiple background `sleep` processes
7. **File Manipulation** - Create, read, process, delete files
8. **Complex Pipelines** - Multi-command shell pipelines
9. **Final System Check** - `date`, `uptime`

### Usage:

```bash
# Terminal 1: Run the agent with capsule
cd capsule-runtime-v2
cargo run -- run python3 scripts/test_agent.py

# Terminal 2: Monitor live processes  
cargo run -- monitor
```

### Expected Results:

The monitor TUI should show:
- Main `python3` process
- Various subprocess commands (`ls`, `ps`, `grep`, etc.)
- Multiple `sleep` processes during parallel phase
- Real-time process creation and termination
- Process PIDs, PPIDs, names, and command lines

This script runs for about 20-30 seconds total, giving plenty of time to observe the live process monitoring in action.