#!/usr/bin/env python3
"""
Test agent script that spawns many subprocesses for testing capsule monitor.

This script simulates an AI agent that performs various system operations,
creating multiple subprocesses that will show up in the live monitor TUI.
"""

import subprocess
import time
import os
import sys
from pathlib import Path

def log(message):
    """Log with timestamp"""
    print(f"[{time.strftime('%H:%M:%S')}] {message}")

def run_command(cmd, desc):
    """Run a command and log it"""
    log(f"Running: {desc}")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=10)
        log(f"  → Exit code: {result.returncode}")
        return result
    except subprocess.TimeoutExpired:
        log(f"  → Timeout after 10s")
    except Exception as e:
        log(f"  → Error: {e}")

def main():
    log("🤖 Starting AI Agent Simulation")
    log("This will create many subprocesses for monitor testing")
    
    # 1. System exploration
    log("\n📊 Phase 1: System Exploration")
    run_command("whoami", "Check current user")
    time.sleep(0.5)
    
    run_command("pwd", "Get working directory")
    time.sleep(0.5)
    
    run_command("uname -a", "Get system info")
    time.sleep(0.5)
    
    run_command("env | head -5", "Check environment")
    time.sleep(0.5)
    
    # 2. File operations
    log("\n📁 Phase 2: File Operations")
    run_command("ls -la", "List current directory")
    time.sleep(0.5)
    
    run_command("find . -name '*.py' | head -3", "Find Python files")
    time.sleep(0.5)
    
    run_command("grep -r 'use' . --include='*.rs' | head -3", "Search Rust files")
    time.sleep(0.5)
    
    # 3. Process monitoring
    log("\n🔍 Phase 3: Process Monitoring")
    run_command("ps aux | head -5", "List running processes")
    time.sleep(0.5)
    
    run_command("top -l 1 -n 5", "Get top processes")
    time.sleep(0.5)
    
    # 4. Network operations
    log("\n🌐 Phase 4: Network Operations")
    run_command("netstat -an | head -5", "Check network connections")
    time.sleep(0.5)
    
    run_command("ping -c 3 8.8.8.8", "Test network connectivity")
    time.sleep(1)
    
    # 5. Development tools
    log("\n⚙️ Phase 5: Development Tools")
    run_command("git --version", "Check git version")
    time.sleep(0.5)
    
    run_command("python3 --version", "Check Python version")
    time.sleep(0.5)
    
    run_command("cargo --version", "Check Cargo version")
    time.sleep(0.5)
    
    # 6. Parallel operations
    log("\n🔄 Phase 6: Parallel Operations")
    
    # Create multiple background processes
    processes = []
    for i in range(3):
        log(f"Starting background task {i+1}")
        proc = subprocess.Popen(f"sleep 2 && echo 'Background task {i+1} done'", 
                               shell=True)
        processes.append(proc)
        time.sleep(0.2)  # Small delay to see processes appear
    
    # Wait for all background processes
    for i, proc in enumerate(processes):
        log(f"Waiting for background task {i+1}")
        proc.wait()
        time.sleep(0.3)
    
    # 7. File creation and manipulation
    log("\n📝 Phase 7: File Operations")
    run_command("echo 'test data' > /tmp/agent_test.txt", "Create test file")
    time.sleep(0.5)
    
    run_command("cat /tmp/agent_test.txt", "Read test file")
    time.sleep(0.5)
    
    run_command("wc -l /tmp/agent_test.txt", "Count lines in file")
    time.sleep(0.5)
    
    run_command("rm /tmp/agent_test.txt", "Clean up test file")
    time.sleep(0.5)
    
    # 8. Complex pipeline
    log("\n🔗 Phase 8: Complex Pipeline")
    run_command("echo -e 'apple\\nbanana\\ncherry' | sort | uniq | wc -l", 
               "Text processing pipeline")
    time.sleep(0.5)
    
    # 9. Final system check
    log("\n✅ Phase 9: Final Check")
    run_command("date", "Current timestamp")
    time.sleep(0.5)
    
    run_command("uptime", "System uptime")
    time.sleep(0.5)
    
    log("\n🎉 AI Agent Simulation Complete!")
    log("All subprocesses have been executed.")
    log("Check 'capsule monitor' to see the process activity!")

if __name__ == "__main__":
    main()