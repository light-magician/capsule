#!/usr/bin/env python3
"""Test chain of forks - children creating their own children"""

import os
import sys
import time

def create_child_chain(depth, max_depth):
    """Recursively create a chain of child processes"""
    current_pid = os.getpid()
    print(f"[CHAIN{depth}] Process PID={current_pid}, PPID={os.getppid()}, depth={depth}")
    
    if depth < max_depth:
        pid = os.fork()
        if pid == 0:
            # Child continues the chain
            time.sleep(0.1)  # Brief pause between forks
            create_child_chain(depth + 1, max_depth)
            os._exit(0)
        else:
            # Parent waits for child
            print(f"[CHAIN{depth}] Created child PID={pid} at depth {depth + 1}")
            os.waitpid(pid, 0)
            print(f"[CHAIN{depth}] Child {pid} at depth {depth + 1} exited")
            return pid
    else:
        print(f"[CHAIN{depth}] Reached max depth {max_depth}, PID={current_pid}")
        time.sleep(0.5)  # Leaf process runs briefly
        return current_pid

def main():
    print(f"[PARENT] Starting chain fork test, PID={os.getpid()}")
    max_depth = 3  # Create a 3-level deep process chain
    
    last_child = create_child_chain(0, max_depth)
    print(f"[PARENT] Chain fork test completed")
    return last_child

if __name__ == "__main__":
    child_pid = main()
    print(f"CHILD_PID:{child_pid}")