#!/usr/bin/env python3
"""Test basic fork() process creation"""

import os
import sys
import time

def main():
    print(f"[PARENT] Starting fork test, PID={os.getpid()}")
    
    pid = os.fork()
    if pid == 0:
        # Child process
        print(f"[CHILD] Fork child PID={os.getpid()}, PPID={os.getppid()}")
        time.sleep(0.5)  # Give eBPF time to track
        print(f"[CHILD] Fork child {os.getpid()} exiting")
        os._exit(0)
    else:
        # Parent process
        print(f"[PARENT] Forked child PID={pid}")
        os.waitpid(pid, 0)
        print(f"[PARENT] Fork child {pid} exited")
        return pid

if __name__ == "__main__":
    child_pid = main()
    print(f"CHILD_PID:{child_pid}")  # For test validation