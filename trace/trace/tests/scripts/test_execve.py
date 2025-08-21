#!/usr/bin/env python3
"""Test execve() - process image replacement"""

import os
import sys
import time

def main():
    print(f"[PARENT] Starting execve test, PID={os.getpid()}")
    
    pid = os.fork()
    if pid == 0:
        # Child process will exec
        print(f"[CHILD] About to execve, PID={os.getpid()}")
        time.sleep(0.1)  # Brief pause before exec
        # Replace process image with echo command
        os.execve('/bin/echo', ['echo', f'[EXECED] Execve successful from PID={os.getpid()}'], {})
        # This line should never be reached
        print("[CHILD] ERROR: execve failed!")
        os._exit(1)
    else:
        # Parent process
        print(f"[PARENT] Forked child PID={pid} for execve")
        os.waitpid(pid, 0)
        print(f"[PARENT] Execve child {pid} finished")
        return pid

if __name__ == "__main__":
    child_pid = main()
    print(f"CHILD_PID:{child_pid}")