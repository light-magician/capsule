#!/usr/bin/env python3
"""Test os.system() call"""

import os
import sys

def main():
    print(f"[PARENT] Starting os.system() test, PID={os.getpid()}")
    
    # Use os.system to run a command that will show its PID
    result = os.system('echo "[SYSTEM] System command PID=$$, PPID=$PPID"')
    print(f"[PARENT] os.system() completed with return code {result}")
    
    # os.system doesn't give us direct access to child PID, so we'll use a different approach
    # Let's fork and then use system in the child so we can track the child PID
    pid = os.fork()
    if pid == 0:
        print(f"[CHILD] About to call os.system() from PID={os.getpid()}")
        os.system('echo "[SYSTEM] System command called from child"')
        print(f"[CHILD] os.system() call completed in PID={os.getpid()}")
        os._exit(0)
    else:
        print(f"[PARENT] Forked child PID={pid} for system call")
        os.waitpid(pid, 0)
        print(f"[PARENT] System call child {pid} finished")
        return pid

if __name__ == "__main__":
    child_pid = main()
    print(f"CHILD_PID:{child_pid}")