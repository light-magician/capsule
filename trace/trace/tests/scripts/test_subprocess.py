#!/usr/bin/env python3
"""Test subprocess.Popen process creation"""

import os
import subprocess
import time

def main():
    print(f"[PARENT] Starting subprocess test, PID={os.getpid()}")
    
    # Create subprocess that runs a simple command
    proc = subprocess.Popen([
        'python3', '-c', 
        f'import os, time; '
        f'print(f"[SUBPROCESS] Child PID={{os.getpid()}}, PPID={{os.getppid()}}"); '
        f'time.sleep(0.5); '
        f'print(f"[SUBPROCESS] Child {{os.getpid()}} exiting")'
    ])
    
    print(f"[PARENT] Created subprocess PID={proc.pid}")
    proc.wait()
    print(f"[PARENT] Subprocess {proc.pid} exited")
    return proc.pid

if __name__ == "__main__":
    child_pid = main()
    print(f"CHILD_PID:{child_pid}")