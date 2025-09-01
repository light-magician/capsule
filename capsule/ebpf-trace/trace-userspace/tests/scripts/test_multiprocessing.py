#!/usr/bin/env python3
"""Test multiprocessing.Process creation"""

import os
import multiprocessing
import time

def worker_function(name):
    print(f"[WORKER] Multiprocessing worker '{name}' PID={os.getpid()}, PPID={os.getppid()}")
    time.sleep(0.5)
    print(f"[WORKER] Worker '{name}' PID={os.getpid()} exiting")

def main():
    print(f"[PARENT] Starting multiprocessing test, PID={os.getpid()}")
    
    # Create multiprocessing child
    process = multiprocessing.Process(target=worker_function, args=("test_worker",))
    process.start()
    
    print(f"[PARENT] Created multiprocessing child PID={process.pid}")
    process.join()
    print(f"[PARENT] Multiprocessing child {process.pid} finished")
    return process.pid

if __name__ == "__main__":
    child_pid = main()
    print(f"CHILD_PID:{child_pid}")