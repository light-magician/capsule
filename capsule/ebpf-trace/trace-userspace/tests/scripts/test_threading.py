#!/usr/bin/env python3
"""Test threading (should NOT create new processes - same TGID)"""

import os
import threading
import time

def thread_function(name):
    print(f"[THREAD] Thread '{name}' in PID={os.getpid()}, PPID={os.getppid()}")
    time.sleep(0.5)
    print(f"[THREAD] Thread '{name}' exiting (still PID={os.getpid()})")

def main():
    print(f"[PARENT] Starting threading test, PID={os.getpid()}")
    
    # Create thread (should NOT create new process)
    thread = threading.Thread(target=thread_function, args=("test_thread",))
    thread.start()
    
    print(f"[PARENT] Created thread (same PID={os.getpid()})")
    thread.join()
    print(f"[PARENT] Thread finished (still PID={os.getpid()})")
    return os.getpid()  # Return own PID since no new process created

if __name__ == "__main__":
    pid = main()
    print(f"SAME_PID:{pid}")  # Different output format for threading test