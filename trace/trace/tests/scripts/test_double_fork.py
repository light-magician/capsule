#!/usr/bin/env python3
"""Test double fork (daemon pattern) - creates orphaned grandchild"""

import os
import sys
import time

def main():
    print(f"[PARENT] Starting double fork test, PID={os.getpid()}")
    
    # First fork
    pid1 = os.fork()
    if pid1 == 0:
        # First child
        print(f"[CHILD1] First child PID={os.getpid()}, PPID={os.getppid()}")
        
        # Second fork
        pid2 = os.fork()
        if pid2 == 0:
            # Second child (grandchild) - will become orphan
            print(f"[GRANDCHILD] Grandchild PID={os.getpid()}, PPID={os.getppid()}")
            time.sleep(1.0)  # Run longer to test orphan tracking
            print(f"[GRANDCHILD] Grandchild {os.getpid()} exiting")
            os._exit(0)
        else:
            print(f"[CHILD1] Created grandchild PID={pid2}, first child exiting immediately")
            print(f"GRANDCHILD_PID:{pid2}")  # For test validation
            os._exit(0)  # First child exits, making grandchild an orphan
    else:
        # Parent
        print(f"[PARENT] Created first child PID={pid1}")
        os.waitpid(pid1, 0)  # Wait for first child to exit
        print(f"[PARENT] First child {pid1} exited, grandchild is now orphaned")
        time.sleep(1.5)  # Give grandchild time to complete
        print(f"[PARENT] Double fork test completed")
        return pid1

if __name__ == "__main__":
    child_pid = main()
    print(f"CHILD_PID:{child_pid}")