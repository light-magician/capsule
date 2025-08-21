#!/usr/bin/env python3
"""
Comprehensive process split test suite for eBPF process tracking validation.
Tests various process creation and execution scenarios to verify that eBPF
code properly tracks child processes.
"""

import os
import sys
import time
import subprocess
import multiprocessing
import threading
from ctypes import CDLL, c_int, c_void_p, POINTER
import signal

# Load libc for system calls
libc = CDLL("libc.so.6")

def test_fork():
    """Test basic fork() process creation"""
    print("[TEST] Starting fork() test")
    
    pid = os.fork()
    if pid == 0:
        # Child process
        print(f"[CHILD] Fork child process PID={os.getpid()}, PPID={os.getppid()}")
        time.sleep(1)
        print("[CHILD] Fork child exiting")
        os._exit(0)
    else:
        # Parent process
        print(f"[PARENT] Forked child PID={pid}")
        os.waitpid(pid, 0)
        print(f"[PARENT] Fork child {pid} exited")

def test_subprocess_popen():
    """Test subprocess.Popen process creation"""
    print("[TEST] Starting subprocess.Popen test")
    
    proc = subprocess.Popen([
        'python3', '-c', 
        'import os, time; '
        'print(f"[CHILD] Subprocess child PID={os.getpid()}, PPID={os.getppid()}"); '
        'time.sleep(1); '
        'print("[CHILD] Subprocess child exiting")'
    ])
    
    print(f"[PARENT] Created subprocess PID={proc.pid}")
    proc.wait()
    print(f"[PARENT] Subprocess {proc.pid} exited")

def test_subprocess_call():
    """Test subprocess.call process creation"""
    print("[TEST] Starting subprocess.call test")
    
    result = subprocess.call([
        'python3', '-c',
        'import os; '
        'print(f"[CHILD] subprocess.call child PID={os.getpid()}, PPID={os.getppid()}")'
    ])
    
    print(f"[PARENT] subprocess.call completed with return code {result}")

def test_execve():
    """Test execve() - replace process image"""
    print("[TEST] Starting execve() test")
    
    pid = os.fork()
    if pid == 0:
        # Child process will exec
        print("[CHILD] About to execve ls -l")
        os.execve('/bin/ls', ['ls', '-l', '/tmp'], {})
        # This line should never be reached
        print("[CHILD] ERROR: execve failed!")
        os._exit(1)
    else:
        # Parent process
        print(f"[PARENT] Forked child PID={pid} for execve")
        os.waitpid(pid, 0)
        print(f"[PARENT] Execve child {pid} finished")

def test_system_call():
    """Test os.system() call"""
    print("[TEST] Starting os.system() test")
    
    result = os.system('python3 -c "import os; print(f\\"[CHILD] system() child PID={os.getpid()}, PPID={os.getppid()}\\")"')
    print(f"[PARENT] os.system() completed with return code {result}")

def test_multiprocessing():
    """Test multiprocessing module process creation"""
    print("[TEST] Starting multiprocessing test")
    
    def worker_function(name):
        print(f"[CHILD] Multiprocessing worker '{name}' PID={os.getpid()}, PPID={os.getppid()}")
        time.sleep(1)
        print(f"[CHILD] Worker '{name}' exiting")
    
    # Create and start process
    process = multiprocessing.Process(target=worker_function, args=("test_worker",))
    process.start()
    
    print(f"[PARENT] Created multiprocessing child PID={process.pid}")
    process.join()
    print(f"[PARENT] Multiprocessing child {process.pid} finished")

def test_threading():
    """Test threading (should NOT create new processes)"""
    print("[TEST] Starting threading test (should NOT create new process)")
    
    def thread_function(name):
        print(f"[THREAD] Thread '{name}' in PID={os.getpid()}, PPID={os.getppid()}")
        time.sleep(1)
        print(f"[THREAD] Thread '{name}' exiting")
    
    # Create and start thread
    thread = threading.Thread(target=thread_function, args=("test_thread",))
    thread.start()
    
    print(f"[PARENT] Created thread (same PID={os.getpid()})")
    thread.join()
    print("[PARENT] Thread finished")

def test_double_fork():
    """Test double fork pattern (daemon creation)"""
    print("[TEST] Starting double fork test (daemon pattern)")
    
    pid1 = os.fork()
    if pid1 == 0:
        # First child
        print(f"[CHILD1] First child PID={os.getpid()}, PPID={os.getppid()}")
        
        pid2 = os.fork()
        if pid2 == 0:
            # Second child (grandchild)
            print(f"[CHILD2] Second child (grandchild) PID={os.getpid()}, PPID={os.getppid()}")
            time.sleep(2)
            print("[CHILD2] Grandchild exiting")
            os._exit(0)
        else:
            print(f"[CHILD1] Created grandchild PID={pid2}, first child exiting")
            os._exit(0)  # First child exits immediately
    else:
        # Parent
        print(f"[PARENT] Created first child PID={pid1}")
        os.waitpid(pid1, 0)  # Wait for first child only
        print(f"[PARENT] First child {pid1} exited (grandchild may still be running)")
        time.sleep(3)  # Give grandchild time to finish

def test_shell_command():
    """Test shell command execution"""
    print("[TEST] Starting shell command test")
    
    proc = subprocess.Popen([
        '/bin/bash', '-c',
        'echo "[CHILD] Shell command PID=$$, PPID=$PPID"; sleep 1; echo "[CHILD] Shell command exiting"'
    ])
    
    print(f"[PARENT] Created shell command PID={proc.pid}")
    proc.wait()
    print(f"[PARENT] Shell command {proc.pid} exited")

def test_chain_execution():
    """Test chain of process executions"""
    print("[TEST] Starting chain execution test")
    
    pid = os.fork()
    if pid == 0:
        # Child process chains multiple commands
        print("[CHILD] Starting command chain")
        
        # First command
        subprocess.call(['echo', '[CHAIN1] First command in chain'])
        
        # Second command
        subprocess.call(['echo', '[CHAIN2] Second command in chain'])
        
        # Third command with pipe
        proc1 = subprocess.Popen(['echo', 'hello world'], stdout=subprocess.PIPE)
        proc2 = subprocess.Popen(['wc', '-w'], stdin=proc1.stdout, stdout=subprocess.PIPE)
        proc1.stdout.close()
        output, _ = proc2.communicate()
        print(f"[CHAIN3] Pipe result: {output.decode().strip()} words")
        
        os._exit(0)
    else:
        print(f"[PARENT] Created chain execution child PID={pid}")
        os.waitpid(pid, 0)
        print(f"[PARENT] Chain execution {pid} completed")

def run_test(test_name, test_func):
    """Run a single test with timing and error handling"""
    try:
        start_time = time.time()
        test_func()
        duration = time.time() - start_time
        print(f"[INFO] Test '{test_name}' completed in {duration:.2f}s")
        return True
    except Exception as e:
        print(f"[ERROR] Test '{test_name}' failed: {e}")
        return False

def main():
    """Main test runner"""
    print("=== Python Process Split Test Suite ===")
    print(f"Main process PID={os.getpid()}")
    print()
    
    # Define all available tests
    tests = {
        'fork': test_fork,
        'subprocess_popen': test_subprocess_popen,
        'subprocess_call': test_subprocess_call,
        'execve': test_execve,
        'system': test_system_call,
        'multiprocessing': test_multiprocessing,
        'threading': test_threading,
        'double_fork': test_double_fork,
        'shell': test_shell_command,
        'chain': test_chain_execution,
    }
    
    # Allow user to specify which tests to run
    if len(sys.argv) > 1:
        # Run specific tests
        passed = 0
        total = 0
        
        for test_name in sys.argv[1:]:
            if test_name in tests:
                total += 1
                if run_test(test_name, tests[test_name]):
                    passed += 1
                print()
            else:
                print(f"Unknown test: {test_name}")
                print(f"Available tests: {', '.join(tests.keys())}")
        
        print(f"=== Results: {passed}/{total} tests passed ===")
    else:
        # Run all tests
        passed = 0
        total = len(tests)
        
        for test_name, test_func in tests.items():
            if run_test(test_name, test_func):
                passed += 1
            print()
        
        print(f"=== All tests completed: {passed}/{total} tests passed ===")

if __name__ == "__main__":
    main()