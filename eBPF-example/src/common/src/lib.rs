// Create a new file: src/hello-ebpf-common/src/lib.rs
#![no_std]

// Syscall categories as bitmasks (can belong to multiple categories)
pub const CATEGORY_PROCESS: u8 = 1 << 0; // 0x01
pub const CATEGORY_FILE_IO: u8 = 1 << 1; // 0x02
pub const CATEGORY_NETWORK: u8 = 1 << 2; // 0x04
pub const CATEGORY_MEMORY: u8 = 1 << 3; // 0x08
pub const CATEGORY_SIGNAL: u8 = 1 << 4; // 0x10
pub const CATEGORY_SECURITY: u8 = 1 << 5; // 0x20
pub const CATEGORY_TIME: u8 = 1 << 6; // 0x40
pub const CATEGORY_SYSTEM: u8 = 1 << 7; // 0x80

// Comprehensive syscall database with categories and metadata
pub const SYSCALL_DATABASE: &[(u32, &str, u8, &str)] = &[
    // Format: (syscall_number, name, category_mask, description)

    // PROCESS MANAGEMENT
    (56, "clone", CATEGORY_PROCESS, "Create child process/thread"),
    (57, "fork", CATEGORY_PROCESS, "Fork current process"),
    (58, "vfork", CATEGORY_PROCESS, "Fork without copying memory"),
    (59, "execve", CATEGORY_PROCESS, "Execute program"),
    (60, "exit", CATEGORY_PROCESS, "Terminate process"),
    (
        61,
        "wait4",
        CATEGORY_PROCESS,
        "Wait for process state change",
    ),
    (
        322,
        "execveat",
        CATEGORY_PROCESS,
        "Execute program relative to directory",
    ),
    (39, "getpid", CATEGORY_PROCESS, "Get process ID"),
    (110, "getppid", CATEGORY_PROCESS, "Get parent process ID"),
    (186, "gettid", CATEGORY_PROCESS, "Get thread ID"),
    (
        231,
        "exit_group",
        CATEGORY_PROCESS,
        "Exit all threads in group",
    ),
    // FILE I/O
    (0, "read", CATEGORY_FILE_IO, "Read from file descriptor"),
    (1, "write", CATEGORY_FILE_IO, "Write to file descriptor"),
    (2, "open", CATEGORY_FILE_IO, "Open file"),
    (3, "close", CATEGORY_FILE_IO, "Close file descriptor"),
    (4, "stat", CATEGORY_FILE_IO, "Get file status"),
    (5, "fstat", CATEGORY_FILE_IO, "Get file status by fd"),
    (
        6,
        "lstat",
        CATEGORY_FILE_IO,
        "Get file status (no deref symlinks)",
    ),
    (
        257,
        "openat",
        CATEGORY_FILE_IO,
        "Open file relative to directory",
    ),
    (
        262,
        "newfstatat",
        CATEGORY_FILE_IO,
        "Get file status relative to directory",
    ),
    (19, "readv", CATEGORY_FILE_IO, "Read multiple buffers"),
    (20, "writev", CATEGORY_FILE_IO, "Write multiple buffers"),
    (17, "pread64", CATEGORY_FILE_IO, "Read from position"),
    (18, "pwrite64", CATEGORY_FILE_IO, "Write to position"),
    (78, "getdents", CATEGORY_FILE_IO, "Get directory entries"),
    (
        217,
        "getdents64",
        CATEGORY_FILE_IO,
        "Get directory entries (64-bit)",
    ),
    (83, "mkdir", CATEGORY_FILE_IO, "Create directory"),
    (84, "rmdir", CATEGORY_FILE_IO, "Remove directory"),
    (87, "unlink", CATEGORY_FILE_IO, "Remove file"),
    (
        263,
        "unlinkat",
        CATEGORY_FILE_IO,
        "Remove file relative to directory",
    ),
    // NETWORK I/O
    (41, "socket", CATEGORY_NETWORK, "Create network socket"),
    (42, "connect", CATEGORY_NETWORK, "Connect socket"),
    (43, "accept", CATEGORY_NETWORK, "Accept connection"),
    (
        288,
        "accept4",
        CATEGORY_NETWORK,
        "Accept connection with flags",
    ),
    (49, "bind", CATEGORY_NETWORK, "Bind socket to address"),
    (50, "listen", CATEGORY_NETWORK, "Listen for connections"),
    (44, "sendto", CATEGORY_NETWORK, "Send data to address"),
    (
        45,
        "recvfrom",
        CATEGORY_NETWORK,
        "Receive data from address",
    ),
    (46, "sendmsg", CATEGORY_NETWORK, "Send message"),
    (47, "recvmsg", CATEGORY_NETWORK, "Receive message"),
    (48, "shutdown", CATEGORY_NETWORK, "Shutdown socket"),
    (51, "getsockname", CATEGORY_NETWORK, "Get socket name"),
    (52, "getpeername", CATEGORY_NETWORK, "Get peer name"),
    (54, "setsockopt", CATEGORY_NETWORK, "Set socket options"),
    (55, "getsockopt", CATEGORY_NETWORK, "Get socket options"),
    // SECURITY/CREDENTIALS
    (102, "getuid", CATEGORY_SECURITY, "Get user ID"),
    (104, "getgid", CATEGORY_SECURITY, "Get group ID"),
    (105, "setuid", CATEGORY_SECURITY, "Set user ID"),
    (106, "setgid", CATEGORY_SECURITY, "Set group ID"),
    (107, "geteuid", CATEGORY_SECURITY, "Get effective user ID"),
    (108, "getegid", CATEGORY_SECURITY, "Get effective group ID"),
    (
        113,
        "setreuid",
        CATEGORY_SECURITY,
        "Set real/effective user ID",
    ),
    (
        114,
        "setregid",
        CATEGORY_SECURITY,
        "Set real/effective group ID",
    ),
    (
        117,
        "setresuid",
        CATEGORY_SECURITY,
        "Set real/effective/saved user ID",
    ),
    (
        119,
        "setresgid",
        CATEGORY_SECURITY,
        "Set real/effective/saved group ID",
    ),
    (
        118,
        "getresuid",
        CATEGORY_SECURITY,
        "Get real/effective/saved user ID",
    ),
    (
        120,
        "getresgid",
        CATEGORY_SECURITY,
        "Get real/effective/saved group ID",
    ),
    (
        115,
        "getgroups",
        CATEGORY_SECURITY,
        "Get supplementary groups",
    ),
    (
        116,
        "setgroups",
        CATEGORY_SECURITY,
        "Set supplementary groups",
    ),
    (125, "capget", CATEGORY_SECURITY, "Get capabilities"),
    (126, "capset", CATEGORY_SECURITY, "Set capabilities"),
    // SIGNALS
    (62, "kill", CATEGORY_SIGNAL, "Send signal to process"),
    (200, "tkill", CATEGORY_SIGNAL, "Send signal to thread"),
    (
        234,
        "tgkill",
        CATEGORY_SIGNAL,
        "Send signal to thread in group",
    ),
    (13, "rt_sigaction", CATEGORY_SIGNAL, "Set signal handler"),
    (14, "rt_sigprocmask", CATEGORY_SIGNAL, "Set signal mask"),
    (15, "rt_sigreturn", CATEGORY_SIGNAL, "Return from signal"),
    (
        128,
        "rt_sigtimedwait",
        CATEGORY_SIGNAL,
        "Wait for signal with timeout",
    ),
    (
        129,
        "rt_sigqueueinfo",
        CATEGORY_SIGNAL,
        "Queue signal with data",
    ),
    (
        130,
        "rt_sigsuspend",
        CATEGORY_SIGNAL,
        "Suspend until signal",
    ),
    // MEMORY (often security-relevant)
    (9, "mmap", CATEGORY_MEMORY, "Map memory"),
    (11, "munmap", CATEGORY_MEMORY, "Unmap memory"),
    (10, "mprotect", CATEGORY_MEMORY, "Change memory protection"),
    (12, "brk", CATEGORY_MEMORY, "Change data segment size"),
    (25, "mremap", CATEGORY_MEMORY, "Remap memory"),
    // TIME (often used in attacks)
    (228, "clock_gettime", CATEGORY_TIME, "Get time"),
    (35, "nanosleep", CATEGORY_TIME, "Sleep for time"),
    (96, "gettimeofday", CATEGORY_TIME, "Get time of day"),
];

// Helper functions for both kernel and userspace
pub fn get_syscall_info(nr: u32) -> Option<(&'static str, u8, &'static str)> {
    SYSCALL_DATABASE
        .iter()
        .find(|(syscall_nr, _, _, _)| *syscall_nr == nr)
        .map(|(_, name, category, desc)| (*name, *category, *desc))
}

pub fn get_category_name(category: u8) -> &'static str {
    match category {
        CATEGORY_PROCESS => "PROCESS",
        CATEGORY_FILE_IO => "FILE_IO",
        CATEGORY_NETWORK => "NETWORK",
        CATEGORY_MEMORY => "MEMORY",
        CATEGORY_SIGNAL => "SIGNAL",
        CATEGORY_SECURITY => "SECURITY",
        CATEGORY_TIME => "TIME",
        CATEGORY_SYSTEM => "SYSTEM",
        _ => "UNKNOWN",
    }
}

// Generate bitmask for kernel initialization
pub fn generate_category_bitmask(target_categories: u8) -> [u64; 8] {
    let mut bitmask = [0u64; 8];

    for (syscall_nr, _, category, _) in SYSCALL_DATABASE.iter() {
        if (category & target_categories) != 0 {
            let bit_index = *syscall_nr as usize;
            let array_index = bit_index / 64;
            let bit_offset = bit_index % 64;

            if array_index < 8 {
                bitmask[array_index] |= 1u64 << bit_offset;
            }
        }
    }

    bitmask
}
