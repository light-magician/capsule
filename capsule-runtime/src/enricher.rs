use crate::model::{
    ProcessContext, SyscallEvent, ProcessForensics, FileForensics, NetworkForensics,
    MemoryForensics, SecurityForensics, SignalForensics, EnvironmentForensics,
    PermissionAnalysis, ProcessAncestor, FileType, SocketState, SocketFamily,
    SocketType, Protocol, SocketAddress, DnsInfo
};
use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use std::os::unix::fs::MetadataExt;
use tokio::sync::broadcast::{Receiver, Sender};
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Context enricher that adds /proc metadata to syscall events
pub struct Enricher {
    cache: HashMap<u32, ProcessContext>,
}

impl Enricher {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    /// Main enricher loop - consumes raw events and emits enriched events
    pub async fn run(
        mut self,
        mut rx_evt: Receiver<SyscallEvent>,
        tx_enriched: Sender<SyscallEvent>,
    ) -> Result<()> {
        self.run_with_cancellation(rx_evt, tx_enriched, CancellationToken::new()).await
    }

    /// Main enricher loop with cancellation support
    pub async fn run_with_cancellation(
        mut self,
        mut rx_evt: Receiver<SyscallEvent>,
        tx_enriched: Sender<SyscallEvent>,
        cancellation_token: CancellationToken,
    ) -> Result<()> {
        loop {
            tokio::select! {
                // Process incoming events
                event_result = rx_evt.recv() => {
                    match event_result {
                        Ok(mut event) => {
                            // Enrich the event with process context
                            if let Some(context) = self.get_process_context(event.pid).await {
                                self.populate_event_fields(&mut event, &context).await;
                            }
                            let _ = tx_enriched.send(event);
                        },
                        Err(_) => break, // Channel closed
                    }
                },
                
                // Graceful shutdown signal
                _ = cancellation_token.cancelled() => {
                    self.cache.clear();
                    break;
                }
            }
        }
        
        Ok(())
    }

    /// Populate SyscallEvent fields with enhanced forensic data
    async fn populate_event_fields(&mut self, event: &mut SyscallEvent, context: &ProcessContext) {
        // Convert ProcessContext data to SyscallEvent fields
        event.ppid = context.ppid;
        event.exe_path = context.exe_path.as_ref().map(|p| p.to_string_lossy().to_string());
        event.cwd = context.cwd.as_ref().map(|p| p.to_string_lossy().to_string());
        event.argv = context.argv.clone();
        event.uid = context.uid;
        event.gid = context.gid;
        event.euid = context.euid;
        event.egid = context.egid;
        event.fd_map = context.fd_map.clone();
        
        // Parse capabilities from hex string to u64 bitmap
        event.caps = context.capabilities.as_ref()
            .and_then(|cap_str| u64::from_str_radix(cap_str, 16).ok());
            
        // Enhance forensic data with comprehensive /proc analysis
        self.enhance_forensic_data(event).await;
    }

    /// Get process context for a PID, using simple cache
    async fn get_process_context(&mut self, pid: u32) -> Option<ProcessContext> {
        // Check cache first
        if let Some(context) = self.cache.get(&pid) {
            return Some(context.clone());
        }

        // Cache miss - fetch from /proc
        if let Ok(context) = self.fetch_process_context(pid).await {
            // Update cache (no TTL, processes don't change much during tracing)
            self.cache.insert(pid, context.clone());
            Some(context)
        } else {
            None
        }
    }

    /// Fetch process context from /proc filesystem - simplified, no concurrency
    async fn fetch_process_context(&self, pid: u32) -> Result<ProcessContext> {
        // Read /proc files sequentially (simpler than managing concurrent futures)
        let exe_path = self.read_exe_path(pid);
        let cwd = self.read_cwd(pid);
        let argv = self.read_cmdline(pid);
        let (uid, gid, euid, egid, ppid) = self.read_status(pid);
        let fd_map = self.read_fd_map(pid);
        let capabilities = self.read_capabilities(pid);
        let namespaces = self.read_namespaces(pid);

        Ok(ProcessContext {
            exe_path,
            cwd,
            argv,
            uid,
            gid,
            ppid,
            euid,
            egid,
            fd_map,
            capabilities,
            namespaces,
        })
    }

    /// Read executable path from /proc/pid/exe
    fn read_exe_path(&self, pid: u32) -> Option<PathBuf> {
        let exe_link = format!("/proc/{}/exe", pid);
        fs::read_link(&exe_link).ok()
    }

    /// Read current working directory from /proc/pid/cwd
    fn read_cwd(&self, pid: u32) -> Option<PathBuf> {
        let cwd_link = format!("/proc/{}/cwd", pid);
        fs::read_link(&cwd_link).ok()
    }

    /// Read command line arguments from /proc/pid/cmdline
    fn read_cmdline(&self, pid: u32) -> Option<Vec<String>> {
        let cmdline_path = format!("/proc/{}/cmdline", pid);
        let content = fs::read_to_string(&cmdline_path).ok()?;
        
        if content.is_empty() {
            return None;
        }
        
        // Split by null bytes and filter empty strings
        let args: Vec<String> = content
            .split('\0')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
            
        if args.is_empty() {
            None
        } else {
            Some(args)
        }
    }

    /// Read UID, GID, EUID, EGID, and PPID from /proc/pid/status
    fn read_status(&self, pid: u32) -> (Option<u32>, Option<u32>, Option<u32>, Option<u32>, Option<u32>) {
        let status_path = format!("/proc/{}/status", pid);
        let content = match fs::read_to_string(&status_path) {
            Ok(c) => c,
            Err(_) => return (None, None, None, None, None),
        };

        let mut uid = None;
        let mut gid = None;
        let mut euid = None;
        let mut egid = None;
        let mut ppid = None;

        for line in content.lines() {
            if line.starts_with("Uid:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    uid = parts[1].parse().ok();  // Real UID
                }
                if parts.len() >= 3 {
                    euid = parts[2].parse().ok(); // Effective UID
                }
            } else if line.starts_with("Gid:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    gid = parts[1].parse().ok();  // Real GID
                }
                if parts.len() >= 3 {
                    egid = parts[2].parse().ok(); // Effective GID
                }
            } else if line.starts_with("PPid:") {
                if let Some(ppid_str) = line.split_whitespace().nth(1) {
                    ppid = ppid_str.parse().ok();
                }
            }
        }

        (uid, gid, euid, egid, ppid)
    }

    /// Read file descriptor mappings from /proc/pid/fd/
    fn read_fd_map(&self, pid: u32) -> HashMap<i32, String> {
        let fd_dir = format!("/proc/{}/fd", pid);
        let mut fd_map = HashMap::new();

        if let Ok(entries) = fs::read_dir(&fd_dir) {
            for entry in entries.flatten() {
                if let Some(fd_str) = entry.file_name().to_str() {
                    if let Ok(fd) = fd_str.parse::<i32>() {
                        if let Ok(target) = fs::read_link(entry.path()) {
                            fd_map.insert(fd, target.to_string_lossy().to_string());
                        }
                    }
                }
            }
        }

        fd_map
    }

    /// Read process capabilities from /proc/pid/status
    fn read_capabilities(&self, pid: u32) -> Option<String> {
        let status_path = format!("/proc/{}/status", pid);
        let content = fs::read_to_string(&status_path).ok()?;

        for line in content.lines() {
            if line.starts_with("CapEff:") {
                return line.split_whitespace().nth(1).map(|s| s.to_string());
            }
        }

        None
    }

    /// Read namespace information from /proc/pid/ns/
    fn read_namespaces(&self, pid: u32) -> HashMap<String, String> {
        let ns_dir = format!("/proc/{}/ns", pid);
        let mut namespaces = HashMap::new();

        if let Ok(entries) = fs::read_dir(&ns_dir) {
            for entry in entries.flatten() {
                if let Some(ns_name) = entry.file_name().to_str() {
                    if let Ok(target) = fs::read_link(entry.path()) {
                        namespaces.insert(ns_name.to_string(), target.to_string_lossy().to_string());
                    }
                }
            }
        }

        namespaces
    }

    /// Enhanced forensic data enrichment using /proc filesystem
    async fn enhance_forensic_data(&mut self, event: &mut SyscallEvent) {
        // Enhance process forensics with genealogy and session info
        if let Some(ref mut process_forensics) = event.process_forensics {
            self.enhance_process_forensics(process_forensics, event.pid).await;
        }
        
        // Enhance file forensics with inode, device, and metadata
        if let Some(ref mut file_forensics) = event.file_forensics {
            self.enhance_file_forensics(file_forensics).await;
        }
        
        // Enhance network forensics with socket state and DNS resolution
        if let Some(ref mut network_forensics) = event.network_forensics {
            self.enhance_network_forensics(network_forensics, event.pid).await;
        }
        
        // Enhance memory forensics with memory map information
        if let Some(ref mut memory_forensics) = event.memory_forensics {
            self.enhance_memory_forensics(memory_forensics, event.pid).await;
        }
        
        // Generate comprehensive forensic summary
        event.forensic_summary = self.generate_forensic_summary(event).await;
    }
    
    /// Enhance process forensics with genealogy and session information
    async fn enhance_process_forensics(&self, forensics: &mut ProcessForensics, pid: u32) {
        // Read process genealogy from /proc
        if let Ok(ancestry) = self.read_process_ancestry(pid).await {
            forensics.ancestry = ancestry;
        }
        
        // Read session and process group information
        if let Ok((pgid, sid)) = self.read_session_info(pid).await {
            forensics.pgid = pgid;
            forensics.sid = sid;
        }
        
        // Determine if this is a daemon process (detached from terminal)
        forensics.is_daemon = self.is_daemon_process(pid).await;
        
        // Read thread count
        forensics.thread_count = self.read_thread_count(pid).await;
        
        // Get process start time
        if let Ok(start_time) = self.read_process_start_time(pid).await {
            forensics.spawn_time = start_time;
        }
    }
    
    /// Enhance file forensics with detailed metadata
    async fn enhance_file_forensics(&self, forensics: &mut FileForensics) {
        let path = &forensics.absolute_path;
        
        // Get file metadata using stat
        if let Ok(metadata) = fs::metadata(path) {
            forensics.inode = Some(metadata.ino());
            forensics.device = Some(metadata.dev());
            
            // File size at current time
            if forensics.size_at_open.is_none() {
                forensics.size_at_open = Some(metadata.len());
            }
            
            // File timestamps
            if let Ok(modified) = metadata.modified() {
                if let Ok(duration) = modified.duration_since(UNIX_EPOCH) {
                    forensics.modification_time = Some(duration.as_secs());
                }
            }
            
            if let Ok(accessed) = metadata.accessed() {
                if let Ok(duration) = accessed.duration_since(UNIX_EPOCH) {
                    forensics.access_time = Some(duration.as_secs());
                }
            }
            
            // Determine file type from metadata
            forensics.file_type = if metadata.is_file() {
                FileType::Regular
            } else if metadata.is_dir() {
                FileType::Directory
            } else if metadata.is_symlink() {
                FileType::SymbolicLink
            } else {
                FileType::Unknown
            };
        }
    }
    
    /// Enhance network forensics with socket state and DNS information
    async fn enhance_network_forensics(&self, forensics: &mut NetworkForensics, pid: u32) {
        // Try to resolve socket information from /proc/net/tcp and /proc/net/udp
        if let Ok(socket_info) = self.read_socket_info(forensics.socket_fd, pid).await {
            forensics.socket_state = socket_info.state;
            if let Some(local) = socket_info.local_address {
                forensics.local_address = local;
            }
        }
        
        // Attempt DNS resolution for remote addresses
        if let Some(ref remote_addr) = forensics.remote_address {
            if let Ok(dns_info) = self.resolve_dns(&remote_addr.address).await {
                forensics.dns_resolution = Some(dns_info);
            }
        }
    }
    
    /// Enhance memory forensics with memory map information
    async fn enhance_memory_forensics(&self, forensics: &mut MemoryForensics, pid: u32) {
        // Read memory maps from /proc/pid/maps to understand mapping context
        if let Some(address) = forensics.address {
            if let Ok(mapping_info) = self.read_memory_mapping(pid, address).await {
                forensics.mapping_type = Some(mapping_info);
            }
        }
    }
    
    /// Generate comprehensive forensic summary
    async fn generate_forensic_summary(&self, event: &SyscallEvent) -> Option<String> {
        let mut summary_parts = Vec::new();
        
        // Process context summary
        if let Some(ref process) = event.process_forensics {
            if !process.ancestry.is_empty() {
                summary_parts.push(format!(
                    "Process ancestry: {} levels deep, session {}, group {}",
                    process.ancestry.len(), process.sid, process.pgid
                ));
            }
            if process.is_daemon {
                summary_parts.push("Daemon process (detached from terminal)".to_string());
            }
        }
        
        // File operation summary
        if let Some(ref file) = event.file_forensics {
            let operation = if file.open_flags.read && file.open_flags.write {
                "read-write access"
            } else if file.open_flags.write {
                "write access"
            } else {
                "read access"
            };
            
            summary_parts.push(format!(
                "File operation: {} to {} ({})",
                operation,
                file.absolute_path,
                file.open_flags.human_description
            ));
            
            if file.was_created {
                summary_parts.push("File was created during this operation".to_string());
            }
        }
        
        // Network operation summary
        if let Some(ref network) = event.network_forensics {
            if let Some(ref remote) = network.remote_address {
                summary_parts.push(format!(
                    "Network: {:?} connection to {}:{}",
                    network.protocol,
                    remote.address,
                    remote.port.unwrap_or(0)
                ));
                
                if let Some(ref dns) = network.dns_resolution {
                    if let Some(ref hostname) = dns.hostname {
                        summary_parts.push(format!("Resolved hostname: {}", hostname));
                    }
                }
            }
        }
        
        // Memory operation summary
        if let Some(ref memory) = event.memory_forensics {
            if let Some(size) = memory.size {
                summary_parts.push(format!(
                    "Memory: {:?} operation, {} bytes",
                    memory.operation_type, size
                ));
            }
            
            if let Some(ref protection) = memory.protection {
                summary_parts.push(format!(
                    "Memory protection: {}", protection.human_description
                ));
            }
        }
        
        // Permission analysis summary
        if let Some(ref permission) = event.permission_analysis {
            if !permission.security_implications.is_empty() {
                summary_parts.push(format!(
                    "Security implications: {}",
                    permission.security_implications.join(", ")
                ));
            }
        }
        
        if summary_parts.is_empty() {
            None
        } else {
            Some(summary_parts.join("; "))
        }
    }
    
    /// Read complete process ancestry chain
    async fn read_process_ancestry(&self, pid: u32) -> Result<Vec<ProcessAncestor>> {
        let mut ancestry = Vec::new();
        let mut current_pid = pid;
        let mut depth = 0;
        
        // Traverse up the process tree (limit depth to prevent infinite loops)
        while depth < 20 {
            if let Ok(ppid) = self.read_parent_pid(current_pid).await {
                if ppid == 0 || ppid == current_pid {
                    break; // Reached init or detected cycle
                }
                
                // Read parent process information
                if let Ok(command) = self.read_process_command(ppid).await {
                    if let Ok(start_time) = self.read_process_start_time(ppid).await {
                        ancestry.push(ProcessAncestor {
                            pid: ppid,
                            command,
                            start_time,
                        });
                    }
                }
                
                current_pid = ppid;
                depth += 1;
            } else {
                break;
            }
        }
        
        Ok(ancestry)
    }
    
    /// Read parent PID from /proc/pid/stat
    async fn read_parent_pid(&self, pid: u32) -> Result<u32> {
        let stat_path = format!("/proc/{}/stat", pid);
        let content = fs::read_to_string(&stat_path)?;
        
        // /proc/pid/stat format: pid (comm) state ppid ...
        // Need to handle command names with spaces/parentheses
        let parts: Vec<&str> = content.split_whitespace().collect();
        if parts.len() >= 4 {
            Ok(parts[3].parse()?)
        } else {
            Err(anyhow::anyhow!("Invalid stat format"))
        }
    }
    
    /// Read process command from /proc/pid/comm
    async fn read_process_command(&self, pid: u32) -> Result<String> {
        let comm_path = format!("/proc/{}/comm", pid);
        let content = fs::read_to_string(&comm_path)?;
        Ok(content.trim().to_string())
    }
    
    /// Read process start time from /proc/pid/stat
    async fn read_process_start_time(&self, pid: u32) -> Result<u64> {
        let stat_path = format!("/proc/{}/stat", pid);
        let content = fs::read_to_string(&stat_path)?;
        
        // Field 22 is starttime in clock ticks since boot
        let parts: Vec<&str> = content.split_whitespace().collect();
        if parts.len() >= 22 {
            let start_ticks: u64 = parts[21].parse()?;
            // Convert to seconds (assuming 100 ticks per second)
            Ok(start_ticks / 100)
        } else {
            Err(anyhow::anyhow!("Cannot read start time"))
        }
    }
    
    /// Read session and process group information
    async fn read_session_info(&self, pid: u32) -> Result<(u32, u32)> {
        let stat_path = format!("/proc/{}/stat", pid);
        let content = fs::read_to_string(&stat_path)?;
        
        let parts: Vec<&str> = content.split_whitespace().collect();
        if parts.len() >= 7 {
            let pgid: u32 = parts[4].parse()?; // Process group ID
            let sid: u32 = parts[5].parse()?;  // Session ID
            Ok((pgid, sid))
        } else {
            Err(anyhow::anyhow!("Cannot read session info"))
        }
    }
    
    /// Check if process is a daemon (detached from terminal)
    async fn is_daemon_process(&self, pid: u32) -> bool {
        // Check if process has a controlling terminal
        let stat_path = format!("/proc/{}/stat", pid);
        if let Ok(content) = fs::read_to_string(&stat_path) {
            let parts: Vec<&str> = content.split_whitespace().collect();
            if parts.len() >= 8 {
                // Field 7 is tty_nr (controlling terminal)
                if let Ok(tty_nr) = parts[6].parse::<i32>() {
                    return tty_nr == 0; // No controlling terminal = daemon
                }
            }
        }
        false
    }
    
    /// Read thread count from /proc/pid/status
    async fn read_thread_count(&self, pid: u32) -> u32 {
        let status_path = format!("/proc/{}/status", pid);
        if let Ok(content) = fs::read_to_string(&status_path) {
            for line in content.lines() {
                if line.starts_with("Threads:") {
                    if let Some(count_str) = line.split_whitespace().nth(1) {
                        if let Ok(count) = count_str.parse::<u32>() {
                            return count;
                        }
                    }
                }
            }
        }
        1 // Default to 1 thread
    }
    
    /// Read socket information from /proc/net/tcp and /proc/net/udp
    async fn read_socket_info(&self, socket_fd: i32, pid: u32) -> Result<SocketInfo> {
        // This is a simplified implementation
        // Real implementation would parse /proc/net/tcp, /proc/net/udp files
        // and match socket inodes to find socket state
        Ok(SocketInfo {
            state: SocketState::Unknown,
            local_address: None,
        })
    }
    
    /// Attempt DNS resolution for an IP address
    async fn resolve_dns(&self, ip_address: &str) -> Result<DnsInfo> {
        // Simplified DNS resolution - in practice would use proper DNS lookup
        Ok(DnsInfo {
            hostname: None,
            resolved_ips: vec![ip_address.to_string()],
            resolution_time: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
        })
    }
    
    /// Read memory mapping information from /proc/pid/maps
    async fn read_memory_mapping(&self, pid: u32, address: u64) -> Result<crate::model::MappingType> {
        let maps_path = format!("/proc/{}/maps", pid);
        let content = fs::read_to_string(&maps_path)?;
        
        for line in content.lines() {
            if let Some(mapping) = self.parse_memory_map_line(line, address) {
                return Ok(mapping);
            }
        }
        
        Ok(crate::model::MappingType::Anonymous)
    }
    
    /// Parse a single line from /proc/pid/maps
    fn parse_memory_map_line(&self, line: &str, target_address: u64) -> Option<crate::model::MappingType> {
        // Format: address perms offset dev inode pathname
        // Example: 7f1234567000-7f123456f000 r-xp 00000000 08:01 1234567 /lib/libc.so.6
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 6 {
            // Parse address range
            if let Some(range_parts) = parts[0].split('-').collect::<Vec<&str>>().get(0..2) {
                if let (Ok(start), Ok(end)) = (
                    u64::from_str_radix(range_parts[0], 16),
                    u64::from_str_radix(range_parts[1], 16)
                ) {
                    if target_address >= start && target_address < end {
                        // Check if it has a pathname (file-backed)
                        if parts.len() >= 6 && !parts[5].is_empty() {
                            return Some(crate::model::MappingType::FileBacked);
                        } else {
                            // Check permissions for shared vs private
                            let perms = parts[1];
                            if perms.chars().nth(3) == Some('s') {
                                return Some(crate::model::MappingType::Shared);
                            } else {
                                return Some(crate::model::MappingType::Private);
                            }
                        }
                    }
                }
            }
        }
        None
    }
}

/// Helper struct for socket information
#[derive(Debug)]
struct SocketInfo {
    state: SocketState,
    local_address: Option<SocketAddress>,
}

/// Run enricher with ready synchronization
pub async fn run_with_ready(
    enricher: Enricher,
    rx_evt: Receiver<SyscallEvent>,
    tx_enriched: Sender<SyscallEvent>,
    ready_tx: mpsc::Sender<()>,
) -> Result<()> {
    // Signal we're ready to receive data
    ready_tx.send(()).await.ok();
    
    // Run the enricher
    enricher.run(rx_evt, tx_enriched).await
}

/// Run enricher with ready synchronization and cancellation support
pub async fn run_with_ready_and_cancellation(
    enricher: Enricher,
    rx_evt: Receiver<SyscallEvent>,
    tx_enriched: Sender<SyscallEvent>,
    ready_tx: mpsc::Sender<()>,
    cancellation_token: CancellationToken,
) -> Result<()> {
    // Signal we're ready to receive data
    ready_tx.send(()).await.ok();
    
    // Run the enricher with cancellation support
    enricher.run_with_cancellation(rx_evt, tx_enriched, cancellation_token).await
}