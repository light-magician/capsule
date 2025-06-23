use crate::model::{ProcessContext, SyscallEvent};
use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::time::{Duration, Instant};
use tokio::sync::broadcast::{Receiver, Sender};
use tokio::sync::{mpsc, Semaphore};
use tokio::time;
use tokio_util::sync::CancellationToken;

/// Cache entry for process context data
#[derive(Debug, Clone)]
struct CacheEntry {
    context: ProcessContext,
    expires_at: Instant,
}

/// Context enricher that adds /proc metadata to syscall events
pub struct Enricher {
    cache: HashMap<u32, CacheEntry>,
    cache_ttl: Duration,
    lookup_semaphore: Semaphore,
}

impl Enricher {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
            cache_ttl: Duration::from_secs(5), // 5 second TTL
            lookup_semaphore: Semaphore::new(10), // Limit concurrent /proc lookups
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
        let mut cleanup_interval = time::interval(Duration::from_secs(10));

        loop {
            tokio::select! {
                // Process incoming events
                event_result = rx_evt.recv() => {
                    match event_result {
                        Ok(mut event) => {
                            // Enrich the event with process context directly in SyscallEvent fields
                            match self.get_process_context(event.pid).await {
                                Ok(context) => {
                                    eprintln!("DEBUG: Enricher successfully got context for PID {}: exe={:?}, uid={:?}", 
                                             event.pid, context.exe_path, context.uid);
                                    self.populate_event_fields(&mut event, &context);
                                    // Keep legacy field for backward compatibility during transition
                                    event.enrichment = Some(context);
                                },
                                Err(e) => {
                                    eprintln!("DEBUG: Enricher failed to get context for PID {}: {}", event.pid, e);
                                }
                            }
                            let _ = tx_enriched.send(event);
                        },
                        Err(_) => break, // Channel closed
                    }
                },
                
                // Periodic cache cleanup
                _ = cleanup_interval.tick() => {
                    self.cleanup_expired_entries();
                },
                
                // Graceful shutdown signal
                _ = cancellation_token.cancelled() => {
                    println!("Enricher received cancellation, cleaning up cache...");
                    self.cache.clear();
                    break;
                }
            }
        }
        
        Ok(())
    }

    /// Populate SyscallEvent fields directly from ProcessContext
    fn populate_event_fields(&self, event: &mut SyscallEvent, context: &ProcessContext) {
        // Convert ProcessContext data to EnhancedEvent fields
        event.ppid = context.ppid;
        event.exe_path = context.exe_path.as_ref().map(|p| p.to_string_lossy().to_string());
        event.cwd = context.cwd.as_ref().map(|p| p.to_string_lossy().to_string());
        event.uid = context.uid;
        event.gid = context.gid;
        event.euid = context.euid;
        event.egid = context.egid;
        
        // Parse capabilities from hex string to u64 bitmap
        event.caps = context.capabilities.as_ref()
            .and_then(|cap_str| u64::from_str_radix(cap_str, 16).ok());
        
        // Note: fd mapping and namespace info is in legacy ProcessContext for now
    }

    /// Get process context for a PID, using cache when available
    async fn get_process_context(&mut self, pid: u32) -> Result<ProcessContext> {
        let now = Instant::now();
        
        // Check cache first
        if let Some(entry) = self.cache.get(&pid) {
            if now < entry.expires_at {
                return Ok(entry.context.clone());
            }
        }

        // Cache miss or expired - fetch from /proc
        let _permit = self.lookup_semaphore.acquire().await?;
        let context = self.fetch_process_context(pid).await?;
        
        // Update cache
        self.cache.insert(pid, CacheEntry {
            context: context.clone(),
            expires_at: now + self.cache_ttl,
        });
        
        Ok(context)
    }

    /// Fetch process context from /proc filesystem
    async fn fetch_process_context(&self, pid: u32) -> Result<ProcessContext> {
        let proc_path = format!("/proc/{}", pid);
        
        // Read various /proc files concurrently
        let exe_path = self.read_exe_path(pid).await;
        let cwd = self.read_cwd(pid).await;
        let argv = self.read_cmdline(pid).await;
        let (uid, gid, euid, egid, ppid) = self.read_status(pid).await;
        let fd_map = self.read_fd_map(pid).await;
        let capabilities = self.read_capabilities(pid).await;
        let namespaces = self.read_namespaces(pid).await;

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
    async fn read_exe_path(&self, pid: u32) -> Option<PathBuf> {
        let exe_link = format!("/proc/{}/exe", pid);
        fs::read_link(&exe_link).ok()
    }

    /// Read current working directory from /proc/pid/cwd
    async fn read_cwd(&self, pid: u32) -> Option<PathBuf> {
        let cwd_link = format!("/proc/{}/cwd", pid);
        fs::read_link(&cwd_link).ok()
    }

    /// Read command line arguments from /proc/pid/cmdline
    async fn read_cmdline(&self, pid: u32) -> Option<Vec<String>> {
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
    async fn read_status(&self, pid: u32) -> (Option<u32>, Option<u32>, Option<u32>, Option<u32>, Option<u32>) {
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
    async fn read_fd_map(&self, pid: u32) -> HashMap<i32, String> {
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
    async fn read_capabilities(&self, pid: u32) -> Option<String> {
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
    async fn read_namespaces(&self, pid: u32) -> HashMap<String, String> {
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

    /// Remove expired entries from the cache
    fn cleanup_expired_entries(&mut self) {
        let now = Instant::now();
        self.cache.retain(|_, entry| now < entry.expires_at);
    }
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