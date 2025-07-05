//! Human-readable action watcher with intelligent collapsing of repeated actions.

use crate::model::{Action, ActionKind};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use crossterm::{
    event::{self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Margin},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, List, ListItem, Paragraph},
    Frame, Terminal,
};
use std::{
    collections::{HashMap, VecDeque},
    fs::{File, OpenOptions},
    io::{self, BufRead, BufReader, Stdout, Write},
    path::PathBuf,
    thread,
    time::{Duration, Instant},
};

/// Configuration for the watch command
pub struct WatchConfig {
    pub run_uuid: Option<String>,
    pub follow: bool,
    pub interval: u64,
    pub security_only: bool,
    pub pid_filter: Option<u32>,
}

/// Efficient sliding window buffer for managing large action lists
pub struct ActionBuffer {
    actions: VecDeque<DisplayedAction>,
    max_size: usize,
    total_actions_seen: u64,
    oldest_action_index: u64,
}

impl ActionBuffer {
    pub fn new(max_size: usize) -> Self {
        Self {
            actions: VecDeque::new(),
            max_size,
            total_actions_seen: 0,
            oldest_action_index: 0,
        }
    }

    /// Add a new action, potentially evicting old ones
    pub fn add_action(&mut self, action: DisplayedAction) {
        self.actions.push_back(action);
        self.total_actions_seen += 1;

        // Evict old actions if we exceed max size
        if self.actions.len() > self.max_size {
            self.actions.pop_front();
            self.oldest_action_index += 1;
        }
    }

    /// Update the last action if it matches, otherwise add new action
    pub fn add_or_update_action(&mut self, action: DisplayedAction) {
        if let Some(last_action) = self.actions.back_mut() {
            if last_action.action_signature == action.action_signature {
                last_action.count += action.count;
                last_action.last_seen = action.last_seen;
                last_action.last_display_content = action.last_display_content;
                return;
            }
        }
        self.add_action(action);
    }

    /// Get slice of actions for display
    pub fn get_actions(&self) -> &VecDeque<DisplayedAction> {
        &self.actions
    }

    /// Get total number of actions ever seen
    pub fn total_actions(&self) -> u64 {
        self.total_actions_seen
    }

    /// Get the number of actions currently in buffer
    pub fn current_size(&self) -> usize {
        self.actions.len()
    }

    /// Get the global index of the first action in buffer
    pub fn oldest_index(&self) -> u64 {
        self.oldest_action_index
    }
}

/// Scroll state management for the TUI
pub struct ScrollState {
    pub auto_scroll: bool,
    pub user_scroll_position: usize,
    pub last_user_interaction: Instant,
    pub auto_scroll_timeout: Duration,
    pub viewport_height: usize,
}

impl ScrollState {
    pub fn new() -> Self {
        Self {
            auto_scroll: true,
            user_scroll_position: 0,
            last_user_interaction: Instant::now(),
            auto_scroll_timeout: Duration::from_secs(30),
            viewport_height: 0,
        }
    }

    /// Handle user scroll input
    pub fn handle_scroll(&mut self, scroll_delta: i32, total_items: usize) {
        self.last_user_interaction = Instant::now();
        
        if scroll_delta > 0 {
            // Scroll up
            self.auto_scroll = false;
            self.user_scroll_position = self.user_scroll_position.saturating_sub(scroll_delta as usize);
        } else if scroll_delta < 0 {
            // Scroll down
            let scroll_amount = (-scroll_delta) as usize;
            self.user_scroll_position = (self.user_scroll_position + scroll_amount).min(total_items.saturating_sub(self.viewport_height));
            
            // If user scrolled to bottom, re-enable auto-scroll
            if self.user_scroll_position + self.viewport_height >= total_items {
                self.auto_scroll = true;
            }
        }
    }

    /// Update scroll position for auto-scroll mode
    pub fn update_auto_scroll(&mut self, total_items: usize) {
        // Re-enable auto-scroll after timeout
        if !self.auto_scroll && self.last_user_interaction.elapsed() >= self.auto_scroll_timeout {
            self.auto_scroll = true;
        }

        // Auto-scroll to bottom in auto-scroll mode
        if self.auto_scroll {
            self.user_scroll_position = total_items.saturating_sub(self.viewport_height);
        }
    }

    /// Get the current scroll position
    pub fn get_scroll_position(&self) -> usize {
        self.user_scroll_position
    }

    /// Set viewport height for calculating scroll positions
    pub fn set_viewport_height(&mut self, height: usize) {
        self.viewport_height = height;
    }
}

/// State for the watch TUI application
pub struct WatchApp {
    pub config: WatchConfig,
    pub action_buffer: ActionBuffer,
    pub scroll_state: ScrollState,
    pub should_quit: bool,
    pub file_reader: Option<BufReader<File>>,
    pub log_file_path: Option<PathBuf>,
    pub watch_file_writer: Option<File>,
    pub last_update: Instant,
    pub total_actions: u64,
    pub filtered_actions: u64,
}

/// A displayed action with collapsing information
#[derive(Debug, Clone)]
pub struct DisplayedAction {
    pub action_signature: ActionSignature,
    pub count: usize,
    pub first_seen: u64,
    pub last_seen: u64,
    pub first_pids: Vec<u32>,
    pub last_display_content: String,
    pub action_kind: ActionKind,
}

/// Signature for comparing actions to determine if they should be collapsed
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ActionSignature {
    pub kind_discriminant: String,
    pub syscall: Option<String>,
    pub path: Option<String>,
    pub primary_pid: u32,
}

impl ActionSignature {
    /// Create a signature from an Action for comparison
    pub fn from_action(action: &Action) -> Self {
        let (kind_discriminant, syscall, path) = match &action.kind {
            ActionKind::FileRead { path, .. } => ("FileRead".to_string(), None, Some(path.display().to_string())),
            ActionKind::FileWrite { path, .. } => ("FileWrite".to_string(), None, Some(path.display().to_string())),
            ActionKind::FileOpen { path, .. } => ("FileOpen".to_string(), None, Some(path.display().to_string())),
            ActionKind::FileClose { path } => ("FileClose".to_string(), None, Some(path.display().to_string())),
            ActionKind::FileStat { path } => ("FileStat".to_string(), None, Some(path.display().to_string())),
            ActionKind::FileChmod { path, .. } => ("FileChmod".to_string(), None, Some(path.display().to_string())),
            ActionKind::FileChown { path, .. } => ("FileChown".to_string(), None, Some(path.display().to_string())),
            ActionKind::DirectoryList { path, .. } => ("DirectoryList".to_string(), None, Some(path.display().to_string())),
            ActionKind::ProcessSpawn { pid, .. } => ("ProcessSpawn".to_string(), None, Some(pid.to_string())),
            ActionKind::ProcessExec { .. } => ("ProcessExec".to_string(), None, None),
            ActionKind::ProcessExit { pid, .. } => ("ProcessExit".to_string(), None, Some(pid.to_string())),
            ActionKind::SocketConnect { addr, protocol, .. } => ("SocketConnect".to_string(), None, Some(format!("{}:{}", addr, protocol))),
            ActionKind::SocketBind { addr, protocol, .. } => ("SocketBind".to_string(), None, Some(format!("{}:{}", addr, protocol))),
            ActionKind::SocketAccept { .. } => ("SocketAccept".to_string(), None, None),
            ActionKind::SignalSend { target_pid, signal } => ("SignalSend".to_string(), None, Some(format!("{}:{}", target_pid, signal))),
            ActionKind::SignalReceive { signal } => ("SignalReceive".to_string(), None, Some(signal.to_string())),
            ActionKind::MemoryMap { .. } => ("MemoryMap".to_string(), None, None),
            ActionKind::MemoryUnmap { .. } => ("MemoryUnmap".to_string(), None, None),
            ActionKind::Other { syscall, .. } => ("Other".to_string(), Some(syscall.clone()), None),
        };

        let primary_pid = action.pids.first().copied().unwrap_or(0);

        Self {
            kind_discriminant,
            syscall,
            path,
            primary_pid,
        }
    }
}

impl DisplayedAction {
    /// Create a new displayed action from an Action
    pub fn from_action(action: Action) -> Self {
        let signature = ActionSignature::from_action(&action);
        let display_content = format_action_display(&action, 1);
        
        Self {
            action_signature: signature,
            count: 1,
            first_seen: action.first_ts,
            last_seen: action.last_ts,
            first_pids: action.pids.to_vec(),
            last_display_content: display_content,
            action_kind: action.kind,
        }
    }

    /// Update this displayed action with a new occurrence
    pub fn update_with_action(&mut self, action: Action) {
        self.count += 1;
        self.last_seen = action.last_ts;
        self.last_display_content = format_action_display(&action, self.count);
    }

    /// Check if this displayed action matches the given action
    pub fn matches_action(&self, action: &Action) -> bool {
        let new_signature = ActionSignature::from_action(action);
        self.action_signature == new_signature
    }
}

/// Format an action for display with emoji and human-readable text
pub fn format_action_display(action: &Action, count: usize) -> String {
    let timestamp = format_timestamp(action.first_ts);
    let emoji = get_action_emoji(&action.kind);
    let primary_pid = action.pids.first().copied().unwrap_or(0);
    
    let (action_name, details) = match &action.kind {
        ActionKind::FileRead { path, bytes } => {
            ("FileRead".to_string(), format!("Read {} bytes from {}", bytes, path.display()))
        }
        ActionKind::FileWrite { path, bytes } => {
            ("FileWrite".to_string(), format!("Write {} bytes to {}", bytes, path.display()))
        }
        ActionKind::FileOpen { path, flags } => {
            ("FileOpen".to_string(), format!("Open {} ({})", path.display(), flags))
        }
        ActionKind::FileClose { path } => {
            ("FileClose".to_string(), format!("Close {}", path.display()))
        }
        ActionKind::FileStat { path } => {
            ("FileStat".to_string(), format!("Stat {}", path.display()))
        }
        ActionKind::FileChmod { path, mode } => {
            ("FileChmod".to_string(), format!("Chmod {} to {:o}", path.display(), mode))
        }
        ActionKind::FileChown { path, uid, gid } => {
            ("FileChown".to_string(), format!("Chown {} to {}:{}", path.display(), uid, gid))
        }
        ActionKind::DirectoryList { path, entries } => {
            ("DirectoryList".to_string(), format!("List {} ({} entries)", path.display(), entries))
        }
        ActionKind::ProcessSpawn { pid, argv, parent_pid } => {
            ("ProcessSpawn".to_string(), format!("Spawn PID {} (parent: {}) -> {}", pid, parent_pid, argv.join(" ")))
        }
        ActionKind::ProcessExec { argv } => {
            ("ProcessExec".to_string(), format!("Exec {}", argv.join(" ")))
        }
        ActionKind::ProcessExit { pid, exit_code } => {
            ("ProcessExit".to_string(), format!("Process {} exited with code {}", pid, exit_code))
        }
        ActionKind::SocketConnect { addr, protocol } => {
            ("SocketConnect".to_string(), format!("Connect to {} ({})", addr, protocol))
        }
        ActionKind::SocketBind { addr, protocol } => {
            ("SocketBind".to_string(), format!("Bind to {} ({})", addr, protocol))
        }
        ActionKind::SocketAccept { local_addr, remote_addr } => {
            ("SocketAccept".to_string(), format!("Accept {} -> {}", remote_addr, local_addr))
        }
        ActionKind::SignalSend { target_pid, signal } => {
            ("SignalSend".to_string(), format!("Send signal {} to PID {}", signal, target_pid))
        }
        ActionKind::SignalReceive { signal } => {
            ("SignalReceive".to_string(), format!("Receive signal {}", signal))
        }
        ActionKind::MemoryMap { addr, size, prot } => {
            ("MemoryMap".to_string(), format!("Map {}KB at 0x{:x} ({})", size / 1024, addr, prot))
        }
        ActionKind::MemoryUnmap { addr, size } => {
            ("MemoryUnmap".to_string(), format!("Unmap {}KB at 0x{:x}", size / 1024, addr))
        }
        ActionKind::Other { syscall, describe } => {
            ("Other".to_string(), format!("{}: {}", syscall, describe))
        }
    };

    let count_display = if count > 1 {
        format!(" [×{}]", count)
    } else {
        String::new()
    };

    format!(
        "{} {} {}: {} (PID: {}){}",
        timestamp, emoji, action_name, details, primary_pid, count_display
    )
}

/// Get emoji for action type
pub fn get_action_emoji(kind: &ActionKind) -> &'static str {
    match kind {
        ActionKind::FileRead { .. } => "📖",
        ActionKind::FileWrite { .. } => "📝",
        ActionKind::FileOpen { .. } => "📂",
        ActionKind::FileClose { .. } => "📁",
        ActionKind::FileStat { .. } => "🔍",
        ActionKind::FileChmod { .. } => "🔒",
        ActionKind::FileChown { .. } => "👤",
        ActionKind::DirectoryList { .. } => "📋",
        ActionKind::ProcessSpawn { .. } => "🆕",
        ActionKind::ProcessExec { .. } => "🚀",
        ActionKind::ProcessExit { .. } => "🏁",
        ActionKind::SocketConnect { .. } => "🌐",
        ActionKind::SocketBind { .. } => "🔗",
        ActionKind::SocketAccept { .. } => "👋",
        ActionKind::SignalSend { .. } => "📡",
        ActionKind::SignalReceive { .. } => "📨",
        ActionKind::MemoryMap { .. } => "🧠",
        ActionKind::MemoryUnmap { .. } => "🧠",
        ActionKind::Other { syscall, .. } => match syscall.as_str() {
            "ioctl" => "🔧",
            "epoll_ctl" => "⏳",
            "epoll_pwait" => "⌛",
            "fcntl" => "🔧",
            _ => "⚙️",
        },
    }
}

/// Format timestamp from microseconds to HH:MM:SS.mmm
pub fn format_timestamp(ts_us: u64) -> String {
    let seconds = ts_us / 1_000_000;
    let microseconds = ts_us % 1_000_000;
    let milliseconds = microseconds / 1000;
    
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    let seconds = seconds % 60;
    
    format!("[{:02}:{:02}:{:02}.{:03}]", hours, minutes, seconds, milliseconds)
}

/// Parse a log line to extract the JSON action
pub fn parse_log_line(line: &str) -> Result<Action> {
    // Log format: "<hash> <json>"
    // Find the first space to separate hash from JSON
    let space_pos = line.find(' ')
        .ok_or_else(|| anyhow::anyhow!("Invalid log line format: no space separator"))?;
    
    let json_part = &line[space_pos + 1..];
    let action: Action = serde_json::from_str(json_part)
        .with_context(|| format!("Failed to parse JSON: {}", json_part))?;
    
    Ok(action)
}

impl WatchApp {
    /// Create a new watch application
    pub fn new(config: WatchConfig) -> Self {
        Self {
            config,
            action_buffer: ActionBuffer::new(10_000), // Keep last 10k actions
            scroll_state: ScrollState::new(),
            should_quit: false,
            file_reader: None,
            log_file_path: None,
            watch_file_writer: None,
            last_update: Instant::now(),
            total_actions: 0,
            filtered_actions: 0,
        }
    }

    /// Initialize the log file for reading and create watch.jsonl file
    pub fn init_log_file(&mut self, log_file_path: PathBuf) -> Result<()> {
        let file = File::open(&log_file_path)
            .with_context(|| format!("Failed to open log file: {:?}", log_file_path))?;
        self.file_reader = Some(BufReader::new(file));
        
        // Create watch.jsonl file in the same directory
        if let Some(parent_dir) = log_file_path.parent() {
            let watch_file_path = parent_dir.join("watch.jsonl");
            let watch_file = OpenOptions::new()
                .create(true)
                .append(true)
                .open(&watch_file_path)
                .with_context(|| format!("Failed to create watch file: {:?}", watch_file_path))?;
            self.watch_file_writer = Some(watch_file);
        }
        
        self.log_file_path = Some(log_file_path);
        Ok(())
    }

    /// Process new lines from the log file
    pub fn process_new_lines(&mut self) -> Result<usize> {
        let mut lines_processed = 0;
        let mut parsed_actions = Vec::new();
        
        // First, read all lines and parse actions (without accessing other self fields)
        if let Some(reader) = &mut self.file_reader {
            let mut line = String::new();
            while reader.read_line(&mut line)? > 0 {
                if let Ok(action) = parse_log_line(line.trim()) {
                    parsed_actions.push(action);
                }
                line.clear();
            }
        }
        
        // Now process all parsed actions (can access all self fields freely)
        for action in parsed_actions {
            self.total_actions += 1;
            
            // Apply filters
            if self.should_filter_action(&action) {
                self.filtered_actions += 1;
            } else {
                self.process_action(action);
                lines_processed += 1;
            }
        }
        
        Ok(lines_processed)
    }

    /// Check if an action should be filtered out
    fn should_filter_action(&self, action: &Action) -> bool {
        // Filter by PID if specified
        if let Some(filter_pid) = self.config.pid_filter {
            if !action.pids.contains(&filter_pid) {
                return true;
            }
        }

        // Security filter (placeholder - would need risk analysis integration)
        if self.config.security_only {
            // For now, keep all actions since we don't have risk analysis integrated
            // In the future, this would check for risk_tags or security-relevant actions
        }

        false
    }

    /// Process a single action, either adding it or updating existing one
    fn process_action(&mut self, action: Action) {
        let displayed_action = DisplayedAction::from_action(action.clone());
        
        // Write to watch.jsonl file
        if let Some(writer) = &mut self.watch_file_writer {
            if let Err(e) = writeln!(writer, "{}", displayed_action.last_display_content) {
                eprintln!("Failed to write to watch.jsonl: {}", e);
            }
        }
        
        // Add to sliding window buffer
        self.action_buffer.add_or_update_action(displayed_action);
    }

    /// Handle key events
    pub fn handle_key_event(&mut self, key: event::KeyEvent) {
        if key.kind == KeyEventKind::Press {
            match key.code {
                KeyCode::Char('q') | KeyCode::Esc => {
                    self.should_quit = true;
                }
                KeyCode::Char('c') if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                    self.should_quit = true;
                }
                KeyCode::Up => {
                    self.scroll_state.handle_scroll(1, self.action_buffer.current_size());
                }
                KeyCode::Down => {
                    self.scroll_state.handle_scroll(-1, self.action_buffer.current_size());
                }
                KeyCode::PageUp => {
                    self.scroll_state.handle_scroll(10, self.action_buffer.current_size());
                }
                KeyCode::PageDown => {
                    self.scroll_state.handle_scroll(-10, self.action_buffer.current_size());
                }
                KeyCode::Home => {
                    self.scroll_state.user_scroll_position = 0;
                    self.scroll_state.auto_scroll = false;
                    self.scroll_state.last_user_interaction = Instant::now();
                }
                KeyCode::End => {
                    let total_items = self.action_buffer.current_size();
                    self.scroll_state.user_scroll_position = total_items.saturating_sub(self.scroll_state.viewport_height);
                    self.scroll_state.auto_scroll = true;
                }
                _ => {}
            }
        }
    }

    /// Handle mouse events
    pub fn handle_mouse_event(&mut self, mouse: event::MouseEvent) {
        match mouse.kind {
            event::MouseEventKind::ScrollUp => {
                self.scroll_state.handle_scroll(3, self.action_buffer.current_size());
            }
            event::MouseEventKind::ScrollDown => {
                self.scroll_state.handle_scroll(-3, self.action_buffer.current_size());
            }
            _ => {}
        }
    }

    /// Update the application state
    pub fn update(&mut self) -> Result<()> {
        if self.config.follow {
            // Only process new lines if enough time has passed
            if self.last_update.elapsed() >= Duration::from_millis(self.config.interval) {
                self.process_new_lines()?;
                self.last_update = Instant::now();
            }
        }
        
        // Update scroll state for auto-scrolling
        let total_items = self.action_buffer.current_size();
        self.scroll_state.update_auto_scroll(total_items);
        
        Ok(())
    }

    /// Render the TUI
    pub fn render(&mut self, frame: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(3), // Header
                Constraint::Min(0),    // Action list
                Constraint::Length(2), // Footer
            ])
            .split(frame.size());

        // Update viewport height for scroll calculations
        let viewport_height = chunks[1].height.saturating_sub(2) as usize; // Account for borders
        self.scroll_state.set_viewport_height(viewport_height);

        // Header
        let scroll_info = if self.scroll_state.auto_scroll {
            "Auto-scroll: ON".to_string()
        } else {
            format!("Auto-scroll: OFF ({}s timeout)", 
                self.scroll_state.auto_scroll_timeout.as_secs() - 
                self.scroll_state.last_user_interaction.elapsed().as_secs().min(self.scroll_state.auto_scroll_timeout.as_secs()))
        };
        
        let header_text = format!(
            "Capsule Watch - Total: {} | Buffer: {}/{} | Filtered: {} | {}",
            self.action_buffer.total_actions(),
            self.action_buffer.current_size(),
            10_000, // max buffer size
            self.filtered_actions,
            scroll_info
        );
        let header = Paragraph::new(header_text)
            .block(Block::default().borders(Borders::ALL).title("Status"))
            .style(Style::default().fg(Color::Yellow));
        frame.render_widget(header, chunks[0]);

        // Action list with scrolling
        let total_items = self.action_buffer.current_size();
        let scroll_pos = self.scroll_state.get_scroll_position();
        
        let items: Vec<ListItem> = self.action_buffer.get_actions()
            .iter()
            .skip(scroll_pos)
            .take(viewport_height)
            .map(|action| {
                let content = Line::from(vec![
                    Span::styled(
                        action.last_display_content.clone(),
                        Style::default().fg(Color::White)
                    )
                ]);
                ListItem::new(content)
            })
            .collect();

        let scroll_indicator = if total_items > viewport_height {
            format!(" ({}/{})", scroll_pos + items.len(), total_items)
        } else {
            String::new()
        };

        let list = List::new(items)
            .block(Block::default().borders(Borders::ALL).title(format!("Actions{}", scroll_indicator)))
            .style(Style::default().fg(Color::White));
        frame.render_widget(list, chunks[1]);

        // Footer
        let footer_text = if self.config.follow {
            "Press 'q' to quit | Mouse/trackpad to scroll | Following live updates..."
        } else {
            "Press 'q' to quit | Mouse/trackpad to scroll | Static view"
        };
        let footer = Paragraph::new(footer_text)
            .block(Block::default().borders(Borders::ALL))
            .style(Style::default().fg(Color::Gray));
        frame.render_widget(footer, chunks[2]);
    }
}

/// Main entry point for the watch command
pub fn run_watch(config: WatchConfig) -> Result<()> {
    // Determine which run to watch
    let run_path = match &config.run_uuid {
        Some(uuid) => crate::constants::RUN_ROOT.join(uuid),
        None => crate::tail::newest_run_dir()?,
    };

    // Read the actual log directory from metadata file
    let log_dir = read_log_dir_from_run(&run_path)?;
    let log_file_path = log_dir.join(crate::constants::ACTION_FILE);

    println!("Watching actions from: {:?}", log_file_path);

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app and initialize log file
    let mut app = WatchApp::new(config);
    app.init_log_file(log_file_path)?;

    // If not following, read all existing lines first
    if !app.config.follow {
        app.process_new_lines()?;
    }

    // Main event loop
    let result = run_event_loop(&mut terminal, &mut app);

    // Restore terminal
    disable_raw_mode()?;
    execute!(
        terminal.backend_mut(),
        LeaveAlternateScreen,
        DisableMouseCapture
    )?;
    terminal.show_cursor()?;

    result
}

/// Run the main event loop
fn run_event_loop(
    terminal: &mut Terminal<CrosstermBackend<Stdout>>,
    app: &mut WatchApp,
) -> Result<()> {
    loop {
        // Render the current state
        terminal.draw(|f| app.render(f))?;

        // Handle events with timeout for live updates
        let timeout = Duration::from_millis(app.config.interval);
        if event::poll(timeout)? {
            match event::read()? {
                Event::Key(key) => {
                    app.handle_key_event(key);
                    if app.should_quit {
                        break;
                    }
                }
                Event::Mouse(mouse) => {
                    app.handle_mouse_event(mouse);
                }
                Event::Resize(_, _) => {
                    // Terminal was resized, will be handled on next render
                }
                _ => {}
            }
        }

        // Update app state
        app.update()?;
    }

    Ok(())
}

/// Read the log directory path from the run directory's metadata file.
fn read_log_dir_from_run(run_path: &std::path::Path) -> Result<std::path::PathBuf> {
    let metadata_path = run_path.join(crate::constants::LOG_DIR_FILE);
    let log_dir_str = std::fs::read_to_string(&metadata_path)
        .with_context(|| format!("read log directory metadata from {:?}", metadata_path))?;
    
    Ok(std::path::PathBuf::from(log_dir_str.trim()))
}