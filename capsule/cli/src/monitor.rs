//! Live process monitoring TUI using ratatui
//!
//! Shows real-time process list with keyboard navigation

use crate::ipc::StateClient;
use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    prelude::*,
    style::{Color, Modifier, Style},
    widgets::{Block, Borders, List, ListItem, ListState, Paragraph, Wrap},
};
use state::{AgentState, LiveProcess};
use std::io;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// TUI application state
struct MonitorApp {
    /// Shared agent state from tracker
    agent_state: Arc<RwLock<AgentState>>,
    /// List selection and scroll state
    list_state: ListState,
    /// Syscall scroll position (line offset)
    syscall_scroll: u16,
    /// Whether to quit the app
    should_quit: bool,
    /// Auto-refresh interval
    refresh_rate: Duration,
    /// Last refresh time for auto-update
    last_refresh: Instant,
    /// Auto-scroll mode for syscalls
    auto_scroll: bool,
}

impl MonitorApp {
    /// Create new monitor app with shared state
    fn new(agent_state: Arc<RwLock<AgentState>>) -> Self {
        Self {
            agent_state,
            list_state: ListState::default(),
            syscall_scroll: 0,
            should_quit: false,
            refresh_rate: Duration::from_millis(500), // 2 FPS refresh
            last_refresh: Instant::now(),
            auto_scroll: true, // Start with auto-scroll enabled
        }
    }

    /// Handle keyboard input
    fn handle_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return true,
            // Process list navigation (left column)
            KeyCode::Up => self.list_state.select_previous(),
            KeyCode::Down => self.list_state.select_next(),
            // Syscall scrolling (right column)
            KeyCode::PageUp => {
                self.auto_scroll = false;
                self.syscall_scroll = self.syscall_scroll.saturating_sub(10);
            }
            KeyCode::PageDown => {
                self.auto_scroll = false;
                self.syscall_scroll = self.syscall_scroll.saturating_add(10);
            }
            KeyCode::Home => {
                self.auto_scroll = false;
                self.syscall_scroll = 0;
            }
            KeyCode::End => {
                self.auto_scroll = true; // Re-enable auto-scroll when going to end
                self.syscall_scroll = 0; // Will be set to max in draw()
            }
            KeyCode::Char(' ') => {
                // Toggle auto-scroll
                self.auto_scroll = !self.auto_scroll;
            }
            KeyCode::Char('r') => self.force_refresh(),
            _ => {}
        }
        false
    }

    /// Force immediate refresh
    fn force_refresh(&mut self) {
        self.last_refresh = Instant::now() - self.refresh_rate;
    }

    /// Check if we need to auto-refresh
    fn should_refresh(&self) -> bool {
        self.last_refresh.elapsed() >= self.refresh_rate
    }

    /// Update refresh timestamp
    fn mark_refreshed(&mut self) {
        self.last_refresh = Instant::now();
    }

    /// Draw the TUI
    fn draw(&mut self, frame: &mut Frame) {
        let area = frame.area();

        // Split into two columns: 40% processes, 60% syscalls (wider to fit columns)
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(area);

        // Read current state (non-blocking)
        let (processes, process_count, syscalls) = match self.agent_state.try_read() {
            Ok(state) => {
                let sorted_processes = state.processes_by_state();
                let count = sorted_processes.len();
                let process_items = create_process_state_items(&sorted_processes);
                let syscall_lines: Vec<String> =
                    state.recent_syscalls().into_iter().cloned().collect();
                (process_items, count, syscall_lines)
            }
            Err(_) => {
                // State locked, show placeholder
                (vec![ListItem::new("Loading...")], 0, vec![])
            }
        };

        // Left column: Process list
        let process_title = format!(" Processes ({}) ", process_count);
        let process_list = List::new(processes)
            .block(Block::default().title(process_title).borders(Borders::ALL))
            .highlight_symbol("> ");
        frame.render_stateful_widget(process_list, chunks[0], &mut self.list_state);

        // Right column: Syscall stream
        let (syscall_text, _scroll_pos) = if syscalls.is_empty() {
            ("Waiting for syscalls...".to_string(), 0)
        } else {
            // Calculate scroll position
            let available_height = chunks[1].height.saturating_sub(2) as usize; // Subtract border
            let total_lines = syscalls.len();

            let scroll_pos = if self.auto_scroll {
                // Auto-scroll: show most recent lines
                if total_lines > available_height {
                    total_lines.saturating_sub(available_height)
                } else {
                    0
                }
            } else {
                // Manual scroll: use scroll position, but clamp to valid range
                let max_scroll = total_lines.saturating_sub(available_height);
                std::cmp::min(self.syscall_scroll as usize, max_scroll)
            };

            // Extract visible lines
            let end_idx = std::cmp::min(scroll_pos + available_height, total_lines);
            let visible_lines = if scroll_pos < total_lines {
                &syscalls[scroll_pos..end_idx]
            } else {
                &[]
            };

            (visible_lines.join("\n"), scroll_pos as u16)
        };

        // Update scroll position for display
        let scroll_indicator = if syscalls.len() > 0 {
            if self.auto_scroll {
                " Live Syscalls [AUTO] "
            } else {
                " Live Syscalls [MANUAL] "
            }
        } else {
            " Live Syscalls "
        };

        let syscall_widget = Paragraph::new(syscall_text)
            .block(
                Block::default()
                    .title(scroll_indicator)
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: true })
            .scroll((0, 0)); // Scroll is handled manually above

        frame.render_widget(syscall_widget, chunks[1]);

        // Show help at bottom of left column
        let help_area = Rect {
            x: chunks[0].x + 1,
            y: chunks[0].y + chunks[0].height - 2,
            width: chunks[0].width - 2,
            height: 1,
        };

        let help_text = "↑/↓ list, PgUp/PgDn scroll, SPACE auto, 'q' quit";
        frame.render_widget(Paragraph::new(help_text), help_area);
    }

    /// Format process runtime
    fn format_runtime(&self, start_time: u64) -> String {
        let now = chrono::Utc::now().timestamp_micros() as u64;
        let runtime_micros = now.saturating_sub(start_time);
        let runtime_secs = runtime_micros / 1_000_000;

        if runtime_secs < 60 {
            format!("{}s", runtime_secs)
        } else if runtime_secs < 3600 {
            format!("{}m{}s", runtime_secs / 60, runtime_secs % 60)
        } else {
            format!("{}h{}m", runtime_secs / 3600, (runtime_secs % 3600) / 60)
        }
    }
}

/// Convert processes to list items (free function to avoid borrowing issues)
fn create_process_list_items(processes: &[&LiveProcess]) -> Vec<ListItem<'static>> {
    if processes.is_empty() {
        return vec![
            ListItem::new("  PID   PPID  NAME         COMMAND"),
            ListItem::new("  ---   ----  ----         -------"),
            ListItem::new("  No active processes"),
        ];
    }

    let mut items = vec![
        ListItem::new("  PID   PPID  NAME         COMMAND"),
        ListItem::new("  ---   ----  ----         -------"),
    ];

    for process in processes {
        let command = if process.command_line.len() > 1 {
            process.command_line.join(" ")
        } else {
            process.command_line.first().cloned().unwrap_or_default()
        };

        // Truncate long commands
        let command = if command.len() > 40 {
            format!("{}...", &command[..37])
        } else {
            command
        };

        let line = format!(
            "{:>5} {:>5} {:12} {}",
            process.pid, process.ppid, process.name, command
        );

        items.push(ListItem::new(line));
    }

    items
}

/// Convert processes to list items with state and command info
fn create_process_state_items(processes: &[&state::LiveProcess]) -> Vec<ListItem<'static>> {
    if processes.is_empty() {
        return vec![
            ListItem::new("NAME              S  PID   PPID"),
            ListItem::new("----------------  -  ----- -----"),
            ListItem::new("No processes"),
        ];
    }

    let mut items = vec![
        ListItem::new("NAME              S  PID   PPID"),
        ListItem::new("----------------  -  ----- -----"),
    ];

    for process in processes {
        // Format state to match ProcessState enum exactly with requested colors
        let (state_code, state_color) = match process.state {
            state::ProcessState::Spawning => ('S', Color::Yellow), // Spawning (yellow)
            state::ProcessState::Active => ('A', Color::Green),    // Active (green)
            state::ProcessState::Waiting => ('W', Color::Rgb(255, 165, 0)), // Waiting (orange)
            state::ProcessState::Exiting => ('X', Color::Red),     // Exiting (red)
            state::ProcessState::Exited => ('E', Color::Rgb(128, 128, 128)), // Exited (grey)
        };

        // Use process name, truncate/pad to fixed width for alignment
        let name = if process.name.len() > 16 {
            format!("{}...", &process.name[..13])
        } else {
            process.name.clone()
        };

        let line_text = format!(
            "{:17} {:1} {:>5} {:>5}",
            name, state_code, process.pid, process.ppid
        );

        // Create ListItem with colored state
        let line_item = ListItem::new(Span::styled(line_text, Style::default().fg(state_color)));
        items.push(line_item);
    }

    items
}

/// Main monitor TUI entry point for demo/shared state
pub async fn run_monitor(agent_state: Arc<RwLock<AgentState>>) -> Result<()> {
    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app
    let mut app = MonitorApp::new(agent_state);

    // Main event loop
    let result = run_app(&mut terminal, &mut app).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

/// Live monitor TUI entry point - connects to running session
pub async fn run_monitor_live(socket_path: &Path) -> Result<()> {
    // Connect to state server
    let mut state_client = StateClient::connect(socket_path).await?;

    // Setup terminal
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut terminal = Terminal::new(backend)?;

    // Create app with live state updates
    let mut app = LiveMonitorApp::new();

    // Main event loop
    let result = run_live_app(&mut terminal, &mut app, &mut state_client).await;

    // Restore terminal
    disable_raw_mode()?;
    execute!(terminal.backend_mut(), LeaveAlternateScreen)?;
    terminal.show_cursor()?;

    result
}

/// Live monitor app state
struct LiveMonitorApp {
    /// Current agent state
    current_state: Option<AgentState>,
    /// List selection and scroll state
    list_state: ListState,
    /// Syscall scroll position (line offset)
    syscall_scroll: u16,
    /// Whether to quit the app
    should_quit: bool,
    /// Auto-scroll mode for syscalls
    auto_scroll: bool,
}

impl LiveMonitorApp {
    fn new() -> Self {
        Self {
            current_state: None,
            list_state: ListState::default(),
            syscall_scroll: 0,
            should_quit: false,
            auto_scroll: true,
        }
    }

    /// Handle keyboard input
    fn handle_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return true,
            // Process list navigation (left column)
            KeyCode::Up => self.list_state.select_previous(),
            KeyCode::Down => self.list_state.select_next(),
            // Syscall scrolling (right column)
            KeyCode::PageUp => {
                self.auto_scroll = false;
                self.syscall_scroll = self.syscall_scroll.saturating_sub(10);
            }
            KeyCode::PageDown => {
                self.auto_scroll = false;
                self.syscall_scroll = self.syscall_scroll.saturating_add(10);
            }
            KeyCode::Home => {
                self.auto_scroll = false;
                self.syscall_scroll = 0;
            }
            KeyCode::End => {
                self.auto_scroll = true; // Re-enable auto-scroll when going to end
                self.syscall_scroll = 0; // Will be set to max in draw()
            }
            KeyCode::Char(' ') => {
                // Toggle auto-scroll
                self.auto_scroll = !self.auto_scroll;
            }
            _ => {}
        }
        false
    }

    /// Update with new state
    fn update_state(&mut self, state: AgentState) {
        self.current_state = Some(state);
    }

    /// Draw the TUI
    fn draw(&mut self, frame: &mut Frame) {
        let area = frame.area();

        // Split into two columns: 40% processes, 60% syscalls (wider to fit columns)
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(40), Constraint::Percentage(60)])
            .split(area);

        let (processes, process_count, syscalls) = match &self.current_state {
            Some(state) => {
                let sorted_processes = state.processes_by_state();
                let count = sorted_processes.len();
                let process_items = create_process_state_items(&sorted_processes);
                let syscall_lines: Vec<String> =
                    state.recent_syscalls().into_iter().cloned().collect();
                (process_items, count, syscall_lines)
            }
            None => (
                vec![
                    ListItem::new("  PID   PPID  STATE  NAME"),
                    ListItem::new("  ---   ----  -----  ----"),
                    ListItem::new("  Connecting to session..."),
                ],
                0,
                vec![],
            ),
        };

        // Left column: Process list
        let process_title = if self.current_state.is_some() {
            format!(" Processes ({}) ", process_count)
        } else {
            " Processes (connecting...) ".to_string()
        };

        let process_list = List::new(processes)
            .block(Block::default().title(process_title).borders(Borders::ALL))
            .highlight_symbol("> ");
        frame.render_stateful_widget(process_list, chunks[0], &mut self.list_state);

        // Right column: Syscall stream
        let (syscall_text, _scroll_pos) = if syscalls.is_empty() {
            if self.current_state.is_some() {
                ("Waiting for syscalls...".to_string(), 0)
            } else {
                ("Connecting to session...".to_string(), 0)
            }
        } else {
            // Calculate scroll position
            let available_height = chunks[1].height.saturating_sub(2) as usize; // Subtract border
            let total_lines = syscalls.len();

            let scroll_pos = if self.auto_scroll {
                // Auto-scroll: show most recent lines
                if total_lines > available_height {
                    total_lines.saturating_sub(available_height)
                } else {
                    0
                }
            } else {
                // Manual scroll: use scroll position, but clamp to valid range
                let max_scroll = total_lines.saturating_sub(available_height);
                std::cmp::min(self.syscall_scroll as usize, max_scroll)
            };

            // Extract visible lines
            let end_idx = std::cmp::min(scroll_pos + available_height, total_lines);
            let visible_lines = if scroll_pos < total_lines {
                &syscalls[scroll_pos..end_idx]
            } else {
                &[]
            };

            (visible_lines.join("\n"), scroll_pos as u16)
        };

        // Update scroll position for display
        let scroll_indicator = if syscalls.len() > 0 {
            if self.auto_scroll {
                " Live Syscalls [AUTO] "
            } else {
                " Live Syscalls [MANUAL] "
            }
        } else {
            " Live Syscalls "
        };

        let syscall_widget = Paragraph::new(syscall_text)
            .block(
                Block::default()
                    .title(scroll_indicator)
                    .borders(Borders::ALL),
            )
            .wrap(Wrap { trim: true })
            .scroll((0, 0)); // Scroll is handled manually above

        frame.render_widget(syscall_widget, chunks[1]);

        // Show help at bottom of left column
        let help_area = Rect {
            x: chunks[0].x + 1,
            y: chunks[0].y + chunks[0].height - 2,
            width: chunks[0].width - 2,
            height: 1,
        };

        let help_text = "↑/↓ list, PgUp/PgDn scroll, SPACE auto, 'q' quit";
        frame.render_widget(Paragraph::new(help_text), help_area);
    }
}

/// Run the live TUI application
async fn run_live_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut LiveMonitorApp,
    state_client: &mut StateClient,
) -> Result<()> {
    loop {
        // Draw UI
        terminal.draw(|frame| app.draw(frame))?;

        // Check for new state updates or keyboard input
        tokio::select! {
            // Receive state updates
            state_result = state_client.receive_state() => {
                match state_result {
                    Ok(state) => {
                        app.update_state(state);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to receive state update: {}", e);
                        // Session might have ended
                        break;
                    }
                }
            }

            // Handle keyboard input
            input_result = tokio::task::spawn_blocking(|| -> Result<Option<KeyEvent>> {
                if event::poll(Duration::from_millis(100))? {
                    if let Event::Key(key) = event::read()? {
                        if key.kind == KeyEventKind::Press {
                            return Ok(Some(key));
                        }
                    }
                }
                Ok(None)
            }) => {
                match input_result {
                    Ok(Ok(Some(key))) => {
                        if app.handle_key(key) {
                            break; // Quit
                        }
                    }
                    Ok(Ok(None)) => {
                        // No input, continue
                    }
                    Ok(Err(e)) => {
                        tracing::warn!("Input error: {}", e);
                    }
                    Err(e) => {
                        tracing::warn!("Input task error: {}", e);
                    }
                }
            }
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}

/// Run the TUI application
async fn run_app(
    terminal: &mut Terminal<CrosstermBackend<io::Stdout>>,
    app: &mut MonitorApp,
) -> Result<()> {
    loop {
        // Draw UI
        terminal.draw(|frame| app.draw(frame))?;

        // Handle events with timeout for auto-refresh
        let timeout = app.refresh_rate.saturating_sub(app.last_refresh.elapsed());

        if event::poll(timeout)? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    if app.handle_key(key) {
                        break; // Quit
                    }
                }
            }
        }

        // Auto-refresh if needed
        if app.should_refresh() {
            app.mark_refreshed();
            // UI will refresh on next draw cycle
        }

        if app.should_quit {
            break;
        }
    }

    Ok(())
}
