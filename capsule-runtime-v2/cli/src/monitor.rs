//! Live process monitoring TUI using ratatui
//!
//! Shows real-time process list with keyboard navigation

use anyhow::Result;
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    prelude::*,
    widgets::{Block, Borders, List, ListItem, ListState},
};
use state::{AgentState, LiveProcess};
use std::io;
use std::path::Path;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::time::{Duration, Instant};
use crate::ipc::StateClient;

/// TUI application state
struct MonitorApp {
    /// Shared agent state from tracker
    agent_state: Arc<RwLock<AgentState>>,
    /// List selection and scroll state
    list_state: ListState,
    /// Whether to quit the app
    should_quit: bool,
    /// Auto-refresh interval
    refresh_rate: Duration,
    /// Last refresh time for auto-update
    last_refresh: Instant,
}

impl MonitorApp {
    /// Create new monitor app with shared state
    fn new(agent_state: Arc<RwLock<AgentState>>) -> Self {
        Self {
            agent_state,
            list_state: ListState::default(),
            should_quit: false,
            refresh_rate: Duration::from_millis(500), // 2 FPS refresh
            last_refresh: Instant::now(),
        }
    }

    /// Handle keyboard input
    fn handle_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return true,
            KeyCode::Up => self.list_state.select_previous(),
            KeyCode::Down => self.list_state.select_next(),
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

        // Read current state (non-blocking)
        let (processes, process_count) = match self.agent_state.try_read() {
            Ok(state) => {
                let live_processes = state.live_processes();
                let count = live_processes.len();
                let items = create_process_list_items(&live_processes);
                (items, count)
            }
            Err(_) => {
                // State locked, show placeholder
                (vec![ListItem::new("Loading...")], 0)
            }
        };

        // Create title with count
        let title = format!(" Live Processes ({} total) ", process_count);

        // Create list widget
        let list = List::new(processes)
            .block(Block::default().title(title).borders(Borders::ALL))
            .highlight_symbol("> ");

        // Render with state
        frame.render_stateful_widget(list, area, &mut self.list_state);

        // Show help at bottom
        let help_area = Rect {
            x: area.x + 1,
            y: area.y + area.height - 2,
            width: area.width - 2,
            height: 1,
        };
        
        let help_text = "Navigation: ↑/↓ arrows, 'r' refresh, 'q' quit";
        frame.render_widget(
            ratatui::widgets::Paragraph::new(help_text),
            help_area,
        );
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
            ListItem::new("  No active processes")
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
            process.pid,
            process.ppid,
            process.name,
            command
        );

        items.push(ListItem::new(line));
    }

    items
}

/// Convert processes to list items with headers (for live monitor)
fn create_process_list_items_with_headers(processes: &[&LiveProcess]) -> Vec<ListItem<'static>> {
    if processes.is_empty() {
        return vec![
            ListItem::new("  PID   PPID  NAME         COMMAND"),
            ListItem::new("  ---   ----  ----         -------"),
            ListItem::new("  No active processes")
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
            process.pid,
            process.ppid,
            process.name,
            command
        );

        items.push(ListItem::new(line));
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
    /// Whether to quit the app
    should_quit: bool,
}

impl LiveMonitorApp {
    fn new() -> Self {
        Self {
            current_state: None,
            list_state: ListState::default(),
            should_quit: false,
        }
    }

    /// Handle keyboard input
    fn handle_key(&mut self, key: KeyEvent) -> bool {
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => return true,
            KeyCode::Up => self.list_state.select_previous(),
            KeyCode::Down => self.list_state.select_next(),
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

        let (processes, process_count) = match &self.current_state {
            Some(state) => {
                let live_processes = state.live_processes();
                let count = live_processes.len();
                let items = create_process_list_items_with_headers(&live_processes);
                (items, count)
            }
            None => {
                (vec![
                    ListItem::new("  PID   PPID  NAME         COMMAND"),
                    ListItem::new("  ---   ----  ----         -------"),
                    ListItem::new("  Connecting to session...")
                ], 0)
            }
        };

        // Create title with count and status
        let title = if self.current_state.is_some() {
            format!(" Live Processes ({} total) ", process_count)
        } else {
            " Live Processes (connecting...) ".to_string()
        };

        // Create list widget
        let list = List::new(processes)
            .block(Block::default().title(title).borders(Borders::ALL))
            .highlight_symbol("> ");

        // Render with state
        frame.render_stateful_widget(list, area, &mut self.list_state);

        // Show help at bottom
        let help_area = Rect {
            x: area.x + 1,
            y: area.y + area.height - 2,
            width: area.width - 2,
            height: 1,
        };
        
        let help_text = "Navigation: ↑/↓ arrows, 'q' quit | Live session data";
        frame.render_widget(
            ratatui::widgets::Paragraph::new(help_text),
            help_area,
        );
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
async fn run_app(terminal: &mut Terminal<CrosstermBackend<io::Stdout>>, app: &mut MonitorApp) -> Result<()> {
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