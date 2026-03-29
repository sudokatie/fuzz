use crate::error::Result;
use crate::stats::{format_bytes, format_number, Stats};
use crossterm::{
    event::{self, Event, KeyCode},
    execute,
    terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen},
};
use ratatui::{
    backend::CrosstermBackend,
    layout::{Constraint, Direction, Layout, Rect},
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::{Block, Borders, Gauge, Paragraph},
    Terminal,
};
use std::io::{self, Stdout};
use std::time::{Duration, Instant};

/// Terminal UI for fuzzing progress.
pub struct FuzzUI {
    terminal: Terminal<CrosstermBackend<Stdout>>,
    last_update: Instant,
    update_interval: Duration,
}

impl FuzzUI {
    /// Create a new fuzzing UI.
    pub fn new() -> Result<Self> {
        enable_raw_mode().map_err(|e| crate::error::Error::Io(e))?;
        let mut stdout = io::stdout();
        execute!(stdout, EnterAlternateScreen).map_err(|e| crate::error::Error::Io(e))?;
        let backend = CrosstermBackend::new(stdout);
        let terminal = Terminal::new(backend).map_err(|e| crate::error::Error::Io(e))?;

        Ok(Self {
            terminal,
            last_update: Instant::now(),
            update_interval: Duration::from_millis(100), // 10 FPS max
        })
    }

    /// Check if UI should update (rate limiting).
    pub fn should_update(&self) -> bool {
        self.last_update.elapsed() >= self.update_interval
    }

    /// Update the UI with current stats.
    pub fn update(&mut self, stats: &Stats) -> Result<()> {
        if !self.should_update() {
            return Ok(());
        }

        self.last_update = Instant::now();

        self.terminal
            .draw(|f| {
                let chunks = Layout::default()
                    .direction(Direction::Vertical)
                    .constraints([
                        Constraint::Length(3),  // Header
                        Constraint::Length(8),  // Stats
                        Constraint::Length(3),  // Progress
                        Constraint::Min(3),     // Status
                    ])
                    .split(f.size());

                // Header
                let header = create_header(stats);
                f.render_widget(header, chunks[0]);

                // Stats panel
                let stats_widget = create_stats_panel(stats);
                f.render_widget(stats_widget, chunks[1]);

                // Progress gauge
                let gauge = create_progress_gauge(stats);
                f.render_widget(gauge, chunks[2]);

                // Status line
                let status = create_status(stats);
                f.render_widget(status, chunks[3]);
            })
            .map_err(|e| crate::error::Error::Io(e))?;

        Ok(())
    }

    /// Check for user input (non-blocking).
    /// Returns true if user pressed 'q' to quit.
    pub fn check_quit(&self) -> bool {
        if event::poll(Duration::from_millis(0)).unwrap_or(false) {
            if let Ok(Event::Key(key)) = event::read() {
                return key.code == KeyCode::Char('q');
            }
        }
        false
    }

    /// Clean up terminal state.
    pub fn cleanup(&mut self) -> Result<()> {
        disable_raw_mode().map_err(|e| crate::error::Error::Io(e))?;
        execute!(self.terminal.backend_mut(), LeaveAlternateScreen)
            .map_err(|e| crate::error::Error::Io(e))?;
        self.terminal.show_cursor().map_err(|e| crate::error::Error::Io(e))?;
        Ok(())
    }
}

impl Drop for FuzzUI {
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn create_header(stats: &Stats) -> Paragraph<'static> {
    let title = format!(
        " fuzz - {} | execs/s: {:.0} ",
        stats.format_elapsed(),
        stats.execs_per_sec
    );

    Paragraph::new(title)
        .style(Style::default().fg(Color::White).bg(Color::Blue))
        .block(Block::default().borders(Borders::ALL).title("Fuzzer"))
}

fn create_stats_panel(stats: &Stats) -> Paragraph<'static> {
    let lines = vec![
        Line::from(vec![
            Span::styled("  Executions: ", Style::default().fg(Color::Cyan)),
            Span::raw(format_number(stats.total_execs)),
            Span::raw("   "),
            Span::styled("Crashes: ", Style::default().fg(Color::Red)),
            Span::styled(
                stats.crashes_found.to_string(),
                Style::default()
                    .fg(if stats.crashes_found > 0 {
                        Color::Red
                    } else {
                        Color::Green
                    })
                    .add_modifier(Modifier::BOLD),
            ),
            Span::raw("   "),
            Span::styled("Timeouts: ", Style::default().fg(Color::Yellow)),
            Span::raw(stats.timeouts.to_string()),
        ]),
        Line::from(vec![
            Span::styled("  Corpus: ", Style::default().fg(Color::Cyan)),
            Span::raw(format!("{} entries", stats.corpus_size)),
            Span::raw("   "),
            Span::styled("Size: ", Style::default().fg(Color::Cyan)),
            Span::raw(format_bytes(stats.corpus_bytes)),
            Span::raw("   "),
            Span::styled("Pending: ", Style::default().fg(Color::Cyan)),
            Span::raw(stats.pending_favored.to_string()),
        ]),
        Line::from(vec![
            Span::styled("  Coverage: ", Style::default().fg(Color::Cyan)),
            Span::raw(format!("{} edges", stats.coverage_edges)),
            Span::raw("   "),
            Span::styled("Last new: ", Style::default().fg(Color::Cyan)),
            Span::raw(stats.format_since_new_cov()),
            Span::raw(" ago"),
        ]),
        Line::from(vec![
            Span::styled("  Stage: ", Style::default().fg(Color::Cyan)),
            Span::styled(
                stats.stage.clone(),
                Style::default().fg(Color::Yellow),
            ),
            if let Some(entry) = stats.current_entry {
                Span::raw(format!("   Entry: #{}", entry))
            } else {
                Span::raw("")
            },
        ]),
    ];

    Paragraph::new(lines)
        .block(Block::default().borders(Borders::ALL).title("Statistics"))
}

fn create_progress_gauge(stats: &Stats) -> Gauge<'static> {
    let progress = (stats.coverage_percent * 100.0).min(100.0);

    Gauge::default()
        .block(Block::default().borders(Borders::ALL).title("Coverage"))
        .gauge_style(
            Style::default()
                .fg(Color::Green)
                .bg(Color::Black)
                .add_modifier(Modifier::BOLD),
        )
        .percent(progress as u16)
        .label(format!("{:.2}%", stats.coverage_percent * 100.0))
}

fn create_status(stats: &Stats) -> Paragraph<'static> {
    let status = if stats.crashes_found > 0 {
        format!("CRASHES FOUND: {} - Press 'q' to quit", stats.crashes_found)
    } else {
        String::from("Running... Press 'q' to quit")
    };

    let style = if stats.crashes_found > 0 {
        Style::default().fg(Color::Red).add_modifier(Modifier::BOLD)
    } else {
        Style::default().fg(Color::Green)
    };

    Paragraph::new(status)
        .style(style)
        .block(Block::default().borders(Borders::ALL).title("Status"))
}

#[cfg(test)]
mod tests {
    use super::*;

    // UI tests are limited since they require a terminal.
    // We test the helper functions and stats formatting instead.

    #[test]
    fn test_stats_rendering_values() {
        let mut stats = Stats::new();
        stats.total_execs = 12345;
        stats.crashes_found = 2;
        stats.corpus_size = 50;
        stats.coverage_edges = 1234;
        stats.stage = String::from("havoc");

        // These just verify the stats are set correctly
        assert_eq!(stats.total_execs, 12345);
        assert_eq!(stats.crashes_found, 2);
        assert_eq!(stats.corpus_size, 50);
        assert_eq!(stats.stage, "havoc");
    }

    #[test]
    fn test_update_interval() {
        // This tests the rate limiting logic conceptually
        let interval = Duration::from_millis(100);
        let last_update = Instant::now();

        // Right after update, should not update again
        assert!(last_update.elapsed() < interval);

        // After waiting, should update
        std::thread::sleep(Duration::from_millis(150));
        assert!(last_update.elapsed() >= interval);
    }
}
