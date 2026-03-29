pub mod ui;

pub use ui::FuzzUI;

use std::time::{Duration, Instant};

/// Fuzzing statistics.
#[derive(Debug, Clone)]
pub struct Stats {
    /// When fuzzing started.
    pub start_time: Instant,
    /// Total number of executions.
    pub total_execs: u64,
    /// Number of unique crashes found.
    pub crashes_found: u64,
    /// Number of timeouts encountered.
    pub timeouts: u64,
    /// Current corpus size.
    pub corpus_size: usize,
    /// Number of unique edges covered.
    pub coverage_edges: usize,
    /// Maximum coverage percentage.
    pub coverage_percent: f64,
    /// When new coverage was last found.
    pub last_new_cov: Instant,
    /// Calculated executions per second.
    pub execs_per_sec: f64,
    /// Current stage name.
    pub stage: String,
    /// Current entry being fuzzed.
    pub current_entry: Option<u64>,
    /// Pending corpus entries to process.
    pub pending_favored: usize,
    /// Total input bytes in corpus.
    pub corpus_bytes: usize,
}

impl Stats {
    /// Create new stats starting now.
    pub fn new() -> Self {
        let now = Instant::now();
        Self {
            start_time: now,
            total_execs: 0,
            crashes_found: 0,
            timeouts: 0,
            corpus_size: 0,
            coverage_edges: 0,
            coverage_percent: 0.0,
            last_new_cov: now,
            execs_per_sec: 0.0,
            stage: String::from("init"),
            current_entry: None,
            pending_favored: 0,
            corpus_bytes: 0,
        }
    }

    /// Update executions per second based on elapsed time.
    pub fn update_execs_per_sec(&mut self) {
        let elapsed = self.start_time.elapsed().as_secs_f64();
        if elapsed > 0.0 {
            self.execs_per_sec = self.total_execs as f64 / elapsed;
        }
    }

    /// Get elapsed time since start.
    pub fn elapsed(&self) -> Duration {
        self.start_time.elapsed()
    }

    /// Get time since last new coverage.
    pub fn time_since_new_cov(&self) -> Duration {
        self.last_new_cov.elapsed()
    }

    /// Record a new execution.
    pub fn record_exec(&mut self) {
        self.total_execs += 1;
    }

    /// Record a crash.
    pub fn record_crash(&mut self) {
        self.crashes_found += 1;
    }

    /// Record a timeout.
    pub fn record_timeout(&mut self) {
        self.timeouts += 1;
    }

    /// Record new coverage found.
    pub fn record_new_cov(&mut self, edges: usize) {
        self.coverage_edges = edges;
        self.last_new_cov = Instant::now();
    }

    /// Update corpus stats.
    pub fn update_corpus(&mut self, size: usize, bytes: usize) {
        self.corpus_size = size;
        self.corpus_bytes = bytes;
    }

    /// Format elapsed time as HH:MM:SS.
    pub fn format_elapsed(&self) -> String {
        format_duration(self.elapsed())
    }

    /// Format time since new coverage.
    pub fn format_since_new_cov(&self) -> String {
        format_duration(self.time_since_new_cov())
    }
}

impl Default for Stats {
    fn default() -> Self {
        Self::new()
    }
}

/// Format duration as HH:MM:SS or D days HH:MM:SS.
pub fn format_duration(d: Duration) -> String {
    let total_secs = d.as_secs();
    let hours = total_secs / 3600;
    let minutes = (total_secs % 3600) / 60;
    let seconds = total_secs % 60;

    if hours >= 24 {
        let days = hours / 24;
        let hours = hours % 24;
        format!("{}d {:02}:{:02}:{:02}", days, hours, minutes, seconds)
    } else {
        format!("{:02}:{:02}:{:02}", hours, minutes, seconds)
    }
}

/// Format a number with SI suffix (K, M, B).
pub fn format_number(n: u64) -> String {
    if n >= 1_000_000_000 {
        format!("{:.2}B", n as f64 / 1_000_000_000.0)
    } else if n >= 1_000_000 {
        format!("{:.2}M", n as f64 / 1_000_000.0)
    } else if n >= 1_000 {
        format!("{:.2}K", n as f64 / 1_000.0)
    } else {
        n.to_string()
    }
}

/// Format bytes as human-readable (KB, MB, GB).
pub fn format_bytes(bytes: usize) -> String {
    if bytes >= 1_073_741_824 {
        format!("{:.2} GB", bytes as f64 / 1_073_741_824.0)
    } else if bytes >= 1_048_576 {
        format!("{:.2} MB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::sleep;

    #[test]
    fn test_stats_new() {
        let stats = Stats::new();
        assert_eq!(stats.total_execs, 0);
        assert_eq!(stats.crashes_found, 0);
        assert_eq!(stats.corpus_size, 0);
        assert_eq!(stats.stage, "init");
    }

    #[test]
    fn test_stats_record_exec() {
        let mut stats = Stats::new();
        stats.record_exec();
        stats.record_exec();
        stats.record_exec();
        assert_eq!(stats.total_execs, 3);
    }

    #[test]
    fn test_stats_record_crash() {
        let mut stats = Stats::new();
        stats.record_crash();
        assert_eq!(stats.crashes_found, 1);
    }

    #[test]
    fn test_stats_record_timeout() {
        let mut stats = Stats::new();
        stats.record_timeout();
        assert_eq!(stats.timeouts, 1);
    }

    #[test]
    fn test_stats_update_corpus() {
        let mut stats = Stats::new();
        stats.update_corpus(10, 5000);
        assert_eq!(stats.corpus_size, 10);
        assert_eq!(stats.corpus_bytes, 5000);
    }

    #[test]
    fn test_execs_per_sec_calculation() {
        let mut stats = Stats::new();
        stats.total_execs = 1000;
        // Sleep briefly to get non-zero elapsed time
        sleep(Duration::from_millis(10));
        stats.update_execs_per_sec();

        assert!(stats.execs_per_sec > 0.0);
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_secs(0)), "00:00:00");
        assert_eq!(format_duration(Duration::from_secs(61)), "00:01:01");
        assert_eq!(format_duration(Duration::from_secs(3661)), "01:01:01");
        assert_eq!(
            format_duration(Duration::from_secs(86400 + 3661)),
            "1d 01:01:01"
        );
    }

    #[test]
    fn test_format_number() {
        assert_eq!(format_number(0), "0");
        assert_eq!(format_number(999), "999");
        assert_eq!(format_number(1000), "1.00K");
        assert_eq!(format_number(1_500_000), "1.50M");
        assert_eq!(format_number(2_500_000_000), "2.50B");
    }

    #[test]
    fn test_format_bytes() {
        assert_eq!(format_bytes(0), "0 B");
        assert_eq!(format_bytes(512), "512 B");
        assert_eq!(format_bytes(1024), "1.00 KB");
        assert_eq!(format_bytes(1_572_864), "1.50 MB");
        assert_eq!(format_bytes(1_610_612_736), "1.50 GB");
    }

    #[test]
    fn test_stats_format_elapsed() {
        let stats = Stats::new();
        // Just verify it returns a formatted string
        let elapsed = stats.format_elapsed();
        assert!(elapsed.contains(':'));
    }
}
