use crate::config::Config;
use crate::corpus::{CorpusEntry, CorpusStorage, EntryMetadata, Scheduler};
use crate::coverage::{Bitmap, CoverageCollector, create_collector};
use crate::crash::{triage_from_signal, Crash, CrashStorage};
use crate::error::{Error, Result};
use crate::executor::{ExitStatus, ForkExecutor, InputMode};
use crate::mutation::Mutator;
use crate::stats::{FuzzUI, Stats};
use rand::rngs::StdRng;
use rand::SeedableRng;
use serde::Serialize;
use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Result of a fuzzing campaign.
#[derive(Debug)]
pub struct FuzzResult {
    /// Total number of executions.
    pub total_execs: u64,
    /// Number of unique crashes found.
    pub crashes_found: u64,
    /// Final corpus size.
    pub corpus_size: usize,
    /// Number of unique edges covered.
    pub coverage_edges: usize,
    /// Duration of the campaign.
    pub duration: Duration,
}

/// Stats file format for stats.json
#[derive(Serialize)]
struct StatsJson {
    start_time: u64,
    last_update: u64,
    fuzzer_pid: u32,
    cycles_done: u64,
    execs_done: u64,
    execs_per_sec: f64,
    corpus_count: usize,
    corpus_bytes: usize,
    crashes_total: u64,
    crashes_unique: u64,
    timeouts_total: u64,
    coverage_edges: usize,
    coverage_percent: f64,
    last_new_cov_time: u64,
    stage: String,
}

/// Plot data entry
struct PlotEntry {
    time_secs: u64,
    execs: u64,
    corpus_size: usize,
    coverage_edges: usize,
    crashes: u64,
}

/// Main fuzzer orchestrator.
pub struct Fuzzer {
    config: Config,
    corpus: CorpusStorage,
    scheduler: Scheduler,
    mutator: Mutator,
    executor: ForkExecutor,
    coverage: Box<dyn CoverageCollector>,
    virgin: Bitmap,
    crashes: CrashStorage,
    hangs: HangStorage,
    stats: Stats,
    ui: Option<FuzzUI>,
    rng: StdRng,
    running: Arc<AtomicBool>,
    next_entry_id: u64,
    start_time_unix: u64,
    log_file: Option<BufWriter<File>>,
    plot_data: Vec<PlotEntry>,
}

/// Storage for hang/timeout inputs
struct HangStorage {
    dir: std::path::PathBuf,
    count: usize,
}

impl HangStorage {
    fn open(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            count: 0,
        })
    }

    fn save(&mut self, input: &[u8]) -> Result<()> {
        self.count += 1;
        let path = self.dir.join(format!("hang_{:06}", self.count));
        fs::write(&path, input)?;
        Ok(())
    }
}

impl Fuzzer {
    /// Create a new fuzzer with the given config.
    pub fn new(config: Config, enable_ui: bool) -> Result<Self> {
        // Validate config
        config.validate()?;

        let target_path = config
            .target
            .path
            .as_ref()
            .ok_or_else(|| Error::Config("target path required".into()))?;

        // Create output directory structure
        fs::create_dir_all(&config.output.dir)
            .map_err(|e| Error::Config(format!("failed to create output dir: {}", e)))?;

        let queue_dir = config.output.dir.join("queue");
        fs::create_dir_all(&queue_dir)?;

        // Initialize corpus storage
        let corpus = CorpusStorage::open(&config.output.dir)?;

        // Determine input mode from args
        let input_mode = if config.target.args.iter().any(|a| a == "@@") {
            InputMode::ArgReplace
        } else {
            InputMode::Stdin
        };

        // Check coverage mode
        use crate::config::CoverageMode;
        if config.execution.coverage_mode == CoverageMode::Breakpoint {
            eprintln!("Warning: Breakpoint coverage mode is experimental and may be slower");
        }

        // Initialize coverage collector based on mode
        let coverage = create_collector(config.execution.coverage_mode.clone(), &target_path)?;

        // Initialize executor
        let mut executor = ForkExecutor::new(target_path.clone())
            .args(config.target.args.clone())
            .timeout(Duration::from_millis(config.execution.timeout_ms))
            .input_mode(input_mode);

        // Set coverage env var if the collector provides one
        if let Some((cov_env_key, cov_env_val)) = coverage.env_var() {
            executor = executor.env(cov_env_key, cov_env_val);
        }

        // Apply memory limit if specified
        if let Some(mem_mb) = config.execution.memory_limit_mb {
            executor = executor.memory_limit(mem_mb);
        }

        // Initialize crash storage
        let crashes_dir = config.output.dir.join("crashes");
        let crashes = CrashStorage::open(&crashes_dir)?;

        // Initialize hang storage
        let hangs_dir = config.output.dir.join("hangs");
        let hangs = HangStorage::open(&hangs_dir)?;

        // Initialize mutator (with dictionary if configured)
        let mutator = if let Some(ref dict_path) = config.mutation.dictionary {
            match Mutator::with_dictionary_file(dict_path) {
                Ok(m) => m,
                Err(e) => {
                    eprintln!("Warning: failed to load dictionary: {}", e);
                    Mutator::new()
                }
            }
        } else {
            Mutator::new()
        };

        // Initialize UI if enabled
        let ui = if enable_ui {
            FuzzUI::new().ok()
        } else {
            None
        };

        // Initialize log file
        let log_path = config.output.dir.join("fuzz.log");
        let log_file = File::create(&log_path)
            .ok()
            .map(|f| BufWriter::new(f));

        let start_time_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        Ok(Self {
            config,
            corpus,
            scheduler: Scheduler::new(),
            mutator,
            executor,
            coverage,
            virgin: Bitmap::virgin(),
            crashes,
            hangs,
            stats: Stats::new(),
            ui,
            rng: StdRng::from_entropy(),
            running: Arc::new(AtomicBool::new(true)),
            next_entry_id: 1,
            start_time_unix,
            log_file,
            plot_data: Vec::new(),
        })
    }

    /// Log a message to fuzz.log
    fn log(&mut self, msg: &str) {
        if let Some(ref mut log) = self.log_file {
            let elapsed = self.stats.elapsed().as_secs();
            let _ = writeln!(log, "[{:>8}s] {}", elapsed, msg);
            let _ = log.flush();
        }
    }

    /// Write stats.json
    fn write_stats_json(&self) -> Result<()> {
        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let last_new_cov_unix = self.start_time_unix + 
            (self.stats.start_time.elapsed().as_secs() - self.stats.time_since_new_cov().as_secs());

        let stats = StatsJson {
            start_time: self.start_time_unix,
            last_update: now_unix,
            fuzzer_pid: std::process::id(),
            cycles_done: self.stats.total_execs / self.stats.corpus_size.max(1) as u64,
            execs_done: self.stats.total_execs,
            execs_per_sec: self.stats.execs_per_sec,
            corpus_count: self.stats.corpus_size,
            corpus_bytes: self.stats.corpus_bytes,
            crashes_total: self.stats.crashes_found,
            crashes_unique: self.stats.crashes_found,
            timeouts_total: self.stats.timeouts,
            coverage_edges: self.stats.coverage_edges,
            coverage_percent: self.stats.coverage_percent,
            last_new_cov_time: last_new_cov_unix,
            stage: self.stats.stage.clone(),
        };

        let path = self.config.output.dir.join("stats.json");
        let json = serde_json::to_string_pretty(&stats)
            .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
        fs::write(&path, json)?;

        Ok(())
    }

    /// Write plot_data file
    fn write_plot_data(&self) -> Result<()> {
        let path = self.config.output.dir.join("plot_data");
        let mut file = File::create(&path)?;

        writeln!(file, "# time_secs, execs, corpus_size, coverage_edges, crashes")?;
        for entry in &self.plot_data {
            writeln!(
                file,
                "{}, {}, {}, {}, {}",
                entry.time_secs, entry.execs, entry.corpus_size, entry.coverage_edges, entry.crashes
            )?;
        }

        Ok(())
    }

    /// Record a plot data point
    fn record_plot_point(&mut self) {
        let entry = PlotEntry {
            time_secs: self.stats.elapsed().as_secs(),
            execs: self.stats.total_execs,
            corpus_size: self.stats.corpus_size,
            coverage_edges: self.stats.coverage_edges,
            crashes: self.stats.crashes_found,
        };
        self.plot_data.push(entry);
    }

    /// Load seed corpus from directories.
    pub fn load_seeds(&mut self) -> Result<usize> {
        let mut loaded = 0;

        for seed_dir in &self.config.corpus.seed_dirs.clone() {
            if !seed_dir.exists() {
                continue;
            }

            for entry in fs::read_dir(seed_dir)
                .map_err(|e| Error::Corpus(format!("failed to read seed dir: {}", e)))?
            {
                let entry = entry.map_err(|e| Error::Corpus(e.to_string()))?;
                let path = entry.path();

                if path.is_file() {
                    let input = fs::read(&path)
                        .map_err(|e| Error::Corpus(format!("failed to read seed: {}", e)))?;

                    if input.len() <= self.config.corpus.max_size {
                        self.add_to_corpus(input, None)?;
                        loaded += 1;
                    }
                }
            }
        }

        // If no seeds, add empty input
        if loaded == 0 {
            self.add_to_corpus(vec![], None)?;
            loaded = 1;
        }

        self.log(&format!("Loaded {} seed inputs", loaded));

        Ok(loaded)
    }

    /// Add an input to the corpus.
    fn add_to_corpus(&mut self, input: Vec<u8>, parent_id: Option<u64>) -> Result<u64> {
        let id = self.next_entry_id;
        self.next_entry_id += 1;

        let mut entry = CorpusEntry::new(id, input);
        entry.parent_id = parent_id;

        // Run to get initial coverage
        self.coverage.reset();
        let result = self.executor.run(&entry.input)?;
        entry.exec_time_us = result.exec_time.as_micros() as u64;

        // Check for crashes in seeds
        if let ExitStatus::Signal(sig) = result.status {
            let crash_type = triage_from_signal(sig);
            let crash = Crash::new(entry.input.clone(), Some(sig), crash_type);
            if self.crashes.save(&crash)? {
                self.stats.record_crash();
                self.log(&format!("Seed crash: {} (signal {})", crash_type.name(), sig));
            }
        }

        // Collect coverage
        let bitmap = self.coverage.collect();
        entry.coverage_hash = bitmap.hash();
        entry.new_coverage = bitmap.set_indices();

        // Save to corpus
        self.corpus.save(&entry)?;

        // Also save to queue directory
        let queue_path = self.config.output.dir.join("queue").join(format!("id:{:06}", id));
        fs::write(&queue_path, &entry.input)?;

        // Add to scheduler
        let depth = if parent_id.is_some() { 1 } else { 0 };
        let metadata = EntryMetadata::from_entry(&entry, depth);
        self.scheduler.add(metadata);

        // Update stats
        self.stats.corpus_size = self.scheduler.len();
        self.stats.corpus_bytes += entry.input.len();

        Ok(id)
    }

    /// Run the main fuzzing loop.
    pub fn run(&mut self) -> Result<FuzzResult> {
        let start = Instant::now();

        // Load seeds
        let seed_count = self.load_seeds()?;
        self.stats.stage = format!("loaded {} seeds", seed_count);

        // Set up signal handler
        let running = self.running.clone();
        ctrlc::set_handler(move || {
            running.store(false, Ordering::SeqCst);
        })
        .ok();

        self.log("Starting fuzzing loop");

        // Record initial plot point
        self.record_plot_point();
        let mut last_stats_write = Instant::now();
        let mut last_plot_record = Instant::now();

        // Main loop
        while self.running.load(Ordering::SeqCst) {
            // Select entry from corpus
            let entry_id = match self.scheduler.select(&mut self.rng) {
                Some(id) => id,
                None => continue,
            };

            // Load entry
            let entries = self.corpus.load_all()?;
            let entry = match entries.iter().find(|e| e.id == entry_id) {
                Some(e) => e,
                None => continue,
            };

            self.stats.current_entry = Some(entry_id);
            self.stats.stage = String::from("havoc");

            // Mutate and execute
            self.fuzz_one(entry)?;

            // Update scheduler
            self.scheduler.update_fuzz_count(entry_id);

            // Update UI
            self.stats.update_execs_per_sec();
            if let Some(ref mut ui) = self.ui {
                ui.update(&self.stats)?;
                if ui.check_quit() {
                    break;
                }
            }

            // Periodic stats.json write (every 5 seconds)
            if last_stats_write.elapsed() >= Duration::from_secs(5) {
                let _ = self.write_stats_json();
                last_stats_write = Instant::now();
            }

            // Periodic plot data record (every 30 seconds)
            if last_plot_record.elapsed() >= Duration::from_secs(30) {
                self.record_plot_point();
                last_plot_record = Instant::now();
            }
        }

        // Cleanup UI
        if let Some(ref mut ui) = self.ui {
            ui.cleanup()?;
        }

        // Final writes
        self.record_plot_point();
        let _ = self.write_stats_json();
        let _ = self.write_plot_data();
        self.log(&format!("Fuzzing complete. {} executions, {} crashes", 
            self.stats.total_execs, self.stats.crashes_found));

        Ok(FuzzResult {
            total_execs: self.stats.total_execs,
            crashes_found: self.stats.crashes_found,
            corpus_size: self.stats.corpus_size,
            coverage_edges: self.stats.coverage_edges,
            duration: start.elapsed(),
        })
    }

    /// Fuzz a single corpus entry.
    fn fuzz_one(&mut self, entry: &CorpusEntry) -> Result<()> {
        let havoc_cycles = self.config.mutation.havoc_cycles;

        for _ in 0..havoc_cycles {
            let mut input = self.mutator.mutate(&entry.input, &mut self.rng);

            // Enforce size limit
            if input.len() > self.config.corpus.max_size {
                input.truncate(self.config.corpus.max_size);
            }

            // Execute
            self.coverage.reset();
            let result = self.executor.run(&input)?;
            self.stats.record_exec();

            match result.status {
                ExitStatus::Signal(sig) => {
                    // Potential crash
                    let crash_type = triage_from_signal(sig);
                    let crash = Crash::new(input.clone(), Some(sig), crash_type);

                    if self.crashes.save(&crash)? {
                        self.stats.record_crash();
                        self.log(&format!("New crash: {} (signal {})", crash_type.name(), sig));
                    }
                }
                ExitStatus::Timeout => {
                    self.stats.record_timeout();
                    // Save hang
                    let _ = self.hangs.save(&input);
                }
                ExitStatus::Normal(_) => {
                    // Check for new coverage
                    let bitmap = self.coverage.collect();
                    if bitmap.has_new_bits(&self.virgin) {
                        bitmap.update_virgin(&mut self.virgin);
                        self.add_to_corpus(input, Some(entry.id))?;
                        self.stats.record_new_cov(self.virgin_edge_count());
                        self.log(&format!("New coverage: {} edges", self.stats.coverage_edges));
                    }
                }
            }
        }

        Ok(())
    }

    /// Count edges in virgin map (edges NOT seen yet have 0xff).
    fn virgin_edge_count(&self) -> usize {
        self.virgin
            .as_slice()
            .iter()
            .filter(|&&b| b != 0xff)
            .count()
    }

    /// Get current stats.
    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    /// Stop the fuzzer.
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use tempfile::TempDir;

    fn find_true_binary() -> PathBuf {
        for path in ["/usr/bin/true", "/bin/true"] {
            let p = PathBuf::from(path);
            if p.exists() {
                return p;
            }
        }
        PathBuf::from("/usr/bin/true")
    }

    fn make_test_config(temp_dir: &TempDir) -> Config {
        let mut config = Config::default();
        config.target.path = Some(find_true_binary());
        config.output.dir = temp_dir.path().to_path_buf();
        config.execution.timeout_ms = 1000;
        config
    }

    #[test]
    fn test_fuzzer_init() {
        let temp_dir = TempDir::new().unwrap();
        let config = make_test_config(&temp_dir);

        let fuzzer = Fuzzer::new(config, false);
        assert!(fuzzer.is_ok(), "fuzzer init failed: {:?}", fuzzer.err());
    }

    #[test]
    fn test_fuzzer_init_missing_target() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = Config::default();
        config.output.dir = temp_dir.path().to_path_buf();

        let fuzzer = Fuzzer::new(config, false);
        assert!(fuzzer.is_err());
    }

    #[test]
    fn test_fuzzer_load_seeds_empty() {
        let temp_dir = TempDir::new().unwrap();
        let config = make_test_config(&temp_dir);

        let mut fuzzer = Fuzzer::new(config, false).unwrap();
        let count = fuzzer.load_seeds().unwrap();

        assert_eq!(count, 1);
        assert_eq!(fuzzer.scheduler.len(), 1);
    }

    #[test]
    fn test_fuzzer_load_seeds_from_dir() {
        let temp_dir = TempDir::new().unwrap();
        let seeds_dir = temp_dir.path().join("seeds");
        fs::create_dir(&seeds_dir).unwrap();

        fs::write(seeds_dir.join("seed1"), b"hello").unwrap();
        fs::write(seeds_dir.join("seed2"), b"world").unwrap();

        let mut config = make_test_config(&temp_dir);
        config.corpus.seed_dirs.push(seeds_dir);

        let mut fuzzer = Fuzzer::new(config, false).unwrap();
        let count = fuzzer.load_seeds().unwrap();

        assert_eq!(count, 2);
        assert_eq!(fuzzer.scheduler.len(), 2);
    }

    #[test]
    fn test_fuzzer_stop() {
        let temp_dir = TempDir::new().unwrap();
        let config = make_test_config(&temp_dir);

        let fuzzer = Fuzzer::new(config, false).unwrap();
        assert!(fuzzer.running.load(Ordering::SeqCst));

        fuzzer.stop();
        assert!(!fuzzer.running.load(Ordering::SeqCst));
    }

    #[test]
    fn test_fuzz_result() {
        let result = FuzzResult {
            total_execs: 1000,
            crashes_found: 2,
            corpus_size: 50,
            coverage_edges: 1234,
            duration: Duration::from_secs(60),
        };

        assert_eq!(result.total_execs, 1000);
        assert_eq!(result.crashes_found, 2);
    }

    #[test]
    fn test_output_directories_created() {
        let temp_dir = TempDir::new().unwrap();
        let config = make_test_config(&temp_dir);

        let _fuzzer = Fuzzer::new(config, false).unwrap();

        // Check directories were created
        assert!(temp_dir.path().join("queue").exists());
        assert!(temp_dir.path().join("crashes").exists());
        assert!(temp_dir.path().join("hangs").exists());
    }
}
