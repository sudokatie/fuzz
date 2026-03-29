use crate::config::Config;
use crate::corpus::{CorpusEntry, CorpusStorage, EntryMetadata, Scheduler};
use crate::coverage::{Bitmap, SancovCollector};
use crate::crash::{triage_from_signal, Crash, CrashStorage};
use crate::error::{Error, Result};
use crate::executor::{ExitStatus, ForkExecutor, InputMode};
use crate::mutation::Mutator;
use crate::stats::{FuzzUI, Stats};
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

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

/// Main fuzzer orchestrator.
pub struct Fuzzer {
    config: Config,
    corpus: CorpusStorage,
    scheduler: Scheduler,
    mutator: Mutator,
    executor: ForkExecutor,
    coverage: SancovCollector,
    virgin: Bitmap,
    crashes: CrashStorage,
    stats: Stats,
    ui: Option<FuzzUI>,
    rng: StdRng,
    running: Arc<AtomicBool>,
    next_entry_id: u64,
}

impl Fuzzer {
    /// Create a new fuzzer with the given config.
    pub fn new(config: Config) -> Result<Self> {
        // Validate config
        config.validate()?;

        let target_path = config
            .target
            .path
            .as_ref()
            .ok_or_else(|| Error::Config("target path required".into()))?;

        // Create output directory
        std::fs::create_dir_all(&config.output.dir)
            .map_err(|e| Error::Config(format!("failed to create output dir: {}", e)))?;

        // Initialize corpus storage
        let corpus = CorpusStorage::open(&config.output.dir)?;

        // Initialize executor
        let executor = ForkExecutor::new(target_path.clone())
            .args(config.target.args.clone())
            .timeout(Duration::from_millis(config.execution.timeout_ms))
            .input_mode(InputMode::Stdin);

        // Initialize coverage collector
        let coverage = SancovCollector::new()?;

        // Initialize crash storage
        let crashes_dir = config.output.dir.join("crashes");
        let crashes = CrashStorage::open(&crashes_dir)?;

        // Initialize mutator
        let mutator = Mutator::new();

        // Initialize UI if not in quiet mode
        let ui = FuzzUI::new().ok();

        Ok(Self {
            config,
            corpus,
            scheduler: Scheduler::new(),
            mutator,
            executor,
            coverage,
            virgin: Bitmap::virgin(),
            crashes,
            stats: Stats::new(),
            ui,
            rng: StdRng::from_entropy(),
            running: Arc::new(AtomicBool::new(true)),
            next_entry_id: 1,
        })
    }

    /// Load seed corpus from directories.
    pub fn load_seeds(&mut self) -> Result<usize> {
        let mut loaded = 0;

        for seed_dir in &self.config.corpus.seed_dirs.clone() {
            if !seed_dir.exists() {
                continue;
            }

            for entry in std::fs::read_dir(seed_dir)
                .map_err(|e| Error::Corpus(format!("failed to read seed dir: {}", e)))?
            {
                let entry = entry.map_err(|e| Error::Corpus(e.to_string()))?;
                let path = entry.path();

                if path.is_file() {
                    let input = std::fs::read(&path)
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

        // Collect coverage
        let bitmap = self.coverage.collect();
        entry.coverage_hash = bitmap.hash();
        entry.new_coverage = bitmap.set_indices();

        // Save to corpus
        self.corpus.save(&entry)?;

        // Add to scheduler
        let depth = if parent_id.is_some() { 1 } else { 0 }; // Simplified depth
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
        }

        // Cleanup UI
        if let Some(ref mut ui) = self.ui {
            ui.cleanup()?;
        }

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
        // Generate mutations
        let havoc_cycles = self.config.mutation.havoc_cycles;

        for _ in 0..havoc_cycles {
            let mut input = entry.input.clone();
            self.mutator.mutate(&mut input, &mut self.rng);

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
                    }
                }
                ExitStatus::Timeout => {
                    self.stats.record_timeout();
                }
                ExitStatus::Normal(_) => {
                    // Check for new coverage
                    let bitmap = self.coverage.collect();
                    if bitmap.has_new_bits(&self.virgin) {
                        bitmap.update_virgin(&mut self.virgin);
                        self.add_to_corpus(input, Some(entry.id))?;
                        self.stats.record_new_cov(self.virgin_edge_count());
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
        // macOS uses /usr/bin/true, Linux uses /bin/true
        for path in ["/usr/bin/true", "/bin/true"] {
            let p = PathBuf::from(path);
            if p.exists() {
                return p;
            }
        }
        PathBuf::from("/usr/bin/true") // Fallback
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

        let fuzzer = Fuzzer::new(config);
        assert!(fuzzer.is_ok(), "fuzzer init failed: {:?}", fuzzer.err());
    }

    #[test]
    fn test_fuzzer_init_missing_target() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = Config::default();
        config.output.dir = temp_dir.path().to_path_buf();
        // No target path

        let fuzzer = Fuzzer::new(config);
        assert!(fuzzer.is_err());
    }

    #[test]
    fn test_fuzzer_load_seeds_empty() {
        let temp_dir = TempDir::new().unwrap();
        let config = make_test_config(&temp_dir);

        let mut fuzzer = Fuzzer::new(config).unwrap();
        let count = fuzzer.load_seeds().unwrap();

        // Should add default empty seed
        assert_eq!(count, 1);
        assert_eq!(fuzzer.scheduler.len(), 1);
    }

    #[test]
    fn test_fuzzer_load_seeds_from_dir() {
        let temp_dir = TempDir::new().unwrap();
        let seeds_dir = temp_dir.path().join("seeds");
        std::fs::create_dir(&seeds_dir).unwrap();

        // Create seed files
        std::fs::write(seeds_dir.join("seed1"), b"hello").unwrap();
        std::fs::write(seeds_dir.join("seed2"), b"world").unwrap();

        let mut config = make_test_config(&temp_dir);
        config.corpus.seed_dirs.push(seeds_dir);

        let mut fuzzer = Fuzzer::new(config).unwrap();
        let count = fuzzer.load_seeds().unwrap();

        assert_eq!(count, 2);
        assert_eq!(fuzzer.scheduler.len(), 2);
    }

    #[test]
    fn test_fuzzer_stop() {
        let temp_dir = TempDir::new().unwrap();
        let config = make_test_config(&temp_dir);

        let fuzzer = Fuzzer::new(config).unwrap();
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
}
