//! Persistent mode fuzzer for high-performance fuzzing.
//!
//! Uses the PersistentExecutor to keep the target alive between executions,
//! eliminating fork overhead for targets compiled with a fuzzing harness.

use crate::config::Config;
use crate::corpus::{CorpusEntry, CorpusStorage, EntryMetadata, Scheduler};
use crate::coverage::{Bitmap, CoverageCollector, create_collector};
use crate::crash::{triage_from_signal, Crash, CrashStorage};
use crate::error::{Error, Result};
use crate::executor::PersistentExecutor;
use crate::fuzzer::FuzzResult;
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

/// Persistent mode fuzzer.
pub struct PersistentFuzzer {
    config: Config,
    corpus: CorpusStorage,
    scheduler: Scheduler,
    mutator: Mutator,
    executor: PersistentExecutor,
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
}

impl PersistentFuzzer {
    /// Create a new persistent fuzzer.
    pub fn new(config: Config, enable_ui: bool) -> Result<Self> {
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

        // Initialize coverage collector based on mode
        let coverage = create_collector(config.execution.coverage_mode.clone(), target_path)?;

        // Initialize persistent executor
        let mut executor = PersistentExecutor::new(target_path.clone())
            .args(config.target.args.clone())
            .timeout(Duration::from_millis(config.execution.timeout_ms));

        if let Some(mem_mb) = config.execution.memory_limit_mb {
            executor = executor.memory_limit(mem_mb);
        }

        // Initialize the persistent executor
        executor.init()?;

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
        let log_file = File::create(&log_path).ok().map(|f| BufWriter::new(f));

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
        })
    }

    /// Log a message
    fn log(&mut self, msg: &str) {
        if let Some(ref mut log) = self.log_file {
            let elapsed = self.stats.elapsed().as_secs();
            let _ = writeln!(log, "[{:>8}s] {}", elapsed, msg);
            let _ = log.flush();
        }
    }

    /// Write stats.json
    fn write_stats_json(&self) -> Result<()> {
        #[derive(Serialize)]
        struct StatsJson {
            start_time: u64,
            last_update: u64,
            fuzzer_pid: u32,
            execs_done: u64,
            execs_per_sec: f64,
            corpus_count: usize,
            crashes_total: u64,
            timeouts_total: u64,
            coverage_edges: usize,
            mode: &'static str,
        }

        let now_unix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        let stats = StatsJson {
            start_time: self.start_time_unix,
            last_update: now_unix,
            fuzzer_pid: std::process::id(),
            execs_done: self.stats.total_execs,
            execs_per_sec: self.stats.execs_per_sec,
            corpus_count: self.stats.corpus_size,
            crashes_total: self.stats.crashes_found,
            timeouts_total: self.stats.timeouts,
            coverage_edges: self.stats.coverage_edges,
            mode: "persistent",
        };

        let path = self.config.output.dir.join("stats.json");
        let json = serde_json::to_string_pretty(&stats)
            .map_err(|e| Error::Io(std::io::Error::new(std::io::ErrorKind::Other, e)))?;
        fs::write(&path, json)?;

        Ok(())
    }

    /// Load seeds into corpus
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

        if loaded == 0 {
            self.add_to_corpus(vec![], None)?;
            loaded = 1;
        }

        self.log(&format!("Loaded {} seed inputs", loaded));
        Ok(loaded)
    }

    /// Add input to corpus
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

        // Save to queue directory
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

    /// Run the fuzzing loop
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

        self.log("Starting persistent fuzzing loop");

        let mut last_stats_write = Instant::now();

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
            self.stats.stage = String::from("persistent-havoc");

            // Fuzz the entry
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

            // Periodic stats write
            if last_stats_write.elapsed() >= Duration::from_secs(5) {
                let _ = self.write_stats_json();
                last_stats_write = Instant::now();
            }
        }

        // Cleanup
        if let Some(ref mut ui) = self.ui {
            ui.cleanup()?;
        }

        let _ = self.write_stats_json();
        self.log(&format!(
            "Fuzzing complete. {} executions, {} crashes",
            self.stats.total_execs, self.stats.crashes_found
        ));

        Ok(FuzzResult {
            total_execs: self.stats.total_execs,
            crashes_found: self.stats.crashes_found,
            corpus_size: self.stats.corpus_size,
            coverage_edges: self.stats.coverage_edges,
            duration: start.elapsed(),
        })
    }

    /// Fuzz a single corpus entry
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

            if result.crashed {
                // Crash detected
                let crash_type = triage_from_signal(result.exit_code);
                let crash = Crash::new(input.clone(), Some(result.exit_code), crash_type);

                if self.crashes.save(&crash)? {
                    self.stats.record_crash();
                    self.log(&format!("New crash: {} (signal {})", crash_type.name(), result.exit_code));
                }
            } else {
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

        Ok(())
    }

    /// Count edges covered
    fn virgin_edge_count(&self) -> usize {
        self.virgin
            .as_slice()
            .iter()
            .filter(|&&b| b != 0xff)
            .count()
    }

    /// Stop the fuzzer
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Persistent mode tests are limited since they require a compatible harness.
    // Basic struct tests only.

    #[test]
    fn test_hang_storage() {
        use tempfile::TempDir;
        
        let tmp = TempDir::new().unwrap();
        let mut storage = HangStorage::open(tmp.path()).unwrap();
        
        storage.save(b"test input").unwrap();
        assert_eq!(storage.count, 1);
        
        let path = tmp.path().join("hang_000001");
        assert!(path.exists());
    }
}
