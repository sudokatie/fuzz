use crate::config::Config;
use crate::corpus::{CorpusEntry, CorpusStorage, EntryMetadata, Scheduler};
use crate::coverage::{Bitmap, SancovCollector};
use crate::crash::{triage_from_signal, Crash, CrashStorage};
use crate::error::{Error, Result};
use crate::executor::{ExitStatus, ForkExecutor, InputMode};
use crate::mutation::Mutator;
use crate::stats::Stats;
use rand::rngs::StdRng;
use rand::SeedableRng;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

/// Atomic statistics for parallel fuzzing.
#[derive(Debug, Default)]
pub struct AtomicStats {
    pub total_execs: AtomicU64,
    pub crashes_found: AtomicU64,
    pub timeouts: AtomicU64,
    pub corpus_size: AtomicU64,
    pub coverage_edges: AtomicU64,
}

impl AtomicStats {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn record_exec(&self) {
        self.total_execs.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_crash(&self) {
        self.crashes_found.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_timeout(&self) {
        self.timeouts.fetch_add(1, Ordering::Relaxed);
    }

    pub fn set_corpus_size(&self, size: u64) {
        self.corpus_size.store(size, Ordering::Relaxed);
    }

    pub fn set_coverage_edges(&self, edges: u64) {
        self.coverage_edges.store(edges, Ordering::Relaxed);
    }

    pub fn to_stats(&self, start_time: Instant) -> Stats {
        let mut stats = Stats::new();
        stats.total_execs = self.total_execs.load(Ordering::Relaxed);
        stats.crashes_found = self.crashes_found.load(Ordering::Relaxed);
        stats.timeouts = self.timeouts.load(Ordering::Relaxed);
        stats.corpus_size = self.corpus_size.load(Ordering::Relaxed) as usize;
        stats.coverage_edges = self.coverage_edges.load(Ordering::Relaxed) as usize;
        stats.start_time = start_time;
        stats.update_execs_per_sec();
        stats
    }
}

/// Shared state between parallel fuzzing workers.
pub struct SharedState {
    /// Global coverage bitmap (virgin map).
    pub virgin: RwLock<Bitmap>,
    /// Corpus scheduler.
    pub scheduler: RwLock<Scheduler>,
    /// Crash storage.
    pub crashes: Mutex<CrashStorage>,
    /// Corpus storage.
    pub corpus: Mutex<CorpusStorage>,
    /// Atomic statistics.
    pub stats: AtomicStats,
    /// Next entry ID counter.
    pub next_entry_id: AtomicU64,
    /// Running flag.
    pub running: AtomicBool,
}

impl SharedState {
    pub fn new(corpus: CorpusStorage, crashes: CrashStorage) -> Self {
        Self {
            virgin: RwLock::new(Bitmap::virgin()),
            scheduler: RwLock::new(Scheduler::new()),
            crashes: Mutex::new(crashes),
            corpus: Mutex::new(corpus),
            stats: AtomicStats::new(),
            next_entry_id: AtomicU64::new(1),
            running: AtomicBool::new(true),
        }
    }

    pub fn next_id(&self) -> u64 {
        self.next_entry_id.fetch_add(1, Ordering::SeqCst)
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::SeqCst)
    }
}

/// Parallel fuzzer with multiple worker threads.
pub struct ParallelFuzzer {
    config: Config,
    shared: Arc<SharedState>,
    workers: Vec<JoinHandle<()>>,
    start_time: Instant,
}

impl ParallelFuzzer {
    /// Create a new parallel fuzzer.
    pub fn new(config: Config) -> Result<Self> {
        config.validate()?;

        let target_path = config.target.path.as_ref()
            .ok_or_else(|| Error::Config("target path required".into()))?;

        // Create output directory
        std::fs::create_dir_all(&config.output.dir)
            .map_err(|e| Error::Config(format!("failed to create output dir: {}", e)))?;

        // Initialize corpus storage
        let corpus = CorpusStorage::open(&config.output.dir)?;

        // Initialize crash storage
        let crashes_dir = config.output.dir.join("crashes");
        let crashes = CrashStorage::open(&crashes_dir)?;

        let shared = Arc::new(SharedState::new(corpus, crashes));

        Ok(Self {
            config,
            shared,
            workers: Vec::new(),
            start_time: Instant::now(),
        })
    }

    /// Load seeds into the corpus.
    pub fn load_seeds(&self) -> Result<usize> {
        let mut loaded = 0;

        for seed_dir in &self.config.corpus.seed_dirs {
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
                        let id = self.shared.next_id();
                        let entry = CorpusEntry::new(id, input);
                        
                        // Save to corpus
                        self.shared.corpus.lock().unwrap().save(&entry)?;
                        
                        // Add to scheduler
                        let metadata = EntryMetadata::from_entry(&entry, 0);
                        self.shared.scheduler.write().unwrap().add(metadata);
                        
                        loaded += 1;
                    }
                }
            }
        }

        // Add empty seed if none loaded
        if loaded == 0 {
            let id = self.shared.next_id();
            let entry = CorpusEntry::new(id, vec![]);
            self.shared.corpus.lock().unwrap().save(&entry)?;
            let metadata = EntryMetadata::from_entry(&entry, 0);
            self.shared.scheduler.write().unwrap().add(metadata);
            loaded = 1;
        }

        self.shared.stats.set_corpus_size(loaded as u64);
        Ok(loaded)
    }

    /// Run the parallel fuzzer with the configured number of jobs.
    pub fn run(&mut self) -> Result<Stats> {
        let jobs = self.config.execution.jobs.max(1);

        // Load seeds first
        self.load_seeds()?;

        // Spawn worker threads
        for worker_id in 0..jobs {
            let config = self.config.clone();
            let shared = Arc::clone(&self.shared);

            let handle = thread::spawn(move || {
                if let Err(e) = run_worker(worker_id, config, shared) {
                    eprintln!("Worker {} error: {}", worker_id, e);
                }
            });

            self.workers.push(handle);
        }

        // Wait for all workers
        for handle in self.workers.drain(..) {
            let _ = handle.join();
        }

        Ok(self.shared.stats.to_stats(self.start_time))
    }

    /// Stop all workers.
    pub fn stop(&self) {
        self.shared.stop();
    }

    /// Get current statistics.
    pub fn stats(&self) -> Stats {
        self.shared.stats.to_stats(self.start_time)
    }

    /// Get number of active workers.
    pub fn worker_count(&self) -> usize {
        self.workers.len()
    }
}

/// Worker thread main loop.
fn run_worker(worker_id: usize, config: Config, shared: Arc<SharedState>) -> Result<()> {
    let target_path = config.target.path.as_ref().unwrap();

    // Each worker has its own executor and RNG
    let executor = ForkExecutor::new(target_path.clone())
        .args(config.target.args.clone())
        .timeout(Duration::from_millis(config.execution.timeout_ms))
        .input_mode(InputMode::Stdin);

    let mut mutator = Mutator::new();
    let mut rng = StdRng::from_entropy();
    let mut coverage = SancovCollector::new()?;

    while shared.is_running() {
        // Select entry from corpus
        let entry_id = {
            let mut scheduler = shared.scheduler.write().unwrap();
            match scheduler.select(&mut rng) {
                Some(id) => {
                    scheduler.update_fuzz_count(id);
                    id
                }
                None => continue,
            }
        };

        // Load entry
        let entry = {
            let corpus = shared.corpus.lock().unwrap();
            let entries = corpus.load_all()?;
            entries.into_iter().find(|e| e.id == entry_id)
        };

        let entry = match entry {
            Some(e) => e,
            None => continue,
        };

        // Fuzz the entry
        for _ in 0..config.mutation.havoc_cycles {
            if !shared.is_running() {
                break;
            }

            let mut input = entry.input.clone();
            mutator.mutate(&mut input, &mut rng);

            // Enforce size limit
            if input.len() > config.corpus.max_size {
                input.truncate(config.corpus.max_size);
            }

            // Execute
            coverage.reset();
            let result = executor.run(&input)?;
            shared.stats.record_exec();

            match result.status {
                ExitStatus::Signal(sig) => {
                    let crash_type = triage_from_signal(sig);
                    let crash = Crash::new(input.clone(), Some(sig), crash_type);

                    let mut crashes = shared.crashes.lock().unwrap();
                    if crashes.save(&crash)? {
                        shared.stats.record_crash();
                    }
                }
                ExitStatus::Timeout => {
                    shared.stats.record_timeout();
                }
                ExitStatus::Normal(_) => {
                    // Check for new coverage
                    let bitmap = coverage.collect();
                    let has_new = {
                        let virgin = shared.virgin.read().unwrap();
                        bitmap.has_new_bits(&virgin)
                    };

                    if has_new {
                        // Update virgin map
                        {
                            let mut virgin = shared.virgin.write().unwrap();
                            bitmap.update_virgin(&mut virgin);
                        }

                        // Add to corpus
                        let id = shared.next_id();
                        let mut new_entry = CorpusEntry::new(id, input);
                        new_entry.parent_id = Some(entry.id);
                        new_entry.coverage_hash = bitmap.hash();
                        new_entry.new_coverage = bitmap.set_indices();
                        new_entry.exec_time_us = result.exec_time.as_micros() as u64;

                        {
                            let mut corpus = shared.corpus.lock().unwrap();
                            corpus.save(&new_entry)?;
                        }

                        {
                            let metadata = EntryMetadata::from_entry(&new_entry, 1);
                            let mut scheduler = shared.scheduler.write().unwrap();
                            scheduler.add(metadata);
                        }

                        shared.stats.set_corpus_size(
                            shared.scheduler.read().unwrap().len() as u64
                        );
                    }
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::path::PathBuf;

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
        config.execution.jobs = 2;
        config
    }

    #[test]
    fn test_atomic_stats() {
        let stats = AtomicStats::new();
        
        stats.record_exec();
        stats.record_exec();
        assert_eq!(stats.total_execs.load(Ordering::Relaxed), 2);

        stats.record_crash();
        assert_eq!(stats.crashes_found.load(Ordering::Relaxed), 1);

        stats.record_timeout();
        assert_eq!(stats.timeouts.load(Ordering::Relaxed), 1);

        stats.set_corpus_size(10);
        assert_eq!(stats.corpus_size.load(Ordering::Relaxed), 10);
    }

    #[test]
    fn test_atomic_stats_to_stats() {
        let stats = AtomicStats::new();
        stats.total_execs.store(1000, Ordering::Relaxed);
        stats.crashes_found.store(5, Ordering::Relaxed);
        stats.corpus_size.store(50, Ordering::Relaxed);

        let start = Instant::now();
        let converted = stats.to_stats(start);

        assert_eq!(converted.total_execs, 1000);
        assert_eq!(converted.crashes_found, 5);
        assert_eq!(converted.corpus_size, 50);
    }

    #[test]
    fn test_shared_state_next_id() {
        let temp_dir = TempDir::new().unwrap();
        let corpus = CorpusStorage::open(temp_dir.path()).unwrap();
        let crashes = CrashStorage::open(&temp_dir.path().join("crashes")).unwrap();
        
        let shared = SharedState::new(corpus, crashes);

        assert_eq!(shared.next_id(), 1);
        assert_eq!(shared.next_id(), 2);
        assert_eq!(shared.next_id(), 3);
    }

    #[test]
    fn test_shared_state_running() {
        let temp_dir = TempDir::new().unwrap();
        let corpus = CorpusStorage::open(temp_dir.path()).unwrap();
        let crashes = CrashStorage::open(&temp_dir.path().join("crashes")).unwrap();
        
        let shared = SharedState::new(corpus, crashes);

        assert!(shared.is_running());
        shared.stop();
        assert!(!shared.is_running());
    }

    #[test]
    fn test_parallel_fuzzer_new() {
        let temp_dir = TempDir::new().unwrap();
        let config = make_test_config(&temp_dir);

        let fuzzer = ParallelFuzzer::new(config);
        assert!(fuzzer.is_ok());
    }

    #[test]
    fn test_parallel_fuzzer_load_seeds() {
        let temp_dir = TempDir::new().unwrap();
        let seeds_dir = temp_dir.path().join("seeds");
        std::fs::create_dir(&seeds_dir).unwrap();
        std::fs::write(seeds_dir.join("seed1"), b"test1").unwrap();
        std::fs::write(seeds_dir.join("seed2"), b"test2").unwrap();

        let mut config = make_test_config(&temp_dir);
        config.corpus.seed_dirs.push(seeds_dir);

        let fuzzer = ParallelFuzzer::new(config).unwrap();
        let count = fuzzer.load_seeds().unwrap();

        assert_eq!(count, 2);
    }

    #[test]
    fn test_parallel_fuzzer_stop() {
        let temp_dir = TempDir::new().unwrap();
        let config = make_test_config(&temp_dir);

        let fuzzer = ParallelFuzzer::new(config).unwrap();
        assert!(fuzzer.shared.is_running());

        fuzzer.stop();
        assert!(!fuzzer.shared.is_running());
    }
}
