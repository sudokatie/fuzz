use clap::{Parser, Subcommand, ValueEnum};
use fuzz::config::Config;
use fuzz::coverage::SancovCollector;
use fuzz::executor::{ExitStatus, ForkExecutor, InputMode};
use fuzz::minimizer::{minimize_corpus, Minimizer};
use fuzz::{Fuzzer, ParallelFuzzer, PersistentFuzzer};
use std::path::PathBuf;
use std::time::Duration;

#[derive(Parser)]
#[command(name = "fuzz")]
#[command(version, about = "Coverage-guided fuzzer")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Clone, Copy, ValueEnum)]
enum CoverageMode {
    Sancov,
    Breakpoint,
}

#[derive(Subcommand)]
enum Commands {
    /// Start fuzzing a target
    Run {
        /// Target binary to fuzz
        target: PathBuf,

        /// Arguments to pass to target (@@ replaced with input file)
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,

        /// Seed corpus directory
        #[arg(short, long)]
        input: Option<PathBuf>,

        /// Output directory
        #[arg(short, long, default_value = "fuzz_output")]
        output: PathBuf,

        /// Execution timeout in milliseconds
        #[arg(short, long, default_value_t = 1000)]
        timeout: u64,

        /// Memory limit in MB
        #[arg(short, long)]
        memory: Option<u64>,

        /// Number of parallel jobs
        #[arg(short, long, default_value_t = 1)]
        jobs: usize,

        /// Dictionary file
        #[arg(short = 'x', long)]
        dict: Option<PathBuf>,

        /// Disable terminal UI
        #[arg(long)]
        no_ui: bool,

        /// Use persistent mode
        #[arg(long)]
        persistent: bool,

        /// Coverage mode
        #[arg(long, value_enum, default_value_t = CoverageMode::Sancov)]
        coverage: CoverageMode,
    },

    /// Minimize a crashing input
    Minimize {
        /// Input file to minimize
        input: PathBuf,

        /// Target binary
        target: PathBuf,

        /// Arguments to pass to target
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,

        /// Output file for minimized input
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Execution timeout in milliseconds
        #[arg(short, long, default_value_t = 1000)]
        timeout: u64,
    },

    /// Triage crashes in a directory
    Triage {
        /// Directory containing crashes
        crashes_dir: PathBuf,

        /// Target binary
        target: PathBuf,

        /// Arguments to pass to target
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,

        /// Execution timeout in milliseconds
        #[arg(short, long, default_value_t = 1000)]
        timeout: u64,
    },

    /// Show corpus coverage
    Cov {
        /// Corpus directory
        corpus: PathBuf,

        /// Target binary
        target: PathBuf,

        /// Arguments to pass to target
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,

        /// Execution timeout in milliseconds
        #[arg(short, long, default_value_t = 1000)]
        timeout: u64,

        /// Output HTML report
        #[arg(long)]
        html: Option<PathBuf>,
    },

    /// Minimize corpus to smallest set with same coverage
    CorpusMin {
        /// Corpus directory
        corpus: PathBuf,

        /// Target binary
        target: PathBuf,

        /// Arguments to pass to target
        #[arg(trailing_var_arg = true)]
        args: Vec<String>,

        /// Output directory for minimized corpus
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Execution timeout in milliseconds
        #[arg(short, long, default_value_t = 1000)]
        timeout: u64,
    },
}

fn main() {
    let cli = Cli::parse();

    if let Err(e) = run(cli) {
        eprintln!("error: {e}");
        std::process::exit(1);
    }
}

fn run(cli: Cli) -> fuzz::Result<()> {
    match cli.command {
        Commands::Run {
            target,
            args,
            input,
            output,
            timeout,
            memory,
            jobs,
            dict,
            no_ui,
            persistent,
            coverage,
        } => cmd_run(
            target, args, input, output, timeout, memory, jobs, dict, no_ui, persistent, coverage,
        ),
        Commands::Minimize {
            input,
            target,
            args,
            output,
            timeout,
        } => cmd_minimize(input, target, args, output, timeout),
        Commands::Triage {
            crashes_dir,
            target,
            args,
            timeout,
        } => cmd_triage(crashes_dir, target, args, timeout),
        Commands::Cov {
            corpus,
            target,
            args,
            timeout,
            html,
        } => cmd_cov(corpus, target, args, timeout, html),
        Commands::CorpusMin {
            corpus,
            target,
            args,
            output,
            timeout,
        } => cmd_corpus_min(corpus, target, args, output, timeout),
    }
}

fn cmd_run(
    target: PathBuf,
    args: Vec<String>,
    input: Option<PathBuf>,
    output: PathBuf,
    timeout: u64,
    memory: Option<u64>,
    jobs: usize,
    dict: Option<PathBuf>,
    no_ui: bool,
    persistent: bool,
    coverage: CoverageMode,
) -> fuzz::Result<()> {
    // Build config
    let mut config = Config::default();
    config.target.path = Some(target.clone());
    config.target.args = args;
    config.output.dir = output.clone();
    config.execution.timeout_ms = timeout;
    config.execution.memory_limit_mb = memory;
    config.execution.jobs = jobs;
    config.execution.coverage_mode = match coverage {
        CoverageMode::Sancov => fuzz::config::CoverageMode::Sancov,
        CoverageMode::Breakpoint => fuzz::config::CoverageMode::Breakpoint,
    };

    if let Some(seed_dir) = input {
        config.corpus.seed_dirs.push(seed_dir);
    }

    if let Some(dict_path) = dict {
        config.mutation.dictionary = Some(dict_path);
    }

    // Validate target exists
    if !target.exists() {
        return Err(fuzz::Error::Config(format!(
            "target does not exist: {}",
            target.display()
        )));
    }

    // Set persistent mode in config
    config.execution.persistent = persistent;

    if persistent {
        println!("fuzz - Coverage-guided fuzzer (PERSISTENT MODE)");
        println!("================================================");
        println!("Note: Target must be compiled with fuzz harness for persistent mode");
    } else {
        println!("fuzz - Coverage-guided fuzzer");
        println!("=============================");
    }
    println!("Target: {}", target.display());
    println!("Output: {}", output.display());
    println!("Timeout: {}ms", timeout);
    println!("Jobs: {}", jobs);
    if persistent {
        println!("Mode: persistent");
    }
    if let Some(m) = memory {
        println!("Memory limit: {}MB", m);
    }
    println!();

    // Run fuzzer based on mode
    let result = if persistent {
        // Persistent mode - single job only
        if jobs > 1 {
            eprintln!("Warning: Persistent mode only supports single job, ignoring -j flag");
        }
        let mut fuzzer = PersistentFuzzer::new(config, !no_ui)?;
        fuzzer.run()?
    } else if jobs > 1 {
        // Parallel fork mode
        let mut fuzzer = ParallelFuzzer::new(config)?;

        // Set up Ctrl-C handler
        let shared = fuzzer.shared_state();
        ctrlc::set_handler(move || {
            shared.stop();
        })
        .ok();

        fuzzer.run()?
    } else {
        // Single-threaded fork mode
        let mut fuzzer = Fuzzer::new(config, !no_ui)?;
        fuzzer.run()?
    };

    println!("\nFuzzing complete!");
    println!("  Total executions: {}", result.total_execs);
    println!("  Unique crashes: {}", result.crashes_found);
    println!("  Corpus size: {}", result.corpus_size);
    println!("  Coverage edges: {}", result.coverage_edges);
    println!("  Duration: {:?}", result.duration);

    Ok(())
}

fn cmd_minimize(
    input: PathBuf,
    target: PathBuf,
    args: Vec<String>,
    output: Option<PathBuf>,
    timeout: u64,
) -> fuzz::Result<()> {
    // Read input file
    let input_data = std::fs::read(&input).map_err(|e| {
        fuzz::Error::Minimize(format!("failed to read input file: {}", e))
    })?;

    println!("Minimizing {} ({} bytes)", input.display(), input_data.len());

    // Determine input mode from args
    let input_mode = if args.iter().any(|a| a == "@@") {
        InputMode::ArgReplace
    } else {
        InputMode::Stdin
    };

    // Create executor
    let executor = ForkExecutor::new(target)
        .args(args)
        .timeout(Duration::from_millis(timeout))
        .input_mode(input_mode);

    // Run once to get original crash status
    let original_result = executor.run(&input_data)?;
    if !original_result.status.is_crash() && !original_result.status.is_timeout() {
        return Err(fuzz::Error::Minimize(
            "input does not cause a crash or timeout".into(),
        ));
    }

    println!("Original status: {:?}", original_result.status);

    // Minimize
    let minimizer = Minimizer::new(executor, original_result.status);
    let minimized = minimizer.minimize(&input_data)?;

    println!(
        "Minimized: {} -> {} bytes ({:.1}% reduction)",
        input_data.len(),
        minimized.len(),
        (1.0 - minimized.len() as f64 / input_data.len() as f64) * 100.0
    );

    // Write output
    let output_path = output.unwrap_or_else(|| {
        let mut p = input.clone();
        p.set_extension("min");
        p
    });

    std::fs::write(&output_path, &minimized).map_err(|e| {
        fuzz::Error::Minimize(format!("failed to write output: {}", e))
    })?;

    println!("Written to: {}", output_path.display());

    Ok(())
}

fn cmd_triage(
    crashes_dir: PathBuf,
    target: PathBuf,
    args: Vec<String>,
    timeout: u64,
) -> fuzz::Result<()> {
    use fuzz::crash::{triage_from_signal, CrashType};
    use fuzz::executor::signal_name;

    if !crashes_dir.exists() {
        return Err(fuzz::Error::Config(format!(
            "crashes directory does not exist: {}",
            crashes_dir.display()
        )));
    }

    println!("Triaging crashes in {}", crashes_dir.display());
    println!();

    // Determine input mode
    let input_mode = if args.iter().any(|a| a == "@@") {
        InputMode::ArgReplace
    } else {
        InputMode::Stdin
    };

    let executor = ForkExecutor::new(target)
        .args(args)
        .timeout(Duration::from_millis(timeout))
        .input_mode(input_mode);

    let mut results: Vec<(String, CrashType, ExitStatus)> = Vec::new();

    // Walk crashes directory
    for entry in std::fs::read_dir(&crashes_dir)? {
        let entry = entry?;
        let path = entry.path();

        // Look for input files
        let input_path = if path.is_dir() {
            path.join("input")
        } else if path.is_file() && path.file_name().map(|n| n != "crash_info").unwrap_or(false) {
            path.clone()
        } else {
            continue;
        };

        if !input_path.exists() {
            continue;
        }

        let input_data = match std::fs::read(&input_path) {
            Ok(d) => d,
            Err(_) => continue,
        };

        let result = executor.run(&input_data)?;
        let crash_type = match &result.status {
            ExitStatus::Signal(sig) => triage_from_signal(*sig),
            ExitStatus::Timeout => CrashType::Timeout,
            ExitStatus::Normal(_) => CrashType::Unknown,
        };

        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "unknown".to_string());

        results.push((name, crash_type, result.status));
    }

    // Print results grouped by type
    println!("{:<40} {:<30} {}", "CRASH", "TYPE", "STATUS");
    println!("{}", "-".repeat(80));

    results.sort_by(|a, b| a.1.name().cmp(b.1.name()));

    for (name, crash_type, status) in &results {
        let status_str = match status {
            ExitStatus::Signal(sig) => signal_name(*sig).to_string(),
            ExitStatus::Timeout => "TIMEOUT".to_string(),
            ExitStatus::Normal(code) => format!("exit({})", code),
        };
        println!("{:<40} {:<30} {}", name, crash_type.name(), status_str);
    }

    println!();
    println!("Total: {} crashes", results.len());

    // Summary by type
    let mut type_counts: std::collections::HashMap<&str, usize> = std::collections::HashMap::new();
    for (_, crash_type, _) in &results {
        *type_counts.entry(crash_type.name()).or_insert(0) += 1;
    }

    println!("\nBy type:");
    for (typ, count) in type_counts {
        println!("  {}: {}", typ, count);
    }

    Ok(())
}

fn cmd_cov(
    corpus: PathBuf,
    target: PathBuf,
    args: Vec<String>,
    timeout: u64,
    html: Option<PathBuf>,
) -> fuzz::Result<()> {
    use fuzz::coverage::CoverageTracker;

    if !corpus.exists() {
        return Err(fuzz::Error::Config(format!(
            "corpus directory does not exist: {}",
            corpus.display()
        )));
    }

    println!("Analyzing coverage for corpus: {}", corpus.display());

    // Determine input mode
    let input_mode = if args.iter().any(|a| a == "@@") {
        InputMode::ArgReplace
    } else {
        InputMode::Stdin
    };

    let executor = ForkExecutor::new(target)
        .args(args)
        .timeout(Duration::from_millis(timeout))
        .input_mode(input_mode);

    let mut coverage = SancovCollector::new()?;
    let mut tracker = CoverageTracker::new();
    let mut input_count = 0;

    // Process all inputs in corpus
    for entry in std::fs::read_dir(&corpus)? {
        let entry = entry?;
        let path = entry.path();

        if !path.is_file() {
            continue;
        }

        // Skip non-input files
        if path.extension().map(|e| e == "db").unwrap_or(false) {
            continue;
        }

        let input_data = match std::fs::read(&path) {
            Ok(d) => d,
            Err(_) => continue,
        };

        coverage.reset();
        let _ = executor.run(&input_data);
        let bitmap = coverage.collect();
        tracker.update(&bitmap, input_count);
        input_count += 1;
    }

    let report = tracker.report();
    println!("{}", report.summary());

    // Write HTML if requested
    if let Some(html_path) = html {
        report.write_html(&html_path)?;
        println!("HTML report written to: {}", html_path.display());
    }

    Ok(())
}

fn cmd_corpus_min(
    corpus: PathBuf,
    target: PathBuf,
    args: Vec<String>,
    output: Option<PathBuf>,
    timeout: u64,
) -> fuzz::Result<()> {
    if !corpus.exists() {
        return Err(fuzz::Error::Config(format!(
            "corpus directory does not exist: {}",
            corpus.display()
        )));
    }

    println!("Minimizing corpus: {}", corpus.display());

    // Load all inputs
    let mut inputs: Vec<Vec<u8>> = Vec::new();
    for entry in std::fs::read_dir(&corpus)? {
        let entry = entry?;
        let path = entry.path();

        if !path.is_file() {
            continue;
        }

        if path.extension().map(|e| e == "db").unwrap_or(false) {
            continue;
        }

        if let Ok(data) = std::fs::read(&path) {
            inputs.push(data);
        }
    }

    println!("Loaded {} inputs", inputs.len());

    // Determine input mode
    let input_mode = if args.iter().any(|a| a == "@@") {
        InputMode::ArgReplace
    } else {
        InputMode::Stdin
    };

    let executor = ForkExecutor::new(target)
        .args(args)
        .timeout(Duration::from_millis(timeout))
        .input_mode(input_mode);

    let mut coverage = SancovCollector::new()?;

    // Coverage function for minimization
    let coverage_fn = |input: &[u8]| -> Vec<u16> {
        coverage.reset();
        let _ = executor.run(input);
        coverage.collect().set_indices()
    };

    let minimized = minimize_corpus(&inputs, coverage_fn);

    println!(
        "Minimized: {} -> {} inputs ({:.1}% reduction)",
        inputs.len(),
        minimized.len(),
        (1.0 - minimized.len() as f64 / inputs.len() as f64) * 100.0
    );

    // Write output
    let output_dir = output.unwrap_or_else(|| {
        let mut p = corpus.clone();
        p.set_file_name(format!(
            "{}_min",
            corpus.file_name().unwrap_or_default().to_string_lossy()
        ));
        p
    });

    std::fs::create_dir_all(&output_dir)?;

    for (i, input) in minimized.iter().enumerate() {
        let path = output_dir.join(format!("{:06}.input", i));
        std::fs::write(&path, input)?;
    }

    println!("Written to: {}", output_dir.display());

    Ok(())
}
