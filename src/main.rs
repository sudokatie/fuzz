use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "fuzz")]
#[command(version, about = "Coverage-guided fuzzer")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Start fuzzing a target
    Run {
        /// Target binary to fuzz
        target: PathBuf,

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
    },

    /// Minimize a crashing input
    Minimize {
        /// Input file to minimize
        input: PathBuf,

        /// Target binary
        target: PathBuf,

        /// Output file for minimized input
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Triage crashes in a directory
    Triage {
        /// Directory containing crashes
        crashes_dir: PathBuf,

        /// Target binary
        target: PathBuf,
    },

    /// Show corpus coverage
    Cov {
        /// Corpus directory
        corpus: PathBuf,

        /// Target binary
        target: PathBuf,
    },

    /// Minimize corpus to smallest set with same coverage
    CorpusMin {
        /// Corpus directory
        corpus: PathBuf,

        /// Target binary
        target: PathBuf,

        /// Output directory for minimized corpus
        #[arg(short, long)]
        output: Option<PathBuf>,
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
            input,
            output,
            timeout,
            memory,
            jobs,
            dict,
            no_ui,
        } => {
            println!(
                "fuzzing {} (timeout={}ms, jobs={}, ui={})",
                target.display(),
                timeout,
                jobs,
                !no_ui
            );
            if let Some(seed) = input {
                println!("  seed corpus: {}", seed.display());
            }
            println!("  output: {}", output.display());
            if let Some(m) = memory {
                println!("  memory limit: {}MB", m);
            }
            if let Some(d) = dict {
                println!("  dictionary: {}", d.display());
            }
            // TODO: implement fuzzing loop
            Ok(())
        }
        Commands::Minimize {
            input,
            target,
            output,
        } => {
            println!(
                "minimizing {} for target {}",
                input.display(),
                target.display()
            );
            if let Some(out) = output {
                println!("  output: {}", out.display());
            }
            // TODO: implement minimization
            Ok(())
        }
        Commands::Triage {
            crashes_dir,
            target,
        } => {
            println!(
                "triaging crashes in {} for target {}",
                crashes_dir.display(),
                target.display()
            );
            // TODO: implement triage
            Ok(())
        }
        Commands::Cov { corpus, target } => {
            println!(
                "showing coverage for corpus {} on target {}",
                corpus.display(),
                target.display()
            );
            // TODO: implement coverage display
            Ok(())
        }
        Commands::CorpusMin {
            corpus,
            target,
            output,
        } => {
            println!(
                "minimizing corpus {} for target {}",
                corpus.display(),
                target.display()
            );
            if let Some(out) = output {
                println!("  output: {}", out.display());
            }
            // TODO: implement corpus minimization
            Ok(())
        }
    }
}
