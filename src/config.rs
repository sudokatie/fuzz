use serde::Deserialize;
use std::path::PathBuf;

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub target: TargetConfig,

    #[serde(default)]
    pub corpus: CorpusConfig,

    #[serde(default)]
    pub execution: ExecutionConfig,

    #[serde(default)]
    pub mutation: MutationConfig,

    #[serde(default)]
    pub output: OutputConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct TargetConfig {
    pub path: Option<PathBuf>,
    #[serde(default)]
    pub args: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct CorpusConfig {
    #[serde(default)]
    pub seed_dirs: Vec<PathBuf>,

    #[serde(default = "default_max_input_size")]
    pub max_size: usize,
}

impl Default for CorpusConfig {
    fn default() -> Self {
        Self {
            seed_dirs: Vec::new(),
            max_size: default_max_input_size(),
        }
    }
}

fn default_max_input_size() -> usize {
    1_048_576 // 1MB
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExecutionConfig {
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,

    pub memory_limit_mb: Option<u64>,

    #[serde(default = "default_jobs")]
    pub jobs: usize,
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            timeout_ms: default_timeout(),
            memory_limit_mb: None,
            jobs: default_jobs(),
        }
    }
}

fn default_timeout() -> u64 {
    1000
}

fn default_jobs() -> usize {
    1
}

#[derive(Debug, Clone, Default, Deserialize)]
pub struct MutationConfig {
    pub dictionary: Option<PathBuf>,

    #[serde(default = "default_havoc_cycles")]
    pub havoc_cycles: usize,
}

fn default_havoc_cycles() -> usize {
    5
}

#[derive(Debug, Clone, Deserialize)]
pub struct OutputConfig {
    #[serde(default = "default_output_dir")]
    pub dir: PathBuf,

    #[serde(default)]
    pub save_all: bool,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            dir: default_output_dir(),
            save_all: false,
        }
    }
}

fn default_output_dir() -> PathBuf {
    PathBuf::from("fuzz_output")
}

impl Default for Config {
    fn default() -> Self {
        Self {
            target: TargetConfig::default(),
            corpus: CorpusConfig::default(),
            execution: ExecutionConfig::default(),
            mutation: MutationConfig::default(),
            output: OutputConfig::default(),
        }
    }
}
