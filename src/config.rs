use crate::error::{Error, Result};
use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};

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

/// Coverage tracking mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CoverageMode {
    /// SanitizerCoverage (requires instrumented binary)
    #[default]
    Sancov,
    /// Breakpoint-based coverage (works on uninstrumented binaries)
    Breakpoint,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ExecutionConfig {
    #[serde(default = "default_timeout")]
    pub timeout_ms: u64,

    pub memory_limit_mb: Option<u64>,

    #[serde(default = "default_jobs")]
    pub jobs: usize,

    #[serde(default)]
    pub coverage_mode: CoverageMode,

    #[serde(default)]
    pub persistent: bool,
}

impl Default for ExecutionConfig {
    fn default() -> Self {
        Self {
            timeout_ms: default_timeout(),
            memory_limit_mb: None,
            jobs: default_jobs(),
            coverage_mode: CoverageMode::default(),
            persistent: false,
        }
    }
}

fn default_timeout() -> u64 {
    1000
}

fn default_jobs() -> usize {
    1
}

#[derive(Debug, Clone, Deserialize)]
pub struct MutationConfig {
    pub dictionary: Option<PathBuf>,

    #[serde(default = "default_havoc_cycles")]
    pub havoc_cycles: usize,
}

fn default_havoc_cycles() -> usize {
    5
}

impl Default for MutationConfig {
    fn default() -> Self {
        Self {
            dictionary: None,
            havoc_cycles: default_havoc_cycles(),
        }
    }
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

impl Config {
    /// Load config from a TOML file.
    pub fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("failed to read config file: {}", e)))?;
        Self::parse(&content)
    }

    /// Parse config from TOML string.
    pub fn parse(content: &str) -> Result<Self> {
        toml::from_str(content).map_err(|e| Error::Config(format!("failed to parse config: {}", e)))
    }

    /// Load config from file if it exists, otherwise use defaults.
    pub fn load_or_default(path: Option<&Path>) -> Result<Self> {
        match path {
            Some(p) if p.exists() => Self::load(p),
            _ => Ok(Self::default()),
        }
    }

    /// Validate the config.
    pub fn validate(&self) -> Result<()> {
        // Validate target path if specified
        if let Some(ref path) = self.target.path {
            if !path.exists() {
                return Err(Error::Config(format!(
                    "target path does not exist: {}",
                    path.display()
                )));
            }
        }

        // Validate seed directories
        for dir in &self.corpus.seed_dirs {
            if !dir.exists() {
                return Err(Error::Config(format!(
                    "seed directory does not exist: {}",
                    dir.display()
                )));
            }
        }

        // Validate timeout
        if self.execution.timeout_ms == 0 {
            return Err(Error::Config("timeout must be greater than 0".into()));
        }

        Ok(())
    }
}

/// Load config from path or return defaults.
pub fn load_config(path: Option<&Path>) -> Result<Config> {
    Config::load_or_default(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert!(config.target.path.is_none());
        assert_eq!(config.execution.timeout_ms, 1000);
        assert_eq!(config.execution.jobs, 1);
        assert_eq!(config.corpus.max_size, 1_048_576);
        assert_eq!(config.output.dir, PathBuf::from("fuzz_output"));
    }

    #[test]
    fn test_config_parse() {
        let toml = r#"
[target]
path = "/bin/test"
args = ["-f", "@@"]

[execution]
timeout_ms = 5000
jobs = 4

[corpus]
max_size = 4096

[output]
dir = "my_output"
save_all = true
"#;

        let config = Config::parse(toml).expect("failed to parse");
        assert_eq!(config.target.path, Some(PathBuf::from("/bin/test")));
        assert_eq!(config.target.args, vec!["-f", "@@"]);
        assert_eq!(config.execution.timeout_ms, 5000);
        assert_eq!(config.execution.jobs, 4);
        assert_eq!(config.corpus.max_size, 4096);
        assert_eq!(config.output.dir, PathBuf::from("my_output"));
        assert!(config.output.save_all);
    }

    #[test]
    fn test_config_parse_partial() {
        // Only specify some fields, rest should use defaults
        let toml = r#"
[execution]
timeout_ms = 2000
"#;

        let config = Config::parse(toml).expect("failed to parse");
        assert_eq!(config.execution.timeout_ms, 2000);
        assert_eq!(config.execution.jobs, 1); // default
        assert!(config.target.path.is_none()); // default
    }

    #[test]
    fn test_config_load_file() {
        let dir = TempDir::new().unwrap();
        let config_path = dir.path().join("fuzz.toml");

        fs::write(
            &config_path,
            r#"
[execution]
timeout_ms = 3000
"#,
        )
        .unwrap();

        let config = Config::load(&config_path).expect("failed to load");
        assert_eq!(config.execution.timeout_ms, 3000);
    }

    #[test]
    fn test_config_load_or_default_missing() {
        let config = Config::load_or_default(Some(Path::new("/nonexistent/config.toml")))
            .expect("should return defaults");
        assert_eq!(config.execution.timeout_ms, 1000);
    }

    #[test]
    fn test_config_validate_timeout_zero() {
        let mut config = Config::default();
        config.execution.timeout_ms = 0;

        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_config_validate_missing_seed_dir() {
        let mut config = Config::default();
        config
            .corpus
            .seed_dirs
            .push(PathBuf::from("/nonexistent/seeds"));

        let result = config.validate();
        assert!(result.is_err());
    }

    #[test]
    fn test_load_config_helper() {
        let config = load_config(None).expect("should return defaults");
        assert_eq!(config.execution.timeout_ms, 1000);
    }
}
