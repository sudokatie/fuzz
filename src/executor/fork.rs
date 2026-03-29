use crate::error::{Error, Result};
use nix::sys::signal::{self, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};
use std::fs::{self, File};
use std::io::Write;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};

/// Result of executing the target.
#[derive(Debug, Clone)]
pub struct ExecutionResult {
    /// How the process exited.
    pub status: ExitStatus,
    /// Time taken for execution.
    pub exec_time: Duration,
}

/// How a process exited.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExitStatus {
    /// Normal exit with code.
    Normal(i32),
    /// Killed by signal.
    Signal(i32),
    /// Timed out.
    Timeout,
}

impl ExitStatus {
    /// Check if this was a crash (signal or non-zero exit).
    pub fn is_crash(&self) -> bool {
        match self {
            ExitStatus::Normal(code) => *code != 0,
            ExitStatus::Signal(_) => true,
            ExitStatus::Timeout => false,
        }
    }

    /// Check if this was a timeout.
    pub fn is_timeout(&self) -> bool {
        matches!(self, ExitStatus::Timeout)
    }

    /// Get signal number if killed by signal.
    pub fn signal(&self) -> Option<i32> {
        match self {
            ExitStatus::Signal(sig) => Some(*sig),
            _ => None,
        }
    }
}

/// How to pass input to the target.
#[derive(Debug, Clone)]
pub enum InputMode {
    /// Pass via stdin.
    Stdin,
    /// Write to a file and pass filename.
    File(PathBuf),
    /// Replace @@ in args with filename.
    ArgReplace,
}

impl Default for InputMode {
    fn default() -> Self {
        InputMode::Stdin
    }
}

/// Fork-based executor.
pub struct ForkExecutor {
    target: PathBuf,
    args: Vec<String>,
    timeout: Duration,
    input_mode: InputMode,
    temp_dir: PathBuf,
}

impl ForkExecutor {
    /// Create a new fork executor.
    pub fn new(target: PathBuf) -> Self {
        Self {
            target,
            args: Vec::new(),
            timeout: Duration::from_secs(1),
            input_mode: InputMode::default(),
            temp_dir: std::env::temp_dir(),
        }
    }

    /// Set command line arguments.
    pub fn args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    /// Set execution timeout.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set input mode.
    pub fn input_mode(mut self, mode: InputMode) -> Self {
        self.input_mode = mode;
        self
    }

    /// Set temp directory for input files.
    pub fn temp_dir(mut self, dir: PathBuf) -> Self {
        self.temp_dir = dir;
        self
    }

    /// Run the target with the given input.
    pub fn run(&self, input: &[u8]) -> Result<ExecutionResult> {
        let start = Instant::now();

        // Prepare input file if needed
        let input_file = match &self.input_mode {
            InputMode::Stdin => None,
            InputMode::File(path) => {
                fs::write(path, input)?;
                Some(path.clone())
            }
            InputMode::ArgReplace => {
                let path = self.temp_dir.join("fuzz_input");
                fs::write(&path, input)?;
                Some(path)
            }
        };

        // Build command arguments
        let args: Vec<String> = if let Some(ref path) = input_file {
            self.args
                .iter()
                .map(|arg| {
                    if arg == "@@" {
                        path.to_string_lossy().to_string()
                    } else {
                        arg.clone()
                    }
                })
                .collect()
        } else {
            self.args.clone()
        };

        // Execute using Command (safer than raw fork)
        let result = self.execute_with_timeout(input, &args, input_file.as_deref())?;

        // Clean up temp file
        if let Some(path) = input_file {
            let _ = fs::remove_file(path);
        }

        Ok(ExecutionResult {
            status: result,
            exec_time: start.elapsed(),
        })
    }

    fn execute_with_timeout(
        &self,
        input: &[u8],
        args: &[String],
        _input_file: Option<&Path>,
    ) -> Result<ExitStatus> {
        use std::process::Stdio;

        let mut cmd = Command::new(&self.target);
        cmd.args(args);

        // Set up stdin
        match &self.input_mode {
            InputMode::Stdin => {
                cmd.stdin(Stdio::piped());
            }
            _ => {
                cmd.stdin(Stdio::null());
            }
        }

        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::null());

        let mut child = cmd.spawn().map_err(|e| Error::Target(e.to_string()))?;

        // Write input to stdin if needed
        if matches!(self.input_mode, InputMode::Stdin) {
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(input);
            }
        }

        // Wait with timeout
        let timeout_ms = self.timeout.as_millis() as u64;
        let start = Instant::now();

        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    return Ok(if let Some(code) = status.code() {
                        ExitStatus::Normal(code)
                    } else {
                        // Killed by signal
                        #[cfg(unix)]
                        {
                            use std::os::unix::process::ExitStatusExt;
                            if let Some(sig) = status.signal() {
                                return Ok(ExitStatus::Signal(sig));
                            }
                        }
                        ExitStatus::Normal(-1)
                    });
                }
                Ok(None) => {
                    if start.elapsed().as_millis() as u64 > timeout_ms {
                        let _ = child.kill();
                        let _ = child.wait();
                        return Ok(ExitStatus::Timeout);
                    }
                    std::thread::sleep(Duration::from_millis(1));
                }
                Err(e) => {
                    return Err(Error::Target(e.to_string()));
                }
            }
        }
    }
}

/// Check if a signal indicates a crash.
pub fn is_crash_signal(sig: i32) -> bool {
    matches!(
        sig,
        libc::SIGSEGV | libc::SIGBUS | libc::SIGABRT | libc::SIGFPE | libc::SIGILL
    )
}

/// Get signal name.
pub fn signal_name(sig: i32) -> &'static str {
    match sig {
        libc::SIGSEGV => "SIGSEGV",
        libc::SIGBUS => "SIGBUS",
        libc::SIGABRT => "SIGABRT",
        libc::SIGFPE => "SIGFPE",
        libc::SIGILL => "SIGILL",
        libc::SIGKILL => "SIGKILL",
        libc::SIGTERM => "SIGTERM",
        _ => "UNKNOWN",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_test_script(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "#!/bin/bash").unwrap();
        writeln!(file, "{}", content).unwrap();
        file.flush().unwrap();

        // Make executable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = file.as_file().metadata().unwrap().permissions();
            perms.set_mode(0o755);
            file.as_file().set_permissions(perms).unwrap();
        }

        file
    }

    #[test]
    fn test_exit_status_normal() {
        let status = ExitStatus::Normal(0);
        assert!(!status.is_crash());
        assert!(!status.is_timeout());
        assert_eq!(status.signal(), None);
    }

    #[test]
    fn test_exit_status_crash() {
        let status = ExitStatus::Normal(1);
        assert!(status.is_crash());

        let status = ExitStatus::Signal(libc::SIGSEGV);
        assert!(status.is_crash());
        assert_eq!(status.signal(), Some(libc::SIGSEGV));
    }

    #[test]
    fn test_exit_status_timeout() {
        let status = ExitStatus::Timeout;
        assert!(!status.is_crash());
        assert!(status.is_timeout());
    }

    #[test]
    fn test_executor_normal_exit() {
        let script = create_test_script("exit 0");
        let executor = ForkExecutor::new(script.path().to_path_buf())
            .timeout(Duration::from_secs(5));

        let result = executor.run(b"test input").unwrap();
        assert_eq!(result.status, ExitStatus::Normal(0));
    }

    #[test]
    fn test_executor_non_zero_exit() {
        let script = create_test_script("exit 42");
        let executor = ForkExecutor::new(script.path().to_path_buf())
            .timeout(Duration::from_secs(5));

        let result = executor.run(b"test input").unwrap();
        assert_eq!(result.status, ExitStatus::Normal(42));
    }

    #[test]
    fn test_executor_timeout() {
        let script = create_test_script("sleep 10");
        let executor = ForkExecutor::new(script.path().to_path_buf())
            .timeout(Duration::from_millis(100));

        let result = executor.run(b"test input").unwrap();
        assert_eq!(result.status, ExitStatus::Timeout);
    }

    #[test]
    fn test_executor_stdin_input() {
        let script = create_test_script("read line; [ \"$line\" = \"hello\" ] && exit 0 || exit 1");
        let executor = ForkExecutor::new(script.path().to_path_buf())
            .input_mode(InputMode::Stdin)
            .timeout(Duration::from_secs(5));

        let result = executor.run(b"hello\n").unwrap();
        assert_eq!(result.status, ExitStatus::Normal(0));
    }

    #[test]
    fn test_signal_name() {
        assert_eq!(signal_name(libc::SIGSEGV), "SIGSEGV");
        assert_eq!(signal_name(libc::SIGABRT), "SIGABRT");
        assert_eq!(signal_name(999), "UNKNOWN");
    }

    #[test]
    fn test_is_crash_signal() {
        assert!(is_crash_signal(libc::SIGSEGV));
        assert!(is_crash_signal(libc::SIGABRT));
        assert!(!is_crash_signal(libc::SIGTERM));
    }
}
