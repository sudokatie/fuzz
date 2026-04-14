//! Persistent mode executor for high-performance fuzzing.
//!
//! Persistent mode keeps the target process alive between test cases,
//! eliminating fork() overhead. The target must be compiled with a
//! fuzzing harness that calls our API.
//!
//! Example harness:
//! ```c
//! #include "fuzz.h"
//!
//! int main() {
//!     fuzz_init();
//!     
//!     while (fuzz_next_input()) {
//!         // Get input
//!         uint8_t *data = fuzz_get_input();
//!         size_t len = fuzz_get_input_len();
//!         
//!         // Call target function
//!         target_function(data, len);
//!     }
//!     
//!     return 0;
//! }
//! ```

use crate::error::{Error, Result};
use memmap2::MmapMut;
use std::fs::File;
use std::os::unix::io::FromRawFd;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

const SHM_INPUT_SIZE: usize = 1024 * 1024; // 1MB max input
const SHM_CONTROL_SIZE: usize = 4096;

static SHM_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Control structure for persistent mode communication.
#[repr(C)]
struct ControlBlock {
    /// Magic value to verify shared memory is set up
    magic: u32,
    /// Current input length
    input_len: u32,
    /// Status: 0=ready, 1=running, 2=done, 3=crash
    status: u32,
    /// Exit code or signal
    exit_code: i32,
}

const MAGIC: u32 = 0x46555A5A; // "FUZZ"
const STATUS_READY: u32 = 0;
const STATUS_RUNNING: u32 = 1;
const STATUS_DONE: u32 = 2;
const STATUS_CRASH: u32 = 3;

/// Execution result from persistent mode.
#[derive(Debug, Clone)]
pub struct PersistentResult {
    /// Whether the target crashed.
    pub crashed: bool,
    /// Exit code or signal.
    pub exit_code: i32,
    /// Execution time.
    pub exec_time: Duration,
}

/// Persistent mode executor.
///
/// Keeps target process alive and communicates via shared memory.
pub struct PersistentExecutor {
    target: PathBuf,
    args: Vec<String>,
    timeout: Duration,
    memory_limit_mb: Option<u64>,
    
    // Shared memory regions
    control_shm_path: String,
    input_shm_path: String,
    control_shm: Option<MmapMut>,
    input_shm: Option<MmapMut>,
    
    // Child process
    child: Option<Child>,
    
    // Stats
    iterations: u64,
    max_iterations: u64,
}

impl PersistentExecutor {
    /// Create a new persistent executor.
    pub fn new(target: PathBuf) -> Self {
        let id = SHM_COUNTER.fetch_add(1, Ordering::SeqCst);
        
        Self {
            target,
            args: Vec::new(),
            timeout: Duration::from_secs(1),
            memory_limit_mb: None,
            control_shm_path: format!("/fuzz_ctrl_{}", id),
            input_shm_path: format!("/fuzz_input_{}", id),
            control_shm: None,
            input_shm: None,
            child: None,
            iterations: 0,
            max_iterations: 10000, // Restart after this many iterations
        }
    }

    /// Set command line arguments.
    pub fn args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }

    /// Set execution timeout per test case.
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Set memory limit in MB.
    pub fn memory_limit(mut self, mb: u64) -> Self {
        self.memory_limit_mb = Some(mb);
        self
    }

    /// Set max iterations before restarting the target.
    pub fn max_iterations(mut self, max: u64) -> Self {
        self.max_iterations = max;
        self
    }

    /// Initialize the executor.
    pub fn init(&mut self) -> Result<()> {
        // Create shared memory regions
        self.control_shm = Some(create_shm(&self.control_shm_path, SHM_CONTROL_SIZE)?);
        self.input_shm = Some(create_shm(&self.input_shm_path, SHM_INPUT_SIZE)?);

        // Initialize control block
        self.init_control_block();

        // Start target process
        self.spawn_target()?;

        Ok(())
    }

    fn init_control_block(&mut self) {
        if let Some(ref mut shm) = self.control_shm {
            let control = shm.as_mut_ptr() as *mut ControlBlock;
            unsafe {
                (*control).magic = MAGIC;
                (*control).input_len = 0;
                (*control).status = STATUS_READY;
                (*control).exit_code = 0;
            }
        }
    }

    fn spawn_target(&mut self) -> Result<()> {
        let mut cmd = Command::new(&self.target);
        cmd.args(&self.args);
        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::null());
        cmd.stderr(Stdio::null());

        // Set environment variables for shared memory paths
        cmd.env("__FUZZ_CTRL_SHM", &self.control_shm_path);
        cmd.env("__FUZZ_INPUT_SHM", &self.input_shm_path);

        // Apply memory limit
        #[cfg(unix)]
        if let Some(mem_mb) = self.memory_limit_mb {
            use std::os::unix::process::CommandExt;
            let mem_bytes = mem_mb * 1024 * 1024;
            unsafe {
                cmd.pre_exec(move || {
                    let limit = libc::rlimit {
                        rlim_cur: mem_bytes,
                        rlim_max: mem_bytes,
                    };
                    libc::setrlimit(libc::RLIMIT_AS, &limit);
                    Ok(())
                });
            }
        }

        self.child = Some(cmd.spawn().map_err(|e| Error::Target(e.to_string()))?);
        self.iterations = 0;

        // Wait for target to initialize
        std::thread::sleep(Duration::from_millis(10));

        Ok(())
    }

    /// Run a single test case.
    pub fn run(&mut self, input: &[u8]) -> Result<PersistentResult> {
        // Check if we need to restart
        if self.iterations >= self.max_iterations {
            self.restart()?;
        }

        // Check if child is still alive
        if !self.is_child_alive() {
            self.restart()?;
        }

        let start = Instant::now();

        // Write input to shared memory
        self.write_input(input)?;

        // Signal target to start
        self.set_status(STATUS_RUNNING);

        // Wait for completion with timeout
        let result = self.wait_for_completion()?;

        self.iterations += 1;

        Ok(PersistentResult {
            crashed: result == STATUS_CRASH,
            exit_code: self.get_exit_code(),
            exec_time: start.elapsed(),
        })
    }

    fn write_input(&mut self, input: &[u8]) -> Result<()> {
        let len = input.len().min(SHM_INPUT_SIZE);

        // Write input data
        if let Some(ref mut shm) = self.input_shm {
            shm[..len].copy_from_slice(&input[..len]);
        }

        // Set input length in control block
        if let Some(ref mut shm) = self.control_shm {
            let control = shm.as_mut_ptr() as *mut ControlBlock;
            unsafe {
                (*control).input_len = len as u32;
            }
        }

        Ok(())
    }

    fn set_status(&mut self, status: u32) {
        if let Some(ref mut shm) = self.control_shm {
            let control = shm.as_mut_ptr() as *mut ControlBlock;
            unsafe {
                (*control).status = status;
            }
        }
    }

    fn get_status(&self) -> u32 {
        if let Some(ref shm) = self.control_shm {
            let control = shm.as_ptr() as *const ControlBlock;
            unsafe { (*control).status }
        } else {
            STATUS_CRASH
        }
    }

    fn get_exit_code(&self) -> i32 {
        if let Some(ref shm) = self.control_shm {
            let control = shm.as_ptr() as *const ControlBlock;
            unsafe { (*control).exit_code }
        } else {
            -1
        }
    }

    fn wait_for_completion(&self) -> Result<u32> {
        let start = Instant::now();
        let timeout_ms = self.timeout.as_millis() as u64;

        loop {
            let status = self.get_status();
            if status == STATUS_DONE || status == STATUS_CRASH {
                return Ok(status);
            }

            if start.elapsed().as_millis() as u64 > timeout_ms {
                return Ok(STATUS_CRASH); // Treat timeout as crash
            }

            // Brief sleep to avoid spinning
            std::thread::sleep(Duration::from_micros(100));
        }
    }

    fn is_child_alive(&mut self) -> bool {
        if let Some(ref mut child) = self.child {
            match child.try_wait() {
                Ok(None) => true,   // Still running
                Ok(Some(_)) => false, // Exited
                Err(_) => false,
            }
        } else {
            false
        }
    }

    fn restart(&mut self) -> Result<()> {
        // Kill existing child
        if let Some(ref mut child) = self.child {
            let _ = child.kill();
            let _ = child.wait();
        }
        self.child = None;

        // Reinitialize control block
        self.init_control_block();

        // Spawn new target
        self.spawn_target()?;

        Ok(())
    }

    /// Get iterations count.
    pub fn iterations(&self) -> u64 {
        self.iterations
    }
}

impl Drop for PersistentExecutor {
    fn drop(&mut self) {
        // Kill child process
        if let Some(ref mut child) = self.child {
            let _ = child.kill();
            let _ = child.wait();
        }

        // Clean up shared memory
        let _ = unlink_shm(&self.control_shm_path);
        let _ = unlink_shm(&self.input_shm_path);
    }
}

/// Create POSIX shared memory region.
#[cfg(target_os = "macos")]
fn create_shm(path: &str, size: usize) -> Result<MmapMut> {
    use std::ffi::CString;

    let c_path = CString::new(path).map_err(|e| Error::Target(e.to_string()))?;

    unsafe {
        libc::shm_unlink(c_path.as_ptr());

        let fd = libc::shm_open(
            c_path.as_ptr(),
            libc::O_CREAT | libc::O_RDWR | libc::O_EXCL,
            0o600,
        );
        if fd < 0 {
            return Err(Error::Target(format!(
                "shm_open failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        if libc::ftruncate(fd, size as libc::off_t) < 0 {
            libc::close(fd);
            libc::shm_unlink(c_path.as_ptr());
            return Err(Error::Target(format!(
                "ftruncate failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let file = File::from_raw_fd(fd);
        MmapMut::map_mut(&file).map_err(|e| Error::Target(format!("mmap failed: {}", e)))
    }
}

#[cfg(target_os = "linux")]
fn create_shm(path: &str, size: usize) -> Result<MmapMut> {
    use std::ffi::CString;

    let c_path = CString::new(path).map_err(|e| Error::Target(e.to_string()))?;

    unsafe {
        libc::shm_unlink(c_path.as_ptr());

        let fd = libc::shm_open(
            c_path.as_ptr(),
            libc::O_CREAT | libc::O_RDWR | libc::O_EXCL,
            0o600,
        );
        if fd < 0 {
            return Err(Error::Target(format!(
                "shm_open failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        if libc::ftruncate(fd, size as i64) < 0 {
            libc::close(fd);
            libc::shm_unlink(c_path.as_ptr());
            return Err(Error::Target(format!(
                "ftruncate failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let file = File::from_raw_fd(fd);
        MmapMut::map_mut(&file).map_err(|e| Error::Target(format!("mmap failed: {}", e)))
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn create_shm(path: &str, size: usize) -> Result<MmapMut> {
    use std::fs::OpenOptions;
    use std::io::Write;

    let temp_path = format!("/tmp{}", path);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temp_path)
        .map_err(|e| Error::Target(format!("failed to create temp file: {}", e)))?;

    file.write_all(&vec![0u8; size])
        .map_err(|e| Error::Target(format!("failed to initialize file: {}", e)))?;

    MmapMut::map_mut(&file).map_err(|e| Error::Target(format!("mmap failed: {}", e)))
}

fn unlink_shm(path: &str) -> Result<()> {
    use std::ffi::CString;

    let c_path = CString::new(path).map_err(|e| Error::Target(e.to_string()))?;

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    unsafe {
        libc::shm_unlink(c_path.as_ptr());
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let temp_path = format!("/tmp{}", path);
        let _ = std::fs::remove_file(&temp_path);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_persistent_executor_new() {
        let exec = PersistentExecutor::new(PathBuf::from("/bin/true"));
        assert_eq!(exec.iterations, 0);
        assert!(exec.child.is_none());
    }

    #[test]
    fn test_persistent_executor_builder() {
        let exec = PersistentExecutor::new(PathBuf::from("/bin/true"))
            .args(vec!["-v".to_string()])
            .timeout(Duration::from_millis(500))
            .memory_limit(100)
            .max_iterations(5000);

        assert_eq!(exec.args, vec!["-v"]);
        assert_eq!(exec.timeout, Duration::from_millis(500));
        assert_eq!(exec.memory_limit_mb, Some(100));
        assert_eq!(exec.max_iterations, 5000);
    }

    #[test]
    fn test_control_block_layout() {
        // Verify control block size assumptions
        assert_eq!(std::mem::size_of::<ControlBlock>(), 16);
    }

    #[test]
    fn test_persistent_result() {
        let result = PersistentResult {
            crashed: false,
            exit_code: 0,
            exec_time: Duration::from_millis(10),
        };
        assert!(!result.crashed);
        assert_eq!(result.exit_code, 0);
    }
}
