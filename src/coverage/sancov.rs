use crate::coverage::bitmap::{bucket_hit_count, Bitmap};
use crate::error::{Error, Result};
use memmap2::MmapMut;
use std::fs::File;
use std::sync::atomic::{AtomicU32, Ordering};

const BITMAP_SIZE: usize = 65536;
static SHM_COUNTER: AtomicU32 = AtomicU32::new(0);

/// Coverage collector using SanitizerCoverage shared memory.
///
/// Creates a shared memory region that instrumented targets write coverage to.
/// Targets compiled with `-fsanitize-coverage=trace-pc-guard` will detect
/// the __AFL_SHM_ID environment variable and write edge coverage to the
/// shared memory.
pub struct SancovCollector {
    shm: MmapMut,
    shm_path: String,
    virgin: Bitmap,
}

impl SancovCollector {
    /// Create a new SanitizerCoverage collector.
    ///
    /// Creates a POSIX shared memory region and returns the collector.
    /// The shared memory path is set as __AFL_SHM_ID in the environment.
    pub fn new() -> Result<Self> {
        let shm_id = SHM_COUNTER.fetch_add(1, Ordering::SeqCst);
        let shm_path = format!("/fuzz_shm_{}", shm_id);

        // Create shared memory
        let shm = create_shm(&shm_path, BITMAP_SIZE)?;

        Ok(Self {
            shm,
            shm_path,
            virgin: Bitmap::virgin(),
        })
    }

    /// Get the shared memory environment variable name and value.
    /// Returns (name, value) tuple to set in target environment.
    pub fn env_var(&self) -> (&'static str, &str) {
        ("__AFL_SHM_ID", &self.shm_path)
    }

    /// Get the shared memory path for environment setup.
    pub fn shm_path(&self) -> &str {
        &self.shm_path
    }

    /// Reset the shared memory to zeros before next execution.
    pub fn reset(&mut self) {
        self.shm.fill(0);
    }

    /// Collect coverage from shared memory into a bitmap.
    ///
    /// Copies the raw coverage data, applies hit count bucketing,
    /// and returns a Bitmap suitable for analysis.
    pub fn collect(&self) -> Bitmap {
        let mut bitmap = Bitmap::new();
        let shm_slice = &self.shm[..BITMAP_SIZE];

        for (i, &count) in shm_slice.iter().enumerate() {
            if count != 0 {
                // Apply hit count bucketing
                bitmap.set(i, bucket_hit_count(count));
            }
        }

        bitmap
    }

    /// Check if the last execution found new coverage.
    ///
    /// Compares against the virgin map to detect previously unseen edges.
    pub fn has_new_coverage(&self) -> bool {
        let bitmap = self.collect();
        bitmap.has_new_bits(&self.virgin)
    }

    /// Update the virgin map with coverage from the last execution.
    ///
    /// Returns true if any new coverage was found.
    pub fn update_virgin(&mut self) -> bool {
        let bitmap = self.collect();
        bitmap.update_virgin(&mut self.virgin)
    }

    /// Get the current edge count (number of unique edges hit).
    pub fn edge_count(&self) -> usize {
        self.shm[..BITMAP_SIZE].iter().filter(|&&b| b != 0).count()
    }

    /// Get reference to the virgin bitmap.
    pub fn virgin(&self) -> &Bitmap {
        &self.virgin
    }

    /// Get mutable reference to shared memory for direct manipulation.
    /// Use with caution - primarily for testing.
    pub fn shm_mut(&mut self) -> &mut [u8] {
        &mut self.shm[..BITMAP_SIZE]
    }
}

impl Drop for SancovCollector {
    fn drop(&mut self) {
        // Clean up shared memory
        let _ = unlink_shm(&self.shm_path);
    }
}

/// Create POSIX shared memory region.
#[cfg(target_os = "macos")]
fn create_shm(path: &str, size: usize) -> Result<MmapMut> {
    use std::ffi::CString;

    let c_path = CString::new(path).map_err(|e| Error::Coverage(e.to_string()))?;

    unsafe {
        // Try to unlink first in case it exists from a previous run
        libc::shm_unlink(c_path.as_ptr());

        // Create shared memory object
        let fd = libc::shm_open(
            c_path.as_ptr(),
            libc::O_CREAT | libc::O_RDWR | libc::O_EXCL,
            0o600,
        );
        if fd < 0 {
            return Err(Error::Coverage(format!(
                "shm_open failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        // Set size
        if libc::ftruncate(fd, size as libc::off_t) < 0 {
            libc::close(fd);
            libc::shm_unlink(c_path.as_ptr());
            return Err(Error::Coverage(format!(
                "ftruncate failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        // Create File from fd for memmap2
        let file = File::from_raw_fd(fd);
        MmapMut::map_mut(&file).map_err(|e| Error::Coverage(format!("mmap failed: {}", e)))
    }
}

/// Create POSIX shared memory region on Linux.
#[cfg(target_os = "linux")]
fn create_shm(path: &str, size: usize) -> Result<MmapMut> {
    use std::ffi::CString;

    let c_path = CString::new(path).map_err(|e| Error::Coverage(e.to_string()))?;

    unsafe {
        // Try to unlink first
        libc::shm_unlink(c_path.as_ptr());

        // Create shared memory object
        let fd = libc::shm_open(
            c_path.as_ptr(),
            libc::O_CREAT | libc::O_RDWR | libc::O_EXCL,
            0o600,
        );
        if fd < 0 {
            return Err(Error::Coverage(format!(
                "shm_open failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        // Set size
        if libc::ftruncate(fd, size as i64) < 0 {
            libc::close(fd);
            libc::shm_unlink(c_path.as_ptr());
            return Err(Error::Coverage(format!(
                "ftruncate failed: {}",
                std::io::Error::last_os_error()
            )));
        }

        let file = File::from_raw_fd(fd);
        MmapMut::map_mut(&file).map_err(|e| Error::Coverage(format!("mmap failed: {}", e)))
    }
}

/// Fallback for other platforms using temp file.
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn create_shm(path: &str, size: usize) -> Result<MmapMut> {
    use std::fs::OpenOptions;
    use std::io::Write;

    // Use a temp file as fallback
    let temp_path = format!("/tmp{}", path);
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&temp_path)
        .map_err(|e| Error::Coverage(format!("failed to create temp file: {}", e)))?;

    // Initialize with zeros
    file.write_all(&vec![0u8; size])
        .map_err(|e| Error::Coverage(format!("failed to initialize file: {}", e)))?;

    MmapMut::map_mut(&file).map_err(|e| Error::Coverage(format!("mmap failed: {}", e)))
}

/// Unlink shared memory.
fn unlink_shm(path: &str) -> Result<()> {
    use std::ffi::CString;

    let c_path = CString::new(path).map_err(|e| Error::Coverage(e.to_string()))?;

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

#[cfg(unix)]
use std::os::unix::io::FromRawFd;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sancov_creation() {
        let collector = SancovCollector::new().expect("failed to create collector");
        assert!(!collector.shm_path().is_empty());
        assert!(collector.shm_path().starts_with("/fuzz_shm_"));
    }

    #[test]
    fn test_sancov_env_var() {
        let collector = SancovCollector::new().expect("failed to create collector");
        let (name, value) = collector.env_var();
        assert_eq!(name, "__AFL_SHM_ID");
        assert!(value.starts_with("/fuzz_shm_"));
    }

    #[test]
    fn test_sancov_reset() {
        let mut collector = SancovCollector::new().expect("failed to create collector");

        // Write some data
        collector.shm_mut()[100] = 5;
        collector.shm_mut()[200] = 10;

        // Reset should clear it
        collector.reset();
        assert_eq!(collector.shm_mut()[100], 0);
        assert_eq!(collector.shm_mut()[200], 0);
    }

    #[test]
    fn test_sancov_collect_empty() {
        let collector = SancovCollector::new().expect("failed to create collector");
        let bitmap = collector.collect();
        assert_eq!(bitmap.count_bits(), 0);
    }

    #[test]
    fn test_sancov_collect_with_coverage() {
        let mut collector = SancovCollector::new().expect("failed to create collector");

        // Simulate coverage writes from target
        collector.shm_mut()[100] = 1;
        collector.shm_mut()[200] = 5;
        collector.shm_mut()[300] = 50;

        let bitmap = collector.collect();
        assert_eq!(bitmap.count_bits(), 3);

        // Check hit count bucketing
        assert_eq!(bitmap.get(100), 1); // 1 -> 1
        assert_eq!(bitmap.get(200), 8); // 5 -> 8 (4-7 bucket)
        assert_eq!(bitmap.get(300), 64); // 50 -> 64 (32-127 bucket)
    }

    #[test]
    fn test_sancov_has_new_coverage() {
        let mut collector = SancovCollector::new().expect("failed to create collector");

        // No coverage yet
        assert!(!collector.has_new_coverage());

        // Add coverage
        collector.shm_mut()[100] = 1;
        assert!(collector.has_new_coverage());

        // Update virgin map
        collector.update_virgin();

        // Same coverage is no longer new
        assert!(!collector.has_new_coverage());

        // Add different coverage
        collector.shm_mut()[200] = 1;
        assert!(collector.has_new_coverage());
    }

    #[test]
    fn test_sancov_edge_count() {
        let mut collector = SancovCollector::new().expect("failed to create collector");

        assert_eq!(collector.edge_count(), 0);

        collector.shm_mut()[100] = 1;
        collector.shm_mut()[200] = 1;
        collector.shm_mut()[300] = 1;

        assert_eq!(collector.edge_count(), 3);
    }

    #[test]
    fn test_sancov_multiple_instances() {
        // Create multiple collectors to test unique IDs
        let c1 = SancovCollector::new().expect("failed to create collector 1");
        let c2 = SancovCollector::new().expect("failed to create collector 2");

        // Should have different paths
        assert_ne!(c1.shm_path(), c2.shm_path());

        // Both should work independently
        let mut c1 = c1;
        let mut c2 = c2;
        c1.shm_mut()[100] = 5;
        c2.shm_mut()[100] = 10;

        assert_eq!(c1.shm_mut()[100], 5);
        assert_eq!(c2.shm_mut()[100], 10);
    }

    #[test]
    fn test_sancov_cleanup_on_drop() {
        {
            let collector = SancovCollector::new().expect("failed to create collector");
            // Just verify it works
            assert!(!collector.shm_path().is_empty());
            // Collector dropped here, should clean up shm
        }

        // Create another - should work fine
        let mut collector2 = SancovCollector::new().expect("failed to create collector 2");
        assert!(!collector2.shm_path().is_empty());
        collector2.reset();
    }
}
