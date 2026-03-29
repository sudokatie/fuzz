pub mod dedup;
pub mod triage;

pub use dedup::{CrashDeduplicator, StackHash};
pub use triage::{triage_from_asan, triage_from_signal, triage_from_status, CrashType};

use crate::error::Result;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// Information about a crash.
#[derive(Debug, Clone)]
pub struct Crash {
    /// The crashing input.
    pub input: Vec<u8>,
    /// Signal that caused the crash.
    pub signal: Option<i32>,
    /// Stack hash for deduplication.
    pub stack_hash: StackHash,
    /// Type of crash.
    pub crash_type: CrashType,
    /// Crash location (if known).
    pub location: Option<String>,
    /// When the crash was found.
    pub found_at: SystemTime,
}

impl Crash {
    /// Create a new crash record.
    pub fn new(input: Vec<u8>, signal: Option<i32>, crash_type: CrashType) -> Self {
        let stack_hash = if let Some(sig) = signal {
            StackHash::from_description(sig, crash_type.name())
        } else {
            StackHash::from_description(0, crash_type.name())
        };

        Self {
            input,
            signal,
            stack_hash,
            crash_type,
            location: None,
            found_at: SystemTime::now(),
        }
    }

    /// Set crash location.
    pub fn with_location(mut self, location: String) -> Self {
        // Update stack hash to include location
        if let Some(sig) = self.signal {
            self.stack_hash = StackHash::from_description(sig, &location);
        }
        self.location = Some(location);
        self
    }
}

/// Crash storage manager.
pub struct CrashStorage {
    dir: PathBuf,
    dedup: CrashDeduplicator,
}

impl CrashStorage {
    /// Open crash storage at the given directory.
    pub fn open(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
            dedup: CrashDeduplicator::new(),
        })
    }

    /// Save a crash if it's unique. Returns true if saved.
    pub fn save(&mut self, crash: &Crash) -> Result<bool> {
        if !self.dedup.add(crash.stack_hash) {
            return Ok(false);
        }

        // Create directory for this crash hash
        let crash_dir = self.dir.join(format!("{:016x}", crash.stack_hash.0));
        fs::create_dir_all(&crash_dir)?;

        // Save input
        fs::write(crash_dir.join("input"), &crash.input)?;

        // Save crash info
        let info = format!(
            "Type: {}\nSignal: {:?}\nLocation: {:?}\nHash: {:016x}\n",
            crash.crash_type.name(),
            crash.signal,
            crash.location,
            crash.stack_hash.0
        );
        fs::write(crash_dir.join("crash_info"), info)?;

        Ok(true)
    }

    /// Number of unique crashes.
    pub fn count(&self) -> usize {
        self.dedup.count()
    }

    /// Path to crashes directory.
    pub fn path(&self) -> &Path {
        &self.dir
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_crash_new() {
        let crash = Crash::new(vec![1, 2, 3], Some(libc::SIGSEGV), CrashType::SegFault);
        assert_eq!(crash.input, vec![1, 2, 3]);
        assert_eq!(crash.signal, Some(libc::SIGSEGV));
        assert_eq!(crash.crash_type, CrashType::SegFault);
    }

    #[test]
    fn test_crash_with_location() {
        let crash = Crash::new(vec![1, 2, 3], Some(libc::SIGSEGV), CrashType::SegFault)
            .with_location("main+0x42".to_string());
        assert_eq!(crash.location, Some("main+0x42".to_string()));
    }

    #[test]
    fn test_crash_storage_open() {
        let tmp = TempDir::new().unwrap();
        let storage = CrashStorage::open(tmp.path()).unwrap();
        assert_eq!(storage.count(), 0);
    }

    #[test]
    fn test_crash_storage_save() {
        let tmp = TempDir::new().unwrap();
        let mut storage = CrashStorage::open(tmp.path()).unwrap();

        let crash = Crash::new(vec![1, 2, 3], Some(libc::SIGSEGV), CrashType::SegFault);

        // First save should succeed
        assert!(storage.save(&crash).unwrap());
        assert_eq!(storage.count(), 1);

        // Second save should be deduplicated
        assert!(!storage.save(&crash).unwrap());
        assert_eq!(storage.count(), 1);
    }

    #[test]
    fn test_crash_storage_unique_crashes() {
        let tmp = TempDir::new().unwrap();
        let mut storage = CrashStorage::open(tmp.path()).unwrap();

        let crash1 = Crash::new(vec![1], Some(libc::SIGSEGV), CrashType::SegFault)
            .with_location("func1".to_string());
        let crash2 = Crash::new(vec![2], Some(libc::SIGSEGV), CrashType::SegFault)
            .with_location("func2".to_string());

        assert!(storage.save(&crash1).unwrap());
        assert!(storage.save(&crash2).unwrap());
        assert_eq!(storage.count(), 2);
    }
}
