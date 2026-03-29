use sha2::{Digest, Sha256};
use std::collections::HashSet;

/// Hash of a crash's stack trace for deduplication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct StackHash(pub u64);

impl StackHash {
    /// Create a stack hash from crash location info.
    pub fn from_location(signal: i32, address: Option<u64>, frames: &[u64]) -> Self {
        let mut hasher = Sha256::new();

        // Include signal in hash
        hasher.update(signal.to_le_bytes());

        // Include crash address if available
        if let Some(addr) = address {
            hasher.update(addr.to_le_bytes());
        }

        // Include top N stack frames
        let top_frames = &frames[..std::cmp::min(frames.len(), 3)];
        for frame in top_frames {
            hasher.update(frame.to_le_bytes());
        }

        let result = hasher.finalize();
        let hash = u64::from_le_bytes(result[..8].try_into().unwrap());
        Self(hash)
    }

    /// Create a simple hash from signal and a string description.
    pub fn from_description(signal: i32, desc: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(signal.to_le_bytes());
        hasher.update(desc.as_bytes());
        let result = hasher.finalize();
        let hash = u64::from_le_bytes(result[..8].try_into().unwrap());
        Self(hash)
    }
}

/// Crash deduplicator tracks unique crashes.
pub struct CrashDeduplicator {
    seen_hashes: HashSet<StackHash>,
}

impl Default for CrashDeduplicator {
    fn default() -> Self {
        Self::new()
    }
}

impl CrashDeduplicator {
    /// Create a new deduplicator.
    pub fn new() -> Self {
        Self {
            seen_hashes: HashSet::new(),
        }
    }

    /// Check if a crash hash has been seen before.
    /// Returns true if this is a new crash, false if duplicate.
    pub fn is_new(&self, hash: StackHash) -> bool {
        !self.seen_hashes.contains(&hash)
    }

    /// Add a crash hash. Returns true if it was new.
    pub fn add(&mut self, hash: StackHash) -> bool {
        self.seen_hashes.insert(hash)
    }

    /// Number of unique crashes seen.
    pub fn count(&self) -> usize {
        self.seen_hashes.len()
    }

    /// Clear all seen hashes.
    pub fn clear(&mut self) {
        self.seen_hashes.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_stack_hash_from_location() {
        let hash1 = StackHash::from_location(11, Some(0x1234), &[0x100, 0x200, 0x300]);
        let hash2 = StackHash::from_location(11, Some(0x1234), &[0x100, 0x200, 0x300]);
        let hash3 = StackHash::from_location(11, Some(0x5678), &[0x100, 0x200, 0x300]);

        // Same inputs should produce same hash
        assert_eq!(hash1, hash2);
        // Different inputs should produce different hash
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_stack_hash_from_description() {
        let hash1 = StackHash::from_description(11, "SEGV at 0x1234");
        let hash2 = StackHash::from_description(11, "SEGV at 0x1234");
        let hash3 = StackHash::from_description(11, "SEGV at 0x5678");

        assert_eq!(hash1, hash2);
        assert_ne!(hash1, hash3);
    }

    #[test]
    fn test_deduplicator_new() {
        let dedup = CrashDeduplicator::new();
        assert_eq!(dedup.count(), 0);
    }

    #[test]
    fn test_deduplicator_add() {
        let mut dedup = CrashDeduplicator::new();
        let hash = StackHash::from_description(11, "test crash");

        // First add should return true (new)
        assert!(dedup.add(hash));
        assert_eq!(dedup.count(), 1);

        // Second add should return false (duplicate)
        assert!(!dedup.add(hash));
        assert_eq!(dedup.count(), 1);
    }

    #[test]
    fn test_deduplicator_is_new() {
        let mut dedup = CrashDeduplicator::new();
        let hash = StackHash::from_description(11, "test crash");

        assert!(dedup.is_new(hash));
        dedup.add(hash);
        assert!(!dedup.is_new(hash));
    }

    #[test]
    fn test_deduplicator_clear() {
        let mut dedup = CrashDeduplicator::new();
        dedup.add(StackHash::from_description(11, "crash1"));
        dedup.add(StackHash::from_description(11, "crash2"));
        assert_eq!(dedup.count(), 2);

        dedup.clear();
        assert_eq!(dedup.count(), 0);
    }
}
