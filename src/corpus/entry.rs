use serde::{Deserialize, Serialize};
use std::time::SystemTime;

/// A single entry in the fuzzing corpus.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CorpusEntry {
    /// Unique identifier for this entry.
    pub id: u64,

    /// The actual input data.
    pub input: Vec<u8>,

    /// Hash of the coverage bitmap when this input was discovered.
    pub coverage_hash: u64,

    /// Indices of new coverage bits this input triggered.
    pub new_coverage: Vec<u16>,

    /// Execution time in microseconds.
    pub exec_time_us: u64,

    /// When this entry was discovered.
    pub found_at: SystemTime,

    /// ID of the parent entry this was mutated from.
    pub parent_id: Option<u64>,

    /// Name of the mutation that created this entry.
    pub mutation: Option<String>,
}

impl CorpusEntry {
    /// Create a new corpus entry.
    pub fn new(id: u64, input: Vec<u8>) -> Self {
        Self {
            id,
            input,
            coverage_hash: 0,
            new_coverage: Vec::new(),
            exec_time_us: 0,
            found_at: SystemTime::now(),
            parent_id: None,
            mutation: None,
        }
    }

    /// Create an entry from a seed input.
    pub fn from_seed(id: u64, input: Vec<u8>) -> Self {
        Self::new(id, input)
    }

    /// Size of the input in bytes.
    pub fn len(&self) -> usize {
        self.input.len()
    }

    /// Check if input is empty.
    pub fn is_empty(&self) -> bool {
        self.input.is_empty()
    }
}

/// Metadata about a corpus entry for scheduling.
#[derive(Debug, Clone)]
pub struct EntryMetadata {
    pub id: u64,
    pub exec_time_us: u64,
    pub coverage_count: usize,
    pub found_at: SystemTime,
    pub depth: usize,
    pub fuzz_count: u64,
}

impl EntryMetadata {
    pub fn from_entry(entry: &CorpusEntry, depth: usize) -> Self {
        Self {
            id: entry.id,
            exec_time_us: entry.exec_time_us,
            coverage_count: entry.new_coverage.len(),
            found_at: entry.found_at,
            depth,
            fuzz_count: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_corpus_entry_new() {
        let entry = CorpusEntry::new(1, vec![1, 2, 3, 4]);
        assert_eq!(entry.id, 1);
        assert_eq!(entry.input, vec![1, 2, 3, 4]);
        assert_eq!(entry.len(), 4);
        assert!(!entry.is_empty());
        assert!(entry.parent_id.is_none());
    }

    #[test]
    fn test_corpus_entry_empty() {
        let entry = CorpusEntry::new(1, vec![]);
        assert!(entry.is_empty());
        assert_eq!(entry.len(), 0);
    }

    #[test]
    fn test_entry_metadata() {
        let mut entry = CorpusEntry::new(1, vec![1, 2, 3]);
        entry.exec_time_us = 1000;
        entry.new_coverage = vec![100, 200, 300];

        let meta = EntryMetadata::from_entry(&entry, 5);
        assert_eq!(meta.id, 1);
        assert_eq!(meta.exec_time_us, 1000);
        assert_eq!(meta.coverage_count, 3);
        assert_eq!(meta.depth, 5);
        assert_eq!(meta.fuzz_count, 0);
    }
}
