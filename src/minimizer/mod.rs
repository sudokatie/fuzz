use crate::error::Result;
use crate::executor::{ExitStatus, ForkExecutor};

/// Minimizes a crashing input to the smallest reproducer.
pub struct Minimizer {
    executor: ForkExecutor,
    original_status: ExitStatus,
}

impl Minimizer {
    /// Create a new minimizer.
    pub fn new(executor: ForkExecutor, original_status: ExitStatus) -> Self {
        Self {
            executor,
            original_status,
        }
    }

    /// Minimize an input.
    pub fn minimize(&self, input: &[u8]) -> Result<Vec<u8>> {
        let mut current = input.to_vec();

        // Phase 1: Binary search on length
        current = self.minimize_length(current)?;

        // Phase 2: Remove individual bytes
        current = self.minimize_bytes(current)?;

        // Phase 3: Replace with zeros
        current = self.replace_with_zeros(current)?;

        Ok(current)
    }

    /// Try to reduce input length using binary search.
    fn minimize_length(&self, mut input: Vec<u8>) -> Result<Vec<u8>> {
        let mut min_len = 1;
        let mut max_len = input.len();

        while min_len < max_len {
            let mid_len = (min_len + max_len) / 2;
            let truncated: Vec<u8> = input[..mid_len].to_vec();

            if self.still_crashes(&truncated)? {
                input = truncated;
                max_len = mid_len;
            } else {
                min_len = mid_len + 1;
            }
        }

        Ok(input)
    }

    /// Try to remove each byte.
    fn minimize_bytes(&self, mut input: Vec<u8>) -> Result<Vec<u8>> {
        let mut i = 0;
        while i < input.len() {
            let mut candidate = input.clone();
            candidate.remove(i);

            if !candidate.is_empty() && self.still_crashes(&candidate)? {
                input = candidate;
                // Don't increment i - try removing at same position again
            } else {
                i += 1;
            }
        }

        Ok(input)
    }

    /// Try to replace bytes with zeros.
    fn replace_with_zeros(&self, mut input: Vec<u8>) -> Result<Vec<u8>> {
        for i in 0..input.len() {
            if input[i] == 0 {
                continue;
            }

            let original = input[i];
            input[i] = 0;

            if !self.still_crashes(&input)? {
                input[i] = original;
            }
        }

        Ok(input)
    }

    /// Check if input still causes the same crash.
    fn still_crashes(&self, input: &[u8]) -> Result<bool> {
        let result = self.executor.run(input)?;
        Ok(self.matches_crash(&result.status))
    }

    /// Check if status matches original crash.
    fn matches_crash(&self, status: &ExitStatus) -> bool {
        match (&self.original_status, status) {
            (ExitStatus::Signal(s1), ExitStatus::Signal(s2)) => s1 == s2,
            (ExitStatus::Timeout, ExitStatus::Timeout) => true,
            _ => false,
        }
    }
}

/// Minimize a corpus to the smallest set with the same coverage.
pub fn minimize_corpus(
    entries: &[Vec<u8>],
    mut coverage_fn: impl FnMut(&[u8]) -> Vec<u16>,
) -> Vec<Vec<u8>> {
    use std::collections::HashSet;

    if entries.is_empty() {
        return Vec::new();
    }

    // Collect coverage for each entry
    let coverages: Vec<(Vec<u8>, HashSet<u16>)> = entries
        .iter()
        .map(|e| {
            let cov: HashSet<u16> = coverage_fn(e).into_iter().collect();
            (e.clone(), cov)
        })
        .collect();

    // Sort by coverage count (descending) to prioritize high-coverage inputs
    let mut sorted = coverages;
    sorted.sort_by(|a, b| b.1.len().cmp(&a.1.len()));

    // Greedy set cover
    let mut selected = Vec::new();
    let mut covered: HashSet<u16> = HashSet::new();

    for (input, cov) in sorted {
        let new_coverage: HashSet<_> = cov.difference(&covered).cloned().collect();
        if !new_coverage.is_empty() {
            covered.extend(new_coverage);
            selected.push(input);
        }
    }

    selected
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_minimize_corpus_empty() {
        let result = minimize_corpus(&[], |_| vec![]);
        assert!(result.is_empty());
    }

    #[test]
    fn test_minimize_corpus_unique_coverage() {
        let entries = vec![vec![1, 2, 3], vec![4, 5, 6], vec![7, 8, 9]];

        // Each entry has unique coverage
        let result = minimize_corpus(&entries, |e| match e[0] {
            1 => vec![100],
            4 => vec![200],
            7 => vec![300],
            _ => vec![],
        });

        assert_eq!(result.len(), 3);
    }

    #[test]
    fn test_minimize_corpus_overlapping_coverage() {
        let entries = vec![
            vec![1], // coverage: [100, 200]
            vec![2], // coverage: [100]
            vec![3], // coverage: [200]
        ];

        let result = minimize_corpus(&entries, |e| match e[0] {
            1 => vec![100, 200],
            2 => vec![100],
            3 => vec![200],
            _ => vec![],
        });

        // Entry [1] covers both, so others are redundant
        assert_eq!(result.len(), 1);
        assert_eq!(result[0], vec![1]);
    }

    #[test]
    fn test_minimize_corpus_partial_overlap() {
        let entries = vec![
            vec![1], // coverage: [100]
            vec![2], // coverage: [200]
            vec![3], // coverage: [100, 200] - but checked last, already covered
        ];

        let result = minimize_corpus(&entries, |e| match e[0] {
            1 => vec![100],
            2 => vec![200],
            3 => vec![100, 200],
            _ => vec![],
        });

        // Entry [3] has most coverage, should be selected first
        // Then nothing else adds new coverage
        assert_eq!(result.len(), 1);
    }
}
