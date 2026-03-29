const BITMAP_SIZE: usize = 65536;

/// Coverage bitmap for tracking edge coverage.
/// Uses 64KB of memory, indexed by edge hash.
#[derive(Clone)]
pub struct Bitmap {
    data: Box<[u8; BITMAP_SIZE]>,
}

impl Default for Bitmap {
    fn default() -> Self {
        Self::new()
    }
}

impl Bitmap {
    /// Create a new empty bitmap.
    pub fn new() -> Self {
        Self {
            data: Box::new([0u8; BITMAP_SIZE]),
        }
    }

    /// Create a virgin bitmap (all 0xff) for tracking uncovered edges.
    pub fn virgin() -> Self {
        Self {
            data: Box::new([0xff; BITMAP_SIZE]),
        }
    }

    /// Reset all entries to zero.
    pub fn reset(&mut self) {
        self.data.fill(0);
    }

    /// Set value at index.
    pub fn set(&mut self, idx: usize, val: u8) {
        if idx < BITMAP_SIZE {
            self.data[idx] = val;
        }
    }

    /// Get value at index.
    pub fn get(&self, idx: usize) -> u8 {
        self.data.get(idx).copied().unwrap_or(0)
    }

    /// Increment hit count at index (saturating).
    pub fn hit(&mut self, idx: usize) {
        if idx < BITMAP_SIZE {
            self.data[idx] = self.data[idx].saturating_add(1);
        }
    }

    /// Check if this bitmap has any new bits compared to a virgin map.
    /// Virgin map has 0xff where no coverage exists yet.
    /// Returns true if any byte in self is non-zero where virgin is 0xff.
    pub fn has_new_bits(&self, virgin: &Bitmap) -> bool {
        for i in 0..BITMAP_SIZE {
            if self.data[i] != 0 && virgin.data[i] == 0xff {
                return true;
            }
            // Also detect new hit count buckets
            if self.data[i] != 0 {
                let old_bucket = bucket_hit_count(255 - virgin.data[i]);
                let new_bucket = bucket_hit_count(self.data[i]);
                if new_bucket > old_bucket {
                    return true;
                }
            }
        }
        false
    }

    /// Update virgin map with new coverage.
    /// Sets virgin[i] to 0 where we have coverage.
    pub fn update_virgin(&self, virgin: &mut Bitmap) -> bool {
        let mut changed = false;
        for i in 0..BITMAP_SIZE {
            if self.data[i] != 0 && virgin.data[i] != 0 {
                let current_bucket = bucket_hit_count(self.data[i]);
                let virgin_bucket = bucket_hit_count(255 - virgin.data[i]);
                if current_bucket > virgin_bucket {
                    virgin.data[i] = 255 - self.data[i];
                    changed = true;
                }
            }
        }
        changed
    }

    /// Merge another bitmap into this one (OR operation).
    pub fn merge(&mut self, other: &Bitmap) {
        for i in 0..BITMAP_SIZE {
            self.data[i] |= other.data[i];
        }
    }

    /// Count non-zero entries.
    pub fn count_bits(&self) -> usize {
        self.data.iter().filter(|&&b| b != 0).count()
    }

    /// Get raw slice.
    pub fn as_slice(&self) -> &[u8] {
        &self.data[..]
    }

    /// Get mutable raw slice.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data[..]
    }

    /// Compute hash of the bitmap for corpus deduplication.
    pub fn hash(&self) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};

        let mut hasher = DefaultHasher::new();
        self.data.hash(&mut hasher);
        hasher.finish()
    }

    /// Get indices of all set bits.
    pub fn set_indices(&self) -> Vec<u16> {
        self.data
            .iter()
            .enumerate()
            .filter(|(_, &b)| b != 0)
            .map(|(i, _)| i as u16)
            .collect()
    }
}

/// Convert raw hit count to bucket value.
/// Buckets: 1, 2, 3, 4-7, 8-15, 16-31, 32-127, 128+
pub fn bucket_hit_count(count: u8) -> u8 {
    match count {
        0 => 0,
        1 => 1,
        2 => 2,
        3 => 4,
        4..=7 => 8,
        8..=15 => 16,
        16..=31 => 32,
        32..=127 => 64,
        _ => 128,
    }
}

/// Hash edge (from_block, to_block) to bitmap index.
pub fn edge_hash(from: u32, to: u32) -> usize {
    // Simple hash combining both blocks
    let hash = (from.wrapping_mul(31337) ^ to.wrapping_mul(65537)) as usize;
    hash % BITMAP_SIZE
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bitmap_new() {
        let bm = Bitmap::new();
        assert_eq!(bm.count_bits(), 0);
        for i in 0..100 {
            assert_eq!(bm.get(i), 0);
        }
    }

    #[test]
    fn test_bitmap_virgin() {
        let bm = Bitmap::virgin();
        for i in 0..100 {
            assert_eq!(bm.get(i), 0xff);
        }
    }

    #[test]
    fn test_bitmap_set_get() {
        let mut bm = Bitmap::new();
        bm.set(100, 42);
        assert_eq!(bm.get(100), 42);
        assert_eq!(bm.get(101), 0);

        bm.set(200, 255);
        assert_eq!(bm.get(200), 255);
    }

    #[test]
    fn test_bitmap_hit() {
        let mut bm = Bitmap::new();
        bm.hit(100);
        assert_eq!(bm.get(100), 1);
        bm.hit(100);
        assert_eq!(bm.get(100), 2);

        // Test saturation
        bm.set(200, 255);
        bm.hit(200);
        assert_eq!(bm.get(200), 255);
    }

    #[test]
    fn test_bitmap_has_new_bits_true() {
        let mut bm = Bitmap::new();
        let virgin = Bitmap::virgin();

        bm.set(100, 1);
        assert!(bm.has_new_bits(&virgin));
    }

    #[test]
    fn test_bitmap_has_new_bits_false() {
        let bm = Bitmap::new();
        let virgin = Bitmap::virgin();

        // Empty bitmap has no new bits
        assert!(!bm.has_new_bits(&virgin));
    }

    #[test]
    fn test_bitmap_merge() {
        let mut bm1 = Bitmap::new();
        let mut bm2 = Bitmap::new();

        bm1.set(100, 0b00001111);
        bm2.set(100, 0b11110000);
        bm2.set(200, 0b10101010);

        bm1.merge(&bm2);
        assert_eq!(bm1.get(100), 0b11111111);
        assert_eq!(bm1.get(200), 0b10101010);
    }

    #[test]
    fn test_bitmap_count_bits() {
        let mut bm = Bitmap::new();
        assert_eq!(bm.count_bits(), 0);

        bm.set(100, 1);
        bm.set(200, 2);
        bm.set(300, 3);
        assert_eq!(bm.count_bits(), 3);
    }

    #[test]
    fn test_hit_count_buckets() {
        assert_eq!(bucket_hit_count(0), 0);
        assert_eq!(bucket_hit_count(1), 1);
        assert_eq!(bucket_hit_count(2), 2);
        assert_eq!(bucket_hit_count(3), 4);
        assert_eq!(bucket_hit_count(4), 8);
        assert_eq!(bucket_hit_count(7), 8);
        assert_eq!(bucket_hit_count(8), 16);
        assert_eq!(bucket_hit_count(15), 16);
        assert_eq!(bucket_hit_count(16), 32);
        assert_eq!(bucket_hit_count(31), 32);
        assert_eq!(bucket_hit_count(32), 64);
        assert_eq!(bucket_hit_count(127), 64);
        assert_eq!(bucket_hit_count(128), 128);
        assert_eq!(bucket_hit_count(255), 128);
    }

    #[test]
    fn test_edge_hash() {
        let h1 = edge_hash(0, 1);
        let h2 = edge_hash(1, 0);
        let h3 = edge_hash(100, 200);

        // All should be valid indices
        assert!(h1 < BITMAP_SIZE);
        assert!(h2 < BITMAP_SIZE);
        assert!(h3 < BITMAP_SIZE);

        // Different edges should (usually) have different hashes
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_bitmap_hash() {
        let mut bm1 = Bitmap::new();
        let mut bm2 = Bitmap::new();

        assert_eq!(bm1.hash(), bm2.hash());

        bm1.set(100, 1);
        assert_ne!(bm1.hash(), bm2.hash());

        bm2.set(100, 1);
        assert_eq!(bm1.hash(), bm2.hash());
    }

    #[test]
    fn test_bitmap_set_indices() {
        let mut bm = Bitmap::new();
        bm.set(100, 1);
        bm.set(200, 2);
        bm.set(300, 3);

        let indices = bm.set_indices();
        assert_eq!(indices.len(), 3);
        assert!(indices.contains(&100));
        assert!(indices.contains(&200));
        assert!(indices.contains(&300));
    }
}
