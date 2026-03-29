use super::strategies::{MutationStrategy, RngCore};

/// Interesting 8-bit values.
const INTERESTING_8: &[u8] = &[
    0, 1, 16, 32, 64, 100, 127, 128, 255,
];

/// Interesting 16-bit values.
const INTERESTING_16: &[u16] = &[
    0, 1, 128, 255, 256, 512, 1000, 1024, 4096, 32767, 32768, 65535,
];

/// Interesting 32-bit values.
const INTERESTING_32: &[u32] = &[
    0, 1, 255, 256, 65535, 65536, 100000, 1000000, 2147483647, 2147483648, 4294967295,
];

/// Replace a byte with an interesting value.
pub struct Interesting8;

impl MutationStrategy for Interesting8 {
    fn mutate(&self, input: &mut Vec<u8>, rng: &mut dyn RngCore) {
        if input.is_empty() {
            return;
        }
        let idx = rng.gen_range_usize(0, input.len());
        let val_idx = rng.gen_range_usize(0, INTERESTING_8.len());
        input[idx] = INTERESTING_8[val_idx];
    }

    fn name(&self) -> &'static str {
        "interesting_8"
    }
}

/// Replace 2 bytes with an interesting 16-bit value.
pub struct Interesting16;

impl MutationStrategy for Interesting16 {
    fn mutate(&self, input: &mut Vec<u8>, rng: &mut dyn RngCore) {
        if input.len() < 2 {
            return;
        }
        let idx = rng.gen_range_usize(0, input.len() - 1);
        let val_idx = rng.gen_range_usize(0, INTERESTING_16.len());
        let val = INTERESTING_16[val_idx];

        let bytes = if rng.gen_bool(0.5) {
            val.to_le_bytes()
        } else {
            val.to_be_bytes()
        };
        input[idx] = bytes[0];
        input[idx + 1] = bytes[1];
    }

    fn name(&self) -> &'static str {
        "interesting_16"
    }
}

/// Replace 4 bytes with an interesting 32-bit value.
pub struct Interesting32;

impl MutationStrategy for Interesting32 {
    fn mutate(&self, input: &mut Vec<u8>, rng: &mut dyn RngCore) {
        if input.len() < 4 {
            return;
        }
        let idx = rng.gen_range_usize(0, input.len() - 3);
        let val_idx = rng.gen_range_usize(0, INTERESTING_32.len());
        let val = INTERESTING_32[val_idx];

        let bytes = if rng.gen_bool(0.5) {
            val.to_le_bytes()
        } else {
            val.to_be_bytes()
        };
        for i in 0..4 {
            input[idx + i] = bytes[i];
        }
    }

    fn name(&self) -> &'static str {
        "interesting_32"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;

    fn seeded_rng() -> ChaCha8Rng {
        ChaCha8Rng::seed_from_u64(12345)
    }

    #[test]
    fn test_interesting_8() {
        let mut input = vec![0x42, 0x42, 0x42];
        let mut rng = seeded_rng();
        Interesting8.mutate(&mut input, &mut rng);
        let has_interesting = input.iter().any(|&b| INTERESTING_8.contains(&b));
        assert!(has_interesting);
    }

    #[test]
    fn test_interesting_16() {
        let mut input = vec![0xFF, 0xFF, 0xFF, 0xFF];
        let mut rng = seeded_rng();
        Interesting16.mutate(&mut input, &mut rng);
        let changed = input.iter().filter(|&&b| b != 0xFF).count();
        assert!(changed >= 2);
    }

    #[test]
    fn test_interesting_32() {
        let mut input = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let mut rng = seeded_rng();
        Interesting32.mutate(&mut input, &mut rng);
        let changed = input.iter().filter(|&&b| b != 0xFF).count();
        assert!(changed >= 4);
    }

    #[test]
    fn test_interesting_8_empty() {
        let mut input = vec![];
        let mut rng = seeded_rng();
        Interesting8.mutate(&mut input, &mut rng);
        assert!(input.is_empty());
    }

    #[test]
    fn test_interesting_16_short() {
        let mut input = vec![0x42];
        let original = input.clone();
        let mut rng = seeded_rng();
        Interesting16.mutate(&mut input, &mut rng);
        assert_eq!(input, original);
    }
}
