use super::strategies::MutationStrategy;
use rand::Rng;

/// Interesting 8-bit values.
const INTERESTING_8: &[u8] = &[
    0,   // Zero
    1,   // One
    16,  // Power of 2
    32,  // Power of 2
    64,  // Power of 2
    100, // Round number
    127, // Max signed i8
    128, // Min signed i8 (as u8)
    255, // Max u8
];

/// Interesting 16-bit values.
const INTERESTING_16: &[u16] = &[
    0,     // Zero
    1,     // One
    128,   // i8 boundary
    255,   // u8 max
    256,   // u8 max + 1
    512,   // Power of 2
    1000,  // Round number
    1024,  // Power of 2
    4096,  // Power of 2
    32767, // Max signed i16
    32768, // Min signed i16 (as u16)
    65535, // Max u16
];

/// Interesting 32-bit values.
const INTERESTING_32: &[u32] = &[
    0,          // Zero
    1,          // One
    255,        // u8 max
    256,        // u8 max + 1
    65535,      // u16 max
    65536,      // u16 max + 1
    100000,     // Round number
    1000000,    // Round number
    2147483647, // Max signed i32
    2147483648, // Min signed i32 (as u32)
    4294967295, // Max u32
];

/// Replace a byte with an interesting value.
pub struct Interesting8;

impl MutationStrategy for Interesting8 {
    fn mutate(&self, input: &mut Vec<u8>, rng: &mut impl Rng) {
        if input.is_empty() {
            return;
        }
        let idx = rng.gen_range(0..input.len());
        let val_idx = rng.gen_range(0..INTERESTING_8.len());
        input[idx] = INTERESTING_8[val_idx];
    }

    fn name(&self) -> &'static str {
        "interesting_8"
    }
}

/// Replace 2 bytes with an interesting 16-bit value.
pub struct Interesting16;

impl MutationStrategy for Interesting16 {
    fn mutate(&self, input: &mut Vec<u8>, rng: &mut impl Rng) {
        if input.len() < 2 {
            return;
        }
        let idx = rng.gen_range(0..input.len() - 1);
        let val_idx = rng.gen_range(0..INTERESTING_16.len());
        let val = INTERESTING_16[val_idx];

        // Random endianness
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
    fn mutate(&self, input: &mut Vec<u8>, rng: &mut impl Rng) {
        if input.len() < 4 {
            return;
        }
        let idx = rng.gen_range(0..input.len() - 3);
        let val_idx = rng.gen_range(0..INTERESTING_32.len());
        let val = INTERESTING_32[val_idx];

        // Random endianness
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
        // At least one byte should be an interesting value
        let has_interesting = input.iter().any(|&b| INTERESTING_8.contains(&b));
        assert!(has_interesting);
    }

    #[test]
    fn test_interesting_16() {
        let mut input = vec![0xFF, 0xFF, 0xFF, 0xFF];
        let mut rng = seeded_rng();
        Interesting16.mutate(&mut input, &mut rng);
        // At least 2 bytes should change (interesting value inserted)
        let changed = input.iter().filter(|&&b| b != 0xFF).count();
        assert!(changed >= 2);
    }

    #[test]
    fn test_interesting_32() {
        let mut input = vec![0xFF, 0xFF, 0xFF, 0xFF, 0xFF];
        let mut rng = seeded_rng();
        Interesting32.mutate(&mut input, &mut rng);
        // At least 4 bytes should change
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
