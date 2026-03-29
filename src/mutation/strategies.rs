use rand::Rng;

/// Trait for mutation strategies.
pub trait MutationStrategy: Send + Sync {
    /// Apply mutation to input buffer.
    fn mutate(&self, input: &mut Vec<u8>, rng: &mut dyn RngCore);

    /// Name of this mutation strategy.
    fn name(&self) -> &'static str;
}

/// Object-safe wrapper around RNG functionality we need.
pub trait RngCore {
    fn gen_range_usize(&mut self, low: usize, high: usize) -> usize;
    fn gen_range_i32(&mut self, low: i32, high: i32) -> i32;
    fn gen_u8(&mut self) -> u8;
    fn gen_bool(&mut self, p: f64) -> bool;
}

impl<R: Rng> RngCore for R {
    fn gen_range_usize(&mut self, low: usize, high: usize) -> usize {
        self.gen_range(low..high)
    }

    fn gen_range_i32(&mut self, low: i32, high: i32) -> i32 {
        self.gen_range(low..high)
    }

    fn gen_u8(&mut self) -> u8 {
        self.gen()
    }

    fn gen_bool(&mut self, p: f64) -> bool {
        Rng::gen_bool(self, p)
    }
}

/// Flip a single bit at a random position.
pub struct BitFlip1;

impl MutationStrategy for BitFlip1 {
    fn mutate(&self, input: &mut Vec<u8>, rng: &mut dyn RngCore) {
        if input.is_empty() {
            return;
        }
        let byte_idx = rng.gen_range_usize(0, input.len());
        let bit_idx = rng.gen_range_usize(0, 8);
        input[byte_idx] ^= 1 << bit_idx;
    }

    fn name(&self) -> &'static str {
        "bit_flip_1"
    }
}

/// Flip 2 adjacent bits at a random position.
pub struct BitFlip2;

impl MutationStrategy for BitFlip2 {
    fn mutate(&self, input: &mut Vec<u8>, rng: &mut dyn RngCore) {
        if input.is_empty() {
            return;
        }
        let byte_idx = rng.gen_range_usize(0, input.len());
        let bit_idx = rng.gen_range_usize(0, 7);
        input[byte_idx] ^= 3 << bit_idx;
    }

    fn name(&self) -> &'static str {
        "bit_flip_2"
    }
}

/// Flip 4 adjacent bits at a random position.
pub struct BitFlip4;

impl MutationStrategy for BitFlip4 {
    fn mutate(&self, input: &mut Vec<u8>, rng: &mut dyn RngCore) {
        if input.is_empty() {
            return;
        }
        let byte_idx = rng.gen_range_usize(0, input.len());
        let bit_idx = rng.gen_range_usize(0, 5);
        input[byte_idx] ^= 0xF << bit_idx;
    }

    fn name(&self) -> &'static str {
        "bit_flip_4"
    }
}

/// Flip a single byte at a random position.
pub struct ByteFlip1;

impl MutationStrategy for ByteFlip1 {
    fn mutate(&self, input: &mut Vec<u8>, rng: &mut dyn RngCore) {
        if input.is_empty() {
            return;
        }
        let idx = rng.gen_range_usize(0, input.len());
        input[idx] ^= 0xFF;
    }

    fn name(&self) -> &'static str {
        "byte_flip_1"
    }
}

/// Flip 2 adjacent bytes at a random position.
pub struct ByteFlip2;

impl MutationStrategy for ByteFlip2 {
    fn mutate(&self, input: &mut Vec<u8>, rng: &mut dyn RngCore) {
        if input.len() < 2 {
            return;
        }
        let idx = rng.gen_range_usize(0, input.len() - 1);
        input[idx] ^= 0xFF;
        input[idx + 1] ^= 0xFF;
    }

    fn name(&self) -> &'static str {
        "byte_flip_2"
    }
}

/// Flip 4 adjacent bytes at a random position.
pub struct ByteFlip4;

impl MutationStrategy for ByteFlip4 {
    fn mutate(&self, input: &mut Vec<u8>, rng: &mut dyn RngCore) {
        if input.len() < 4 {
            return;
        }
        let idx = rng.gen_range_usize(0, input.len() - 3);
        for i in 0..4 {
            input[idx + i] ^= 0xFF;
        }
    }

    fn name(&self) -> &'static str {
        "byte_flip_4"
    }
}

/// Maximum value for arithmetic mutations (AFL uses 35).
const ARITH_MAX: i32 = 35;

/// Add or subtract small values to a byte.
pub struct Arith8;

impl MutationStrategy for Arith8 {
    fn mutate(&self, input: &mut Vec<u8>, rng: &mut dyn RngCore) {
        if input.is_empty() {
            return;
        }
        let idx = rng.gen_range_usize(0, input.len());
        let delta = rng.gen_range_i32(1, ARITH_MAX + 1) as i16;
        let val = input[idx] as i16;
        input[idx] = if rng.gen_bool(0.5) {
            val.wrapping_add(delta) as u8
        } else {
            val.wrapping_sub(delta) as u8
        };
    }

    fn name(&self) -> &'static str {
        "arith_8"
    }
}

/// Add or subtract small values to a 16-bit value.
pub struct Arith16;

impl MutationStrategy for Arith16 {
    fn mutate(&self, input: &mut Vec<u8>, rng: &mut dyn RngCore) {
        if input.len() < 2 {
            return;
        }
        let idx = rng.gen_range_usize(0, input.len() - 1);
        let delta = rng.gen_range_i32(1, ARITH_MAX + 1);

        if rng.gen_bool(0.5) {
            let val = u16::from_le_bytes([input[idx], input[idx + 1]]) as i32;
            let new_val = if rng.gen_bool(0.5) {
                val.wrapping_add(delta) as u16
            } else {
                val.wrapping_sub(delta) as u16
            };
            let bytes = new_val.to_le_bytes();
            input[idx] = bytes[0];
            input[idx + 1] = bytes[1];
        } else {
            let val = u16::from_be_bytes([input[idx], input[idx + 1]]) as i32;
            let new_val = if rng.gen_bool(0.5) {
                val.wrapping_add(delta) as u16
            } else {
                val.wrapping_sub(delta) as u16
            };
            let bytes = new_val.to_be_bytes();
            input[idx] = bytes[0];
            input[idx + 1] = bytes[1];
        }
    }

    fn name(&self) -> &'static str {
        "arith_16"
    }
}

/// Add or subtract small values to a 32-bit value.
pub struct Arith32;

impl MutationStrategy for Arith32 {
    fn mutate(&self, input: &mut Vec<u8>, rng: &mut dyn RngCore) {
        if input.len() < 4 {
            return;
        }
        let idx = rng.gen_range_usize(0, input.len() - 3);
        let delta = rng.gen_range_i32(1, ARITH_MAX + 1) as i64;

        if rng.gen_bool(0.5) {
            let val =
                u32::from_le_bytes([input[idx], input[idx + 1], input[idx + 2], input[idx + 3]])
                    as i64;
            let new_val = if rng.gen_bool(0.5) {
                val.wrapping_add(delta) as u32
            } else {
                val.wrapping_sub(delta) as u32
            };
            let bytes = new_val.to_le_bytes();
            for i in 0..4 {
                input[idx + i] = bytes[i];
            }
        } else {
            let val =
                u32::from_be_bytes([input[idx], input[idx + 1], input[idx + 2], input[idx + 3]])
                    as i64;
            let new_val = if rng.gen_bool(0.5) {
                val.wrapping_add(delta) as u32
            } else {
                val.wrapping_sub(delta) as u32
            };
            let bytes = new_val.to_be_bytes();
            for i in 0..4 {
                input[idx + i] = bytes[i];
            }
        }
    }

    fn name(&self) -> &'static str {
        "arith_32"
    }
}

/// Set a random byte to a random value.
pub struct RandomByte;

impl MutationStrategy for RandomByte {
    fn mutate(&self, input: &mut Vec<u8>, rng: &mut dyn RngCore) {
        if input.is_empty() {
            return;
        }
        let idx = rng.gen_range_usize(0, input.len());
        input[idx] = rng.gen_u8();
    }

    fn name(&self) -> &'static str {
        "random_byte"
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
    fn test_bit_flip_1() {
        let mut input = vec![0b00000000];
        let mut rng = seeded_rng();
        BitFlip1.mutate(&mut input, &mut rng);
        assert_eq!(input[0].count_ones(), 1);
    }

    #[test]
    fn test_bit_flip_1_empty() {
        let mut input = vec![];
        let mut rng = seeded_rng();
        BitFlip1.mutate(&mut input, &mut rng);
        assert!(input.is_empty());
    }

    #[test]
    fn test_bit_flip_2() {
        let mut input = vec![0b00000000];
        let mut rng = seeded_rng();
        BitFlip2.mutate(&mut input, &mut rng);
        assert_eq!(input[0].count_ones(), 2);
    }

    #[test]
    fn test_bit_flip_4() {
        let mut input = vec![0b00000000];
        let mut rng = seeded_rng();
        BitFlip4.mutate(&mut input, &mut rng);
        assert_eq!(input[0].count_ones(), 4);
    }

    #[test]
    fn test_byte_flip_1() {
        let mut input = vec![0x00, 0x00, 0x00];
        let original = input.clone();
        let mut rng = seeded_rng();
        ByteFlip1.mutate(&mut input, &mut rng);
        let changed = input.iter().filter(|&&b| b == 0xFF).count();
        assert_eq!(changed, 1);
        let unchanged = input
            .iter()
            .zip(original.iter())
            .filter(|(&a, &b)| a == b)
            .count();
        assert_eq!(unchanged, 2);
    }

    #[test]
    fn test_byte_flip_2() {
        let mut input = vec![0x00, 0x00, 0x00, 0x00];
        let mut rng = seeded_rng();
        ByteFlip2.mutate(&mut input, &mut rng);
        let changed = input.iter().filter(|&&b| b == 0xFF).count();
        assert_eq!(changed, 2);
    }

    #[test]
    fn test_byte_flip_4() {
        let mut input = vec![0x00, 0x00, 0x00, 0x00, 0x00];
        let mut rng = seeded_rng();
        ByteFlip4.mutate(&mut input, &mut rng);
        let changed = input.iter().filter(|&&b| b == 0xFF).count();
        assert_eq!(changed, 4);
    }

    #[test]
    fn test_byte_flip_4_short_input() {
        let mut input = vec![0x00, 0x00];
        let original = input.clone();
        let mut rng = seeded_rng();
        ByteFlip4.mutate(&mut input, &mut rng);
        assert_eq!(input, original);
    }

    #[test]
    fn test_arith_8() {
        let mut input = vec![100];
        let original = input[0];
        let mut rng = seeded_rng();
        Arith8.mutate(&mut input, &mut rng);
        let diff = (input[0] as i16 - original as i16).abs();
        assert!(diff <= ARITH_MAX as i16);
        assert!(diff >= 1);
    }

    #[test]
    fn test_arith_16() {
        let mut input = vec![0x00, 0x64];
        let mut rng = seeded_rng();
        Arith16.mutate(&mut input, &mut rng);
        assert!(input != vec![0x00, 0x64] || input != vec![0x64, 0x00]);
    }

    #[test]
    fn test_arith_32() {
        let mut input = vec![0x00, 0x00, 0x00, 0x64];
        let original = input.clone();
        let mut rng = seeded_rng();
        Arith32.mutate(&mut input, &mut rng);
        assert_ne!(input, original);
    }

    #[test]
    fn test_random_byte() {
        let mut input = vec![0x00, 0x00, 0x00];
        let mut rng = seeded_rng();
        RandomByte.mutate(&mut input, &mut rng);
        let zeros = input.iter().filter(|&&b| b == 0).count();
        assert!(zeros < 3 || input.iter().any(|&b| b != 0));
    }

    #[test]
    fn test_strategy_names() {
        assert_eq!(BitFlip1.name(), "bit_flip_1");
        assert_eq!(BitFlip2.name(), "bit_flip_2");
        assert_eq!(BitFlip4.name(), "bit_flip_4");
        assert_eq!(ByteFlip1.name(), "byte_flip_1");
        assert_eq!(ByteFlip2.name(), "byte_flip_2");
        assert_eq!(ByteFlip4.name(), "byte_flip_4");
        assert_eq!(Arith8.name(), "arith_8");
        assert_eq!(Arith16.name(), "arith_16");
        assert_eq!(Arith32.name(), "arith_32");
        assert_eq!(RandomByte.name(), "random_byte");
    }
}
