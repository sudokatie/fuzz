use super::strategies::{MutationStrategy, RngCore};

/// Delete a random chunk of bytes.
pub struct BlockDelete;

impl MutationStrategy for BlockDelete {
    fn mutate(&self, input: &mut Vec<u8>, rng: &mut dyn RngCore) {
        if input.len() < 2 {
            return;
        }
        let max_del = std::cmp::min(input.len() - 1, 32);
        let del_len = rng.gen_range_usize(1, max_del + 1);
        let start = rng.gen_range_usize(0, input.len() - del_len + 1);
        input.drain(start..start + del_len);
    }

    fn name(&self) -> &'static str {
        "block_delete"
    }
}

/// Insert random bytes at a random position.
pub struct BlockInsert;

impl MutationStrategy for BlockInsert {
    fn mutate(&self, input: &mut Vec<u8>, rng: &mut dyn RngCore) {
        let max_ins = std::cmp::min(32, 1024 - input.len());
        if max_ins == 0 {
            return;
        }
        let ins_len = rng.gen_range_usize(1, max_ins + 1);
        let pos = rng.gen_range_usize(0, input.len() + 1);

        let new_bytes: Vec<u8> = (0..ins_len).map(|_| rng.gen_u8()).collect();
        input.splice(pos..pos, new_bytes);
    }

    fn name(&self) -> &'static str {
        "block_insert"
    }
}

/// Overwrite a chunk with random bytes.
pub struct BlockOverwrite;

impl MutationStrategy for BlockOverwrite {
    fn mutate(&self, input: &mut Vec<u8>, rng: &mut dyn RngCore) {
        if input.is_empty() {
            return;
        }
        let max_len = std::cmp::min(input.len(), 32);
        let len = rng.gen_range_usize(1, max_len + 1);
        let start = rng.gen_range_usize(0, input.len() - len + 1);

        for i in start..start + len {
            input[i] = rng.gen_u8();
        }
    }

    fn name(&self) -> &'static str {
        "block_overwrite"
    }
}

/// Clone a chunk to another position.
pub struct BlockClone;

impl MutationStrategy for BlockClone {
    fn mutate(&self, input: &mut Vec<u8>, rng: &mut dyn RngCore) {
        if input.len() < 2 {
            return;
        }
        let max_len = std::cmp::min(input.len(), 32);
        let len = rng.gen_range_usize(1, max_len + 1);
        let src_start = rng.gen_range_usize(0, input.len() - len + 1);

        let chunk: Vec<u8> = input[src_start..src_start + len].to_vec();
        let dst = rng.gen_range_usize(0, input.len() + 1);
        input.splice(dst..dst, chunk);
    }

    fn name(&self) -> &'static str {
        "block_clone"
    }
}

/// Swap two chunks.
pub struct BlockSwap;

impl MutationStrategy for BlockSwap {
    fn mutate(&self, input: &mut Vec<u8>, rng: &mut dyn RngCore) {
        if input.len() < 4 {
            return;
        }
        let max_len = std::cmp::min(input.len() / 2, 16);
        if max_len == 0 {
            return;
        }
        let len = rng.gen_range_usize(1, max_len + 1);

        let pos1 = rng.gen_range_usize(0, input.len() - len * 2 + 1);
        let pos2 = rng.gen_range_usize(pos1 + len, input.len() - len + 1);

        for i in 0..len {
            input.swap(pos1 + i, pos2 + i);
        }
    }

    fn name(&self) -> &'static str {
        "block_swap"
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
    fn test_block_delete() {
        let mut input = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let original_len = input.len();
        let mut rng = seeded_rng();
        BlockDelete.mutate(&mut input, &mut rng);
        assert!(input.len() < original_len);
        assert!(!input.is_empty());
    }

    #[test]
    fn test_block_delete_short() {
        let mut input = vec![1];
        let original = input.clone();
        let mut rng = seeded_rng();
        BlockDelete.mutate(&mut input, &mut rng);
        assert_eq!(input, original);
    }

    #[test]
    fn test_block_insert() {
        let mut input = vec![1, 2, 3, 4];
        let original_len = input.len();
        let mut rng = seeded_rng();
        BlockInsert.mutate(&mut input, &mut rng);
        assert!(input.len() > original_len);
    }

    #[test]
    fn test_block_overwrite() {
        let mut input = vec![0, 0, 0, 0, 0];
        let mut rng = seeded_rng();
        BlockOverwrite.mutate(&mut input, &mut rng);
        let zeros = input.iter().filter(|&&b| b == 0).count();
        assert!(zeros < 5);
    }

    #[test]
    fn test_block_clone() {
        let mut input = vec![1, 2, 3, 4];
        let original_len = input.len();
        let mut rng = seeded_rng();
        BlockClone.mutate(&mut input, &mut rng);
        assert!(input.len() > original_len);
    }

    #[test]
    fn test_block_swap() {
        let mut input = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let original = input.clone();
        let mut rng = seeded_rng();
        BlockSwap.mutate(&mut input, &mut rng);
        assert_eq!(input.len(), original.len());
        assert_ne!(input, original);
    }

    #[test]
    fn test_block_swap_short() {
        let mut input = vec![1, 2];
        let original = input.clone();
        let mut rng = seeded_rng();
        BlockSwap.mutate(&mut input, &mut rng);
        assert_eq!(input, original);
    }
}
