use super::block::{BlockClone, BlockDelete, BlockInsert, BlockOverwrite, BlockSwap};
use super::interesting::{Interesting16, Interesting32, Interesting8};
use super::strategies::{
    Arith16, Arith32, Arith8, BitFlip1, BitFlip2, BitFlip4, ByteFlip1, ByteFlip2, ByteFlip4,
    MutationStrategy, RandomByte, RngCore,
};

/// Havoc mutator applies multiple random mutations.
pub struct HavocMutator {
    strategies: Vec<Box<dyn MutationStrategy>>,
    min_mutations: usize,
    max_mutations: usize,
}

impl Default for HavocMutator {
    fn default() -> Self {
        Self::new()
    }
}

impl HavocMutator {
    /// Create a new havoc mutator with default strategies.
    pub fn new() -> Self {
        let strategies: Vec<Box<dyn MutationStrategy>> = vec![
            Box::new(BitFlip1),
            Box::new(BitFlip2),
            Box::new(BitFlip4),
            Box::new(ByteFlip1),
            Box::new(ByteFlip2),
            Box::new(ByteFlip4),
            Box::new(Arith8),
            Box::new(Arith16),
            Box::new(Arith32),
            Box::new(Interesting8),
            Box::new(Interesting16),
            Box::new(Interesting32),
            Box::new(BlockDelete),
            Box::new(BlockInsert),
            Box::new(BlockOverwrite),
            Box::new(BlockClone),
            Box::new(BlockSwap),
            Box::new(RandomByte),
        ];

        Self {
            strategies,
            min_mutations: 2,
            max_mutations: 16,
        }
    }

    /// Set the range of mutations to apply.
    pub fn with_range(mut self, min: usize, max: usize) -> Self {
        self.min_mutations = min;
        self.max_mutations = max;
        self
    }

    /// Apply multiple random mutations to input.
    pub fn mutate(&self, input: &mut Vec<u8>, rng: &mut dyn RngCore) {
        if self.strategies.is_empty() {
            return;
        }

        let num_mutations = rng.gen_range_usize(self.min_mutations, self.max_mutations + 1);

        for _ in 0..num_mutations {
            let strategy_idx = rng.gen_range_usize(0, self.strategies.len());
            self.strategies[strategy_idx].mutate(input, rng);
        }
    }

    /// Get the name of a random strategy for logging.
    pub fn random_strategy_name(&self, rng: &mut dyn RngCore) -> &'static str {
        if self.strategies.is_empty() {
            "none"
        } else {
            let idx = rng.gen_range_usize(0, self.strategies.len());
            self.strategies[idx].name()
        }
    }
}

/// Splice two inputs together.
pub fn splice(input1: &[u8], input2: &[u8], rng: &mut dyn RngCore) -> Vec<u8> {
    if input1.is_empty() {
        return input2.to_vec();
    }
    if input2.is_empty() {
        return input1.to_vec();
    }

    let split1 = rng.gen_range_usize(0, input1.len() + 1);
    let split2 = rng.gen_range_usize(0, input2.len() + 1);

    let mut result = input1[..split1].to_vec();
    result.extend_from_slice(&input2[split2..]);
    result
}

/// Main mutator that coordinates different mutation stages.
pub struct Mutator {
    havoc: HavocMutator,
    stage: MutationStage,
}

/// Mutation stages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MutationStage {
    Deterministic,
    Havoc,
    Splice,
}

impl Default for Mutator {
    fn default() -> Self {
        Self::new()
    }
}

impl Mutator {
    /// Create a new mutator.
    pub fn new() -> Self {
        Self {
            havoc: HavocMutator::new(),
            stage: MutationStage::Havoc,
        }
    }

    /// Get current mutation stage.
    pub fn stage(&self) -> MutationStage {
        self.stage
    }

    /// Set mutation stage.
    pub fn set_stage(&mut self, stage: MutationStage) {
        self.stage = stage;
    }

    /// Mutate an input using the current stage.
    pub fn mutate(&self, input: &[u8], rng: &mut dyn RngCore) -> Vec<u8> {
        let mut result = input.to_vec();
        self.havoc.mutate(&mut result, rng);
        result
    }

    /// Mutate by splicing two inputs.
    pub fn splice(&self, input1: &[u8], input2: &[u8], rng: &mut dyn RngCore) -> Vec<u8> {
        let mut result = splice(input1, input2, rng);
        if rng.gen_bool(0.5) {
            self.havoc.mutate(&mut result, rng);
        }
        result
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
    fn test_havoc_mutator_new() {
        let havoc = HavocMutator::new();
        assert!(!havoc.strategies.is_empty());
    }

    #[test]
    fn test_havoc_mutator_mutate() {
        let havoc = HavocMutator::new();
        let mut input = vec![0; 100];
        let original = input.clone();
        let mut rng = seeded_rng();
        havoc.mutate(&mut input, &mut rng);
        assert_ne!(input, original);
    }

    #[test]
    fn test_havoc_multiple_mutations() {
        let havoc = HavocMutator::new().with_range(5, 10);
        let mut input = vec![0; 100];
        let original = input.clone();
        let mut rng = seeded_rng();
        havoc.mutate(&mut input, &mut rng);
        let diff_count = input
            .iter()
            .zip(original.iter())
            .filter(|(&a, &b)| a != b)
            .count();
        assert!(diff_count > 0);
    }

    #[test]
    fn test_splice() {
        let input1 = vec![1, 2, 3, 4, 5];
        let input2 = vec![6, 7, 8, 9, 10];
        let mut rng = seeded_rng();
        let result = splice(&input1, &input2, &mut rng);
        assert!(!result.is_empty());
    }

    #[test]
    fn test_splice_empty() {
        let input1: Vec<u8> = vec![];
        let input2 = vec![1, 2, 3];
        let mut rng = seeded_rng();
        let result = splice(&input1, &input2, &mut rng);
        assert!(!result.is_empty());
        let result = splice(&input2, &input1, &mut rng);
        assert!(!result.is_empty());
    }

    #[test]
    fn test_mutator_new() {
        let mutator = Mutator::new();
        assert_eq!(mutator.stage(), MutationStage::Havoc);
    }

    #[test]
    fn test_mutator_mutate() {
        let mutator = Mutator::new();
        let input = vec![0; 50];
        let mut rng = seeded_rng();
        let result = mutator.mutate(&input, &mut rng);
        assert_ne!(result, input);
    }

    #[test]
    fn test_mutator_splice() {
        let mutator = Mutator::new();
        let input1 = vec![1, 2, 3, 4, 5];
        let input2 = vec![6, 7, 8, 9, 10];
        let mut rng = seeded_rng();
        let result = mutator.splice(&input1, &input2, &mut rng);
        assert!(!result.is_empty());
    }

    #[test]
    fn test_mutator_set_stage() {
        let mut mutator = Mutator::new();
        mutator.set_stage(MutationStage::Deterministic);
        assert_eq!(mutator.stage(), MutationStage::Deterministic);
    }
}
