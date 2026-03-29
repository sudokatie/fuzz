pub mod strategies;

pub use strategies::{
    Arith16, Arith32, Arith8, BitFlip1, BitFlip2, BitFlip4, ByteFlip1, ByteFlip2, ByteFlip4,
    MutationStrategy, RandomByte,
};
