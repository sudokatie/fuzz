pub mod config;
pub mod corpus;
pub mod coverage;
pub mod crash;
pub mod error;
pub mod executor;
pub mod fuzzer;
pub mod minimizer;
pub mod mutation;
pub mod stats;

pub use error::{Error, Result};
pub use fuzzer::{FuzzResult, Fuzzer};
