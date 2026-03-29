pub mod entry;
pub mod storage;

pub use entry::{CorpusEntry, EntryMetadata};
pub use storage::{load_seeds, CorpusStorage};
