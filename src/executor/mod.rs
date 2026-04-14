pub mod fork;
pub mod persistent;

pub use fork::{
    is_crash_signal, signal_name, ExecutionResult, ExitStatus, ForkExecutor, InputMode,
};
pub use persistent::{PersistentExecutor, PersistentResult};
