pub mod bitmap;
pub mod breakpoint;
pub mod report;
pub mod sancov;

pub use bitmap::{bucket_hit_count, edge_hash, Bitmap};
pub use breakpoint::BreakpointCollector;
pub use report::{CoverageReport, CoverageTracker};
pub use sancov::SancovCollector;

use crate::error::Result;
use std::path::Path;

/// Trait for coverage collection backends.
pub trait CoverageCollector: Send {
    /// Reset coverage state before next execution.
    fn reset(&mut self);
    
    /// Collect coverage into a bitmap.
    fn collect(&self) -> Bitmap;
    
    /// Get environment variable to set for target (if any).
    /// Returns None if this collector doesn't use env vars.
    fn env_var(&self) -> Option<(&'static str, &str)>;
    
    /// Record a hit at the given address (for breakpoint mode).
    /// No-op for collectors that don't use explicit hit recording.
    fn record_hit(&mut self, _addr: u64) {}
}

impl CoverageCollector for SancovCollector {
    fn reset(&mut self) {
        self.reset();
    }
    
    fn collect(&self) -> Bitmap {
        self.collect()
    }
    
    fn env_var(&self) -> Option<(&'static str, &str)> {
        let (key, val) = SancovCollector::env_var(self);
        Some((key, val))
    }
}

impl CoverageCollector for BreakpointCollector {
    fn reset(&mut self) {
        self.reset();
    }
    
    fn collect(&self) -> Bitmap {
        self.collect()
    }
    
    fn env_var(&self) -> Option<(&'static str, &str)> {
        None // Breakpoint collector doesn't use env vars
    }
    
    fn record_hit(&mut self, addr: u64) {
        self.record_hit(addr);
    }
}

/// Create the appropriate coverage collector based on mode.
pub fn create_collector(
    mode: crate::config::CoverageMode,
    target_path: &Path,
) -> Result<Box<dyn CoverageCollector>> {
    match mode {
        crate::config::CoverageMode::Sancov => {
            Ok(Box::new(SancovCollector::new()?))
        }
        crate::config::CoverageMode::Breakpoint => {
            Ok(Box::new(BreakpointCollector::from_binary(target_path)?))
        }
    }
}
