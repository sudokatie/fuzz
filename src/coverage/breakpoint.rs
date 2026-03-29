use crate::coverage::Bitmap;
use crate::error::{Error, Result};
use goblin::Object;
use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::Path;

/// Coverage collector using software breakpoints.
///
/// This is a fallback for binaries without SanitizerCoverage instrumentation.
/// It parses the binary to find basic block addresses and tracks which
/// blocks are hit during execution.
///
/// Note: This is significantly slower than sancov due to breakpoint overhead.
/// Use primarily for analysis or when sancov is unavailable.
pub struct BreakpointCollector {
    /// Basic block addresses found in binary.
    blocks: Vec<u64>,
    /// Map from block address to bitmap index.
    addr_to_idx: HashMap<u64, usize>,
    /// Set of hit block addresses.
    hit_blocks: HashSet<u64>,
    /// Binary base address (for ASLR adjustment).
    base_addr: u64,
}

impl BreakpointCollector {
    /// Create a new breakpoint collector by analyzing a binary.
    pub fn from_binary(path: &Path) -> Result<Self> {
        let data =
            fs::read(path).map_err(|e| Error::Coverage(format!("failed to read binary: {}", e)))?;

        let blocks = parse_basic_blocks(&data)?;

        let mut addr_to_idx = HashMap::new();
        for (idx, &addr) in blocks.iter().enumerate() {
            addr_to_idx.insert(addr, idx);
        }

        Ok(Self {
            blocks,
            addr_to_idx,
            hit_blocks: HashSet::new(),
            base_addr: 0,
        })
    }

    /// Set the base address for ASLR adjustment.
    pub fn set_base_addr(&mut self, addr: u64) {
        self.base_addr = addr;
    }

    /// Record a breakpoint hit at the given address.
    pub fn record_hit(&mut self, addr: u64) {
        // Adjust for base address
        let adjusted = addr.wrapping_sub(self.base_addr);
        if self.addr_to_idx.contains_key(&adjusted) {
            self.hit_blocks.insert(adjusted);
        }
    }

    /// Check if we've seen new coverage.
    pub fn has_new_coverage(&self, previous: &HashSet<u64>) -> bool {
        self.hit_blocks.difference(previous).next().is_some()
    }

    /// Get the set of hit blocks.
    pub fn hit_blocks(&self) -> &HashSet<u64> {
        &self.hit_blocks
    }

    /// Reset hit tracking for next execution.
    pub fn reset(&mut self) {
        self.hit_blocks.clear();
    }

    /// Collect coverage into a bitmap.
    pub fn collect(&self) -> Bitmap {
        let mut bitmap = Bitmap::new();

        for &addr in &self.hit_blocks {
            if let Some(&idx) = self.addr_to_idx.get(&addr) {
                // Use modulo to fit in bitmap
                let bitmap_idx = idx % 65536;
                bitmap.hit(bitmap_idx);
            }
        }

        bitmap
    }

    /// Number of basic blocks in the binary.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    /// Number of blocks hit so far.
    pub fn hit_count(&self) -> usize {
        self.hit_blocks.len()
    }

    /// Coverage percentage.
    pub fn coverage_percent(&self) -> f64 {
        if self.blocks.is_empty() {
            return 0.0;
        }
        self.hit_blocks.len() as f64 / self.blocks.len() as f64
    }

    /// Get all block addresses (for setting breakpoints).
    pub fn block_addresses(&self) -> &[u64] {
        &self.blocks
    }
}

/// Parse basic block addresses from a binary.
fn parse_basic_blocks(data: &[u8]) -> Result<Vec<u64>> {
    match Object::parse(data) {
        Ok(Object::Elf(elf)) => parse_elf_blocks(&elf),
        Ok(Object::Mach(mach)) => parse_macho_blocks(&mach),
        Ok(_) => Err(Error::Coverage("unsupported binary format".into())),
        Err(e) => Err(Error::Coverage(format!("failed to parse binary: {}", e))),
    }
}

/// Parse basic block addresses from ELF binary.
fn parse_elf_blocks(elf: &goblin::elf::Elf) -> Result<Vec<u64>> {
    let mut blocks = Vec::new();

    // Get text section
    for section in &elf.section_headers {
        if section.sh_flags & goblin::elf::section_header::SHF_EXECINSTR as u64 != 0 {
            // This is an executable section
            // For simplicity, treat function symbols as block starts
            // A real implementation would disassemble to find all basic blocks
        }
    }

    // Use function symbols as basic block indicators
    for sym in &elf.syms {
        if sym.st_type() == goblin::elf::sym::STT_FUNC && sym.st_value != 0 {
            blocks.push(sym.st_value);
        }
    }

    // Also check dynamic symbols
    for sym in &elf.dynsyms {
        if sym.st_type() == goblin::elf::sym::STT_FUNC && sym.st_value != 0 {
            blocks.push(sym.st_value);
        }
    }

    // Remove duplicates and sort
    blocks.sort();
    blocks.dedup();

    Ok(blocks)
}

/// Parse basic block addresses from Mach-O binary.
fn parse_macho_blocks(mach: &goblin::mach::Mach) -> Result<Vec<u64>> {
    let mut blocks = Vec::new();

    match mach {
        goblin::mach::Mach::Binary(macho) => {
            // Get function starts from symbols
            if let Some(symbols) = macho.symbols.as_ref() {
                for symbol in symbols.iter() {
                    if let Ok((_name, nlist)) = symbol {
                        // Check if it's a function (N_SECT type)
                        if nlist.n_type & goblin::mach::symbols::N_TYPE
                            == goblin::mach::symbols::N_SECT
                        {
                            if nlist.n_value != 0 {
                                blocks.push(nlist.n_value);
                            }
                        }
                    }
                }
            }
        }
        goblin::mach::Mach::Fat(_fat) => {
            // Fat/universal binaries require extracting the right architecture.
            // For simplicity, return empty - caller should use lipo to extract.
            // A full implementation would select the native architecture slice.
            return Ok(Vec::new());
        }
    }

    // Remove duplicates and sort
    blocks.sort();
    blocks.dedup();

    Ok(blocks)
}

/// Information about a basic block.
#[derive(Debug, Clone)]
pub struct BasicBlock {
    /// Start address.
    pub addr: u64,
    /// Size in bytes (if known).
    pub size: Option<u64>,
    /// Function name (if known).
    pub function: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;

    fn test_binary_path() -> Option<PathBuf> {
        // Use our compiled test target (not a fat binary)
        let target = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("test_targets")
            .join("null_deref");

        if target.exists() {
            return Some(target);
        }

        // Fallback - won't work on macOS with fat binaries
        None
    }

    #[test]
    fn test_from_binary() {
        let path = match test_binary_path() {
            Some(p) => p,
            None => {
                eprintln!("Skipping: test target not compiled. Run `cd test_targets && make`");
                return;
            }
        };

        let collector = BreakpointCollector::from_binary(&path);
        assert!(
            collector.is_ok(),
            "Failed to parse binary: {:?}",
            collector.err()
        );

        let collector = collector.unwrap();
        // Should find at least some blocks (main at minimum)
        assert!(collector.block_count() > 0, "No blocks found in binary");
    }

    #[test]
    fn test_record_hit() {
        let path = match test_binary_path() {
            Some(p) => p,
            None => return,
        };

        let mut collector = BreakpointCollector::from_binary(&path).unwrap();

        // Get a valid block address
        if let Some(&addr) = collector.blocks.first() {
            collector.record_hit(addr);
            assert_eq!(collector.hit_count(), 1);
            assert!(collector.hit_blocks.contains(&addr));
        }
    }

    #[test]
    fn test_reset() {
        let path = match test_binary_path() {
            Some(p) => p,
            None => return,
        };

        let mut collector = BreakpointCollector::from_binary(&path).unwrap();

        if let Some(&addr) = collector.blocks.first() {
            collector.record_hit(addr);
            assert_eq!(collector.hit_count(), 1);

            collector.reset();
            assert_eq!(collector.hit_count(), 0);
        }
    }

    #[test]
    fn test_has_new_coverage() {
        let path = match test_binary_path() {
            Some(p) => p,
            None => return,
        };

        let mut collector = BreakpointCollector::from_binary(&path).unwrap();
        let previous = HashSet::new();

        // No hits yet - no new coverage
        assert!(!collector.has_new_coverage(&previous));

        // Hit a block
        if let Some(&addr) = collector.blocks.first() {
            collector.record_hit(addr);
            assert!(collector.has_new_coverage(&previous));

            // Same coverage as previous - no new coverage
            let current = collector.hit_blocks.clone();
            assert!(!collector.has_new_coverage(&current));
        }
    }

    #[test]
    fn test_collect_bitmap() {
        let path = match test_binary_path() {
            Some(p) => p,
            None => return,
        };

        let mut collector = BreakpointCollector::from_binary(&path).unwrap();

        // Hit some blocks - clone addresses first to avoid borrow issues
        let addrs: Vec<u64> = collector.blocks.iter().take(5).copied().collect();
        for addr in addrs {
            collector.record_hit(addr);
        }

        let bitmap = collector.collect();
        assert!(bitmap.count_bits() > 0);
    }

    #[test]
    fn test_coverage_percent() {
        let path = match test_binary_path() {
            Some(p) => p,
            None => return,
        };

        let mut collector = BreakpointCollector::from_binary(&path).unwrap();

        assert_eq!(collector.coverage_percent(), 0.0);

        // Hit half the blocks - clone addresses first
        let half = collector.blocks.len() / 2;
        let addrs: Vec<u64> = collector.blocks.iter().take(half).copied().collect();
        for addr in addrs {
            collector.record_hit(addr);
        }

        let percent = collector.coverage_percent();
        assert!(percent > 0.0 && percent <= 1.0);
    }

    #[test]
    fn test_base_addr_adjustment() {
        let path = match test_binary_path() {
            Some(p) => p,
            None => return,
        };

        let mut collector = BreakpointCollector::from_binary(&path).unwrap();

        if let Some(&addr) = collector.blocks.first() {
            // Set a base address offset
            let offset = 0x10000u64;
            collector.set_base_addr(offset);

            // Hit at adjusted address
            collector.record_hit(addr.wrapping_add(offset));

            assert_eq!(collector.hit_count(), 1);
        }
    }

    #[test]
    fn test_invalid_binary() {
        let result = BreakpointCollector::from_binary(Path::new("/nonexistent/binary"));
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_hits_no_new_coverage() {
        let path = match test_binary_path() {
            Some(p) => p,
            None => return,
        };

        let collector = BreakpointCollector::from_binary(&path).unwrap();
        let previous = HashSet::new();

        // Empty collector should have no new coverage
        assert!(!collector.has_new_coverage(&previous));
    }
}
