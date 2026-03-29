use crate::corpus::entry::EntryMetadata;
use rand::Rng;
use std::collections::HashMap;
use std::time::SystemTime;

/// Scheduler for selecting corpus entries based on energy.
///
/// Energy is calculated based on:
/// - Execution speed (faster entries get more energy)
/// - Unique coverage (entries with more new coverage get more energy)
/// - Recency (newer entries get more energy)
/// - Depth (shallower mutation chains get more energy)
/// - Fuzz count (entries fuzzed less get more energy)
#[derive(Debug)]
pub struct Scheduler {
    /// Entry metadata indexed by id.
    entries: HashMap<u64, SchedulerEntry>,
    /// Cached total energy for weighted selection.
    total_energy: f64,
    /// Whether energy needs recalculation.
    dirty: bool,
}

#[derive(Debug, Clone)]
struct SchedulerEntry {
    metadata: EntryMetadata,
    energy: f64,
}

/// Configuration for energy calculation.
#[derive(Debug, Clone)]
pub struct EnergyConfig {
    /// Weight for execution speed factor (0-1).
    pub speed_weight: f64,
    /// Weight for coverage count factor (0-1).
    pub coverage_weight: f64,
    /// Weight for recency factor (0-1).
    pub recency_weight: f64,
    /// Weight for depth factor (0-1).
    pub depth_weight: f64,
    /// Base energy for all entries.
    pub base_energy: f64,
    /// Decay factor for recency (seconds until half energy).
    pub recency_half_life_secs: f64,
}

impl Default for EnergyConfig {
    fn default() -> Self {
        Self {
            speed_weight: 0.3,
            coverage_weight: 0.35,
            recency_weight: 0.2,
            depth_weight: 0.15,
            base_energy: 1.0,
            recency_half_life_secs: 3600.0, // 1 hour
        }
    }
}

impl Scheduler {
    /// Create a new scheduler.
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            total_energy: 0.0,
            dirty: false,
        }
    }

    /// Add an entry to the scheduler.
    pub fn add(&mut self, metadata: EntryMetadata) {
        let energy = calculate_energy(&metadata, &EnergyConfig::default());
        self.entries
            .insert(metadata.id, SchedulerEntry { metadata, energy });
        self.dirty = true;
    }

    /// Add an entry with custom energy config.
    pub fn add_with_config(&mut self, metadata: EntryMetadata, config: &EnergyConfig) {
        let energy = calculate_energy(&metadata, config);
        self.entries
            .insert(metadata.id, SchedulerEntry { metadata, energy });
        self.dirty = true;
    }

    /// Remove an entry from the scheduler.
    pub fn remove(&mut self, id: u64) -> Option<EntryMetadata> {
        self.dirty = true;
        self.entries.remove(&id).map(|e| e.metadata)
    }

    /// Select an entry using weighted random selection.
    ///
    /// Higher energy entries are more likely to be selected.
    pub fn select(&mut self, rng: &mut impl Rng) -> Option<u64> {
        if self.entries.is_empty() {
            return None;
        }

        self.recalculate_if_dirty();

        if self.total_energy <= 0.0 {
            // Fallback to uniform selection
            let idx = rng.gen_range(0..self.entries.len());
            return self.entries.keys().nth(idx).copied();
        }

        let target = rng.gen_range(0.0..self.total_energy);
        let mut cumulative = 0.0;

        for entry in self.entries.values() {
            cumulative += entry.energy;
            if cumulative >= target {
                return Some(entry.metadata.id);
            }
        }

        // Fallback to last entry (shouldn't happen)
        self.entries.keys().last().copied()
    }

    /// Update the fuzz count for an entry and recalculate energy.
    pub fn update_fuzz_count(&mut self, id: u64) {
        if let Some(entry) = self.entries.get_mut(&id) {
            entry.metadata.fuzz_count += 1;
            self.dirty = true;
        }
    }

    /// Manually update energy for an entry.
    pub fn update_energy(&mut self, id: u64, factor: f64) {
        if let Some(entry) = self.entries.get_mut(&id) {
            entry.energy *= factor;
            self.dirty = true;
        }
    }

    /// Get energy for an entry.
    pub fn get_energy(&self, id: u64) -> Option<f64> {
        self.entries.get(&id).map(|e| e.energy)
    }

    /// Get metadata for an entry.
    pub fn get_metadata(&self, id: u64) -> Option<&EntryMetadata> {
        self.entries.get(&id).map(|e| &e.metadata)
    }

    /// Get total number of entries.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Check if scheduler is empty.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Get total energy (recalculates if dirty).
    pub fn total_energy(&mut self) -> f64 {
        self.recalculate_if_dirty();
        self.total_energy
    }

    /// Recalculate all energies with given config.
    pub fn recalculate_all(&mut self, config: &EnergyConfig) {
        for entry in self.entries.values_mut() {
            entry.energy = calculate_energy(&entry.metadata, config);
        }
        self.recalculate_total();
    }

    fn recalculate_if_dirty(&mut self) {
        if self.dirty {
            self.recalculate_total();
            self.dirty = false;
        }
    }

    fn recalculate_total(&mut self) {
        self.total_energy = self.entries.values().map(|e| e.energy).sum();
    }
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

/// Calculate energy for an entry based on its metadata.
pub fn calculate_energy(metadata: &EntryMetadata, config: &EnergyConfig) -> f64 {
    let mut energy = config.base_energy;

    // Speed factor: faster execution = more energy
    // Normalize to 0-2 range where 100us is baseline (1.0)
    let speed_factor = if metadata.exec_time_us > 0 {
        (100_000.0 / metadata.exec_time_us as f64).min(2.0).max(0.1)
    } else {
        1.0
    };

    // Coverage factor: more new coverage = more energy
    // Each new edge adds 0.1, capped at 2.0
    let coverage_factor = (1.0 + metadata.coverage_count as f64 * 0.1).min(2.0);

    // Recency factor: newer = more energy
    // Uses exponential decay with half-life
    let recency_factor = if let Ok(elapsed) = SystemTime::now().duration_since(metadata.found_at) {
        let secs = elapsed.as_secs_f64();
        0.5_f64.powf(secs / config.recency_half_life_secs).max(0.1)
    } else {
        1.0
    };

    // Depth factor: shallower chains = more energy
    // Depth 0 = 1.5, depth 10+ = 0.5
    let depth_factor = (1.5 - metadata.depth as f64 * 0.1).max(0.5);

    // Fuzz count factor: less fuzzed = more energy
    // Prevent starvation by not going below 0.2
    let fuzz_factor = (1.0 / (1.0 + metadata.fuzz_count as f64 * 0.05)).max(0.2);

    // Combine factors with weights
    energy *= 1.0
        + config.speed_weight * (speed_factor - 1.0)
        + config.coverage_weight * (coverage_factor - 1.0)
        + config.recency_weight * (recency_factor - 1.0)
        + config.depth_weight * (depth_factor - 1.0);

    // Apply fuzz count factor separately
    energy *= fuzz_factor;

    energy.max(0.01) // Minimum energy to prevent starvation
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_metadata(
        id: u64,
        exec_time_us: u64,
        coverage_count: usize,
        depth: usize,
    ) -> EntryMetadata {
        EntryMetadata {
            id,
            exec_time_us,
            coverage_count,
            found_at: SystemTime::now(),
            depth,
            fuzz_count: 0,
        }
    }

    #[test]
    fn test_scheduler_new() {
        let sched = Scheduler::new();
        assert!(sched.is_empty());
        assert_eq!(sched.len(), 0);
    }

    #[test]
    fn test_scheduler_add() {
        let mut sched = Scheduler::new();
        let meta = make_metadata(1, 1000, 5, 0);
        sched.add(meta);

        assert_eq!(sched.len(), 1);
        assert!(sched.get_energy(1).is_some());
        assert!(sched.get_metadata(1).is_some());
    }

    #[test]
    fn test_scheduler_remove() {
        let mut sched = Scheduler::new();
        sched.add(make_metadata(1, 1000, 5, 0));
        sched.add(make_metadata(2, 1000, 5, 0));

        assert_eq!(sched.len(), 2);

        let removed = sched.remove(1);
        assert!(removed.is_some());
        assert_eq!(removed.unwrap().id, 1);
        assert_eq!(sched.len(), 1);
    }

    #[test]
    fn test_scheduler_select_single() {
        let mut sched = Scheduler::new();
        sched.add(make_metadata(42, 1000, 5, 0));

        let mut rng = rand::thread_rng();
        let selected = sched.select(&mut rng);
        assert_eq!(selected, Some(42));
    }

    #[test]
    fn test_scheduler_select_weighted() {
        let mut sched = Scheduler::new();

        // Add fast entry (high energy) and slow entry (low energy)
        let mut fast = make_metadata(1, 100, 10, 0); // Fast, high coverage
        let mut slow = make_metadata(2, 100000, 1, 5); // Slow, low coverage, deep

        sched.add(fast.clone());
        sched.add(slow.clone());

        // Fast entry should have higher energy
        let fast_energy = sched.get_energy(1).unwrap();
        let slow_energy = sched.get_energy(2).unwrap();
        assert!(
            fast_energy > slow_energy,
            "fast: {}, slow: {}",
            fast_energy,
            slow_energy
        );

        // Select many times, fast should be selected more often
        let mut rng = rand::thread_rng();
        let mut fast_count = 0;
        let iterations = 1000;

        for _ in 0..iterations {
            if sched.select(&mut rng) == Some(1) {
                fast_count += 1;
            }
        }

        // Fast entry should be selected more than 60% of the time
        let fast_ratio = fast_count as f64 / iterations as f64;
        assert!(fast_ratio > 0.6, "fast selected {}%", fast_ratio * 100.0);
    }

    #[test]
    fn test_scheduler_update_fuzz_count() {
        let mut sched = Scheduler::new();
        sched.add(make_metadata(1, 1000, 5, 0));

        let initial_energy = sched.get_energy(1).unwrap();

        // Update fuzz count multiple times
        for _ in 0..10 {
            sched.update_fuzz_count(1);
        }

        // Recalculate to apply fuzz count effect
        sched.recalculate_all(&EnergyConfig::default());

        // Energy should decrease with more fuzz count
        let final_energy = sched.get_energy(1).unwrap();
        assert!(final_energy < initial_energy);
    }

    #[test]
    fn test_scheduler_update_energy() {
        let mut sched = Scheduler::new();
        sched.add(make_metadata(1, 1000, 5, 0));

        let initial_energy = sched.get_energy(1).unwrap();
        sched.update_energy(1, 2.0);

        let new_energy = sched.get_energy(1).unwrap();
        assert!((new_energy - initial_energy * 2.0).abs() < 0.001);
    }

    #[test]
    fn test_energy_calculation_speed() {
        let config = EnergyConfig::default();

        let fast = make_metadata(1, 100, 5, 0);
        let slow = make_metadata(2, 100000, 5, 0);

        let fast_energy = calculate_energy(&fast, &config);
        let slow_energy = calculate_energy(&slow, &config);

        assert!(fast_energy > slow_energy);
    }

    #[test]
    fn test_energy_calculation_coverage() {
        let config = EnergyConfig::default();

        let high_cov = make_metadata(1, 1000, 10, 0);
        let low_cov = make_metadata(2, 1000, 1, 0);

        let high_energy = calculate_energy(&high_cov, &config);
        let low_energy = calculate_energy(&low_cov, &config);

        assert!(high_energy > low_energy);
    }

    #[test]
    fn test_energy_calculation_depth() {
        let config = EnergyConfig::default();

        let shallow = make_metadata(1, 1000, 5, 0);
        let deep = make_metadata(2, 1000, 5, 10);

        let shallow_energy = calculate_energy(&shallow, &config);
        let deep_energy = calculate_energy(&deep, &config);

        assert!(shallow_energy > deep_energy);
    }

    #[test]
    fn test_energy_calculation_fuzz_count() {
        let config = EnergyConfig::default();

        let fresh = make_metadata(1, 1000, 5, 0);
        let mut fuzzed = make_metadata(2, 1000, 5, 0);
        fuzzed.fuzz_count = 20;

        let fresh_energy = calculate_energy(&fresh, &config);
        let fuzzed_energy = calculate_energy(&fuzzed, &config);

        assert!(fresh_energy > fuzzed_energy);
    }

    #[test]
    fn test_energy_minimum() {
        let config = EnergyConfig::default();

        // Even with bad stats, energy should be positive
        let mut bad = make_metadata(1, 1_000_000, 0, 100);
        bad.fuzz_count = 1000;

        let energy = calculate_energy(&bad, &config);
        assert!(energy >= 0.01);
    }

    #[test]
    fn test_scheduler_empty_select() {
        let mut sched = Scheduler::new();
        let mut rng = rand::thread_rng();

        assert!(sched.select(&mut rng).is_none());
    }

    #[test]
    fn test_total_energy() {
        let mut sched = Scheduler::new();
        sched.add(make_metadata(1, 1000, 5, 0));
        sched.add(make_metadata(2, 1000, 5, 0));

        let total = sched.total_energy();
        let e1 = sched.get_energy(1).unwrap();
        let e2 = sched.get_energy(2).unwrap();

        assert!((total - (e1 + e2)).abs() < 0.001);
    }
}
