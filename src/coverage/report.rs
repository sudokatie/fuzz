//! Coverage visualization and reporting.

use super::Bitmap;
use std::collections::HashMap;
use std::io::Write;
use std::path::Path;

/// Coverage report for visualization.
#[derive(Debug, Clone)]
pub struct CoverageReport {
    /// Total edges in the target.
    pub total_edges: usize,
    /// Edges that have been hit.
    pub covered_edges: usize,
    /// Edge hit counts (edge_id -> hit_count).
    pub edge_hits: HashMap<usize, u8>,
    /// Coverage percentage.
    pub coverage_pct: f64,
    /// Hit count distribution (bucket -> count).
    pub hit_distribution: [usize; 8],
}

impl CoverageReport {
    /// Create a new coverage report from a virgin bitmap.
    ///
    /// The virgin bitmap has 0xff for uncovered edges and lower values for covered.
    pub fn from_virgin(virgin: &Bitmap, total_edges: Option<usize>) -> Self {
        let mut covered_edges = 0;
        let mut edge_hits = HashMap::new();
        let mut hit_distribution = [0usize; 8];

        for (idx, &byte) in virgin.as_slice().iter().enumerate() {
            if byte != 0xff {
                covered_edges += 1;
                let hits = 0xff - byte;
                edge_hits.insert(idx, hits);
                
                // Bucket the hit count
                let bucket = bucket_index(hits);
                hit_distribution[bucket] += 1;
            }
        }

        let total = total_edges.unwrap_or(virgin.as_slice().len());
        let coverage_pct = if total > 0 {
            (covered_edges as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        CoverageReport {
            total_edges: total,
            covered_edges,
            edge_hits,
            coverage_pct,
            hit_distribution,
        }
    }

    /// Create a report from an active coverage bitmap.
    ///
    /// The active bitmap has non-zero values for edges hit in this execution.
    pub fn from_active(bitmap: &Bitmap) -> Self {
        let mut covered_edges = 0;
        let mut edge_hits = HashMap::new();
        let mut hit_distribution = [0usize; 8];

        for (idx, &byte) in bitmap.as_slice().iter().enumerate() {
            if byte != 0 {
                covered_edges += 1;
                edge_hits.insert(idx, byte);
                
                let bucket = bucket_index(byte);
                hit_distribution[bucket] += 1;
            }
        }

        let total = bitmap.as_slice().len();
        let coverage_pct = if total > 0 {
            (covered_edges as f64 / total as f64) * 100.0
        } else {
            0.0
        };

        CoverageReport {
            total_edges: total,
            covered_edges,
            edge_hits,
            coverage_pct,
            hit_distribution,
        }
    }

    /// Generate a text summary.
    pub fn summary(&self) -> String {
        let mut s = String::new();
        
        s.push_str(&format!("Coverage Report\n"));
        s.push_str(&format!("===============\n\n"));
        s.push_str(&format!("Covered edges: {} / {} ({:.2}%)\n\n",
            self.covered_edges, self.total_edges, self.coverage_pct));
        
        s.push_str("Hit count distribution:\n");
        let labels = ["1", "2", "3", "4-7", "8-15", "16-31", "32-127", "128+"];
        for (i, label) in labels.iter().enumerate() {
            let count = self.hit_distribution[i];
            let bar_len = (count as f64 / self.covered_edges.max(1) as f64 * 40.0) as usize;
            let bar: String = "█".repeat(bar_len);
            s.push_str(&format!("  {:>7} hits: {:>6} {}\n", label, count, bar));
        }
        
        s
    }

    /// Generate an HTML report.
    pub fn to_html(&self) -> String {
        let mut html = String::new();
        
        html.push_str("<!DOCTYPE html>\n<html>\n<head>\n");
        html.push_str("<title>Coverage Report</title>\n");
        html.push_str("<style>\n");
        html.push_str("body { font-family: sans-serif; margin: 2em; }\n");
        html.push_str(".stats { margin: 1em 0; }\n");
        html.push_str(".bar { background: #4CAF50; height: 20px; }\n");
        html.push_str(".bar-container { background: #ddd; width: 400px; }\n");
        html.push_str("table { border-collapse: collapse; margin-top: 1em; }\n");
        html.push_str("th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }\n");
        html.push_str("th { background: #f5f5f5; }\n");
        html.push_str("</style>\n</head>\n<body>\n");
        
        html.push_str("<h1>Coverage Report</h1>\n");
        
        // Summary stats
        html.push_str("<div class='stats'>\n");
        html.push_str(&format!("<p><strong>Covered edges:</strong> {} / {} ({:.2}%)</p>\n",
            self.covered_edges, self.total_edges, self.coverage_pct));
        html.push_str("<div class='bar-container'>\n");
        html.push_str(&format!("<div class='bar' style='width: {}%;'></div>\n",
            self.coverage_pct.min(100.0)));
        html.push_str("</div>\n</div>\n");
        
        // Hit distribution table
        html.push_str("<h2>Hit Count Distribution</h2>\n");
        html.push_str("<table>\n<tr><th>Hits</th><th>Count</th><th>Percentage</th></tr>\n");
        
        let labels = ["1", "2", "3", "4-7", "8-15", "16-31", "32-127", "128+"];
        for (i, label) in labels.iter().enumerate() {
            let count = self.hit_distribution[i];
            let pct = if self.covered_edges > 0 {
                (count as f64 / self.covered_edges as f64) * 100.0
            } else {
                0.0
            };
            html.push_str(&format!("<tr><td>{}</td><td>{}</td><td>{:.1}%</td></tr>\n",
                label, count, pct));
        }
        
        html.push_str("</table>\n");
        html.push_str("</body>\n</html>\n");
        
        html
    }

    /// Write HTML report to a file.
    pub fn write_html<P: AsRef<Path>>(&self, path: P) -> std::io::Result<()> {
        let html = self.to_html();
        std::fs::write(path, html)
    }

    /// Generate a coverage map visualization (ASCII art).
    pub fn coverage_map(&self, width: usize) -> String {
        let mut map = String::new();
        let slice = vec![0u8; self.total_edges]; // Placeholder - would need actual edge data
        
        // Group edges into chunks for visualization
        let chunk_size = (self.total_edges / width).max(1);
        
        for chunk_start in (0..self.total_edges).step_by(chunk_size * width) {
            for col in 0..width {
                let start = chunk_start + col * chunk_size;
                let end = (start + chunk_size).min(self.total_edges);
                
                if start >= self.total_edges {
                    break;
                }
                
                // Count covered in this chunk
                let covered_in_chunk = (start..end)
                    .filter(|&i| self.edge_hits.contains_key(&i))
                    .count();
                
                let ratio = covered_in_chunk as f64 / (end - start).max(1) as f64;
                let char = if ratio == 0.0 {
                    '░'
                } else if ratio < 0.25 {
                    '▒'
                } else if ratio < 0.75 {
                    '▓'
                } else {
                    '█'
                };
                
                map.push(char);
            }
            map.push('\n');
        }
        
        map
    }
}

/// Map hit count to bucket index (0-7).
fn bucket_index(hits: u8) -> usize {
    match hits {
        1 => 0,
        2 => 1,
        3 => 2,
        4..=7 => 3,
        8..=15 => 4,
        16..=31 => 5,
        32..=127 => 6,
        _ => 7,
    }
}

/// Live coverage tracker for incremental updates.
pub struct CoverageTracker {
    /// Cumulative virgin bitmap.
    virgin: Bitmap,
    /// Number of unique edges discovered over time.
    history: Vec<(u64, usize)>, // (exec_count, edge_count)
}

impl CoverageTracker {
    /// Create a new coverage tracker.
    pub fn new() -> Self {
        Self {
            virgin: Bitmap::virgin(),
            history: Vec::new(),
        }
    }

    /// Update with new coverage, returns true if new edges found.
    pub fn update(&mut self, bitmap: &Bitmap, exec_count: u64) -> bool {
        let had_new = bitmap.has_new_bits(&self.virgin);
        if had_new {
            bitmap.update_virgin(&mut self.virgin);
            let edge_count = self.edge_count();
            self.history.push((exec_count, edge_count));
        }
        had_new
    }

    /// Get current edge count.
    pub fn edge_count(&self) -> usize {
        self.virgin
            .as_slice()
            .iter()
            .filter(|&&b| b != 0xff)
            .count()
    }

    /// Get coverage history for plotting.
    pub fn history(&self) -> &[(u64, usize)] {
        &self.history
    }

    /// Generate a report from current state.
    pub fn report(&self) -> CoverageReport {
        CoverageReport::from_virgin(&self.virgin, None)
    }
}

impl Default for CoverageTracker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bucket_index() {
        assert_eq!(bucket_index(1), 0);
        assert_eq!(bucket_index(2), 1);
        assert_eq!(bucket_index(3), 2);
        assert_eq!(bucket_index(5), 3);
        assert_eq!(bucket_index(10), 4);
        assert_eq!(bucket_index(20), 5);
        assert_eq!(bucket_index(50), 6);
        assert_eq!(bucket_index(200), 7);
    }

    #[test]
    fn test_coverage_report_from_virgin() {
        let mut virgin = Bitmap::virgin();
        // Simulate some coverage
        let slice = virgin.as_mut_slice();
        slice[0] = 0xfe; // 1 hit
        slice[1] = 0xfd; // 2 hits
        slice[10] = 0xf0; // 15 hits
        
        let report = CoverageReport::from_virgin(&virgin, Some(1000));
        
        assert_eq!(report.covered_edges, 3);
        assert_eq!(report.total_edges, 1000);
        assert!(report.coverage_pct > 0.0);
    }

    #[test]
    fn test_coverage_report_from_active() {
        let mut bitmap = Bitmap::new();
        let slice = bitmap.as_mut_slice();
        slice[0] = 5;
        slice[1] = 10;
        slice[2] = 1;
        
        let report = CoverageReport::from_active(&bitmap);
        
        assert_eq!(report.covered_edges, 3);
    }

    #[test]
    fn test_coverage_report_summary() {
        let mut virgin = Bitmap::virgin();
        let slice = virgin.as_mut_slice();
        slice[0] = 0xfe;
        slice[1] = 0xfc;
        
        let report = CoverageReport::from_virgin(&virgin, None);
        let summary = report.summary();
        
        assert!(summary.contains("Coverage Report"));
        assert!(summary.contains("Covered edges"));
    }

    #[test]
    fn test_coverage_report_html() {
        let report = CoverageReport {
            total_edges: 1000,
            covered_edges: 250,
            edge_hits: HashMap::new(),
            coverage_pct: 25.0,
            hit_distribution: [100, 50, 30, 40, 20, 5, 3, 2],
        };
        
        let html = report.to_html();
        
        assert!(html.contains("<!DOCTYPE html>"));
        assert!(html.contains("Coverage Report"));
        assert!(html.contains("25.0%") || html.contains("25.00%"));
    }

    #[test]
    fn test_coverage_tracker_new() {
        let tracker = CoverageTracker::new();
        assert_eq!(tracker.edge_count(), 0);
        assert!(tracker.history().is_empty());
    }

    #[test]
    fn test_coverage_tracker_update() {
        let mut tracker = CoverageTracker::new();
        
        let mut bitmap = Bitmap::new();
        bitmap.as_mut_slice()[0] = 1;
        bitmap.as_mut_slice()[1] = 1;
        
        let found_new = tracker.update(&bitmap, 100);
        assert!(found_new);
        assert_eq!(tracker.edge_count(), 2);
        assert_eq!(tracker.history().len(), 1);
        assert_eq!(tracker.history()[0], (100, 2));
    }

    #[test]
    fn test_coverage_tracker_no_new() {
        let mut tracker = CoverageTracker::new();
        
        let mut bitmap = Bitmap::new();
        bitmap.as_mut_slice()[0] = 1;
        
        tracker.update(&bitmap, 100);
        
        // Same coverage again - should not add to history
        let found_new = tracker.update(&bitmap, 200);
        assert!(!found_new);
        assert_eq!(tracker.history().len(), 1);
    }

    #[test]
    fn test_coverage_tracker_report() {
        let mut tracker = CoverageTracker::new();
        
        let mut bitmap = Bitmap::new();
        bitmap.as_mut_slice()[0] = 5;
        bitmap.as_mut_slice()[1] = 10;
        tracker.update(&bitmap, 100);
        
        let report = tracker.report();
        assert_eq!(report.covered_edges, 2);
    }

    #[test]
    fn test_coverage_map() {
        let report = CoverageReport {
            total_edges: 100,
            covered_edges: 25,
            edge_hits: (0..25).map(|i| (i, 1)).collect(),
            coverage_pct: 25.0,
            hit_distribution: [25, 0, 0, 0, 0, 0, 0, 0],
        };
        
        let map = report.coverage_map(10);
        assert!(!map.is_empty());
    }

    #[test]
    fn test_empty_report() {
        let virgin = Bitmap::virgin();
        let report = CoverageReport::from_virgin(&virgin, Some(100));
        
        assert_eq!(report.covered_edges, 0);
        assert_eq!(report.coverage_pct, 0.0);
    }
}
