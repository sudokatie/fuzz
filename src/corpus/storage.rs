use crate::corpus::entry::CorpusEntry;
use crate::error::Result;
use rusqlite::{params, Connection};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

/// On-disk storage for corpus entries using SQLite.
pub struct CorpusStorage {
    dir: PathBuf,
    db: Connection,
}

impl CorpusStorage {
    /// Open or create a corpus storage at the given directory.
    pub fn open(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir)?;

        let db_path = dir.join("corpus.db");
        let db = Connection::open(&db_path)?;

        // Create tables if they don't exist
        db.execute_batch(
            "
            CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY,
                coverage_hash INTEGER NOT NULL,
                exec_time_us INTEGER NOT NULL,
                found_at INTEGER NOT NULL,
                parent_id INTEGER,
                mutation TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_coverage_hash ON entries(coverage_hash);
            
            CREATE TABLE IF NOT EXISTS new_coverage (
                entry_id INTEGER NOT NULL,
                bit_index INTEGER NOT NULL,
                FOREIGN KEY (entry_id) REFERENCES entries(id)
            );
            CREATE INDEX IF NOT EXISTS idx_entry_id ON new_coverage(entry_id);
            ",
        )?;

        Ok(Self {
            dir: dir.to_path_buf(),
            db,
        })
    }

    /// Save a corpus entry.
    pub fn save(&self, entry: &CorpusEntry) -> Result<()> {
        // Save input to file
        let input_path = self.input_path(entry.id);
        fs::write(&input_path, &entry.input)?;

        // Save metadata to database
        let found_at = entry
            .found_at
            .duration_since(SystemTime::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        self.db.execute(
            "INSERT OR REPLACE INTO entries (id, coverage_hash, exec_time_us, found_at, parent_id, mutation)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                entry.id as i64,
                entry.coverage_hash as i64,
                entry.exec_time_us as i64,
                found_at as i64,
                entry.parent_id.map(|id| id as i64),
                entry.mutation.as_deref(),
            ],
        )?;

        // Save new coverage bits
        self.db.execute(
            "DELETE FROM new_coverage WHERE entry_id = ?1",
            params![entry.id as i64],
        )?;

        for &bit_index in &entry.new_coverage {
            self.db.execute(
                "INSERT INTO new_coverage (entry_id, bit_index) VALUES (?1, ?2)",
                params![entry.id as i64, bit_index as i64],
            )?;
        }

        Ok(())
    }

    /// Load a single entry by ID.
    pub fn load(&self, id: u64) -> Result<Option<CorpusEntry>> {
        let input_path = self.input_path(id);
        if !input_path.exists() {
            return Ok(None);
        }

        let input = fs::read(&input_path)?;

        let row: Option<(i64, i64, i64, Option<i64>, Option<String>)> = self
            .db
            .query_row(
                "SELECT coverage_hash, exec_time_us, found_at, parent_id, mutation
                 FROM entries WHERE id = ?1",
                params![id as i64],
                |row| {
                    Ok((
                        row.get(0)?,
                        row.get(1)?,
                        row.get(2)?,
                        row.get(3)?,
                        row.get(4)?,
                    ))
                },
            )
            .ok();

        let Some((coverage_hash, exec_time_us, found_at_secs, parent_id, mutation)) = row else {
            return Ok(None);
        };

        let found_at =
            SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(found_at_secs as u64);

        // Load new coverage bits
        let mut stmt = self
            .db
            .prepare("SELECT bit_index FROM new_coverage WHERE entry_id = ?1")?;
        let new_coverage: Vec<u16> = stmt
            .query_map(params![id as i64], |row| {
                let idx: i64 = row.get(0)?;
                Ok(idx as u16)
            })?
            .filter_map(|r| r.ok())
            .collect();

        Ok(Some(CorpusEntry {
            id,
            input,
            coverage_hash: coverage_hash as u64,
            new_coverage,
            exec_time_us: exec_time_us as u64,
            found_at,
            parent_id: parent_id.map(|id| id as u64),
            mutation,
        }))
    }

    /// Load all entries from storage.
    pub fn load_all(&self) -> Result<Vec<CorpusEntry>> {
        let mut entries = Vec::new();

        let mut stmt = self.db.prepare("SELECT id FROM entries")?;
        let ids: Vec<u64> = stmt
            .query_map([], |row| {
                let id: i64 = row.get(0)?;
                Ok(id as u64)
            })?
            .filter_map(|r| r.ok())
            .collect();

        for id in ids {
            if let Some(entry) = self.load(id)? {
                entries.push(entry);
            }
        }

        Ok(entries)
    }

    /// Count entries in storage.
    pub fn count(&self) -> Result<usize> {
        let count: i64 = self
            .db
            .query_row("SELECT COUNT(*) FROM entries", [], |row| row.get(0))?;
        Ok(count as usize)
    }

    /// Check if a coverage hash already exists.
    pub fn has_coverage_hash(&self, hash: u64) -> Result<bool> {
        let count: i64 = self.db.query_row(
            "SELECT COUNT(*) FROM entries WHERE coverage_hash = ?1",
            params![hash as i64],
            |row| row.get(0),
        )?;
        Ok(count > 0)
    }

    /// Get the next available ID.
    pub fn next_id(&self) -> Result<u64> {
        let max_id: Option<i64> = self
            .db
            .query_row("SELECT MAX(id) FROM entries", [], |row| row.get(0))?;
        Ok(max_id.map(|id| (id + 1) as u64).unwrap_or(1))
    }

    /// Delete an entry.
    pub fn delete(&self, id: u64) -> Result<()> {
        let input_path = self.input_path(id);
        if input_path.exists() {
            fs::remove_file(&input_path)?;
        }

        self.db
            .execute("DELETE FROM entries WHERE id = ?1", params![id as i64])?;
        self.db.execute(
            "DELETE FROM new_coverage WHERE entry_id = ?1",
            params![id as i64],
        )?;

        Ok(())
    }

    /// Path to input file for an entry.
    fn input_path(&self, id: u64) -> PathBuf {
        self.dir.join(format!("{:016x}.input", id))
    }
}

/// Load seed corpus from a directory.
pub fn load_seeds(dir: &Path) -> Result<Vec<Vec<u8>>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }

    let mut seeds = Vec::new();

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.is_file() {
            match fs::read(&path) {
                Ok(data) => seeds.push(data),
                Err(e) => {
                    eprintln!("warning: failed to read seed {}: {}", path.display(), e);
                }
            }
        }
    }

    Ok(seeds)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_storage_open() {
        let tmp = TempDir::new().unwrap();
        let storage = CorpusStorage::open(tmp.path()).unwrap();
        assert_eq!(storage.count().unwrap(), 0);
    }

    #[test]
    fn test_storage_save_load() {
        let tmp = TempDir::new().unwrap();
        let storage = CorpusStorage::open(tmp.path()).unwrap();

        let mut entry = CorpusEntry::new(1, vec![1, 2, 3, 4, 5]);
        entry.coverage_hash = 12345;
        entry.exec_time_us = 1000;
        entry.new_coverage = vec![100, 200, 300];
        entry.mutation = Some("bit_flip".to_string());

        storage.save(&entry).unwrap();
        assert_eq!(storage.count().unwrap(), 1);

        let loaded = storage.load(1).unwrap().unwrap();
        assert_eq!(loaded.input, entry.input);
        assert_eq!(loaded.coverage_hash, entry.coverage_hash);
        assert_eq!(loaded.exec_time_us, entry.exec_time_us);
        assert_eq!(loaded.new_coverage, entry.new_coverage);
        assert_eq!(loaded.mutation, entry.mutation);
    }

    #[test]
    fn test_storage_load_all() {
        let tmp = TempDir::new().unwrap();
        let storage = CorpusStorage::open(tmp.path()).unwrap();

        for i in 1..=3 {
            let entry = CorpusEntry::new(i, vec![i as u8; i as usize]);
            storage.save(&entry).unwrap();
        }

        let all = storage.load_all().unwrap();
        assert_eq!(all.len(), 3);
    }

    #[test]
    fn test_storage_delete() {
        let tmp = TempDir::new().unwrap();
        let storage = CorpusStorage::open(tmp.path()).unwrap();

        let entry = CorpusEntry::new(1, vec![1, 2, 3]);
        storage.save(&entry).unwrap();
        assert_eq!(storage.count().unwrap(), 1);

        storage.delete(1).unwrap();
        assert_eq!(storage.count().unwrap(), 0);
        assert!(storage.load(1).unwrap().is_none());
    }

    #[test]
    fn test_storage_next_id() {
        let tmp = TempDir::new().unwrap();
        let storage = CorpusStorage::open(tmp.path()).unwrap();

        assert_eq!(storage.next_id().unwrap(), 1);

        let entry = CorpusEntry::new(5, vec![1, 2, 3]);
        storage.save(&entry).unwrap();
        assert_eq!(storage.next_id().unwrap(), 6);
    }

    #[test]
    fn test_storage_has_coverage_hash() {
        let tmp = TempDir::new().unwrap();
        let storage = CorpusStorage::open(tmp.path()).unwrap();

        assert!(!storage.has_coverage_hash(12345).unwrap());

        let mut entry = CorpusEntry::new(1, vec![1, 2, 3]);
        entry.coverage_hash = 12345;
        storage.save(&entry).unwrap();

        assert!(storage.has_coverage_hash(12345).unwrap());
        assert!(!storage.has_coverage_hash(99999).unwrap());
    }

    #[test]
    fn test_load_seeds() {
        let tmp = TempDir::new().unwrap();

        fs::write(tmp.path().join("seed1"), b"hello").unwrap();
        fs::write(tmp.path().join("seed2"), b"world").unwrap();

        let seeds = load_seeds(tmp.path()).unwrap();
        assert_eq!(seeds.len(), 2);
    }

    #[test]
    fn test_load_seeds_empty() {
        let tmp = TempDir::new().unwrap();
        let seeds = load_seeds(tmp.path()).unwrap();
        assert!(seeds.is_empty());
    }

    #[test]
    fn test_load_seeds_nonexistent() {
        let seeds = load_seeds(Path::new("/nonexistent/path")).unwrap();
        assert!(seeds.is_empty());
    }
}
