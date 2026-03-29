use super::strategies::{MutationStrategy, RngCore};
use crate::error::Result;
use std::fs;
use std::path::Path;

/// Dictionary of tokens for mutation.
#[derive(Debug, Clone, Default)]
pub struct Dictionary {
    tokens: Vec<Vec<u8>>,
}

impl Dictionary {
    /// Create an empty dictionary.
    pub fn new() -> Self {
        Self { tokens: Vec::new() }
    }

    /// Load dictionary from file.
    pub fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let mut dict = Self::new();

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(token) = parse_token(line) {
                dict.add(token);
            }
        }

        Ok(dict)
    }

    /// Add a token to the dictionary.
    pub fn add(&mut self, token: Vec<u8>) {
        if !token.is_empty() && !self.tokens.contains(&token) {
            self.tokens.push(token);
        }
    }

    /// Get a random token.
    pub fn random(&self, rng: &mut dyn RngCore) -> Option<&[u8]> {
        if self.tokens.is_empty() {
            None
        } else {
            let idx = rng.gen_range_usize(0, self.tokens.len());
            Some(&self.tokens[idx])
        }
    }

    /// Number of tokens.
    pub fn len(&self) -> usize {
        self.tokens.len()
    }

    /// Check if empty.
    pub fn is_empty(&self) -> bool {
        self.tokens.is_empty()
    }

    /// Auto-extract tokens from input data.
    pub fn auto_extract(data: &[u8]) -> Self {
        let mut dict = Self::new();

        let mut current_string = Vec::new();
        for &b in data {
            if b.is_ascii_graphic() || b == b' ' {
                current_string.push(b);
            } else {
                if current_string.len() >= 4 {
                    dict.add(current_string.clone());
                }
                current_string.clear();
            }
        }
        if current_string.len() >= 4 {
            dict.add(current_string);
        }

        for window_size in [2, 4, 8] {
            if data.len() >= window_size {
                dict.add(data[..window_size].to_vec());
            }
        }

        dict
    }
}

fn parse_token(s: &str) -> Option<Vec<u8>> {
    let s = s.trim_matches('"');
    let mut result = Vec::new();
    let mut chars = s.chars().peekable();

    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('x') => {
                    let hi = chars.next()?.to_digit(16)?;
                    let lo = chars.next()?.to_digit(16)?;
                    result.push((hi * 16 + lo) as u8);
                }
                Some('n') => result.push(b'\n'),
                Some('r') => result.push(b'\r'),
                Some('t') => result.push(b'\t'),
                Some('0') => result.push(0),
                Some('\\') => result.push(b'\\'),
                Some('"') => result.push(b'"'),
                Some(other) => {
                    result.push(b'\\');
                    result.push(other as u8);
                }
                None => result.push(b'\\'),
            }
        } else {
            result.push(c as u8);
        }
    }

    if result.is_empty() { None } else { Some(result) }
}

/// Insert a dictionary token at a random position.
pub struct DictInsert {
    dict: Dictionary,
}

impl DictInsert {
    pub fn new(dict: Dictionary) -> Self {
        Self { dict }
    }
}

impl MutationStrategy for DictInsert {
    fn mutate(&self, input: &mut Vec<u8>, rng: &mut dyn RngCore) {
        if let Some(token) = self.dict.random(rng) {
            let pos = rng.gen_range_usize(0, input.len() + 1);
            input.splice(pos..pos, token.iter().copied());
        }
    }

    fn name(&self) -> &'static str {
        "dict_insert"
    }
}

/// Overwrite with a dictionary token.
pub struct DictOverwrite {
    dict: Dictionary,
}

impl DictOverwrite {
    pub fn new(dict: Dictionary) -> Self {
        Self { dict }
    }
}

impl MutationStrategy for DictOverwrite {
    fn mutate(&self, input: &mut Vec<u8>, rng: &mut dyn RngCore) {
        if let Some(token) = self.dict.random(rng) {
            if input.len() >= token.len() {
                let pos = rng.gen_range_usize(0, input.len() - token.len() + 1);
                for (i, &b) in token.iter().enumerate() {
                    input[pos + i] = b;
                }
            }
        }
    }

    fn name(&self) -> &'static str {
        "dict_overwrite"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::SeedableRng;
    use rand_chacha::ChaCha8Rng;
    use tempfile::NamedTempFile;

    fn seeded_rng() -> ChaCha8Rng {
        ChaCha8Rng::seed_from_u64(12345)
    }

    #[test]
    fn test_dictionary_new() {
        let dict = Dictionary::new();
        assert!(dict.is_empty());
        assert_eq!(dict.len(), 0);
    }

    #[test]
    fn test_dictionary_add() {
        let mut dict = Dictionary::new();
        dict.add(b"hello".to_vec());
        dict.add(b"world".to_vec());
        assert_eq!(dict.len(), 2);
        dict.add(b"hello".to_vec());
        assert_eq!(dict.len(), 2);
        dict.add(vec![]);
        assert_eq!(dict.len(), 2);
    }

    #[test]
    fn test_dictionary_random() {
        let mut dict = Dictionary::new();
        let mut rng = seeded_rng();
        assert!(dict.random(&mut rng).is_none());
        dict.add(b"test".to_vec());
        assert_eq!(dict.random(&mut rng), Some(b"test".as_ref()));
    }

    #[test]
    fn test_dictionary_load() {
        use std::io::Write;

        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "# comment").unwrap();
        writeln!(file, "hello").unwrap();
        writeln!(file, "\"world\"").unwrap();
        writeln!(file, "\"\\x41\\x42\"").unwrap();
        writeln!(file).unwrap();
        file.flush().unwrap();

        let dict = Dictionary::load(file.path()).unwrap();
        assert_eq!(dict.len(), 3);
    }

    #[test]
    fn test_parse_token() {
        assert_eq!(parse_token("hello"), Some(b"hello".to_vec()));
        assert_eq!(parse_token("\"quoted\""), Some(b"quoted".to_vec()));
        assert_eq!(parse_token("\\x41\\x42"), Some(b"AB".to_vec()));
        assert_eq!(parse_token("a\\nb"), Some(b"a\nb".to_vec()));
        assert_eq!(parse_token(""), None);
    }

    #[test]
    fn test_auto_extract() {
        let data = b"Hello World! \x00\x01\x02";
        let dict = Dictionary::auto_extract(data);
        assert!(!dict.is_empty());
    }

    #[test]
    fn test_dict_insert() {
        let mut dict = Dictionary::new();
        dict.add(b"FUZZ".to_vec());
        let mutator = DictInsert::new(dict);

        let mut input = vec![1, 2, 3, 4];
        let original_len = input.len();
        let mut rng = seeded_rng();
        mutator.mutate(&mut input, &mut rng);
        assert_eq!(input.len(), original_len + 4);
    }

    #[test]
    fn test_dict_overwrite() {
        let mut dict = Dictionary::new();
        dict.add(b"XX".to_vec());
        let mutator = DictOverwrite::new(dict);

        let mut input = vec![1, 2, 3, 4];
        let mut rng = seeded_rng();
        mutator.mutate(&mut input, &mut rng);
        assert_eq!(input.len(), 4);
        let has_xx = input.windows(2).any(|w| w == b"XX");
        assert!(has_xx);
    }
}
