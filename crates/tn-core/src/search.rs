#![forbid(unsafe_code)]
#![warn(clippy::all)]
//! In-memory inverted search index over decrypted notes.
//!
//! Guarantees:
//! - Operates purely in volatile RAM while the vault is unlocked.
//! - Search terms and inverted indexes are NEVER written unencrypted to disk.

use std::collections::{HashMap, HashSet};
use tn_types::Id16;

/// In-memory inverted index for searching note titles, tags, and bodies.
#[derive(Debug, Default, Clone)]
pub struct SearchIndex {
    /// Token -> Map<object_id, score>
    index: HashMap<String, HashMap<Id16, u32>>,
    /// Tracks which objects are currently indexed.
    indexed_objects: HashSet<Id16>,
}

impl SearchIndex {
    /// Create a new empty search index.
    #[must_use]
    pub fn new() -> Self {
        Self {
            index: HashMap::new(),
            indexed_objects: HashSet::new(),
        }
    }

    /// Tokenizes input string into lowercase alphanumeric words.
    #[must_use]
    pub fn tokenize(text: &str) -> Vec<String> {
        text.split(|c: char| !c.is_alphanumeric())
            .filter(|w| !w.is_empty())
            .map(|w| w.to_lowercase())
            .collect()
    }

    /// Indexes or re-indexes a note.
    pub fn index_note(&mut self, object_id: Id16, title: &str, body_md: &str, tags: &[String]) {
        self.remove_note(object_id);

        // Title terms weighted 5x
        for token in Self::tokenize(title) {
            *self
                .index
                .entry(token)
                .or_default()
                .entry(object_id)
                .or_default() += 5;
        }

        // Tags weighted 3x
        for tag in tags {
            for token in Self::tokenize(tag) {
                *self
                    .index
                    .entry(token)
                    .or_default()
                    .entry(object_id)
                    .or_default() += 3;
            }
        }

        // Body terms weighted 1x
        for token in Self::tokenize(body_md) {
            *self
                .index
                .entry(token)
                .or_default()
                .entry(object_id)
                .or_default() += 1;
        }

        self.indexed_objects.insert(object_id);
    }

    /// Removes an object from the index (e.g. on deletion or re-indexing).
    pub fn remove_note(&mut self, object_id: Id16) {
        if !self.indexed_objects.remove(&object_id) {
            return;
        }

        for postings in self.index.values_mut() {
            postings.remove(&object_id);
        }
    }

    /// Searches for notes matching query tokens. Returns object_ids sorted by match score descending.
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<Id16> {
        let tokens = Self::tokenize(query);
        if tokens.is_empty() {
            return Vec::new();
        }

        let mut scores: HashMap<Id16, u32> = HashMap::new();

        for token in &tokens {
            if let Some(postings) = self.index.get(token) {
                for (&obj_id, &score) in postings {
                    *scores.entry(obj_id).or_default() += score;
                }
            }
        }

        let mut results: Vec<(Id16, u32)> = scores.into_iter().collect();
        // Sort descending by score, tie-break by object_id bytes
        results.sort_by(|a, b| {
            b.1.cmp(&a.1)
                .then_with(|| a.0.as_bytes().cmp(b.0.as_bytes()))
        });
        results.into_iter().map(|(id, _)| id).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_search_index_ranking() {
        let mut idx = SearchIndex::new();

        let id1 = Id16::from_bytes([1u8; 16]);
        let id2 = Id16::from_bytes([2u8; 16]);

        // Note 1 has "cryptography" in title
        idx.index_note(id1, "Modern Cryptography", "Security notes", &[]);
        // Note 2 has "cryptography" in body
        idx.index_note(
            id2,
            "General Notes",
            "Talks about cryptography in details",
            &[],
        );

        let results = idx.search("cryptography");
        assert_eq!(results.len(), 2);
        // Note 1 should rank higher due to title weight
        assert_eq!(results[0], id1);
        assert_eq!(results[1], id2);
    }
}
