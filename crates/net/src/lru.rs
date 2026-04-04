//! `lru-slabmap`
//!
//! This wraps `lru-slab` with a `HashMap` as necessary to achieve a LRU cache'd hash map. The
//! choice of `lru-slab` is due to how it is in use within `quinn-proto`, a transient dependency,
//! and how it claims constant complexity which means it ideally is efficient enough to compose
//! with `HashMap` without being too much of a regression compared to a dedicated, inlined
//! solution.

use core::{cmp::Eq, hash::Hash};
use std::collections::{HashMap, hash_map};

use lru_slab::LruSlab;

/// A LRU cache'd hash map.
#[derive(Debug)]
pub struct LruCache<K: Hash, V> {
    // The LRU cache over the keys, determining which entries are stale.
    lru: LruSlab<K>,
    /// The map from the key to its slot in the LRU cache and value.
    ///
    /// The slot is stored here so when we look up a value by key, we may mark the slot as recently
    /// used.
    map: HashMap<K, (u32, V)>,
}

impl<K: Clone + Eq + Hash, V> LruCache<K, V> {
    pub fn new(capacity: usize) -> Self {
        /*
          `1 <= actual_capacity <= u16::MAX`

          `LruSlab` has an initialization cost linear to the capacity and will panic at ~2**32, hence
          this bounding.
        */
        let capacity = u16::try_from(capacity).unwrap_or(u16::MAX).max(1);
        Self {
            lru: LruSlab::with_capacity(u32::from(capacity)),
            map: HashMap::with_capacity(usize::from(capacity)),
        }
    }

    /// Get if there are no entries populated within the cache.
    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }

    /// Get the amount of populated entries within the cache.
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Get a value from the cache.
    pub fn get_mut(&mut self, key: &K) -> Option<&mut V> {
        let (slot, value) = self.map.get_mut(key)?;
        // Mark this as recently used within the LRU cache
        let _key = self.lru.get_mut(*slot);
        Some(value)
    }

    /// Insert a value, returning the prior value under this key (if one existed).
    pub fn insert(&mut self, key: K, value: V) -> Option<V> {
        let prior_value_from_removal = if self.lru.len() == self.lru.capacity() {
            let lru = self
                .lru
                .lru()
                .expect("`1 <= actual_capacity`, so this is non-empty");
            let lru_key = self.lru.remove(lru);
            Some(
                self.map
                    .remove(&lru_key)
                    .expect("key present in LRU cache but not in corollary map"),
            )
            .filter(|_| lru_key == key)
        } else {
            None
        };

        let prior_value_from_insert = match self.map.entry(key.clone()) {
            hash_map::Entry::Vacant(entry) => {
                let slot = self.lru.insert(key);
                entry.insert((slot, value));
                None
            }
            hash_map::Entry::Occupied(mut occupied) => {
                let (slot, _existing_value) = occupied.get();
                let _key = self.lru.get_mut(*slot);
                Some(occupied.insert((*slot, value)))
            }
        };

        prior_value_from_removal
            .or(prior_value_from_insert)
            .map(|(_old_slot, old_value)| old_value)
    }

    /// Remove a value, returning it if it was present.
    pub fn remove(&mut self, key: &K) -> Option<V> {
        let (slot, value) = self.map.remove(key)?;
        self.lru.remove(slot);
        Some(value)
    }

    /// Clear the cache.
    pub fn clear(&mut self) {
        for (_key, (slot, _value)) in self.map.drain() {
            self.lru.remove(slot);
        }
    }

    /// Iterate over all values in the cache.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &V)> {
        self.map.iter().map(|(key, (_slot, value))| (key, value))
    }
}
