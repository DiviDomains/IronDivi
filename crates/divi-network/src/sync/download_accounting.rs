use super::{Hash256, PeerId};
use std::collections::{HashMap, HashSet, VecDeque};

pub(super) struct Entry<T> {
    pub owner: PeerId,
    pub bytes: usize,
    pub value: T,
}

/// Charge the original owner until removal, not the current retry destination.
pub(super) struct Store<T> {
    entries: HashMap<Hash256, Entry<T>>,
    owners: HashMap<PeerId, (usize, usize)>,
    bytes: usize,
    global: (usize, usize),
    peer: (usize, usize),
}

impl<T> Store<T> {
    pub fn new(global: (usize, usize), peer: (usize, usize)) -> Self {
        Self {
            entries: HashMap::new(),
            owners: HashMap::new(),
            bytes: 0,
            global,
            peer,
        }
    }

    pub fn peer_fits(&self, owner: PeerId, bytes: usize) -> bool {
        let (n, used) = self.owners.get(&owner).copied().unwrap_or_default();
        n < self.peer.0 && bytes <= self.peer.1 - used
    }
    fn fits(&self, owner: PeerId, bytes: usize) -> bool {
        self.peer_fits(owner, bytes)
            && self.len() < self.global.0
            && bytes <= self.global.1 - self.bytes
    }

    pub fn insert(&mut self, key: Hash256, owner: PeerId, bytes: usize, value: T) -> bool {
        if self.contains_key(&key) || !self.fits(owner, bytes) {
            return false;
        }
        let used = self.owners.entry(owner).or_default();
        used.0 += 1;
        used.1 += bytes;
        self.bytes += bytes;
        self.entries.insert(
            key,
            Entry {
                owner,
                bytes,
                value,
            },
        );
        true
    }

    pub fn remove(&mut self, key: &Hash256) -> Option<Entry<T>> {
        let entry = self.entries.remove(key)?;
        let used = self.owners.get_mut(&entry.owner).expect("registered owner");
        used.0 -= 1;
        used.1 -= entry.bytes;
        if used.0 == 0 {
            self.owners.remove(&entry.owner);
        }
        self.bytes -= entry.bytes;
        Some(entry)
    }

    pub fn get(&self, key: &Hash256) -> Option<&T> {
        self.entries.get(key).map(|e| &e.value)
    }
    pub fn copy_one(&self, key: &Hash256) -> Option<(PeerId, T)>
    where
        T: Clone,
    {
        self.entries.get(key).map(|e| (e.owner, e.value.clone()))
    }
    /// Only a block that can advance validation now may displace waiting data.
    /// Free the producer's quota first; never evict for an impossible insertion.
    pub fn make_room(&mut self, owner: PeerId, bytes: usize) -> bool {
        if self.fits(owner, bytes) || bytes > self.peer.1.min(self.global.1) {
            return false;
        }
        let (own, other): (Vec<_>, Vec<_>) = self
            .entries
            .keys()
            .copied()
            .partition(|k| self.entries[k].owner == owner);
        let mut removed = false;
        for key in own.into_iter().chain(other) {
            self.remove(&key);
            removed = true;
            if self.fits(owner, bytes) {
                break;
            }
        }
        removed
    }
    pub fn get_mut(&mut self, key: &Hash256) -> Option<&mut T> {
        self.entries.get_mut(key).map(|e| &mut e.value)
    }
    pub fn iter(&self) -> impl Iterator<Item = (&Hash256, &T)> {
        self.entries.iter().map(|(k, e)| (k, &e.value))
    }
    pub fn owned(&self) -> impl Iterator<Item = (&Hash256, PeerId, &T)> {
        self.entries.iter().map(|(k, e)| (k, e.owner, &e.value))
    }
    pub fn keys(&self) -> impl Iterator<Item = &Hash256> {
        self.entries.keys()
    }
    pub fn values(&self) -> impl Iterator<Item = &T> {
        self.entries.values().map(|e| &e.value)
    }
    pub fn contains_key(&self, key: &Hash256) -> bool {
        self.entries.contains_key(key)
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn retain(&mut self, mut keep: impl FnMut(&Hash256, &T) -> bool) {
        let remove: Vec<_> = self
            .iter()
            .filter_map(|(k, v)| (!keep(k, v)).then_some(*k))
            .collect();
        for key in remove {
            self.remove(&key);
        }
    }
}

#[cfg(test)]
impl<T> std::ops::Index<&Hash256> for Store<T> {
    type Output = T;
    fn index(&self, key: &Hash256) -> &Self::Output {
        self.get(key).unwrap()
    }
}

#[derive(Default)]
pub(super) struct Queue {
    fifo: VecDeque<(Hash256, PeerId)>,
    members: HashSet<Hash256>,
}

impl Queue {
    pub fn push_back(&mut self, item: (Hash256, PeerId)) {
        if self.members.insert(item.0) {
            self.fifo.push_back(item);
        }
    }
    pub fn push_front(&mut self, item: (Hash256, PeerId)) {
        if self.members.insert(item.0) {
            self.fifo.push_front(item);
        }
    }
    pub fn pop_front(&mut self) -> Option<(Hash256, PeerId)> {
        let item = self.fifo.pop_front()?;
        self.members.remove(&item.0);
        Some(item)
    }
    pub fn remove(&mut self, hash: &Hash256) {
        if self.members.remove(hash) {
            self.fifo.retain(|(h, _)| h != hash);
        }
    }
    pub fn reassign(&mut self, from: PeerId, to: PeerId) {
        for (_, peer) in &mut self.fifo {
            if *peer == from {
                *peer = to;
            }
        }
    }
    pub fn contains(&self, hash: &Hash256) -> bool {
        self.members.contains(hash)
    }
    pub fn len(&self) -> usize {
        self.fifo.len()
    }
    pub fn is_empty(&self) -> bool {
        self.fifo.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn h(i: u8) -> Hash256 {
        Hash256::from_bytes([i; 32])
    }

    #[test]
    fn fixed_entries_obey_both_byte_budgets_and_return_credit() {
        let mut cache = Store::new((8, 12), (5, 8));
        let entry = [0u8; 4];
        assert!(cache.insert(h(1), 1, entry.len(), entry));
        assert!(cache.insert(h(2), 1, entry.len(), entry));
        assert!(!cache.insert(h(3), 1, entry.len(), entry));
        assert!(!cache.insert(h(1), 2, entry.len(), entry));
        assert!(cache.insert(h(3), 2, entry.len(), entry));
        assert!(!cache.insert(h(4), 3, entry.len(), entry));
        cache.retain(|key, _| *key == h(3));
        assert!(!cache.owners.contains_key(&1));
        assert!(cache.insert(h(4), 1, entry.len(), entry));
        assert_eq!(cache.bytes, 8);
    }

    #[test]
    fn next_block_can_advance_at_item_limit_without_evicting_for_oversize() {
        let mut cache = Store::new((3, 64), (2, 32));
        for (i, owner) in [(1, 1), (2, 1), (3, 2)] {
            assert!(cache.insert(h(i), owner, 4, [0u8; 4]));
        }
        assert!(!cache.insert(h(4), 1, 4, [0; 4]));
        assert!(!cache.make_room(1, 33));
        assert_eq!(cache.len(), 3);
        assert!(cache.make_room(1, 4));
        assert!(cache.contains_key(&h(3)));
        assert!(cache.insert(h(4), 1, 4, [0; 4]));
        let moved = cache.remove(&h(4)).unwrap();
        let mut orphans = Store::new((1, 4), (1, 4));
        assert!(orphans.insert(h(4), moved.owner, moved.bytes, moved.value));
        assert!(cache.insert(h(5), 1, 4, [0; 4]));
        assert_eq!(orphans.remove(&h(4)).unwrap().owner, 1);
        assert!(orphans.owners.is_empty());
    }

    #[test]
    fn retry_keeps_charge_and_fifo_position_across_reassignment() {
        let mut queue = Queue::default();
        let mut tracked = Store::new((3, 96), (2, 64));
        for (i, peer) in [(1, 7), (2, 7), (3, 8)] {
            assert!(tracked.insert(h(i), peer, 32, ()));
            queue.push_back((h(i), peer));
        }
        queue.reassign(7, 8);
        let first = queue.pop_front().unwrap();
        queue.push_back((h(2), 8));
        queue.push_front(first);
        assert!(!tracked.insert(h(4), 7, 32, ()));
        for i in 1..=3 {
            assert!(queue.contains(&h(i)));
            assert_eq!(queue.pop_front(), Some((h(i), 8)));
            tracked.remove(&h(i));
        }
        assert!(queue.is_empty() && tracked.is_empty());
        assert!(tracked.insert(h(4), 7, 32, ()));
    }
}
