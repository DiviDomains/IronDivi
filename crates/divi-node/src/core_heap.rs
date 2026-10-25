// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi

//! `std::make_heap`, `std::push_heap` and `std::pop_heap` as the GNU C++
//! library implements them (bits/stl_heap.h: `__adjust_heap`, `__push_heap`,
//! `__pop_heap`). Divi Core keeps its block candidates in such a heap
//! (BlockMemoryPoolTransactionCollector.cpp:276-337); which of several equal
//! candidates comes out first follows from these exact steps, so they are
//! reproduced here rather than any other heap's.
//!
//! `less(a, b)` is the comparator: true when `a` goes after `b`. The greatest
//! element is at index 0.

fn push_hole<T, F: FnMut(&T, &T) -> bool>(
    v: &mut [T],
    mut hole: usize,
    top: usize,
    value: T,
    less: &mut F,
) where
    T: Clone,
{
    let mut parent = hole.wrapping_sub(1) / 2;
    while hole > top && less(&v[parent], &value) {
        v[hole] = v[parent].clone();
        hole = parent;
        parent = hole.wrapping_sub(1) / 2;
    }
    v[hole] = value;
}

fn adjust<T, F: FnMut(&T, &T) -> bool>(
    v: &mut [T],
    mut hole: usize,
    len: usize,
    value: T,
    less: &mut F,
) where
    T: Clone,
{
    let top = hole;
    let mut second = hole;
    while second < (len - 1) / 2 {
        second = 2 * (second + 1);
        if less(&v[second], &v[second - 1]) {
            second -= 1;
        }
        v[hole] = v[second].clone();
        hole = second;
    }
    if len & 1 == 0 && second == (len - 2) / 2 {
        second = 2 * (second + 1);
        v[hole] = v[second - 1].clone();
        hole = second - 1;
    }
    push_hole(v, hole, top, value, less);
}

/// `std::make_heap(v.begin(), v.end(), less)`
pub fn make_heap<T: Clone, F: FnMut(&T, &T) -> bool>(v: &mut [T], mut less: F) {
    let len = v.len();
    if len < 2 {
        return;
    }
    let mut parent = (len - 2) / 2;
    loop {
        let value = v[parent].clone();
        adjust(v, parent, len, value, &mut less);
        if parent == 0 {
            return;
        }
        parent -= 1;
    }
}

/// `std::push_heap(v.begin(), v.end(), less)`: the last element into the heap
pub fn push_heap<T: Clone, F: FnMut(&T, &T) -> bool>(v: &mut [T], mut less: F) {
    let len = v.len();
    if len < 2 {
        return;
    }
    let value = v[len - 1].clone();
    push_hole(v, len - 1, 0, value, &mut less);
}

/// `std::pop_heap(v.begin(), v.end(), less)`: the greatest element moves to
/// the end (the caller then removes it)
pub fn pop_heap<T: Clone, F: FnMut(&T, &T) -> bool>(v: &mut [T], mut less: F) {
    let len = v.len();
    if len < 2 {
        return;
    }
    let last = len - 1;
    let value = v[last].clone();
    v[last] = v[0].clone();
    adjust(&mut v[..last], 0, last, value, &mut less);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn less(a: &(u32, u32), b: &(u32, u32)) -> bool {
        a.0 < b.0
    }

    /// make_heap over `keys` (ids 0..), then pop until empty; after each pop
    /// of an even id the next of `pushed` joins with push_heap (ids after the
    /// first ones), as a block's dependent transactions join Divi Core's heap
    fn run(keys: &[u32], pushed: &[u32]) -> Vec<u32> {
        let mut v: Vec<(u32, u32)> = keys
            .iter()
            .enumerate()
            .map(|(i, &k)| (k, i as u32))
            .collect();
        let mut next = keys.len() as u32;
        let mut extra = pushed.iter();
        make_heap(&mut v, less);
        let mut out = Vec::new();
        while !v.is_empty() {
            let top = v[0];
            out.push(top.1);
            pop_heap(&mut v, less);
            v.pop();
            if top.1.is_multiple_of(2) {
                if let Some(&k) = extra.next() {
                    v.push((k, next));
                    next += 1;
                    push_heap(&mut v, less);
                }
            }
        }
        out
    }

    /// Ten equal keys: libstdc++ (g++ 11.4, bits/stl_heap.h) gives them in
    /// this order from make_heap and pop_heap
    #[test]
    fn equal_keys_come_out_as_libstdcxx_gives_them() {
        assert_eq!(run(&[0; 10], &[]), vec![6, 2, 0, 1, 3, 5, 7, 4, 9, 8])
    }

    /// Keys of 0..3 (many ties) with pushes between the pops: the orders a
    /// libstdc++ heap gives (generated with g++ 11.4 from the same steps)
    #[test]
    fn ties_and_pushes_follow_libstdcxx() {
        let cases: &[(&[u32], &[u32], &[u32])] = &[
            (
                &[1, 2, 2, 0, 3, 0, 3, 3, 3, 3, 2, 0, 1, 2, 0, 3, 1, 3, 1, 1],
                &[1, 3, 3, 3, 1, 3, 3, 3, 0, 0, 0, 3, 2, 0, 1],
                &[
                    6, 9, 4, 17, 8, 15, 21, 7, 22, 23, 13, 2, 10, 25, 1, 0, 26, 27, 12, 19, 20, 24,
                    18, 31, 16, 32, 5, 29, 28, 34, 11, 33, 3, 14, 30,
                ],
            ),
            (
                &[
                    3, 1, 1, 3, 3, 1, 1, 0, 3, 1, 3, 2, 0, 1, 3, 3, 0, 0, 2, 2, 2, 1, 0, 3, 3, 3,
                    2, 2, 1, 3, 1, 1, 0, 3, 1, 1, 2,
                ],
                &[1, 1, 1, 1, 1, 0, 3, 0, 0, 2, 2, 0, 3, 3, 1],
                &[
                    29, 14, 0, 25, 24, 23, 10, 4, 8, 3, 33, 15, 27, 26, 43, 11, 20, 19, 18, 36, 46,
                    47, 30, 28, 49, 38, 50, 5, 6, 40, 37, 51, 35, 2, 39, 21, 1, 9, 41, 31, 13, 34,
                    45, 48, 17, 42, 32, 7, 12, 44, 22, 16,
                ],
            ),
            (
                &[
                    3, 3, 1, 1, 0, 3, 1, 0, 3, 1, 2, 1, 3, 0, 1, 1, 3, 1, 3, 0, 2, 2, 1, 3, 2, 3,
                    0, 3, 2, 1, 3, 1, 3, 3, 2, 1, 2, 1, 2, 3, 0, 0, 3, 2, 2, 1, 0, 0, 3, 3, 1, 2,
                    1, 1,
                ],
                &[1, 2, 2, 2, 1, 0, 3, 0, 3, 2, 1, 1, 2, 3, 0],
                &[
                    30, 27, 0, 25, 12, 5, 49, 48, 23, 42, 39, 1, 18, 8, 33, 16, 60, 32, 62, 28, 51,
                    55, 24, 56, 67, 44, 21, 10, 66, 43, 63, 20, 57, 38, 36, 34, 14, 6, 11, 29, 2,
                    45, 53, 22, 52, 50, 64, 65, 54, 9, 58, 3, 37, 35, 17, 15, 31, 61, 7, 59, 46,
                    26, 4, 68, 13, 47, 19, 41, 40,
                ],
            ),
            (
                &[
                    3, 3, 0, 1, 2, 0, 3, 2, 3, 3, 3, 3, 1, 2, 1, 0, 0, 1, 3, 3, 0, 1, 3, 3, 2, 0,
                    2, 1, 3, 3, 2, 0, 3, 0, 3, 0, 0, 2, 1, 3, 2, 1, 0, 1, 2, 0, 3, 0, 0, 2, 1, 0,
                    3, 0, 1, 3, 3, 3, 0, 0, 2, 2, 2, 1, 1, 1, 3, 3, 0, 2, 1,
                ],
                &[1, 2, 2, 0, 0, 0, 2, 2, 3, 0, 1, 3, 2, 3, 0],
                &[
                    29, 6, 57, 28, 0, 56, 55, 52, 23, 11, 46, 22, 10, 1, 39, 19, 9, 18, 8, 79, 34,
                    67, 66, 32, 82, 84, 62, 30, 72, 83, 61, 60, 13, 26, 49, 24, 73, 4, 44, 40, 77,
                    78, 37, 69, 7, 70, 71, 27, 54, 12, 50, 3, 65, 21, 43, 41, 38, 63, 81, 17, 14,
                    64, 85, 68, 53, 59, 48, 51, 47, 45, 74, 36, 35, 25, 16, 20, 76, 33, 75, 42, 58,
                    5, 2, 31, 15, 80,
                ],
            ),
        ];
        for (keys, pushed, out) in cases {
            assert_eq!(run(keys, pushed), out.to_vec());
        }
    }
}
