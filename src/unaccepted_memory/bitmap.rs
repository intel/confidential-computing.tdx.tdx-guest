// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2026 Intel Corporation.

//! Bitmap data structures for tracking unaccepted memory.

use core::{
    ops::Range,
    sync::atomic::{AtomicU64, Ordering},
};

pub(super) type BitIndex = u64;

/// Bitmap view backed by a slice of [`AtomicU64`].
///
/// Supports lock-free queries with acquire semantics and atomic updates with release semantics.
#[derive(Clone, Copy)]
pub(super) struct BitmapRef<'a> {
    bits: &'a [AtomicU64],
}

impl<'a> BitmapRef<'a> {
    /// Creates a bitmap view from a `u64`-aligned raw pointer.
    ///
    /// # Safety
    ///
    /// - `ptr` must be valid for reads and writes of `len_bytes` initialized
    ///   bytes, aligned to `align_of::<AtomicU64>()`, for lifetime `'a`.
    /// - The memory must not be accessed through any mutable reference or
    ///   non-atomic operation during `'a`.
    pub(super) unsafe fn from_raw(ptr: *const u8, len_bytes: usize) -> Self {
        debug_assert_eq!(len_bytes % core::mem::size_of::<AtomicU64>(), 0);
        let len_words = len_bytes / core::mem::size_of::<AtomicU64>();
        // SAFETY: Caller guarantees alignment, validity, and length constraints.
        let bits = unsafe { core::slice::from_raw_parts(ptr.cast::<AtomicU64>(), len_words) };
        Self { bits }
    }

    /// Returns the total capacity in bits.
    pub(super) const fn capacity(&self) -> u64 {
        (self.bits.len() as u64) * 64
    }

    /// Returns `true` if `bit` is within capacity and set (`1`), using acquire ordering.
    pub(super) fn is_bit_set(&self, bit: BitIndex) -> bool {
        self.bit_word_and_mask(bit)
            .is_some_and(|(word, mask)| word.load(Ordering::Acquire) & mask != 0)
    }

    /// Clears `bit` to `0` using release ordering and returns `true` if it was previously set.
    pub(super) fn clear_bit(&self, bit: BitIndex) -> bool {
        self.bit_word_and_mask(bit)
            .is_some_and(|(word, mask)| word.fetch_and(!mask, Ordering::Release) & mask != 0)
    }

    /// Returns the total number of set bits (`1`s) across the bitmap.
    pub(super) fn count_ones(&self) -> u64 {
        self.bits
            .iter()
            .map(|word| word.load(Ordering::Acquire).count_ones() as u64)
            .sum()
    }

    /// Finds the first set bit (`1`) in `range`.
    pub(super) fn find_next_set(&self, range: Range<BitIndex>) -> Option<BitIndex> {
        for (word_idx, mask) in self.word_masks(range) {
            let match_bits = self.bits[word_idx].load(Ordering::Acquire) & mask;
            if match_bits != 0 {
                return Some((word_idx * 64 + match_bits.trailing_zeros() as usize) as u64);
            }
        }

        None
    }

    /// Sets all bits in `range` to `1`.
    pub(super) fn set_range(&self, range: Range<BitIndex>) {
        for (word_idx, mask) in self.word_masks(range) {
            self.bits[word_idx].fetch_or(mask, Ordering::Release);
        }
    }

    fn bit_word_and_mask(&self, bit: BitIndex) -> Option<(&AtomicU64, u64)> {
        let word_idx = usize::try_from(bit / 64).ok()?;
        let word = self.bits.get(word_idx)?;
        Some((word, 1u64 << (bit % 64)))
    }

    fn word_masks(&self, range: Range<BitIndex>) -> impl Iterator<Item = (usize, u64)> {
        let end = range.end.min(self.capacity()) as usize;
        let start = (range.start as usize).min(end);
        let word_range = if start < end {
            (start / 64)..end.div_ceil(64)
        } else {
            0..0
        };

        word_range.map(move |word_idx| {
            let word_bit_start = word_idx * 64;
            let lo = start.saturating_sub(word_bit_start);
            let hi = end.min(word_bit_start + 64) - word_bit_start;
            let mask = (!0u64 >> (64 - (hi - lo))) << lo;
            (word_idx, mask)
        })
    }
}
