// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2026 Intel Corporation.

//! Bitmap data structures for tracking unaccepted memory.
//!
//! This module provides four bitmap views with different ownership and
//! synchronization semantics:
//!
//! - [`BitmapMut`] — mutable view backed by `&mut [u8]`, used by the
//!   exclusive (`&mut self`) acceptance and registration paths.
//! - [`BitmapRef`] — read-only view backed by `&[u8]`, used for pending
//!   queries without requiring mutable access. Requires external
//!   synchronization against concurrent writes.
//! - [`AtomicBitmapRef`] — read-only view that reads bitmap words via
//!   `AtomicU64` loads.
//! - [`AtomicBitmapMut`] — atomic writer view that updates bitmap words via
//!   `fetch_or`/`fetch_and`, suitable for lock-free reads by
//!   [`AtomicBitmapRef`].
//!
//! `BitmapMut` and `AtomicBitmapMut` cover non-atomic/atomic writer paths,
//! while `BitmapRef` and `AtomicBitmapRef` cover the corresponding reader
//! paths. `AtomicBitmapMut` is the atomic writer
//! counterpart used when lock-free atomic readers may run concurrently.

use core::sync::atomic::{AtomicU64, Ordering};

use crate::AcceptError;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct BitIndex(u64);

impl BitIndex {
    pub(super) const fn new(raw: u64) -> Self {
        Self(raw)
    }

    pub(super) const fn raw(self) -> u64 {
        self.0
    }
}

/// Mutable bitmap view used by registration/acceptance paths.
///
/// This helper is intentionally non-atomic; callers must provide external
/// synchronization when multiple CPUs could touch the same bitmap.
pub(super) struct BitmapMut<'a> {
    bits: &'a mut [u8],
}

impl<'a> BitmapMut<'a> {
    pub(super) fn new(bits: &'a mut [u8]) -> Self {
        Self { bits }
    }

    fn byte_len(&self) -> usize {
        self.bits.len()
    }

    fn get_byte(&self, index: usize) -> Result<u8, AcceptError> {
        self.bits
            .get(index)
            .copied()
            .ok_or(AcceptError::OutOfBounds)
    }

    fn put_byte(&mut self, index: usize, value: u8) -> Result<(), AcceptError> {
        *self.bits.get_mut(index).ok_or(AcceptError::OutOfBounds)? = value;
        Ok(())
    }

    fn as_raw_ptr(&self) -> *const u8 {
        self.bits.as_ptr()
    }

    fn capacity(&self) -> Result<u64, AcceptError> {
        let len = u64::try_from(self.byte_len()).map_err(|_| AcceptError::OutOfBounds)?;
        len.checked_mul(8).ok_or(AcceptError::ArithmeticOverflow)
    }

    fn get_pos_mask(&self, bit_index: BitIndex) -> Result<(usize, u8), AcceptError> {
        if bit_index.raw() >= self.capacity()? {
            return Err(AcceptError::OutOfBounds);
        }
        let byte_index =
            usize::try_from(bit_index.raw() >> 3).map_err(|_| AcceptError::OutOfBounds)?;
        let mask = 1u8 << (bit_index.raw() & 7);
        Ok((byte_index, mask))
    }

    fn is_set(&self, bit_index: BitIndex) -> Result<bool, AcceptError> {
        let (byte_index, mask) = self.get_pos_mask(bit_index)?;
        Ok((self.get_byte(byte_index)? & mask) != 0)
    }

    pub(super) fn find_next_set(
        &self,
        start_bit: BitIndex,
        end_bit: BitIndex,
    ) -> Result<Option<BitIndex>, AcceptError> {
        self.find_next_matching(start_bit, end_bit, true)
    }

    pub(super) fn find_next_zero(
        &self,
        start_bit: BitIndex,
        end_bit: BitIndex,
    ) -> Result<Option<BitIndex>, AcceptError> {
        self.find_next_matching(start_bit, end_bit, false)
    }

    fn find_next_matching(
        &self,
        start_bit: BitIndex,
        end_bit: BitIndex,
        target: bool,
    ) -> Result<Option<BitIndex>, AcceptError> {
        let bit_len = self.capacity()?;
        if start_bit.raw() > end_bit.raw() || end_bit.raw() > bit_len {
            return Err(AcceptError::OutOfBounds);
        }
        if start_bit == end_bit {
            return Ok(None);
        }

        let mut scan_bit = start_bit.raw();
        let end_bit_raw = end_bit.raw();

        // Scan leading bits until the index is 64-bit aligned.
        while scan_bit < end_bit_raw && (scan_bit & 63) != 0 {
            if self.is_set(BitIndex::new(scan_bit))? == target {
                return Ok(Some(BitIndex::new(scan_bit)));
            }
            scan_bit += 1;
        }

        // Bulk scan by 64-bit words, then use trailing_zeros for first matching bit.
        while end_bit_raw - scan_bit >= 64 {
            let next = scan_bit + 64;
            let byte_index =
                usize::try_from(scan_bit >> 3).map_err(|_| AcceptError::OutOfBounds)?;

            // SAFETY: Loop condition `end_bit_raw - scan_bit >= 64` guarantees
            // `byte_index + 8 <= byte_len()`. The pointer from `as_raw_ptr()`
            // is valid for at least `byte_len()` bytes per the trait contract.
            let word = unsafe {
                let ptr = self.as_raw_ptr().add(byte_index).cast::<u64>();
                u64::from_le(ptr.read_unaligned())
            };

            let match_word = if target { word } else { !word };
            if match_word != 0 {
                let delta = u64::from(match_word.trailing_zeros());
                let found = scan_bit + delta;
                return Ok(Some(BitIndex::new(found)));
            }

            scan_bit = next;
        }

        // Scan remaining tail bits (< 64).
        while scan_bit < end_bit_raw {
            if self.is_set(BitIndex::new(scan_bit))? == target {
                return Ok(Some(BitIndex::new(scan_bit)));
            }
            scan_bit += 1;
        }

        Ok(None)
    }

    pub(super) fn clear_range(
        &mut self,
        start_bit: BitIndex,
        end_bit: BitIndex,
    ) -> Result<(), AcceptError> {
        self.update_range(start_bit, end_bit, false)
    }

    /// Sets all bits in `[start_bit, end_bit)` to `1`.
    pub(super) fn set_range(
        &mut self,
        start_bit: BitIndex,
        end_bit: BitIndex,
    ) -> Result<(), AcceptError> {
        self.update_range(start_bit, end_bit, true)
    }

    fn update_range(
        &mut self,
        start_bit: BitIndex,
        end_bit: BitIndex,
        set_bits: bool,
    ) -> Result<(), AcceptError> {
        let bit_len = self.capacity()?;
        if start_bit.raw() > end_bit.raw() || end_bit.raw() > bit_len {
            return Err(AcceptError::OutOfBounds);
        }
        if start_bit == end_bit {
            return Ok(());
        }

        let (start_byte, end_exclusive_byte, start_off, end_off) =
            byte_range_params(start_bit, end_bit)?;

        if start_byte + 1 == end_exclusive_byte {
            let end_off_eff = if end_off == 0 { 8 } else { end_off };
            let range_mask = bit_range_mask(start_off, end_off_eff);
            let val = self.get_byte(start_byte)?;
            let new_val = if set_bits {
                val | range_mask
            } else {
                val & !range_mask
            };
            self.put_byte(start_byte, new_val)?;
            return Ok(());
        }

        // Leading partial byte.
        if start_off != 0 {
            let head_mask = !low_bits_mask(start_off);
            let val = self.get_byte(start_byte)?;
            let new_val = if set_bits {
                val | head_mask
            } else {
                val & !head_mask
            };
            self.put_byte(start_byte, new_val)?;
        } else {
            self.put_byte(start_byte, if set_bits { 0xFF } else { 0 })?;
        }

        // Middle full bytes — single bounds check + memset.
        let middle_start = start_byte + 1;
        let middle_end = if end_off == 0 {
            end_exclusive_byte
        } else {
            end_exclusive_byte - 1
        };
        let fill_val = if set_bits { 0xFF } else { 0 };
        self.bits
            .get_mut(middle_start..middle_end)
            .ok_or(AcceptError::OutOfBounds)?
            .fill(fill_val);

        // Trailing partial byte.
        if end_off != 0 {
            let tail_mask = low_bits_mask(end_off);
            let last = end_exclusive_byte - 1;
            let val = self.get_byte(last)?;
            let new_val = if set_bits {
                val | tail_mask
            } else {
                val & !tail_mask
            };
            self.put_byte(last, new_val)?;
        }

        Ok(())
    }
}

/// Read-only bitmap view for pending-state queries.
pub(super) struct BitmapRef<'a> {
    bits: &'a [u8],
}

impl<'a> BitmapRef<'a> {
    pub(super) fn new(bits: &'a [u8]) -> Self {
        Self { bits }
    }

    pub(super) fn has_set_bit(
        &self,
        start_bit: BitIndex,
        end_bit: BitIndex,
    ) -> Result<bool, AcceptError> {
        let total_bits = self
            .bits
            .len()
            .checked_mul(8)
            .ok_or(AcceptError::ArithmeticOverflow)?;
        let start = usize::try_from(start_bit.raw()).map_err(|_| AcceptError::OutOfBounds)?;
        let end = usize::try_from(end_bit.raw()).map_err(|_| AcceptError::OutOfBounds)?;

        has_set_bit_with_word_loader(start, end, total_bits, |word_idx| {
            let byte_index = word_idx * 8;
            if byte_index + 8 <= self.bits.len() {
                // SAFETY: Bounds checked above; 8 readable bytes are available.
                unsafe {
                    let ptr = self.bits.as_ptr().add(byte_index).cast::<u64>();
                    u64::from_le(ptr.read_unaligned())
                }
            } else {
                // Tail path for non-8-byte-aligned bitmaps: zero-extend remaining bytes.
                let mut word = 0u64;
                let remaining = self.bits.len().saturating_sub(byte_index);
                for offset in 0..remaining {
                    word |= u64::from(self.bits[byte_index + offset]) << (offset * 8);
                }
                word
            }
        })
    }
}

fn low_bits_mask(count: u8) -> u8 {
    debug_assert!(count <= 8);
    if count == 0 {
        0
    } else {
        u8::MAX >> (8 - count)
    }
}

fn bit_range_mask(start_off: u8, end_off: u8) -> u8 {
    debug_assert!(start_off <= end_off && end_off <= 8);
    if start_off == end_off {
        return 0;
    }

    let width = end_off - start_off;
    low_bits_mask(width) << start_off
}

/// Computes the byte-level parameters shared by `clear_range` / `set_range`.
///
/// Returns `(start_byte, end_exclusive_byte, start_off, end_off)`.
fn byte_range_params(
    start_bit: BitIndex,
    end_bit: BitIndex,
) -> Result<(usize, usize, u8, u8), AcceptError> {
    let start_byte = usize::try_from(start_bit.raw() >> 3).map_err(|_| AcceptError::OutOfBounds)?;
    let end_exclusive_byte = usize::try_from(
        end_bit
            .raw()
            .checked_add(7)
            .ok_or(AcceptError::ArithmeticOverflow)?
            >> 3,
    )
    .map_err(|_| AcceptError::OutOfBounds)?;
    let start_off = u8::try_from(start_bit.raw() & 7).map_err(|_| AcceptError::OutOfBounds)?;
    let end_off = u8::try_from(end_bit.raw() & 7).map_err(|_| AcceptError::OutOfBounds)?;
    Ok((start_byte, end_exclusive_byte, start_off, end_off))
}

/// Lock-free, read-only bitmap view for concurrent pending-state queries.
///
/// Unlike [`BitmapRef`], this type reads bitmap words via [`AtomicU64`] loads,
/// but this is data-race-free only if overlapping concurrent writers also use
/// atomic word updates on the same backing memory. `Relaxed` ordering suffices
/// for advisory queries where no happens-before relationship is required.
///
/// # Safety invariants (established at construction)
///
/// - The backing memory must be at least `len_words * 8` bytes, starting at a
///   `u64`-aligned address that can be legally viewed as `&[AtomicU64]`.
/// - The memory must remain valid for the lifetime `'a`.
pub(super) struct AtomicBitmapRef<'a> {
    words: &'a [AtomicU64],
}

impl<'a> AtomicBitmapRef<'a> {
    /// Creates an atomic bitmap view from a `u64`-aligned raw pointer.
    ///
    /// # Safety
    ///
    /// - `ptr` must be non-null and aligned to `align_of::<AtomicU64>()`.
    /// - `ptr` must point to at least `len_bytes` bytes of valid memory.
    /// - The memory must remain valid and not deallocated for lifetime `'a`.
    /// - Any overlapping concurrent access to the backing memory must also use
    ///   atomic word operations. Mixing these atomic loads with non-atomic
    ///   reads/writes of the same memory is undefined behavior.
    pub(super) unsafe fn from_raw(ptr: *const u8, len_bytes: usize) -> Self {
        debug_assert_eq!(len_bytes % core::mem::size_of::<AtomicU64>(), 0);
        let len_words = len_bytes / core::mem::size_of::<AtomicU64>();
        // SAFETY: Caller guarantees alignment and validity.
        let words = unsafe { core::slice::from_raw_parts(ptr.cast::<AtomicU64>(), len_words) };
        Self { words }
    }

    /// Returns `true` if any bit in `[start_bit, end_bit)` is set.
    ///
    /// Each word is loaded with `Relaxed` ordering — sufficient for advisory
    /// queries that tolerate stale or partially-updated results.
    pub(super) fn has_set_bit(
        &self,
        start_bit: BitIndex,
        end_bit: BitIndex,
    ) -> Result<bool, AcceptError> {
        let total_bits = self
            .words
            .len()
            .checked_mul(64)
            .ok_or(AcceptError::ArithmeticOverflow)?;
        let start = usize::try_from(start_bit.raw()).map_err(|_| AcceptError::OutOfBounds)?;
        let end = usize::try_from(end_bit.raw()).map_err(|_| AcceptError::OutOfBounds)?;

        has_set_bit_with_word_loader(start, end, total_bits, |word_idx| {
            self.words[word_idx].load(Ordering::Relaxed)
        })
    }
}

/// Atomic writer bitmap view for concurrent mutation.
///
/// All updates use `AtomicU64` RMW operations (`fetch_or` / `fetch_and`), so
/// readers using [`AtomicBitmapRef`] can load concurrently without mixing
/// atomic and non-atomic accesses on the same memory.
pub(super) struct AtomicBitmapMut<'a> {
    words: &'a [AtomicU64],
}

impl<'a> AtomicBitmapMut<'a> {
    /// Creates an atomic mutable bitmap view from a `u64`-aligned raw pointer.
    ///
    /// # Safety
    ///
    /// - `ptr` must be non-null and aligned to `align_of::<AtomicU64>()`.
    /// - `ptr` must point to at least `len_bytes` bytes of valid writable memory.
    /// - `len_bytes` must be a multiple of `size_of::<AtomicU64>()`.
    /// - The memory must remain valid and not deallocated for lifetime `'a`.
    /// - Any overlapping concurrent access to this memory must use atomic word
    ///   operations.
    pub(super) unsafe fn from_raw(ptr: *mut u8, len_bytes: usize) -> Self {
        debug_assert_eq!(len_bytes % core::mem::size_of::<AtomicU64>(), 0);
        let len_words = len_bytes / core::mem::size_of::<AtomicU64>();
        // SAFETY: Caller guarantees alignment, validity, and lifetime.
        let words = unsafe { core::slice::from_raw_parts(ptr.cast::<AtomicU64>(), len_words) };
        Self { words }
    }

    pub(super) fn find_next_set(
        &self,
        start_bit: BitIndex,
        end_bit: BitIndex,
    ) -> Result<Option<BitIndex>, AcceptError> {
        self.find_next_matching(start_bit, end_bit, true)
    }

    pub(super) fn find_next_zero(
        &self,
        start_bit: BitIndex,
        end_bit: BitIndex,
    ) -> Result<Option<BitIndex>, AcceptError> {
        self.find_next_matching(start_bit, end_bit, false)
    }

    pub(super) fn set_range(
        &self,
        start_bit: BitIndex,
        end_bit: BitIndex,
    ) -> Result<(), AcceptError> {
        self.update_range(start_bit, end_bit, true)
    }

    pub(super) fn clear_range(
        &self,
        start_bit: BitIndex,
        end_bit: BitIndex,
    ) -> Result<(), AcceptError> {
        self.update_range(start_bit, end_bit, false)
    }

    fn capacity_bits(&self) -> Result<u64, AcceptError> {
        let word_len = u64::try_from(self.words.len()).map_err(|_| AcceptError::OutOfBounds)?;
        word_len
            .checked_mul(64)
            .ok_or(AcceptError::ArithmeticOverflow)
    }

    fn validate_range(
        &self,
        start_bit: BitIndex,
        end_bit: BitIndex,
    ) -> Result<(usize, usize), AcceptError> {
        let bit_len = self.capacity_bits()?;
        if start_bit.raw() > end_bit.raw() || end_bit.raw() > bit_len {
            return Err(AcceptError::OutOfBounds);
        }

        let start = usize::try_from(start_bit.raw()).map_err(|_| AcceptError::OutOfBounds)?;
        let end = usize::try_from(end_bit.raw()).map_err(|_| AcceptError::OutOfBounds)?;
        Ok((start, end))
    }

    fn find_next_matching(
        &self,
        start_bit: BitIndex,
        end_bit: BitIndex,
        target: bool,
    ) -> Result<Option<BitIndex>, AcceptError> {
        let (start, end) = self.validate_range(start_bit, end_bit)?;
        if start >= end {
            return Ok(None);
        }

        let start_word = start / 64;
        let end_word = (end - 1) / 64;

        for word_idx in start_word..=end_word {
            let word_bit_start = word_idx * 64;
            let lo = start.saturating_sub(word_bit_start);
            let hi = end.min(word_bit_start + 64) - word_bit_start;
            let mask = word_range_mask(lo, hi);

            let word = self.words[word_idx].load(Ordering::Relaxed);
            let match_bits = (if target { word } else { !word }) & mask;
            if match_bits != 0 {
                let delta = usize::try_from(match_bits.trailing_zeros())
                    .map_err(|_| AcceptError::OutOfBounds)?;
                let found = word_bit_start + delta;
                let found_u64 = u64::try_from(found).map_err(|_| AcceptError::OutOfBounds)?;
                return Ok(Some(BitIndex::new(found_u64)));
            }
        }

        Ok(None)
    }

    fn update_range(
        &self,
        start_bit: BitIndex,
        end_bit: BitIndex,
        set_bits: bool,
    ) -> Result<(), AcceptError> {
        let (start, end) = self.validate_range(start_bit, end_bit)?;
        if start >= end {
            return Ok(());
        }

        let start_word = start / 64;
        let end_word = (end - 1) / 64;

        for word_idx in start_word..=end_word {
            let word_bit_start = word_idx * 64;
            let lo = start.saturating_sub(word_bit_start);
            let hi = end.min(word_bit_start + 64) - word_bit_start;
            let mask = word_range_mask(lo, hi);

            if set_bits {
                self.words[word_idx].fetch_or(mask, Ordering::Relaxed);
            } else {
                self.words[word_idx].fetch_and(!mask, Ordering::Relaxed);
            }
        }

        Ok(())
    }
}

fn has_set_bit_with_word_loader(
    start: usize,
    end: usize,
    total_bits: usize,
    mut load_word_fn: impl FnMut(usize) -> u64,
) -> Result<bool, AcceptError> {
    if start >= end {
        return Ok(false);
    }
    if end > total_bits {
        return Err(AcceptError::OutOfBounds);
    }

    let start_word = start / 64;
    let end_word = (end - 1) / 64;

    for word_idx in start_word..=end_word {
        let word_bit_start = word_idx * 64;
        let lo = start.saturating_sub(word_bit_start);
        let hi = end.min(word_bit_start + 64) - word_bit_start;
        let mask = word_range_mask(lo, hi);
        if load_word_fn(word_idx) & mask != 0 {
            return Ok(true);
        }
    }

    Ok(false)
}

fn word_range_mask(lo: usize, hi: usize) -> u64 {
    debug_assert!(lo < hi && hi <= 64);
    if hi == 64 {
        !0u64 << lo
    } else {
        ((!0u64) >> (64 - hi)) & ((!0u64) << lo)
    }
}
