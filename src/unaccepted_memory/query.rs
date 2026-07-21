// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2026 Intel Corporation.

//! Read-only query APIs for unaccepted-memory status.
//!
//! This file implements pending-state checks over GPA ranges using either
//! non-atomic bitmap reads or advisory atomic-word reads.

use super::{bitmap::BitmapRef, EfiUnacceptedMemory, MemoryStatus};
use crate::AcceptError;

impl EfiUnacceptedMemory {
    /// Returns the number of pending (set) bitmap units in the whole table.
    ///
    /// # Safety
    ///
    /// The caller must ensure this header is followed by at least
    /// `self.bitmap_size_bytes` readable bytes (valid trailing bitmap payload).
    pub unsafe fn pending_unit_count(&self) -> Result<u64, AcceptError> {
        // SAFETY: Caller guarantees trailing bitmap is valid and readable.
        let bitmap = unsafe { self.as_bitmap_slice()? };
        Ok(bitmap.iter().map(|byte| u64::from(byte.count_ones())).sum())
    }

    /// Checks whether `(start, size)` overlaps any pending bitmap unit.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - This header is followed by at least `self.bitmap_size_bytes` readable bytes
    ///   (i.e., the trailing bitmap payload exists in valid memory).
    /// - No concurrent mutation of overlapping bitmap bytes is in progress.
    pub unsafe fn check_range_status_by_size(
        &self,
        start: u64,
        size: u64,
    ) -> Result<MemoryStatus, AcceptError> {
        let Some(end) = start.checked_add(size) else {
            return Err(AcceptError::ArithmeticOverflow);
        };

        // SAFETY: Caller guarantees trailing bitmap validity and no concurrent mutation.
        unsafe { self.check_range_status(start, end) }
    }

    /// Checks whether `[start, end)` overlaps any pending bitmap unit.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - This header is followed by at least `self.bitmap_size_bytes` readable bytes
    ///   (i.e., the trailing bitmap payload exists in valid memory).
    /// - No concurrent mutation of overlapping bitmap bytes is in progress.
    ///
    /// In concurrent accept paths, use [`Self::is_range_pending`] instead.
    pub unsafe fn check_range_status(
        &self,
        start: u64,
        end: u64,
    ) -> Result<MemoryStatus, AcceptError> {
        let Some((first_bit, last_bit, _unit_size)) = self.overlapping_bit_range(start, end)?
        else {
            return Ok(MemoryStatus::AllAccepted);
        };

        // SAFETY: Caller guarantees trailing bitmap is valid and readable.
        let bitmap = unsafe { self.as_bitmap_slice()? };
        let has_pending = BitmapRef::new(bitmap).has_set_bit(first_bit, last_bit)?;
        Ok(if has_pending {
            MemoryStatus::HasPending
        } else {
            MemoryStatus::AllAccepted
        })
    }

    /// Lock-free advisory query: checks whether `[start, end)` overlaps any
    /// pending (unaccepted) bitmap unit.
    ///
    /// Unlike [`Self::check_range_status`], this method reads the bitmap
    /// through `AtomicU64` loads. The query is advisory — a stale `false` is
    /// possible if another CPU is mid-accept.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - This header is followed by at least `self.bitmap_size_bytes` bytes of
    ///   valid memory (the trailing bitmap payload).
    /// - The bitmap payload is `u64`-aligned.
    /// - Any overlapping concurrent access to the bitmap uses atomic word
    ///   operations. Mixing this API with non-atomic bitmap writers in the
    ///   `BitmapMut` path (byte writes)
    ///   is undefined behavior.
    pub unsafe fn is_range_pending(&self, start: u64, end: u64) -> Result<bool, AcceptError> {
        let Some((first_bit, last_bit, _unit_size)) = self.overlapping_bit_range(start, end)?
        else {
            return Ok(false);
        };

        // SAFETY: Caller guarantees trailing bitmap is valid and u64-aligned.
        let atomic_bitmap = unsafe { self.atomic_bitmap_ref()? };

        atomic_bitmap.has_set_bit(first_bit, last_bit)
    }
}
