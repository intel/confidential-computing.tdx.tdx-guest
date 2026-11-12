// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2026 Intel Corporation.

//! Acceptance-path operations for unaccepted-memory bitmap ranges.
//!
//! This file contains range acceptance flows and synchronized on-demand
//! acceptance state management.

use core::ops::Range;

use spin::Mutex;

use super::EfiUnacceptedMemory;
use crate::{accept_memory, AcceptError};

pub(super) const SHARD_COUNT: usize = 64;

impl EfiUnacceptedMemory {
    /// Returns the number of unaccepted memory bytes remaining in this table.
    pub fn unaccepted_bytes(&self) -> usize {
        (self.bitmap_ref().count_ones() * u64::from(self.unit_size_bytes())) as usize
    }

    /// Accepts all pending memory units in this table that overlap `range`.
    ///
    /// `disable_local_irq` must disable local interrupts for the lifetime of its
    /// returned guard and restore the previous interrupt state when the guard is
    /// dropped, preventing interrupt-handler deadlocks on shard locks.
    ///
    /// # Errors
    ///
    /// Returns an error if TDX memory acceptance fails for any pending unit.
    /// Units accepted earlier in the same call remain accepted and cleared in the
    /// bitmap.
    pub fn ensure_accepted<G>(
        &self,
        range: Range<u64>,
        disable_local_irq: impl Fn() -> G,
    ) -> Result<(), AcceptError> {
        self.ensure_accepted_with(range, disable_local_irq, |unit| {
            // SAFETY: By `Self`'s type invariants, every pending unit in the table
            // is unused guest-private memory, and the shard lock serializes
            // acceptance of `unit`.
            unsafe { accept_memory(unit.start, unit.end) }
        })
    }

    pub(super) fn ensure_accepted_with<G>(
        &self,
        range: Range<u64>,
        disable_local_irq: impl Fn() -> G,
        mut accept_unit: impl FnMut(Range<u64>) -> Result<(), AcceptError>,
    ) -> Result<(), AcceptError> {
        let Some(bit_range) = self.overlapping_bit_range(range) else {
            return Ok(());
        };

        let bitmap = self.bitmap_ref();
        let mut next_bit = bit_range.start;
        while let Some(unit_bit) = bitmap.find_next_set(next_bit..bit_range.end) {
            next_bit = unit_bit + 1;
            let shard_index = (unit_bit as usize) % SHARD_COUNT;
            let _irq_guard = disable_local_irq();
            // Reverse drop order releases the lock before restoring IRQs, even on errors.
            let _shard_guard = SHARD_LOCKS[shard_index].lock();

            if !bitmap.is_bit_set(unit_bit) {
                continue;
            }

            accept_unit(self.unit_range(unit_bit))?;
            bitmap.clear_bit(unit_bit);
        }

        Ok(())
    }
}

/// Shard spinlocks indexed by `unit_bit % SHARD_COUNT` to serialize concurrent
/// acceptance of the same bitmap unit.
///
/// Because [`EfiUnacceptedMemory`] has a fixed `#[repr(C)]` ABI layout followed
/// immediately by its trailing bitmap, locks cannot be embedded in the table and
/// are shared across all [`EfiUnacceptedMemory`] instances in the address space.
pub(super) static SHARD_LOCKS: [Mutex<()>; SHARD_COUNT] = [const { Mutex::new(()) }; SHARD_COUNT];
