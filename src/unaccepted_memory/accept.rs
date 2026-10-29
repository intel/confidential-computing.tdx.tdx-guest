// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2026 Intel Corporation.

//! Acceptance-path operations for unaccepted-memory bitmap ranges.
//!
//! This file contains range acceptance flows and synchronized on-demand
//! acceptance state management.

use core::{
    ops::Range,
    sync::atomic::{AtomicUsize, Ordering},
};

use spin::{Mutex, Once};

use super::EfiUnacceptedMemory;
use crate::{accept_memory, AcceptError};

/// Initializes the global unaccepted-memory acceptance state with `table`.
pub fn init_acceptance_state(table: &'static EfiUnacceptedMemory) {
    ACCEPTANCE_STATE.call_once(|| AcceptanceState::new(table));
}

/// Returns a reference to the registered [`EfiUnacceptedMemory`] table, if initialized.
pub fn unaccepted_memory_table() -> Option<&'static EfiUnacceptedMemory> {
    ACCEPTANCE_STATE.get().map(|state| state.table)
}

/// Returns the number of unaccepted memory bytes remaining, or zero if uninitialized.
pub fn unaccepted_bytes() -> usize {
    ACCEPTANCE_STATE
        .get()
        .map_or(0, AcceptanceState::unaccepted_bytes)
}

/// Accepts all pending memory units in the registered [`EfiUnacceptedMemory`]
/// table that overlap `range` (or does nothing if no table is registered).
///
/// `disable_local_irq` must disable local interrupts for the lifetime of its
/// returned guard to prevent interrupt-handler deadlocks.
///
/// # Errors
///
/// Returns an error if TDX memory acceptance fails for any pending unit.
///
/// # Safety
///
/// Every pending unit in the registered table overlapping `range` must be unused
/// guest-private memory (accepting a page zero-initializes it in hardware).
pub unsafe fn ensure_accepted<G>(
    range: Range<u64>,
    disable_local_irq: impl Fn() -> G,
) -> Result<(), AcceptError> {
    let Some(state) = ACCEPTANCE_STATE.get() else {
        return Ok(());
    };

    state.ensure_accepted_with(range, disable_local_irq, |unit| {
        // SAFETY: The caller guarantees overlapping pending units are unused
        // guest-private memory, and the shard lock serializes acceptance of `unit`.
        unsafe { accept_memory(unit.start, unit.end) }
    })
}

pub(super) const SHARD_COUNT: usize = 64;

pub(super) struct AcceptanceState {
    pub(super) table: &'static EfiUnacceptedMemory,
    pub(super) shard_locks: [Mutex<()>; SHARD_COUNT],
    unaccepted_bytes: AtomicUsize,
}

impl AcceptanceState {
    pub(super) fn new(table: &'static EfiUnacceptedMemory) -> Self {
        let total_bytes = table.bitmap_ref().count_ones() * u64::from(table.unit_size_bytes());
        Self {
            table,
            shard_locks: [const { Mutex::new(()) }; SHARD_COUNT],
            unaccepted_bytes: AtomicUsize::new(total_bytes as usize),
        }
    }

    pub(super) fn unaccepted_bytes(&self) -> usize {
        self.unaccepted_bytes.load(Ordering::Relaxed)
    }

    pub(super) fn ensure_accepted_with<G>(
        &self,
        range: Range<u64>,
        disable_local_irq: impl Fn() -> G,
        mut accept_unit: impl FnMut(Range<u64>) -> Result<(), AcceptError>,
    ) -> Result<(), AcceptError> {
        let Some(bit_range) = self.table.overlapping_bit_range(range) else {
            return Ok(());
        };

        let bitmap = self.table.bitmap_ref();
        let unit_size = self.table.unit_size_bytes() as usize;
        let mut next_bit = bit_range.start;
        while let Some(unit_bit) = bitmap.find_next_set(next_bit..bit_range.end) {
            next_bit = unit_bit + 1;
            let shard_index = (unit_bit as usize) % SHARD_COUNT;
            let _irq_guard = disable_local_irq();
            // Reverse drop order releases the lock before restoring IRQs, even on errors.
            let _shard_guard = self.shard_locks[shard_index].lock();

            if !bitmap.is_bit_set(unit_bit) {
                continue;
            }

            accept_unit(self.table.unit_range(unit_bit))?;

            if bitmap.clear_bit(unit_bit) {
                self.unaccepted_bytes
                    .fetch_sub(unit_size, Ordering::Relaxed);
            }
        }

        Ok(())
    }
}

static ACCEPTANCE_STATE: Once<AcceptanceState> = Once::new();
