// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2026 Intel Corporation.

//! Registration-path logic for unaccepted-memory ranges.
//!
//! This file handles `register_range` splitting: it accepts edges/out-of-coverage
//! segments eagerly and marks in-coverage aligned segments as pending in the bitmap.

use core::{ops::Range, pin::Pin};

use super::{
    layout::{align_down, align_up},
    EfiUnacceptedMemory,
};
use crate::{accept_memory, AcceptError};

/// Builder for constructing an [`EfiUnacceptedMemory`] table incrementally without heap allocation.
pub struct EfiUnacceptedMemoryBuilder {
    table: Pin<&'static mut EfiUnacceptedMemory>,
}

impl EfiUnacceptedMemoryBuilder {
    /// Registers a single unaccepted memory range.
    ///
    /// Aligned units within the table's coverage are marked pending in the bitmap;
    /// sub-unit edges and out-of-coverage segments are accepted eagerly.
    ///
    /// # Safety
    ///
    /// `range` must be unused guest-private memory (accepting a page
    /// zero-initializes it in hardware).
    pub unsafe fn register_range(&mut self, range: Range<u64>) -> Result<(), AcceptError> {
        if range.start >= range.end {
            return Ok(());
        }

        let unit_size = u64::from(self.table.unit_size_bytes());
        let coverage = self.table.coverage_range();
        let pending_start = align_up(range.start, unit_size)
            .ok_or(AcceptError::ArithmeticOverflow)?
            .max(coverage.start);
        let pending_end = align_down(range.end, unit_size).min(coverage.end);

        let Some(bits) = self.table.overlapping_bit_range(pending_start..pending_end) else {
            // SAFETY: The caller guarantees `range` is unused guest-private memory.
            return unsafe { accept_memory(range.start, range.end) };
        };

        let bitmap = self.table.bitmap_ref();
        if bitmap.find_next_set(bits.clone()).is_some() {
            return Err(AcceptError::Overlap);
        }

        // SAFETY: The caller guarantees all subranges of `range` are unused
        // guest-private memory.
        unsafe {
            accept_memory(range.start, pending_start)?;
            accept_memory(pending_end, range.end)?;
        }
        bitmap.set_range(bits);

        Ok(())
    }

    /// Consumes the builder and returns the completed pinned [`EfiUnacceptedMemory`] table.
    pub fn build(self) -> Pin<&'static mut EfiUnacceptedMemory> {
        self.table
    }

    pub(super) fn new(table: Pin<&'static mut EfiUnacceptedMemory>) -> Self {
        Self { table }
    }
}
