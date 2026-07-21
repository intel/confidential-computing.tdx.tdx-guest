// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2026 Intel Corporation.

//! Registration-path logic for unaccepted-memory ranges.
//!
//! This file handles `register_range` splitting: it accepts edges/out-of-coverage
//! segments eagerly and marks in-coverage aligned segments as pending in the bitmap.

use super::{
    align_down, align_up,
    bitmap::{BitIndex, BitmapMut},
    EfiUnacceptedMemory,
};
use crate::AcceptError;

impl EfiUnacceptedMemory {
    /// Processes `start..end` by eagerly accepting required parts and deferring the rest in bitmap.
    ///
    /// # Safety
    ///
    /// The caller must ensure the range is valid guest-private memory in pending/acceptable state.
    pub unsafe fn register_range(&mut self, start: u64, end: u64) -> Result<(), AcceptError> {
        let table_phys_base = self.phys_base;
        let unit_size = self.validated_unit_size()?;
        if start >= end {
            return Ok(());
        }

        let unit_mask = unit_size - 1;

        if end - start < 2 * unit_size {
            // SAFETY: Caller guarantees the physical range is valid for TDX acceptance.
            return unsafe { Self::try_accept_range(start, end) };
        }

        let mut current_start = start;
        let mut current_end = end;

        if current_start & unit_mask != 0 {
            let Some(aligned_start) = align_up(current_start, unit_size) else {
                return Err(AcceptError::ArithmeticOverflow);
            };
            // SAFETY: Caller guarantees the physical subrange is valid for TDX acceptance.
            unsafe { Self::try_accept_range(current_start, aligned_start)? };
            current_start = aligned_start;
        }

        if current_end & unit_mask != 0 {
            let aligned_end = align_down(current_end, unit_size);
            // SAFETY: Caller guarantees the physical subrange is valid for TDX acceptance.
            unsafe { Self::try_accept_range(aligned_end, current_end)? };
            current_end = aligned_end;
        }

        let Some(bitmap_coverage) = self.total_coverage_size() else {
            return Err(AcceptError::ArithmeticOverflow);
        };

        let Some(bitmap_end) = table_phys_base.checked_add(bitmap_coverage) else {
            return Err(AcceptError::ArithmeticOverflow);
        };

        // 1) Process aligned range before bitmap coverage.
        if current_start < table_phys_base {
            let accept_end = current_end.min(table_phys_base);
            // SAFETY: Caller guarantees the physical subrange is valid for TDX acceptance.
            unsafe { Self::try_accept_range(current_start, accept_end)? };
            current_start = accept_end;
        }

        if current_start >= current_end {
            return Ok(());
        }

        // 2) Process aligned range within bitmap coverage.
        if current_start < bitmap_end {
            let bitmap_range_end = current_end.min(bitmap_end);
            if current_start < bitmap_range_end {
                // SAFETY: GPA range is unit-aligned and within bitmap coverage.
                unsafe {
                    self.mark_range_as_unaccepted(current_start, bitmap_range_end, unit_size)?
                };
            }
            current_start = bitmap_range_end;
        }

        // 3) Process aligned range after bitmap coverage.
        if current_start < current_end {
            // SAFETY: Caller guarantees the physical subrange is valid for TDX acceptance.
            unsafe { Self::try_accept_range(current_start, current_end)? };
        }

        Ok(())
    }

    /// Accepts physical memory in `start..end` if the range is non-empty.
    ///
    /// # Safety
    ///
    /// The caller must ensure `start..end` is a valid GPA range for TDX acceptance.
    unsafe fn try_accept_range(start: u64, end: u64) -> Result<(), AcceptError> {
        if start < end {
            // SAFETY: Caller guarantees the physical range is valid for TDX acceptance.
            return unsafe { crate::accept_memory(start, end) };
        }
        Ok(())
    }

    /// Marks unit-aligned bitmap-covered GPA range `start..end` as unaccepted bits.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - `self` points to a valid unaccepted-memory table whose trailing bitmap memory is writable;
    /// - mutable access to `self`/bitmap is unique for the duration of this call (no aliasing);
    /// - `start..end` is unit-aligned for `unit_size` and corresponds to this table's
    ///   bitmap coverage semantics.
    unsafe fn mark_range_as_unaccepted(
        &mut self,
        start: u64,
        end: u64,
        unit_size: u64,
    ) -> Result<(), AcceptError> {
        if start >= end {
            return Ok(());
        }

        if !start.is_multiple_of(unit_size) || !end.is_multiple_of(unit_size) {
            return Err(AcceptError::InvalidAlignment);
        }

        let start_bit = BitIndex::new((start - self.phys_base) / unit_size);
        let end_bit = BitIndex::new((end - self.phys_base) / unit_size);
        let total_bits = BitIndex::new(self.total_bits()?);

        let clamped_start_bit = BitIndex::new(start_bit.raw().min(total_bits.raw()));
        let clamped_end_bit = BitIndex::new(end_bit.raw().min(total_bits.raw()));
        if clamped_start_bit >= clamped_end_bit {
            return Ok(());
        }

        // SAFETY: Caller guarantees bitmap memory is writable and uniquely accessible.
        let mut bitmap = BitmapMut::new(unsafe { self.as_bitmap_slice_mut()? });
        if bitmap
            .find_next_set(clamped_start_bit, clamped_end_bit)?
            .is_some()
        {
            return Err(AcceptError::Overlap);
        }
        bitmap.set_range(clamped_start_bit, clamped_end_bit)?;

        Ok(())
    }
}
