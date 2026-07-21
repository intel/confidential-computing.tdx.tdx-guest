// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2026 Intel Corporation.

//! Acceptance-path operations for unaccepted-memory bitmap ranges.
//!
//! This file contains range acceptance flows, including exclusive (`&mut self`)
//! and concurrent (`&self` + atomic bitmap writer) paths, plus pending-run
//! claim/restore helpers used during acceptance.

use super::{
    bitmap::{AtomicBitmapMut, BitIndex, BitmapMut},
    EfiUnacceptedMemory, PhysAddr,
};
use crate::{accept_memory, AcceptError};

impl EfiUnacceptedMemory {
    /// Convenience wrapper for [`EfiUnacceptedMemory::accept_range`].
    ///
    /// # Safety
    ///
    /// The caller must ensure `self` is uniquely borrowed for in-place bitmap updates and
    /// points to a valid unaccepted-memory table with writable bitmap memory.
    pub unsafe fn accept_by_size(&mut self, start: u64, size: u64) -> Result<(), AcceptError> {
        let Some(end) = start.checked_add(size) else {
            return Err(AcceptError::ArithmeticOverflow);
        };

        // SAFETY: Caller guarantees table/bitmap validity and target range correctness.
        unsafe { self.accept_range(start, end) }
    }

    /// Accepts bitmap-marked units that overlap `start..end`, then clears accepted bits.
    ///
    /// # Safety
    ///
    /// The caller must ensure this table and bitmap describe pending private-memory units,
    /// and the target GPA ranges are valid for TDX acceptance.
    pub unsafe fn accept_range(&mut self, start: u64, end: u64) -> Result<(), AcceptError> {
        let Some((first_bit, last_bit, unit_size)) = self.overlapping_bit_range(start, end)? else {
            return Ok(());
        };

        let phys_base = self.phys_base;

        // SAFETY: Caller guarantees table/bitmap validity and exclusive mutable access.
        let mut bitmap = BitmapMut::new(unsafe { self.as_bitmap_slice_mut()? });
        // SAFETY: Caller guarantees bitmap/GPA mapping validity for pending private pages.
        unsafe {
            Self::accept_pending_runs(&mut bitmap, first_bit, last_bit, unit_size, phys_base)?
        };
        Ok(())
    }

    /// Accepts bitmap-marked units that overlap `start..end`
    /// and clears the corresponding bitmap bits.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - This table and bitmap describe pending private-memory units.
    /// - The target GPA range is valid for TDX acceptance.
    /// - No concurrent call touches the same bitmap bits.
    pub unsafe fn accept_range_concurrent(&self, start: u64, end: u64) -> Result<(), AcceptError> {
        self.with_atomic_bitmap_range_or(
            start,
            end,
            (),
            |bitmap, first_bit, last_bit, unit_size| {
                // SAFETY: Caller guarantees bitmap/GPA validity for pending private pages.
                unsafe {
                    Self::accept_pending_runs_atomic(
                        bitmap,
                        first_bit,
                        last_bit,
                        unit_size,
                        self.phys_base,
                    )
                }
            },
        )
    }

    /// Finds the first contiguous run of set bits overlapping `[start, end)`,
    /// clears those bits, and returns the corresponding GPA range.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - This table and bitmap reside in valid, writable memory.
    /// - No concurrent call touches the same bitmap bits.
    pub unsafe fn claim_next_pending_run(
        &self,
        start: u64,
        end: u64,
    ) -> Result<Option<(u64, u64)>, AcceptError> {
        self.with_atomic_bitmap_range_or(
            start,
            end,
            None,
            |bitmap, first_bit, last_bit, unit_size| {
                let Some(run_start) = bitmap.find_next_set(first_bit, last_bit)? else {
                    return Ok(None);
                };
                let run_end = bitmap
                    .find_next_zero(run_start, last_bit)?
                    .unwrap_or(last_bit);

                bitmap.clear_range(run_start, run_end)?;

                let gpa_start = Self::bit_to_gpa(self.phys_base, run_start, unit_size)?;
                let gpa_end = Self::bit_to_gpa(self.phys_base, run_end, unit_size)?;
                Ok(Some((gpa_start, gpa_end)))
            },
        )
    }

    /// Re-sets bitmap bits for a GPA range whose TDX accept failed.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - This table and bitmap reside in valid, writable memory.
    /// - No concurrent call touches the same bitmap bits.
    /// - The range was previously claimed and not yet accepted.
    pub unsafe fn restore_pending_range(&self, start: u64, end: u64) -> Result<(), AcceptError> {
        self.with_atomic_bitmap_range_or(
            start,
            end,
            (),
            |bitmap, first_bit, last_bit, _unit_size| bitmap.set_range(first_bit, last_bit),
        )
    }

    fn with_atomic_bitmap_range_or<T>(
        &self,
        start: u64,
        end: u64,
        default_value: T,
        op_fn: impl FnOnce(&AtomicBitmapMut<'_>, BitIndex, BitIndex, u64) -> Result<T, AcceptError>,
    ) -> Result<T, AcceptError> {
        let (first_bit, last_bit, unit_size) = match self.overlapping_bit_range(start, end)? {
            Some(vals) => vals,
            None => return Ok(default_value),
        };

        // SAFETY: Public concurrent API contract guarantees valid writable bitmap
        // payload and atomic-access discipline for overlapping ranges.
        let bitmap = unsafe { self.atomic_bitmap_mut()? };
        op_fn(&bitmap, first_bit, last_bit, unit_size)
    }

    /// Scans set-bit runs in `[first_bit, last_bit)`, accepts each run, then clears it.
    ///
    /// # Safety
    ///
    /// The caller must ensure bitmap and GPA mapping validity for pending private pages,
    /// and that `bitmap` mutation obeys the aliasing/synchronization contract of its type.
    unsafe fn accept_pending_runs(
        bitmap: &mut BitmapMut<'_>,
        first_bit: BitIndex,
        last_bit: BitIndex,
        unit_size: u64,
        phys_base: u64,
    ) -> Result<(), AcceptError> {
        let mut scan = first_bit;
        while let Some(run_start) = bitmap.find_next_set(scan, last_bit)? {
            let run_end = bitmap
                .find_next_zero(run_start, last_bit)?
                .unwrap_or(last_bit);

            let run_gpa_start = Self::bit_to_gpa(phys_base, run_start, unit_size)?;
            let run_gpa_end = Self::bit_to_gpa(phys_base, run_end, unit_size)?;

            // SAFETY: Caller guarantees bitmap/GPA mapping validity for pending private pages.
            unsafe { accept_memory(run_gpa_start, run_gpa_end)? };
            bitmap.clear_range(run_start, run_end)?;

            scan = run_end;
        }

        Ok(())
    }

    fn bit_to_gpa(phys_base: u64, bit: BitIndex, unit_size: u64) -> Result<u64, AcceptError> {
        PhysAddr::new(phys_base)
            .checked_add_units(bit, unit_size)
            .map(PhysAddr::raw)
    }

    /// Atomic-writer variant of `accept_pending_runs`.
    ///
    /// # Safety
    ///
    /// The caller must ensure bitmap and GPA mapping validity for pending private pages.
    unsafe fn accept_pending_runs_atomic(
        bitmap: &AtomicBitmapMut<'_>,
        first_bit: BitIndex,
        last_bit: BitIndex,
        unit_size: u64,
        phys_base: u64,
    ) -> Result<(), AcceptError> {
        let mut scan = first_bit;
        while let Some(run_start) = bitmap.find_next_set(scan, last_bit)? {
            let run_end = bitmap
                .find_next_zero(run_start, last_bit)?
                .unwrap_or(last_bit);

            let run_gpa_start = Self::bit_to_gpa(phys_base, run_start, unit_size)?;
            let run_gpa_end = Self::bit_to_gpa(phys_base, run_end, unit_size)?;

            // SAFETY: Caller guarantees bitmap/GPA mapping validity for pending private pages.
            unsafe { accept_memory(run_gpa_start, run_gpa_end)? };
            bitmap.clear_range(run_start, run_end)?;

            scan = run_end;
        }

        Ok(())
    }
}
