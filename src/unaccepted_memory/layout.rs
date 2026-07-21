// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2026 Intel Corporation.

//! Layout and mapping helpers for unaccepted-memory metadata.
//!
//! This file provides address/bit conversions, coverage clamping, unit-size
//! validation, and trailing-bitmap raw/slice view construction.

use super::{
    bitmap::{AtomicBitmapMut, AtomicBitmapRef, BitIndex},
    EfiUnacceptedMemory, PhysAddr,
};
use crate::AcceptError;

impl EfiUnacceptedMemory {
    /// Returns the end GPA (exclusive) covered by the bitmap.
    ///
    /// This is equivalent to `phys_base + total_coverage_size()`.
    pub fn bitmap_coverage_end(&self) -> Option<u64> {
        Some(
            PhysAddr::new(self.phys_base)
                .checked_add(self.total_coverage_size()?)
                .ok()?
                .raw(),
        )
    }

    /// Clears all bits in the trailing bitmap payload.
    ///
    /// # Safety
    ///
    /// The caller must ensure that this header is followed by at least
    /// `self.bitmap_size_bytes` writable bytes in memory, and that mutable
    /// access to the bitmap payload is unique for the duration of this call.
    pub unsafe fn clear_bitmap(&mut self) -> Result<(), AcceptError> {
        // SAFETY: Caller guarantees writable trailing bitmap payload and unique access.
        let bitmap = unsafe { self.as_bitmap_slice_mut()? };
        bitmap.fill(0);
        Ok(())
    }

    /// Returns an immutable slice view of the trailing bitmap payload.
    ///
    /// # Safety
    ///
    /// The caller must ensure that this header is followed by at least
    /// `self.bitmap_size_bytes` readable bytes in memory.
    pub(super) unsafe fn as_bitmap_slice(&self) -> Result<&[u8], AcceptError> {
        // SAFETY: Caller guarantees readable trailing bitmap payload.
        let (bitmap_ptr, bitmap_len) = unsafe { self.bitmap_raw_parts()? };
        // SAFETY: `bitmap_ptr` points to the trailing bitmap bytes immediately
        // after `self`; `bitmap_len` is validated from `self.bitmap_size_bytes`;
        // caller guarantees readable backing memory for the returned slice.
        Ok(unsafe { core::slice::from_raw_parts(bitmap_ptr, bitmap_len) })
    }

    /// Returns a mutable slice view of the trailing bitmap payload.
    ///
    /// # Safety
    ///
    /// The caller must ensure that this header is followed by at least
    /// `self.bitmap_size_bytes` writable bytes in memory, and that no aliased
    /// mutable reference exists while the returned slice is in use.
    pub(super) unsafe fn as_bitmap_slice_mut(&mut self) -> Result<&mut [u8], AcceptError> {
        let bitmap_len = self.byte_len()?;
        // Derive the mutable pointer from `&mut self` via `from_mut` so that
        // the resulting `*mut u8` carries write provenance.  Going through
        // `bitmap_raw_parts` (which uses `from_ref`) would lose mutability.
        let bitmap_ptr = core::ptr::from_mut(self)
            .cast::<u8>()
            .add(core::mem::size_of::<Self>());
        // SAFETY: `bitmap_ptr` points to the trailing bitmap bytes immediately
        // after `self`; `bitmap_len` is validated from `self.bitmap_size_bytes`;
        // caller guarantees writable backing memory and unique mutable access.
        Ok(unsafe { core::slice::from_raw_parts_mut(bitmap_ptr, bitmap_len) })
    }

    pub(super) fn total_bits(&self) -> Result<u64, AcceptError> {
        self.bitmap_size_bytes
            .checked_mul(8)
            .ok_or(AcceptError::ArithmeticOverflow)
    }

    pub(super) fn validated_unit_size(&self) -> Result<u64, AcceptError> {
        let unit_size = u64::from(self.unit_size_bytes);
        if unit_size == 0 || !unit_size.is_power_of_two() {
            return Err(AcceptError::InvalidAlignment);
        }
        Ok(unit_size)
    }

    /// Converts a GPA range into an overlapping bitmap bit range.
    ///
    /// Returns `Ok(None)` when there is no overlap with bitmap coverage.
    pub(super) fn overlapping_bit_range(
        &self,
        start: u64,
        end: u64,
    ) -> Result<Option<(BitIndex, BitIndex, u64)>, AcceptError> {
        let Some((range_start, range_end, unit_size)) =
            self.clamp_gpa_range_to_bitmap_coverage(start, end)?
        else {
            return Ok(None);
        };

        let (first_bit, last_bit) = self.addr_to_bit_range(range_start, range_end, unit_size)?;
        Ok(Some((first_bit, last_bit, unit_size)))
    }

    /// Returns an atomic read-only bitmap view after validating atomic layout constraints.
    ///
    /// # Safety
    ///
    /// The caller must guarantee the trailing bitmap payload is valid for reads,
    /// and overlapping concurrent accesses use only atomic word operations.
    pub(super) unsafe fn atomic_bitmap_ref(&self) -> Result<AtomicBitmapRef<'_>, AcceptError> {
        // SAFETY: Caller guarantees readable trailing bitmap payload.
        let (bitmap_ptr, bitmap_len) = unsafe { self.bitmap_raw_parts()? };
        Self::validate_atomic_bitmap_layout(bitmap_ptr, bitmap_len)?;

        // SAFETY: Layout validation above guarantees alignment and length constraints.
        Ok(unsafe { AtomicBitmapRef::from_raw(bitmap_ptr, bitmap_len) })
    }

    /// Returns an atomic writable bitmap view after validating atomic layout constraints.
    ///
    /// # Safety
    ///
    /// The caller must guarantee the trailing bitmap payload is valid for writes,
    /// and overlapping concurrent accesses use only atomic word operations.
    pub(super) unsafe fn atomic_bitmap_mut(&self) -> Result<AtomicBitmapMut<'_>, AcceptError> {
        // SAFETY: Caller guarantees writable trailing bitmap payload.
        let (bitmap_ptr, bitmap_len) = unsafe { self.bitmap_raw_parts_mut()? };
        Self::validate_atomic_bitmap_layout(bitmap_ptr.cast_const(), bitmap_len)?;

        // SAFETY: Layout validation above guarantees alignment and length constraints.
        Ok(unsafe { AtomicBitmapMut::from_raw(bitmap_ptr, bitmap_len) })
    }

    fn byte_len(&self) -> Result<usize, AcceptError> {
        usize::try_from(self.bitmap_size_bytes).map_err(|_| AcceptError::OutOfBounds)
    }

    fn max_phys_addr_exclusive(&self, unit_size: u64) -> Result<u64, AcceptError> {
        let total_bits = self.total_bits()?;
        let coverage_len = total_bits
            .checked_mul(unit_size)
            .ok_or(AcceptError::ArithmeticOverflow)?;
        self.phys_base
            .checked_add(coverage_len)
            .ok_or(AcceptError::ArithmeticOverflow)
    }

    fn clamp_gpa_range_to_bitmap_coverage(
        &self,
        start: u64,
        end: u64,
    ) -> Result<Option<(u64, u64, u64)>, AcceptError> {
        if start >= end {
            return Ok(None);
        }

        let unit_size = self.validated_unit_size()?;
        let coverage_end = self.max_phys_addr_exclusive(unit_size)?;

        let range_start = start.max(self.phys_base);
        let range_end = end.min(coverage_end);
        if range_start >= range_end {
            return Ok(None);
        }

        Ok(Some((range_start, range_end, unit_size)))
    }

    fn addr_to_bit_range(
        &self,
        start: u64,
        end: u64,
        unit_size: u64,
    ) -> Result<(BitIndex, BitIndex), AcceptError> {
        debug_assert!(start >= self.phys_base);
        debug_assert!(start < end);
        debug_assert!(unit_size.is_power_of_two());

        let rel_start = start - self.phys_base;
        let rel_end = end - self.phys_base;

        let first_bit = rel_start / unit_size;
        // NOTE: last_bit is exclusive and uses ceil-div for overlap semantics.
        // Any unit intersecting [start, end) is considered.
        let last_bit = rel_end
            .checked_add(unit_size - 1)
            .ok_or(AcceptError::ArithmeticOverflow)?
            / unit_size;

        Ok((BitIndex::new(first_bit), BitIndex::new(last_bit)))
    }

    /// Returns the raw const pointer and length of the trailing bitmap payload.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - This header is followed by at least `self.bitmap_size_bytes` readable
    ///   bytes in memory.
    pub(super) unsafe fn bitmap_raw_parts(&self) -> Result<(*const u8, usize), AcceptError> {
        let bitmap_len = self.byte_len()?;
        let bitmap_ptr = core::ptr::from_ref(self)
            .cast::<u8>()
            .add(core::mem::size_of::<Self>());
        Ok((bitmap_ptr, bitmap_len))
    }

    /// Returns the raw mutable pointer and length of the trailing bitmap payload.
    ///
    /// The pointer is derived by casting `self` (via `*const Self`) to
    /// `*mut u8` and advancing past the header.  Because the trailing
    /// bitmap lives *outside* the Rust‐level pointee of `&self`, the
    /// provenance of the resulting `*mut u8` does **not** come from a
    /// mutable reference — callers must only use this pointer to form
    /// `&[AtomicU64]` (interior mutability) or other atomic views.
    /// For non‐atomic mutable access, prefer [`Self::as_bitmap_slice_mut`]
    /// which derives its pointer from `&mut self`.
    ///
    /// # Safety
    ///
    /// The caller must ensure:
    /// - The header is followed by at least `self.bitmap_size_bytes`
    ///   bytes of valid, writable memory.
    /// - The returned pointer is only used for atomic operations, or the
    ///   caller has arranged exclusive access by other means.
    pub(super) unsafe fn bitmap_raw_parts_mut(&self) -> Result<(*mut u8, usize), AcceptError> {
        let bitmap_len = self.byte_len()?;
        let bitmap_ptr = core::ptr::from_ref(self)
            .cast_mut()
            .cast::<u8>()
            .add(core::mem::size_of::<Self>());
        Ok((bitmap_ptr, bitmap_len))
    }

    fn validate_atomic_bitmap_layout(
        bitmap_ptr: *const u8,
        bitmap_len: usize,
    ) -> Result<(), AcceptError> {
        if !bitmap_ptr.addr().is_multiple_of(core::mem::align_of::<core::sync::atomic::AtomicU64>()) {
            return Err(AcceptError::InvalidAlignment);
        }
        if !bitmap_len.is_multiple_of(core::mem::size_of::<core::sync::atomic::AtomicU64>()) {
            return Err(AcceptError::InvalidAlignment);
        }

        Ok(())
    }
}
