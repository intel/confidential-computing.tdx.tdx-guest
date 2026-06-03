// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2026 Intel Corporation.

//! Support for unaccepted memory in TDX guest environments.
//! This module provides mechanisms to manage and accept unaccepted memory regions in TDX guests.
//! The core data structure is `EfiUnacceptedMemory`, which represents the EFI table header and provides
//! methods to manipulate the unaccepted memory bitmap and perform acceptance operations.

use crate::{accept_memory, AcceptError};

/// GUID of the Linux-compatible unaccepted-memory EFI table.
pub const LINUX_EFI_UNACCEPTED_MEM_TABLE_GUID: uefi_raw::Guid =
    uefi_raw::guid!("d5d1de3c-105c-44f9-9ea9-bcef98120031");

/// Version of the Linux-compatible unaccepted-memory EFI table supported here.
pub const LINUX_EFI_UNACCEPTED_MEM_TABLE_VERSION: u32 = 1;

/// Unit size for unaccepted-memory bitmap entries (2 MiB).
pub const EFI_UNACCEPTED_UNIT_SIZE: u64 = 2 * 1024 * 1024;

/// Header of the Linux-compatible EFI unaccepted-memory table.
///
/// This type describes only the fixed-size header. The bitmap payload is stored
/// immediately after the header in memory (C-style trailing data):
///
/// ### Memory Layout
/// The total memory footprint is
/// `size_of::<EfiUnacceptedMemory>() + self.bitmap_size_bytes`.
/// The bitmap begins at the first byte following this structure.
///
/// ### Bitmap Semantics
/// - Each bit in the trailing bitmap represents a memory region of
///   `unit_size_bytes` bytes.
/// - Bit 0 corresponds to the physical address specified by `phys_base`.
/// - A **set bit (1)** indicates memory is unaccepted (pending);
///   a **cleared bit (0)** indicates it has been accepted.
///
/// ### Concurrency Contract
/// This type does not provide internal synchronization for bitmap mutation.
/// Callers must serialize mutating operations (for example with a spinlock)
/// before invoking methods like `register_range` or `accept_range`.
#[derive(Debug)]
#[repr(C, packed)]
pub struct EfiUnacceptedMemory {
    /// The version of the table. Currently, only version 1 is defined.
    version: u32,
    /// The size of the memory region represented by a single bit in the bitmap.
    /// Typically set to 2MiB (0x200000) to align with huge page boundaries.
    unit_size_bytes: u32,
    /// The start physical address of the memory range covered by this bitmap.
    /// Bit 0 of the bitmap corresponds to this address.
    phys_base: u64,
    /// The bitmap payload length in bytes, excluding this header.
    bitmap_size_bytes: u64,
}

impl EfiUnacceptedMemory {
    /// Initializes the table header fields for EFI installation.
    pub fn init_header(
        &mut self,
        unit_size_bytes: u32,
        phys_base: u64,
        bitmap_size_bytes: u64,
    ) -> Result<(), AcceptError> {
        if unit_size_bytes == 0 || !unit_size_bytes.is_power_of_two() {
            return Err(AcceptError::InvalidAlignment);
        }

        self.version = LINUX_EFI_UNACCEPTED_MEM_TABLE_VERSION;
        self.unit_size_bytes = unit_size_bytes;
        self.phys_base = phys_base;
        self.bitmap_size_bytes = bitmap_size_bytes;
        Ok(())
    }

    /// Returns the version of the table header.
    pub const fn version(&self) -> u32 {
        self.version
    }

    /// Returns the unit size represented by one bitmap bit, in bytes.
    pub const fn unit_size_bytes(&self) -> u32 {
        self.unit_size_bytes
    }

    /// Returns the start physical address covered by the bitmap.
    pub const fn phys_base(&self) -> u64 {
        self.phys_base
    }

    /// Returns the trailing bitmap payload length, in bytes.
    pub const fn bitmap_size_bytes(&self) -> u64 {
        self.bitmap_size_bytes
    }

    /// Returns whether `(start, size)` overlaps any pending bitmap unit.
    ///
    /// # Safety
    ///
    /// The caller must ensure this header is followed in memory by at least
    /// `self.bitmap_size_bytes` readable bitmap bytes.
    pub unsafe fn is_range_pending_by_size(
        &self,
        start: u64,
        size: u64,
    ) -> Result<bool, AcceptError> {
        let Some(end) = start.checked_add(size) else {
            return Err(AcceptError::ArithmeticOverflow);
        };

        // SAFETY: Caller guarantees the table header is followed by readable bitmap bytes.
        unsafe { self.is_range_pending(start, end) }
    }

    /// Returns whether `[start, end)` overlaps any pending bitmap unit.
    ///
    /// # Safety
    ///
    /// The caller must ensure this header is followed in memory by at least
    /// `self.bitmap_size_bytes` readable bitmap bytes.
    pub unsafe fn is_range_pending(&self, start: u64, end: u64) -> Result<bool, AcceptError> {
        let Some((range_start, range_end, unit_size)) =
            self.clamp_gpa_range_to_bitmap_coverage(start, end)?
        else {
            return Ok(false);
        };

        let (first_bit, last_bit) = self.addr_to_bit_range(range_start, range_end, unit_size)?;
        // SAFETY: Caller guarantees the table header is followed by readable bitmap bytes.
        let bitmap = unsafe { self.as_bitmap_slice() };
        BitmapRef::new(bitmap).has_set_bit(first_bit, last_bit)
    }

    /// Returns whether every bitmap unit overlapping `[start, end)` is accepted.
    ///
    /// Ranges outside bitmap coverage are considered accepted by definition,
    /// because this table only tracks deferred acceptance inside its own coverage.
    ///
    /// # Safety
    ///
    /// The caller must ensure this header is followed in memory by at least
    /// `self.bitmap_size_bytes` readable bitmap bytes.
    pub unsafe fn is_fully_accepted(&self, start: u64, end: u64) -> Result<bool, AcceptError> {
        // SAFETY: Caller guarantees the table header is followed by readable bitmap bytes.
        Ok(!unsafe { self.is_range_pending(start, end) }?)
    }

    /// Convenience wrapper for
    /// [`EfiUnacceptedMemory::accept_range`] using
    /// `(start, size)` instead of `(start, end)`.
    ///
    /// Computes `end = start + size` and forwards to the range-based API.
    ///
    /// # Safety
    ///
    /// The caller must ensure `self` is uniquely borrowed for in-place bitmap updates and
    /// points to a valid unaccepted-memory table with writable bitmap memory.
    ///
    /// # Errors
    ///
    /// Returns [`AcceptError::ArithmeticOverflow`] if `start + size` overflows.
    /// Propagates any error from [`EfiUnacceptedMemory::accept_range`].
    pub unsafe fn accept_by_size(&mut self, start: u64, size: u64) -> Result<(), AcceptError> {
        let Some(end) = start.checked_add(size) else {
            return Err(AcceptError::ArithmeticOverflow);
        };

        // SAFETY: Caller guarantees table/bitmap validity and target range correctness.
        unsafe { self.accept_range(start, end) }
    }

    /// Accepts bitmap-marked units that overlap `start..end`, then clears accepted bits.
    ///
    /// The input is interpreted as a half-open GPA interval `[start, end)`.
    ///
    /// Behavior summary:
    /// - The requested range is first clamped to bitmap coverage.
    /// - Any bitmap bit set to `1` and overlapping the clamped range is accepted.
    /// - Successfully accepted bits are cleared to `0` in-place.
    /// - If the clamped range is empty, this is a no-op.
    ///
    /// # Safety
    ///
    /// The caller must ensure this table and bitmap describe pending private-memory units,
    /// and the target GPA ranges are valid for TDX acceptance.
    ///
    /// # Errors
    ///
    /// Returns [`AcceptError::InvalidAlignment`] for invalid unit configuration.
    /// Returns [`AcceptError::ArithmeticOverflow`] for address/index arithmetic overflow.
    /// Returns [`AcceptError::OutOfBounds`] for bitmap index out-of-range accesses.
    /// Returns hardware-originated failures from `accept_memory` via
    /// [`AcceptError::TdCall`].
    pub unsafe fn accept_range(&mut self, start: u64, end: u64) -> Result<(), AcceptError> {
        // SAFETY: Caller guarantees table/bitmap validity and target range correctness.
        let _ = unsafe { self.accept_if_needed_range(start, end) }?;
        Ok(())
    }

    /// Returns the end GPA (exclusive) covered by the bitmap.
    ///
    /// This is equivalent to `phys_base + total_coverage_size()`.
    pub fn bitmap_coverage_end(&self) -> Option<u64> {
        let base = PhysAddr::new(self.phys_base);
        Some(base.checked_add(self.total_coverage_size()?).ok()?.raw())
    }

    /// Returns an immutable slice view of the trailing bitmap payload.
    ///
    /// # Safety
    ///
    /// The caller must ensure that this header is followed by at least
    /// `self.bitmap_size_bytes`
    /// readable bytes in memory.
    pub unsafe fn as_bitmap_slice(&self) -> &[u8] {
        debug_assert!(self.byte_len().is_ok());
        let bitmap_ptr = core::ptr::from_ref(self)
            .cast::<u8>()
            .wrapping_add(core::mem::size_of::<Self>());
        let bitmap_len = self
            .byte_len()
            .expect("bitmap size must fit usize on this platform");
        // SAFETY: `bitmap_ptr` points to the trailing bitmap bytes immediately
        // after `self`; `bitmap_len` is validated from `self.bitmap_size_bytes`;
        // caller guarantees
        // readable backing memory for the returned slice.
        unsafe { core::slice::from_raw_parts(bitmap_ptr, bitmap_len) }
    }

    /// Returns a mutable slice view of the trailing bitmap payload.
    ///
    /// # Safety
    ///
    /// The caller must ensure that this header is followed by at least
    /// `self.bitmap_size_bytes`
    /// writable bytes in memory, and that no aliased mutable reference exists
    /// while the returned slice is in use.
    pub unsafe fn as_bitmap_slice_mut(&mut self) -> &mut [u8] {
        debug_assert!(self.byte_len().is_ok());
        let bitmap_ptr_mut = core::ptr::from_mut(self)
            .cast::<u8>()
            .wrapping_add(core::mem::size_of::<Self>());
        debug_assert!(!bitmap_ptr_mut.is_null());
        let bitmap_len = self
            .byte_len()
            .expect("bitmap size must fit usize on this platform");
        // SAFETY: `bitmap_ptr_mut` points to the trailing bitmap bytes immediately
        // after `self`; `bitmap_len` is validated from `self.bitmap_size_bytes`;
        // caller guarantees
        // writable backing memory and unique mutable access for the returned slice.
        unsafe { core::slice::from_raw_parts_mut(bitmap_ptr_mut, bitmap_len) }
    }

    /// Processes `start..end` by eagerly accepting required parts and deferring the rest in bitmap.
    ///
    /// This method applies a hybrid policy:
    /// - edge fragments that are not `unit_size`-aligned are accepted immediately;
    /// - aligned interior regions within bitmap coverage are marked as unaccepted bits;
    /// - aligned regions outside bitmap coverage are accepted immediately.
    ///
    /// # Safety
    ///
    /// The caller must ensure the range is valid guest-private memory in pending/acceptable state.
    ///
    /// # Errors
    ///
    /// Returns [`AcceptError::InvalidAlignment`] for invalid unit configuration.
    /// Returns [`AcceptError::ArithmeticOverflow`] for address arithmetic overflow.
    /// Returns [`AcceptError::Overlap`] if the same bitmap unit is registered twice.
    /// Returns hardware-originated errors from `accept_memory`
    /// via [`AcceptError::TdCall`].
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

    pub fn total_coverage_size(&self) -> Option<u64> {
        let unit_size = u64::from(self.unit_size_bytes);
        self.bitmap_size_bytes
            .checked_mul(unit_size)?
            .checked_mul(8)
    }

    /// Conditionally accepts bitmap-marked units that overlap `start..end`.
    ///
    /// Returns [`AcceptOutcome::AlreadyAccepted`] when the range overlaps the
    /// bitmap but there are no pending bits to process.
    ///
    /// # Safety
    ///
    /// Same requirements as [`Self::accept_range`].
    unsafe fn accept_if_needed_range(
        &mut self,
        start: u64,
        end: u64,
    ) -> Result<AcceptOutcome, AcceptError> {
        if start >= end {
            return Ok(AcceptOutcome::AlreadyAccepted);
        }

        let (range_start, range_end, unit_size) =
            match self.clamp_gpa_range_to_bitmap_coverage(start, end)? {
                Some(vals) => vals,
                None => return Ok(AcceptOutcome::OutOfCoverage),
            };

        let (first_bit, last_bit) = self.addr_to_bit_range(range_start, range_end, unit_size)?;
        let phys_base = PhysAddr::new(self.phys_base);

        let bit_to_gpa = |bit: BitIndex| -> Result<u64, AcceptError> {
            Ok(phys_base.checked_add_units(bit, unit_size)?.raw())
        };

        // SAFETY: Caller guarantees table/bitmap validity and exclusive mutable access.
        let mut bitmap = BitmapMut::new(unsafe { self.as_bitmap_slice_mut() });
        let mut accepted_units = 0u64;

        let mut scan = first_bit;
        while let Some(run_start) = bitmap.find_next_set(scan, last_bit)? {
            let run_end = bitmap
                .find_next_zero(run_start, last_bit)?
                .unwrap_or(last_bit);

            let run_gpa_start = bit_to_gpa(run_start)?;
            let run_gpa_end = bit_to_gpa(run_end)?;

            // SAFETY: Caller guarantees bitmap/GPA mapping validity for pending private pages.
            unsafe { accept_memory(run_gpa_start, run_gpa_end)? };
            accepted_units = accepted_units
                .checked_add(run_end.raw() - run_start.raw())
                .ok_or(AcceptError::ArithmeticOverflow)?;

            bitmap.clear_range(run_start, run_end)?;

            scan = run_end;
        }

        match accepted_units {
            0 => Ok(AcceptOutcome::AlreadyAccepted),
            n => Ok(AcceptOutcome::AcceptedNow { accepted_units: n }),
        }
    }

    /// Marks `start..end` (bitmap-relative) as unaccepted bits.
    ///
    /// # Safety
    ///
    /// The caller must ensure `start..end` is already converted to bitmap-relative offsets
    /// (i.e., based on `self.phys_base`) and does not violate bitmap ownership/aliasing rules.
    unsafe fn set_unaccepted_bits(&mut self, start: u64, end: u64) -> Result<(), AcceptError> {
        let unit_size = self.validated_unit_size()?;

        let abs_start = self
            .phys_base
            .checked_add(start)
            .ok_or(AcceptError::ArithmeticOverflow)?;
        let abs_end = self
            .phys_base
            .checked_add(end)
            .ok_or(AcceptError::ArithmeticOverflow)?;

        // SAFETY: Caller guarantees bitmap-relative range correctness and exclusive access.
        unsafe { self.mark_range_as_unaccepted(abs_start, abs_end, unit_size) }
    }

    fn total_bits(&self) -> Result<u64, AcceptError> {
        self.bitmap_size_bytes
            .checked_mul(8)
            .ok_or(AcceptError::ArithmeticOverflow)
    }

    fn byte_len(&self) -> Result<usize, AcceptError> {
        usize::try_from(self.bitmap_size_bytes).map_err(|_| AcceptError::OutOfBounds)
    }

    fn validated_unit_size(&self) -> Result<u64, AcceptError> {
        let unit_size = u64::from(self.unit_size_bytes);
        if unit_size == 0 || !unit_size.is_power_of_two() {
            return Err(AcceptError::InvalidAlignment);
        }
        Ok(unit_size)
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

        debug_assert_eq!(start % unit_size, 0);
        debug_assert_eq!(end % unit_size, 0);

        let start_bit = BitIndex::new((start - self.phys_base) / unit_size);
        let end_bit = BitIndex::new((end - self.phys_base) / unit_size);
        let total_bits = BitIndex::new(self.total_bits()?);

        let clamped_start_bit = BitIndex::new(start_bit.raw().min(total_bits.raw()));
        let clamped_end_bit = BitIndex::new(end_bit.raw().min(total_bits.raw()));
        if clamped_start_bit >= clamped_end_bit {
            return Ok(());
        }

        // SAFETY: Caller guarantees bitmap memory is writable and uniquely accessible.
        let mut bitmap = BitmapMut::new(unsafe { self.as_bitmap_slice_mut() });
        for bit in clamped_start_bit.raw()..clamped_end_bit.raw() {
            bitmap.set_bit(BitIndex::new(bit))?;
        }

        Ok(())
    }

    /// Accepts physical memory in `start..end` if the range is non-empty.
    ///
    /// # Safety
    ///
    /// The caller must ensure `start..end` is a valid GPA range for TDX acceptance,
    /// and that accepting this range does not race with other concurrent acceptance or
    /// access operations on the same memory.
    unsafe fn try_accept_range(start: u64, end: u64) -> Result<(), AcceptError> {
        if start >= end {
            return Ok(());
        }
        // SAFETY: Caller guarantees the physical range is valid for TDX acceptance.
        unsafe { accept_memory(start, end) }
    }
}

/// Mutable bitmap view used by registration/acceptance paths.
///
/// This helper is intentionally non-atomic; callers must provide external
/// synchronization when multiple CPUs could touch the same bitmap.
struct BitmapMut<'a> {
    bits: &'a mut [u8],
}

impl<'a> BitmapMut<'a> {
    fn new(bits: &'a mut [u8]) -> Self {
        Self { bits }
    }

    fn capacity(&self) -> Result<u64, AcceptError> {
        let len = u64::try_from(self.bits.len()).map_err(|_| AcceptError::OutOfBounds)?;
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
        Ok((self.bits[byte_index] & mask) != 0)
    }

    fn set_bit(&mut self, bit_index: BitIndex) -> Result<(), AcceptError> {
        if self.is_set(bit_index)? {
            return Err(AcceptError::Overlap);
        }
        let (byte_index, mask) = self.get_pos_mask(bit_index)?;
        self.bits[byte_index] |= mask;
        Ok(())
    }

    fn clear_bit(&mut self, bit_index: BitIndex) -> Result<(), AcceptError> {
        let (byte_index, mask) = self.get_pos_mask(bit_index)?;
        self.bits[byte_index] &= !mask;
        Ok(())
    }

    fn clear_range(&mut self, start_bit: BitIndex, end_bit: BitIndex) -> Result<(), AcceptError> {
        let bit_len = self.capacity()?;
        if start_bit.raw() > end_bit.raw() || end_bit.raw() > bit_len {
            return Err(AcceptError::OutOfBounds);
        }
        if start_bit == end_bit {
            return Ok(());
        }

        let start_byte =
            usize::try_from(start_bit.raw() >> 3).map_err(|_| AcceptError::OutOfBounds)?;
        let end_exclusive_byte =
            usize::try_from((end_bit.raw() + 7) >> 3).map_err(|_| AcceptError::OutOfBounds)?;
        let start_off = u8::try_from(start_bit.raw() & 7).map_err(|_| AcceptError::OutOfBounds)?;
        let end_off = u8::try_from(end_bit.raw() & 7).map_err(|_| AcceptError::OutOfBounds)?;

        if start_byte + 1 == end_exclusive_byte {
            // Entire range is inside one byte.
            let end_off_eff = if end_off == 0 { 8 } else { end_off };
            let clear_mask = bit_range_mask(start_off, end_off_eff);
            self.bits[start_byte] &= !clear_mask;
            return Ok(());
        }

        // Leading partial byte.
        if start_off != 0 {
            self.bits[start_byte] &= low_bits_mask(start_off);
        } else {
            self.bits[start_byte] = 0;
        }

        // Middle full bytes.
        let middle_start = start_byte + 1;
        let middle_end = if end_off == 0 {
            end_exclusive_byte
        } else {
            end_exclusive_byte - 1
        };
        if middle_start < middle_end {
            self.bits[middle_start..middle_end].fill(0);
        }

        // Trailing partial byte.
        if end_off != 0 {
            let keep_high = !low_bits_mask(end_off);
            let last = end_exclusive_byte - 1;
            self.bits[last] &= keep_high;
        }

        Ok(())
    }

    fn find_next_set(
        &self,
        start_bit: BitIndex,
        end_bit: BitIndex,
    ) -> Result<Option<BitIndex>, AcceptError> {
        self.find_next_matching(start_bit, end_bit, true)
    }

    fn find_next_zero(
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

            // SAFETY: `next <= end_bit <= bit_len` guarantees we can read exactly 8 bytes here.
            let word = unsafe {
                let ptr = self.bits.as_ptr().add(byte_index).cast::<u64>();
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
}

struct BitmapRef<'a> {
    bits: &'a [u8],
}

impl<'a> BitmapRef<'a> {
    fn new(bits: &'a [u8]) -> Self {
        Self { bits }
    }

    fn has_set_bit(&self, start_bit: BitIndex, end_bit: BitIndex) -> Result<bool, AcceptError> {
        if start_bit >= end_bit {
            return Ok(false);
        }

        let bit_len = self
            .bits
            .len()
            .checked_mul(8)
            .ok_or(AcceptError::ArithmeticOverflow)?;
        let start_bit = usize::try_from(start_bit.raw()).map_err(|_| AcceptError::OutOfBounds)?;
        let end_bit = usize::try_from(end_bit.raw()).map_err(|_| AcceptError::OutOfBounds)?;
        if end_bit > bit_len {
            return Err(AcceptError::OutOfBounds);
        }

        let mut bit = start_bit;

        // Scan head until byte alignment.
        while bit < end_bit && (bit & 7) != 0 {
            let byte_idx = bit >> 3;
            let mask = 1u8 << (bit & 7);
            if (self.bits[byte_idx] & mask) != 0 {
                return Ok(true);
            }
            bit += 1;
        }

        let mut byte_idx = bit >> 3;
        let end_full_byte = end_bit >> 3;

        // Bulk scan by u64 for full bytes.
        while byte_idx + 8 <= end_full_byte {
            // SAFETY: loop condition guarantees 8 readable bytes.
            let word = unsafe {
                let ptr = self.bits.as_ptr().add(byte_idx).cast::<u64>();
                u64::from_le(ptr.read_unaligned())
            };
            if word != 0 {
                return Ok(true);
            }
            byte_idx += 8;
        }

        while byte_idx < end_full_byte {
            if self.bits[byte_idx] != 0 {
                return Ok(true);
            }
            byte_idx += 1;
        }

        // Check tail bits in one masked-byte test.
        let tail_bits = (end_bit & 7) as u8;
        if tail_bits != 0 {
            let tail_mask = low_bits_mask(tail_bits);
            if (self.bits[end_full_byte] & tail_mask) != 0 {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct PhysAddr(u64);

impl PhysAddr {
    const fn new(raw: u64) -> Self {
        Self(raw)
    }

    const fn raw(self) -> u64 {
        self.0
    }

    fn checked_add(self, bytes: u64) -> Result<Self, AcceptError> {
        self.0
            .checked_add(bytes)
            .map(Self)
            .ok_or(AcceptError::ArithmeticOverflow)
    }

    fn checked_add_units(self, bits: BitIndex, unit_size: u64) -> Result<Self, AcceptError> {
        let bytes = bits
            .raw()
            .checked_mul(unit_size)
            .ok_or(AcceptError::ArithmeticOverflow)?;
        self.checked_add(bytes)
    }
}

/// Strongly-typed bitmap index used to avoid mixing bit position with GPA.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct BitIndex(u64);

impl BitIndex {
    const fn new(raw: u64) -> Self {
        Self(raw)
    }

    const fn raw(self) -> u64 {
        self.0
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

fn align_down(addr: u64, align: u64) -> u64 {
    addr & !(align - 1)
}

fn align_up(addr: u64, align: u64) -> Option<u64> {
    addr.checked_add(align - 1).map(|v| v & !(align - 1))
}

/// Result of a conditional accept operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AcceptOutcome {
    /// The range overlaps bitmap coverage but no unit is pending (already accepted).
    AlreadyAccepted,
    /// At least one pending unit was accepted and the corresponding bitmap bits were cleared.
    AcceptedNow {
        /// Number of bitmap units accepted by this call.
        accepted_units: u64,
    },
    /// The range does not overlap bitmap coverage.
    OutOfCoverage,
}
