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

/// Unit size for unaccepted-memory bitmap entries (2 MiB).
pub const EFI_UNACCEPTED_UNIT_SIZE: u64 = 2 * 1024 * 1024;

/// Header of the Linux-compatible EFI unaccepted-memory table.
///
/// This type describes only the fixed-size header. The bitmap payload is stored
/// immediately after the header in memory (C-style trailing data):
///
/// ### Memory Layout
/// The total memory footprint is `size_of::<EfiUnacceptedMemory>() + self.size`.
/// The bitmap begins at the first byte following this structure.
///
/// ### Bitmap Semantics
/// - Each bit in the trailing bitmap represents a memory region of `unit_size` bytes.
/// - Bit 0 corresponds to the physical address specified by `phys_base`.
/// - A **set bit (1)** indicates memory is unaccepted (pending);
///   a **cleared bit (0)** indicates it has been accepted.
#[derive(Copy, Clone, Debug)]
#[repr(C, packed)]
pub struct EfiUnacceptedMemory {
    /// The version of the table. Currently, only version 1 is defined.
    pub version: u32,
    /// The size of the memory region represented by a single bit in the bitmap.
    /// Typically set to 2MiB (0x200000) to align with huge page boundaries.
    pub unit_size: u32,
    /// The start physical address of the memory range covered by this bitmap.
    /// Bit 0 of the bitmap corresponds to this address.
    pub phys_base: u64,
    /// The bitmap payload length in bytes, excluding this header.
    pub size: u64,
}

impl EfiUnacceptedMemory {
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
    /// Returns [`AcceptError::InvalidAlignment`] if `start + size` overflows.
    /// Propagates any error from [`EfiUnacceptedMemory::accept_range`].
    pub unsafe fn accept_by_size(&mut self, start: u64, size: u64) -> Result<(), AcceptError> {
        let Some(end) = start.checked_add(size) else {
            return Err(AcceptError::InvalidAlignment);
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
    /// Returns [`AcceptError::InvalidAlignment`] for invalid unit configuration,
    /// index/address arithmetic overflow, or bitmap/index conversion failures.
    /// Returns hardware-originated failures from `accept_memory` via
    /// [`AcceptError::TdCall`].
    pub unsafe fn accept_range(&mut self, start: u64, end: u64) -> Result<(), AcceptError> {
        let Some((range_start, range_end, unit_size)) =
            self.clamp_gpa_range_to_bitmap_coverage(start, end)?
        else {
            return Ok(());
        };

        let (first_bit, last_bit) = self.addr_to_bit_range(range_start, range_end, unit_size)?;
        let phys_base = self.phys_base;

        // SAFETY: Caller guarantees table/bitmap validity and exclusive mutable access.
        let mut bitmap = BitmapMut::new(unsafe { self.as_bitmap_slice_mut() });

        let mut scan = first_bit;
        while let Some(run_start) = bitmap.find_next_set(scan, last_bit)? {
            let run_end = bitmap
                .find_next_zero(run_start, last_bit)?
                .unwrap_or(last_bit);

            let run_gpa_start = phys_base
                .checked_add(
                    run_start
                        .checked_mul(unit_size)
                        .ok_or(AcceptError::InvalidAlignment)?,
                )
                .ok_or(AcceptError::InvalidAlignment)?;
            let run_gpa_end = phys_base
                .checked_add(
                    run_end
                        .checked_mul(unit_size)
                        .ok_or(AcceptError::InvalidAlignment)?,
                )
                .ok_or(AcceptError::InvalidAlignment)?;

            // SAFETY: Caller guarantees bitmap/GPA mapping validity for pending private pages.
            unsafe { accept_memory(run_gpa_start, run_gpa_end)? };

            let mut clear = run_start;
            while clear < run_end {
                bitmap.clear_bit(clear)?;
                clear += 1;
            }

            scan = run_end;
        }

        Ok(())
    }

    /// Returns the end GPA (exclusive) covered by the bitmap.
    ///
    /// This is equivalent to `phys_base + total_coverage_size()`.
    pub fn bitmap_coverage_end(&self) -> Option<u64> {
        self.phys_base.checked_add(self.total_coverage_size()?)
    }

    /// Returns an immutable slice view of the trailing bitmap payload.
    ///
    /// # Safety
    ///
    /// The caller must ensure that this header is followed by at least `self.size`
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
        // after `self`; `bitmap_len` is validated from `self.size`; caller guarantees
        // readable backing memory for the returned slice.
        unsafe { core::slice::from_raw_parts(bitmap_ptr, bitmap_len) }
    }

    /// Returns a mutable slice view of the trailing bitmap payload.
    ///
    /// # Safety
    ///
    /// The caller must ensure that this header is followed by at least `self.size`
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
        // after `self`; `bitmap_len` is validated from `self.size`; caller guarantees
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
    /// Returns [`AcceptError::InvalidAlignment`] for invalid unit configuration or
    /// arithmetic overflows. Returns hardware-originated errors from `accept_memory`
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
                return Err(AcceptError::InvalidAlignment);
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
            return Err(AcceptError::InvalidAlignment);
        };

        let Some(bitmap_end) = table_phys_base.checked_add(bitmap_coverage) else {
            return Err(AcceptError::InvalidAlignment);
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
        let unit_size = u64::from(self.unit_size);
        self.size.checked_mul(unit_size)?.checked_mul(8)
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
            .ok_or(AcceptError::InvalidAlignment)?;
        let abs_end = self
            .phys_base
            .checked_add(end)
            .ok_or(AcceptError::InvalidAlignment)?;

        // SAFETY: Caller guarantees bitmap-relative range correctness and exclusive access.
        unsafe { self.mark_range_as_unaccepted(abs_start, abs_end, unit_size) }
    }

    fn total_bits(&self) -> Result<u64, AcceptError> {
        self.size
            .checked_mul(8)
            .ok_or(AcceptError::InvalidAlignment)
    }

    fn byte_len(&self) -> Result<usize, AcceptError> {
        usize::try_from(self.size).map_err(|_| AcceptError::InvalidAlignment)
    }

    fn validated_unit_size(&self) -> Result<u64, AcceptError> {
        let unit_size = u64::from(self.unit_size);
        if unit_size == 0 || !unit_size.is_power_of_two() {
            return Err(AcceptError::InvalidAlignment);
        }
        Ok(unit_size)
    }

    fn max_phys_addr_exclusive(&self, unit_size: u64) -> Result<u64, AcceptError> {
        let total_bits = self.total_bits()?;
        let coverage_len = total_bits
            .checked_mul(unit_size)
            .ok_or(AcceptError::InvalidAlignment)?;
        self.phys_base
            .checked_add(coverage_len)
            .ok_or(AcceptError::InvalidAlignment)
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
    ) -> Result<(u64, u64), AcceptError> {
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
            .ok_or(AcceptError::InvalidAlignment)?
            / unit_size;

        Ok((first_bit, last_bit))
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

        let start_bit = (start - self.phys_base) / unit_size;
        let end_bit = (end - self.phys_base) / unit_size;
        let total_bits = self.total_bits()?;

        let clamped_start_bit = start_bit.min(total_bits);
        let clamped_end_bit = end_bit.min(total_bits);
        if clamped_start_bit >= clamped_end_bit {
            return Ok(());
        }

        // SAFETY: Caller guarantees bitmap memory is writable and uniquely accessible.
        let mut bitmap = BitmapMut::new(unsafe { self.as_bitmap_slice_mut() });
        for bit in clamped_start_bit..clamped_end_bit {
            bitmap.set_bit(bit)?;
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

struct BitmapMut<'a> {
    bits: &'a mut [u8],
}

impl<'a> BitmapMut<'a> {
    fn new(bits: &'a mut [u8]) -> Self {
        Self { bits }
    }

    fn capacity(&self) -> Result<u64, AcceptError> {
        let len = u64::try_from(self.bits.len()).map_err(|_| AcceptError::InvalidAlignment)?;
        len.checked_mul(8).ok_or(AcceptError::InvalidAlignment)
    }

    fn get_pos_mask(&self, bit_index: u64) -> Result<(usize, u8), AcceptError> {
        if bit_index >= self.capacity()? {
            return Err(AcceptError::InvalidAlignment);
        }

        let byte_index =
            usize::try_from(bit_index >> 3).map_err(|_| AcceptError::InvalidAlignment)?;
        let mask = 1u8 << (bit_index & 7);
        Ok((byte_index, mask))
    }

    fn is_set(&self, bit_index: u64) -> Result<bool, AcceptError> {
        let (byte_index, mask) = self.get_pos_mask(bit_index)?;
        Ok((self.bits[byte_index] & mask) != 0)
    }

    fn set_bit(&mut self, bit_index: u64) -> Result<(), AcceptError> {
        let (byte_index, mask) = self.get_pos_mask(bit_index)?;
        self.bits[byte_index] |= mask;
        Ok(())
    }

    fn clear_bit(&mut self, bit_index: u64) -> Result<(), AcceptError> {
        let (byte_index, mask) = self.get_pos_mask(bit_index)?;
        self.bits[byte_index] &= !mask;
        Ok(())
    }

    fn find_next_set(&self, start_bit: u64, end_bit: u64) -> Result<Option<u64>, AcceptError> {
        self.find_next_matching(start_bit, end_bit, true)
    }

    fn find_next_zero(&self, start_bit: u64, end_bit: u64) -> Result<Option<u64>, AcceptError> {
        self.find_next_matching(start_bit, end_bit, false)
    }

    fn find_next_matching(
        &self,
        start_bit: u64,
        end_bit: u64,
        target: bool,
    ) -> Result<Option<u64>, AcceptError> {
        let bit_len = self.capacity()?;
        if start_bit > end_bit || end_bit > bit_len {
            return Err(AcceptError::InvalidAlignment);
        }

        if start_bit == end_bit {
            return Ok(None);
        }

        let mut scan_bit = start_bit;

        // Scan leading bits until the index is 64-bit aligned.
        while scan_bit < end_bit && (scan_bit & 63) != 0 {
            if self.is_set(scan_bit)? == target {
                return Ok(Some(scan_bit));
            }
            scan_bit += 1;
        }

        // Bulk scan by 64-bit words.
        while end_bit - scan_bit >= 64 {
            let next = scan_bit + 64;

            let byte_index =
                usize::try_from(scan_bit >> 3).map_err(|_| AcceptError::InvalidAlignment)?;

            // SAFETY: `next <= end_bit <= bit_len` guarantees we can read exactly 8 bytes here.
            let word = unsafe {
                let ptr = self.bits.as_ptr().add(byte_index).cast::<u64>();
                u64::from_le(ptr.read_unaligned())
            };

            let match_word = if target { word } else { !word };
            if match_word != 0 {
                let delta = u64::from(match_word.trailing_zeros());
                let found = scan_bit + delta;
                return Ok(Some(found));
            }

            scan_bit = next;
        }

        // Scan remaining tail bits (< 64).
        while scan_bit < end_bit {
            if self.is_set(scan_bit)? == target {
                return Ok(Some(scan_bit));
            }
            scan_bit += 1;
        }

        Ok(None)
    }
}

fn align_down(addr: u64, align: u64) -> u64 {
    addr & !(align - 1)
}

fn align_up(addr: u64, align: u64) -> Option<u64> {
    addr.checked_add(align - 1).map(|v| v & !(align - 1))
}
