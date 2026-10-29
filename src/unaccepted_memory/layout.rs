// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2026 Intel Corporation.

//! Table layout, address mapping, and alignment helpers for unaccepted-memory metadata.

use core::{
    marker::PhantomPinned,
    mem::{align_of, size_of},
    ops::Range,
    pin::Pin,
    ptr::NonNull,
    sync::atomic::AtomicU64,
};

use super::{
    bitmap::{BitIndex, BitmapRef},
    EfiUnacceptedMemoryBuilder,
};
use crate::AcceptError;

/// Header of the Linux-compatible EFI unaccepted-memory table.
///
/// This struct describes only the fixed-size header; the variable-length bitmap
/// is stored immediately after it in memory, so mutable access is restricted to
/// [`Pin<&mut Self>`](Pin) to prevent moving the header away from its trailing
/// bitmap.
///
/// Each bitmap bit covers [`Self::unit_size_bytes`] bytes starting at the base
/// of [`Self::coverage_range`]: `1` indicates unaccepted (pending) memory and
/// `0` indicates accepted memory.
//
// Type invariants for any valid `&Self` or `Pin<&mut Self>`:
// - Immediately followed by `bitmap_size_bytes` initialized bytes, aligned to
//   `align_of::<AtomicU64>()` and accessed only atomically.
// - `unit_size_bytes` is a non-zero power of two, and `coverage_range()` does
//   not overflow `u64`.
#[derive(Debug)]
#[repr(C)]
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
    _pinned: PhantomPinned,
}

impl EfiUnacceptedMemory {
    /// Returns the allocation size required for a table covering `coverage`.
    pub fn required_size_for_range(coverage: Range<u64>) -> Result<usize, AcceptError> {
        Ok(BitmapLayout::from_range(coverage)?.table_size_bytes)
    }

    /// Initializes a table header and zeroed bitmap in caller-provided memory,
    /// returning an [`EfiUnacceptedMemoryBuilder`] to register unaccepted ranges.
    ///
    /// # Safety
    ///
    /// `table_addr` must point to a writable allocation of at least
    /// `allocation_size` bytes that remains valid and is accessed only through
    /// the returned builder and table for `'static`.
    pub unsafe fn builder(
        table_addr: NonNull<u8>,
        allocation_size: usize,
        coverage: Range<u64>,
    ) -> Result<EfiUnacceptedMemoryBuilder, AcceptError> {
        const {
            assert!(size_of::<EfiUnacceptedMemory>().is_multiple_of(align_of::<AtomicU64>()));
        }

        let bitmap_layout = BitmapLayout::from_range(coverage)?;

        if !table_addr
            .as_ptr()
            .addr()
            .is_multiple_of(align_of::<AtomicU64>())
        {
            return Err(AcceptError::InvalidAlignment);
        }
        if allocation_size < bitmap_layout.table_size_bytes {
            return Err(AcceptError::OutOfBounds);
        }

        let table = {
            let table_ptr = table_addr.cast::<Self>().as_ptr();
            // SAFETY: `table_addr` is aligned and points to at least `table_size_bytes`
            // writable bytes with unique `'static` access. Initializing the header
            // and zeroing the trailing bitmap establishes `Self`'s type invariants,
            // and the `'static` allocation is never moved or deallocated.
            unsafe {
                table_ptr.write(Self {
                    version: LINUX_EFI_UNACCEPTED_MEM_TABLE_VERSION,
                    unit_size_bytes: EFI_UNACCEPTED_UNIT_SIZE as u32,
                    phys_base: bitmap_layout.phys_base,
                    bitmap_size_bytes: bitmap_layout.bitmap_size_bytes as u64,
                    _pinned: PhantomPinned,
                });
                table_addr
                    .as_ptr()
                    .add(size_of::<Self>())
                    .write_bytes(0, bitmap_layout.bitmap_size_bytes);

                Pin::new_unchecked(&mut *table_ptr)
            }
        };

        Ok(EfiUnacceptedMemoryBuilder::new(table))
    }

    /// Returns the unit size represented by one bitmap bit, in bytes.
    pub const fn unit_size_bytes(&self) -> u32 {
        self.unit_size_bytes
    }

    /// Returns the trailing bitmap payload length, in bytes.
    pub const fn bitmap_size_bytes(&self) -> u64 {
        self.bitmap_size_bytes
    }

    /// Returns the physical address range covered by the bitmap.
    ///
    /// Because the trailing bitmap is allocated in 64-bit words, this range is
    /// rounded up to a multiple of `64 * self.unit_size_bytes()` from `phys_base`;
    /// any trailing bits not registered via [`EfiUnacceptedMemoryBuilder::register_range`]
    /// remain `0` (already accepted).
    pub const fn coverage_range(&self) -> Range<u64> {
        let total_bits = self.bitmap_size_bytes * 8;
        let end = self.phys_base + total_bits * (self.unit_size_bytes as u64);
        self.phys_base..end
    }

    #[cfg(test)]
    pub(super) const fn version(&self) -> u32 {
        self.version
    }

    /// Converts a GPA range into an overlapping bitmap bit range.
    ///
    /// Returns `None` when there is no overlap with bitmap coverage.
    pub(super) fn overlapping_bit_range(&self, range: Range<u64>) -> Option<Range<BitIndex>> {
        let coverage = self.coverage_range();
        let range_start = range.start.max(coverage.start);
        let range_end = range.end.min(coverage.end);
        if range_start >= range_end {
            return None;
        }

        let unit_size = u64::from(self.unit_size_bytes);
        let first_bit = (range_start - self.phys_base) / unit_size;
        let last_bit = (range_end - self.phys_base).div_ceil(unit_size);

        Some(first_bit..last_bit)
    }

    /// Returns the physical address range corresponding to `bit`.
    pub(super) const fn unit_range(&self, bit: BitIndex) -> Range<u64> {
        let unit_size = self.unit_size_bytes as u64;
        let start = self.phys_base + bit * unit_size;
        start..start + unit_size
    }

    /// Returns an atomic view of the trailing bitmap.
    pub(super) fn bitmap_ref(&self) -> BitmapRef<'_> {
        let bitmap_len = self.bitmap_size_bytes as usize;
        let bitmap_ptr = core::ptr::from_ref(self)
            .cast::<u8>()
            .wrapping_add(size_of::<Self>());
        // SAFETY: By `Self`'s type invariants, the header is immediately followed by
        // `self.bitmap_size_bytes` initialized, `AtomicU64`-aligned bytes accessed only atomically.
        unsafe { BitmapRef::from_raw(bitmap_ptr, bitmap_len) }
    }
}

struct BitmapLayout {
    phys_base: u64,
    bitmap_size_bytes: usize,
    table_size_bytes: usize,
}

impl BitmapLayout {
    /// Computes the physical base address and required bitmap/table sizes (in bytes)
    /// to cover memory within `range`.
    fn from_range(range: Range<u64>) -> Result<Self, AcceptError> {
        if range.start >= range.end {
            return Err(AcceptError::OutOfBounds);
        }

        let phys_base = align_down(range.start, EFI_UNACCEPTED_UNIT_SIZE);
        let coverage_end =
            align_up(range.end, EFI_UNACCEPTED_UNIT_SIZE).ok_or(AcceptError::ArithmeticOverflow)?;
        let bitmap_words = ((coverage_end - phys_base) / EFI_UNACCEPTED_UNIT_SIZE).div_ceil(64);

        // Ensure `EfiUnacceptedMemory::coverage_range()` (which covers all bits
        // in `bitmap_words`) cannot overflow `u64`.
        let total_coverage_bytes = bitmap_words
            .checked_mul(64 * EFI_UNACCEPTED_UNIT_SIZE)
            .ok_or(AcceptError::ArithmeticOverflow)?;
        phys_base
            .checked_add(total_coverage_bytes)
            .ok_or(AcceptError::ArithmeticOverflow)?;

        let bitmap_size_bytes = usize::try_from(bitmap_words * size_of::<u64>() as u64)
            .map_err(|_| AcceptError::OutOfBounds)?;
        let table_size_bytes = size_of::<EfiUnacceptedMemory>()
            .checked_add(bitmap_size_bytes)
            .ok_or(AcceptError::ArithmeticOverflow)?;

        Ok(Self {
            phys_base,
            bitmap_size_bytes,
            table_size_bytes,
        })
    }
}

pub(super) const fn align_down(addr: u64, align: u64) -> u64 {
    addr & !(align - 1)
}

pub(super) fn align_up(addr: u64, align: u64) -> Option<u64> {
    addr.checked_add(align - 1).map(|v| v & !(align - 1))
}

/// Version of the Linux-compatible unaccepted-memory EFI table supported here.
pub(super) const LINUX_EFI_UNACCEPTED_MEM_TABLE_VERSION: u32 = 1;

/// Unit size for unaccepted-memory bitmap entries (2 MiB).
pub(super) const EFI_UNACCEPTED_UNIT_SIZE: u64 = 2 * 1024 * 1024;
