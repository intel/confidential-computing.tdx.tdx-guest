// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2026 Intel Corporation.

//! Support for unaccepted memory in TDX guest environments.
//!
//! This module provides mechanisms to manage and accept
//! unaccepted memory regions in TDX guests.
//! The core data structure is [`EfiUnacceptedMemory`],
//! which represents the EFI table header
//! and provides methods to manipulate the unaccepted memory bitmap
//! and perform acceptance operations.

mod accept;
mod bitmap;
mod layout;
mod query;
mod register;

use bitmap::BitIndex;

use crate::AcceptError;

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
#[derive(Copy, Clone, Debug)]
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

    /// Returns the total physical address range (in bytes) covered by the bitmap.
    ///
    /// Returns `None` if the computation overflows.
    pub fn total_coverage_size(&self) -> Option<u64> {
        let unit_size = u64::from(self.unit_size_bytes);
        self.bitmap_size_bytes
            .checked_mul(unit_size)?
            .checked_mul(8)
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
        self.raw()
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

fn align_down(addr: u64, align: u64) -> u64 {
    addr & !(align - 1)
}

fn align_up(addr: u64, align: u64) -> Option<u64> {
    addr.checked_add(align - 1).map(|v| v & !(align - 1))
}

/// Status of a memory range with respect to TDX acceptance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryStatus {
    /// Every bitmap unit in the queried range has been accepted (or the range
    /// is outside bitmap coverage).
    AllAccepted,
    /// At least one bitmap unit in the queried range is still pending acceptance.
    HasPending,
}
