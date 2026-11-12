// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2026 Intel Corporation.

//! Support for unaccepted memory in TDX guest environments.
//!
//! This module provides mechanisms to manage and accept
//! unaccepted memory regions in TDX guests.
//! Build an [`EfiUnacceptedMemory`] table with [`EfiUnacceptedMemoryBuilder`],
//! and call [`EfiUnacceptedMemory::ensure_accepted`] before accessing pending memory.

mod accept;
mod bitmap;
mod layout;
mod register;
#[cfg(test)]
mod tests;

pub use layout::EfiUnacceptedMemory;
pub use register::EfiUnacceptedMemoryBuilder;
