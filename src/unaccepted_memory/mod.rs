// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2026 Intel Corporation.

//! Support for unaccepted memory in TDX guest environments.
//!
//! This module provides mechanisms to manage and accept
//! unaccepted memory regions in TDX guests.
//! Build an [`EfiUnacceptedMemory`] table with [`EfiUnacceptedMemoryBuilder`],
//! register it with [`init_acceptance_state`], and use [`ensure_accepted`] before
//! accessing pending memory.

mod accept;
mod bitmap;
mod layout;
mod register;
#[cfg(test)]
mod tests;

pub use accept::{
    ensure_accepted, init_acceptance_state, unaccepted_bytes, unaccepted_memory_table,
};
pub use layout::EfiUnacceptedMemory;
pub use register::EfiUnacceptedMemoryBuilder;
