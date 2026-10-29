// SPDX-License-Identifier: BSD-3-Clause
// Copyright(c) 2026 Intel Corporation.

use alloc::{boxed::Box, vec};
use core::{
    cell::Cell,
    mem::size_of,
    ops::Range,
    ptr::NonNull,
    sync::atomic::{AtomicU64, Ordering},
};
use std::{
    sync::mpsc::{self, TryRecvError},
    thread,
    time::Duration,
};

use super::{
    accept::{AcceptanceState, SHARD_COUNT},
    bitmap::BitmapRef,
    layout::{EFI_UNACCEPTED_UNIT_SIZE, LINUX_EFI_UNACCEPTED_MEM_TABLE_VERSION},
    EfiUnacceptedMemory, EfiUnacceptedMemoryBuilder,
};
use crate::AcceptError;

#[test]
fn required_size_for_range() {
    assert!(matches!(
        EfiUnacceptedMemory::required_size_for_range(0..0),
        Err(AcceptError::OutOfBounds)
    ));
    assert!(matches!(
        EfiUnacceptedMemory::required_size_for_range(Range {
            start: 100,
            end: 50
        }),
        Err(AcceptError::OutOfBounds)
    ));
    assert!(matches!(
        EfiUnacceptedMemory::required_size_for_range(0..u64::MAX),
        Err(AcceptError::ArithmeticOverflow)
    ));
    assert!(matches!(
        EfiUnacceptedMemory::required_size_for_range(
            (u64::MAX - 2 * UNIT_SIZE)..(u64::MAX - UNIT_SIZE)
        ),
        Err(AcceptError::ArithmeticOverflow)
    ));

    // 2 MiB to 6 MiB is 4 MiB = 2 units. 2 bits fit in 1 u64 (8 bytes).
    let size = EfiUnacceptedMemory::required_size_for_range(0x200_000..0x600_000).unwrap();
    assert_eq!(size, size_of::<EfiUnacceptedMemory>() + 8);
}

#[test]
fn builder_type_invariants() {
    let table = new_builder(0x200_000..0x600_000).build();

    assert_eq!(table.version(), LINUX_EFI_UNACCEPTED_MEM_TABLE_VERSION);
    assert_eq!(table.unit_size_bytes(), EFI_UNACCEPTED_UNIT_SIZE as u32);
    assert_eq!(table.bitmap_size_bytes(), 8);
    assert_eq!(table.coverage_range(), 0x200_000..0x8_200_000); // 8 bytes * 8 bits = 64 bits * 2 MiB = 128 MiB
    assert_eq!(table.bitmap_ref().count_ones(), 0);
}

#[test]
fn builder_incremental() {
    let mut builder = new_builder(0x200_000..0xe00_000);

    // Empty and aligned unit ranges only update the bitmap, without executing TDCALL.
    unsafe {
        builder.register_range(0x600_000..0x600_000).unwrap();
        builder.register_range(0x200_000..0x400_000).unwrap();
        builder.register_range(0x400_000..0x600_000).unwrap();
        builder.register_range(0xa00_000..0xe00_000).unwrap();
        assert!(matches!(
            builder.register_range(0x1ff_000..0x601_000),
            Err(AcceptError::Overlap)
        ));
    }

    let table = builder.build();
    let bitmap = table.bitmap_ref();
    assert_eq!(bitmap.count_ones(), 4);
    assert!(bitmap.is_bit_set(0));
    assert!(bitmap.is_bit_set(1));
    assert!(!bitmap.is_bit_set(2));
    assert!(!bitmap.is_bit_set(3));
    assert!(bitmap.is_bit_set(4));
    assert!(bitmap.is_bit_set(5));
}

#[test]
fn builder_invalid_inputs() {
    let coverage = 0x200_000..0x600_000;
    let required_size = EfiUnacceptedMemory::required_size_for_range(coverage.clone()).unwrap();
    let table_addr = allocate_table_buffer(required_size + 1);

    // The builder rejects the undersized buffer before initializing the table.
    let res =
        unsafe { EfiUnacceptedMemory::builder(table_addr, required_size - 1, coverage.clone()) };
    assert!(matches!(res, Err(AcceptError::OutOfBounds)));

    // The builder also rejects misalignment before touching the allocation.
    let unaligned_addr = NonNull::new(table_addr.as_ptr().wrapping_add(1)).unwrap();
    let res = unsafe { EfiUnacceptedMemory::builder(unaligned_addr, required_size, coverage) };
    assert!(matches!(res, Err(AcceptError::InvalidAlignment)));
}

#[test]
fn bitmap_word_boundaries() {
    let words = [const { AtomicU64::new(0) }; 4];
    // SAFETY: `words` is an aligned array of initialized atomic words and outlives the view.
    let bitmap = unsafe { BitmapRef::from_raw(words.as_ptr().cast::<u8>(), words.len() * 8) };

    assert_eq!(bitmap.capacity(), 256);
    assert_eq!(bitmap.find_next_set(0..256), None);

    // Set a range spanning word 0 and word 1 (e.g. bits 60..70)
    bitmap.set_range(60..70);
    assert_eq!(bitmap.find_next_set(60..70), Some(60));
    assert_eq!(bitmap.find_next_set(0..65), Some(60));
    assert_eq!(bitmap.find_next_set(0..60), None);
    assert_eq!(bitmap.find_next_set(70..256), None);
    assert_eq!(bitmap.find_next_set(0..256), Some(60));
    assert_eq!(bitmap.count_ones(), 10);

    // Check underlying raw word values
    // Bits 60..64 in word 0 are 0xF000_0000_0000_0000
    assert_eq!(words[0].load(Ordering::Relaxed), 0xF000_0000_0000_0000);
    // Bits 64..70 (bits 0..6 of word 1) are 0x3F
    assert_eq!(words[1].load(Ordering::Relaxed), 0x3F);

    for bit in 62..68 {
        assert!(bitmap.clear_bit(bit));
    }
    assert_eq!(bitmap.count_ones(), 4); // 60, 61 and 68, 69
    assert_eq!(bitmap.find_next_set(0..256), Some(60));
    assert_eq!(bitmap.find_next_set(62..256), Some(68));
    assert_eq!(bitmap.find_next_set(70..256), None);

    assert!(bitmap.is_bit_set(60));
    assert!(bitmap.clear_bit(60));
    assert!(!bitmap.is_bit_set(60));
    assert!(!bitmap.clear_bit(60));
    assert!(!bitmap.is_bit_set(256));
    assert!(!bitmap.clear_bit(256));
}

#[test]
fn accepts_whole_units_before_publishing_completion() {
    let second_bit = SHARD_COUNT as u64;
    let state = new_state(&[0, second_bit, second_bit + 1]);
    let disabled = Cell::new(false);
    let drops = Cell::new(0);
    let mut accepted_units = vec![];
    state
        .ensure_accepted_with(
            unit_range(0).start + 4096..unit_range(second_bit).end - 4096,
            || TestIrqGuard::new(&state, &disabled, &drops),
            |unit| {
                let bit = (unit.start - UNIT_SIZE) / UNIT_SIZE;
                assert!(disabled.get());
                assert!(state.shard_locks[bit as usize % SHARD_COUNT]
                    .try_lock()
                    .is_none());
                assert!(state.table.bitmap_ref().is_bit_set(bit));
                assert_eq!(
                    state.unaccepted_bytes(),
                    (3 - accepted_units.len()) * UNIT_SIZE as usize
                );
                accepted_units.push(unit);
                Ok(())
            },
        )
        .unwrap();

    assert_eq!(accepted_units, vec![unit_range(0), unit_range(second_bit)]);
    assert_eq!(drops.get(), 2);
    assert!(!disabled.get());
    assert_eq!(state.unaccepted_bytes(), UNIT_SIZE as usize);
    assert_eq!(
        state.table.bitmap_ref().find_next_set(0..second_bit + 1),
        None
    );

    let coverage_end = state.table.coverage_range().end;
    for range in [
        unit_range(0).start..unit_range(second_bit).end,
        UNIT_SIZE..UNIT_SIZE,
        0..UNIT_SIZE,
        coverage_end..u64::MAX,
    ] {
        state
            .ensure_accepted_with(
                range,
                || panic!("ranges without pending units must not disable interrupts"),
                |_| panic!("ranges without pending units must not be accepted"),
            )
            .unwrap();
    }
}

#[test]
fn errors_preserve_pending_units_and_release_guards() {
    let state = new_state(&[0, 1, 2]);
    let disabled = Cell::new(false);
    let drops = Cell::new(0);
    let mut attempted_units = vec![];
    let result = state.ensure_accepted_with(
        UNIT_SIZE..4 * UNIT_SIZE,
        || TestIrqGuard::new(&state, &disabled, &drops),
        |unit| {
            assert!(disabled.get());
            attempted_units.push(unit);
            if attempted_units.len() == 2 {
                return Err(AcceptError::InvalidAlignment);
            }
            Ok(())
        },
    );

    assert!(matches!(result, Err(AcceptError::InvalidAlignment)));
    assert_eq!(attempted_units, vec![unit_range(0), unit_range(1)]);
    assert_eq!(drops.get(), 2);
    assert!(!disabled.get());
    assert!(!state.table.bitmap_ref().is_bit_set(0));
    assert!(state.table.bitmap_ref().is_bit_set(1));
    assert!(state.table.bitmap_ref().is_bit_set(2));
    assert_eq!(state.unaccepted_bytes(), 2 * UNIT_SIZE as usize);
}

#[test]
fn overlapping_callers_wait_for_acceptance() {
    let state = new_state(&[0, 1]);
    let state = &state;
    let (started_tx, started_rx) = mpsc::channel();
    let (release_tx, release_rx) = mpsc::channel();
    let (waiting_tx, waiting_rx) = mpsc::channel();
    let (finished_tx, finished_rx) = mpsc::channel();

    thread::scope(|scope| {
        scope.spawn(move || {
            state
                .ensure_accepted_with(
                    unit_range(0),
                    || (),
                    |_| {
                        started_tx.send(()).unwrap();
                        release_rx.recv_timeout(WAIT_TIMEOUT).unwrap();
                        Ok(())
                    },
                )
                .unwrap();
        });
        started_rx.recv_timeout(WAIT_TIMEOUT).unwrap();
        assert!(state.table.bitmap_ref().is_bit_set(0));
        assert_eq!(state.unaccepted_bytes(), 2 * UNIT_SIZE as usize);

        scope.spawn(move || {
            let mut accepted_units = vec![];
            state
                .ensure_accepted_with(
                    unit_range(0).start..unit_range(1).end,
                    || waiting_tx.send(()).unwrap(),
                    |unit| {
                        accepted_units.push(unit);
                        Ok(())
                    },
                )
                .unwrap();
            assert_eq!(accepted_units, vec![unit_range(1)]);
            finished_tx.send(()).unwrap();
        });
        waiting_rx.recv_timeout(WAIT_TIMEOUT).unwrap();
        assert!(matches!(finished_rx.try_recv(), Err(TryRecvError::Empty)));
        release_tx.send(()).unwrap();
        finished_rx.recv_timeout(WAIT_TIMEOUT).unwrap();
    });

    assert_eq!(state.table.bitmap_ref().count_ones(), 0);
    assert_eq!(state.unaccepted_bytes(), 0);
}

#[test]
fn different_shards_accept_concurrently() {
    let state = new_state(&[0, 1]);
    let state = &state;
    let (started_tx, started_rx) = mpsc::channel();
    let (release_first_tx, release_first_rx) = mpsc::channel();
    let (release_second_tx, release_second_rx) = mpsc::channel();

    thread::scope(|scope| {
        for (bit, release_rx) in [(0, release_first_rx), (1, release_second_rx)] {
            let started_tx = started_tx.clone();
            scope.spawn(move || {
                state
                    .ensure_accepted_with(
                        unit_range(bit),
                        || (),
                        |_| {
                            started_tx.send(bit).unwrap();
                            release_rx.recv_timeout(WAIT_TIMEOUT).unwrap();
                            Ok(())
                        },
                    )
                    .unwrap();
            });
        }
        let first = started_rx.recv_timeout(WAIT_TIMEOUT).unwrap();
        let second = started_rx.recv_timeout(WAIT_TIMEOUT).unwrap();
        assert_ne!(first, second);
        assert_eq!(state.unaccepted_bytes(), 2 * UNIT_SIZE as usize);
        assert_eq!(state.table.bitmap_ref().count_ones(), 2);
        release_first_tx.send(()).unwrap();
        release_second_tx.send(()).unwrap();
    });

    assert_eq!(state.unaccepted_bytes(), 0);
    assert_eq!(state.table.bitmap_ref().count_ones(), 0);
}

const UNIT_SIZE: u64 = EFI_UNACCEPTED_UNIT_SIZE;
const WAIT_TIMEOUT: Duration = Duration::from_secs(10);

fn allocate_table_buffer(size: usize) -> NonNull<u8> {
    let words = Box::leak(vec![0u64; size.div_ceil(size_of::<u64>())].into_boxed_slice());
    NonNull::new(words.as_mut_ptr().cast()).unwrap()
}

fn new_builder(coverage: Range<u64>) -> EfiUnacceptedMemoryBuilder {
    let size = EfiUnacceptedMemory::required_size_for_range(coverage.clone()).unwrap();
    let table_addr = allocate_table_buffer(size);

    // SAFETY: The leaked allocation is aligned, large enough, and exclusively
    // accessed through the builder and resulting table from this point on.
    unsafe { EfiUnacceptedMemory::builder(table_addr, size, coverage).unwrap() }
}

fn new_state(pending_bits: &[u64]) -> AcceptanceState {
    let table = {
        let unit_count = pending_bits
            .iter()
            .copied()
            .max()
            .map_or(1, |max_bit| max_bit + 1);
        let coverage = UNIT_SIZE..(unit_count + 1) * UNIT_SIZE;
        new_builder(coverage).build().into_ref().get_ref()
    };

    // Simulate pending units without executing TDCALL during test setup.
    let bitmap = table.bitmap_ref();
    for &bit in pending_bits {
        bitmap.set_range(bit..bit + 1);
    }
    AcceptanceState::new(table)
}

fn unit_range(bit: u64) -> Range<u64> {
    (bit + 1) * UNIT_SIZE..(bit + 2) * UNIT_SIZE
}

struct TestIrqGuard<'a> {
    state: &'a AcceptanceState,
    disabled: &'a Cell<bool>,
    drops: &'a Cell<usize>,
}

impl<'a> TestIrqGuard<'a> {
    fn new(state: &'a AcceptanceState, disabled: &'a Cell<bool>, drops: &'a Cell<usize>) -> Self {
        assert!(!disabled.replace(true));
        assert!(state
            .shard_locks
            .iter()
            .all(|lock| lock.try_lock().is_some()));
        Self {
            state,
            disabled,
            drops,
        }
    }
}

impl Drop for TestIrqGuard<'_> {
    fn drop(&mut self) {
        assert!(self
            .state
            .shard_locks
            .iter()
            .all(|lock| lock.try_lock().is_some()));
        assert!(self.disabled.replace(false));
        self.drops.set(self.drops.get() + 1);
    }
}
