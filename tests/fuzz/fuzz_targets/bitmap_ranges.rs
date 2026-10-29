#![no_main]

use core::sync::atomic::{AtomicU64, Ordering};

use libfuzzer_sys::fuzz_target;

// Test the private implementation without exposing bitmap mutation in the library API.
#[path = "../../../src/unaccepted_memory/bitmap.rs"]
mod bitmap;

use bitmap::BitmapRef;

fuzz_target!(|data: &[u8]| {
    if data.len() < 2 {
        return;
    }

    let word_count = usize::from(data[0] % 4) + 1;
    let words_end = 2 + word_count * 8;
    if data.len() < words_end + 32 {
        return;
    }

    let words: Vec<_> = data[2..words_end]
        .chunks_exact(8)
        .map(|chunk| AtomicU64::new(u64::from_le_bytes(chunk.try_into().unwrap())))
        .collect();
    // SAFETY: The initialized atomic words are aligned and outlive the bitmap view.
    let bitmap = unsafe {
        BitmapRef::from_raw(
            words.as_ptr().cast(),
            words.len() * core::mem::size_of::<AtomicU64>(),
        )
    };
    let mut expected: Vec<bool> = (0..word_count * 64)
        .map(|bit| words[bit / 64].load(Ordering::Relaxed) & (1 << (bit % 64)) != 0)
        .collect();

    assert_eq!(bitmap.capacity(), expected.len() as u64);
    assert_eq!(
        bitmap.pending_unit_count(),
        expected.iter().filter(|&&bit| bit).count() as u64
    );

    let ranges = [
        (
            u64::from_le_bytes(data[words_end..words_end + 8].try_into().unwrap()),
            u64::from_le_bytes(data[words_end + 8..words_end + 16].try_into().unwrap()),
        ),
        (
            u64::from_le_bytes(data[words_end + 16..words_end + 24].try_into().unwrap()),
            u64::from_le_bytes(data[words_end + 24..words_end + 32].try_into().unwrap()),
        ),
    ];

    for (start, end) in ranges {
        let expected_first = if start >= end {
            None
        } else {
            let capped_end = end.min(expected.len() as u64);
            (start..capped_end).find(|&bit| expected[bit as usize])
        };

        assert_eq!(bitmap.find_next_set(start, end), expected_first);
        assert_eq!(
            bitmap.is_bit_set(start),
            start < expected.len() as u64 && expected[start as usize]
        );

        let bounded_start = start.min(expected.len() as u64);
        let bounded_end = end.min(expected.len() as u64);
        if bounded_start < bounded_end {
            for bit in bounded_start..bounded_end {
                expected[bit as usize] = true;
            }
        }
        bitmap.set_range(start, end);
        assert_eq!(
            bitmap.pending_unit_count(),
            expected.iter().filter(|&&bit| bit).count() as u64
        );

        if bounded_start < bounded_end {
            for bit in bounded_start..bounded_end {
                let was_set = core::mem::replace(&mut expected[bit as usize], false);
                assert_eq!(bitmap.clear_bit(bit), was_set);
            }
        }
        if start >= expected.len() as u64 {
            assert!(!bitmap.clear_bit(start));
        }
        assert_eq!(
            bitmap.pending_unit_count(),
            expected.iter().filter(|&&bit| bit).count() as u64
        );
    }

    bitmap.clear_all();
    assert_eq!(bitmap.pending_unit_count(), 0);
});
