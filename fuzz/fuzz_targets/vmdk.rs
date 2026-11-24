// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! Fuzzes the VMDK reader: the sparse header, grain directory and tables,
//! compressed grains and descriptors. Every extent a descriptor names resolves
//! to the input itself or to a fixed patterned file, so flat, sparse and zero
//! extents are all reached.

#![no_main]

use std::sync::Arc;

use atlas_fs_core::error::Result;
use atlas_vmdk::VmdkSource;
use atlas_fs_core::io::block::{BlockSource, MemSource};
use libfuzzer_sys::fuzz_target;

/// Most disk bytes read per input, so a large claimed size costs little time.
const READ_LIMIT: u64 = 1 << 20;
/// Bytes per read: not a multiple of any block size, so reads straddle blocks.
const STEP: usize = 64 * 1024 + 1;

fuzz_target!(|data: &[u8]| {
    let file: Arc<dyn BlockSource> = Arc::new(MemSource::new(data));
    let input: Arc<[u8]> = Arc::from(data);
    let resolve = |name: &str| -> Result<Arc<dyn BlockSource>> {
        // Names ending in `s` get the input as a sparse extent, the rest a
        // small patterned flat file.
        if name.ends_with('s') {
            Ok(Arc::new(MemSource::new(Arc::clone(&input))))
        } else {
            Ok(Arc::new(MemSource::new(vec![0xA5u8; 8192])))
        }
    };
    let Ok(disk) = VmdkSource::new(file, &resolve) else {
        return;
    };
    let end = disk.len().min(READ_LIMIT);
    let mut buf = vec![0u8; STEP];
    let mut pos = 0;
    while pos < end {
        let n = usize::try_from(end - pos).map_or(STEP, |left| left.min(STEP));
        if disk.read_at(pos, &mut buf[..n]).is_err() {
            break;
        }
        pos += n as u64;
    }
    // Read the start again, after the walk.
    if end > 0 {
        let _ = disk.read_bulk(0, &mut buf[..1]);
    }
    // And the last byte of the disk.
    if !disk.is_empty() {
        let _ = disk.read_at(disk.len() - 1, &mut buf[..1]);
    }
});
