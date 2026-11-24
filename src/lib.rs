// SPDX-License-Identifier: MIT OR Apache-2.0
// Copyright (C) 2026 Julian A. Loy.

//! VMware virtual disk (`.vmdk`): monolithic sparse, stream-optimized, and
//! descriptor files over flat and sparse extents.
//!
//! # Layout
//!
//! Source: "Virtual Disk Format 5.0" and "Virtual Disk Format 1.1",
//! VMware, public. Sizes are in 512-byte sectors; integers little-endian.
//!
//! A sparse extent starts with a 512-byte header: `KDMV`, the version (1 to
//! 3), flags, the capacity (u64 at 12), the grain size (u64 at 20), the
//! embedded descriptor's sector and length (u64 at 28 and 36), the grain
//! table entries per table (u32 at 44, 512 in practice), the redundant grain
//! directory (u64 at 48, ignored), the grain directory (u64 at 56), the
//! overhead (u64 at 64) and the compression algorithm (u16 at 77: 0 none, 1
//! deflate). The grain directory holds one `u32` sector number per grain
//! table, the grain table one `u32` per grain: 0 is a grain that was never
//! written (zeros), 1 a grain of zeros, any other value the sector of the
//! grain. In an uncompressed extent the grain is `grain size` sectors of
//! data; in a stream-optimized one (algorithm 1) it is a marker (`lba` u64,
//! `size` u32) followed by `size` bytes of zlib data that inflate to one
//! grain. A stream-optimized file stores the grain directory sector as
//! `0xFFFF_FFFF_FFFF_FFFF` in its first header; the real header is the copy
//! 1024 bytes from the end of the file.
//!
//! A descriptor is a text file (or the text embedded after a sparse
//! extent's header) that starts `# Disk DescriptorFile`. `createType`,
//! `parentFileNameHint` and extent lines `RW <sectors> FLAT "name" <offset>`,
//! `RW <sectors> SPARSE "name"` and `RW <sectors> ZERO` are read. The extents
//! are laid end to end.
//!
//! # Choices where the specification is silent
//!
//! - A descriptor embedded in a sparse extent is checked for a parent and an
//!   unsupported `createType` and otherwise ignored; the file is the extent.
//! - Extent types `FLAT`, `VMFS` (a flat extent on VMFS), `SPARSE` and
//!   `ZERO` are read. `VMFSSPARSE`, `SESPARSE`, raw device extents and every
//!   other type are `Unsupported`. The `COWD` (ESX) and SeSparse headers, and
//!   a `createType` of `vsanSparse`, `seSparse` or `vmfsSparse`, are
//!   `Unsupported`.
//! - A parent (`parentFileNameHint` that is not empty) is `Unsupported`,
//!   naming the hint. [`open`] adds the path of the file it was reading.
//! - An extent file name must be a plain name: one that is empty, holds a
//!   path separator, `:`, a NUL or `..` is `Corrupt`, and the resolver is not
//!   asked for it. More than 128 extents is `Unsupported`.
//! - A sparse extent's capacity must be at least the descriptor's sector
//!   count for it, else `Corrupt`. A flat extent that starts at or after the
//!   end of its file is `Corrupt`; one that runs past the end reads zeros
//!   there.
//! - Grain size must be a power of two of at most 4096 sectors (2 MiB); more
//!   is `Unsupported`. Grain table entries per table from 1 to 65536. A
//!   grain directory over 64 MiB is `Unsupported`; one that does not fit in
//!   the file is `Corrupt`. Grain tables are read when first used and 32 are
//!   kept; one decompressed grain is kept.
//! - A grain table or grain entry at or past the end of the file is
//!   `Corrupt`; an uncompressed grain cut short by the end reads its missing
//!   part as zeros. A compressed grain that is cut short, whose marker size
//!   is zero or over twice the grain size plus 1 KiB, whose `lba` is not its
//!   own, or that inflates to more than one grain is `Corrupt`; one that
//!   inflates to less is padded with zeros. The deflate data must be a zlib
//!   stream.
//! - The unclean-shutdown flag, the end-of-line check characters and the
//!   redundant grain directory are not read. Sparse extents named by a
//!   descriptor are not compared with it beyond the capacity.
//!
//! ```no_run
//! use std::path::Path;
//!
//! use atlas_fs_core::io::block::BlockSource;
//!
//! # fn main() -> Result<(), atlas_fs_core::error::Error> {
//! let disk = atlas_vmdk::open(Path::new("disk.vmdk"))?;
//! println!("{} bytes of disk", disk.len());
//! # Ok(())
//! # }
//! ```

#![forbid(unsafe_code)]
// On-disk bytes are hostile. These lints make the usual ways of trusting
// them (unchecked indexing, arithmetic and casts, panicking shortcuts) fail
// the clippy gate. Unit tests and the test fixtures are exempt.
#![warn(
    clippy::arithmetic_side_effects,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    clippy::cast_sign_loss,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unimplemented,
    clippy::unreachable,
    clippy::unwrap_used
)]
#![cfg_attr(
    test,
    allow(
        clippy::arithmetic_side_effects,
        clippy::cast_possible_truncation,
        clippy::cast_possible_wrap,
        clippy::cast_sign_loss,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic,
        clippy::unwrap_used
    )
)]

use std::io::Read;
use std::sync::{Arc, Mutex, PoisonError};

use atlas_fs_core::error::{CorruptKind, Corruption, Error, Location, Result};
use atlas_fs_core::io::block::{BlockSource, check_range};
use atlas_fs_core::io::file::FileSource;
use std::path::Path;

/// Bytes per sector.
const SECTOR: u64 = 512;
/// Size of a sparse extent header.
const HEADER_LEN: usize = 512;
/// `KDMV`.
const SPARSE_MAGIC: [u8; 4] = *b"KDMV";
/// `COWD`, the ESX sparse format.
const COWD_MAGIC: [u8; 4] = *b"COWD";
/// The SeSparse header: the u64 0xCAFEBABE.
const SESPARSE_MAGIC: [u8; 8] = 0xCAFE_BABEu64.to_le_bytes();
/// The text a descriptor starts with.
const DESCRIPTOR_START: &str = "# Disk DescriptorFile";
/// Largest descriptor read, in bytes.
const MAX_DESCRIPTOR: u64 = 1 << 20;
/// Most extents in a descriptor.
const MAX_EXTENTS: usize = 128;
/// Largest grain, in sectors.
const MAX_GRAIN_SECTORS: u64 = 4096;
/// Most grain table entries per table.
const MAX_GTES: u64 = 65536;
/// Most grain directory bytes held in memory.
const MAX_GD_BYTES: u64 = 64 << 20;
/// Grain tables kept.
const GT_CACHE: usize = 32;

const HEADER: &str = "VMDK sparse header";
const DIRECTORY: &str = "VMDK grain directory";
const TABLE: &str = "VMDK grain table";
const GRAIN: &str = "VMDK grain";
const DESCRIPTOR: &str = "VMDK descriptor";

fn corrupt(what: &'static str, offset: u64, kind: CorruptKind) -> Error {
    Error::Corrupt(Corruption::new(what, Location::Byte(offset), kind))
}

fn invalid(what: &'static str, offset: u64, field: &'static str, value: u64) -> Error {
    corrupt(what, offset, CorruptKind::InvalidValue { field, value })
}

fn other(what: &'static str, text: &'static str) -> Error {
    corrupt(what, 0, CorruptKind::Other(text))
}

fn field<const N: usize>(buf: &[u8], offset: usize) -> Option<[u8; N]> {
    offset
        .checked_add(N)
        .and_then(|end| buf.get(offset..end))
        .and_then(|b| <[u8; N]>::try_from(b).ok())
}

fn le16(buf: &[u8], offset: usize, what: &'static str) -> Result<u16> {
    field(buf, offset)
        .map(u16::from_le_bytes)
        .ok_or_else(|| truncated(what, offset))
}

fn le32(buf: &[u8], offset: usize, what: &'static str) -> Result<u32> {
    field(buf, offset)
        .map(u32::from_le_bytes)
        .ok_or_else(|| truncated(what, offset))
}

fn le64(buf: &[u8], offset: usize, what: &'static str) -> Result<u64> {
    field(buf, offset)
        .map(u64::from_le_bytes)
        .ok_or_else(|| truncated(what, offset))
}

fn truncated(what: &'static str, offset: usize) -> Error {
    corrupt(
        what,
        offset as u64,
        CorruptKind::Truncated {
            needed: 0,
            available: 0,
        },
    )
}

/// Reads `buf` from `file` at `start`; whatever lies past the end of the
/// file reads as zeros.
fn read_clamped(file: &dyn BlockSource, start: u64, buf: &mut [u8], bulk: bool) -> Result<()> {
    let file_len = file.len();
    let avail =
        usize::try_from(file_len.saturating_sub(start)).map_or(buf.len(), |a| a.min(buf.len()));
    let want = u64::try_from(buf.len()).unwrap_or(u64::MAX);
    let (data, zeros) = buf.split_at_mut_checked(avail).ok_or(Error::OutOfBounds {
        offset: start,
        len: want,
        size: file_len,
    })?;
    if !data.is_empty() {
        if bulk {
            file.read_bulk(start, data)?;
        } else {
            file.read_at(start, data)?;
        }
    }
    zeros.fill(0);
    Ok(())
}

/// Reads `len` bytes at `offset`; a range outside the file is `Corrupt`.
fn read_checked(
    file: &dyn BlockSource,
    what: &'static str,
    offset: u64,
    len: usize,
) -> Result<Vec<u8>> {
    let file_len = file.len();
    let want = u64::try_from(len).unwrap_or(u64::MAX);
    match offset.checked_add(want) {
        Some(end) if end <= file_len => {}
        _ => {
            return Err(corrupt(
                what,
                offset,
                CorruptKind::Truncated {
                    needed: want,
                    available: file_len.saturating_sub(offset),
                },
            ));
        }
    }
    let mut buf = vec![0u8; len];
    file.read_at(offset, &mut buf)?;
    Ok(buf)
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

// ---------------------------------------------------------------------------
// Descriptor

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum LineKind {
    Flat,
    Sparse,
    Zero,
}

#[derive(Debug)]
struct ExtentLine {
    sectors: u64,
    kind: LineKind,
    name: Option<String>,
    /// Offset in sectors into a flat extent's file.
    offset: u64,
}

#[derive(Debug, Default)]
struct Descriptor {
    create_type: String,
    parent_hint: String,
    extents: Vec<ExtentLine>,
}

fn unquote(value: &str) -> &str {
    let value = value.trim();
    value
        .strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .unwrap_or(value)
}

fn parse_extent_line(line: &str) -> Result<ExtentLine> {
    let mut words = line.split_whitespace();
    let (_access, sectors, kind) = (words.next(), words.next(), words.next());
    let sectors = sectors
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| other(DESCRIPTOR, "extent line without a sector count"))?;
    let kind_text = kind.ok_or_else(|| other(DESCRIPTOR, "extent line without a type"))?;
    let kind = if kind_text.eq_ignore_ascii_case("FLAT") || kind_text.eq_ignore_ascii_case("VMFS") {
        LineKind::Flat
    } else if kind_text.eq_ignore_ascii_case("SPARSE") {
        LineKind::Sparse
    } else if kind_text.eq_ignore_ascii_case("ZERO") {
        LineKind::Zero
    } else {
        return Err(Error::unsupported(format!("VMDK extent type {kind_text}")));
    };
    let mut name = None;
    let mut offset = 0u64;
    if let Some(open) = line.find('"') {
        let rest = line.get(open.saturating_add(1)..).unwrap_or("");
        let close = rest
            .find('"')
            .ok_or_else(|| other(DESCRIPTOR, "extent file name without a closing quote"))?;
        name = rest.get(..close).map(str::to_string);
        let after = rest.get(close.saturating_add(1)..).unwrap_or("");
        if let Some(word) = after.split_whitespace().next() {
            offset = word
                .parse::<u64>()
                .map_err(|_| other(DESCRIPTOR, "extent offset is not a number"))?;
        }
    }
    if kind != LineKind::Zero && name.is_none() {
        return Err(other(DESCRIPTOR, "extent line without a file name"));
    }
    Ok(ExtentLine {
        sectors,
        kind,
        name,
        offset,
    })
}

fn parse_descriptor(text: &str) -> Result<Descriptor> {
    let mut out = Descriptor::default();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let first = line.split_whitespace().next().unwrap_or("");
        if first.eq_ignore_ascii_case("RW")
            || first.eq_ignore_ascii_case("RDONLY")
            || first.eq_ignore_ascii_case("NOACCESS")
        {
            if out.extents.len() >= MAX_EXTENTS {
                return Err(Error::unsupported(format!(
                    "VMDK with more than {MAX_EXTENTS} extents"
                )));
            }
            out.extents.push(parse_extent_line(line)?);
        } else if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            if key.eq_ignore_ascii_case("createType") {
                out.create_type = unquote(value).to_string();
            } else if key.eq_ignore_ascii_case("parentFileNameHint") {
                out.parent_hint = unquote(value).to_string();
            }
        }
    }
    Ok(out)
}

/// Refuses what this reader does not do, from what a descriptor says.
fn check_supported(descriptor: &Descriptor) -> Result<()> {
    if !descriptor.parent_hint.is_empty() {
        return Err(Error::unsupported(format!(
            "differencing VMDK (parent: {})",
            descriptor.parent_hint
        )));
    }
    let create_type = descriptor.create_type.to_ascii_lowercase();
    for name in ["sesparse", "vsansparse", "vmfssparse"] {
        if create_type == name {
            return Err(Error::unsupported(format!(
                "VMDK of type {}",
                descriptor.create_type
            )));
        }
    }
    Ok(())
}

/// An extent file name must be a plain name in the descriptor's folder.
fn check_name(name: &str) -> Result<()> {
    let bad = name.is_empty()
        || name == "."
        || name.contains("..")
        || name.contains(['/', '\\', ':', '\0']);
    if bad {
        return Err(other(
            DESCRIPTOR,
            "extent file name is not a plain name in the descriptor's folder",
        ));
    }
    Ok(())
}

/// The descriptor text in `bytes`: up to the first NUL.
fn descriptor_text(bytes: &[u8]) -> String {
    let end = bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(bytes.get(..end).unwrap_or(bytes)).into_owned()
}

fn starts_like_descriptor(text: &str) -> bool {
    text.trim_start_matches('\u{feff}')
        .trim_start()
        .starts_with(DESCRIPTOR_START)
}

// ---------------------------------------------------------------------------
// Sparse extents

struct SparseHeader {
    capacity: u64,
    grain_sectors: u64,
    descriptor_sector: u64,
    descriptor_sectors: u64,
    gtes: u64,
    gd_sector: u64,
    compressed: bool,
}

fn parse_sparse_header(buf: &[u8]) -> Result<SparseHeader> {
    let magic: [u8; 4] = field(buf, 0).ok_or_else(|| truncated(HEADER, 0))?;
    if magic == COWD_MAGIC {
        return Err(Error::unsupported("VMware ESX sparse (COWD) disk"));
    }
    if field::<8>(buf, 0) == Some(SESPARSE_MAGIC) {
        return Err(Error::unsupported("VMware SeSparse disk"));
    }
    if magic != SPARSE_MAGIC {
        return Err(corrupt(
            HEADER,
            0,
            CorruptKind::BadSignature {
                expected: u64::from(u32::from_le_bytes(SPARSE_MAGIC)),
                found: u64::from(u32::from_le_bytes(magic)),
            },
        ));
    }
    let version = le32(buf, 4, HEADER)?;
    if !(1..=3).contains(&version) {
        return Err(Error::unsupported(format!("VMDK sparse version {version}")));
    }
    let algorithm = le16(buf, 77, HEADER)?;
    if algorithm > 1 {
        return Err(Error::unsupported(format!(
            "VMDK compression algorithm {algorithm}"
        )));
    }
    Ok(SparseHeader {
        capacity: le64(buf, 12, HEADER)?,
        grain_sectors: le64(buf, 20, HEADER)?,
        descriptor_sector: le64(buf, 28, HEADER)?,
        descriptor_sectors: le64(buf, 36, HEADER)?,
        gtes: u64::from(le32(buf, 44, HEADER)?),
        gd_sector: le64(buf, 56, HEADER)?,
        compressed: algorithm == 1,
    })
}

#[derive(Default)]
struct Cache {
    /// Grain tables, oldest first: directory index and the table's bytes.
    tables: Vec<(u64, Arc<[u8]>)>,
    /// The last decompressed grain: its index and bytes.
    grain: Option<(u64, Arc<[u8]>)>,
}

/// One sparse extent: the grain directory and the extent's file.
struct Sparse {
    file: Arc<dyn BlockSource>,
    capacity: u64,
    grain_bytes: u64,
    grain_sectors: u64,
    gtes: u64,
    compressed: bool,
    /// The grain directory as stored: little-endian `u32` entries.
    gd: Vec<u8>,
    cache: Mutex<Cache>,
}

impl Sparse {
    /// Parses the sparse extent in `file`. Also checks its embedded
    /// descriptor for what this reader does not do.
    fn new(file: Arc<dyn BlockSource>) -> Result<Self> {
        let file_len = file.len();
        let head = read_checked(&*file, HEADER, 0, HEADER_LEN)?;
        let first = parse_sparse_header(&head)?;
        // Descriptor first: a differencing disk is `Unsupported` whatever
        // the rest looks like.
        if first.descriptor_sector != 0 && first.descriptor_sectors != 0 {
            let start = first.descriptor_sector.checked_mul(SECTOR);
            let want = first
                .descriptor_sectors
                .saturating_mul(SECTOR)
                .min(MAX_DESCRIPTOR);
            let start = start
                .filter(|s| *s < file_len)
                .ok_or_else(|| invalid(HEADER, 28, "descriptor offset", first.descriptor_sector))?;
            let want = want.min(file_len.saturating_sub(start));
            let len = usize::try_from(want).map_err(|_| other(HEADER, "descriptor too large"))?;
            let bytes = read_checked(&*file, DESCRIPTOR, start, len)?;
            check_supported(&parse_descriptor(&descriptor_text(&bytes))?)?;
        }
        let h = if first.gd_sector == u64::MAX {
            // Stream-optimized: the real header is the footer, 1024 bytes
            // from the end.
            let at = file_len
                .checked_sub(1024)
                .ok_or_else(|| truncated(HEADER, 0))?;
            let foot = read_checked(&*file, HEADER, at, HEADER_LEN)?;
            let h = parse_sparse_header(&foot)?;
            if h.gd_sector == u64::MAX {
                return Err(other(
                    HEADER,
                    "grain directory at the end of the file twice",
                ));
            }
            h
        } else {
            first
        };
        if h.capacity == 0 || h.capacity.checked_mul(SECTOR).is_none() {
            return Err(invalid(HEADER, 12, "capacity", h.capacity));
        }
        if h.grain_sectors == 0 || !h.grain_sectors.is_power_of_two() {
            return Err(invalid(HEADER, 20, "grain size", h.grain_sectors));
        }
        if h.grain_sectors > MAX_GRAIN_SECTORS {
            return Err(Error::unsupported(format!(
                "VMDK grain size of {} sectors (over {MAX_GRAIN_SECTORS})",
                h.grain_sectors
            )));
        }
        if h.gtes == 0 || h.gtes > MAX_GTES {
            return Err(invalid(HEADER, 44, "grain table entries", h.gtes));
        }
        if h.gd_sector == 0 {
            return Err(invalid(HEADER, 56, "grain directory offset", 0));
        }
        let grains = h.capacity.div_ceil(h.grain_sectors);
        let gd_entries = grains.div_ceil(h.gtes);
        let gd_bytes = gd_entries.saturating_mul(4);
        if gd_bytes > MAX_GD_BYTES {
            return Err(Error::unsupported(format!(
                "VMDK grain directory of {gd_bytes} bytes (over {MAX_GD_BYTES})"
            )));
        }
        let gd_start = h
            .gd_sector
            .checked_mul(SECTOR)
            .ok_or_else(|| invalid(HEADER, 56, "grain directory offset", h.gd_sector))?;
        let gd_len = usize::try_from(gd_bytes).map_err(|_| other(DIRECTORY, "too large"))?;
        let gd = read_checked(&*file, DIRECTORY, gd_start, gd_len)?;
        Ok(Self {
            file,
            capacity: h.capacity,
            // At most 4096 * 512.
            grain_bytes: h.grain_sectors.saturating_mul(SECTOR),
            grain_sectors: h.grain_sectors,
            gtes: h.gtes,
            compressed: h.compressed,
            gd,
            cache: Mutex::new(Cache::default()),
        })
    }

    /// The grain table for directory entry `gd_index`, whose sector is
    /// `sector`.
    fn table(&self, gd_index: u64, sector: u32) -> Result<Arc<[u8]>> {
        {
            let cache = lock(&self.cache);
            if let Some((_, table)) = cache.tables.iter().find(|(i, _)| *i == gd_index) {
                return Ok(Arc::clone(table));
            }
        }
        let start = u64::from(sector) * SECTOR;
        // gtes <= 65536.
        let len =
            usize::try_from(self.gtes.saturating_mul(4)).map_err(|_| other(TABLE, "too large"))?;
        let bytes = read_checked(&*self.file, TABLE, start, len)?;
        let table: Arc<[u8]> = Arc::from(bytes);
        let mut cache = lock(&self.cache);
        if cache.tables.len() >= GT_CACHE {
            cache.tables.remove(0);
        }
        cache.tables.push((gd_index, Arc::clone(&table)));
        Ok(table)
    }

    /// The inflated grain number `grain`, whose marker is at byte `start`.
    fn grain(&self, grain: u64, start: u64) -> Result<Arc<[u8]>> {
        {
            let cache = lock(&self.cache);
            if let Some((i, bytes)) = &cache.grain
                && *i == grain
            {
                return Ok(Arc::clone(bytes));
            }
        }
        let marker = read_checked(&*self.file, GRAIN, start, 12)?;
        let lba = le64(&marker, 0, GRAIN)?;
        let size = u64::from(le32(&marker, 8, GRAIN)?);
        let expected = grain.saturating_mul(self.grain_sectors);
        if lba != expected {
            return Err(invalid(GRAIN, start, "grain lba", lba));
        }
        let limit = self.grain_bytes.saturating_mul(2).saturating_add(1024);
        if size == 0 || size > limit {
            return Err(invalid(GRAIN, start, "compressed size", size));
        }
        let data_start = start
            .checked_add(12)
            .ok_or_else(|| other(GRAIN, "offset overflow"))?;
        let len = usize::try_from(size).map_err(|_| other(GRAIN, "too large"))?;
        let packed = read_checked(&*self.file, GRAIN, data_start, len)?;
        let cap = self.grain_bytes;
        let mut out = Vec::new();
        flate2::read::ZlibDecoder::new(&packed[..])
            .take(cap.saturating_add(1))
            .read_to_end(&mut out)
            .map_err(|_| other(GRAIN, "bad deflate stream"))?;
        if u64::try_from(out.len()).unwrap_or(u64::MAX) > cap {
            return Err(corrupt(
                GRAIN,
                start,
                CorruptKind::LimitExceeded {
                    what: "inflated grain bytes",
                    limit: cap,
                },
            ));
        }
        out.resize(
            usize::try_from(cap).map_err(|_| other(GRAIN, "too large"))?,
            0,
        );
        let bytes: Arc<[u8]> = Arc::from(out);
        lock(&self.cache).grain = Some((grain, Arc::clone(&bytes)));
        Ok(bytes)
    }

    /// Reads `buf` at byte `pos` of the extent.
    fn read(&self, pos: u64, buf: &mut [u8], bulk: bool) -> Result<()> {
        let file_len = self.file.len();
        let capacity_bytes = self.capacity.saturating_mul(SECTOR);
        let oob = |offset: u64, len: usize| Error::OutOfBounds {
            offset,
            len: u64::try_from(len).unwrap_or(u64::MAX),
            size: capacity_bytes,
        };
        let mut pos = pos;
        let mut rest = buf;
        // Each pass takes at least one byte: `within < grain_bytes`.
        while !rest.is_empty() {
            let left = rest.len();
            let grain = pos
                .checked_div(self.grain_bytes)
                .ok_or_else(|| oob(pos, left))?;
            let within = pos
                .checked_rem(self.grain_bytes)
                .ok_or_else(|| oob(pos, left))?;
            let in_grain = self
                .grain_bytes
                .checked_sub(within)
                .ok_or_else(|| oob(pos, left))?;
            let n = usize::try_from(in_grain).map_or(left, |g| g.min(left));
            let (chunk, tail) = rest.split_at_mut_checked(n).ok_or_else(|| oob(pos, left))?;
            let gd_index = grain.checked_div(self.gtes).ok_or_else(|| oob(pos, left))?;
            let slot = grain.checked_rem(self.gtes).ok_or_else(|| oob(pos, left))?;
            let gd_at = usize::try_from(gd_index)
                .ok()
                .and_then(|i| i.checked_mul(4))
                .ok_or_else(|| oob(pos, left))?;
            let gd_entry = le32(&self.gd, gd_at, DIRECTORY)?;
            let entry = if gd_entry == 0 {
                0
            } else {
                let table = self.table(gd_index, gd_entry)?;
                let at = usize::try_from(slot)
                    .ok()
                    .and_then(|i| i.checked_mul(4))
                    .ok_or_else(|| oob(pos, left))?;
                le32(&table, at, TABLE)?
            };
            // 0 was never written, 1 is a grain of zeros.
            if entry <= 1 {
                chunk.fill(0);
            } else {
                let start = u64::from(entry) * SECTOR;
                if start >= file_len {
                    return Err(corrupt(
                        GRAIN,
                        start,
                        CorruptKind::OutOfRange {
                            field: "grain offset",
                            value: start,
                            limit_name: "file size",
                            limit: file_len,
                        },
                    ));
                }
                if self.compressed {
                    let bytes = self.grain(grain, start)?;
                    let a = usize::try_from(within).map_err(|_| oob(pos, left))?;
                    let b = a.checked_add(n).ok_or_else(|| oob(pos, left))?;
                    chunk.copy_from_slice(bytes.get(a..b).ok_or_else(|| oob(pos, left))?);
                } else {
                    let at = start.checked_add(within).ok_or_else(|| oob(pos, left))?;
                    read_clamped(&*self.file, at, chunk, bulk)?;
                }
            }
            pos = pos
                .checked_add(u64::try_from(n).unwrap_or(u64::MAX))
                .ok_or_else(|| oob(pos, n))?;
            rest = tail;
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The disk

enum Kind {
    Zero,
    Flat {
        file: Arc<dyn BlockSource>,
        /// Byte offset of the extent in its file.
        offset: u64,
    },
    Sparse(Sparse),
}

struct Extent {
    /// Byte offset of the extent in the disk.
    start: u64,
    len: u64,
    kind: Kind,
}

/// The disk a VMDK presents.
pub struct VmdkSource {
    extents: Vec<Extent>,
    len: u64,
}

/// Opens the VMDK at `path` read-only: a sparse file, or a descriptor whose
/// extents are files in the same folder.
pub fn open(path: &Path) -> Result<Arc<dyn BlockSource>> {
    let file: Arc<dyn BlockSource> = Arc::new(FileSource::open(path)?);
    let folder = path
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .to_path_buf();
    let resolve = move |name: &str| -> Result<Arc<dyn BlockSource>> {
        // `new` has already refused names that are not plain.
        Ok(Arc::new(FileSource::open(&folder.join(name))?))
    };
    match VmdkSource::new(file, &resolve) {
        Ok(source) => Ok(Arc::new(source)),
        Err(Error::Unsupported(text)) => {
            Err(Error::unsupported(format!("{text} in {}", path.display())))
        }
        Err(e) => Err(e),
    }
}

impl VmdkSource {
    /// Parses the VMDK stored in `file`.
    ///
    /// `file` is either a sparse extent (monolithic or stream-optimized) or
    /// a descriptor. For a descriptor, `resolve` is called with the plain
    /// file name of each flat or sparse extent and returns that file's
    /// bytes. Fails with [`Error::Corrupt`] on damage and
    /// [`Error::Unsupported`] for what the module docs list.
    pub fn new(
        file: Arc<dyn BlockSource>,
        resolve: &dyn Fn(&str) -> Result<Arc<dyn BlockSource>>,
    ) -> Result<Self> {
        let file_len = file.len();
        let mut head = [0u8; 8];
        let head_len = usize::try_from(file_len).map_or(head.len(), |l| l.min(head.len()));
        if let Some(part) = head.get_mut(..head_len) {
            file.read_at(0, part)?;
        }
        let magic = head.get(..4);
        if magic == Some(&SPARSE_MAGIC[..])
            || magic == Some(&COWD_MAGIC[..])
            || head == SESPARSE_MAGIC
        {
            let sparse = Sparse::new(file)?;
            let len = sparse.capacity.saturating_mul(SECTOR);
            return Ok(Self {
                extents: vec![Extent {
                    start: 0,
                    len,
                    kind: Kind::Sparse(sparse),
                }],
                len,
            });
        }
        if file_len > MAX_DESCRIPTOR {
            return Err(other(HEADER, "not a VMDK file"));
        }
        let len = usize::try_from(file_len).map_err(|_| other(DESCRIPTOR, "too large"))?;
        let bytes = read_checked(&*file, DESCRIPTOR, 0, len)?;
        let text = descriptor_text(&bytes);
        if !starts_like_descriptor(&text) {
            return Err(corrupt(
                HEADER,
                0,
                CorruptKind::BadSignature {
                    expected: u64::from(u32::from_le_bytes(SPARSE_MAGIC)),
                    found: u64::from(u32::from_le_bytes(field(&head, 0).unwrap_or_default())),
                },
            ));
        }
        let descriptor = parse_descriptor(&text)?;
        check_supported(&descriptor)?;
        if descriptor.extents.is_empty() {
            return Err(other(DESCRIPTOR, "descriptor lists no extents"));
        }
        let mut extents = Vec::new();
        let mut total = 0u64;
        for line in &descriptor.extents {
            let len = line.sectors.checked_mul(SECTOR).ok_or_else(|| {
                corrupt(
                    DESCRIPTOR,
                    0,
                    CorruptKind::Overflow {
                        field: "extent size",
                    },
                )
            })?;
            let kind = match (line.kind, &line.name) {
                (LineKind::Zero, _) => Kind::Zero,
                (LineKind::Flat, Some(name)) => {
                    check_name(name)?;
                    let source = resolve(name)?;
                    let offset = line.offset.checked_mul(SECTOR).ok_or_else(|| {
                        corrupt(
                            DESCRIPTOR,
                            0,
                            CorruptKind::Overflow {
                                field: "extent offset",
                            },
                        )
                    })?;
                    if len > 0 && offset >= source.len() {
                        return Err(corrupt(
                            DESCRIPTOR,
                            0,
                            CorruptKind::OutOfRange {
                                field: "flat extent offset",
                                value: offset,
                                limit_name: "extent file size",
                                limit: source.len(),
                            },
                        ));
                    }
                    Kind::Flat {
                        file: source,
                        offset,
                    }
                }
                (LineKind::Sparse, Some(name)) => {
                    check_name(name)?;
                    let sparse = Sparse::new(resolve(name)?)?;
                    if sparse.capacity < line.sectors {
                        return Err(corrupt(
                            DESCRIPTOR,
                            0,
                            CorruptKind::OutOfRange {
                                field: "extent sectors",
                                value: line.sectors,
                                limit_name: "sparse extent capacity",
                                limit: sparse.capacity,
                            },
                        ));
                    }
                    Kind::Sparse(sparse)
                }
                _ => return Err(other(DESCRIPTOR, "extent line without a file name")),
            };
            if len == 0 {
                continue;
            }
            extents.push(Extent {
                start: total,
                len,
                kind,
            });
            total = total.checked_add(len).ok_or_else(|| {
                corrupt(DESCRIPTOR, 0, CorruptKind::Overflow { field: "disk size" })
            })?;
        }
        if total == 0 {
            return Err(other(DESCRIPTOR, "descriptor extents hold no sectors"));
        }
        Ok(Self {
            extents,
            len: total,
        })
    }

    fn read_with(&self, offset: u64, buf: &mut [u8], bulk: bool) -> Result<()> {
        check_range(offset, buf.len(), self.len)?;
        let oob = |offset: u64, len: usize| Error::OutOfBounds {
            offset,
            len: u64::try_from(len).unwrap_or(u64::MAX),
            size: self.len,
        };
        let mut pos = offset;
        let mut rest = buf;
        // Each pass takes at least one byte: `within < extent.len`.
        while !rest.is_empty() {
            let left = rest.len();
            let index = self
                .extents
                .partition_point(|e| e.start <= pos)
                .checked_sub(1)
                .ok_or_else(|| oob(pos, left))?;
            let extent = self.extents.get(index).ok_or_else(|| oob(pos, left))?;
            let within = pos
                .checked_sub(extent.start)
                .ok_or_else(|| oob(pos, left))?;
            let in_extent = extent
                .len
                .checked_sub(within)
                .filter(|r| *r > 0)
                .ok_or_else(|| oob(pos, left))?;
            let n = usize::try_from(in_extent).map_or(left, |r| r.min(left));
            let (chunk, tail) = rest.split_at_mut_checked(n).ok_or_else(|| oob(pos, left))?;
            match &extent.kind {
                Kind::Zero => chunk.fill(0),
                Kind::Flat { file, offset } => {
                    let at = offset.checked_add(within).ok_or_else(|| oob(pos, left))?;
                    read_clamped(&**file, at, chunk, bulk)?;
                }
                Kind::Sparse(sparse) => sparse.read(within, chunk, bulk)?,
            }
            pos = pos
                .checked_add(u64::try_from(n).unwrap_or(u64::MAX))
                .ok_or_else(|| oob(pos, n))?;
            rest = tail;
        }
        Ok(())
    }
}

impl BlockSource for VmdkSource {
    fn len(&self) -> u64 {
        self.len
    }

    fn sector_size(&self) -> u32 {
        512
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.read_with(offset, buf, false)
    }

    fn read_bulk(&self, offset: u64, buf: &mut [u8]) -> Result<()> {
        self.read_with(offset, buf, true)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use atlas_fs_core::io::block::MemSource;
    use std::io::Write;

    const GRAIN: usize = 4096;

    fn pattern(seed: u8, offset: usize) -> u8 {
        (usize::from(seed) * 37 + offset * 11 + 3) as u8
    }

    fn grain_data(seed: u8) -> Vec<u8> {
        (0..GRAIN).map(|o| pattern(seed, o)).collect()
    }

    fn put(buf: &mut Vec<u8>, at: usize, bytes: &[u8]) {
        if buf.len() < at + bytes.len() {
            buf.resize(at + bytes.len(), 0);
        }
        buf[at..at + bytes.len()].copy_from_slice(bytes);
    }

    fn header(
        capacity: u64,
        descriptor: (u64, u64),
        gtes: u32,
        gd: u64,
        compressed: bool,
        grain_sectors: u64,
    ) -> Vec<u8> {
        let mut h = vec![0u8; HEADER_LEN];
        h[..4].copy_from_slice(b"KDMV");
        h[4..8].copy_from_slice(&1u32.to_le_bytes());
        h[12..20].copy_from_slice(&capacity.to_le_bytes());
        h[20..28].copy_from_slice(&grain_sectors.to_le_bytes());
        h[28..36].copy_from_slice(&descriptor.0.to_le_bytes());
        h[36..44].copy_from_slice(&descriptor.1.to_le_bytes());
        h[44..48].copy_from_slice(&gtes.to_le_bytes());
        h[56..64].copy_from_slice(&gd.to_le_bytes());
        h[77..79].copy_from_slice(&u16::from(compressed).to_le_bytes());
        h
    }

    fn embedded_descriptor(extra: &str) -> Vec<u8> {
        let text = format!(
            "# Disk DescriptorFile\nversion=1\ncreateType=\"monolithicSparse\"\n{extra}\nRW 2048 SPARSE \"x.vmdk\"\n"
        );
        let mut bytes = text.into_bytes();
        bytes.resize(1024, 0);
        bytes
    }

    /// A sparse extent of 2048 sectors (1 MiB, 256 grains) with 4 KiB
    /// grains. `present` lists the grain indexes stored, `zero` the ones
    /// marked as zero grains.
    fn build_sparse(present: &[usize], zero: &[usize], extra_descriptor: &str) -> Vec<u8> {
        let mut f = header(2048, (1, 2), 512, 3, false, 8);
        f.resize(512, 0);
        put(&mut f, 512, &embedded_descriptor(extra_descriptor));
        // GD at sector 3: one entry, the GT at sector 4 (4 sectors).
        put(&mut f, 3 * 512, &4u32.to_le_bytes());
        let mut gt = vec![0u8; 2048];
        for (k, &g) in present.iter().enumerate() {
            let sector = 8 + k * 8;
            gt[g * 4..g * 4 + 4].copy_from_slice(&(sector as u32).to_le_bytes());
            put(&mut f, sector * 512, &grain_data(g as u8));
        }
        for &g in zero {
            gt[g * 4..g * 4 + 4].copy_from_slice(&1u32.to_le_bytes());
        }
        put(&mut f, 4 * 512, &gt);
        f
    }

    fn expected_sparse(present: &[usize]) -> Vec<u8> {
        let mut disk = vec![0u8; 256 * GRAIN];
        for &g in present {
            disk[g * GRAIN..(g + 1) * GRAIN].copy_from_slice(&grain_data(g as u8));
        }
        disk
    }

    /// A stream-optimized extent with the same layout idea: markers and
    /// zlib grains, the grain directory at the end.
    fn build_stream(present: &[usize]) -> Vec<u8> {
        let mut f = header(2048, (1, 2), 512, u64::MAX, true, 8);
        f.resize(512, 0);
        put(&mut f, 512, &embedded_descriptor(""));
        let mut gt = vec![0u8; 2048];
        let mut at = 3 * 512;
        for &g in present {
            let mut enc =
                flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::default());
            enc.write_all(&grain_data(g as u8)).unwrap();
            let packed = enc.finish().unwrap();
            gt[g * 4..g * 4 + 4].copy_from_slice(&((at / 512) as u32).to_le_bytes());
            let mut marker = ((g * 8) as u64).to_le_bytes().to_vec();
            marker.extend((packed.len() as u32).to_le_bytes());
            marker.extend(&packed);
            marker.resize(marker.len().div_ceil(512) * 512, 0);
            put(&mut f, at, &marker);
            at += marker.len();
        }
        let gt_at = at;
        put(&mut f, gt_at, &gt);
        let gd_at = gt_at + 2048;
        put(&mut f, gd_at, &((gt_at / 512) as u32).to_le_bytes());
        f.resize(gd_at + 512, 0);
        // Footer marker, footer header, end-of-stream marker.
        f.extend(vec![0u8; 512]);
        f.extend(header(2048, (1, 2), 512, (gd_at / 512) as u64, true, 8));
        f.extend(vec![0u8; 512]);
        f
    }

    fn no_resolver(_: &str) -> Result<Arc<dyn BlockSource>> {
        Err(Error::unsupported("no extents here"))
    }

    fn open_bytes(bytes: Vec<u8>) -> Result<VmdkSource> {
        VmdkSource::new(Arc::new(MemSource::new(bytes)), &no_resolver)
    }

    fn read_all(src: &VmdkSource) -> Vec<u8> {
        let mut buf = vec![0u8; src.len() as usize];
        src.read_at(0, &mut buf).unwrap();
        buf
    }

    #[test]
    fn sparse_uncompressed_reads_grains_and_zeros() {
        let present = [0usize, 1, 5, 255];
        let src = open_bytes(build_sparse(&present, &[3], "")).unwrap();
        assert_eq!(src.len(), 1 << 20);
        assert_eq!(src.sector_size(), 512);
        assert_eq!(read_all(&src), expected_sparse(&present));
        // Across a grain boundary, from the middle of grain 1 to grain 2.
        let mut buf = vec![0u8; 5000];
        src.read_bulk(GRAIN as u64 + 2000, &mut buf).unwrap();
        let want = expected_sparse(&present);
        assert_eq!(buf, want[GRAIN + 2000..GRAIN + 7000]);
        assert!(src.read_at(1 << 20, &mut [0u8; 1]).is_err());
    }

    #[test]
    fn sparse_uncompressed_cut_short_reads_zeros() {
        let mut bytes = build_sparse(&[0, 1], &[], "");
        bytes.truncate(8 * 512 + GRAIN + 100); // grain 1 keeps 100 bytes
        let src = open_bytes(bytes).unwrap();
        let mut buf = vec![0u8; GRAIN];
        src.read_at(GRAIN as u64, &mut buf).unwrap();
        assert_eq!(buf[..100], grain_data(1)[..100]);
        assert!(buf[100..].iter().all(|b| *b == 0));
    }

    #[test]
    fn stream_optimized_inflates_grains() {
        let present = [0usize, 2, 7, 200];
        let src = open_bytes(build_stream(&present)).unwrap();
        assert_eq!(read_all(&src), expected_sparse(&present));
        let mut buf = vec![0u8; 3 * GRAIN];
        src.read_at(GRAIN as u64 + 1, &mut buf).unwrap();
        assert_eq!(buf, expected_sparse(&present)[GRAIN + 1..4 * GRAIN + 1]);
    }

    #[test]
    fn stream_optimized_hostile_grains_are_errors() {
        let good = build_stream(&[0, 1]);
        // A marker whose lba is wrong, whose size is zero, and whose zlib
        // data is garbage.
        let marker_at = 3 * 512;
        let mut bad = good.clone();
        bad[marker_at] ^= 1;
        assert!(read_all_err(bad));
        let mut bad = good.clone();
        bad[marker_at + 8..marker_at + 12].copy_from_slice(&0u32.to_le_bytes());
        assert!(read_all_err(bad));
        let mut bad = good.clone();
        for b in &mut bad[marker_at + 12..marker_at + 40] {
            *b = 0xFF;
        }
        assert!(read_all_err(bad));
        // A size that runs past the end of the file.
        let mut bad = good;
        bad[marker_at + 8..marker_at + 12].copy_from_slice(&8000u32.to_le_bytes());
        bad.truncate(marker_at + 600);
        assert!(read_all_err(bad));
    }

    fn read_all_err(bytes: Vec<u8>) -> bool {
        match open_bytes(bytes) {
            Err(_) => true,
            Ok(src) => src.read_at(0, &mut vec![0u8; src.len() as usize]).is_err(),
        }
    }

    #[test]
    fn hostile_sparse_headers_are_errors() {
        let good = build_sparse(&[0], &[], "");
        assert!(open_bytes(good.clone()).is_ok());
        // Bad magic: a file of zeros is not a descriptor either.
        let mut bad = good.clone();
        bad[0] = b'X';
        assert!(open_bytes(bad).is_err());
        // A capacity so large the grain directory is over 64 MiB.
        let mut bad = good.clone();
        bad[12..20].copy_from_slice(&(1u64 << 50).to_le_bytes());
        let err = open_bytes(bad).err().unwrap();
        assert!(matches!(err, Error::Unsupported(_)), "{err}");
        // A capacity with a directory that does not fit in the file.
        let mut bad = good.clone();
        bad[12..20].copy_from_slice(&(1u64 << 36).to_le_bytes());
        assert!(open_bytes(bad).is_err());
        // Grain size 0, not a power of two, huge; table entries 0 and huge.
        for (at, value) in [
            (20usize, 0u64),
            (20, 12),
            (20, 1 << 40),
            (44, 0),
            (44, 1 << 30),
        ] {
            let mut bad = good.clone();
            bad[at..at + 8].copy_from_slice(&value.to_le_bytes());
            assert!(open_bytes(bad).is_err(), "{at} {value}");
        }
        // A grain directory past the end of the file.
        let mut bad = good.clone();
        bad[56..64].copy_from_slice(&1_000_000u64.to_le_bytes());
        assert!(open_bytes(bad).is_err());
        // A grain table and a grain past the end of the file: open works,
        // reading fails.
        let mut bad = good.clone();
        bad[3 * 512..3 * 512 + 4].copy_from_slice(&1_000_000u32.to_le_bytes());
        assert!(read_all_err(bad));
        let mut bad = good.clone();
        bad[4 * 512..4 * 512 + 4].copy_from_slice(&1_000_000u32.to_le_bytes());
        assert!(read_all_err(bad));
        // Unsupported flavours.
        let mut bad = good.clone();
        bad[..4].copy_from_slice(b"COWD");
        let err = open_bytes(bad).err().unwrap();
        assert!(
            matches!(&err, Error::Unsupported(t) if t.contains("COWD")),
            "{err}"
        );
        let mut bad = good.clone();
        bad[..8].copy_from_slice(&0xCAFE_BABEu64.to_le_bytes());
        assert!(matches!(
            open_bytes(bad).err().unwrap(),
            Error::Unsupported(_)
        ));
        let mut bad = good;
        bad[77] = 2;
        assert!(matches!(
            open_bytes(bad).err().unwrap(),
            Error::Unsupported(_)
        ));
        // Truncated everywhere: no panic.
        let good = build_sparse(&[0, 1], &[], "");
        for len in [0usize, 3, 8, 100, 511, 512, 700, 1535, 1536, 2000, 3000] {
            let _ = open_bytes(good[..len.min(good.len())].to_vec());
        }
    }

    #[test]
    fn parent_in_embedded_descriptor_is_unsupported() {
        let bytes = build_sparse(&[0], &[], "parentFileNameHint=\"base.vmdk\"");
        let err = open_bytes(bytes).err().unwrap();
        assert!(
            matches!(&err, Error::Unsupported(t) if t.contains("base.vmdk")),
            "{err}"
        );
    }

    fn descriptor(extents: &[&str]) -> Vec<u8> {
        let mut text = String::from(
            "# Disk DescriptorFile\nversion=1\nCID=12345678\nparentCID=ffffffff\ncreateType=\"twoGbMaxExtentFlat\"\n\n# Extent description\n",
        );
        for e in extents {
            text.push_str(e);
            text.push('\n');
        }
        text.push_str("\n# The Disk Data Base\n#DDB\nddb.virtualHWVersion = \"4\"\n");
        text.into_bytes()
    }

    fn flat_bytes(seed: u8, len: usize) -> Vec<u8> {
        (0..len).map(|o| pattern(seed, o)).collect()
    }

    #[test]
    fn descriptor_with_flat_zero_and_sparse_extents() {
        let sparse = build_sparse(&[0, 1], &[], "");
        let f1 = flat_bytes(1, 8 * 512);
        let f2 = flat_bytes(2, 6 * 512);
        let text = descriptor(&[
            "RW 8 FLAT \"disk-f001.vmdk\" 0",
            "RW 4 FLAT \"disk-f002.vmdk\" 2",
            "RW 3 ZERO",
            "RW 2048 SPARSE \"disk-s001.vmdk\"",
        ]);
        let resolve = |name: &str| -> Result<Arc<dyn BlockSource>> {
            let bytes = match name {
                "disk-f001.vmdk" => f1.clone(),
                "disk-f002.vmdk" => f2.clone(),
                "disk-s001.vmdk" => sparse.clone(),
                _ => return Err(Error::unsupported("no such extent")),
            };
            Ok(Arc::new(MemSource::new(bytes)))
        };
        let src = VmdkSource::new(Arc::new(MemSource::new(text)), &resolve).unwrap();
        assert_eq!(src.len(), (8 + 4 + 3 + 2048) * 512);
        let all = read_all(&src);
        assert_eq!(all[..8 * 512], f1[..]);
        assert_eq!(all[8 * 512..12 * 512], f2[2 * 512..6 * 512]);
        assert!(all[12 * 512..15 * 512].iter().all(|b| *b == 0));
        assert_eq!(all[15 * 512..], expected_sparse(&[0, 1])[..]);
        // A read across the boundary between the two flat extents.
        let mut buf = vec![0u8; 100];
        src.read_at(8 * 512 - 50, &mut buf).unwrap();
        assert_eq!(buf[..50], f1[8 * 512 - 50..]);
        assert_eq!(buf[50..], f2[2 * 512..2 * 512 + 50]);
        // And across the zero extent into the sparse one.
        src.read_at(15 * 512 - 10, &mut buf).unwrap();
        assert!(buf[..10].iter().all(|b| *b == 0));
        assert_eq!(buf[10..], expected_sparse(&[0, 1])[..90]);
    }

    #[test]
    fn descriptor_hostile_inputs_are_errors() {
        let ok = |_: &str| -> Result<Arc<dyn BlockSource>> {
            Ok(Arc::new(MemSource::new(flat_bytes(1, 4096))))
        };
        let try_text = |text: Vec<u8>| VmdkSource::new(Arc::new(MemSource::new(text)), &ok);
        assert!(try_text(descriptor(&["RW 8 FLAT \"a.vmdk\" 0"])).is_ok());
        // Names that leave the folder: Corrupt, and the resolver is not asked.
        for name in [
            "../a.vmdk",
            "..",
            "sub/a.vmdk",
            "sub\\a.vmdk",
            "C:a.vmdk",
            "",
            "a..b",
        ] {
            let line = format!("RW 8 FLAT \"{name}\" 0");
            let err = try_text(descriptor(&[&line])).err().unwrap();
            assert!(matches!(err, Error::Corrupt(_)), "{name}: {err}");
        }
        // A flat extent that starts past the end of its file.
        assert!(try_text(descriptor(&["RW 8 FLAT \"a.vmdk\" 100"])).is_err());
        // Parent, unsupported extent types, no extents, too many extents.
        let mut with_parent = descriptor(&["RW 8 FLAT \"a.vmdk\" 0"]);
        with_parent.extend(b"parentFileNameHint=\"base.vmdk\"\n");
        assert!(matches!(
            try_text(with_parent).err().unwrap(),
            Error::Unsupported(_)
        ));
        assert!(matches!(
            try_text(descriptor(&["RW 8 VMFSSPARSE \"a.vmdk\""]))
                .err()
                .unwrap(),
            Error::Unsupported(_)
        ));
        assert!(try_text(descriptor(&[])).is_err());
        let many: Vec<String> = (0..129).map(|_| "RW 8 ZERO".to_string()).collect();
        let many: Vec<&str> = many.iter().map(String::as_str).collect();
        assert!(matches!(
            try_text(descriptor(&many)).err().unwrap(),
            Error::Unsupported(_)
        ));
        // Garbage that is neither a sparse extent nor a descriptor.
        assert!(try_text(vec![0x41u8; 5000]).is_err());
        assert!(try_text(Vec::new()).is_err());
        // A sector count that overflows.
        assert!(try_text(descriptor(&["RW 18446744073709551615 ZERO"])).is_err());
        assert!(
            try_text(descriptor(&[
                "RW 9223372036854775807 ZERO",
                "RW 9223372036854775807 ZERO"
            ]))
            .is_err()
        );
    }

    #[test]
    fn open_reads_a_descriptor_and_its_extents_from_a_folder() {
        let dir = std::env::temp_dir().join(format!("disk-atlas-vmdk-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let flat = flat_bytes(5, 4096);
        std::fs::write(dir.join("d-flat.vmdk"), &flat).unwrap();
        std::fs::write(
            dir.join("d.vmdk"),
            descriptor(&["RW 8 FLAT \"d-flat.vmdk\" 0"]),
        )
        .unwrap();
        let src = open(&dir.join("d.vmdk")).unwrap();
        let mut buf = vec![0u8; 96];
        src.read_at(4000, &mut buf).unwrap();
        assert_eq!(buf, flat[4000..4096]);
        // A missing extent is an I/O error, not a panic.
        std::fs::remove_file(dir.join("d-flat.vmdk")).unwrap();
        assert!(open(&dir.join("d.vmdk")).is_err());
        // A parent names the file.
        let mut text = descriptor(&["RW 8 ZERO"]);
        text.extend(b"parentFileNameHint=\"base.vmdk\"\n");
        std::fs::write(dir.join("child.vmdk"), text).unwrap();
        let err = open(&dir.join("child.vmdk")).err().unwrap();
        assert!(
            matches!(&err, Error::Unsupported(t) if t.contains("child.vmdk") && t.contains("base.vmdk")),
            "{err}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
