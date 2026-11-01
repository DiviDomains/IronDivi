// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! The files Divi Core keeps with CFlatDB (flat-database.h): the magic
//! message, the network's magic number, the data, and the double SHA-256 of
//! all that; and the serialisation helpers they are read and written with.

/// What CFlatDB::Read makes of a file's checksum and header
/// (flat-database.h:178-216, flat-database.cpp:18-60)
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Header {
    /// No file
    Missing,
    /// The checksum is right but the header does not parse (IncorrectFormat)
    BadFormat,
    /// The checksum, the magic message or the network's magic number is
    /// wrong: divid will not start on it, nor overwrite it
    Invalid(&'static str),
}

/// The data of the file at `path` once its checksum, its network's magic
/// number and its magic message (checked in that order, as NextChunk and
/// Read do) are right
pub(crate) fn read(
    path: &std::path::Path,
    magic: &str,
    network_magic: [u8; 4],
) -> Result<Vec<u8>, Header> {
    let bytes = std::fs::read(path).map_err(|_| Header::Missing)?;
    // The data is all but the last 32 bytes, which are its double SHA-256
    if bytes.len() < 32 {
        return Err(Header::Invalid("the checksum cannot be read"));
    }
    let (data, checksum) = bytes.split_at(bytes.len() - 32);
    if divi_crypto::double_sha256(data) != checksum {
        return Err(Header::Invalid("the checksum does not match"));
    }
    let mut r = Reader { data, pos: 0 };
    let (Some(file_magic), Some(network)) = (r.varbytes(), r.array::<4>()) else {
        return Err(Header::BadFormat);
    };
    if network != network_magic {
        return Err(Header::Invalid("another network's file"));
    }
    if file_magic != magic.as_bytes() {
        return Err(Header::Invalid("another kind of file"));
    }
    Ok(data[r.pos..].to_vec())
}

/// The file's bytes for `data`, as FlatDataFile::Write makes them
/// (flat-database.h:59-97)
pub(crate) fn bytes(magic: &str, network_magic: [u8; 4], data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + magic.len() + 40);
    write_varbytes(&mut out, magic.as_bytes());
    out.extend_from_slice(&network_magic);
    out.extend_from_slice(data);
    let checksum = divi_crypto::double_sha256(&out);
    out.extend_from_slice(&checksum);
    out
}

/// uint256's order: the bytes compared from the last
pub(crate) fn cmp_u256(a: &[u8; 32], b: &[u8; 32]) -> std::cmp::Ordering {
    a.iter().rev().cmp(b.iter().rev())
}

pub(crate) fn write_compact_size(out: &mut Vec<u8>, n: usize) {
    match n {
        0..=0xfc => out.push(n as u8),
        0xfd..=0xffff => {
            out.push(0xfd);
            out.extend_from_slice(&(n as u16).to_le_bytes());
        }
        0x1_0000..=0xffff_ffff => {
            out.push(0xfe);
            out.extend_from_slice(&(n as u32).to_le_bytes());
        }
        _ => {
            out.push(0xff);
            out.extend_from_slice(&(n as u64).to_le_bytes());
        }
    }
}

pub(crate) fn write_varbytes(out: &mut Vec<u8>, bytes: &[u8]) {
    write_compact_size(out, bytes.len());
    out.extend_from_slice(bytes);
}

/// A reader over the bytes of a file; None once they run out
pub(crate) struct Reader<'a> {
    pub(crate) data: &'a [u8],
    pub(crate) pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
    pub(crate) fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let out = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(out)
    }
    pub(crate) fn array<const N: usize>(&mut self) -> Option<[u8; N]> {
        self.take(N)?.try_into().ok()
    }
    pub(crate) fn u32(&mut self) -> Option<u32> {
        self.array().map(u32::from_le_bytes)
    }
    pub(crate) fn i32(&mut self) -> Option<i32> {
        self.array().map(i32::from_le_bytes)
    }
    pub(crate) fn i64(&mut self) -> Option<i64> {
        self.array().map(i64::from_le_bytes)
    }
    pub(crate) fn compact_size(&mut self) -> Option<usize> {
        Some(match self.take(1)?[0] {
            0xfd => u16::from_le_bytes(self.array()?) as usize,
            0xfe => u32::from_le_bytes(self.array()?) as usize,
            0xff => usize::try_from(u64::from_le_bytes(self.array()?)).ok()?,
            n => n as usize,
        })
    }
    pub(crate) fn varbytes(&mut self) -> Option<Vec<u8>> {
        let n = self.compact_size()?;
        self.take(n).map(<[u8]>::to_vec)
    }
    /// What is left
    pub(crate) fn rest(&self) -> &'a [u8] {
        &self.data[self.pos..]
    }
}
