// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// Portions derived from Divi Core (https://github.com/DiviProject/Divi)
// licensed under the MIT License. See LICENSE-MIT-UPSTREAM for details.

//! Bounds-checked reading of message payloads
//!
//! Every read checks the remaining length, so a short or lying payload is a
//! parse error (Divi Core's "end of data") instead of a panic, and sizes go
//! through `CompactSize`, which refuses anything above `MAX_SIZE`.

use crate::error::NetworkError;
use divi_primitives::compact::CompactSize;
use divi_primitives::hash::Hash256;
use divi_primitives::serialize::Decodable;

fn short() -> NetworkError {
    NetworkError::Deserialization("end of data".into())
}

/// A cursor over a payload
pub(crate) struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub(crate) fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    /// Bytes not read yet
    pub(crate) fn remaining(&self) -> usize {
        self.data.len() - self.pos
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], NetworkError> {
        if n > self.remaining() {
            return Err(short());
        }
        let out = &self.data[self.pos..self.pos + n];
        self.pos += n;
        Ok(out)
    }

    fn array<const N: usize>(&mut self) -> Result<[u8; N], NetworkError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, NetworkError> {
        Ok(self.take(1)?[0])
    }

    pub(crate) fn u16_be(&mut self) -> Result<u16, NetworkError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, NetworkError> {
        Ok(u32::from_le_bytes(self.array()?))
    }

    pub(crate) fn i32(&mut self) -> Result<i32, NetworkError> {
        Ok(i32::from_le_bytes(self.array()?))
    }

    pub(crate) fn u64(&mut self) -> Result<u64, NetworkError> {
        Ok(u64::from_le_bytes(self.array()?))
    }

    pub(crate) fn i64(&mut self) -> Result<i64, NetworkError> {
        Ok(i64::from_le_bytes(self.array()?))
    }

    pub(crate) fn hash(&mut self) -> Result<Hash256, NetworkError> {
        Ok(Hash256::from_bytes(self.array()?))
    }

    /// A CompactSize length (at most `MAX_SIZE`, as Divi Core's `ReadCompactSize`)
    pub(crate) fn size(&mut self) -> Result<usize, NetworkError> {
        let mut rest = &self.data[self.pos..];
        let before = rest.len();
        let size = CompactSize::decode(&mut rest).map_err(|e| match e {
            divi_primitives::error::Error::UnexpectedEof => short(),
            other => NetworkError::Deserialization(other.to_string()),
        })?;
        self.pos += before - rest.len();
        Ok(size.value() as usize)
    }

    /// A value in Divi's serialization, read from the rest of the payload
    pub(crate) fn decode<T: Decodable>(&mut self) -> Result<T, NetworkError> {
        let mut rest = &self.data[self.pos..];
        let before = rest.len();
        let value = T::decode(&mut rest).map_err(|e| match e {
            divi_primitives::error::Error::UnexpectedEof => short(),
            other => NetworkError::Deserialization(other.to_string()),
        })?;
        self.pos += before - rest.len();
        Ok(value)
    }

    /// A length-prefixed byte string
    pub(crate) fn var_bytes(&mut self) -> Result<&'a [u8], NetworkError> {
        let len = self.size()?;
        self.take(len)
    }

    /// A length-prefixed string of at most `limit` bytes (Divi Core
    /// `LIMITED_STRING`: a longer one is a parse error)
    pub(crate) fn limited_string(&mut self, limit: usize) -> Result<String, NetworkError> {
        let len = self.size()?;
        if len > limit {
            return Err(NetworkError::Deserialization(
                "String length limit exceeded".into(),
            ));
        }
        Ok(String::from_utf8_lossy(self.take(len)?).into_owned())
    }

    /// Capacity to reserve for `count` items of `item_size` bytes each:
    /// never more than the payload could hold
    pub(crate) fn capacity(&self, count: usize, item_size: usize) -> usize {
        count.min(self.remaining() / item_size.max(1))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_reads_are_errors() {
        let mut r = Reader::new(&[1, 2, 3]);
        assert!(r.u32().is_err());
        assert_eq!(r.u8().unwrap(), 1);
        assert!(r.take(3).is_err());
        assert_eq!(r.take(2).unwrap(), &[2, 3]);
        assert!(r.is_empty());
    }

    #[test]
    fn sizes_above_max_size_are_refused() {
        // 0xfe + 0x02000001
        let mut r = Reader::new(&[0xfe, 0x01, 0x00, 0x00, 0x02]);
        assert!(r.size().is_err());
        let mut r = Reader::new(&[0xfe, 0x00, 0x00, 0x00, 0x02]);
        assert_eq!(r.size().unwrap(), 0x0200_0000);
    }
}
