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

//! Serialization matching Divi's C++ CDataStream format
//!
//! All integers are little-endian. Vectors use CompactSize length prefix.

use crate::error::Error;
use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use std::io::{Cursor, Read, Write};

/// Trait for types that can be serialized to bytes (matching C++ Serialize)
pub trait Encodable {
    /// Encode this value to a writer
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error>;

    /// Get the serialized size in bytes
    fn encoded_size(&self) -> usize;
}

/// Trait for types that can be deserialized from bytes (matching C++ Unserialize)
pub trait Decodable: Sized {
    /// Decode a value from a reader
    fn decode<R: Read>(reader: &mut R) -> Result<Self, Error>;
}

/// Serialize a value to bytes
pub fn serialize<T: Encodable>(value: &T) -> Vec<u8> {
    let mut buf = Vec::with_capacity(value.encoded_size());
    value
        .encode(&mut buf)
        .expect("serialization to vec cannot fail");
    buf
}

/// Deserialize a value from bytes
pub fn deserialize<T: Decodable>(data: &[u8]) -> Result<T, Error> {
    let mut cursor = Cursor::new(data);
    T::decode(&mut cursor)
}

// Implementations for primitive integer types (all little-endian)

impl Encodable for u8 {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        writer.write_u8(*self)?;
        Ok(1)
    }

    fn encoded_size(&self) -> usize {
        1
    }
}

impl Decodable for u8 {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        Ok(reader.read_u8()?)
    }
}

impl Encodable for i8 {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        writer.write_i8(*self)?;
        Ok(1)
    }

    fn encoded_size(&self) -> usize {
        1
    }
}

impl Decodable for i8 {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        Ok(reader.read_i8()?)
    }
}

impl Encodable for u16 {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        writer.write_u16::<LittleEndian>(*self)?;
        Ok(2)
    }

    fn encoded_size(&self) -> usize {
        2
    }
}

impl Decodable for u16 {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        Ok(reader.read_u16::<LittleEndian>()?)
    }
}

impl Encodable for i16 {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        writer.write_i16::<LittleEndian>(*self)?;
        Ok(2)
    }

    fn encoded_size(&self) -> usize {
        2
    }
}

impl Decodable for i16 {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        Ok(reader.read_i16::<LittleEndian>()?)
    }
}

impl Encodable for u32 {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        writer.write_u32::<LittleEndian>(*self)?;
        Ok(4)
    }

    fn encoded_size(&self) -> usize {
        4
    }
}

impl Decodable for u32 {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        Ok(reader.read_u32::<LittleEndian>()?)
    }
}

impl Encodable for i32 {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        writer.write_i32::<LittleEndian>(*self)?;
        Ok(4)
    }

    fn encoded_size(&self) -> usize {
        4
    }
}

impl Decodable for i32 {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        Ok(reader.read_i32::<LittleEndian>()?)
    }
}

impl Encodable for u64 {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        writer.write_u64::<LittleEndian>(*self)?;
        Ok(8)
    }

    fn encoded_size(&self) -> usize {
        8
    }
}

impl Decodable for u64 {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        Ok(reader.read_u64::<LittleEndian>()?)
    }
}

impl Encodable for i64 {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        writer.write_i64::<LittleEndian>(*self)?;
        Ok(8)
    }

    fn encoded_size(&self) -> usize {
        8
    }
}

impl Decodable for i64 {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        Ok(reader.read_i64::<LittleEndian>()?)
    }
}

impl Encodable for bool {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        writer.write_u8(if *self { 1 } else { 0 })?;
        Ok(1)
    }

    fn encoded_size(&self) -> usize {
        1
    }
}

impl Decodable for bool {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        Ok(reader.read_u8()? != 0)
    }
}

// Implementation for Vec<T> where T: Encodable + Decodable
// Note: For Vec<u8>, this will encode each byte individually with the u8 impl,
// which is correct for the protocol (CompactSize length + raw bytes).
impl<T: Encodable> Encodable for Vec<T> {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        let mut size = crate::compact::CompactSize(self.len() as u64).encode(writer)?;
        for item in self {
            size += item.encode(writer)?;
        }
        Ok(size)
    }

    fn encoded_size(&self) -> usize {
        crate::compact::CompactSize(self.len() as u64).encoded_size()
            + self.iter().map(|item| item.encoded_size()).sum::<usize>()
    }
}

impl<T: Decodable> Decodable for Vec<T> {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let len = crate::compact::CompactSize::decode(reader)?.0 as usize;
        let mut vec = Vec::with_capacity(len);
        for _ in 0..len {
            vec.push(T::decode(reader)?);
        }
        Ok(vec)
    }
}

// Fixed-size array implementations
impl<const N: usize> Encodable for [u8; N] {
    fn encode<W: Write>(&self, writer: &mut W) -> Result<usize, Error> {
        writer.write_all(self)?;
        Ok(N)
    }

    fn encoded_size(&self) -> usize {
        N
    }
}

impl<const N: usize> Decodable for [u8; N] {
    fn decode<R: Read>(reader: &mut R) -> Result<Self, Error> {
        let mut buf = [0u8; N];
        reader.read_exact(&mut buf)?;
        Ok(buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_u32_roundtrip() {
        let value: u32 = 0x12345678;
        let encoded = serialize(&value);
        assert_eq!(encoded, vec![0x78, 0x56, 0x34, 0x12]); // Little-endian
        let decoded: u32 = deserialize(&encoded).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn test_i64_roundtrip() {
        let value: i64 = -1;
        let encoded = serialize(&value);
        assert_eq!(encoded, vec![0xff; 8]);
        let decoded: i64 = deserialize(&encoded).unwrap();
        assert_eq!(decoded, value);
    }

    #[test]
    fn test_vec_u8_roundtrip() {
        let value: Vec<u8> = vec![1, 2, 3, 4, 5];
        let encoded = serialize(&value);
        assert_eq!(encoded, vec![5, 1, 2, 3, 4, 5]); // CompactSize(5) + data
        let decoded: Vec<u8> = deserialize(&encoded).unwrap();
        assert_eq!(decoded, value);
    }
}
