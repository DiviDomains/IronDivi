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

//! Script stack operations
//!
//! The script stack holds arbitrary byte vectors.
//! Numbers are encoded as little-endian with sign bit.

use crate::error::ScriptError;

/// Maximum stack size (number of elements)
pub const MAX_STACK_SIZE: usize = 1000;

/// Maximum element size in bytes
pub const MAX_ELEMENT_SIZE: usize = 520;

/// Maximum script size in bytes
pub const MAX_SCRIPT_SIZE: usize = 10000;

/// Maximum number of opcodes
pub const MAX_OPS_PER_SCRIPT: usize = 201;

/// A script number (arbitrary precision integer with sign)
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptNum(i64);

impl ScriptNum {
    /// Maximum size of a script number in bytes
    pub const MAX_SIZE: usize = 4;

    /// Create from i64
    pub fn new(n: i64) -> Self {
        ScriptNum(n)
    }

    /// Get as i64
    pub fn value(&self) -> i64 {
        self.0
    }

    /// Decode a script number from bytes
    ///
    /// Numbers are encoded as little-endian with the sign bit in the
    /// most significant byte. Empty array represents 0.
    pub fn decode(
        data: &[u8],
        max_size: usize,
        require_minimal: bool,
    ) -> Result<Self, ScriptError> {
        if data.len() > max_size {
            return Err(ScriptError::ScriptNumOverflow);
        }

        if data.is_empty() {
            return Ok(ScriptNum(0));
        }

        // Check for minimal encoding
        if require_minimal {
            // Check that the number is encoded with the minimum possible
            // number of bytes.
            if data[data.len() - 1] & 0x7f == 0
                && (data.len() <= 1 || data[data.len() - 2] & 0x80 == 0)
            {
                return Err(ScriptError::MinimalData);
            }
        }

        // Decode the number
        let mut result: i64 = 0;
        for (i, &byte) in data.iter().enumerate() {
            result |= (byte as i64) << (8 * i);
        }

        // Handle sign bit
        if data[data.len() - 1] & 0x80 != 0 {
            result &= !(0x80_i64 << (8 * (data.len() - 1)));
            result = -result;
        }

        Ok(ScriptNum(result))
    }

    /// Encode this number to bytes
    pub fn encode(&self) -> Vec<u8> {
        if self.0 == 0 {
            return Vec::new();
        }

        let mut result = Vec::new();
        let negative = self.0 < 0;
        let mut abs_value = if negative {
            -(self.0 as i128) as u64
        } else {
            self.0 as u64
        };

        while abs_value != 0 {
            result.push((abs_value & 0xff) as u8);
            abs_value >>= 8;
        }

        // Add sign bit if necessary
        if result[result.len() - 1] & 0x80 != 0 {
            result.push(if negative { 0x80 } else { 0x00 });
        } else if negative {
            let last = result.len() - 1;
            result[last] |= 0x80;
        }

        result
    }
}

impl From<i64> for ScriptNum {
    fn from(n: i64) -> Self {
        ScriptNum(n)
    }
}

impl From<ScriptNum> for i64 {
    fn from(n: ScriptNum) -> Self {
        n.0
    }
}

impl std::ops::Add for ScriptNum {
    type Output = Self;
    fn add(self, other: Self) -> Self {
        ScriptNum(self.0 + other.0)
    }
}

impl std::ops::Sub for ScriptNum {
    type Output = Self;
    fn sub(self, other: Self) -> Self {
        ScriptNum(self.0 - other.0)
    }
}

impl std::ops::Neg for ScriptNum {
    type Output = Self;
    fn neg(self) -> Self {
        ScriptNum(-self.0)
    }
}

/// Check if a byte vector represents true (non-zero)
pub fn cast_to_bool(data: &[u8]) -> bool {
    for (i, &byte) in data.iter().enumerate() {
        if byte != 0 {
            // Can be negative zero (-0x80 with all other bytes zero)
            if i == data.len() - 1 && byte == 0x80 {
                return false;
            }
            return true;
        }
    }
    false
}

/// Script execution stack
#[derive(Debug, Default)]
pub struct Stack {
    data: Vec<Vec<u8>>,
}

impl Stack {
    /// Create a new empty stack
    pub fn new() -> Self {
        Stack { data: Vec::new() }
    }

    /// Get the number of elements on the stack
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the stack is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Push a value onto the stack
    pub fn push(&mut self, value: Vec<u8>) -> Result<(), ScriptError> {
        if self.data.len() >= MAX_STACK_SIZE {
            return Err(ScriptError::StackSize);
        }
        if value.len() > MAX_ELEMENT_SIZE {
            return Err(ScriptError::ElementSize);
        }
        self.data.push(value);
        Ok(())
    }

    /// Pop a value from the stack
    pub fn pop(&mut self) -> Result<Vec<u8>, ScriptError> {
        self.data.pop().ok_or(ScriptError::InvalidStackOperation)
    }

    /// Peek at the top of the stack
    pub fn top(&self) -> Result<&Vec<u8>, ScriptError> {
        self.data.last().ok_or(ScriptError::InvalidStackOperation)
    }

    /// Get an element by index from the top (0 = top)
    pub fn peek(&self, index: usize) -> Result<&Vec<u8>, ScriptError> {
        if index >= self.data.len() {
            return Err(ScriptError::InvalidStackOperation);
        }
        Ok(&self.data[self.data.len() - 1 - index])
    }

    /// Get a mutable element by index from the top
    pub fn peek_mut(&mut self, index: usize) -> Result<&mut Vec<u8>, ScriptError> {
        let len = self.data.len();
        if index >= len {
            return Err(ScriptError::InvalidStackOperation);
        }
        Ok(&mut self.data[len - 1 - index])
    }

    /// Remove an element at index from top
    pub fn remove(&mut self, index: usize) -> Result<Vec<u8>, ScriptError> {
        if index >= self.data.len() {
            return Err(ScriptError::InvalidStackOperation);
        }
        let pos = self.data.len() - 1 - index;
        Ok(self.data.remove(pos))
    }

    /// Insert an element at index from top
    pub fn insert(&mut self, index: usize, value: Vec<u8>) -> Result<(), ScriptError> {
        if self.data.len() >= MAX_STACK_SIZE {
            return Err(ScriptError::StackSize);
        }
        if value.len() > MAX_ELEMENT_SIZE {
            return Err(ScriptError::ElementSize);
        }
        let pos = self.data.len() - index;
        self.data.insert(pos, value);
        Ok(())
    }

    /// Push a boolean value
    pub fn push_bool(&mut self, value: bool) -> Result<(), ScriptError> {
        if value {
            self.push(vec![1])
        } else {
            self.push(vec![])
        }
    }

    /// Pop and interpret as boolean
    pub fn pop_bool(&mut self) -> Result<bool, ScriptError> {
        let data = self.pop()?;
        Ok(cast_to_bool(&data))
    }

    /// Push a script number
    pub fn push_num(&mut self, num: ScriptNum) -> Result<(), ScriptError> {
        self.push(num.encode())
    }

    /// Pop and interpret as script number
    pub fn pop_num(&mut self, require_minimal: bool) -> Result<ScriptNum, ScriptError> {
        let data = self.pop()?;
        ScriptNum::decode(&data, ScriptNum::MAX_SIZE, require_minimal)
    }

    /// Swap the top two elements
    pub fn swap(&mut self) -> Result<(), ScriptError> {
        let len = self.data.len();
        if len < 2 {
            return Err(ScriptError::InvalidStackOperation);
        }
        self.data.swap(len - 1, len - 2);
        Ok(())
    }

    /// OP_DUP: duplicate top element
    pub fn dup(&mut self) -> Result<(), ScriptError> {
        let top = self.top()?.clone();
        self.push(top)
    }

    /// OP_DROP: remove top element
    pub fn drop(&mut self) -> Result<(), ScriptError> {
        self.pop()?;
        Ok(())
    }

    /// OP_NIP: remove second element (keep top, remove second)
    pub fn nip(&mut self) -> Result<(), ScriptError> {
        self.remove(1)?;
        Ok(())
    }

    /// OP_OVER: copy second element to top
    pub fn over(&mut self) -> Result<(), ScriptError> {
        let second = self.peek(1)?.clone();
        self.push(second)
    }

    /// OP_ROT: rotate top three elements
    pub fn rot(&mut self) -> Result<(), ScriptError> {
        let len = self.data.len();
        if len < 3 {
            return Err(ScriptError::InvalidStackOperation);
        }
        // Move element at -3 to top
        let elem = self.data.remove(len - 3);
        self.data.push(elem);
        Ok(())
    }

    /// OP_TUCK: copy top to before second
    pub fn tuck(&mut self) -> Result<(), ScriptError> {
        let len = self.data.len();
        if len < 2 {
            return Err(ScriptError::InvalidStackOperation);
        }
        let top = self.data[len - 1].clone();
        self.data.insert(len - 2, top);
        Ok(())
    }

    /// OP_2DUP: duplicate top two elements
    pub fn dup2(&mut self) -> Result<(), ScriptError> {
        let len = self.data.len();
        if len < 2 {
            return Err(ScriptError::InvalidStackOperation);
        }
        let a = self.data[len - 2].clone();
        let b = self.data[len - 1].clone();
        self.push(a)?;
        self.push(b)
    }

    /// OP_3DUP: duplicate top three elements
    pub fn dup3(&mut self) -> Result<(), ScriptError> {
        let len = self.data.len();
        if len < 3 {
            return Err(ScriptError::InvalidStackOperation);
        }
        let a = self.data[len - 3].clone();
        let b = self.data[len - 2].clone();
        let c = self.data[len - 1].clone();
        self.push(a)?;
        self.push(b)?;
        self.push(c)
    }

    /// OP_2DROP: drop top two elements
    pub fn drop2(&mut self) -> Result<(), ScriptError> {
        self.pop()?;
        self.pop()?;
        Ok(())
    }

    /// OP_2OVER: copy second pair to top
    pub fn over2(&mut self) -> Result<(), ScriptError> {
        let len = self.data.len();
        if len < 4 {
            return Err(ScriptError::InvalidStackOperation);
        }
        let a = self.data[len - 4].clone();
        let b = self.data[len - 3].clone();
        self.push(a)?;
        self.push(b)
    }

    /// OP_2SWAP: swap top two pairs
    pub fn swap2(&mut self) -> Result<(), ScriptError> {
        let len = self.data.len();
        if len < 4 {
            return Err(ScriptError::InvalidStackOperation);
        }
        self.data.swap(len - 4, len - 2);
        self.data.swap(len - 3, len - 1);
        Ok(())
    }

    /// Clear the stack
    pub fn clear(&mut self) {
        self.data.clear();
    }

    /// Get all data
    pub fn data(&self) -> &[Vec<u8>] {
        &self.data
    }

    /// Take ownership of the data
    pub fn into_data(self) -> Vec<Vec<u8>> {
        self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_script_num_encode_decode() {
        // Zero
        assert_eq!(ScriptNum::new(0).encode(), vec![]);
        assert_eq!(ScriptNum::decode(&[], 4, false).unwrap().value(), 0);

        // Positive numbers
        assert_eq!(ScriptNum::new(1).encode(), vec![0x01]);
        assert_eq!(ScriptNum::new(127).encode(), vec![0x7f]);
        assert_eq!(ScriptNum::new(128).encode(), vec![0x80, 0x00]);
        assert_eq!(ScriptNum::new(255).encode(), vec![0xff, 0x00]);
        assert_eq!(ScriptNum::new(256).encode(), vec![0x00, 0x01]);

        // Negative numbers
        assert_eq!(ScriptNum::new(-1).encode(), vec![0x81]);
        assert_eq!(ScriptNum::new(-127).encode(), vec![0xff]);
        assert_eq!(ScriptNum::new(-128).encode(), vec![0x80, 0x80]);

        // Roundtrip
        for n in [-1000, -1, 0, 1, 127, 128, 255, 256, 1000] {
            let encoded = ScriptNum::new(n).encode();
            let decoded = ScriptNum::decode(&encoded, 4, false).unwrap();
            assert_eq!(decoded.value(), n);
        }
    }

    #[test]
    fn test_cast_to_bool() {
        assert!(!cast_to_bool(&[]));
        assert!(!cast_to_bool(&[0x00]));
        assert!(!cast_to_bool(&[0x80])); // Negative zero
        assert!(!cast_to_bool(&[0x00, 0x00, 0x80]));
        assert!(cast_to_bool(&[0x01]));
        assert!(cast_to_bool(&[0x00, 0x01]));
        assert!(cast_to_bool(&[0x81])); // -1
    }

    #[test]
    fn test_stack_operations() {
        let mut stack = Stack::new();

        // Push and pop
        stack.push(vec![1, 2, 3]).unwrap();
        stack.push(vec![4, 5]).unwrap();
        assert_eq!(stack.len(), 2);
        assert_eq!(stack.pop().unwrap(), vec![4, 5]);
        assert_eq!(stack.pop().unwrap(), vec![1, 2, 3]);
        assert!(stack.is_empty());

        // Dup
        stack.push(vec![1]).unwrap();
        stack.dup().unwrap();
        assert_eq!(stack.len(), 2);
        assert_eq!(stack.pop().unwrap(), vec![1]);
        assert_eq!(stack.pop().unwrap(), vec![1]);

        // Swap
        stack.push(vec![1]).unwrap();
        stack.push(vec![2]).unwrap();
        stack.swap().unwrap();
        assert_eq!(stack.pop().unwrap(), vec![1]);
        assert_eq!(stack.pop().unwrap(), vec![2]);
    }

    #[test]
    fn test_stack_limits() {
        let mut stack = Stack::new();

        // Element size limit
        let big = vec![0u8; MAX_ELEMENT_SIZE + 1];
        assert!(matches!(stack.push(big), Err(ScriptError::ElementSize)));

        // Stack size limit
        for i in 0..MAX_STACK_SIZE {
            stack.push(vec![i as u8]).unwrap();
        }
        assert!(matches!(stack.push(vec![0]), Err(ScriptError::StackSize)));
    }
}
