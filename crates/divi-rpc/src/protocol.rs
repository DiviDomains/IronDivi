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

//! JSON-RPC 2.0 protocol types
//!
//! Standard JSON-RPC request and response types.

use crate::error::RpcError;
use serde::{Deserialize, Serialize};

/// JSON-RPC version string
pub const JSON_RPC_VERSION: &str = "2.0";

/// JSON-RPC request ID
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(untagged)]
pub enum RequestId {
    Number(i64),
    String(String),
    Null,
}

impl Default for RequestId {
    fn default() -> Self {
        RequestId::Null
    }
}

/// JSON-RPC request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Request {
    /// JSON-RPC version (should be "2.0")
    pub jsonrpc: String,
    /// Request ID
    #[serde(default)]
    pub id: RequestId,
    /// Method name
    pub method: String,
    /// Method parameters
    #[serde(default)]
    pub params: Params,
}

/// Method parameters
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(untagged)]
pub enum Params {
    #[default]
    None,
    Array(Vec<serde_json::Value>),
    Object(serde_json::Map<String, serde_json::Value>),
}

impl Params {
    /// Get positional parameter by index
    pub fn get(&self, index: usize) -> Option<&serde_json::Value> {
        match self {
            Params::Array(arr) => arr.get(index),
            _ => None,
        }
    }

    /// Get named parameter by key
    pub fn get_named(&self, key: &str) -> Option<&serde_json::Value> {
        match self {
            Params::Object(obj) => obj.get(key),
            _ => None,
        }
    }

    /// Get parameter as string
    pub fn get_str(&self, index: usize) -> Option<&str> {
        self.get(index).and_then(|v| v.as_str())
    }

    /// Get parameter as i64
    /// Accepts JSON numbers or numeric strings (matches C++ Divi behavior)
    pub fn get_i64(&self, index: usize) -> Option<i64> {
        self.get(index).and_then(|v| {
            if let Some(n) = v.as_i64() {
                return Some(n);
            }
            if let Some(s) = v.as_str() {
                return s.parse::<i64>().ok();
            }
            None
        })
    }

    /// Get parameter as u64
    /// Accepts JSON numbers or numeric strings (matches C++ Divi behavior)
    pub fn get_u64(&self, index: usize) -> Option<u64> {
        self.get(index).and_then(|v| {
            if let Some(n) = v.as_u64() {
                return Some(n);
            }
            if let Some(s) = v.as_str() {
                return s.parse::<u64>().ok();
            }
            None
        })
    }

    /// Get parameter as bool
    /// Handles JSON booleans, numbers (0=false, non-zero=true), and strings ("true"/"false" only)
    /// Matches C++ Divi RPC behavior: rejects ambiguous strings like "yes", "no", "1", "0"
    pub fn get_bool(&self, index: usize) -> Option<bool> {
        self.get(index).and_then(|v| {
            if let Some(b) = v.as_bool() {
                return Some(b);
            }
            if let Some(n) = v.as_i64() {
                return Some(n != 0);
            }
            if let Some(n) = v.as_u64() {
                return Some(n != 0);
            }
            if let Some(n) = v.as_f64() {
                return Some(n != 0.0);
            }
            if let Some(s) = v.as_str() {
                match s.to_lowercase().as_str() {
                    "true" => return Some(true),
                    "false" => return Some(false),
                    _ => return None,
                }
            }
            None
        })
    }

    /// Get the number of parameters
    pub fn len(&self) -> usize {
        match self {
            Params::None => 0,
            Params::Array(arr) => arr.len(),
            Params::Object(obj) => obj.len(),
        }
    }

    /// Check if empty
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// JSON-RPC response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Response {
    /// JSON-RPC version
    pub jsonrpc: String,
    /// Request ID
    pub id: RequestId,
    /// Result (success case)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Error (failure case)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<RpcError>,
}

impl Response {
    /// Create a success response
    pub fn success(id: RequestId, result: serde_json::Value) -> Self {
        Response {
            jsonrpc: JSON_RPC_VERSION.to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    /// Create an error response
    pub fn error(id: RequestId, error: RpcError) -> Self {
        Response {
            jsonrpc: JSON_RPC_VERSION.to_string(),
            id,
            result: None,
            error: Some(error),
        }
    }

    /// Create an error response with default ID
    pub fn error_only(error: RpcError) -> Self {
        Self::error(RequestId::Null, error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_request_parsing() {
        let json = r#"{"jsonrpc":"2.0","id":1,"method":"getblockcount","params":[]}"#;
        let req: Request = serde_json::from_str(json).unwrap();

        assert_eq!(req.jsonrpc, "2.0");
        assert_eq!(req.id, RequestId::Number(1));
        assert_eq!(req.method, "getblockcount");
    }

    #[test]
    fn test_request_with_params() {
        let json = r#"{"jsonrpc":"2.0","id":"test","method":"getblock","params":["00000000"]}"#;
        let req: Request = serde_json::from_str(json).unwrap();

        assert_eq!(req.id, RequestId::String("test".to_string()));
        assert_eq!(req.params.get_str(0), Some("00000000"));
    }

    #[test]
    fn test_response_success() {
        let resp = Response::success(RequestId::Number(1), serde_json::json!(100));
        let json = serde_json::to_string(&resp).unwrap();

        assert!(json.contains(r#""result":100"#));
        assert!(!json.contains("error"));
    }

    #[test]
    fn test_response_error() {
        let resp = Response::error(RequestId::Number(1), RpcError::method_not_found("unknown"));
        let json = serde_json::to_string(&resp).unwrap();

        assert!(json.contains("error"));
        assert!(json.contains("-32601"));
        assert!(!json.contains("result"));
    }

    #[test]
    fn test_params_access() {
        let params = Params::Array(vec![
            serde_json::json!("abc"),
            serde_json::json!(42),
            serde_json::json!(true),
        ]);

        assert_eq!(params.get_str(0), Some("abc"));
        assert_eq!(params.get_i64(1), Some(42));
        assert_eq!(params.get_bool(2), Some(true));
        assert_eq!(params.len(), 3);
    }

    #[test]
    fn test_get_bool_native_boolean() {
        let params = Params::Array(vec![serde_json::json!(true)]);
        assert_eq!(params.get_bool(0), Some(true));

        let params = Params::Array(vec![serde_json::json!(false)]);
        assert_eq!(params.get_bool(0), Some(false));
    }

    #[test]
    fn test_get_bool_numbers() {
        let params = Params::Array(vec![serde_json::json!(0)]);
        assert_eq!(params.get_bool(0), Some(false));

        let params = Params::Array(vec![serde_json::json!(1)]);
        assert_eq!(params.get_bool(0), Some(true));

        let params = Params::Array(vec![serde_json::json!(-1)]);
        assert_eq!(params.get_bool(0), Some(true));

        let params = Params::Array(vec![serde_json::json!(42)]);
        assert_eq!(params.get_bool(0), Some(true));
    }

    #[test]
    fn test_get_bool_strings() {
        let params = Params::Array(vec![serde_json::json!("true")]);
        assert_eq!(params.get_bool(0), Some(true));

        let params = Params::Array(vec![serde_json::json!("false")]);
        assert_eq!(params.get_bool(0), Some(false));

        let params = Params::Array(vec![serde_json::json!("TRUE")]);
        assert_eq!(params.get_bool(0), Some(true));

        let params = Params::Array(vec![serde_json::json!("FALSE")]);
        assert_eq!(params.get_bool(0), Some(false));
    }

    #[test]
    fn test_get_bool_rejects_ambiguous_strings() {
        let params = Params::Array(vec![serde_json::json!("yes")]);
        assert_eq!(params.get_bool(0), None);

        let params = Params::Array(vec![serde_json::json!("no")]);
        assert_eq!(params.get_bool(0), None);

        let params = Params::Array(vec![serde_json::json!("maybe")]);
        assert_eq!(params.get_bool(0), None);

        let params = Params::Array(vec![serde_json::json!("1")]);
        assert_eq!(params.get_bool(0), None);

        let params = Params::Array(vec![serde_json::json!("0")]);
        assert_eq!(params.get_bool(0), None);

        let params = Params::Array(vec![serde_json::json!("")]);
        assert_eq!(params.get_bool(0), None);
    }

    #[test]
    fn test_get_bool_rejects_invalid_types() {
        let params = Params::Array(vec![serde_json::json!(null)]);
        assert_eq!(params.get_bool(0), None);

        let params = Params::Array(vec![serde_json::json!([1, 2, 3])]);
        assert_eq!(params.get_bool(0), None);

        let params = Params::Array(vec![serde_json::json!({"key": "value"})]);
        assert_eq!(params.get_bool(0), None);
    }

    #[test]
    fn test_get_i64_accepts_numbers() {
        let params = Params::Array(vec![serde_json::json!(0)]);
        assert_eq!(params.get_i64(0), Some(0));

        let params = Params::Array(vec![serde_json::json!(42)]);
        assert_eq!(params.get_i64(0), Some(42));

        let params = Params::Array(vec![serde_json::json!(-123)]);
        assert_eq!(params.get_i64(0), Some(-123));
    }

    #[test]
    fn test_get_i64_accepts_numeric_strings() {
        let params = Params::Array(vec![serde_json::json!("0")]);
        assert_eq!(params.get_i64(0), Some(0));

        let params = Params::Array(vec![serde_json::json!("42")]);
        assert_eq!(params.get_i64(0), Some(42));

        let params = Params::Array(vec![serde_json::json!("-123")]);
        assert_eq!(params.get_i64(0), Some(-123));

        let params = Params::Array(vec![serde_json::json!("1")]);
        assert_eq!(params.get_i64(0), Some(1));
    }

    #[test]
    fn test_get_i64_rejects_non_numeric_strings() {
        let params = Params::Array(vec![serde_json::json!("abc")]);
        assert_eq!(params.get_i64(0), None);

        let params = Params::Array(vec![serde_json::json!("12.34")]);
        assert_eq!(params.get_i64(0), None);

        let params = Params::Array(vec![serde_json::json!("")]);
        assert_eq!(params.get_i64(0), None);
    }
}
