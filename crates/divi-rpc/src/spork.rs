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

use crate::error::{Error, RpcError};
use crate::protocol::Params;
use serde_json::Value;

pub struct SporkRpc;

impl SporkRpc {
    pub fn new() -> Self {
        Self
    }

    pub fn spork(&self, params: &Params) -> Result<Value, Error> {
        let command = params.get_str(0);

        if let Some(cmd) = command {
            match cmd.to_lowercase().as_str() {
                "show" | "active" => {}
                _ => {
                    let _value = params.get_str(1);
                }
            }
        }

        Err(RpcError::new(
            -32603,
            "Spork management requires network-wide coordination and admin privileges. Sporks are network-level configuration switches that can activate or deactivate features without requiring a hard fork. This functionality requires P2P message handling, cryptographic signing with the spork private key, and network broadcast capabilities. This feature will be added in a future release. For spork operations, please use the C++ Divi client."
        ).into())
    }
}

impl Default for SporkRpc {
    fn default() -> Self {
        Self::new()
    }
}
