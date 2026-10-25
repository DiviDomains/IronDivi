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

//! The node's warning, as Divi Core's Warnings keeps it (Warnings.cpp): the
//! status bar text that getinfo and getmininginfo give as "errors"
//! (rpcmisc.cpp:156, rpcmining.cpp:242).

use std::sync::RwLock;

static MISC_WARNING: RwLock<String> = RwLock::new(String::new());

/// Set the miscellaneous warning (Warnings::setMiscWarning)
pub fn set_misc_warning(text: &str) {
    if let Ok(mut warning) = MISC_WARNING.write() {
        *warning = text.to_string();
    }
}

/// The status bar text (Warnings::GetWarnings): the miscellaneous warning
pub fn status_bar() -> String {
    MISC_WARNING
        .read()
        .map(|warning| warning.clone())
        .unwrap_or_default()
}
