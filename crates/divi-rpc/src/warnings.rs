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
//! (rpcmisc.cpp:156, rpcmining.cpp:242), and the safe mode -testsafemode
//! turns on, in which the server refuses some calls (rpcserver.cpp:1049-1054).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::RwLock;

static MISC_WARNING: RwLock<String> = RwLock::new(String::new());
static TEST_SAFE_MODE: AtomicBool = AtomicBool::new(false);
static SAFE_MODE_DISABLED: AtomicBool = AtomicBool::new(false);

/// Divi Core's text for the safe mode -testsafemode turns on (Warnings.cpp:32-33)
const TEST_SAFE_MODE_TEXT: &str = "testsafemode enabled";

/// -testsafemode and -disablesafemode, as the start reads them
pub fn set_safe_mode(test_safe_mode: bool, disable_safe_mode: bool) {
    TEST_SAFE_MODE.store(test_safe_mode, Ordering::Relaxed);
    SAFE_MODE_DISABLED.store(disable_safe_mode, Ordering::Relaxed);
}

/// Set the miscellaneous warning (Warnings::setMiscWarning)
pub fn set_misc_warning(text: &str) {
    if let Ok(mut warning) = MISC_WARNING.write() {
        *warning = text.to_string();
    }
}

/// The status bar text (Warnings::GetWarnings): the miscellaneous warning,
/// else safe mode's text under -testsafemode
pub fn status_bar() -> String {
    let misc = MISC_WARNING
        .read()
        .map(|warning| warning.clone())
        .unwrap_or_default();
    if misc.is_empty() {
        rpc_warning()
    } else {
        misc
    }
}

/// The warning that puts the server in safe mode (GetWarnings' strRPC):
/// safe mode's text under -testsafemode, else none
pub fn rpc_warning() -> String {
    if TEST_SAFE_MODE.load(Ordering::Relaxed) {
        TEST_SAFE_MODE_TEXT.to_string()
    } else {
        String::new()
    }
}

/// The refusal of a call Divi Core does not run in safe mode, unless
/// -disablesafemode is given (rpcserver.cpp:1049-1054)
pub fn safe_mode_refusal() -> Option<String> {
    let warning = rpc_warning();
    if warning.is_empty() || SAFE_MODE_DISABLED.load(Ordering::Relaxed) {
        return None;
    }
    Some(format!("Safe mode: {warning}"))
}
