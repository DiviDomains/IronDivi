// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! SQLite persistence for maker and taker swaps (file mode 0600; the taker's preimage
//! lives here). **Lane engine** owns the implementation; `open`/`in_memory` are frozen.

use std::path::Path;

use crate::error::Result;

/// Swap database handle. Cheap to clone.
#[derive(Clone)]
#[allow(dead_code)] // filled in by lane engine
pub struct Store {
    conn: std::sync::Arc<parking_lot::Mutex<rusqlite::Connection>>,
}

impl Store {
    /// Open (creating if needed) the database at `path`, migrating the schema.
    pub fn open(path: &Path) -> Result<Self> {
        let _ = path;
        todo!("lane engine: Store::open")
    }

    /// A throwaway in-memory database (tests).
    pub fn in_memory() -> Result<Self> {
        todo!("lane engine: Store::in_memory")
    }
}
