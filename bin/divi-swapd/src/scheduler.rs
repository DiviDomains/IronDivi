// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! Drives `Maker::tick` at startup and then on an interval.

use std::sync::Arc;
use std::time::Duration;

use divi_swap::Maker;
use tokio::task::JoinHandle;

/// Tick once immediately (resuming whatever a previous run left in the store), then every
/// `every`. Tick errors are logged and never stop the loop.
pub fn spawn_scheduler(maker: Arc<Maker>, every: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(every);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            if let Err(e) = maker.tick().await {
                tracing::warn!(error = %e, "scheduler tick failed");
            }
        }
    })
}
