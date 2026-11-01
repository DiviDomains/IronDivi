// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! -timeout: the connection timeout is divid's, 5000 ms unless set, and the
//! node takes the configured value (net.cpp SetNetworkingParameters)

use divi_node::config::NodeConfig;
use divi_primitives::ChainMode;
use std::time::Duration;

#[test]
fn connect_timeout_is_divid_s_and_configurable() {
    let config = NodeConfig::regtest(ChainMode::Divi);
    assert_eq!(config.p2p.connect_timeout_ms, 5000);
    assert_eq!(divi_network::connect_timeout(), Duration::from_millis(5000));
    divi_network::set_connect_timeout_ms(1234);
    assert_eq!(divi_network::connect_timeout(), Duration::from_millis(1234));
}
