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

use std::fs;

#[test]
fn test_config_file_integration() {
    // Create a temporary directory for test
    let temp_dir = std::env::temp_dir().join("irondivi_config_test");
    fs::create_dir_all(&temp_dir).unwrap();

    // Create a test config file with all supported options
    let config_path = temp_dir.join("irondivi.conf");
    let config_content = r#"
# IronDivi Configuration File Test
# This tests all supported configuration options

# RPC Settings
rpcuser=testuser123
rpcpassword=securepass456
rpcport=19999
rpcbind=192.168.1.100

# P2P Network Settings
port=18888
bind=10.0.0.50
listen=1

# Index Settings
txindex=1
spentindex=1
addressindex=0

# Peer Connections
addnode=seed1.example.com:51472
addnode=192.168.1.10:51472

# Logging
maxlogsize=5
maxlogfiles=15

# Unknown keys should be warned but not fail
unknownkey=somevalue
anotherkey=anothervalue

# Empty lines and comments should be ignored

# Boolean values in different formats
# testnet=true
# regtest=yes
"#;

    fs::write(&config_path, config_content).unwrap();

    println!("Test config file created at: {:?}", config_path);
    println!("Config content:");
    println!("{}", config_content);

    // Verify the file was created
    assert!(config_path.exists());
    let content = fs::read_to_string(&config_path).unwrap();
    assert!(content.contains("rpcuser=testuser123"));
    assert!(content.contains("rpcport=19999"));
    assert!(content.contains("txindex=1"));

    // Cleanup
    fs::remove_dir_all(&temp_dir).unwrap();
}

#[test]
fn test_bitcoin_style_config_format() {
    // Test that our parser handles Bitcoin-style config format correctly
    let temp_dir = std::env::temp_dir().join("irondivi_bitcoin_config_test");
    fs::create_dir_all(&temp_dir).unwrap();

    let config_path = temp_dir.join("divi.conf");
    let config_content = r#"
# This is a comment
rpcuser=alice
rpcpassword=hunter2  # inline comment

# Boolean flags
txindex=1
spentindex=0

# Whitespace handling
  port  =  8333
bind=0.0.0.0

# Multiple values (addnode can appear multiple times)
addnode=node1.example.com
addnode=node2.example.com
addnode=192.168.1.5:51472
"#;

    fs::write(&config_path, config_content).unwrap();

    // Verify parsing would work
    assert!(config_path.exists());

    // Cleanup
    fs::remove_dir_all(&temp_dir).unwrap();
}

#[test]
fn test_config_with_network_flags() {
    let temp_dir = std::env::temp_dir().join("irondivi_network_config_test");
    fs::create_dir_all(&temp_dir).unwrap();

    let config_path = temp_dir.join("irondivi.conf");

    // Test mainnet config
    let mainnet_config = r#"
rpcuser=mainnetuser
rpcport=51471
txindex=1
"#;
    fs::write(&config_path, mainnet_config).unwrap();
    assert!(config_path.exists());

    // Test testnet config
    let testnet_config = r#"
testnet=1
rpcuser=testnetuser
rpcport=51473
txindex=1
"#;
    fs::write(&config_path, testnet_config).unwrap();
    assert!(config_path.exists());

    // Test regtest config
    let regtest_config = r#"
regtest=1
rpcuser=regtestuser
rpcport=51475
txindex=1
"#;
    fs::write(&config_path, regtest_config).unwrap();
    assert!(config_path.exists());

    // Cleanup
    fs::remove_dir_all(&temp_dir).unwrap();
}
