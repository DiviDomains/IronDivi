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

use super::*;

#[test]
fn test_parse_config_line() {
    // Basic key=value
    assert_eq!(
        parse_config_line("rpcuser=testuser"),
        Some(("rpcuser".to_string(), "testuser".to_string()))
    );

    // With spaces
    assert_eq!(
        parse_config_line("  rpcport = 9999  "),
        Some(("rpcport".to_string(), "9999".to_string()))
    );

    // Comment
    assert_eq!(parse_config_line("# This is a comment"), None);

    // Inline comment
    assert_eq!(
        parse_config_line("rpcuser=testuser # inline comment"),
        Some(("rpcuser".to_string(), "testuser".to_string()))
    );

    // Boolean flag
    assert_eq!(
        parse_config_line("testnet"),
        Some(("testnet".to_string(), "1".to_string()))
    );

    // Empty line
    assert_eq!(parse_config_line(""), None);
    assert_eq!(parse_config_line("   "), None);

    // Empty key
    assert_eq!(parse_config_line("=value"), None);

    // Value with equals sign
    assert_eq!(
        parse_config_line("key=value=with=equals"),
        Some(("key".to_string(), "value=with=equals".to_string()))
    );
}

#[test]
fn test_parse_bool() {
    assert_eq!(parse_bool("1"), Some(true));
    assert_eq!(parse_bool("0"), Some(false));
    assert_eq!(parse_bool("true"), Some(true));
    assert_eq!(parse_bool("false"), Some(false));
    assert_eq!(parse_bool("TRUE"), Some(true));
    assert_eq!(parse_bool("FALSE"), Some(false));
    assert_eq!(parse_bool("yes"), Some(true));
    assert_eq!(parse_bool("no"), Some(false));
    assert_eq!(parse_bool("invalid"), None);
}

#[test]
fn test_parse_int() {
    assert_eq!(parse_int::<u16>("9999"), Some(9999u16));
    assert_eq!(parse_int::<u32>("123456"), Some(123456u32));
    assert_eq!(parse_int::<u16>("invalid"), None);
    assert_eq!(parse_int::<u16>("99999"), None); // overflow
}

#[test]
fn test_apply_config_file() {
    let mut config = NodeConfig::regtest();
    let mut file_config = std::collections::HashMap::new();

    // RPC settings
    file_config.insert("rpcuser".to_string(), "testuser".to_string());
    file_config.insert("rpcpassword".to_string(), "testpass".to_string());
    file_config.insert("rpcport".to_string(), "9999".to_string());
    file_config.insert("rpcbind".to_string(), "192.168.1.1".to_string());

    // P2P settings
    file_config.insert("port".to_string(), "8888".to_string());
    file_config.insert("bind".to_string(), "10.0.0.1".to_string());
    file_config.insert("listen".to_string(), "1".to_string());

    // Index settings
    file_config.insert("txindex".to_string(), "0".to_string());
    file_config.insert("spentindex".to_string(), "1".to_string());
    file_config.insert("addressindex".to_string(), "1".to_string());

    // Peer settings
    file_config.insert("addnode".to_string(), "10.0.0.2:51472".to_string());

    // Log settings
    file_config.insert("maxlogsize".to_string(), "2".to_string());
    file_config.insert("maxlogfiles".to_string(), "10".to_string());

    apply_config_file(&mut config, &file_config);

    // Verify RPC settings
    assert_eq!(config.rpc.username, Some("testuser".to_string()));
    assert_eq!(config.rpc.password, Some("testpass".to_string()));
    assert_eq!(config.rpc.port, 9999);
    assert_eq!(config.rpc.listen_addr, "192.168.1.1");

    // Verify P2P settings
    assert_eq!(config.p2p.port, 8888);
    assert_eq!(config.p2p.listen_addr, "10.0.0.1");
    assert_eq!(config.p2p.enable_discovery, true);

    // Verify index settings
    assert_eq!(config.index.txindex, false);
    assert_eq!(config.index.spentindex, true);
    assert_eq!(config.index.addressindex, true);

    // Verify peer settings
    assert!(config
        .network
        .static_peers
        .contains(&"10.0.0.2:51472".to_string()));

    // Verify log settings
    assert_eq!(config.log.max_file_size, 2 * 1_048_576); // 2 MB
    assert_eq!(config.log.max_files, 10);
}

#[test]
fn test_config_invalid_values() {
    let mut config = NodeConfig::regtest();
    let mut file_config = std::collections::HashMap::new();

    // Invalid values should be logged as warnings, config unchanged
    file_config.insert("rpcport".to_string(), "invalid".to_string());
    file_config.insert("port".to_string(), "not_a_number".to_string());
    file_config.insert("txindex".to_string(), "maybe".to_string());

    let original_rpc_port = config.rpc.port;
    let original_p2p_port = config.p2p.port;
    let original_txindex = config.index.txindex;

    apply_config_file(&mut config, &file_config);

    // Values should remain unchanged
    assert_eq!(config.rpc.port, original_rpc_port);
    assert_eq!(config.p2p.port, original_p2p_port);
    assert_eq!(config.index.txindex, original_txindex);
}

#[test]
fn test_load_nonexistent_config_file() {
    let path = PathBuf::from("/tmp/nonexistent_config_file_12345.conf");
    let result = load_config_file(&path).unwrap();
    assert!(result.is_none());
}

#[test]
fn test_cli_overrides_config_file() {
    // Create a test config file
    let temp_dir = std::env::temp_dir();
    let config_path = temp_dir.join("test_irondivi_override.conf");
    std::fs::write(&config_path, "rpcport=9999\nrpcuser=fileuser\ntxindex=0").unwrap();

    // Create Args with CLI overrides
    let args = Args {
        conf: Some(config_path.clone()),
        datadir: Some(temp_dir.clone()),
        testnet: false,
        regtest: true,
        daemon: false,
        printtoconsole: true,
        rpcuser: Some("cliuser".to_string()), // CLI override
        rpcpassword: None,
        rpcport: Some(7777), // CLI override
        rpcbind: None,
        port: None,
        bind: None,
        addnode: vec![],
        connect: vec![],
        debug: false,
        wallet: None,
        disablewallet: false,
        txindex: true, // CLI override
        spentindex: false,
        addressindex: false,
        reindex: false,
        export_chain: false,
        export_start: None,
        export_end: None,
        export_output: None,
        maxlogsize: 1,
        maxlogfiles: 5,
    };

    let config = build_config(&args).unwrap();

    // CLI args should override file config
    assert_eq!(config.rpc.username, Some("cliuser".to_string())); // CLI wins
    assert_eq!(config.rpc.port, 7777); // CLI wins
    assert_eq!(config.index.txindex, true); // CLI wins

    // Cleanup
    let _ = std::fs::remove_file(&config_path);
}
