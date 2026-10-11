// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 Bert Shuler
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.

//! ABI bindings. Signatures are hand-kept in sync with `contracts/htlc/src/Erc20Htlc.sol`
//! (the Foundry project is the source of truth; `swap_id_matches_contract` cross-checks
//! the two independently compute the same id).

use alloy::sol;

sol! {
    #[sol(rpc)]
    interface IErc20Htlc {
        function lock(address token, uint256 amount, address receiver, bytes32 hashlock, uint256 timelock)
            external returns (bytes32 id);
        function claim(bytes32 id, bytes32 preimage) external;
        function refund(bytes32 id) external;
        function swapId(
            address sender, address receiver, address token, uint256 amount, bytes32 hashlock, uint256 timelock
        ) external pure returns (bytes32);
        function swaps(bytes32 id) external view returns (
            address sender,
            address receiver,
            address token,
            uint256 amount,
            bytes32 hashlock,
            uint256 timelock,
            bool claimed,
            bool refunded
        );

        event Locked(
            bytes32 indexed id,
            address indexed sender,
            address indexed receiver,
            address token,
            uint256 amount,
            bytes32 hashlock,
            uint256 timelock
        );
        event Claimed(bytes32 indexed id, bytes32 preimage);
        event Refunded(bytes32 indexed id);
    }
}

sol! {
    #[sol(rpc)]
    interface IErc20 {
        function approve(address spender, uint256 amount) external returns (bool);
        function allowance(address owner, address spender) external view returns (uint256);
        function balanceOf(address account) external view returns (uint256);
        function transfer(address to, uint256 amount) external returns (bool);
    }
}

// `MockErc20.mint` (`contracts/htlc/test/MockErc20.sol`) — anvil-only test token funding.
sol! {
    #[sol(rpc)]
    interface IMockErc20 {
        function mint(address to, uint256 amount) external;
    }
}
