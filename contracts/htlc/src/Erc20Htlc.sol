// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 human
// IronDivi - https://github.com/DiviDomains/IronDivi
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, version 3.
pragma solidity 0.8.26;

/// Minimal ERC-20 interface (the subset this contract calls).
interface IERC20 {
    function transfer(address to, uint256 amount) external returns (bool);
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
}

/// `transfer`/`transferFrom` that tolerate tokens returning no value (USDT-style) while
/// still reverting on a `false` return or a revert, without pulling in OpenZeppelin.
library SafeTransfer {
    function safeTransfer(IERC20 token, address to, uint256 amount) internal {
        (bool ok, bytes memory data) = address(token).call(abi.encodeCall(IERC20.transfer, (to, amount)));
        require(ok && (data.length == 0 || abi.decode(data, (bool))), "SafeTransfer: transfer failed");
    }

    function safeTransferFrom(IERC20 token, address from, address to, uint256 amount) internal {
        (bool ok, bytes memory data) =
            address(token).call(abi.encodeCall(IERC20.transferFrom, (from, to, amount)));
        require(ok && (data.length == 0 || abi.decode(data, (bool))), "SafeTransfer: transferFrom failed");
    }
}

/// Hash-time-locked ERC-20 escrow for the IronDivi atomic swap POC
/// (`docs/plans/swap-poc/lanes/usdc.md`). Mirrors the UTXO HTLCs in `divi-swap::htlc`:
/// same SHA-256 hashlock over a 32-byte preimage, same claim/refund split. No owner, no
/// upgrade path, no fee; every external call follows checks-effects-interactions, so a
/// malicious or reentrant token cannot double-spend a swap's escrowed funds.
contract Erc20Htlc {
    using SafeTransfer for IERC20;

    struct Swap {
        address sender;
        address receiver;
        IERC20 token;
        uint256 amount;
        bytes32 hashlock;
        uint256 timelock;
        bool claimed;
        bool refunded;
    }

    /// `swapId(...) => Swap`. A zero `sender` means "no such swap".
    mapping(bytes32 => Swap) public swaps;

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

    /// The id a `lock` call with these parameters would produce.
    function swapId(
        address sender,
        address receiver,
        address token,
        uint256 amount,
        bytes32 hashlock,
        uint256 timelock
    ) public pure returns (bytes32) {
        return keccak256(abi.encode(sender, receiver, token, amount, hashlock, timelock));
    }

    /// Escrow `amount` of `token` from the caller for `receiver`, claimable with the
    /// preimage of `hashlock` (SHA-256) or refundable to the caller after `timelock`
    /// (unix seconds). Requires a prior `approve` of at least `amount`.
    function lock(IERC20 token, uint256 amount, address receiver, bytes32 hashlock, uint256 timelock)
        external
        returns (bytes32 id)
    {
        require(amount > 0, "Erc20Htlc: zero amount");
        require(receiver != address(0), "Erc20Htlc: zero receiver");
        require(timelock > block.timestamp, "Erc20Htlc: timelock in the past");
        id = swapId(msg.sender, receiver, address(token), amount, hashlock, timelock);
        require(swaps[id].sender == address(0), "Erc20Htlc: swap exists");

        // Effects before the interaction: a reentrant token cannot relock this id mid-call.
        swaps[id] = Swap({
            sender: msg.sender,
            receiver: receiver,
            token: token,
            amount: amount,
            hashlock: hashlock,
            timelock: timelock,
            claimed: false,
            refunded: false
        });
        // A fee-on-transfer token would deliver less than `amount`, while `claim`/`refund`
        // still promise to pay out the full `amount` recorded above — the shortfall would
        // only surface later, as a revert with no recovery path, when the contract's actual
        // balance can no longer cover every swap's recorded `amount`. Caught here instead,
        // before any state outlives this one reverting transaction (same "reject, don't
        // silently round" stance as `amount_to_usdc_units`). `>=`, not `==`: a token that
        // delivers *more* than requested leaves harmless dust the contract just holds, not
        // a shortfall anyone can be stranded by.
        uint256 balanceBefore = token.balanceOf(address(this));
        token.safeTransferFrom(msg.sender, address(this), amount);
        require(
            token.balanceOf(address(this)) - balanceBefore >= amount,
            "Erc20Htlc: fee-on-transfer tokens unsupported"
        );
        emit Locked(id, msg.sender, receiver, address(token), amount, hashlock, timelock);
    }

    /// Pay `receiver` if `sha256(preimage) == hashlock` and the swap is neither claimed
    /// nor refunded. Callable by anyone who knows the preimage.
    function claim(bytes32 id, bytes32 preimage) external {
        Swap storage s = swaps[id];
        require(s.sender != address(0), "Erc20Htlc: no such swap");
        require(!s.claimed, "Erc20Htlc: already claimed");
        require(!s.refunded, "Erc20Htlc: already refunded");
        require(sha256(abi.encodePacked(preimage)) == s.hashlock, "Erc20Htlc: wrong preimage");

        s.claimed = true;
        s.token.safeTransfer(s.receiver, s.amount);
        emit Claimed(id, preimage);
    }

    /// Return the escrow to `sender` once `block.timestamp >= timelock`, if unclaimed.
    function refund(bytes32 id) external {
        Swap storage s = swaps[id];
        require(s.sender != address(0), "Erc20Htlc: no such swap");
        require(!s.claimed, "Erc20Htlc: already claimed");
        require(!s.refunded, "Erc20Htlc: already refunded");
        require(block.timestamp >= s.timelock, "Erc20Htlc: too early");

        s.refunded = true;
        s.token.safeTransfer(s.sender, s.amount);
        emit Refunded(id);
    }
}
