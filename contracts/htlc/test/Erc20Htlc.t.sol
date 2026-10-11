// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {Erc20Htlc, IERC20} from "../src/Erc20Htlc.sol";
import {MockErc20} from "./MockErc20.sol";

contract Erc20HtlcTest is Test {
    Erc20Htlc htlc;
    MockErc20 token;

    address sender = address(0xA11CE);
    address receiver = address(0xB0B);

    bytes32 preimage = keccak256("swap-poc preimage");
    bytes32 hashlock;
    uint256 timelock;

    function setUp() public {
        htlc = new Erc20Htlc();
        token = new MockErc20();
        hashlock = sha256(abi.encodePacked(preimage));
        timelock = block.timestamp + 1 hours;
        token.mint(sender, 1_000_000e6);
    }

    function _lock(uint256 amount, uint256 lockTime) internal returns (bytes32 id) {
        vm.startPrank(sender);
        token.approve(address(htlc), amount);
        id = htlc.lock(IERC20(address(token)), amount, receiver, hashlock, lockTime);
        vm.stopPrank();
    }

    function test_swapIdMatchesContract() public {
        uint256 amount = 100e6;
        bytes32 expected =
            keccak256(abi.encode(sender, receiver, address(token), amount, hashlock, timelock));
        bytes32 id = _lock(amount, timelock);
        assertEq(id, expected);
        (address s,,,,,,,) = htlc.swaps(id);
        assertEq(s, sender);
    }

    function test_lockThenClaimPaysReceiver() public {
        uint256 amount = 250e6;
        bytes32 id = _lock(amount, timelock);
        assertEq(token.balanceOf(address(htlc)), amount);

        htlc.claim(id, preimage);

        assertEq(token.balanceOf(receiver), amount);
        assertEq(token.balanceOf(address(htlc)), 0);
        (,,,,,, bool claimed, bool refunded) = htlc.swaps(id);
        assertTrue(claimed);
        assertFalse(refunded);
    }

    function test_claimEmitsPreimage() public {
        bytes32 id = _lock(10e6, timelock);
        vm.expectEmit(true, false, false, false, address(htlc));
        emit Erc20Htlc.Claimed(id, preimage);
        htlc.claim(id, preimage);
    }

    function test_lockThenRefundAfterTimelockPaysSender() public {
        uint256 amount = 75e6;
        bytes32 id = _lock(amount, timelock);

        vm.warp(timelock);
        htlc.refund(id);

        assertEq(token.balanceOf(sender), 1_000_000e6);
        assertEq(token.balanceOf(address(htlc)), 0);
        (,,,,,, bool claimed, bool refunded) = htlc.swaps(id);
        assertFalse(claimed);
        assertTrue(refunded);
    }

    function test_earlyRefundRejected() public {
        bytes32 id = _lock(10e6, timelock);
        vm.warp(timelock - 1);
        vm.expectRevert("Erc20Htlc: too early");
        htlc.refund(id);
    }

    function test_wrongPreimageRejected() public {
        bytes32 id = _lock(10e6, timelock);
        vm.expectRevert("Erc20Htlc: wrong preimage");
        htlc.claim(id, keccak256("not it"));
    }

    function test_doubleClaimRejected() public {
        bytes32 id = _lock(10e6, timelock);
        htlc.claim(id, preimage);
        vm.expectRevert("Erc20Htlc: already claimed");
        htlc.claim(id, preimage);
    }

    function test_claimAfterRefundRejected() public {
        bytes32 id = _lock(10e6, timelock);
        vm.warp(timelock);
        htlc.refund(id);
        vm.expectRevert("Erc20Htlc: already refunded");
        htlc.claim(id, preimage);
    }

    function test_refundAfterClaimRejected() public {
        bytes32 id = _lock(10e6, timelock);
        htlc.claim(id, preimage);
        vm.warp(timelock);
        vm.expectRevert("Erc20Htlc: already claimed");
        htlc.refund(id);
    }

    function test_lockRejectsPastTimelock() public {
        vm.startPrank(sender);
        token.approve(address(htlc), 10e6);
        vm.expectRevert("Erc20Htlc: timelock in the past");
        htlc.lock(IERC20(address(token)), 10e6, receiver, hashlock, block.timestamp);
        vm.stopPrank();
    }

    function test_lockRejectsZeroAmount() public {
        vm.startPrank(sender);
        vm.expectRevert("Erc20Htlc: zero amount");
        htlc.lock(IERC20(address(token)), 0, receiver, hashlock, timelock);
        vm.stopPrank();
    }

    function test_lockRejectsDuplicateId() public {
        _lock(10e6, timelock);
        vm.startPrank(sender);
        token.approve(address(htlc), 10e6);
        vm.expectRevert("Erc20Htlc: swap exists");
        htlc.lock(IERC20(address(token)), 10e6, receiver, hashlock, timelock);
        vm.stopPrank();
    }

    function test_claimUnknownSwapRejected() public {
        vm.expectRevert("Erc20Htlc: no such swap");
        htlc.claim(bytes32(uint256(0xdead)), preimage);
    }

    /// Fuzz: any non-zero amount the sender can afford and any future timelock round-trip
    /// through claim, paying the receiver exactly `amount`.
    function testFuzz_lockClaimRoundTrip(uint96 amount, uint32 delay) public {
        vm.assume(amount > 0 && amount <= 1_000_000e6);
        uint256 lockTime = block.timestamp + 1 + uint256(delay);

        bytes32 id = _lock(amount, lockTime);
        htlc.claim(id, preimage);

        assertEq(token.balanceOf(receiver), amount);
    }

    /// Fuzz: any non-zero amount refunds back to the sender once warped to the timelock.
    function testFuzz_lockRefundRoundTrip(uint96 amount, uint32 delay) public {
        vm.assume(amount > 0 && amount <= 1_000_000e6);
        uint256 lockTime = block.timestamp + 1 + uint256(delay);

        bytes32 id = _lock(amount, lockTime);
        vm.warp(lockTime);
        htlc.refund(id);

        assertEq(token.balanceOf(sender), 1_000_000e6 - amount + amount);
    }
}
