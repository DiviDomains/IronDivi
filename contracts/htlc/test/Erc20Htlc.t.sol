// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {Erc20Htlc, IERC20} from "../src/Erc20Htlc.sol";
import {MockErc20} from "./MockErc20.sol";
import {
    FalseReturningErc20,
    FeeOnTransferErc20,
    NoReturnErc20,
    ReentrantErc20
} from "./AdversarialErc20.sol";

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

    // ---- Adversarial review (orchestrator's ask): reentrancy, fee-on-transfer/non-
    // standard ERC-20 returns, claim/refund at exactly the timelock, double claim, a zero
    // hashlock, and approve races. --------------------------------------------------------

    /// A token whose `transfer` hook reenters `claim` for the same id, mid-payout. The
    /// inner call must see `claimed` already `true` (set before the interaction) and
    /// revert; the receiver must end up paid exactly once, not twice.
    function test_reentrantClaimCannotDoublePay() public {
        ReentrantErc20 rtoken = new ReentrantErc20();
        rtoken.mint(sender, 1_000_000e6);
        vm.startPrank(sender);
        rtoken.approve(address(htlc), 100e6);
        bytes32 id = htlc.lock(IERC20(address(rtoken)), 100e6, receiver, hashlock, timelock);
        vm.stopPrank();

        rtoken.arm(address(htlc), abi.encodeCall(Erc20Htlc.claim, (id, preimage)));
        htlc.claim(id, preimage);

        assertFalse(rtoken.lastAttackOk(), "reentrant claim must have been rejected");
        assertEq(rtoken.balanceOf(receiver), 100e6, "receiver must be paid exactly once");
        (,,,,,, bool claimed, bool refunded) = htlc.swaps(id);
        assertTrue(claimed);
        assertFalse(refunded);
    }

    /// Same attack against `refund`'s payout instead of `claim`'s.
    function test_reentrantRefundCannotDoublePay() public {
        ReentrantErc20 rtoken = new ReentrantErc20();
        rtoken.mint(sender, 1_000_000e6);
        vm.startPrank(sender);
        rtoken.approve(address(htlc), 100e6);
        bytes32 id = htlc.lock(IERC20(address(rtoken)), 100e6, receiver, hashlock, timelock);
        vm.stopPrank();

        vm.warp(timelock);
        rtoken.arm(address(htlc), abi.encodeCall(Erc20Htlc.refund, (id)));
        htlc.refund(id);

        assertFalse(rtoken.lastAttackOk(), "reentrant refund must have been rejected");
        assertEq(rtoken.balanceOf(sender), 1_000_000e6, "sender must be refunded exactly once");
        (,,,,,, bool claimed, bool refunded) = htlc.swaps(id);
        assertFalse(claimed);
        assertTrue(refunded);
    }

    /// A fee-on-transfer token delivers less than the requested `amount`; `lock` must
    /// reject it up front rather than record a promise the contract's actual balance can
    /// never cover.
    function test_lockRejectsFeeOnTransferToken() public {
        FeeOnTransferErc20 ftoken = new FeeOnTransferErc20(100); // 1% fee
        ftoken.mint(sender, 1_000_000e6);
        vm.startPrank(sender);
        ftoken.approve(address(htlc), 100e6);
        vm.expectRevert("Erc20Htlc: fee-on-transfer tokens unsupported");
        htlc.lock(IERC20(address(ftoken)), 100e6, receiver, hashlock, timelock);
        vm.stopPrank();
    }

    /// A token that returns no data at all on `transfer`/`transferFrom` (real USDT's own
    /// mainnet behavior) must still work end to end through `SafeTransfer`, both for a
    /// claim and for a refund.
    function test_lockClaimWorksWithNoReturnValueToken() public {
        NoReturnErc20 ntoken = new NoReturnErc20();
        ntoken.mint(sender, 1_000_000e6);
        vm.startPrank(sender);
        ntoken.approve(address(htlc), 100e6);
        bytes32 id = htlc.lock(IERC20(address(ntoken)), 100e6, receiver, hashlock, timelock);
        vm.stopPrank();

        htlc.claim(id, preimage);
        assertEq(ntoken.balanceOf(receiver), 100e6);
    }

    function test_lockRefundWorksWithNoReturnValueToken() public {
        NoReturnErc20 ntoken = new NoReturnErc20();
        ntoken.mint(sender, 1_000_000e6);
        vm.startPrank(sender);
        ntoken.approve(address(htlc), 100e6);
        bytes32 id = htlc.lock(IERC20(address(ntoken)), 100e6, receiver, hashlock, timelock);
        vm.stopPrank();

        vm.warp(timelock);
        htlc.refund(id);
        assertEq(ntoken.balanceOf(sender), 1_000_000e6);
    }

    /// A token that explicitly returns `false` (never moves anything) must not be
    /// mistaken for success just because the call itself didn't revert.
    function test_lockRejectsFalseReturningToken() public {
        FalseReturningErc20 btoken = new FalseReturningErc20();
        vm.startPrank(sender);
        vm.expectRevert("SafeTransfer: transferFrom failed");
        htlc.lock(IERC20(address(btoken)), 100e6, receiver, hashlock, timelock);
        vm.stopPrank();
    }

    /// `claim` has no time restriction at all — it must still succeed exactly at the
    /// timelock, not just before it.
    function test_claimSucceedsExactlyAtTimelock() public {
        bytes32 id = _lock(10e6, timelock);
        vm.warp(timelock);
        htlc.claim(id, preimage);
        assertEq(token.balanceOf(receiver), 10e6);
    }

    /// At exactly the timelock both claim and refund are individually valid; whichever
    /// lands first wins and permanently blocks the other — the designed atomic-swap race,
    /// not a bug.
    function test_claimWinsRaceAtExactTimelock() public {
        bytes32 id = _lock(10e6, timelock);
        vm.warp(timelock);
        htlc.claim(id, preimage);
        vm.expectRevert("Erc20Htlc: already claimed");
        htlc.refund(id);
    }

    /// A zero hashlock is a safe degenerate case, not an exploit: SHA-256 preimage
    /// resistance means no preimage anyone can produce hashes to zero, so the swap is
    /// simply unclaimable and only ever recoverable by the sender's own refund.
    function test_zeroHashlockCannotBeClaimedButCanBeRefunded() public {
        bytes32 zeroHashlock = bytes32(0);
        vm.startPrank(sender);
        token.approve(address(htlc), 10e6);
        bytes32 id = htlc.lock(IERC20(address(token)), 10e6, receiver, zeroHashlock, timelock);
        vm.stopPrank();

        vm.expectRevert("Erc20Htlc: wrong preimage");
        htlc.claim(id, bytes32(0));

        vm.warp(timelock);
        htlc.refund(id);
        assertEq(token.balanceOf(sender), 1_000_000e6);
    }

    /// `lock` must pull exactly `amount` from the allowance, leaving the remainder
    /// available — no race lets it over- or under-consume what was approved.
    function test_lockConsumesExactlyApprovedAmountLeavingRemainder() public {
        vm.startPrank(sender);
        token.approve(address(htlc), 100e6);
        htlc.lock(IERC20(address(token)), 40e6, receiver, hashlock, timelock);
        vm.stopPrank();
        assertEq(token.allowance(sender, address(htlc)), 60e6);
    }

    /// An allowance set lower than `amount` (e.g. by a racing second approval, or simply
    /// an operator mistake) must cause a clean revert with no partial state committed —
    /// the id stays free to retry once the allowance is fixed.
    function test_lockRevertsCleanlyOnInsufficientAllowance() public {
        vm.startPrank(sender);
        token.approve(address(htlc), 5e6);
        bytes32 id = htlc.swapId(sender, receiver, address(token), 10e6, hashlock, timelock);
        vm.expectRevert("SafeTransfer: transferFrom failed");
        htlc.lock(IERC20(address(token)), 10e6, receiver, hashlock, timelock);
        vm.stopPrank();
        (address s,,,,,,,) = htlc.swaps(id);
        assertEq(s, address(0), "no partial state must survive the revert");
    }
}
