// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.26;

import {Test} from "forge-std/Test.sol";
import {Erc20Htlc, IERC20} from "../src/Erc20Htlc.sol";
import {MockErc20} from "./MockErc20.sol";
import {ReentrantErc20} from "./AdversarialErc20.sol";

/// USDC FiatToken-style token: a blacklisted `from` or `to` makes transfer/transferFrom revert,
/// and a paused token reverts every transfer (Circle FiatTokenV2_2 `notBlacklisted` / `whenNotPaused`).
contract BlacklistErc20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => bool) public isBlacklisted;
    bool public paused;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function setBlacklisted(address a, bool b) external {
        isBlacklisted[a] = b;
    }

    function setPaused(bool p) external {
        paused = p;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _move(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        require(!isBlacklisted[msg.sender], "Blacklistable: account is blacklisted");
        allowance[from][msg.sender] -= amount;
        _move(from, to, amount);
        return true;
    }

    function _move(address from, address to, uint256 amount) internal {
        require(!paused, "Pausable: paused");
        require(!isBlacklisted[from] && !isBlacklisted[to], "Blacklistable: account is blacklisted");
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}

/// Handler for the escrow-solvency invariant: drives random lock/claim/refund/warp.
contract HtlcHandler is Test {
    Erc20Htlc public htlc;
    MockErc20 public token;
    address public constant SENDER = address(0xA11CE2);
    address public constant RECEIVER = address(0xB0B);
    bytes32[] public ids;
    bytes32[] public preimages;

    constructor(Erc20Htlc h, MockErc20 t) {
        htlc = h;
        token = t;
        t.mint(SENDER, type(uint96).max);
    }

    function lock(uint96 amount, uint32 delta, bytes32 pre) external {
        amount = uint96(bound(amount, 1, 1_000_000e6));
        uint256 tl = block.timestamp + bound(delta, 1, 30 days);
        vm.startPrank(SENDER);
        token.approve(address(htlc), amount);
        try htlc.lock(IERC20(address(token)), amount, RECEIVER, sha256(abi.encodePacked(pre)), tl) returns (
            bytes32 id
        ) {
            ids.push(id);
            preimages.push(pre);
        } catch {}
        vm.stopPrank();
    }

    function claim(uint256 i) external {
        if (ids.length == 0) return;
        i = bound(i, 0, ids.length - 1);
        try htlc.claim(ids[i], preimages[i]) {} catch {}
    }

    function refund(uint256 i) external {
        if (ids.length == 0) return;
        i = bound(i, 0, ids.length - 1);
        try htlc.refund(ids[i]) {} catch {}
    }

    function warp(uint32 dt) external {
        vm.warp(block.timestamp + bound(dt, 0, 10 days));
    }

    /// Sum of `amount` over swaps that are neither claimed nor refunded.
    function openTotal() external view returns (uint256 total) {
        for (uint256 i = 0; i < ids.length; i++) {
            (,,, uint256 amount,,, bool claimed, bool refunded) = htlc.swaps(ids[i]);
            if (!claimed && !refunded) total += amount;
        }
    }

    function count() external view returns (uint256) {
        return ids.length;
    }
}

contract Erc20HtlcPreauditTest is Test {
    Erc20Htlc htlc;
    MockErc20 token;
    BlacklistErc20 usdc;
    HtlcHandler handler;

    address sender = address(0xA11CE);
    address receiver = address(0xB0B);
    address stranger = address(0xBAD);
    bytes32 preimage = keccak256("preaudit preimage");
    bytes32 hashlock;
    uint256 timelock;

    function setUp() public {
        htlc = new Erc20Htlc();
        token = new MockErc20();
        usdc = new BlacklistErc20();
        hashlock = sha256(abi.encodePacked(preimage));
        timelock = block.timestamp + 1 hours;
        token.mint(sender, 1_000_000e6);
        usdc.mint(sender, 1_000_000e6);

        handler = new HtlcHandler(htlc, token);
        targetContract(address(handler));
    }

    function _lock(IERC20 t, uint256 amount) internal returns (bytes32 id) {
        vm.startPrank(sender);
        MockErc20(address(t)).approve(address(htlc), amount);
        id = htlc.lock(t, amount, receiver, hashlock, timelock);
        vm.stopPrank();
    }

    // ---- inputs -----------------------------------------------------------------------

    function test_lockRejectsZeroReceiver() public {
        vm.startPrank(sender);
        token.approve(address(htlc), 1e6);
        vm.expectRevert("Erc20Htlc: zero receiver");
        htlc.lock(IERC20(address(token)), 1e6, address(0), hashlock, timelock);
        vm.stopPrank();
    }

    function test_lockRejectsTimelockEqualToNow() public {
        vm.startPrank(sender);
        token.approve(address(htlc), 1e6);
        vm.expectRevert("Erc20Htlc: timelock in the past");
        htlc.lock(IERC20(address(token)), 1e6, receiver, hashlock, block.timestamp);
        vm.stopPrank();
    }

    /// A token address with no code: `balanceOf` is a high-level call, so extcodesize check reverts
    /// before any state outlives the transaction (a bare low-level call to an EOA would "succeed").
    function test_lockRejectsTokenWithoutCode() public {
        vm.startPrank(sender);
        vm.expectRevert();
        htlc.lock(IERC20(address(0xDEAD)), 1e6, receiver, hashlock, timelock);
        vm.stopPrank();
        bytes32 id = htlc.swapId(sender, receiver, address(0xDEAD), 1e6, hashlock, timelock);
        (address s,,,,,,,) = htlc.swaps(id);
        assertEq(s, address(0), "no swap may be recorded");
    }

    // ---- who may call, where funds go -------------------------------------------------

    function test_anyoneCanClaimButReceiverIsPaid() public {
        bytes32 id = _lock(IERC20(address(token)), 50e6);
        vm.prank(stranger);
        htlc.claim(id, preimage);
        assertEq(token.balanceOf(receiver), 50e6);
        assertEq(token.balanceOf(stranger), 0);
    }

    function test_anyoneCanRefundButSenderIsPaid() public {
        bytes32 id = _lock(IERC20(address(token)), 50e6);
        vm.warp(timelock);
        uint256 before_ = token.balanceOf(sender);
        vm.prank(stranger);
        htlc.refund(id);
        assertEq(token.balanceOf(sender), before_ + 50e6);
        assertEq(token.balanceOf(stranger), 0);
    }

    // ---- events -----------------------------------------------------------------------

    function test_lockEmitsLocked() public {
        bytes32 id = htlc.swapId(sender, receiver, address(token), 7e6, hashlock, timelock);
        vm.startPrank(sender);
        token.approve(address(htlc), 7e6);
        vm.expectEmit(true, true, true, true, address(htlc));
        emit Erc20Htlc.Locked(id, sender, receiver, address(token), 7e6, hashlock, timelock);
        htlc.lock(IERC20(address(token)), 7e6, receiver, hashlock, timelock);
        vm.stopPrank();
    }

    function test_refundEmitsRefunded() public {
        bytes32 id = _lock(IERC20(address(token)), 7e6);
        vm.warp(timelock);
        vm.expectEmit(true, false, false, true, address(htlc));
        emit Erc20Htlc.Refunded(id);
        htlc.refund(id);
    }

    // ---- replay -----------------------------------------------------------------------

    /// A settled swap keeps its record, so identical parameters can never be locked again.
    function test_settledSwapIdCannotBeRelocked() public {
        bytes32 id = _lock(IERC20(address(token)), 5e6);
        htlc.claim(id, preimage);
        vm.startPrank(sender);
        token.approve(address(htlc), 5e6);
        vm.expectRevert("Erc20Htlc: swap exists");
        htlc.lock(IERC20(address(token)), 5e6, receiver, hashlock, timelock);
        vm.stopPrank();
    }

    function test_preimageOfOtherLengthRejected() public {
        bytes32 id = _lock(IERC20(address(token)), 5e6);
        vm.expectRevert("Erc20Htlc: wrong preimage");
        htlc.claim(id, bytes32(0));
    }

    /// The hashlock is SHA-256 of the raw 32 bytes (same as the BTC/LTC/DIVI legs), not keccak.
    function test_hashlockIsSha256NotKeccak() public {
        bytes32 keccakLock = keccak256(abi.encodePacked(preimage));
        vm.startPrank(sender);
        token.approve(address(htlc), 5e6);
        bytes32 id = htlc.lock(IERC20(address(token)), 5e6, receiver, keccakLock, timelock);
        vm.stopPrank();
        vm.expectRevert("Erc20Htlc: wrong preimage");
        htlc.claim(id, preimage);
    }

    // ---- USDC blacklist / pause -------------------------------------------------------

    /// Receiver blacklisted after lock: claim reverts (preimage stays unrevealed on-chain), the
    /// funds stay escrowed, and the sender recovers them via refund after the timelock.
    function test_blacklistedReceiverCannotBeClaimedButSenderRefunds() public {
        bytes32 id = _lock(IERC20(address(usdc)), 20e6);
        usdc.setBlacklisted(receiver, true);
        vm.expectRevert();
        htlc.claim(id, preimage);
        assertEq(usdc.balanceOf(address(htlc)), 20e6);
        (,,,,,, bool claimed,) = htlc.swaps(id);
        assertFalse(claimed, "failed claim must not mark the swap claimed");

        vm.warp(timelock);
        htlc.refund(id);
        assertEq(usdc.balanceOf(sender), 1_000_000e6);
    }

    /// Sender blacklisted after lock: refund reverts, but the receiver can still claim.
    function test_blacklistedSenderCannotRefundButReceiverClaims() public {
        bytes32 id = _lock(IERC20(address(usdc)), 20e6);
        usdc.setBlacklisted(sender, true);
        vm.warp(timelock);
        vm.expectRevert();
        htlc.refund(id);
        htlc.claim(id, preimage);
        assertEq(usdc.balanceOf(receiver), 20e6);
    }

    /// Token paused: both exits revert; after unpause both work again (funds are not lost).
    function test_pausedTokenBlocksBothExitsUntilUnpaused() public {
        bytes32 id = _lock(IERC20(address(usdc)), 20e6);
        usdc.setPaused(true);
        vm.expectRevert();
        htlc.claim(id, preimage);
        vm.warp(timelock);
        vm.expectRevert();
        htlc.refund(id);
        usdc.setPaused(false);
        htlc.refund(id);
        assertEq(usdc.balanceOf(sender), 1_000_000e6);
    }

    /// The HTLC itself being blacklisted by Circle freezes every escrow: both exits revert.
    function test_blacklistedContractFreezesEscrow() public {
        bytes32 id = _lock(IERC20(address(usdc)), 20e6);
        usdc.setBlacklisted(address(htlc), true);
        vm.expectRevert();
        htlc.claim(id, preimage);
        vm.warp(timelock);
        vm.expectRevert();
        htlc.refund(id);
        assertEq(usdc.balanceOf(address(htlc)), 20e6);
    }

    // ---- reentrancy -------------------------------------------------------------------

    /// Re-enter `lock` with identical parameters from inside `transferFrom`: the record is
    /// written before the interaction, so the inner call hits "swap exists".
    function test_reentrantLockSameIdRejected() public {
        ReentrantErc20 rtoken = new ReentrantErc20();
        rtoken.mint(address(rtoken), 1_000_000e6);
        rtoken.mint(sender, 1_000_000e6);
        vm.startPrank(sender);
        rtoken.approve(address(htlc), 10e6);
        rtoken.arm(
            address(htlc),
            abi.encodeCall(Erc20Htlc.lock, (IERC20(address(rtoken)), 10e6, receiver, hashlock, timelock))
        );
        htlc.lock(IERC20(address(rtoken)), 10e6, receiver, hashlock, timelock);
        vm.stopPrank();
        assertFalse(rtoken.lastAttackOk(), "reentrant relock must be rejected");
        assertEq(rtoken.balanceOf(address(htlc)), 10e6, "escrow holds exactly one amount");
    }

    /// Cross-function: refund attempted from inside claim's payout is rejected (`claimed` already set).
    function test_crossFunctionRefundDuringClaimRejected() public {
        ReentrantErc20 rtoken = new ReentrantErc20();
        rtoken.mint(sender, 1_000_000e6);
        vm.startPrank(sender);
        rtoken.approve(address(htlc), 10e6);
        bytes32 id = htlc.lock(IERC20(address(rtoken)), 10e6, receiver, hashlock, timelock);
        vm.stopPrank();
        vm.warp(timelock);
        rtoken.arm(address(htlc), abi.encodeCall(Erc20Htlc.refund, (id)));
        htlc.claim(id, preimage);
        assertFalse(rtoken.lastAttackOk());
        assertEq(rtoken.balanceOf(receiver), 10e6);
        assertEq(rtoken.balanceOf(sender), 1_000_000e6 - 10e6);
    }

    // ---- fuzz / invariant -------------------------------------------------------------

    /// Exactly one of claim/refund ever pays out, whatever the order and timing.
    function testFuzz_atMostOnePayout(uint96 amount, uint32 lockSecs, uint32 warpSecs, bool claimFirst) public {
        amount = uint96(bound(amount, 1, 1_000_000e6));
        lockSecs = uint32(bound(lockSecs, 1, 365 days));
        bytes32 id;
        uint256 expiry = block.timestamp + lockSecs;
        vm.startPrank(sender);
        token.approve(address(htlc), amount);
        id = htlc.lock(IERC20(address(token)), amount, receiver, hashlock, expiry);
        vm.stopPrank();
        vm.warp(block.timestamp + warpSecs);

        if (claimFirst) {
            htlc.claim(id, preimage);
            vm.expectRevert();
            htlc.refund(id);
        } else if (block.timestamp >= expiry) {
            htlc.refund(id);
            vm.expectRevert();
            htlc.claim(id, preimage);
        } else {
            vm.expectRevert("Erc20Htlc: too early");
            htlc.refund(id);
        }
        assertEq(token.balanceOf(sender) + token.balanceOf(receiver) + token.balanceOf(address(htlc)), 1_000_000e6);
        assertTrue(token.balanceOf(receiver) == 0 || token.balanceOf(receiver) == amount);
    }

    /// Escrow solvency: the contract holds exactly the sum of unsettled swaps.
    function invariant_balanceEqualsOpenSwaps() public view {
        assertEq(token.balanceOf(address(htlc)), handler.openTotal());
    }
}
