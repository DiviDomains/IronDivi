// SPDX-License-Identifier: AGPL-3.0-only
pragma solidity 0.8.26;

/// ERC-20 mocks for Erc20Htlc's adversarial test suite — each misbehaves in exactly one
/// way a real token is known to (fee-on-transfer, no return value, an explicit `false`, or
/// a reentrant callback on transfer), so the HTLC's defenses are exercised against the
/// real thing instead of asserted by code reading alone. `MockErc20.sol` stays the clean
/// baseline these are deliberately not.

/// Fee-on-transfer: delivers `amount * (10000 - feeBps) / 10000` and burns the rest, the
/// same accounting several real deflationary/fee tokens use.
contract FeeOnTransferErc20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    uint256 public immutable feeBps;

    constructor(uint256 _feeBps) {
        feeBps = _feeBps;
    }

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        balanceOf[from] -= amount;
        balanceOf[to] += amount - (amount * feeBps / 10000); // the fee bps is simply burned
    }
}

/// No return value at all (real USDT's mainnet behavior) — `SafeTransfer` must tolerate
/// this rather than treat the empty return as failure.
contract NoReturnErc20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external {
        _transfer(msg.sender, to, amount);
    }

    function transferFrom(address from, address to, uint256 amount) external {
        allowance[from][msg.sender] -= amount;
        _transfer(from, to, amount);
    }

    function _transfer(address from, address to, uint256 amount) internal {
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}

/// Returns `false` explicitly and never moves a single token — `SafeTransfer` must treat
/// this as a failure, not optimistically succeed just because the call itself didn't
/// revert.
contract FalseReturningErc20 {
    function balanceOf(address) external pure returns (uint256) {
        return 0;
    }

    function approve(address, uint256) external pure returns (bool) {
        return true;
    }

    function transfer(address, uint256) external pure returns (bool) {
        return false;
    }

    function transferFrom(address, address, uint256) external pure returns (bool) {
        return false;
    }
}

/// Reentrant: `transfer`/`transferFrom` call back into an armed target with armed data
/// *before* completing their own bookkeeping, simulating an ERC-777-like hook (or simply a
/// maliciously coded token) probing `Erc20Htlc`'s checks-effects-interactions ordering.
/// Armed for exactly one shot so a test can observe the single reentrant attempt's outcome
/// without the mock itself recursing forever.
contract ReentrantErc20 {
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    address public attackTarget;
    bytes public attackData;
    bool public armed;
    bool public lastAttackOk;

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function arm(address target, bytes calldata data) external {
        attackTarget = target;
        attackData = data;
        armed = true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _maybeAttack();
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        _maybeAttack();
        _transfer(from, to, amount);
        return true;
    }

    function _maybeAttack() internal {
        if (armed) {
            armed = false;
            (bool ok,) = attackTarget.call(attackData);
            lastAttackOk = ok;
        }
    }

    function _transfer(address from, address to, uint256 amount) internal {
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
    }
}
