// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice DEMO TARGET — intentionally vulnerable to reentrancy.
///         `withdraw` sends the full balance with an external call BEFORE zeroing it,
///         so an attacker contract can re-enter and drain every depositor's funds.
contract VulnerableVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "no balance");
        // INTERACTION before EFFECT -> reentrancy: balance is still set during the callback.
        (bool ok,) = msg.sender.call{value: bal}("");
        require(ok, "transfer failed");
        balances[msg.sender] = 0;
    }

    function totalAssets() external view returns (uint256) {
        return address(this).balance;
    }
}
