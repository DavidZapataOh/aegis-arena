// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice DEMO TARGET — the fixed version. Checks-effects-interactions + reentrancy guard.
///         The same exploit that drains VulnerableVault reverts here.
contract SecureVault {
    mapping(address => uint256) public balances;
    uint256 private _locked = 1;

    modifier nonReentrant() {
        require(_locked == 1, "reentrancy");
        _locked = 2;
        _;
        _locked = 1;
    }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external nonReentrant {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "no balance");
        // EFFECT before INTERACTION, and guarded against re-entry.
        balances[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: bal}("");
        require(ok, "transfer failed");
    }

    function totalAssets() external view returns (uint256) {
        return address(this).balance;
    }
}
