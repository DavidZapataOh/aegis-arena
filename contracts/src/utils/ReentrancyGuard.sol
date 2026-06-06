// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Minimal reentrancy guard.
abstract contract ReentrancyGuard {
    uint256 private _locked = 1;

    error Reentrancy();

    modifier nonReentrant() {
        if (_locked != 1) revert Reentrancy();
        _locked = 2;
        _;
        _locked = 1;
    }
}
