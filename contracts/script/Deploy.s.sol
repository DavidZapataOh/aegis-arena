// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Script, console2} from "forge-std/Script.sol";
import {AuditArena} from "../src/AuditArena.sol";
import {AttestationNFT} from "../src/AttestationNFT.sol";

/// @notice Deploys AttestationNFT + AuditArena and wires the minter.
/// Required env: DEPLOYER_PRIVATE_KEY, VERIFIER_ADDRESS
/// Usage:
///   forge script script/Deploy.s.sol:Deploy \
///     --rpc-url monad_testnet --broadcast
contract Deploy is Script {
    function run() external {
        uint256 pk = vm.envUint("DEPLOYER_PRIVATE_KEY");
        address verifier = vm.envAddress("VERIFIER_ADDRESS");

        vm.startBroadcast(pk);
        AttestationNFT nft = new AttestationNFT();
        AuditArena arena = new AuditArena(verifier, address(nft));
        nft.setMinter(address(arena));
        vm.stopBroadcast();

        console2.log("=== AegisArena deployed ===");
        console2.log("AttestationNFT:", address(nft));
        console2.log("AuditArena:    ", address(arena));
        console2.log("Verifier:      ", verifier);
    }
}
