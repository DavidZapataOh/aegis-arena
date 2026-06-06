// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Test} from "forge-std/Test.sol";
import {AuditArena} from "../src/AuditArena.sol";
import {AttestationNFT} from "../src/AttestationNFT.sol";

contract AuditArenaTest is Test {
    AuditArena arena;
    AttestationNFT nft;

    address verifier = makeAddr("verifier");
    address submitter = makeAddr("submitter");
    address agent1 = makeAddr("agent1");

    function setUp() public {
        nft = new AttestationNFT();
        arena = new AuditArena(verifier, address(nft));
        nft.setMinter(address(arena));
        vm.deal(submitter, 100 ether);
    }

    function test_fullFlow_confirmedCriticalPaysAgentAndRefundsRest() public {
        vm.prank(submitter);
        uint256 auditId = arena.submitContract{value: 5 ether}("ipfs://code", "VulnerableVault", 1 days);

        vm.prank(verifier);
        uint256 fid = arena.submitFinding(
            auditId, agent1, "Reentrancy Hunter", AuditArena.Severity.Critical, "Reentrancy in withdraw()", "ipfs://poc"
        );

        vm.prank(verifier);
        arena.resolveFinding(fid, true, AuditArena.Severity.Critical);
        // Critical = 50% of 5 ether
        assertEq(agent1.balance, 2.5 ether, "agent paid critical reward");

        uint256 subBefore = submitter.balance;
        vm.prank(verifier);
        uint256 attId = arena.closeAudit(auditId);

        assertEq(submitter.balance - subBefore, 2.5 ether, "remaining bounty refunded");
        assertEq(nft.ownerOf(attId), submitter, "attestation minted to submitter");

        (,, bool secured, uint8 score,, uint256 confirmed,) = nft.attestations(attId);
        assertFalse(secured, "not secured: a critical was confirmed");
        assertEq(score, 40, "score = 100 - 60 (critical)");
        assertEq(confirmed, 1);
    }

    function test_securedFlow_noFindings_fullRefundAndBadge() public {
        vm.prank(submitter);
        uint256 auditId = arena.submitContract{value: 3 ether}("ipfs://code", "SecureVault", 1 days);

        uint256 subBefore = submitter.balance;
        vm.prank(verifier);
        uint256 attId = arena.closeAudit(auditId);

        assertEq(submitter.balance - subBefore, 3 ether, "full refund when no bugs");
        (,, bool secured, uint8 score,,,) = nft.attestations(attId);
        assertTrue(secured);
        assertEq(score, 100);
    }

    function test_rejectedFalsePositive_paysNothing() public {
        vm.prank(submitter);
        uint256 auditId = arena.submitContract{value: 1 ether}("ipfs://code", "Token", 1 days);

        vm.prank(verifier);
        uint256 fid = arena.submitFinding(
            auditId, agent1, "Hallucinator", AuditArena.Severity.High, "imaginary overflow", "ipfs://x"
        );

        vm.prank(verifier);
        arena.resolveFinding(fid, false, AuditArena.Severity.None);
        assertEq(agent1.balance, 0, "false positive earns nothing");

        AuditArena.Finding[] memory list = arena.getFindings(auditId);
        assertEq(uint8(list[0].status), uint8(AuditArena.FindingStatus.Rejected));
    }

    function test_onlyVerifierCanSettle() public {
        vm.prank(submitter);
        uint256 auditId = arena.submitContract{value: 1 ether}("ipfs://code", "Token", 1 days);
        vm.expectRevert(AuditArena.OnlyVerifier.selector);
        arena.submitFinding(auditId, agent1, "x", AuditArena.Severity.Low, "t", "u");
    }

    function test_tokenURIRenders() public {
        vm.prank(submitter);
        uint256 auditId = arena.submitContract{value: 1 ether}("ipfs://code", "SecureVault", 1 days);
        vm.prank(verifier);
        uint256 attId = arena.closeAudit(auditId);
        string memory uri = nft.tokenURI(attId);
        assertGt(bytes(uri).length, 100, "tokenURI produced");
    }
}
