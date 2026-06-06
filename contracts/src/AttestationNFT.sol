// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ERC721} from "./utils/ERC721.sol";
import {Ownable} from "./utils/Ownable.sol";
import {Base64} from "./utils/Base64.sol";
import {Strings} from "./utils/Strings.sol";

/// @title AegisArena Attestation
/// @notice Soulbound-style on-chain security attestation minted when an audit closes.
///         Metadata + image are fully on-chain (data URI), so it renders in any wallet.
contract AttestationNFT is ERC721, Ownable {
    using Strings for uint256;
    using Strings for address;

    struct Attestation {
        uint256 auditId;
        address subject; // the contract submitter
        bool secured; // true if no high/critical finding was confirmed
        uint8 score; // 0-100 security score
        uint256 bountyPaid; // total paid to auditors (wei)
        uint256 findingsConfirmed;
        uint256 issuedAt;
    }

    address public minter; // the AuditArena contract
    uint256 public totalSupply;
    mapping(uint256 => Attestation) public attestations;

    error OnlyMinter();

    constructor() ERC721("AegisArena Attestation", "AEGIS") Ownable(msg.sender) {}

    function setMinter(address _minter) external onlyOwner {
        minter = _minter;
    }

    function mint(
        uint256 auditId,
        address subject,
        bool secured,
        uint8 score,
        uint256 bountyPaid,
        uint256 findingsConfirmed
    ) external returns (uint256 id) {
        if (msg.sender != minter) revert OnlyMinter();
        id = ++totalSupply;
        attestations[id] = Attestation({
            auditId: auditId,
            subject: subject,
            secured: secured,
            score: score,
            bountyPaid: bountyPaid,
            findingsConfirmed: findingsConfirmed,
            issuedAt: block.timestamp
        });
        _mint(subject, id);
    }

    function tokenURI(uint256 id) public view override returns (string memory) {
        require(_ownerOf[id] != address(0), "NOT_MINTED");
        Attestation memory a = attestations[id];
        string memory status = a.secured ? "SECURED" : "VULNERABILITIES FOUND";
        string memory color = a.secured ? "#16a34a" : "#dc2626";

        string memory image = _svg(a, status, color);
        string memory json = string(
            abi.encodePacked(
                '{"name":"AegisArena Audit #',
                a.auditId.toString(),
                '","description":"On-chain security attestation issued by AegisArena on Monad.",',
                '"image":"data:image/svg+xml;base64,',
                Base64.encode(bytes(image)),
                '","attributes":[',
                '{"trait_type":"Status","value":"',
                status,
                '"},{"trait_type":"Score","value":',
                uint256(a.score).toString(),
                '},{"trait_type":"Findings Confirmed","value":',
                a.findingsConfirmed.toString(),
                '},{"trait_type":"Bounty Paid (wei)","value":"',
                a.bountyPaid.toString(),
                '"},{"trait_type":"Subject","value":"',
                a.subject.toHexString(),
                '"}]}'
            )
        );
        return string(abi.encodePacked("data:application/json;base64,", Base64.encode(bytes(json))));
    }

    function _svg(Attestation memory a, string memory status, string memory color)
        internal
        pure
        returns (string memory)
    {
        return string(
            abi.encodePacked(
                '<svg xmlns="http://www.w3.org/2000/svg" width="500" height="500">',
                '<rect width="500" height="500" fill="#0b0b14"/>',
                '<text x="40" y="80" fill="#ffffff" font-family="monospace" font-size="34">AegisArena</text>',
                '<text x="40" y="116" fill="#8b8ba7" font-family="monospace" font-size="18">Audit #',
                a.auditId.toString(),
                " &#183; Monad</text>",
                '<circle cx="250" cy="270" r="92" fill="none" stroke="',
                color,
                '" stroke-width="10"/>',
                '<text x="250" y="290" fill="',
                color,
                '" font-family="monospace" font-size="64" text-anchor="middle">',
                uint256(a.score).toString(),
                "</text>",
                '<text x="250" y="420" fill="',
                color,
                '" font-family="monospace" font-size="22" text-anchor="middle">',
                status,
                "</text></svg>"
            )
        );
    }
}
