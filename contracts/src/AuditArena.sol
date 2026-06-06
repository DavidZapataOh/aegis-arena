// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {Ownable} from "./utils/Ownable.sol";
import {ReentrancyGuard} from "./utils/ReentrancyGuard.sol";

interface IAttestationNFT {
    function mint(
        uint256 auditId,
        address subject,
        bool secured,
        uint8 score,
        uint256 bountyPaid,
        uint256 findingsConfirmed
    ) external returns (uint256);
}

/// @title AuditArena
/// @notice Bounty escrow + proof-of-exploit settlement for decentralized smart-contract audits.
///         A submitter escrows a bounty for their contract. Auditor agents submit findings backed
///         by an executable exploit (verified off-chain in a Foundry sandbox). The trusted verifier
///         (oracle) confirms or rejects each finding; confirmed findings are paid out instantly from
///         the bounty by severity. On close, an on-chain attestation NFT is minted and any unspent
///         bounty is refunded to the submitter.
/// @dev    MVP: a single trusted `verifier` settles findings. v2 decentralizes this into a staked
///         committee / TEE / zk proof of the sandbox run. The economic shape (escrow, severity-based
///         payout, refund, attestation) is already real and on-chain here.
contract AuditArena is Ownable, ReentrancyGuard {
    enum Severity {
        None,
        Low,
        Medium,
        High,
        Critical
    }

    enum AuditStatus {
        Open,
        Closed
    }

    enum FindingStatus {
        Pending,
        Confirmed,
        Rejected
    }

    struct Audit {
        address submitter;
        uint256 bounty;
        uint256 paidOut;
        string codeURI; // pointer / hash / label of the audited source
        string title;
        uint64 createdAt;
        uint64 deadline;
        AuditStatus status;
        uint256 confirmedHigh; // # of confirmed High/Critical findings
        uint256 attestationId;
    }

    struct Finding {
        uint256 auditId;
        address agent; // auditor agent's payout address
        string agentName;
        Severity severity;
        string title;
        string exploitURI; // pointer to the PoC exploit
        FindingStatus status;
        uint256 reward;
        uint64 createdAt;
    }

    uint256 public constant BPS = 10_000;

    address public verifier; // oracle / relayer that runs the sandbox and settles findings
    IAttestationNFT public immutable attestation;

    uint256 public auditCount;
    uint256 public findingCount;
    mapping(uint256 => Audit) public audits;
    mapping(uint256 => Finding) public findings;
    mapping(uint256 => uint256[]) internal _auditFindings;
    mapping(Severity => uint256) public rewardBps; // share of bounty per confirmed finding

    event AuditSubmitted(uint256 indexed auditId, address indexed submitter, uint256 bounty, string title);
    event FindingSubmitted(
        uint256 indexed findingId, uint256 indexed auditId, address indexed agent, Severity severity, string title
    );
    event FindingResolved(uint256 indexed findingId, bool valid, Severity severity, uint256 reward);
    event AuditClosed(
        uint256 indexed auditId, bool secured, uint8 score, uint256 bountyPaid, uint256 refunded, uint256 attestationId
    );
    event VerifierUpdated(address indexed verifier);

    error OnlyVerifier();
    error NoBounty();
    error AuditNotOpen();
    error BadSeverity();
    error AlreadyResolved();
    error NotAllowed();
    error TransferFailed();

    modifier onlyVerifier() {
        if (msg.sender != verifier) revert OnlyVerifier();
        _;
    }

    constructor(address _verifier, address _attestation) Ownable(msg.sender) {
        verifier = _verifier;
        attestation = IAttestationNFT(_attestation);
        rewardBps[Severity.Critical] = 5_000; // 50%
        rewardBps[Severity.High] = 2_500; // 25%
        rewardBps[Severity.Medium] = 1_000; // 10%
        rewardBps[Severity.Low] = 500; // 5%
    }

    function setVerifier(address _verifier) external onlyOwner {
        verifier = _verifier;
        emit VerifierUpdated(_verifier);
    }

    /// @notice Submit a contract for audit, escrowing a bounty (msg.value).
    /// @param codeURI pointer/hash/label of the source under audit (full source lives off-chain).
    /// @param title human-readable name shown in the arena.
    /// @param duration audit window in seconds (0 => 1 day default).
    function submitContract(string calldata codeURI, string calldata title, uint64 duration)
        external
        payable
        returns (uint256 id)
    {
        if (msg.value == 0) revert NoBounty();
        id = ++auditCount;
        Audit storage a = audits[id];
        a.submitter = msg.sender;
        a.bounty = msg.value;
        a.codeURI = codeURI;
        a.title = title;
        a.createdAt = uint64(block.timestamp);
        a.deadline = uint64(block.timestamp) + (duration == 0 ? 1 days : duration);
        a.status = AuditStatus.Open;
        emit AuditSubmitted(id, msg.sender, msg.value, title);
    }

    /// @notice Register a finding reported by an auditor agent (pending verification).
    /// @dev MVP relays through the verifier so agents don't need gas; the agent's payout
    ///      address is recorded as `agent`. v2 makes this permissionless with a report stake.
    function submitFinding(
        uint256 auditId,
        address agent,
        string calldata agentName,
        Severity severity,
        string calldata title,
        string calldata exploitURI
    ) external onlyVerifier returns (uint256 fid) {
        Audit storage a = audits[auditId];
        if (a.status != AuditStatus.Open) revert AuditNotOpen();
        if (severity == Severity.None) revert BadSeverity();

        fid = ++findingCount;
        findings[fid] = Finding({
            auditId: auditId,
            agent: agent,
            agentName: agentName,
            severity: severity,
            title: title,
            exploitURI: exploitURI,
            status: FindingStatus.Pending,
            reward: 0,
            createdAt: uint64(block.timestamp)
        });
        _auditFindings[auditId].push(fid);
        emit FindingSubmitted(fid, auditId, agent, severity, title);
    }

    /// @notice Settle a finding after the sandbox has run the exploit.
    /// @param valid true if the exploit reproduced (proof-of-exploit passed).
    /// @param finalSeverity verifier-assigned severity for the confirmed finding.
    function resolveFinding(uint256 findingId, bool valid, Severity finalSeverity)
        external
        onlyVerifier
        nonReentrant
    {
        Finding storage f = findings[findingId];
        if (f.status != FindingStatus.Pending) revert AlreadyResolved();
        Audit storage a = audits[f.auditId];
        if (a.status != AuditStatus.Open) revert AuditNotOpen();

        if (!valid) {
            f.status = FindingStatus.Rejected;
            emit FindingResolved(findingId, false, Severity.None, 0);
            return;
        }
        if (finalSeverity == Severity.None) revert BadSeverity();

        f.severity = finalSeverity;
        f.status = FindingStatus.Confirmed;

        uint256 remaining = a.bounty - a.paidOut;
        uint256 reward = (a.bounty * rewardBps[finalSeverity]) / BPS;
        if (reward > remaining) reward = remaining;
        f.reward = reward;
        a.paidOut += reward;
        if (finalSeverity == Severity.High || finalSeverity == Severity.Critical) {
            a.confirmedHigh += 1;
        }

        if (reward > 0) {
            (bool ok,) = payable(f.agent).call{value: reward}("");
            if (!ok) revert TransferFailed();
        }
        emit FindingResolved(findingId, true, finalSeverity, reward);
    }

    /// @notice Close an audit: mint the attestation NFT and refund any unspent bounty.
    /// @dev Callable by verifier, submitter, or anyone after the deadline.
    function closeAudit(uint256 auditId) external nonReentrant returns (uint256 attId) {
        Audit storage a = audits[auditId];
        if (a.status != AuditStatus.Open) revert AuditNotOpen();
        if (msg.sender != verifier && msg.sender != a.submitter && block.timestamp < a.deadline) {
            revert NotAllowed();
        }
        a.status = AuditStatus.Closed;

        bool secured = a.confirmedHigh == 0;
        (uint8 score, uint256 confirmed) = _scoreAndCount(auditId);

        attId = attestation.mint(auditId, a.submitter, secured, score, a.paidOut, confirmed);
        a.attestationId = attId;

        uint256 refund = a.bounty - a.paidOut;
        if (refund > 0) {
            (bool ok,) = payable(a.submitter).call{value: refund}("");
            if (!ok) revert TransferFailed();
        }
        emit AuditClosed(auditId, secured, score, a.paidOut, refund, attId);
    }

    // ---------------------------------------------------------------------
    // Views
    // ---------------------------------------------------------------------

    function getFindingIds(uint256 auditId) external view returns (uint256[] memory) {
        return _auditFindings[auditId];
    }

    function getFindings(uint256 auditId) external view returns (Finding[] memory list) {
        uint256[] storage ids = _auditFindings[auditId];
        list = new Finding[](ids.length);
        for (uint256 i; i < ids.length; ++i) {
            list[i] = findings[ids[i]];
        }
    }

    function _scoreAndCount(uint256 auditId) internal view returns (uint8 score, uint256 confirmed) {
        uint256[] storage ids = _auditFindings[auditId];
        int256 s = 100;
        for (uint256 i; i < ids.length; ++i) {
            Finding storage f = findings[ids[i]];
            if (f.status != FindingStatus.Confirmed) continue;
            confirmed += 1;
            if (f.severity == Severity.Critical) s -= 60;
            else if (f.severity == Severity.High) s -= 35;
            else if (f.severity == Severity.Medium) s -= 12;
            else if (f.severity == Severity.Low) s -= 4;
        }
        if (s < 0) s = 0;
        score = uint8(uint256(s));
    }

    receive() external payable {}
}
