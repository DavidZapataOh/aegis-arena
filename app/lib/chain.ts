import {
  createPublicClient,
  createWalletClient,
  defineChain,
  http,
  parseEventLogs,
  type Hash,
} from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { parseAbi } from "viem";
import { MONAD_TESTNET, AUDIT_ARENA_ADDRESS, VERIFIER_PRIVATE_KEY, ONCHAIN } from "./config";

export const monadTestnet = defineChain({
  id: MONAD_TESTNET.id,
  name: MONAD_TESTNET.name,
  nativeCurrency: { name: "Monad", symbol: MONAD_TESTNET.symbol, decimals: 18 },
  rpcUrls: { default: { http: [MONAD_TESTNET.rpcUrl] } },
  blockExplorers: { default: { name: "MonadExplorer", url: MONAD_TESTNET.explorer } },
  testnet: true,
});

export const AUDIT_ARENA_ABI = parseAbi([
  "function submitContract(string codeURI, string title, uint64 duration) payable returns (uint256)",
  "function submitFinding(uint256 auditId, address agent, string agentName, uint8 severity, string title, string exploitURI) returns (uint256)",
  "function resolveFinding(uint256 findingId, bool valid, uint8 finalSeverity)",
  "function closeAudit(uint256 auditId) returns (uint256)",
  "event AuditSubmitted(uint256 indexed auditId, address indexed submitter, uint256 bounty, string title)",
  "event FindingSubmitted(uint256 indexed findingId, uint256 indexed auditId, address indexed agent, uint8 severity, string title)",
  "event FindingResolved(uint256 indexed findingId, bool valid, uint8 severity, uint256 reward)",
  "event AuditClosed(uint256 indexed auditId, bool secured, uint8 score, uint256 bountyPaid, uint256 refunded, uint256 attestationId)",
]);

export function explorerTx(hash: string) {
  return `${MONAD_TESTNET.explorer}/tx/${hash}`;
}

export function isOnchain() {
  return ONCHAIN;
}

function clients() {
  const account = privateKeyToAccount(VERIFIER_PRIVATE_KEY as `0x${string}`);
  const transport = http(MONAD_TESTNET.rpcUrl);
  const publicClient = createPublicClient({ chain: monadTestnet, transport });
  const walletClient = createWalletClient({ account, chain: monadTestnet, transport });
  return { account, publicClient, walletClient };
}

export interface CloseResult {
  attestationId: number;
  secured: boolean;
  score: number;
  bountyPaidWei: bigint;
  refundedWei: bigint;
  txHash: Hash;
}

export const Chain = {
  async submitContract(codeURI: string, title: string, bountyWei: bigint, durationSecs = 3600n) {
    const { publicClient, walletClient } = clients();
    const hash = await walletClient.writeContract({
      address: AUDIT_ARENA_ADDRESS as `0x${string}`,
      abi: AUDIT_ARENA_ABI,
      functionName: "submitContract",
      args: [codeURI, title, durationSecs],
      value: bountyWei,
    });
    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    const logs = parseEventLogs({ abi: AUDIT_ARENA_ABI, logs: receipt.logs, eventName: "AuditSubmitted" });
    const auditId = (logs[0] as any).args.auditId as bigint;
    return { auditId, txHash: hash };
  },

  async submitFinding(
    auditId: bigint,
    agent: `0x${string}`,
    agentName: string,
    severityIdx: number,
    title: string,
    exploitURI: string
  ) {
    const { publicClient, walletClient } = clients();
    const hash = await walletClient.writeContract({
      address: AUDIT_ARENA_ADDRESS as `0x${string}`,
      abi: AUDIT_ARENA_ABI,
      functionName: "submitFinding",
      args: [auditId, agent, agentName, severityIdx, title, exploitURI],
    });
    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    const logs = parseEventLogs({ abi: AUDIT_ARENA_ABI, logs: receipt.logs, eventName: "FindingSubmitted" });
    const findingId = (logs[0] as any).args.findingId as bigint;
    return { findingId, txHash: hash };
  },

  async resolveFinding(findingId: bigint, valid: boolean, severityIdx: number) {
    const { publicClient, walletClient } = clients();
    const hash = await walletClient.writeContract({
      address: AUDIT_ARENA_ADDRESS as `0x${string}`,
      abi: AUDIT_ARENA_ABI,
      functionName: "resolveFinding",
      args: [findingId, valid, valid ? severityIdx : 0],
    });
    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    const logs = parseEventLogs({ abi: AUDIT_ARENA_ABI, logs: receipt.logs, eventName: "FindingResolved" });
    const reward = (logs[0] as any)?.args?.reward as bigint | undefined;
    return { txHash: hash, rewardWei: reward ?? 0n };
  },

  async closeAudit(auditId: bigint): Promise<CloseResult> {
    const { publicClient, walletClient } = clients();
    const hash = await walletClient.writeContract({
      address: AUDIT_ARENA_ADDRESS as `0x${string}`,
      abi: AUDIT_ARENA_ABI,
      functionName: "closeAudit",
      args: [auditId],
    });
    const receipt = await publicClient.waitForTransactionReceipt({ hash });
    const logs = parseEventLogs({ abi: AUDIT_ARENA_ABI, logs: receipt.logs, eventName: "AuditClosed" });
    const a = (logs[0] as any).args;
    return {
      attestationId: Number(a.attestationId),
      secured: Boolean(a.secured),
      score: Number(a.score),
      bountyPaidWei: a.bountyPaid as bigint,
      refundedWei: a.refunded as bigint,
      txHash: hash,
    };
  },
};
