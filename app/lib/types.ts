export type Severity = "None" | "Low" | "Medium" | "High" | "Critical";

export const SEVERITY_INDEX: Record<Severity, number> = {
  None: 0,
  Low: 1,
  Medium: 2,
  High: 3,
  Critical: 4,
};

export type FindingStatus = "pending" | "confirmed" | "rejected";

export interface AgentSpec {
  id: string;
  name: string; // display name, e.g. "Reentrancy Hunter"
  emoji: string;
  focus: string; // short description of what it hunts
  payoutAddress: `0x${string}`;
}

export interface Finding {
  agentId: string;
  agentName: string;
  agentEmoji: string;
  claimed: boolean; // did the agent claim a vulnerability?
  severity: Severity;
  title: string;
  rationale: string;
  exploit: string; // the Foundry PoC test source
  status: FindingStatus;
  verified: boolean; // did the sandbox reproduce it?
  rewardWei: string; // "0" if none / simulated
  sandbox?: {
    durationMs: number;
    forgePassed: boolean;
    output: string; // trimmed forge output
  };
  txHash?: string; // resolveFinding tx (on-chain mode)
}

export interface AuditResult {
  id: string;
  title: string;
  contractName: string;
  code: string;
  createdAt: number;
  bountyWei: string;
  onchain: boolean;
  demoMode: boolean;
  status: "running" | "closed";
  findings: Finding[];
  score: number;
  secured: boolean;
  paidOutWei: string;
  refundedWei: string;
  attestationId?: number;
  txs: { label: string; hash: string }[];
  explorer: string;
}
