export type Severity = "None" | "Low" | "Medium" | "High" | "Critical";

export const SEVERITY_INDEX: Record<Severity, number> = {
  None: 0,
  Low: 1,
  Medium: 2,
  High: 3,
  Critical: 4,
};

export type FindingStatus = "pending" | "confirmed" | "rejected";

// What kind of asset is being audited. Settlement is identical across all three.
export type AuditKind = "contract" | "web" | "api";

export interface AgentSpec {
  id: string;
  name: string;
  emoji: string;
  focus: string;
  payoutAddress: `0x${string}`;
}

export type AgentSummary = Omit<AgentSpec, "payoutAddress">;

// How a finding was verified. tool="forge" for contracts, tool="http" for web/api.
export interface Verification {
  tool: "forge" | "http";
  passed: boolean; // true => the exploit/issue actually reproduced
  durationMs: number;
  summary: string; // one-line verdict, e.g. "forge PASS → vault drained" / "header absent"
  detail: string; // trimmed transcript / forge output
}

export interface Finding {
  agentId: string;
  agentName: string;
  agentEmoji: string;
  claimed: boolean; // did the agent claim an issue?
  severity: Severity;
  category: string; // e.g. "Reentrancy", "Missing Security Headers", "Reflected XSS"
  title: string;
  rationale: string;
  remediation?: string;
  proof: string; // solidity exploit OR the HTTP request/response transcript
  status: FindingStatus;
  verified: boolean; // sandbox/probe reproduced it (paid) vs heuristic/unproven
  rewardWei: string; // "0" if none / simulated
  payoutAddress?: `0x${string}`;
  verification?: Verification;
  txHash?: string;
}

export interface AuditResult {
  id: string;
  kind: AuditKind;
  title: string;
  target: string; // contract name OR audited URL
  createdAt: number;
  bountyWei: string;
  onchain: boolean;
  demoMode: boolean;
  status: "running" | "closed";
  summary: string; // short analyst summary of the run
  agents: AgentSummary[]; // roster, for grouping findings in the arena
  findings: Finding[];
  score: number;
  secured: boolean;
  paidOutWei: string;
  refundedWei: string;
  attestationId?: number;
  txs: { label: string; hash: string }[];
  explorer: string;
}
