import { parseEther, formatEther } from "viem";
import type { AuditKind, AuditResult, Finding, Severity, AgentSummary } from "./types";
import { SEVERITY_INDEX } from "./types";
import { AGENTS, runAgents } from "./agents";
import { WEB_AGENTS, runWebAudit } from "./webagents";
import { runExploit } from "./sandbox";
import { extractContractName } from "./examples";
import { Chain, isOnchain } from "./chain";
import { DEMO_MODE, DEFAULT_BOUNTY_MON, MONAD_TESTNET } from "./config";

const REWARD_BPS: Record<Severity, bigint> = {
  Critical: 5000n,
  High: 2500n,
  Medium: 1000n,
  Low: 500n,
  None: 0n,
};

const toSummary = (specs: { id: string; name: string; emoji: string; focus: string }[]): AgentSummary[] =>
  specs.map(({ id, name, emoji, focus }) => ({ id, name, emoji, focus }));

function scoreOf(findings: Finding[]): { score: number; secured: boolean } {
  let s = 100;
  let secured = true;
  for (const f of findings) {
    if (f.status !== "confirmed") continue;
    if (f.severity === "Critical") s -= 60;
    else if (f.severity === "High") s -= 35;
    else if (f.severity === "Medium") s -= 12;
    else if (f.severity === "Low") s -= 4;
    if (f.severity === "High" || f.severity === "Critical") secured = false;
  }
  return { score: Math.max(0, s), secured };
}

// ── Contract audits: agents claim -> Foundry sandbox verifies ────────────────
async function buildContractFindings(code: string): Promise<{ findings: Finding[]; agents: AgentSummary[] }> {
  const contractName = extractContractName(code);
  const claims = await runAgents(contractName, code);
  const findings: Finding[] = [];

  for (const claim of claims) {
    const f: Finding = {
      agentId: claim.spec.id,
      agentName: claim.spec.name,
      agentEmoji: claim.spec.emoji,
      claimed: claim.claimed,
      severity: claim.claimed ? claim.severity : "None",
      category: claim.spec.name,
      title: claim.title,
      rationale: claim.rationale,
      proof: claim.exploit,
      status: "rejected",
      verified: false,
      rewardWei: "0",
      payoutAddress: claim.spec.payoutAddress,
    };
    if (claim.claimed) {
      const sb = await runExploit(code, claim.exploit);
      f.verified = sb.forgePassed;
      f.status = sb.forgePassed ? "confirmed" : "rejected";
      f.verification = {
        tool: "forge",
        passed: sb.forgePassed,
        durationMs: sb.durationMs,
        summary: sb.forgePassed ? "forge PASS → exploit reproduced" : "forge FAIL → could not reproduce",
        detail: sb.output,
      };
    }
    findings.push(f);
  }
  return { findings, agents: toSummary(AGENTS) };
}

/** Run a full audit of any target kind, then settle (on-chain or simulated). */
export async function runAudit(input: {
  kind: AuditKind;
  code?: string;
  target?: string;
  title?: string;
}): Promise<AuditResult> {
  const { kind } = input;
  let findings: Finding[];
  let agents: AgentSummary[];
  let target: string;
  let codeURI: string;

  if (kind === "contract") {
    const code = (input.code || "").trim() + "\n";
    target = extractContractName(code);
    codeURI = `inline://${target}`;
    ({ findings, agents } = await buildContractFindings(code));
  } else {
    const url = (input.target || "").trim();
    const res = await runWebAudit(kind, url);
    findings = res.findings;
    agents = toSummary(WEB_AGENTS);
    try {
      target = new URL(url).host;
    } catch {
      target = url;
    }
    codeURI = url;
  }

  const title = (input.title || target).slice(0, 80);
  return finalize({ kind, target, title, codeURI, findings, agents });
}

async function finalize(args: {
  kind: AuditKind;
  target: string;
  title: string;
  codeURI: string;
  findings: Finding[];
  agents: AgentSummary[];
}): Promise<AuditResult> {
  const { kind, target, title, codeURI, findings, agents } = args;
  const bountyWei = parseEther(DEFAULT_BOUNTY_MON);
  const onchain = isOnchain();
  const txs: { label: string; hash: string }[] = [];

  let auditId = 0n;
  if (onchain) {
    const r = await Chain.submitContract(codeURI, title, bountyWei);
    auditId = r.auditId;
    txs.push({ label: `Audit #${auditId} opened (bounty escrowed)`, hash: r.txHash });
  }

  let paidOut = 0n;
  for (const f of findings) {
    if (!f.claimed) continue;
    const sevIdx = SEVERITY_INDEX[f.severity];
    if (onchain && f.payoutAddress) {
      const sf = await Chain.submitFinding(auditId, f.payoutAddress, f.agentName, sevIdx, f.title, codeURI);
      txs.push({ label: `${f.agentName}: ${f.title}`, hash: sf.txHash });
      const rf = await Chain.resolveFinding(sf.findingId, f.verified, sevIdx);
      f.rewardWei = rf.rewardWei.toString();
      f.txHash = rf.txHash;
      txs.push({
        label: f.verified ? `✓ verified — paid ${f.agentName}` : `✗ unproven — ${f.agentName} rejected`,
        hash: rf.txHash,
      });
    } else if (f.verified) {
      const remaining = bountyWei - paidOut;
      let reward = (bountyWei * REWARD_BPS[f.severity]) / 10000n;
      if (reward > remaining) reward = remaining;
      paidOut += reward;
      f.rewardWei = reward.toString();
    }
  }

  let score: number;
  let secured: boolean;
  let refunded: bigint;
  let attestationId: number | undefined;

  if (onchain) {
    const close = await Chain.closeAudit(auditId);
    score = close.score;
    secured = close.secured;
    paidOut = close.bountyPaidWei;
    refunded = close.refundedWei;
    attestationId = close.attestationId;
    txs.push({ label: `Closed — attestation #${close.attestationId} (score ${close.score})`, hash: close.txHash });
  } else {
    const sc = scoreOf(findings);
    score = sc.score;
    secured = sc.secured;
    refunded = bountyWei - paidOut;
  }

  const confirmed = findings.filter((f) => f.status === "confirmed");
  const worst = ["Critical", "High", "Medium", "Low"].find((s) => confirmed.some((f) => f.severity === s));
  const paidAgents = new Set(confirmed.map((f) => f.agentName)).size;
  const summary =
    confirmed.length === 0
      ? `No issues proven across ${agents.length} agents — ${target} earns a Secured attestation; bounty refunded.`
      : `${confirmed.length} proven issue(s)${worst ? ` (max severity ${worst})` : ""} on ${target}. ` +
        `${formatEther(paidOut)} MON paid to ${paidAgents} agent(s).` +
        (secured ? " No high/critical issues — attestation: Secured." : "");

  return {
    id: `${Date.now().toString(36)}-${Math.floor(performance.now()).toString(36)}`,
    kind,
    title,
    target,
    createdAt: Date.now(),
    bountyWei: bountyWei.toString(),
    onchain,
    demoMode: DEMO_MODE && kind === "contract", // web/api probes are always real
    status: "closed",
    summary,
    agents,
    findings,
    score,
    secured,
    paidOutWei: paidOut.toString(),
    refundedWei: refunded.toString(),
    attestationId,
    txs,
    explorer: MONAD_TESTNET.explorer,
  };
}
