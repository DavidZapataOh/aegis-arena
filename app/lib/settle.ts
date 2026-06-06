import { parseEther } from "viem";
import type { AuditResult, Finding, Severity } from "./types";
import { SEVERITY_INDEX } from "./types";
import { runAgents } from "./agents";
import { runExploit } from "./sandbox";
import { extractContractName } from "./examples";
import { Chain, isOnchain, explorerTx } from "./chain";
import { DEMO_MODE, DEFAULT_BOUNTY_MON, MONAD_TESTNET } from "./config";

const REWARD_BPS: Record<Severity, bigint> = {
  Critical: 5000n,
  High: 2500n,
  Medium: 1000n,
  Low: 500n,
  None: 0n,
};

function score(findings: Finding[]): { score: number; secured: boolean } {
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

/** Run a full audit: agents claim -> sandbox verifies -> settle (on-chain or simulated). */
export async function runAudit(rawCode: string, rawTitle?: string): Promise<AuditResult> {
  const code = rawCode.trim() + "\n";
  const contractName = extractContractName(code);
  const title = (rawTitle || contractName).slice(0, 80);
  const id = `${Date.now().toString(36)}-${Math.floor(performance.now()).toString(36)}`;
  const bountyWei = parseEther(DEFAULT_BOUNTY_MON);
  const onchain = isOnchain();
  const txs: { label: string; hash: string }[] = [];

  // 1) Escrow a bounty + open the audit (on-chain) or note it (simulated).
  let auditId = 0n;
  if (onchain) {
    const r = await Chain.submitContract(`inline://${contractName}`, title, bountyWei);
    auditId = r.auditId;
    txs.push({ label: `Audit #${auditId} opened (bounty escrowed)`, hash: r.txHash });
  }

  // 2) Agents analyze in parallel and produce claims.
  const claims = await runAgents(contractName, code);

  // 3) Verify each claim in the sandbox (sequential) and settle.
  const findings: Finding[] = [];
  let paidOut = 0n;

  for (const claim of claims) {
    const base: Finding = {
      agentId: claim.spec.id,
      agentName: claim.spec.name,
      agentEmoji: claim.spec.emoji,
      claimed: claim.claimed,
      severity: claim.severity,
      title: claim.title,
      rationale: claim.rationale,
      exploit: claim.exploit,
      status: "rejected",
      verified: false,
      rewardWei: "0",
    };

    if (!claim.claimed) {
      base.status = "rejected"; // no claim -> nothing to settle
      base.severity = "None";
      findings.push(base);
      continue;
    }

    // Proof-of-exploit: run the agent's PoC against the target in the sandbox.
    const sb = await runExploit(code, claim.exploit);
    base.sandbox = { durationMs: sb.durationMs, forgePassed: sb.forgePassed, output: sb.output };
    base.verified = sb.forgePassed;
    base.status = sb.forgePassed ? "confirmed" : "rejected";

    if (onchain) {
      const sevIdx = SEVERITY_INDEX[claim.severity];
      const sf = await Chain.submitFinding(
        auditId,
        claim.spec.payoutAddress,
        claim.spec.name,
        sevIdx,
        claim.title,
        "inline://poc"
      );
      txs.push({ label: `${claim.spec.name} submitted finding #${sf.findingId}`, hash: sf.txHash });
      const rf = await Chain.resolveFinding(sf.findingId, sb.forgePassed, sevIdx);
      base.rewardWei = rf.rewardWei.toString();
      base.txHash = rf.txHash;
      txs.push({
        label: sb.forgePassed
          ? `Exploit verified ✓ — paid ${claim.spec.name}`
          : `Exploit failed ✗ — ${claim.spec.name} rejected`,
        hash: rf.txHash,
      });
    } else if (sb.forgePassed) {
      // Simulated payout (display only): severity share of bounty, capped by remainder.
      const remaining = bountyWei - paidOut;
      let reward = (bountyWei * REWARD_BPS[claim.severity]) / 10000n;
      if (reward > remaining) reward = remaining;
      paidOut += reward;
      base.rewardWei = reward.toString();
    }

    findings.push(base);
  }

  // 4) Close out: score, attestation, refund.
  let finalScore: number;
  let secured: boolean;
  let refunded: bigint;
  let attestationId: number | undefined;

  if (onchain) {
    const close = await Chain.closeAudit(auditId);
    finalScore = close.score;
    secured = close.secured;
    paidOut = close.bountyPaidWei;
    refunded = close.refundedWei;
    attestationId = close.attestationId;
    txs.push({
      label: `Audit closed — attestation #${close.attestationId} minted (score ${close.score})`,
      hash: close.txHash,
    });
  } else {
    const sc = score(findings);
    finalScore = sc.score;
    secured = sc.secured;
    refunded = bountyWei - paidOut;
  }

  return {
    id,
    title,
    contractName,
    code,
    createdAt: Date.now(),
    bountyWei: bountyWei.toString(),
    onchain,
    demoMode: DEMO_MODE,
    status: "closed",
    findings,
    score: finalScore,
    secured,
    paidOutWei: paidOut.toString(),
    refundedWei: refunded.toString(),
    attestationId,
    txs: txs.map((t) => ({ label: t.label, hash: t.hash })),
    explorer: MONAD_TESTNET.explorer,
  };
}
