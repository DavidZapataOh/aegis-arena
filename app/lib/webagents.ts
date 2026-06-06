import type { AgentSpec, Finding } from "./types";
import { runProbes, type WebAgentId } from "./webprobe";

// Three web/API auditor agents. Each owns a family of non-destructive probes; a
// finding is "claimed + verified" only when the live HTTP response proves it.
const webAddrs = (process.env.WEB_AGENT_ADDRESSES || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean) as `0x${string}`[];

export const WEB_AGENTS: AgentSpec[] = [
  {
    id: "transport",
    name: "Transport & Headers",
    emoji: "🔒",
    focus: "TLS, HSTS, security headers, cookie flags, version disclosure",
    payoutAddress: webAddrs[0] || "0x15d34AAf54267DB7D7c367839AAf71A00a2C6A65",
  },
  {
    id: "injection",
    name: "Injection & Inputs",
    emoji: "💉",
    focus: "reflected XSS, SQL-error reflection, open redirect",
    payoutAddress: webAddrs[1] || "0x9965507D1a55bcC2695C58ba16FB37d819B0A4dc",
  },
  {
    id: "exposure",
    name: "Exposure & CORS",
    emoji: "🌐",
    focus: "CORS, exposed secrets/paths, directory listing, verbose errors",
    payoutAddress: webAddrs[2] || "0x976EA74026E726554dB657fA54763abd0C3a0aa9",
  },
];

const byId = (id: WebAgentId) => WEB_AGENTS.find((a) => a.id === id)!;

/** Audit a web frontend or backend API via the safe probe engine. */
export async function runWebAudit(
  kind: "web" | "api",
  target: string
): Promise<{ findings: Finding[]; origin: string }> {
  const { origin, findings: probes } = await runProbes(kind, target);

  const findings: Finding[] = probes.map((p) => {
    const agent = byId(p.agentId);
    return {
      agentId: agent.id,
      agentName: agent.name,
      agentEmoji: agent.emoji,
      claimed: true,
      severity: p.severity,
      category: p.category,
      title: p.title,
      rationale: p.rationale,
      remediation: p.remediation,
      proof: p.evidence,
      status: "confirmed", // probes only emit issues they observed live
      verified: true,
      rewardWei: "0",
      payoutAddress: agent.payoutAddress,
      verification: {
        tool: "http",
        passed: true,
        durationMs: p.durationMs,
        summary: `live HTTP proof · ${p.category}`,
        detail: p.evidence,
      },
    };
  });

  return { findings, origin };
}
