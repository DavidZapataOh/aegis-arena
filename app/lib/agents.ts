import Anthropic from "@anthropic-ai/sdk";
import { ANTHROPIC_API_KEY, AGENT_MODEL, AGENT_EFFORT, DEMO_MODE } from "./config";
import type { AgentSpec, Severity, StaticFinding } from "./types";
import { reentrancyExploit } from "./examples";

// Three independent auditor agents, each a different "person" with a payout address.
// Override the addresses with AGENT_ADDRESSES="0x..,0x..,0x.." (defaults are anvil keys,
// recognizable in a demo).
const addrs = (process.env.AGENT_ADDRESSES || "")
  .split(",")
  .map((s) => s.trim())
  .filter(Boolean) as `0x${string}`[];

export const AGENTS: AgentSpec[] = [
  {
    id: "reentrancy",
    name: "Reentrancy Hunter",
    emoji: "🔁",
    focus: "reentrancy, unchecked external calls, checks-effects-interactions violations",
    payoutAddress: addrs[0] || "0x70997970C51812dc3A010C7d01b50e0d17dc79C8",
  },
  {
    id: "access",
    name: "Access Control",
    emoji: "🔑",
    focus: "missing/incorrect access control, unprotected privileged functions, ownership bugs",
    payoutAddress: addrs[1] || "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC",
  },
  {
    id: "arithmetic",
    name: "Arithmetic & Logic",
    emoji: "🧮",
    focus: "overflow/underflow, rounding/precision loss, accounting and business-logic errors",
    payoutAddress: addrs[2] || "0x90F79bf6EB2c4f870365E785982E1f101E93b906",
  },
];

export interface AgentClaim {
  spec: AgentSpec;
  claimed: boolean;
  severity: Severity;
  title: string;
  rationale: string;
  exploit: string; // Foundry PoC source (empty when no claim)
}

const RESPONSE_SCHEMA = {
  type: "object",
  properties: {
    vulnerability_found: { type: "boolean" },
    severity: { type: "string", enum: ["None", "Low", "Medium", "High", "Critical"] },
    title: { type: "string" },
    rationale: { type: "string" },
    exploit_test: { type: "string" },
  },
  required: ["vulnerability_found", "severity", "title", "rationale", "exploit_test"],
  additionalProperties: false,
} as const;

function systemPrompt(spec: AgentSpec, contractName: string): string {
  return `You are "${spec.name}", an autonomous smart-contract security auditor competing in a decentralized audit arena.
Your specialty: ${spec.focus}.

You are paid ONLY for vulnerabilities you can PROVE with an executable exploit, and you are SLASHED for false positives. So never report a bug you cannot demonstrate.

THE PROOF-OF-EXPLOIT CONTRACT (read carefully):
- The contract under audit is available to import as: import {${contractName}} from "../src/Target.sol";
- If you believe there is an exploitable vulnerability, you MUST return a complete, self-contained Foundry test file in "exploit_test".
- That test file must define a contract named exactly "Exploit" (an extension of forge-std's Test) with a public function "test_exploit()".
- The test must be written so that it PASSES if and only if the vulnerability genuinely reproduces (e.g. funds are drained, an invariant is broken, access control is bypassed). Use assertions to encode the violated invariant.
- A verifier runs \`forge test\` on your file. If it passes, your finding is confirmed and you are paid by severity. If it fails or does not compile, your finding is rejected.
- Only use forge-std and the imported target. Do not import anything else. Solidity ^0.8.24.

Reference example of the exact shape (a reentrancy drain):
\`\`\`solidity
${reentrancyExploit(contractName)}
\`\`\`

If, after analysis, you cannot construct a passing proof for an exploitable issue in your specialty, set vulnerability_found=false, severity="None", and exploit_test="". Do not pad with speculative or low-confidence findings.`;
}

function staticHintsBlock(hints: StaticFinding[], focusId: string): string {
  if (!hints.length) return "";
  const lines = hints
    .map((h) => `- [${h.impact}/${h.confidence}] ${h.check}: ${h.description}`)
    .join("\n");
  return `\n\nAn open-source static analyzer (Slither) flagged these LEADS on this contract:\n${lines}\n\nTreat them as candidates, not conclusions: investigate the ones in your specialty, PROVE the real ones with a passing PoC, and ignore Slither's false positives. You may also report issues Slither missed.`;
}

async function callAgent(
  client: Anthropic,
  spec: AgentSpec,
  contractName: string,
  source: string,
  staticHints: StaticFinding[]
): Promise<AgentClaim> {
  try {
    const res = await client.messages.create({
      model: AGENT_MODEL,
      max_tokens: 12000,
      thinking: { type: "adaptive" },
      output_config: { effort: AGENT_EFFORT, format: { type: "json_schema", schema: RESPONSE_SCHEMA } },
      system: systemPrompt(spec, contractName),
      messages: [
        {
          role: "user",
          content: `Audit this contract (importable as ${contractName} from ../src/Target.sol):\n\n\`\`\`solidity\n${source}\n\`\`\`${staticHintsBlock(staticHints, spec.id)}`,
        },
      ],
    } as any);

    const text = res.content.find((b: any) => b.type === "text") as any;
    const parsed = JSON.parse(text?.text ?? "{}");
    const claimed = Boolean(parsed.vulnerability_found) && Boolean(parsed.exploit_test?.trim());
    return {
      spec,
      claimed,
      severity: (parsed.severity as Severity) || "None",
      title: parsed.title || (claimed ? "Potential vulnerability" : "No issue found"),
      rationale: parsed.rationale || "",
      exploit: claimed ? stripFences(parsed.exploit_test) : "",
    };
  } catch (err: any) {
    return {
      spec,
      claimed: false,
      severity: "None",
      title: "Agent error",
      rationale: `Agent could not complete analysis: ${err?.message || err}`,
      exploit: "",
    };
  }
}

function stripFences(s: string): string {
  return s.replace(/^```(?:solidity)?\s*/i, "").replace(/```\s*$/i, "").trim() + "\n";
}

/** Deterministic demo claims — used when there's no ANTHROPIC_API_KEY (DEMO_MODE).
 *  The reentrancy agent always submits a PoC; the SANDBOX decides if it reproduces,
 *  so the full claim -> verify -> (confirm|reject) loop still runs for real. */
function demoClaims(contractName: string): AgentClaim[] {
  return AGENTS.map((spec) => {
    if (spec.id === "reentrancy") {
      return {
        spec,
        claimed: true,
        severity: "Critical" as Severity,
        title: "Reentrancy in withdraw() drains the vault",
        rationale:
          "withdraw() makes an external call to msg.sender before zeroing the balance, so a malicious contract can re-enter and withdraw repeatedly, draining all depositor funds.",
        exploit: reentrancyExploit(contractName),
      };
    }
    return {
      spec,
      claimed: false,
      severity: "None" as Severity,
      title: "No provable issue in scope",
      rationale: `No exploitable ${spec.focus} issue could be proven.`,
      exploit: "",
    };
  });
}

export async function runAgents(
  contractName: string,
  source: string,
  staticHints: StaticFinding[] = []
): Promise<AgentClaim[]> {
  if (DEMO_MODE) return demoClaims(contractName);
  const client = new Anthropic({ apiKey: ANTHROPIC_API_KEY });
  return Promise.all(AGENTS.map((spec) => callAgent(client, spec, contractName, source, staticHints)));
}
