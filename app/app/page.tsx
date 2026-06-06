"use client";

import { useState } from "react";
import { formatEther } from "viem";
import { useAccount, useConnect, useDisconnect, useChainId, useSwitchChain } from "wagmi";
import { injected } from "wagmi/connectors";
import { EXAMPLES } from "@/lib/examples";
import type { AuditResult, Finding } from "@/lib/types";

const AGENTS_UI = [
  { id: "reentrancy", name: "Reentrancy Hunter", emoji: "🔁", focus: "reentrancy & external calls" },
  { id: "access", name: "Access Control", emoji: "🔑", focus: "privilege & ownership" },
  { id: "arithmetic", name: "Arithmetic & Logic", emoji: "🧮", focus: "overflow & accounting" },
];

const MON = (wei: string) => `${Number(formatEther(BigInt(wei || "0"))).toFixed(4)} MON`;
const short = (a?: string) => (a ? `${a.slice(0, 8)}…${a.slice(-4)}` : "");

function WalletButton() {
  const { address, isConnected } = useAccount();
  const { connect } = useConnect();
  const { disconnect } = useDisconnect();
  const chainId = useChainId();
  const { switchChain } = useSwitchChain();
  if (!isConnected)
    return (
      <button className="btn ghost" onClick={() => connect({ connector: injected() })}>
        Connect Wallet
      </button>
    );
  return (
    <div className="row">
      {chainId !== 10143 && (
        <button className="btn ghost" onClick={() => switchChain({ chainId: 10143 })}>
          Switch to Monad
        </button>
      )}
      <span className="pill">{short(address)}</span>
      <button className="btn ghost" onClick={() => disconnect()}>
        ✕
      </button>
    </div>
  );
}

function scoreColor(s: number) {
  return s >= 80 ? "var(--green)" : s >= 50 ? "var(--amber)" : "var(--red)";
}

function AgentCard({ finding }: { finding: Finding }) {
  const cls = !finding.claimed
    ? "clean"
    : finding.status === "confirmed"
    ? "confirmed"
    : "rejected";
  return (
    <div className={`agent ${cls}`}>
      <div className="head">
        <span className="ico">{finding.agentEmoji}</span>
        <div>
          <div className="name">{finding.agentName}</div>
        </div>
        <span className={`tag-sev sev-${finding.severity}`}>{finding.severity}</span>
      </div>

      {!finding.claimed ? (
        <div className="verdict ok">✓ No provable issue</div>
      ) : finding.status === "confirmed" ? (
        <div className="verdict bad">⚠ Exploit confirmed</div>
      ) : (
        <div className="verdict warn">✗ Could not prove (rejected)</div>
      )}

      <div className="desc">{finding.title}</div>

      {finding.sandbox && (
        <div className={`statusline ${finding.sandbox.forgePassed ? "bad" : "warn"}`}>
          sandbox: forge {finding.sandbox.forgePassed ? "PASS → drained" : "FAIL → safe"} ·{" "}
          {finding.sandbox.durationMs}ms
        </div>
      )}

      {finding.status === "confirmed" && BigInt(finding.rewardWei || "0") > 0n && (
        <div className="statusline ok">paid {MON(finding.rewardWei)}{finding.txHash ? " ✓ on-chain" : " (sim)"}</div>
      )}

      {finding.claimed && finding.exploit && (
        <details className="poc">
          <summary>view proof-of-exploit</summary>
          <pre>{finding.exploit}</pre>
        </details>
      )}
    </div>
  );
}

function Result({ r }: { r: AuditResult }) {
  return (
    <>
      <div className="panel">
        <div className="summary">
          <div
            className="gauge"
            style={{
              background: `conic-gradient(${scoreColor(r.score)} ${r.score * 3.6}deg, var(--border) 0)`,
            }}
          >
            <div className="inner">
              <div>
                <div className="num" style={{ color: scoreColor(r.score) }}>
                  {r.score}
                </div>
                <div className="lbl">SECURITY SCORE</div>
              </div>
            </div>
          </div>
          <div>
            <div className={`verdict-badge ${r.secured ? "secured" : "vuln"}`}>
              {r.secured ? "🛡️ SECURED" : "🚨 VULNERABILITIES FOUND"}
              {r.attestationId ? (
                <span className="mono small">· Attestation #{r.attestationId}</span>
              ) : null}
            </div>
            <div className="kv">
              <div>
                <div className="k">Bounty escrowed</div>
                <div className="v">{MON(r.bountyWei)}</div>
              </div>
              <div>
                <div className="k">Paid to auditors</div>
                <div className="v" style={{ color: "var(--green)" }}>
                  {MON(r.paidOutWei)}
                </div>
              </div>
              <div>
                <div className="k">Refunded</div>
                <div className="v">{MON(r.refundedWei)}</div>
              </div>
              <div>
                <div className="k">Settlement</div>
                <div className="v">{r.onchain ? "On-chain" : "Simulated"}</div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <div className="panel">
        <h3>⚔️ The Arena — {r.contractName}</h3>
        <div className="agents">
          {r.findings.map((f) => (
            <AgentCard key={f.agentId} finding={f} />
          ))}
        </div>
      </div>

      {r.txs.length > 0 && (
        <div className="panel">
          <h3>⛓️ On-chain settlement (Monad testnet)</h3>
          <ul className="ledger">
            {r.txs.map((t, i) => (
              <li key={i}>
                <span>{t.label}</span>
                <a href={`${r.explorer}/tx/${t.hash}`} target="_blank" rel="noreferrer" className="mono small">
                  {short(t.hash)} ↗
                </a>
              </li>
            ))}
          </ul>
        </div>
      )}
    </>
  );
}

export default function Home() {
  const [code, setCode] = useState(EXAMPLES[0].code);
  const [picked, setPicked] = useState(EXAMPLES[0].key);
  const [title, setTitle] = useState(EXAMPLES[0].title);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<AuditResult | null>(null);
  const [error, setError] = useState("");

  function pick(ex: (typeof EXAMPLES)[number]) {
    setPicked(ex.key);
    setCode(ex.code);
    setTitle(ex.title);
    setResult(null);
    setError("");
  }

  async function run() {
    setRunning(true);
    setError("");
    setResult(null);
    try {
      const res = await fetch("/api/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ code, title }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || "Audit failed");
      setResult(data);
    } catch (e: any) {
      setError(String(e?.message || e));
    } finally {
      setRunning(false);
    }
  }

  return (
    <div className="wrap">
      <div className="topbar">
        <div className="brand">
          <div className="logo">🛡️</div>
          <div>
            <h1>AegisArena</h1>
            <div className="tag">Proof-of-exploit audits · Monad</div>
          </div>
        </div>
        <WalletButton />
      </div>

      <div className="hero">
        <h2>
          A swarm of AI auditors that <span className="accent">prove</span> the bug, then get{" "}
          <span className="accent">paid</span>.
        </h2>
        <p>
          Submit a contract with a bounty. Independent agents compete to find vulnerabilities — but a finding
          only counts if its <strong>executable exploit reproduces in a Foundry sandbox</strong>. Real bugs pay
          out instantly on Monad; false positives earn nothing.
        </p>
      </div>

      <div className="panel">
        <h3>1 · Choose a target</h3>
        <div className="examples">
          {EXAMPLES.map((ex) => (
            <div key={ex.key} className={`chip ${picked === ex.key ? "active" : ""}`} onClick={() => pick(ex)}>
              {ex.title}
              <small>{ex.hint}</small>
            </div>
          ))}
          <div
            className={`chip ${picked === "custom" ? "active" : ""}`}
            onClick={() => {
              setPicked("custom");
              setResult(null);
            }}
          >
            Paste your own
            <small>any self-contained .sol</small>
          </div>
        </div>
        <textarea value={code} onChange={(e) => setCode(e.target.value)} spellCheck={false} />
        <div className="row spread" style={{ marginTop: 14 }}>
          <span className="muted small">Contract under audit · solc 0.8.x · self-contained single file</span>
          <button className="btn big" onClick={run} disabled={running}>
            {running ? (
              <>
                <span className="spin" /> &nbsp;Agents auditing…
              </>
            ) : (
              "⚔️ Send to the Arena"
            )}
          </button>
        </div>
      </div>

      {error && <div className="banner err">⚠ {error}</div>}

      {running && (
        <div className="panel">
          <h3>⚔️ The Arena</h3>
          <div className="agents">
            {AGENTS_UI.map((a) => (
              <div key={a.id} className="agent working">
                <div className="head">
                  <span className="ico">{a.emoji}</span>
                  <div>
                    <div className="name">{a.name}</div>
                    <div className="focus">{a.focus}</div>
                  </div>
                </div>
                <div className="desc">Analyzing source &amp; drafting an exploit…</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {result && (
        <>
          {result.demoMode && (
            <div className="banner info">
              Running in <strong>demo mode</strong> (no <span className="mono">ANTHROPIC_API_KEY</span> set) — the
              reentrancy agent submits a canned PoC, but the Foundry sandbox verdict is 100% real.
            </div>
          )}
          {!result.onchain && (
            <div className="banner info">
              Settlement is <strong>simulated</strong> — set <span className="mono">AUDIT_ARENA_ADDRESS</span> +{" "}
              <span className="mono">VERIFIER_PRIVATE_KEY</span> to pay agents for real on Monad.
            </div>
          )}
          <Result r={result} />
        </>
      )}

      <footer>
        AegisArena · proof-of-exploit audit marketplace · built for the Monad hackathon · agents are paid only for
        bugs they can prove.
      </footer>
    </div>
  );
}
