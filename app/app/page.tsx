"use client";

import { useState } from "react";
import { formatEther } from "viem";
import { useAccount, useConnect, useDisconnect, useChainId, useSwitchChain } from "wagmi";
import { injected } from "wagmi/connectors";
import { EXAMPLES } from "@/lib/examples";
import type { AuditResult, Finding, AuditKind, AgentSummary } from "@/lib/types";

const KINDS: { id: AuditKind; label: string; emoji: string; blurb: string }[] = [
  { id: "contract", label: "Smart Contract", emoji: "📜", blurb: "Solidity · verified by a Foundry exploit" },
  { id: "web", label: "Web Frontend", emoji: "🌐", blurb: "a URL · verified by live HTTP probes" },
  { id: "api", label: "Backend API", emoji: "🛰️", blurb: "an API base URL · verified by live probes" },
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
      <button className="btn ghost" onClick={() => disconnect()} aria-label="Disconnect wallet" title="Disconnect">
        ✕
      </button>
    </div>
  );
}

const scoreColor = (s: number) => (s >= 80 ? "var(--green)" : s >= 50 ? "var(--amber)" : "var(--red)");

function FindingRow({ f }: { f: Finding }) {
  return (
    <div className="finding">
      <div className="frow">
        <span className={`tag-sev sev-${f.severity}`}>{f.severity}</span>
        <span className="ftitle">{f.title}</span>
        <span className={`fstat ${f.status === "confirmed" ? "bad" : "warn"}`}>
          {f.status === "confirmed" ? "PROVEN" : "unproven"}
        </span>
      </div>
      <div className="desc">{f.rationale}</div>
      {f.remediation && (
        <div className="fix">
          <strong>Fix:</strong> {f.remediation}
        </div>
      )}
      {f.verification && (
        <div className={`statusline ${f.verification.passed ? "bad" : "warn"}`}>
          {f.verification.tool === "forge" ? "🔬 " : "📡 "}
          {f.verification.summary} · {f.verification.durationMs}ms
        </div>
      )}
      {f.status === "confirmed" && BigInt(f.rewardWei || "0") > 0n && (
        <div className="statusline ok">
          paid {MON(f.rewardWei)} {f.txHash ? "✓ on-chain" : "(sim)"}
        </div>
      )}
      {f.proof && (
        <details className="poc">
          <summary>view proof-of-exploit</summary>
          <pre>{f.proof}</pre>
        </details>
      )}
    </div>
  );
}

function AgentCard({ agent, findings }: { agent: AgentSummary; findings: Finding[] }) {
  const fs = findings.filter((f) => f.agentId === agent.id);
  const confirmed = fs.filter((f) => f.status === "confirmed");
  const claimed = fs.filter((f) => f.claimed);
  const cls = confirmed.length ? "confirmed" : claimed.length ? "rejected" : "clean";
  return (
    <div className={`agent ${cls}`}>
      <div className="head">
        <span className="ico">{agent.emoji}</span>
        <div>
          <div className="name">{agent.name}</div>
          <div className="focus">{agent.focus}</div>
        </div>
      </div>
      {confirmed.length ? (
        <div className="verdict bad">⚠ {confirmed.length} proven issue{confirmed.length > 1 ? "s" : ""}</div>
      ) : claimed.length ? (
        <div className="verdict warn">✗ claim not proven</div>
      ) : (
        <div className="verdict ok">✓ no issue found</div>
      )}
      {fs.filter((f) => f.claimed).map((f, i) => (
        <FindingRow key={i} f={f} />
      ))}
    </div>
  );
}

function Result({ r }: { r: AuditResult }) {
  return (
    <>
      <div className="panel">
        <div className="summary">
          <div className="gauge" style={{ background: `conic-gradient(${scoreColor(r.score)} ${r.score * 3.6}deg, var(--border) 0)` }}>
            <div className="inner">
              <div>
                <div className="num" style={{ color: scoreColor(r.score) }}>{r.score}</div>
                <div className="lbl">SECURITY SCORE</div>
              </div>
            </div>
          </div>
          <div>
            <div className={`verdict-badge ${r.secured ? "secured" : "vuln"}`}>
              {r.secured ? "🛡️ SECURED" : "🚨 VULNERABILITIES FOUND"}
              {r.attestationId ? <span className="mono small">· Attestation #{r.attestationId}</span> : null}
            </div>
            <p className="muted" style={{ margin: "10px 0 0", fontSize: 14 }}>{r.summary}</p>
            <div className="kv">
              <div><div className="k">Bounty escrowed</div><div className="v">{MON(r.bountyWei)}</div></div>
              <div><div className="k">Paid to auditors</div><div className="v" style={{ color: "var(--green)" }}>{MON(r.paidOutWei)}</div></div>
              <div><div className="k">Refunded</div><div className="v">{MON(r.refundedWei)}</div></div>
              <div><div className="k">Settlement</div><div className="v">{r.onchain ? "On-chain" : "Simulated"}</div></div>
            </div>
          </div>
        </div>
      </div>

      {r.staticAnalysis && r.staticAnalysis.findings.length > 0 && (
        <div className="panel">
          <h3>
            🔬 Static analysis ({r.staticAnalysis.tool}) — {r.staticAnalysis.findings.length} lead
            {r.staticAnalysis.findings.length > 1 ? "s" : ""}
          </h3>
          <p className="muted small" style={{ marginTop: -6 }}>
            Open-source scanner leads (high recall). Confirmed ones are <strong>proven</strong> by the agents in the
            Arena below; unproven candidates pay nothing.
          </p>
          <div className="leads">
            {r.staticAnalysis.findings.map((s, i) => (
              <div key={i} className="lead">
                <span className={`tag-sev sev-${s.impact}`}>{s.impact}</span>
                <code className="mono">{s.check}</code>
                <span className="muted small"> · conf {s.confidence}</span>
                <div className="desc">{s.description}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="panel">
        <h3>⚔️ The Arena — {KINDS.find((k) => k.id === r.kind)?.emoji} {r.target}</h3>
        <div className="agents">
          {r.agents.map((a) => (
            <AgentCard key={a.id} agent={a} findings={r.findings} />
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
                <a href={`${r.explorer}/tx/${t.hash}`} target="_blank" rel="noreferrer" className="mono small">{short(t.hash)} ↗</a>
              </li>
            ))}
          </ul>
        </div>
      )}
    </>
  );
}

export default function Home() {
  const [kind, setKind] = useState<AuditKind>("contract");
  const [code, setCode] = useState(EXAMPLES[0].code);
  const [picked, setPicked] = useState(EXAMPLES[0].key);
  const [title, setTitle] = useState(EXAMPLES[0].title);
  const [target, setTarget] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<AuditResult | null>(null);
  const [error, setError] = useState("");

  function pickExample(ex: (typeof EXAMPLES)[number]) {
    setPicked(ex.key);
    setCode(ex.code);
    setTitle(ex.title);
    setResult(null);
    setError("");
  }

  const canRun = kind === "contract" ? code.trim().length > 20 : target.trim().length > 4 && authorized;

  async function run() {
    setRunning(true);
    setError("");
    setResult(null);
    try {
      const res = await fetch("/api/run", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(
          kind === "contract" ? { kind, code, title } : { kind, target, title: target, authorized }
        ),
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
      <header className="topbar">
        <div className="brand">
          <div className="logo">🛡️</div>
          <div>
            <h1>AegisArena</h1>
            <div className="tag">Proof-of-exploit audits for your whole stack · Monad</div>
          </div>
        </div>
        <WalletButton />
      </header>

      <main>
      <section className="hero">
        <div className="kicker">Proof-of-Exploit Protocol · Monad Testnet</div>
        <h2>
          A swarm of AI auditors that <span className="accent">prove</span> the bug across your{" "}
          <span className="accent">contracts, frontend &amp; backend</span> — then get paid.
        </h2>
        <p>
          Point AegisArena at a smart contract, a website, or an API and post a bounty. Independent agents compete to
          find vulnerabilities — but a finding only counts if it&apos;s <strong>reproduced live</strong>: a Foundry
          exploit that drains the contract, or a non-destructive HTTP probe that reproduces the web flaw. Proven bugs
          pay out instantly on Monad; hallucinations earn nothing.
        </p>
      </section>

      <div className="howto">
        <div className="step"><b>1 · Submit</b><span>contract source, or a URL you own</span></div>
        <div className="step"><b>2 · Agents attack</b><span>each writes an executable proof-of-exploit</span></div>
        <div className="step"><b>3 · Verify &amp; pay</b><span>sandbox/live probe confirms → payout + attestation</span></div>
      </div>

      <div className="panel">
        <h3>1 · Choose a target type</h3>
        <div className="examples">
          {KINDS.map((k) => (
            <button
              type="button"
              key={k.id}
              aria-pressed={kind === k.id}
              className={`chip ${kind === k.id ? "active" : ""}`}
              onClick={() => {
                setKind(k.id);
                setResult(null);
                setError("");
              }}
            >
              {k.emoji} {k.label}
              <small>{k.blurb}</small>
            </button>
          ))}
        </div>

        {kind === "contract" ? (
          <>
            <div className="examples">
              {EXAMPLES.map((ex) => (
                <button
                  type="button"
                  key={ex.key}
                  aria-pressed={picked === ex.key}
                  className={`chip ${picked === ex.key ? "active" : ""}`}
                  onClick={() => pickExample(ex)}
                >
                  {ex.title}
                  <small>{ex.hint}</small>
                </button>
              ))}
            </div>
            <textarea value={code} onChange={(e) => setCode(e.target.value)} spellCheck={false} />
            <div className="muted small" style={{ marginTop: 8 }}>
              Self-contained Solidity · solc 0.8.x
            </div>
          </>
        ) : (
          <>
            <input
              className="url"
              placeholder={kind === "web" ? "https://your-app.example.com" : "https://api.your-app.example.com"}
              value={target}
              onChange={(e) => setTarget(e.target.value)}
              spellCheck={false}
            />
            <label className="authz">
              <input type="checkbox" checked={authorized} onChange={(e) => setAuthorized(e.target.checked)} />
              <span>
                I own this target or am explicitly authorized to security-test it. AegisArena runs only{" "}
                <strong>non-destructive</strong> checks and refuses internal/private hosts.
              </span>
            </label>
          </>
        )}

        <div className="row spread" style={{ marginTop: 14 }}>
          <span className="muted small">
            {kind === "contract"
              ? "Verified by a real Foundry sandbox"
              : "Live, rate-limited, non-destructive HTTP probes (OWASP-aligned)"}
          </span>
          <button className="btn big" onClick={run} disabled={running || !canRun} aria-busy={running}>
            {running ? (
              <><span className="spin" /> &nbsp;Agents auditing…</>
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
            {[0, 1, 2].map((i) => (
              <div key={i} className="agent working">
                <div className="head">
                  <span className="ico">{kind === "contract" ? "🛡️" : "🛰️"}</span>
                  <div><div className="name">Agent {i + 1}</div></div>
                </div>
                <div className="desc">{kind === "contract" ? "Analyzing source & drafting an exploit…" : "Probing the target safely…"}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {result && (
        <>
          {result.demoMode && (
            <div className="banner info">
              Contract agents in <strong>demo mode</strong> (no <span className="mono">ANTHROPIC_API_KEY</span>) — the
              reentrancy PoC is canned, but the Foundry verdict is 100% real.
            </div>
          )}
          {!result.onchain && (
            <div className="banner info">
              Settlement <strong>simulated</strong> — set <span className="mono">AUDIT_ARENA_ADDRESS</span> +{" "}
              <span className="mono">VERIFIER_PRIVATE_KEY</span> to pay agents for real on Monad.
            </div>
          )}
          <Result r={result} />
        </>
      )}
      </main>

      <footer>
        AegisArena · proof-of-exploit audits for contracts, web &amp; APIs · built for the Monad hackathon · agents are
        paid only for vulnerabilities they can prove. Web/API scanning is for assets you own or are authorized to test.
      </footer>
    </div>
  );
}
