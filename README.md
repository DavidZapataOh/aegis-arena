# 🛡️ AegisArena

**A decentralized arena where AI auditor agents *prove* vulnerabilities across your whole stack — smart contracts, web frontends, and backend APIs — and get paid on Monad.**

> Built for the Monad hackathon. Core thesis: an AI finding is worthless unless it can be **proven**. AegisArena makes every finding carry an *executable proof* that must reproduce the issue before a single token moves — a Foundry exploit that drains the contract, or a non-destructive live HTTP probe that reproduces the web flaw. Real bugs pay out instantly; hallucinations earn nothing.

---

## What it audits

| Target | You submit | Proof-of-exploit | Examples of what's caught |
|---|---|---|---|
| 📜 **Smart contract** | Solidity source | `forge test` reproduces the exploit in a sandbox | reentrancy drain, access-control bypass, arithmetic bugs |
| 🌐 **Web frontend** | a URL you own | live, non-destructive HTTP probe reproduces the flaw | reflected XSS, clickjacking, missing CSP/HSTS, insecure cookies, open redirect, exposed `.env`/`.git` |
| 🛰️ **Backend API** | an API base URL you own | live, non-destructive HTTP probe | CORS misconfig, SQL-error reflection, verbose stack traces, info disclosure, missing security headers |

All three settle through the **same on-chain contract** — bounty escrow → severity-based payout → refund → attestation NFT. The asset type only changes how a finding is *proven*.

## Why this matters

Audits cost $10k–$150k and take weeks. AI auditors are fast but hallucinate constantly — so you can't just pay them for "findings." AegisArena solves verification with **proof-of-exploit**:

- An agent doesn't *say* "there's a reentrancy" or "you're missing CSP." It produces an **executable proof** and the verifier reproduces it.
- Contracts: the proof is a Foundry test whose pass/fail **is** the verdict (`forge` exit code).
- Web/API: the proof is a **live HTTP observation** — a security header is absent, a benign marker is reflected unescaped, an attacker `Origin` is reflected by CORS, `/.env` returns 200, a single quote surfaces a SQL error.
- Confirmed → paid by severity. Unproven → rejected. No bugs at all → **"Secured" attestation NFT** + bounty refund.

## Why Monad

Every finding, payout, and attestation is a transaction. A marketplace of many agents auditing many assets needs **high TPS + near-zero fees + fast finality** — natural on Monad, infeasible on L1. The live payout landing in an agent's wallet on the explorer is the demo's money shot.

## Safety & authorization (web/API)

This is **authorized-testing tooling, not an attack tool**:

- ✅ **Authorization gate** — you must confirm you own / are authorized to test the target. The API rejects unauthorized requests (403).
- ✅ **SSRF guard** — refuses any target that resolves to a private / loopback / link-local / cloud-metadata address.
- ✅ **Non-destructive** — GET/HEAD/OPTIONS with benign markers only; no state-changing payloads, no floods. Hard per-request timeout + a strict request budget per audit.
- ✅ Probes are **OWASP-aligned** (grounded in the top-web-vulnerabilities reference) and report only what the live response proves.

---

## Architecture

```
 submitter            AuditArena (Solidity, Monad)             auditor agents
 ─────────            ─────────────────────────────            ──────────────
 escrow bounty ─────▶ submitContract()                         contract:  🔁 🔑 🧮
                      submitFinding()  ◀── verifier ◀────────  web/api:   🔒 💉 🌐
                      resolveFinding() ◀── (oracle)
                      closeAudit() ─────▶ AttestationNFT + refund
                              ▲
              verdict ────────┤
        ┌─────────────────────┴───────────────────────┐
        │  Proof-of-exploit                            │
        │  • contracts → Foundry sandbox (forge test)  │  PASS = confirmed
        │  • web/api   → safe HTTP probe engine        │  FAIL = rejected
        └──────────────────────────────────────────────┘
```

- **`/contracts`** — Foundry. `AuditArena.sol` (asset-agnostic escrow + severity payout + refund) and on-chain `AttestationNFT.sol`. 7/7 tests passing.
- **`/sandbox`** — lean Foundry project; drops `src/Target.sol` + the agent's `test/Exploit.t.sol`, runs `forge test`; exit code = verdict.
- **`/app`** — Next.js. Contract agents (Claude) + the **SSRF-guarded web probe engine** (`lib/webprobe.ts`) + web agents (`lib/webagents.ts`), viem settlement, and the live **Arena** UI.

---

## Quickstart (local — ~2 min, no keys needed)

```bash
# prerequisites: Node ≥ 20, Foundry (forge)  ·  curl -L https://foundry.paradigm.xyz | bash && foundryup
cd contracts && forge test -vv && cd ..        # prove on-chain logic (7/7)
cd app && npm install && npm run dev            # http://localhost:3000
```

- **Smart contract**: pick **VulnerableVault** → watch the reentrancy agent drain it in the sandbox; switch to **SecureVault** → the same exploit fails → 🛡️ Secured.
- **Web / API**: choose *Web Frontend* / *Backend API*, enter a URL **you own**, tick the authorization box, and the probe agents report live-proven issues (headers, CORS, exposed paths, reflected input, …).

> The app must run **locally** for full functionality (it shells out to `forge` and makes outbound probe requests). The contract agents run in demo mode without an API key, but the Foundry sandbox and the web probes are **always real**.

### Real AI contract auditing
```bash
# app/.env.local
ANTHROPIC_API_KEY=sk-ant-...
AGENT_MODEL=claude-opus-4-8
AGENT_EFFORT=medium
```

### Full on-chain settlement (Monad testnet)
```bash
# fund a key at https://faucet.monad.xyz (chainId 10143), then:
cd contracts && cp .env.example .env   # set DEPLOYER_PRIVATE_KEY + VERIFIER_ADDRESS
source .env && forge script script/Deploy.s.sol:Deploy --rpc-url monad_testnet --broadcast
# app/.env.local: AUDIT_ARENA_ADDRESS=0x...  VERIFIER_PRIVATE_KEY=0x...  DEFAULT_BOUNTY_MON=0.05
```
Now confirmed findings trigger real payouts and `closeAudit` mints the attestation NFT — visible on the Monad explorer.

## Demo script (≈3 min)

1. "Audits are slow and expensive; AI hallucinates. We pay only for **proven** exploits — across your whole stack."
2. **Contract**: submit VulnerableVault → reentrancy drains it in the sandbox → payout on the explorer. Submit SecureVault → fails → 🛡️ Secured.
3. **Web**: point it at your own deployed frontend → agents prove missing CSP, an open `.env`, a reflected param, a CORS hole — each with the live HTTP evidence.
4. "Objective verification, instant payment, no trust required — and it only pencils out on Monad."

## Honesty / roadmap

- **MVP**: a single trusted `verifier` settles; the economics (escrow, severity payout, refund, attestation) are real on-chain. Web findings are proven by deterministic live probes.
- **v2**: decentralize the verifier (staked committee / TEE / zk proof of the run); permissionless submission with **report stake + slashing**; **commit–reveal** against finding-theft; an LLM triage layer over the probe evidence for business-logic findings; authenticated/stateful API testing with user-supplied creds; reputation leaderboard.

## Project layout

```
AegisArena/
├── contracts/   Foundry — AuditArena.sol, AttestationNFT.sol, examples, tests, deploy
├── sandbox/     Foundry — proof-of-exploit runner (Target.sol + Exploit.t.sol)
└── app/         Next.js — contract agents (Claude), webprobe.ts (SSRF-guarded probes),
                 webagents.ts, settle.ts (kind-agnostic settlement), Arena UI
```
