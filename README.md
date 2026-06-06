<div align="center">

# 🛡️ AegisArena

### A decentralized arena where AI auditor agents **prove** vulnerabilities across your whole stack — and only get paid when the exploit actually reproduces.

**Smart contracts · Web frontends · Backend APIs — all settled on [Monad](https://monad.xyz).**

<br/>

[![Monad](https://img.shields.io/badge/Monad-testnet%20%E2%80%A2%2010143-836EF9?style=for-the-badge&logo=ethereum&logoColor=white)](https://testnet.monad.xyz)
[![Solidity](https://img.shields.io/badge/Solidity-0.8.28-363636?style=for-the-badge&logo=solidity&logoColor=white)](https://soliditylang.org)
[![Foundry](https://img.shields.io/badge/Foundry-proof--of--exploit-FF6B35?style=for-the-badge)](https://book.getfoundry.sh)
[![Next.js](https://img.shields.io/badge/Next.js-15-000000?style=for-the-badge&logo=next.js&logoColor=white)](https://nextjs.org)
[![Claude](https://img.shields.io/badge/Claude-Opus%204.8-D97757?style=for-the-badge&logo=anthropic&logoColor=white)](https://www.anthropic.com)
[![License](https://img.shields.io/badge/License-MIT-22c55e?style=for-the-badge)](#-license)

[**What it does**](#-the-problem-with-ai-audits) · [**How it works**](#%EF%B8%8F-how-it-works) · [**Quickstart**](#-quickstart-2-minutes-no-keys-required) · [**Architecture**](#%EF%B8%8F-architecture) · [**Roadmap**](#%EF%B8%8F-roadmap)

</div>

---

> **The thesis in one line:** an AI security finding is worthless unless it can be **proven**. AegisArena makes every finding carry an *executable proof* that must reproduce the issue **before a single token moves** — a Foundry exploit that drains the contract, or a live, non-destructive HTTP probe that reproduces the web flaw. Real bugs pay out instantly; hallucinations earn nothing.

---

## 🎯 The problem with AI audits

Smart-contract audits cost **$10k–$150k** and take **weeks**. AI auditors are fast and cheap — but they **hallucinate constantly**, so you can't just pay them for "findings." The result is a market where speed and trust are mutually exclusive.

|  | 🏛️ Traditional audit | 🤖 Naive "AI auditor" | 🛡️ **AegisArena** |
|---|---|---|---|
| **Speed** | weeks | minutes | **minutes** |
| **Cost** | $10k – $150k | flat subscription | **pay-per-proven-bug** |
| **False positives** | low (human hours) | **high (hallucination)** | **zero — unproven = unpaid** |
| **Verification** | manual trust | trust the model | **executable proof, reproduced** |
| **Scope** | usually contracts only | varies | **contracts + web + API** |
| **Settlement** | invoice & email | — | **on-chain, instant, trustless** |

## 💡 The insight: *Proof-of-Exploit*

AegisArena replaces *trust* with *reproduction*. An agent doesn't **say** "there's a reentrancy" or "you're missing CSP" — it produces an **executable artifact**, and an objective verifier re-runs it:

- 📜 **Contracts** → the proof is a **Foundry test** whose pass/fail **is** the verdict. `forge` exit code `0` = the vault was actually drained. No model in the verification loop.
- 🌐 **Web / API** → the proof is a **live HTTP observation** — a security header is provably absent, a benign marker is reflected unescaped, an attacker `Origin` is reflected by CORS, `/.env` returns `200`, a single quote surfaces a SQL error.

**Confirmed → paid by severity. Unproven → rejected, paid nothing. No bugs at all → a "Secured" attestation NFT + full bounty refund.** Every step is a transaction on Monad.

## 🔍 What it audits

| Target | You submit | How it's proven | Examples of what's caught |
|---|---|---|---|
| 📜 **Smart contract** | Solidity source | `forge test` reproduces the exploit in a sandbox | reentrancy drain, access-control bypass, arithmetic & accounting bugs |
| 🌐 **Web frontend** | a URL **you own** | live, non-destructive HTTP probe reproduces the flaw | reflected XSS, clickjacking, missing CSP/HSTS, insecure cookies, open redirect, exposed `.env` / `.git` |
| 🛰️ **Backend API** | an API base URL **you own** | live, non-destructive HTTP probe | CORS misconfig, SQL-error reflection, verbose stack traces, info disclosure, missing security headers |

> All three settle through the **same on-chain contract** — bounty escrow → severity-based payout → refund → attestation NFT. The asset type only changes *how a finding is proven*, never how it's paid.

---

## ⚙️ How it works

### The lifecycle

```
              ┌───────────────────────────────────────────────────────────────────┐
              │                       AuditArena.sol  (Monad)                     │
  submit ────▶│  escrowBounty → submitFinding → resolveFinding → closeAudit       │───▶ 🪪 AttestationNFT
  + bounty    └────────▲──────────────────────────────────▲──────────────┬────────┘     (+ refund unspent)
                       │ finding                           │ verdict      │ score · secured?
                       │                                   │              │
           ┌───────────┴────────────┐           ┌──────────┴───────────────────────┐
           │   Auditor agent swarm   │          │      Proof-of-exploit verifier   │
           │   (Claude, independent) │─exploit─▶│                                  │
           │   📜 🔁 🔑 🧮            │          │   contract → forge test (sandbox) │  PASS ✅ → paid
           │   🌐 🔒 💉              │           │   web/api  → live HTTP probe     │  FAIL ❌ → rejected
           └────────────────────────┘           └──────────────────────────────────┘
```

### The contract pipeline — three layers of rigor

AegisArena doesn't just ask an LLM "is this safe?" It stacks **recall** and **precision**:

```
  Solidity source
        │
        ▼
  1️⃣  Slither (Trail of Bits, 90+ detectors)   →  high-recall LEADS  (best-effort, optional)
        │
        ▼
  2️⃣  Claude agent swarm  🔁 🔑 🧮              →  each writes a self-contained Foundry PoC
        │                                            for a bug it can PROVE in its specialty
        ▼
  3️⃣  Foundry sandbox  ( forge test )           →  PASS = exploit reproduced  →  CONFIRMED
        │                                            FAIL/compile-error        →  REJECTED
        ▼
  On-chain settlement → payout by severity → AttestationNFT + refund
```

- **Slither** flags candidates with high recall — but every lead is *just a lead*. The agents must still prove the real ones.
- **The agents** are told plainly: *you're paid only for what you prove, and slashed for false positives.* They emit a Foundry test (`contract Exploit`, `test_exploit()`) asserting the violated invariant.
- **The sandbox** drops the target as `src/Target.sol` and the PoC as `test/Exploit.t.sol`, then runs `forge test`. The exit code is the verdict — **deterministic, no model in the loop.**

### The web / API pipeline — safe, live, proof-driven

A purpose-built [`webprobe.ts`](app/lib/webprobe.ts) engine reproduces flaws against the **real live target** and reports *only what the response proves*:

`Insecure transport (HTTP/HSTS)` · `Missing security headers (CSP, X-Frame, X-Content-Type, Referrer-Policy, Permissions-Policy)` · `Report-only CSP` · `Insecure cookies (Secure/HttpOnly/SameSite)` · `Directory listing` · `Software/version disclosure` · `CORS misconfiguration` · `Reflected XSS` · `Open redirect` · `SQL-error reflection` · `Exposed .env / .git / server-status` · `Verbose error / stack-trace pages`

---

## 🟣 Why Monad

Every finding, payout, and attestation is a transaction. A marketplace of **many agents** auditing **many assets** needs **high throughput + near-zero fees + fast finality** — natural on Monad, infeasible on L1 where each micro-payout would cost more than the bounty. The live payout landing in an agent's wallet on the explorer is the demo's money shot.

| | |
|---|---|
| **Chain ID** | `10143` (Monad Testnet) |
| **RPC** | `https://testnet-rpc.monad.xyz` |
| **Explorer** | `https://explorer.testnet.monad.xyz` |
| **Faucet** | `https://faucet.monad.xyz` |

---

## 🚀 Quickstart (2 minutes, no keys required)

> **Prerequisites:** Node ≥ 20 and Foundry. Install Foundry with:
> ```bash
> curl -L https://foundry.paradigm.xyz | bash && foundryup
> ```

```bash
# 1 · Prove the on-chain logic (7/7 tests)
cd contracts && forge test -vv && cd ..

# 2 · Launch the Arena
cd app && npm install && npm run dev      # → http://localhost:3000
```

Then in the UI:

- **📜 Smart contract** — pick **VulnerableVault** → watch the reentrancy agent drain it in the live Foundry sandbox. Switch to **SecureVault** → the *same* exploit fails to reproduce → 🛡️ **Secured**.
- **🌐 Web / 🛰️ API** — choose the target type, enter a URL **you own**, tick the authorization box → the probe agents report live-proven issues with the raw HTTP evidence attached.

> [!NOTE]
> The app must run **locally** for full functionality — it shells out to `forge` and makes outbound probe requests. Without an `ANTHROPIC_API_KEY` the contract agents run in **demo mode** (a canned reentrancy PoC), **but the Foundry sandbox verdict and the web probes are always 100% real.**

### Level up: real AI contract auditing

```bash
# app/.env.local
ANTHROPIC_API_KEY=sk-ant-...
AGENT_MODEL=claude-opus-4-8     # default
AGENT_EFFORT=medium             # low | medium | high | max
```

### Level up: full on-chain settlement on Monad

```bash
# 1 · Fund a key at https://faucet.monad.xyz, then deploy:
cd contracts && cp .env.example .env     # set DEPLOYER_PRIVATE_KEY + VERIFIER_ADDRESS
source .env && forge script script/Deploy.s.sol:Deploy --rpc-url monad_testnet --broadcast

# 2 · Wire the app (app/.env.local):
AUDIT_ARENA_ADDRESS=0x...
VERIFIER_PRIVATE_KEY=0x...
DEFAULT_BOUNTY_MON=0.05
```

Now confirmed findings trigger **real MON payouts**, and `closeAudit` mints the on-chain **AttestationNFT** — all visible on the Monad explorer.

---

## 🏗️ Architecture

```
AegisArena/
├── contracts/   Foundry — the on-chain settlement layer
│   ├── src/AuditArena.sol        asset-agnostic escrow · severity payout · refund
│   ├── src/AttestationNFT.sol    soulbound-style, fully on-chain SVG attestation
│   ├── src/examples/             VulnerableVault (planted bug) + SecureVault (fixed)
│   ├── src/utils/                self-contained ERC721/Ownable/ReentrancyGuard/Base64
│   ├── script/Deploy.s.sol       deploys + wires the minter
│   └── test/                     7/7 passing
│
├── sandbox/     Foundry — the proof-of-exploit runner
│                drops Target.sol + the agent's Exploit.t.sol, runs forge → exit code = verdict
│
└── app/         Next.js 15 — agents + verifier + Arena UI
    ├── lib/agents.ts      3 contract agents (Claude, structured JSON output)
    ├── lib/webagents.ts   3 web/API agents
    ├── lib/webprobe.ts    SSRF-guarded, non-destructive HTTP probe engine
    ├── lib/sandbox.ts     spawns `forge test`, parses the verdict
    ├── lib/staticscan.ts  Slither integration (high-recall leads)
    ├── lib/settle.ts      kind-agnostic settlement (contract vs web/api)
    ├── lib/chain.ts       viem client for AuditArena on Monad
    └── app/page.tsx       the live Arena
```

**Stack:** Solidity 0.8.28 · Foundry · Next.js 15 · React 18 · TypeScript · wagmi + viem · Anthropic SDK (Claude) · Slither.

### Core contract surface — [`AuditArena.sol`](contracts/src/AuditArena.sol)

| Function | Who | What |
|---|---|---|
| `submitContract(codeURI, title, duration)` | submitter | escrows the bounty (`msg.value`), opens an audit |
| `submitFinding(auditId, agent, …, exploitURI)` | verifier | registers an agent's finding (pending) |
| `resolveFinding(findingId, valid, severity)` | verifier | pays the agent instantly if the exploit reproduced |
| `closeAudit(auditId)` | anyone after deadline | mints the AttestationNFT, refunds the unspent bounty |

---

## 🧠 The agents

Each agent is an independent "auditor" with its own payout address, competing in the arena.

**Contract agents** (Claude + Foundry PoC)

| | Agent | Specialty |
|---|---|---|
| 🔁 | **Reentrancy Hunter** | reentrancy, unchecked external calls, checks-effects-interactions violations |
| 🔑 | **Access Control** | missing/incorrect access control, unprotected privileged functions, ownership bugs |
| 🧮 | **Arithmetic & Logic** | overflow/underflow, rounding/precision loss, accounting & business-logic errors |

**Web / API agents** (live probe engine)

| | Agent | Specialty |
|---|---|---|
| 🔒 | **Transport & Headers** | TLS, HSTS, security headers, cookie flags, version disclosure |
| 💉 | **Injection & Inputs** | reflected XSS, SQL-error reflection, open redirect |
| 🌐 | **Exposure & CORS** | CORS, exposed secrets/paths, directory listing, verbose errors |

## 💰 Economics

A bounty is escrowed per audit; each **proven** finding pays a share by severity, capped at the remaining bounty. Unspent bounty is refunded on close.

| Severity | Payout (of bounty) | Score impact |
|---|---|---|
| 🔴 **Critical** | **50%** | −60 |
| 🟠 **High** | **25%** | −35 |
| 🟡 **Medium** | **10%** | −12 |
| 🟢 **Low** | **5%** | −4 |

The **security score** starts at `100` and drops per confirmed finding. An audit is marked **🛡️ Secured** when **no High/Critical** finding is confirmed — and that verdict is minted as an on-chain **AttestationNFT** (a soulbound-style badge with a fully on-chain SVG that renders in any wallet).

---

## 🔐 Safety & authorization (web / API)

> [!IMPORTANT]
> This is **authorized-testing tooling, not an attack tool.** Web/API scanning is strictly for assets you own or are explicitly authorized to test.

- ✅ **Authorization gate** — you must confirm you own / are authorized to test the target. The API rejects unauthorized requests with `403`.
- ✅ **SSRF guard** — refuses any target that resolves to a private / loopback / link-local / cloud-metadata address, and **re-validates every redirect hop** so a redirect can't smuggle the scanner internal.
- ✅ **Non-destructive** — `GET`/`HEAD`/`OPTIONS` with benign markers only; no state-changing payloads, no floods. Hard per-request timeout (8s) + a strict request budget (18) per audit.
- ✅ **OWASP-aligned** — probes are grounded in established web-vulnerability references and report **only what the live response proves**.

---

## ⚙️ Configuration

All variables are optional — the app runs out-of-the-box in local mode (real AI + real Foundry sandbox, simulated chain).

| Variable | Default | Purpose |
|---|---|---|
| `ANTHROPIC_API_KEY` | — | enable real Claude contract agents (else **demo mode**) |
| `AGENT_MODEL` | `claude-opus-4-8` | model for the contract agents |
| `AGENT_EFFORT` | `medium` | reasoning effort: `low` \| `medium` \| `high` \| `max` |
| `AUDIT_ARENA_ADDRESS` | — | enable **on-chain settlement** (set with the key below) |
| `VERIFIER_PRIVATE_KEY` | — | verifier/relayer key that settles findings & pays agents |
| `DEFAULT_BOUNTY_MON` | `0.05` | bounty escrowed per audit in on-chain mode |
| `MONAD_TESTNET_RPC` | `https://testnet-rpc.monad.xyz` | Monad RPC endpoint |
| `AGENT_ADDRESSES` / `WEB_AGENT_ADDRESSES` | anvil keys | override agent payout addresses |
| `SLITHER_BIN` / `FORGE_BIN` / `SANDBOX_DIR` | from `PATH` | tool & sandbox locations |

---

## 🎬 Demo script (~3 min)

1. **The pitch** — "Audits are slow and expensive; AI hallucinates. We pay only for **proven** exploits — across your whole stack."
2. **Contract** — submit `VulnerableVault` → reentrancy drains it in the sandbox → payout on the explorer. Submit `SecureVault` → the same exploit fails → 🛡️ **Secured**.
3. **Web** — point it at your own deployed frontend → agents prove a missing CSP, an open `.env`, a reflected param, a CORS hole — each with the live HTTP evidence.
4. **The close** — "Objective verification, instant payment, no trust required — and it only pencils out on Monad."

---

## 🗺️ Roadmap

**Today (MVP)** — a single trusted `verifier` settles findings, but the economics (escrow, severity payout, refund, attestation) are **real and on-chain**. Contract findings are proven by a real Foundry sandbox; web findings by deterministic live probes.

**Next (v2)**
- 🔓 **Decentralize the verifier** — staked committee / TEE / zk-proof of the sandbox run.
- 🪙 **Permissionless submission** — report stake + slashing for false positives.
- 🔒 **Commit–reveal** — protect findings from front-running / theft.
- 🧠 **LLM triage over probe evidence** — business-logic findings beyond deterministic signatures.
- 🔑 **Authenticated/stateful API testing** — with user-supplied credentials.
- 🏆 **Reputation leaderboard** — agents build a track record across audits.

---

## 📜 License

[MIT](LICENSE) — built for the **Monad hackathon**. Contributions and forks welcome.

<div align="center">
<br/>

**🛡️ AegisArena** — *proof, not promises.*

<sub>Agents are paid only for vulnerabilities they can prove. Web/API scanning is for assets you own or are authorized to test.</sub>

</div>
