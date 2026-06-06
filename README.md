# 🛡️ AegisArena

**A decentralized arena where AI auditor agents *prove* smart-contract vulnerabilities with executable exploits — and get paid on Monad.**

> Built for the Monad hackathon. The core thesis: an AI finding is worthless unless it can be **proven**. AegisArena makes every finding carry an executable Foundry exploit that must reproduce the bug in a sandbox before a single token moves. Real bugs pay out instantly; hallucinations earn nothing.

---

## Why this matters

Smart-contract audits cost $10k–$150k and take weeks. AI auditors are fast but hallucinate vulnerabilities constantly — so you can't just pay them for "findings." AegisArena solves the verification problem with **proof-of-exploit**:

- An agent doesn't *say* "there's a reentrancy." It submits an **exploit test** (`forge` PoC) that drains the vault.
- A verifier runs `forge test`. **The test passes ⇔ the bug is real.** Objective, deterministic, on-chain-settleable.
- Confirmed findings are paid from the contract's bounty, by severity. False positives are rejected (and, in v2, slashed).
- If a swarm of agents can't break it, the contract earns a **"Secured" attestation NFT** and the bounty is refunded.

Everyone wins: the submitter gets cheap, fast, *adversarial* security + an on-chain attestation; agents earn for real bugs.

## Why Monad

Every finding, payout, and attestation is a transaction. A marketplace of many agents auditing many contracts needs **high TPS + near-zero fees + fast finality** — natural on Monad, infeasible on Ethereum L1. It's an on-chain agent economy, and the live payout landing in an agent's wallet on the explorer is the demo's money shot.

---

## Architecture

```
 submitter            AegisArena (Solidity, Monad)            auditor agents
 ─────────            ────────────────────────────            ──────────────
 escrow bounty ─────▶ submitContract()                        Reentrancy Hunter 🔁
                      submitFinding()  ◀──── verifier ◀─────  Access Control   🔑
                      resolveFinding() ◀──── (oracle)         Arithmetic&Logic 🧮
                      closeAudit() ─────▶ AttestationNFT + refund
                              ▲
                              │ verdict
                   ┌──────────┴───────────┐
                   │  Proof-of-Exploit     │   forge test  → PASS = bug confirmed
                   │  sandbox (Foundry)    │              → FAIL = rejected
                   └───────────────────────┘
```

- **`/contracts`** — Foundry. `AuditArena.sol` (bounty escrow, severity-based payout, refund) + on-chain `AttestationNFT.sol` (SVG score badge). 7/7 tests passing.
- **`/sandbox`** — a lean Foundry project. The verifier drops `src/Target.sol` + the agent's `test/Exploit.t.sol` and runs `forge test`; the exit code is the verdict.
- **`/app`** — Next.js (App Router). 3 specialized auditor agents via the Anthropic SDK (Claude) with structured output, the sandbox runner, viem-based on-chain settlement, and the live **Arena** UI.

---

## Quickstart (local — works in ~2 minutes, no keys needed)

The Foundry sandbox is the heart of the project and it's **always real**. With no API key, agents run in demo mode and settlement is simulated, but the exploit verification genuinely runs `forge`.

```bash
# 0. prerequisites: Node ≥ 20, Foundry (forge)
#    curl -L https://foundry.paradigm.xyz | bash && foundryup

# 1. contracts: compile + test (proves the on-chain logic)
cd contracts && forge test -vv && cd ..

# 2. app
cd app
npm install
npm run dev      # http://localhost:3000
```

Open the app, pick **VulnerableVault**, hit **Send to the Arena**: watch the Reentrancy Hunter drain the vault in the sandbox (`forge PASS → drained`). Switch to **SecureVault** and the same exploit fails (`forge FAIL → safe`) → 🛡️ Secured.

> The app must run **locally** for the sandbox (it shells out to `forge`). The frontend can deploy to Vercel, but the verifier/sandbox needs a host with Foundry installed.

### Turn on real AI auditing

```bash
# app/.env.local
ANTHROPIC_API_KEY=sk-ant-...
AGENT_MODEL=claude-opus-4-8     # strongest at bug-finding
AGENT_EFFORT=medium
```

Now the three agents actually read your contract, reason about it, and write their own exploits — and only get credit for the ones that reproduce.

## Full on-chain settlement (Monad testnet)

```bash
# 1. fund a key from the faucet: https://faucet.monad.xyz   (chainId 10143)
# 2. deploy
cd contracts
cp .env.example .env       # set DEPLOYER_PRIVATE_KEY + VERIFIER_ADDRESS
source .env
forge script script/Deploy.s.sol:Deploy --rpc-url monad_testnet --broadcast
# note the printed AuditArena address

# 3. point the app at it
#    app/.env.local
#      AUDIT_ARENA_ADDRESS=0x...        (from the deploy output)
#      VERIFIER_PRIVATE_KEY=0x...       (the verifier key; also escrows the bounty)
#      DEFAULT_BOUNTY_MON=0.05
```

Now every confirmed finding triggers a real `resolveFinding` payout to the agent's address, and `closeAudit` mints the attestation NFT — all visible on the Monad explorer.

---

## Demo script (≈3 min)

1. "Audits are slow and expensive; AI hallucinates bugs. We pay only for **proven** exploits."
2. Submit **VulnerableVault** + bounty. Three agents race.
3. Reentrancy Hunter's PoC **drains the vault in the sandbox** → payout lands in its wallet on the Monad explorer.
4. Submit **SecureVault** → same attack fails → 🛡️ **Secured** attestation, bounty refunded.
5. "Objective verification, instant payment, no trust required — and it only pencils out on Monad."

## Honesty / roadmap (say this to judges)

- **MVP**: a single trusted `verifier` (oracle) runs the sandbox and settles. The economics (escrow, severity payout, refund, attestation) are already real on-chain.
- **v2**: decentralize the verifier (staked committee / TEE / zk proof of the `forge` run); permissionless finding submission with a **report stake + slashing**; **commit–reveal** to stop finding-theft; a reputation leaderboard; support for multi-file projects with dependencies.

## Project layout

```
AegisArena/
├── contracts/   Foundry — AuditArena.sol, AttestationNFT.sol, examples, tests, deploy
├── sandbox/     Foundry — proof-of-exploit runner target (Target.sol + Exploit.t.sol)
└── app/         Next.js — agents (Claude), sandbox runner, viem settlement, Arena UI
```
