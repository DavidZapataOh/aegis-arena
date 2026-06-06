// Central runtime config. Everything is optional so the app runs out-of-the-box in
// "local" mode (real AI + real Foundry sandbox, simulated chain). Set the on-chain vars
// to settle findings for real on Monad testnet.

import path from "node:path";

export const MONAD_TESTNET = {
  id: 10143,
  name: "Monad Testnet",
  rpcUrl: process.env.MONAD_TESTNET_RPC || "https://testnet-rpc.monad.xyz",
  explorer: "https://explorer.testnet.monad.xyz",
  symbol: "MON",
};

// Path to the Foundry sandbox project (sibling of /app). Override with SANDBOX_DIR.
export const SANDBOX_DIR =
  process.env.SANDBOX_DIR || path.resolve(process.cwd(), "..", "sandbox");

export const FORGE_BIN = process.env.FORGE_BIN || "forge";

// AI orchestration
export const ANTHROPIC_API_KEY = process.env.ANTHROPIC_API_KEY || "";
export const AGENT_MODEL = process.env.AGENT_MODEL || "claude-opus-4-8";
export const AGENT_EFFORT = (process.env.AGENT_EFFORT || "medium") as
  | "low"
  | "medium"
  | "high"
  | "max";
// When no API key is present we fall back to a deterministic demo so the flow always runs.
export const DEMO_MODE = !ANTHROPIC_API_KEY || process.env.DEMO_MODE === "true";

// On-chain settlement (optional). When unset, settlement is simulated locally.
export const AUDIT_ARENA_ADDRESS = (process.env.AUDIT_ARENA_ADDRESS || "") as `0x${string}` | "";
export const VERIFIER_PRIVATE_KEY = (process.env.VERIFIER_PRIVATE_KEY || "") as `0x${string}` | "";
export const ONCHAIN = Boolean(AUDIT_ARENA_ADDRESS && VERIFIER_PRIVATE_KEY);

// Default bounty (in MON) the relayer escrows per audit in on-chain mode.
export const DEFAULT_BOUNTY_MON = process.env.DEFAULT_BOUNTY_MON || "0.05";
