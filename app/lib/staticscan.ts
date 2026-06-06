import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import path from "node:path";
import type { StaticFinding } from "./types";

const exec = promisify(execFile);

// Slither lives wherever pipx/pip put it (often ~/.local/bin), which may not be on the
// server's PATH — point at it explicitly via SLITHER_BIN.
const SLITHER_BIN = process.env.SLITHER_BIN || "slither";

export interface StaticScan {
  available: boolean;
  tool: string;
  findings: StaticFinding[];
  error?: string;
}

/**
 * Ground the contract agents with Slither (Trail of Bits, 90+ detectors).
 *
 * Slither needs a solc. Rather than depend on a standalone solc/solc-select, we drop
 * the contract into a minimal throwaway Foundry project so crytic-compile compiles it
 * via `forge` (which resolves solc through svm) — the same toolchain the sandbox uses.
 *
 * Best-effort: if Slither/forge aren't available it returns available=false and the
 * agents proceed without the static layer. These findings are LEADS — every real one
 * still has to be proven by a PoC.
 */
export async function runSlither(source: string): Promise<StaticScan> {
  let dir: string | undefined;
  try {
    dir = await mkdtemp(path.join(tmpdir(), "aegis-slither-"));
    await mkdir(path.join(dir, "src"), { recursive: true });
    // Minimal project: no solc pin, so forge auto-selects a compiler matching the pragma.
    await writeFile(path.join(dir, "foundry.toml"), "[profile.default]\nsrc = 'src'\nout = 'out'\nlibs = []\n", "utf8");
    await writeFile(path.join(dir, "src", "Target.sol"), source, "utf8");

    let stdout = "";
    try {
      const res = await exec(SLITHER_BIN, [".", "--json", "-"], {
        cwd: dir,
        timeout: 120_000,
        maxBuffer: 32 * 1024 * 1024,
        env: process.env,
      });
      stdout = res.stdout;
    } catch (e: any) {
      // Slither exits non-zero when it finds issues — the JSON is still on stdout.
      stdout = e?.stdout || "";
      if (!stdout) return { available: false, tool: "slither", findings: [], error: trim(e?.stderr || e?.message) };
    }

    const parsed = JSON.parse(stdout);
    if (!parsed?.results) {
      return { available: false, tool: "slither", findings: [], error: trim(parsed?.error) };
    }
    const dets: any[] = parsed?.results?.detectors || [];
    const findings: StaticFinding[] = dets
      .filter((d) => ["High", "Medium", "Low"].includes(d.impact))
      .map((d) => ({
        check: String(d.check || "unknown"),
        impact: String(d.impact || "Low"),
        confidence: String(d.confidence || "Medium"),
        description: trim(d.description, 400),
      }));
    return { available: true, tool: "slither", findings };
  } catch (e: any) {
    return { available: false, tool: "slither", findings: [], error: trim(e?.message) };
  } finally {
    if (dir) await rm(dir, { recursive: true, force: true }).catch(() => {});
  }
}

function trim(s: any, n = 300): string {
  return String(s || "").replace(/\s+/g, " ").trim().slice(0, n);
}
