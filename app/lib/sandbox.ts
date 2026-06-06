import { execFile } from "node:child_process";
import { promisify } from "node:util";
import { mkdir, writeFile, readdir, rm } from "node:fs/promises";
import path from "node:path";
import { SANDBOX_DIR, FORGE_BIN } from "./config";

const exec = promisify(execFile);

export interface SandboxResult {
  forgePassed: boolean; // true => the exploit reproduced the vulnerability
  durationMs: number;
  output: string;
}

/**
 * Proof-of-exploit sandbox. Drops the submitted contract as src/Target.sol and the
 * agent-generated PoC as test/Exploit.t.sol, then runs `forge test`. By convention the
 * PoC test PASSES only when the vulnerability actually reproduces, so forge's exit code
 * IS the verdict — deterministic, no model in the loop.
 *
 * Runs are sequential (one exploit file at a time) to avoid duplicate-contract clashes
 * in the shared project; each call clears the previous PoC first.
 */
export async function runExploit(targetSource: string, exploitSource: string): Promise<SandboxResult> {
  const srcDir = path.join(SANDBOX_DIR, "src");
  const testDir = path.join(SANDBOX_DIR, "test");
  await mkdir(srcDir, { recursive: true });
  await mkdir(testDir, { recursive: true });

  // Clear any prior PoC files so two agents' exploits never collide on contract names.
  for (const f of await readdir(testDir).catch(() => [])) {
    if (f.endsWith(".sol")) await rm(path.join(testDir, f)).catch(() => {});
  }

  await writeFile(path.join(srcDir, "Target.sol"), targetSource, "utf8");
  await writeFile(path.join(testDir, "Exploit.t.sol"), exploitSource, "utf8");

  const start = Date.now();
  let stdout = "";
  let stderr = "";
  let exitCode = 0;
  try {
    const res = await exec(FORGE_BIN, ["test", "--match-path", "test/Exploit.t.sol", "-vv"], {
      cwd: SANDBOX_DIR,
      timeout: 90_000,
      maxBuffer: 8 * 1024 * 1024,
      env: { ...process.env },
    });
    stdout = res.stdout;
    stderr = res.stderr;
  } catch (err: any) {
    // forge exits non-zero when the test fails OR fails to compile -> vulnerability NOT reproduced
    exitCode = typeof err.code === "number" ? err.code : 1;
    stdout = err.stdout || "";
    stderr = err.stderr || String(err.message || err);
  }

  const durationMs = Date.now() - start;
  const output = `${stdout}\n${stderr}`.trim();
  return {
    forgePassed: exitCode === 0,
    durationMs,
    output: output.slice(-4000),
  };
}
