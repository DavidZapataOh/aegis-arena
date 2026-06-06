import { mkdir, readFile, writeFile } from "node:fs/promises";
import path from "node:path";
import type { AuditResult } from "./types";

const DATA_DIR = path.resolve(process.cwd(), ".data");
const FILE = path.join(DATA_DIR, "audits.json");

async function readAll(): Promise<AuditResult[]> {
  try {
    return JSON.parse(await readFile(FILE, "utf8"));
  } catch {
    return [];
  }
}

export async function saveAudit(result: AuditResult): Promise<void> {
  await mkdir(DATA_DIR, { recursive: true });
  const all = await readAll();
  const idx = all.findIndex((a) => a.id === result.id);
  if (idx >= 0) all[idx] = result;
  else all.unshift(result);
  await writeFile(FILE, JSON.stringify(all.slice(0, 100), null, 2), "utf8");
}

export async function listAudits(): Promise<AuditResult[]> {
  return readAll();
}
