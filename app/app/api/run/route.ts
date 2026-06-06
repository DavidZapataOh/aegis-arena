import type { NextRequest } from "next/server";
import { runAudit } from "@/lib/settle";
import { saveAudit } from "@/lib/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 300;

export async function POST(req: NextRequest) {
  let body: { code?: string; title?: string };
  try {
    body = await req.json();
  } catch {
    return Response.json({ error: "Invalid JSON body" }, { status: 400 });
  }
  const code = (body.code || "").trim();
  if (code.length < 20 || !/contract\s+\w+/.test(code)) {
    return Response.json({ error: "Provide valid Solidity source with a contract." }, { status: 400 });
  }
  try {
    const result = await runAudit(code, body.title);
    await saveAudit(result);
    return Response.json(result);
  } catch (e: any) {
    return Response.json({ error: String(e?.message || e) }, { status: 500 });
  }
}
