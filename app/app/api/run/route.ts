import type { NextRequest } from "next/server";
import { runAudit } from "@/lib/settle";
import { saveAudit } from "@/lib/store";
import type { AuditKind } from "@/lib/types";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";
export const maxDuration = 300;

export async function POST(req: NextRequest) {
  let body: { kind?: AuditKind; code?: string; target?: string; title?: string; authorized?: boolean };
  try {
    body = await req.json();
  } catch {
    return Response.json({ error: "Invalid JSON body" }, { status: 400 });
  }

  const kind: AuditKind = body.kind || "contract";

  if (kind === "contract") {
    const code = (body.code || "").trim();
    if (code.length < 20 || !/contract\s+\w+/.test(code)) {
      return Response.json({ error: "Provide valid Solidity source with a contract." }, { status: 400 });
    }
  } else {
    if (!body.target) return Response.json({ error: "Provide a target URL." }, { status: 400 });
    // Authorization gate — this is authorized testing tooling, not an attack tool.
    if (body.authorized !== true) {
      return Response.json(
        { error: "You must confirm you own or are authorized to test this target." },
        { status: 403 }
      );
    }
  }

  try {
    const result = await runAudit({ kind, code: body.code, target: body.target, title: body.title });
    await saveAudit(result);
    return Response.json(result);
  } catch (e: any) {
    return Response.json({ error: String(e?.message || e) }, { status: 500 });
  }
}
