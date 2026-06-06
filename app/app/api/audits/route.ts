import { listAudits } from "@/lib/store";

export const runtime = "nodejs";
export const dynamic = "force-dynamic";

export async function GET() {
  const audits = await listAudits();
  // Strip heavy fields for the list view.
  const lite = audits.map((a) => ({
    id: a.id,
    title: a.title,
    score: a.score,
    secured: a.secured,
    createdAt: a.createdAt,
    onchain: a.onchain,
    findings: a.findings.length,
    confirmed: a.findings.filter((f) => f.status === "confirmed").length,
  }));
  return Response.json(lite);
}
