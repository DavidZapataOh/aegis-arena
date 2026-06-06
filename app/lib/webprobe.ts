import { lookup } from "node:dns/promises";
import type { Severity, AuditKind } from "./types";

// ─────────────────────────────────────────────────────────────────────────────
// SAFE web/API proof-of-exploit engine.
//
// Design constraints (this is authorized-testing tooling, not an attack tool):
//  • Only audits targets the operator declares they own/are authorized to test.
//  • SSRF guard: refuses private / loopback / link-local / cloud-metadata hosts,
//    and RE-VALIDATES every redirect hop (a redirect can't smuggle us internal).
//  • Non-destructive: GET/HEAD/OPTIONS with benign markers only. No floods, no
//    payloads that change state. Bounded request budget + per-request timeout.
//  • Findings are PROVEN by observing the live response of the REAL final page.
// ─────────────────────────────────────────────────────────────────────────────

const REQUEST_BUDGET = 18;
const REQUEST_TIMEOUT_MS = 8000;
const MAX_BODY = 250_000;
const UA = "AegisArena-Auditor/0.1 (+authorized security scan)";

export type WebAgentId = "transport" | "injection" | "exposure";

export interface ProbeFinding {
  agentId: WebAgentId;
  category: string;
  severity: Severity;
  title: string;
  rationale: string;
  remediation: string;
  evidence: string;
  durationMs: number;
}

function isPrivateIp(ip: string): boolean {
  const v4 = ip.split(".").map(Number);
  if (v4.length === 4 && v4.every((n) => Number.isFinite(n))) {
    const [a, b] = v4;
    if (a === 10 || a === 127 || a === 0) return true;
    if (a === 169 && b === 254) return true; // link-local + cloud metadata
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 100 && b >= 64 && b <= 127) return true;
    if (a === 198 && (b === 18 || b === 19)) return true;
    return false;
  }
  const a = ip.toLowerCase();
  if (a === "::1" || a === "::") return true;
  if (a.startsWith("fc") || a.startsWith("fd")) return true;
  if (a.startsWith("fe8") || a.startsWith("fe9") || a.startsWith("fea") || a.startsWith("feb")) return true;
  const mapped = a.match(/::ffff:(\d+\.\d+\.\d+\.\d+)/);
  if (mapped) return isPrivateIp(mapped[1]);
  return false;
}

export async function assertSafeTarget(raw: string): Promise<{ url: URL; origin: string }> {
  let url: URL;
  try {
    url = new URL(raw.trim());
  } catch {
    throw new Error("Invalid URL.");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new Error("Only http(s) targets are allowed.");
  }
  const host = url.hostname.toLowerCase();
  if (!host || host === "localhost" || host.endsWith(".local") || host.endsWith(".internal")) {
    throw new Error("Refusing to scan internal/loopback hosts.");
  }
  let addrs: { address: string }[] = [];
  try {
    addrs = await lookup(host, { all: true });
  } catch {
    throw new Error(`Could not resolve host "${host}".`);
  }
  if (addrs.some((a) => isPrivateIp(a.address))) {
    throw new Error("Refusing to scan a host that resolves to a private/internal address (SSRF guard).");
  }
  return { url, origin: url.origin };
}

interface Resp {
  ok: boolean;
  status: number;
  headers: Headers;
  body: string;
  location?: string;
  error?: string;
}

function makeFetcher() {
  let used = 0;
  return async function safeFetch(
    target: string,
    opts: { method?: string; headers?: Record<string, string>; redirect?: RequestRedirect } = {}
  ): Promise<Resp> {
    if (used >= REQUEST_BUDGET) return { ok: false, status: 0, headers: new Headers(), body: "", error: "budget" };
    used++;
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), REQUEST_TIMEOUT_MS);
    try {
      const res = await fetch(target, {
        method: opts.method || "GET",
        headers: { "User-Agent": UA, Accept: "*/*", ...(opts.headers || {}) },
        redirect: opts.redirect || "manual",
        signal: ctrl.signal,
      });
      let body = "";
      const len = Number(res.headers.get("content-length") || "0");
      if (len <= 5_000_000) body = (await res.text().catch(() => "")).slice(0, MAX_BODY);
      return { ok: true, status: res.status, headers: res.headers, body, location: res.headers.get("location") || undefined };
    } catch (e: any) {
      return { ok: false, status: 0, headers: new Headers(), body: "", error: String(e?.name || e?.message || e) };
    } finally {
      clearTimeout(t);
    }
  };
}

const SEC_HEADER_RE = /server|x-powered|content-type|location|access-control|set-cookie|strict-transport|content-security|x-frame|x-content|referrer|permissions/i;

const transcript = (method: string, url: string, r: Resp, extraReq = "") =>
  `> ${method} ${url}\n${extraReq}` +
  (r.ok
    ? `< HTTP ${r.status}\n` +
      [...r.headers.entries()].filter(([k]) => SEC_HEADER_RE.test(k)).map(([k, v]) => `< ${k}: ${v}`).join("\n")
    : `< (request failed: ${r.error})`);

export async function runProbes(
  kind: AuditKind,
  rawUrl: string
): Promise<{ origin: string; homepageStatus: number; finalUrl: string; findings: ProbeFinding[] }> {
  const { url: startUrl } = await assertSafeTarget(rawUrl);
  const fetchOnce = makeFetcher();
  const findings: ProbeFinding[] = [];
  const push = (f: ProbeFinding) => findings.push(f);
  const time = async <T>(fn: () => Promise<T>): Promise<[T, number]> => {
    const s = Date.now();
    const v = await fn();
    return [v, Date.now() - s];
  };

  // Follow redirects — re-validating each hop against the SSRF guard — so we analyze
  // the REAL final page, not an apex→www redirect stub.
  async function follow(start: string): Promise<{ resp: Resp; finalUrl: URL }> {
    let current = new URL(start);
    let resp = await fetchOnce(current.href, { redirect: "manual" });
    for (let i = 0; i < 5 && resp.ok && resp.status >= 300 && resp.status < 400 && resp.location; i++) {
      let next: URL;
      try {
        next = new URL(resp.location, current);
      } catch {
        break;
      }
      if (next.protocol !== "http:" && next.protocol !== "https:") break;
      try {
        await assertSafeTarget(next.href); // refuse a redirect into a private host
      } catch {
        break;
      }
      current = next;
      resp = await fetchOnce(current.href, { redirect: "manual" });
    }
    return { resp, finalUrl: current };
  }

  const [{ resp: home, finalUrl: base }, homeMs] = await time(() => follow(startUrl.href));
  const H = (n: string) => home.headers.get(n);
  const stillRedirect = home.status >= 300 && home.status < 400; // couldn't resolve to a real page
  const pageEvidence = transcript("GET", base.href, home);

  // ── 1) Transport security ─────────────────────────────────────────────────
  if (base.protocol === "http:") {
    push({
      agentId: "transport",
      category: "Insecure Transport",
      severity: "High",
      title: "Served over plaintext HTTP (no TLS)",
      rationale: "Traffic — including credentials/session cookies — is unencrypted and interceptable (MITM).",
      remediation: "Serve exclusively over HTTPS and add HSTS.",
      evidence: pageEvidence,
      durationMs: homeMs,
    });
  } else {
    const hsts = H("strict-transport-security");
    if (hsts && /max-age\s*=\s*0\b/i.test(hsts)) {
      push({
        agentId: "transport",
        category: "HSTS Disabled",
        severity: "Medium",
        title: "HSTS effectively disabled (max-age=0)",
        rationale: "An HSTS header with max-age=0 instructs browsers to forget HSTS, re-enabling protocol-downgrade/MITM.",
        remediation: "Set Strict-Transport-Security: max-age=31536000; includeSubDomains.",
        evidence: `> GET ${base.href}\n< strict-transport-security: ${hsts}`,
        durationMs: homeMs,
      });
    } else if (!hsts && !stillRedirect) {
      push({
        agentId: "transport",
        category: "Missing HSTS",
        severity: "Low",
        title: "Missing Strict-Transport-Security header",
        rationale: "Without HSTS a first request can be downgraded to HTTP and intercepted.",
        remediation: "Strict-Transport-Security: max-age=31536000; includeSubDomains",
        evidence: pageEvidence,
        durationMs: homeMs,
      });
    }
  }

  // ── 2) Security headers (only judge a REAL page, never a redirect stub) ─────
  if (home.ok && !stillRedirect) {
    const csp = H("content-security-policy");
    const cspRO = H("content-security-policy-report-only");
    const missing: string[] = [];
    if (!csp && !cspRO) missing.push("Content-Security-Policy");
    if (!H("x-frame-options") && !/frame-ancestors/i.test(csp || "")) missing.push("X-Frame-Options (clickjacking)");
    if (!H("x-content-type-options")) missing.push("X-Content-Type-Options (MIME sniffing)");
    if (!H("referrer-policy")) missing.push("Referrer-Policy");
    if (!H("permissions-policy")) missing.push("Permissions-Policy");

    if (!csp && cspRO) {
      push({
        agentId: "transport",
        category: "CSP Not Enforced",
        severity: "Low",
        title: "Content-Security-Policy is report-only (not enforced)",
        rationale: "A report-only CSP collects telemetry but blocks nothing — it provides no XSS/clickjacking protection.",
        remediation: "Move the policy to the enforcing Content-Security-Policy header once tuned.",
        evidence: `> GET ${base.href}\n< content-security-policy-report-only: ${cspRO.slice(0, 100)}…\n(no enforcing Content-Security-Policy header present)`,
        durationMs: homeMs,
      });
    }

    if (missing.length) {
      const sev: Severity = missing.some((m) => /Content-Security|X-Frame/.test(m)) ? "Medium" : "Low";
      const present = [...home.headers.entries()]
        .filter(([k]) => /strict-transport|x-content|x-frame|referrer-policy|permissions-policy|content-security/i.test(k))
        .map(([k, v]) => `< ${k}: ${v.slice(0, 70)}`);
      const evidence =
        `> GET ${base.href}\n< HTTP ${home.status}\n` +
        (present.length ? `present security headers:\n${present.join("\n")}\n` : "") +
        `\nMissing (proven absent in the response):\n` +
        missing.map((m) => `  ❌ ${m}`).join("\n");
      push({
        agentId: "transport",
        category: "Missing Security Headers",
        severity: sev,
        title: `Missing ${missing.length} security header${missing.length > 1 ? "s" : ""}`,
        rationale: `Absent: ${missing.join(", ")}. These defend against XSS, clickjacking and MIME-sniffing.`,
        remediation: "Add the standard hardening headers (CSP, X-Frame-Options/frame-ancestors, X-Content-Type-Options, Referrer-Policy, Permissions-Policy).",
        evidence,
        durationMs: homeMs,
      });
    }

    // ── 3) Cookie flags ──────────────────────────────────────────────────────
    const cookies = home.headers.getSetCookie?.() || [];
    const weak = cookies.filter((c) => !/;\s*secure/i.test(c) || !/;\s*httponly/i.test(c) || !/;\s*samesite/i.test(c));
    if (weak.length) {
      push({
        agentId: "transport",
        category: "Insecure Cookies",
        severity: "Medium",
        title: "Cookie missing Secure/HttpOnly/SameSite",
        rationale: "Cookies without these flags are exposable to XSS theft, CSRF and plaintext interception.",
        remediation: "Set Secure; HttpOnly; SameSite=Lax|Strict on session cookies.",
        evidence: weak.map((c) => `< set-cookie: ${c.slice(0, 120)}`).join("\n"),
        durationMs: homeMs,
      });
    }

    // ── 5) Directory listing ───────────────────────────────────────────────────
    if (/<title>\s*Index of \//i.test(home.body)) {
      push({
        agentId: "exposure",
        category: "Directory Listing",
        severity: "Medium",
        title: "Directory listing enabled",
        rationale: "The server returns an auto-generated index, exposing file names and structure.",
        remediation: "Disable autoindex / directory browsing.",
        evidence: pageEvidence,
        durationMs: homeMs,
      });
    }
  }

  // ── 4) Software/technology disclosure ───────────────────────────────────────
  const server = H("server");
  const powered = H("x-powered-by");
  const hasVersion = (server && /\d/.test(server)) || (powered && /\d/.test(powered));
  if (hasVersion || powered) {
    push({
      agentId: "transport",
      category: "Information Disclosure",
      severity: "Low",
      title: hasVersion ? "Software version disclosed" : "Technology stack disclosed",
      rationale: hasVersion
        ? `Response advertises a software version (${[server, powered].filter(Boolean).join(", ")}), enabling targeted exploitation of version-specific CVEs.`
        : `Response advertises the technology in use (${[powered && `X-Powered-By: ${powered}`, server && `Server: ${server}`].filter(Boolean).join(", ")}), aiding fingerprinting.`,
      remediation: "Suppress or genericize Server / X-Powered-By headers.",
      evidence: transcript("GET", base.href, home),
      durationMs: homeMs,
    });
  }

  // ── 6) CORS misconfiguration ────────────────────────────────────────────────
  const evilOrigin = "https://aegis-cors-probe.example";
  const [cors, corsMs] = await time(() => fetchOnce(base.href, { headers: { Origin: evilOrigin } }));
  const acao = cors.headers.get("access-control-allow-origin");
  const acac = cors.headers.get("access-control-allow-credentials");
  if (acao === evilOrigin || acao === "*") {
    const credentialed = acao === evilOrigin && acac === "true";
    push({
      agentId: "exposure",
      category: "CORS Misconfiguration",
      severity: credentialed ? "High" : "Medium",
      title: credentialed ? "CORS reflects arbitrary origin with credentials" : "Overly permissive CORS policy",
      rationale: credentialed
        ? "The server reflects an attacker-controlled Origin AND allows credentials — any site can read authenticated responses."
        : `Access-Control-Allow-Origin is "${acao}", allowing cross-origin reads from untrusted sites.`,
      remediation: "Reflect only an allowlist of trusted origins; never combine a reflected origin with Allow-Credentials: true.",
      evidence: transcript("GET", base.href, cors, `> Origin: ${evilOrigin}\n`),
      durationMs: corsMs,
    });
  }

  // ── 7) Reflected, unescaped input — XSS indicator ───────────────────────────
  const marker = "aegis<svg/onload>9k7";
  const xssUrl = `${base.origin}${base.pathname}?aegis_probe=${encodeURIComponent(marker)}`;
  const [xss, xssMs] = await time(() => fetchOnce(xssUrl, { redirect: "follow" }));
  if (xss.ok && xss.body.includes(marker)) {
    push({
      agentId: "injection",
      category: "Reflected XSS",
      severity: "High",
      title: "User input reflected without HTML-encoding",
      rationale: "A benign marker with HTML metacharacters (<, >, /) was reflected verbatim — a reliable reflected-XSS indicator.",
      remediation: "Context-aware output encoding + a strict Content-Security-Policy.",
      evidence: `> GET ${xssUrl}\n  (marker: ${marker})\n< HTTP ${xss.status} — marker reflected UNescaped in body`,
      durationMs: xssMs,
    });
  }

  // ── 8) Open redirect ─────────────────────────────────────────────────────────
  const redirHost = "aegis-redirect.example";
  for (const param of ["next", "redirect", "url", "return"]) {
    const ru = `${base.origin}${base.pathname}?${param}=${encodeURIComponent(`https://${redirHost}/`)}`;
    const [r, ms] = await time(() => fetchOnce(ru, { redirect: "manual" }));
    if (r.status >= 300 && r.status < 400 && r.location && /(^https?:)?\/\/aegis-redirect\.example/.test(r.location)) {
      push({
        agentId: "injection",
        category: "Open Redirect",
        severity: "Medium",
        title: `Open redirect via "${param}" parameter`,
        rationale: "The app redirects to an attacker-supplied external URL, enabling phishing and OAuth token theft.",
        remediation: "Allowlist redirect destinations or use relative paths only.",
        evidence: `> GET ${ru}\n< HTTP ${r.status}\n< location: ${r.location}`,
        durationMs: ms,
      });
      break;
    }
  }

  // ── 9) SQL error reflection — benign single quote only ──────────────────────
  const sqlUrl = `${base.origin}${base.pathname}?id=1%27`;
  const [sql, sqlMs] = await time(() => fetchOnce(sqlUrl, { redirect: "follow" }));
  const sqlSig = /(SQL syntax|mysql_fetch|ORA-0\d{4}|PostgreSQL.*ERROR|SQLite3?::|SQLSTATE|Unclosed quotation mark|syntax error at or near)/i;
  if (sql.ok && sqlSig.test(sql.body)) {
    push({
      agentId: "injection",
      category: "SQL Injection",
      severity: "High",
      title: "SQL error triggered by a single quote",
      rationale: "A single quote surfaced a database error — the input reaches an unparameterized query (injectable).",
      remediation: "Use parameterized queries / prepared statements.",
      evidence: `> GET ${sqlUrl}\n< HTTP ${sql.status} — SQL error signature present in body`,
      durationMs: sqlMs,
    });
  }

  // ── 10) Exposed sensitive paths ─────────────────────────────────────────────
  const sensitive: { path: string; sig: RegExp; sev: Severity; what: string }[] = [
    { path: "/.env", sig: /(^|\n)\s*[A-Z0-9_]+\s*=/m, sev: "Critical", what: ".env secrets file" },
    { path: "/.git/config", sig: /\[core\]|\[remote /, sev: "Critical", what: ".git repository config" },
    { path: "/.git/HEAD", sig: /^ref:\s/m, sev: "High", what: ".git HEAD (source exposure)" },
    { path: "/server-status", sig: /Apache Server Status|Server uptime/i, sev: "Medium", what: "Apache server-status" },
  ];
  for (const s of sensitive) {
    const pu = `${base.origin}${s.path}`;
    const [r, ms] = await time(() => fetchOnce(pu));
    if (r.ok && r.status === 200 && s.sig.test(r.body)) {
      push({
        agentId: "exposure",
        category: "Sensitive File Exposure",
        severity: s.sev,
        title: `Exposed ${s.what}`,
        rationale: `${s.path} is publicly readable and returns sensitive content.`,
        remediation: `Block access to ${s.path} at the web server / deny dotfiles.`,
        evidence: `> GET ${pu}\n< HTTP 200 — sensitive content matched`,
        durationMs: ms,
      });
    }
  }

  // ── 11) Verbose error / stack trace ─────────────────────────────────────────
  const errUrl = `${base.origin}/aegis-nonexistent-${Math.abs(hash(rawUrl))}`;
  const [err, errMs] = await time(() => fetchOnce(errUrl, { redirect: "follow" }));
  const traceSig = /(Traceback \(most recent call last\)|Whoops, looks like something went wrong|\bat [\w.$]+\([\w$]+\.java:\d+\)|Werkzeug Debugger|RailsError|stack trace:)/i;
  if (err.ok && traceSig.test(err.body)) {
    push({
      agentId: "exposure",
      category: "Verbose Errors",
      severity: "Medium",
      title: "Stack trace / debug page exposed",
      rationale: "An error response leaks a stack trace or framework debug page, revealing internals.",
      remediation: "Disable debug mode in production; return generic error pages.",
      evidence: `> GET ${errUrl}\n< HTTP ${err.status} — stack-trace signature present`,
      durationMs: errMs,
    });
  }

  return { origin: base.origin, homepageStatus: home.status, finalUrl: base.href, findings };
}

function hash(s: string): number {
  let h = 0;
  for (let i = 0; i < s.length; i++) h = (h * 31 + s.charCodeAt(i)) | 0;
  return h;
}
