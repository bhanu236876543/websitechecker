import { NextRequest, NextResponse } from "next/server";
import dns from "node:dns/promises";
import { isIP } from "node:net";
import type { Analysis, Finding } from "../../report";

export const runtime = "nodejs";
const RATE_LIMIT_WINDOW_MS = 60_000;
const RATE_LIMIT_MAX_REQUESTS = 12;
const requestWindows = new Map<string, { count: number; startedAt: number }>();

const privateHost = (host: string) => host === "localhost" || host.endsWith(".localhost") || host.endsWith(".local") || host.endsWith(".internal") || host === "metadata.google.internal";
function privateIp(ip: string) {
  const normalized = ip.toLowerCase();
  const p = normalized.split(".").map(Number);
  return normalized === "::" || normalized === "::1" || normalized.startsWith("fc") || normalized.startsWith("fd") || normalized.startsWith("fe80") || normalized.startsWith("::ffff:127.") || normalized.startsWith("::ffff:10.") || normalized.startsWith("::ffff:192.168.") || (p.length === 4 && (p[0] === 10 || p[0] === 127 || p[0] === 0 || (p[0] === 169 && p[1] === 254) || (p[0] === 192 && p[1] === 168) || (p[0] === 172 && p[1] >= 16 && p[1] <= 31)));
}
async function assertPublicUrl(url: URL, field: string) {
  if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || privateHost(url.hostname)) throw new Error(`${field} must be a public HTTP(S) URL.`);
  const addresses = isIP(url.hostname) ? [{ address: url.hostname }] : await dns.lookup(url.hostname, { all: true, verbatim: true });
  if (!addresses.length || addresses.some(({ address }) => privateIp(address))) throw new Error(`${field} must not point to a private or internal address.`);
}
async function safeUrl(value: unknown, field: string) {
  if (!value) return undefined;
  if (typeof value !== "string") throw new Error(`${field} must be a URL.`);
  let url: URL;
  try { url = new URL(value); } catch { throw new Error(`${field} is not a valid URL.`); }
  await assertPublicUrl(url, field);
  return url;
}
function allowRequest(request: NextRequest) {
  const client = request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "anonymous";
  const now = Date.now();
  const current = requestWindows.get(client);
  if (!current || now - current.startedAt >= RATE_LIMIT_WINDOW_MS) {
    requestWindows.set(client, { count: 1, startedAt: now });
    return true;
  }
  current.count += 1;
  return current.count <= RATE_LIMIT_MAX_REQUESTS;
}
async function fetchPublicUrl(initialUrl: URL) {
  let url = initialUrl;
  for (let redirects = 0; redirects <= 5; redirects += 1) {
    await assertPublicUrl(url, "Redirect destination");
    const response = await fetch(url, { redirect: "manual", signal: AbortSignal.timeout(9000), headers: { "User-Agent": "WebsiteChecker/0.1 (safe security assessment)" } });
    if (![301, 302, 303, 307, 308].includes(response.status)) return { response, finalUrl: url };
    const location = response.headers.get("location");
    if (!location) return { response, finalUrl: url };
    url = new URL(location, url);
  }
  throw new Error("Website redirected too many times.");
}
function finding(severity: Finding["severity"], title: string, description: string, evidence: string, remediation: string, source: string): Finding { return { severity, title, description, evidence, remediation, source, confidence: "High" }; }
function score(findings: Finding[]) { const weights = { CRITICAL: 25, HIGH: 15, MEDIUM: 8, LOW: 3, INFO: 0 }; return Math.max(0, 100 - findings.reduce((n, f) => n + weights[f.severity], 0)); }
const demoAnalysis = (): Analysis => ({ demo: true, score: 82, status: "Needs Improvement", websiteUrl: "https://example-project.dev", githubUrl: "https://github.com/example/project", generatedAt: new Date().toISOString(), checks: ["HTTPS is enabled", "HTTP requests redirect to HTTPS", "HttpOnly cookies were observed", "No obvious committed secrets detected"], project: { name: "Example Project", overview: "A modern web application with a public frontend and API-driven backend.", stack: ["Next.js", "TypeScript", "PostgreSQL", "Docker"], architecture: ["Frontend", "API", "Database", "External services"], importantFiles: [{ path: "app/page.tsx", purpose: "Main application interface" }, { path: "package.json", purpose: "Dependencies and build scripts" }] }, findings: [finding("HIGH", "Missing Content-Security-Policy", "A Content Security Policy helps reduce the impact of client-side injection.", "Content-Security-Policy header was not detected.", "Add a restrictive Content-Security-Policy response header.", "Website"), finding("MEDIUM", "Referrer policy is not set", "Browsers may send more URL information than necessary to other sites.", "Referrer-Policy header was not detected.", "Set Referrer-Policy: strict-origin-when-cross-origin.", "Website"), finding("LOW", "Server technology is disclosed", "Version or platform disclosure can help attackers tailor reconnaissance.", "Server header was publicly visible.", "Remove or minimize unnecessary server-identifying headers.", "Website")] });
async function scanWebsite(url: URL, findings: Finding[], checks: string[]) { const { response, finalUrl } = await fetchPublicUrl(url); const h = response.headers; if (finalUrl.protocol === "https:") checks.push("HTTPS is enabled"); else findings.push(finding("HIGH", "Website is not using HTTPS", "Unencrypted connections can expose traffic in transit.", `Final URL uses ${finalUrl.protocol}.`, "Serve the site over HTTPS and redirect HTTP traffic.", "Website")); const headers: [string, string, Finding["severity"], string][] = [["content-security-policy", "Content-Security-Policy", "HIGH", "Add a restrictive Content-Security-Policy response header."], ["strict-transport-security", "Strict-Transport-Security", "MEDIUM", "Enable HSTS after confirming HTTPS is fully deployed."], ["x-content-type-options", "X-Content-Type-Options", "LOW", "Set X-Content-Type-Options: nosniff."], ["x-frame-options", "X-Frame-Options", "MEDIUM", "Set X-Frame-Options: DENY or use CSP frame-ancestors."], ["referrer-policy", "Referrer-Policy", "LOW", "Set a privacy-preserving Referrer-Policy."], ["permissions-policy", "Permissions-Policy", "LOW", "Set a Permissions-Policy appropriate for the application."]]; for (const [key, label, severity, fix] of headers) h.get(key) ? checks.push(`${label} header is present`) : findings.push(finding(severity, `Missing ${label}`, `${label} provides an important browser security control.`, `${label} header was not detected on the final response.`, fix, "Website")); const cookies = h.getSetCookie?.() || []; if (cookies.length) { if (cookies.some(c => !/;\s*Secure/i.test(c))) findings.push(finding("MEDIUM", "Cookie missing Secure attribute", "Cookies without Secure can be sent over insecure connections.", "At least one response cookie did not show the Secure attribute.", "Mark HTTPS cookies Secure, HttpOnly, and with an appropriate SameSite value.", "Website")); else checks.push("Secure cookies were observed"); } if (h.get("server")) findings.push(finding("LOW", "Server technology is disclosed", "Public server identifiers can assist targeted reconnaissance.", "A Server response header was present.", "Remove or minimize unnecessary server-identifying headers.", "Website")); if (!response.ok) findings.push(finding("INFO", "Non-success HTTP response", "The submitted page did not return a successful status.", `Final response status: ${response.status}.`, "Review the public endpoint and redirect configuration.", "Website")); }
async function scanGithub(url: URL, findings: Finding[], project: Analysis["project"]) { if (url.hostname !== "github.com") throw new Error("GitHub URL must use github.com."); const [owner, repo] = url.pathname.split("/").filter(Boolean); if (!owner || !repo) throw new Error("Enter a GitHub repository URL in the form github.com/owner/repository."); const api = `https://api.github.com/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo.replace(/\.git$/, ""))}`; const res = await fetch(api, { headers: { Accept: "application/vnd.github+json", "User-Agent": "WebsiteChecker" }, signal: AbortSignal.timeout(9000) }); if (!res.ok) throw new Error(res.status === 404 ? "Public GitHub repository not found." : res.status === 403 ? "GitHub's public request limit was reached. Try again shortly." : "GitHub could not be inspected right now."); const data = await res.json() as { name: string; description?: string; language?: string; topics?: string[]; default_branch: string }; project.name = data.name; project.overview = data.description || "A public GitHub repository."; project.stack = [data.language, ...(data.topics || [])].filter(Boolean) as string[]; project.architecture = ["Repository", "Application code", "Configuration"]; const tree = await fetch(`${api}/git/trees/${encodeURIComponent(data.default_branch)}?recursive=1`, { headers: { Accept: "application/vnd.github+json", "User-Agent": "WebsiteChecker" }, signal: AbortSignal.timeout(9000) }); if (tree.ok) { const files = ((await tree.json()) as { tree?: { path: string; type: string }[] }).tree || []; const names = files.filter(f => f.type === "blob").map(f => f.path); const important = names.filter(n => /^(package\.json|README\.md|Dockerfile|docker-compose|prisma\/schema|src\/.*\.(ts|js)|app\/.*\.(ts|tsx))$/i.test(n)).slice(0, 6); project.importantFiles = important.map(path => ({ path, purpose: path === "package.json" ? "Dependencies and application scripts" : /readme/i.test(path) ? "Project documentation" : /docker/i.test(path) ? "Container configuration" : "Application source or configuration" })); if (names.some(n => /(^|\/)\.env($|\.)/i.test(n))) findings.push(finding("HIGH", "Environment file committed", "Environment files often contain secrets or deployment configuration.", "A filename matching .env was found in the public repository. Values were not read.", "Remove it from version control, rotate any exposed values, and use secret management.", "Repository")); } }
export async function POST(request: NextRequest) { if (!allowRequest(request)) return NextResponse.json({ error: "Too many requests. Please wait a minute and try again." }, { status: 429 }); try { const input = await request.json() as { websiteUrl?: string; githubUrl?: string; demo?: boolean }; if (input.demo) return NextResponse.json(demoAnalysis()); if (!input.websiteUrl && !input.githubUrl) return NextResponse.json({ error: "Enter a website URL, a GitHub URL, or choose demo mode." }, { status: 400 }); const website = await safeUrl(input.websiteUrl, "Website URL"); const github = await safeUrl(input.githubUrl, "GitHub URL"); const findings: Finding[] = [], checks: string[] = []; const project: Analysis["project"] = { name: website?.hostname || "Untitled project", overview: "Public project analyzed through safe, automated checks.", stack: [], architecture: ["Public website"], importantFiles: [] }; if (website) await scanWebsite(website, findings, checks); if (github) await scanGithub(github, findings, project); const finalScore = score(findings); return NextResponse.json({ demo: false, score: finalScore, status: finalScore >= 90 ? "Strong posture" : finalScore >= 75 ? "Needs Improvement" : "Action recommended", websiteUrl: website?.toString(), githubUrl: github?.toString(), project, checks, findings, generatedAt: new Date().toISOString() } satisfies Analysis); } catch (e) { return NextResponse.json({ error: e instanceof Error ? e.message : "Analysis failed." }, { status: 400 }); } }
