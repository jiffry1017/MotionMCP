/**
 * Sign-in gate (jiffry1017 fork only; not part of upstream MotionMCP).
 *
 * Wraps the stock Worker in src/worker.ts with an OAuth browser sign-in.
 * Only someone who knows GATE_PASSCODE can finish signing in, so the Claude
 * "Motion Cloud" connector can live at the Team org level without letting
 * coworkers reach this Motion account.
 *
 * Kept outside src/ on purpose: upstream never touches this folder, and the
 * upstream tsconfig, CI and tests don't see it, so Sync fork stays clean.
 * The only upstream file changed is wrangler.toml (main, PUBLIC_ORIGIN, KV).
 *
 * The OAuth library is vendored in gate/vendor (MIT, @cloudflare/
 * workers-oauth-provider 1.2.3) so package.json and package-lock.json stay
 * identical to upstream.
 */
import OAuthProvider, { AuthorizationError, CimdFetchError } from "./vendor/workers-oauth-provider.js";
import type { OAuthHelpers, ConsentDescription } from "./vendor/workers-oauth-provider.js";
import worker from "../src/worker";

export interface Env {
  OAUTH_KV: KVNamespace;
  OAUTH_PROVIDER: OAuthHelpers;
  MOTION_API_KEY: string;     // used by src/worker.ts
  MOTION_MCP_SECRET: string;  // internal: the gate adds it so src/worker.ts accepts the request
  MOTION_MCP_TOOLS?: string;
  GATE_PASSCODE: string;      // what you type on the sign-in page
  PUBLIC_ORIGIN: string;      // e.g. https://motion-gatekeeper.jiffry1017.workers.dev
}

const USER_ID = "owner";
const MAX_FAILS = 5;            // wrong passcodes allowed per window
const FAIL_WINDOW_S = 15 * 60;  // window and lockout length

// ---------- handing signed-in requests to the stock Worker ----------

const mcpHandler = {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    if (!env.MOTION_MCP_SECRET) return new Response("Server misconfigured", { status: 500 });
    // The caller proved who they are with an OAuth token. Swap it for the
    // shared secret src/worker.ts expects, then let it handle the request.
    const headers = new Headers(request.headers);
    headers.set("Authorization", "Bearer " + env.MOTION_MCP_SECRET);
    const inner = new Request(request, { headers });
    return worker.fetch(inner, env as any, ctx);
  },
};

// ---------- sign-in page ----------

const esc = (v: string) => String(v).replace(/[&<>"']/g, (c) => `&#${c.charCodeAt(0)};`);

function page(details: ConsentDescription, handle: string, message = ""): string {
  const name = esc(details.clientName);
  const verified = details.clientDomain
    ? `Requested by <strong>${esc(details.clientDomain)}</strong>.`
    : `This app registered itself, so its name isn’t verified.`;
  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in to Motion Cloud</title>
<style>
:root{color-scheme:light dark;--bg:#f4f6f8;--card:#fff;--fg:#1c2430;--mute:#5b6775;--line:#d7dde4;--accent:#3d5a80;--err:#b3261e}
@media (prefers-color-scheme:dark){:root{--bg:#12161b;--card:#1b2129;--fg:#e6eaef;--mute:#9aa6b3;--line:#2d3640;--accent:#8fb0d8;--err:#f2b8b5}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,sans-serif;display:flex;min-height:100vh;align-items:center;justify-content:center;padding:24px 16px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:26px 24px;max-width:420px;width:100%}
h1{font-size:20px;margin:0 0 6px}p{margin:0 0 14px;color:var(--mute)}strong{color:var(--fg)}
label{display:block;font-weight:600;margin:16px 0 6px}
input[type=password]{width:100%;font:inherit;padding:10px 12px;border:1px solid var(--line);border-radius:8px;background:transparent;color:var(--fg)}
input:focus-visible,button:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.row{display:flex;gap:10px;margin-top:18px}
button{font:inherit;font-weight:600;padding:10px 16px;border-radius:8px;border:1px solid var(--line);background:transparent;color:var(--fg);cursor:pointer}
button.primary{background:var(--accent);border-color:var(--accent);color:var(--card);flex:1}
.err{color:var(--err);font-weight:600;margin-top:12px}
.warn{color:var(--err)}
</style></head><body><main class="card">
<h1>Sign in to Motion Cloud</h1>
<p><strong>${name}</strong> wants access to this Motion account. ${verified} Access will be sent to <strong>${esc(details.redirectHost)}</strong>.</p>
${details.redirectIsLoopback ? `<p class="warn">This sends access to an app on your computer. Continue only if you just started signing in from it.</p>` : ""}
<form method="post">
<input type="hidden" name="handle" value="${esc(handle)}">
<label for="passcode">Passcode</label>
<input id="passcode" name="passcode" type="password" autocomplete="current-password" required autofocus>
${message ? `<div class="err" role="alert">${esc(message)}</div>` : ""}
<div class="row"><button class="primary" name="decision" value="approve">Sign in</button><button name="decision" value="deny" formnovalidate>Cancel</button></div>
</form></main></body></html>`;
}

function textPage(status: number, message: string): Response {
  return new Response(message, { status, headers: { "Content-Type": "text/plain; charset=utf-8" } });
}

async function passcodeMatches(provided: string, expected: string): Promise<boolean> {
  if (!expected) return false;
  const enc = new TextEncoder();
  const [a, b] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(provided)),
    crypto.subtle.digest("SHA-256", enc.encode(expected)),
  ]);
  return crypto.subtle.timingSafeEqual(a, b);
}

// Lockout counts failures for everyone together, so guessing from many
// addresses doesn't help. Only you should ever be typing here.
async function failCount(env: Env): Promise<number> {
  return Number((await env.OAUTH_KV.get("gate:fails")) || "0");
}
async function recordFail(env: Env): Promise<number> {
  const n = (await failCount(env)) + 1;
  await env.OAUTH_KV.put("gate:fails", String(n), { expirationTtl: FAIL_WINDOW_S });
  return n;
}

async function authorize(request: Request, env: Env): Promise<Response> {
  const oauth = env.OAUTH_PROVIDER;
  try {
    if (request.method === "GET") {
      const authReq = await oauth.parseAuthRequest(request);
      const details = await oauth.describeConsent(authReq);
      const consent = await oauth.beginConsent(authReq);
      consent.headers.set("Content-Type", "text/html; charset=utf-8");
      return new Response(page(details, consent.handle), { headers: consent.headers });
    }
    if (request.method !== "POST") return textPage(405, "Method not allowed");

    const form = await request.formData();
    const handle = String(form.get("handle") || "");
    if (form.get("decision") !== "approve") {
      const denied = await oauth.denyConsent(request, handle);
      return new Response(null, { status: 302, headers: denied.headers });
    }
    if ((await failCount(env)) >= MAX_FAILS) {
      return textPage(429, "Too many wrong passcodes. Sign-in is locked for 15 minutes. Start again from Claude after that.");
    }
    if (!(await passcodeMatches(String(form.get("passcode") || ""), env.GATE_PASSCODE))) {
      const n = await recordFail(env);
      console.log("gate_wrong_passcode", n);
      if (n >= MAX_FAILS) return textPage(429, "Wrong passcode. Sign-in is now locked for 15 minutes. Start again from Claude after that.");
      // Show the same page again. The form posts back to the original
      // /authorize URL, so its query string still holds the request.
      const again = await oauth.parseAuthRequest(new Request(request.url, { method: "GET" }));
      const details = await oauth.describeConsent(again);
      const left = MAX_FAILS - n;
      return new Response(page(details, handle, `Wrong passcode. ${left} ${left === 1 ? "try" : "tries"} left before sign-in locks for 15 minutes.`), {
        status: 401,
        headers: { "Content-Type": "text/html; charset=utf-8", "X-Frame-Options": "DENY", "Content-Security-Policy": "frame-ancestors 'none'", "Cache-Control": "no-store" },
      });
    }
    const approved = await oauth.approveConsent(request, handle);
    const { redirectTo } = await oauth.completeAuthorization({
      request: approved.request,
      userId: USER_ID,
      metadata: { label: "Motion Cloud owner" },
      scope: approved.request.scope,
      props: { userId: USER_ID },
    });
    approved.headers.set("Location", redirectTo);
    return new Response(null, { status: 302, headers: approved.headers });
  } catch (error) {
    if (error instanceof AuthorizationError && error.redirectTo) return Response.redirect(error.redirectTo, 302);
    if (error instanceof AuthorizationError) return textPage(400, error.description || "This sign-in link is no longer valid. Start again from Claude.");
    if (error instanceof CimdFetchError) return textPage(400, "This app could not be verified.");
    throw error;
  }
}

const defaultHandler = {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    if (url.pathname === "/authorize") return authorize(request, env);
    // Health check and anything else: the stock Worker answers (it 404s
    // whatever lacks the internal secret).
    return worker.fetch(request, env as any, ctx);
  },
};

// The provider needs absolute URLs for its metadata, which come from the
// Worker's own address, so it's built once per isolate from PUBLIC_ORIGIN.
let provider: OAuthProvider<Env> | null = null;
function getProvider(env: Env): OAuthProvider<Env> {
  if (provider) return provider;
  const origin = env.PUBLIC_ORIGIN.replace(/\/+$/, "");
  provider = new OAuthProvider<Env>({
    apiRoute: "/mcp",
    apiHandler: mcpHandler as any,
    defaultHandler: defaultHandler as any,
    authorizeEndpoint: "/authorize",
    tokenEndpoint: "/oauth/token",
    clientRegistrationEndpoint: "/oauth/register",
    // Client ID Metadata Documents would need the global_fetch_strictly_public
    // compatibility flag (another upstream line to change); Claude falls back
    // to dynamic registration, which needs nothing extra.
    scopesSupported: ["mcp", "offline_access"],
    resourceMetadata: { resource: origin + "/mcp", authorization_servers: [origin] },
    accessTokenTTL: 60 * 60,               // 1 hour, refreshed automatically
    refreshTokenIdleTTL: 90 * 24 * 60 * 60, // stays signed in while used; expires after 90 idle days
  });
  return provider;
}

export default {
  fetch(request: Request, env: Env, ctx: ExecutionContext) {
    return getProvider(env).fetch(request, env, ctx);
  },
};
