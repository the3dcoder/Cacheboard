// Cacheboard — optional backend companion.
//
// The dashboard works entirely without this. Everything here exists to do
// the three things a browser genuinely cannot:
//
//   1. Reach APIs that refuse browser calls   (OpenAI sends no CORS headers)
//   2. Hold a secret the browser must not see (any client_secret)
//   3. Keep a refresh token alive             (Fitbit expires in ~8 hours)
//
// Deliberately zero npm dependencies — Node's standard library covers all
// of it, so there is no lockfile, no supply chain, and no install step
// beyond having Node (or Docker) available.
//
// Run:  node server.mjs        (or: docker compose up -d)

import http from "node:http";
import https from "node:https";
import net from "node:net";
import tls from "node:tls";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

// A tiny .env reader. Avoids a dependency for what is ~10 lines, and keeps
// secrets out of the process list and out of git.
function loadEnvFile(file) {
  if (!fs.existsSync(file)) return {};
  const out = {};
  for (const raw of fs.readFileSync(file, "utf8").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const eq = line.indexOf("=");
    if (eq === -1) continue;
    const key = line.slice(0, eq).trim();
    let val = line.slice(eq + 1).trim();
    if ((val.startsWith('"') && val.endsWith('"')) || (val.startsWith("'") && val.endsWith("'"))) {
      val = val.slice(1, -1);
    }
    out[key] = val;
  }
  return out;
}

const env = { ...loadEnvFile(path.join(HERE, ".env")), ...process.env };

const PORT = Number(env.PORT || 8787);
const HOST = env.HOST || "0.0.0.0";
const DASHBOARD_TOKEN = env.DASHBOARD_TOKEN || "";
const STATIC_DIR = env.STATIC_DIR || "";       // set to serve index.html too
const STATE_FILE = env.STATE_FILE || path.join(HERE, "state.json");

// Exact-match origin allowlist. "*" is accepted but warned about loudly,
// because this process holds real API keys.
const ALLOWED_ORIGINS = String(env.ALLOWED_ORIGINS || "")
  .split(",").map(s => s.trim()).filter(Boolean);

// ---------------------------------------------------------------------------
// Providers
//
// `host` is the ONLY host this provider may reach — the path comes from the
// request but the host never does, so a caller can't aim the injected secret
// somewhere else. Adding a provider is one entry here.
// ---------------------------------------------------------------------------
const PROXY_PROVIDERS = {
  openai: {
    host: "api.openai.com",
    headers: () => env.OPENAI_API_KEY
      ? { authorization: `Bearer ${env.OPENAI_API_KEY}`,
          ...(env.OPENAI_ORG_ID ? { "openai-organization": env.OPENAI_ORG_ID } : {}) }
      : null,
    missing: "OPENAI_API_KEY is not set in the server's .env file."
  },
  // A deliberately open-ended slot: point it at any host that blocks browser
  // calls and supply the header it wants. No new server code required.
  custom: {
    host: env.CUSTOM_PROXY_HOST || "",
    headers: () => env.CUSTOM_PROXY_HEADER && env.CUSTOM_PROXY_VALUE
      ? { [env.CUSTOM_PROXY_HEADER.toLowerCase()]: env.CUSTOM_PROXY_VALUE }
      : {},
    missing: "CUSTOM_PROXY_HOST is not set in the server's .env file."
  }
};

// OAuth refresh-token grants. The refresh token lives here, never in the
// browser; the dashboard asks for a short-lived access token when it needs
// one. Providers that rotate refresh tokens (Fitbit does) get the new one
// persisted to STATE_FILE.
const OAUTH_PROVIDERS = {
  fitbit: {
    tokenUrl: "https://api.fitbit.com/oauth2/token",
    clientId: () => env.FITBIT_CLIENT_ID,
    clientSecret: () => env.FITBIT_CLIENT_SECRET || "",   // optional under PKCE
    seedRefreshToken: () => env.FITBIT_REFRESH_TOKEN
  },
  google: {
    tokenUrl: "https://oauth2.googleapis.com/token",
    clientId: () => env.GOOGLE_CLIENT_ID,
    clientSecret: () => env.GOOGLE_CLIENT_SECRET || "",
    seedRefreshToken: () => env.GOOGLE_REFRESH_TOKEN
  },
  spotify: {
    tokenUrl: "https://accounts.spotify.com/api/token",
    clientId: () => env.SPOTIFY_CLIENT_ID,
    clientSecret: () => env.SPOTIFY_CLIENT_SECRET || "",
    seedRefreshToken: () => env.SPOTIFY_REFRESH_TOKEN
  },
  strava: {
    tokenUrl: "https://www.strava.com/oauth/token",
    clientId: () => env.STRAVA_CLIENT_ID,
    clientSecret: () => env.STRAVA_CLIENT_SECRET || "",
    seedRefreshToken: () => env.STRAVA_REFRESH_TOKEN
  }
};

// ---------------------------------------------------------------------------
// Security self-assessment
//
// Scope: the operator's OWN hosts, listed in .env. Targets are never taken
// from the request — a caller picks a check by NAME and the server decides
// what runs and against what. That keeps this from becoming a scan-anything
// service, which is the failure mode a network tool exposed over HTTP has.
//
// Everything here is pure Node: a TCP connect, a TLS handshake, an HTTP GET.
// No nmap, no raw sockets, nothing privileged — so it runs in the stock
// container with no extra packages and no elevated capabilities.
// ---------------------------------------------------------------------------
const csv = v => String(v || "").split(",").map(s => s.trim()).filter(Boolean);

const SEC = {
  hosts: csv(env.SECURITY_HOSTS),           // "192.168.1.10, nas.local"
  tlsTargets: csv(env.SECURITY_TLS_HOSTS),  // "example.com, ha.local:8123"
  httpUrls: csv(env.SECURITY_HTTP_URLS),    // "http://nas.local, http://printer.local"
  ports: csv(env.SECURITY_PORTS).map(Number).filter(Number.isFinite)
};

// Scanned when SECURITY_PORTS isn't set. Chosen for a developer/IoT/3D-print
// /self-hosted-AI network rather than a generic top-1000.
const DEFAULT_PORTS = [
  21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
  1883,        // MQTT — IoT
  3000, 3306, 5000, 5432, 5900, 6379,   // dev servers, DBs, VNC
  7125,        // Moonraker (Klipper)
  8000, 8080, 8081, 8096, 8123, 8443,   // web UIs, Jellyfin, Home Assistant
  9000, 9090,  // Portainer, Prometheus
  11434,       // Ollama
  27017,       // MongoDB
  32400        // Plex
];

// Ports that are a finding purely by being open, with the reason. These are
// the ones that actually bite on a home lab: plaintext protocols, remote
// desktop, and databases or AI endpoints that ship with no auth by default.
const RISKY_PORTS = {
  21: "FTP — credentials sent in plaintext",
  23: "Telnet — credentials sent in plaintext",
  25: "SMTP — open relay risk if unauthenticated",
  445: "SMB — high-value target, should never face the internet",
  3306: "MySQL exposed on the network",
  5432: "PostgreSQL exposed on the network",
  5900: "VNC — often unauthenticated or weakly authenticated",
  6379: "Redis — no authentication by default",
  7125: "Moonraker/Klipper — full printer control, often unauthenticated",
  11434: "Ollama — no authentication by default; anyone can use your models",
  27017: "MongoDB — historically unauthenticated by default"
};

// Headers a service exposed on a LAN should still be setting.
const WANTED_HEADERS = [
  ["strict-transport-security", "HSTS not set"],
  ["content-security-policy", "No Content-Security-Policy"],
  ["x-content-type-options", "Missing X-Content-Type-Options: nosniff"],
  ["x-frame-options", "No X-Frame-Options (clickjacking)"],
  ["referrer-policy", "No Referrer-Policy"]
];

function splitHostPort(entry, defaultPort) {
  const idx = entry.lastIndexOf(":");
  // Guard against IPv6 literals and bare hostnames.
  if (idx > 0 && !entry.includes("]") && /^\d+$/.test(entry.slice(idx + 1))) {
    return { host: entry.slice(0, idx), port: Number(entry.slice(idx + 1)) };
  }
  return { host: entry, port: defaultPort };
}

// Bounded parallelism: a home lab switch does not enjoy 500 simultaneous
// connections, and neither does a cheap IoT device.
async function mapLimit(items, limit, fn) {
  const out = new Array(items.length);
  let cursor = 0;
  await Promise.all(Array.from({ length: Math.min(limit, items.length) }, async () => {
    while (cursor < items.length) {
      const i = cursor++;
      try { out[i] = await fn(items[i], i); }
      catch (e) { out[i] = { error: e.message }; }
    }
  }));
  return out;
}

function tcpProbe(host, port, timeout = 1500) {
  return new Promise(resolve => {
    const socket = new net.Socket();
    let settled = false;
    const done = open => { if (settled) return; settled = true; socket.destroy(); resolve(open); };
    socket.setTimeout(timeout);
    socket.once("connect", () => done(true));
    socket.once("timeout", () => done(false));
    socket.once("error", () => done(false));
    socket.connect(port, host);
  });
}

function tlsCertInfo(host, port, timeout = 6000) {
  return new Promise((resolve, reject) => {
    // rejectUnauthorized:false on purpose — a self-signed or expired cert is
    // exactly what we're trying to REPORT, not a reason to refuse to look.
    const socket = tls.connect({ host, port, servername: host, rejectUnauthorized: false, timeout }, () => {
      const cert = socket.getPeerCertificate();
      const authorized = socket.authorized;
      const reason = socket.authorizationError ? String(socket.authorizationError) : "";
      socket.end();
      if (!cert || !cert.valid_to) return reject(new Error("No certificate presented"));
      resolve({ validTo: cert.valid_to, issuer: (cert.issuer && cert.issuer.O) || "unknown", authorized, reason });
    });
    socket.setTimeout(timeout, () => { socket.destroy(); reject(new Error("TLS handshake timed out")); });
    socket.once("error", e => reject(e));
  });
}

const SECURITY_CHECKS = {
  // Days until the SOONEST expiry across every host. Higher is healthier.
  "tls-expiry": {
    needs: "SECURITY_TLS_HOSTS",
    async run() {
      if (!SEC.tlsTargets.length) throw new Error("SECURITY_TLS_HOSTS is not set in the server's .env file.");
      const results = await mapLimit(SEC.tlsTargets, 8, async entry => {
        const { host, port } = splitHostPort(entry, 443);
        try {
          const info = await tlsCertInfo(host, port);
          const days = Math.floor((Date.parse(info.validTo) - Date.now()) / 86400000);
          return { target: entry, days, issuer: info.issuer, trusted: info.authorized, note: info.reason };
        } catch (e) {
          return { target: entry, error: e.message };
        }
      });
      const ok = results.filter(r => Number.isFinite(r.days));
      if (!ok.length) throw new Error(`No certificate could be read. ${results.map(r => `${r.target}: ${r.error}`).join("; ")}`);
      const soonest = ok.reduce((a, b) => (a.days <= b.days ? a : b));
      const detail = results.map(r => r.error
        ? `${r.target}: unreachable (${r.error})`
        : `${r.target}: ${r.days}d${r.trusted ? "" : " · untrusted/self-signed"}`);
      return { value: soonest.days, unit: "days to soonest expiry", detail, worst: soonest.target };
    }
  },

  // How many ports changed since the saved baseline. Zero is healthy.
  // The first run establishes the baseline rather than reporting everything
  // as a change, which would be noise, not signal.
  "port-drift": {
    needs: "SECURITY_HOSTS",
    async run() {
      if (!SEC.hosts.length) throw new Error("SECURITY_HOSTS is not set in the server's .env file.");
      const ports = SEC.ports.length ? SEC.ports : DEFAULT_PORTS;
      const jobs = [];
      for (const host of SEC.hosts) for (const port of ports) jobs.push({ host, port });

      const probes = await mapLimit(jobs, 64, async j => ({ ...j, open: await tcpProbe(j.host, j.port) }));
      const open = probes.filter(p => p.open).map(p => `${p.host}:${p.port}`).sort();

      state.security = state.security || {};
      const baseline = state.security.portBaseline;
      const risky = probes.filter(p => p.open && RISKY_PORTS[p.port])
        .map(p => `${p.host}:${p.port} — ${RISKY_PORTS[p.port]}`);

      if (!Array.isArray(baseline)) {
        state.security.portBaseline = open;
        state.security.portBaselineAt = new Date().toISOString();
        await persistState();
        return {
          value: 0,
          unit: "changes since baseline",
          detail: [`Baseline saved: ${open.length} open port(s) across ${SEC.hosts.length} host(s).`, ...risky],
          baselineJustCreated: true
        };
      }

      const baseSet = new Set(baseline);
      const nowSet = new Set(open);
      // Only compare what THIS run actually probed. Without this, narrowing
      // SECURITY_PORTS or SECURITY_HOSTS would report every no-longer-scanned
      // port as "now closed" — an alert storm caused purely by a config edit.
      const scanned = new Set(jobs.map(j => `${j.host}:${j.port}`));
      const opened = open.filter(p => !baseSet.has(p));
      const closed = baseline.filter(p => scanned.has(p) && !nowSet.has(p));
      const detail = [];
      opened.forEach(p => detail.push(`NEW open: ${p}${RISKY_PORTS[Number(p.split(":")[1])] ? " — " + RISKY_PORTS[Number(p.split(":")[1])] : ""}`));
      closed.forEach(p => detail.push(`now closed: ${p}`));
      risky.forEach(r => detail.push(`risky: ${r}`));
      if (!detail.length) detail.push(`No change. ${open.length} open port(s) match the baseline.`);

      return { value: opened.length + closed.length, unit: "changes since baseline", detail, opened, closed };
    }
  },

  // Recommended headers missing across your own services. Zero is healthy.
  "http-headers": {
    needs: "SECURITY_HTTP_URLS",
    async run() {
      if (!SEC.httpUrls.length) throw new Error("SECURITY_HTTP_URLS is not set in the server's .env file.");
      const results = await mapLimit(SEC.httpUrls, 6, async raw => {
        let url;
        try { url = new URL(raw); } catch (e) { return { target: raw, error: "not a valid URL" }; }
        const mod = url.protocol === "https:" ? https : http;
        return await new Promise(resolve => {
          const req = mod.request({
            hostname: url.hostname,
            port: url.port || (url.protocol === "https:" ? 443 : 80),
            path: url.pathname + url.search,
            method: "GET",
            rejectUnauthorized: false,
            timeout: 5000
          }, res => {
            res.resume();
            const missing = WANTED_HEADERS.filter(([h]) => !res.headers[h]).map(([, label]) => label);
            resolve({ target: raw, status: res.statusCode, missing });
          });
          req.on("timeout", () => { req.destroy(); resolve({ target: raw, error: "timed out" }); });
          req.on("error", e => resolve({ target: raw, error: e.message }));
          req.end();
        });
      });

      let total = 0;
      const detail = results.map(r => {
        if (r.error) return `${r.target}: unreachable (${r.error})`;
        total += r.missing.length;
        return r.missing.length
          ? `${r.target} [${r.status}]: ${r.missing.join(", ")}`
          : `${r.target} [${r.status}]: all recommended headers present`;
      });
      return { value: total, unit: "missing headers", detail };
    }
  }
};

// Deliberately NOT implemented here, and why:
//
//   arp-scan / new-device detection  needs raw sockets + host networking
//                                    (Linux only; not available under Docker
//                                    Desktop on Windows)
//   nuclei                           needs the binary and a template corpus
//   Suricata / Zeek alerts           needs an IDS already running + log mounts
//   default-credential probes        needs per-device protocol handling
//
// To add one: install the tool in the Dockerfile, then add an entry to
// SECURITY_CHECKS whose run() shells out with FIXED arguments and targets
// read from .env. Never interpolate anything from the HTTP request into a
// command — the whole point of the name-based dispatch is that a caller
// cannot influence what executes.

// ---------------------------------------------------------------------------
// Rotating-token state
// ---------------------------------------------------------------------------
let state = { refreshTokens: {} };
try {
  if (fs.existsSync(STATE_FILE)) state = JSON.parse(fs.readFileSync(STATE_FILE, "utf8"));
} catch (e) {
  console.warn(`[warn] Could not read ${STATE_FILE}, starting fresh:`, e.message);
}
if (!state.refreshTokens || typeof state.refreshTokens !== "object") state.refreshTokens = {};

async function persistState() {
  try { await fsp.writeFile(STATE_FILE, JSON.stringify(state, null, 2), "utf8"); }
  catch (e) { console.warn("[warn] Could not persist state:", e.message); }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function corsHeaders(origin) {
  const allowAll = ALLOWED_ORIGINS.includes("*");
  const ok = allowAll || (origin && ALLOWED_ORIGINS.includes(origin));
  if (!ok) return null;
  return {
    "access-control-allow-origin": allowAll ? "*" : origin,
    "access-control-allow-headers": "authorization, content-type",
    "access-control-allow-methods": "GET, POST, PUT, PATCH, DELETE, OPTIONS",
    "access-control-max-age": "600",
    "vary": "origin"
  };
}

function send(res, status, body, headers = {}) {
  const payload = typeof body === "string" ? body : JSON.stringify(body);
  res.writeHead(status, {
    // charset matters: detail strings contain "·" and similar, and a client
    // that guesses latin-1 mangles them.
    "content-type": typeof body === "string" ? "text/plain; charset=utf-8" : "application/json; charset=utf-8",
    "cache-control": "no-store",
    ...headers
  });
  res.end(payload);
}

function authorized(req) {
  if (!DASHBOARD_TOKEN) return false;      // unset means "refuse everything"
  const header = req.headers["authorization"] || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  // Length-independent comparison is overkill on a LAN, but it costs nothing.
  if (token.length !== DASHBOARD_TOKEN.length) return false;
  let diff = 0;
  for (let i = 0; i < token.length; i++) diff |= token.charCodeAt(i) ^ DASHBOARD_TOKEN.charCodeAt(i);
  return diff === 0;
}

function readBody(req, limitBytes = 1024 * 1024) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let size = 0;
    req.on("data", c => {
      size += c.length;
      if (size > limitBytes) { reject(new Error("Request body too large")); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks)));
    req.on("error", reject);
  });
}

function httpsRequest(urlString, { method = "GET", headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const url = new URL(urlString);
    const req = https.request({
      hostname: url.hostname,
      port: url.port || 443,
      path: url.pathname + url.search,
      method,
      headers
    }, upstream => {
      const chunks = [];
      upstream.on("data", c => chunks.push(c));
      upstream.on("end", () => resolve({
        status: upstream.statusCode,
        headers: upstream.headers,
        body: Buffer.concat(chunks)
      }));
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

// ---------------------------------------------------------------------------
// Route: /proxy/<provider>/<path...>
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Local LLM usage: Claude Code transcripts
//
// Claude Code writes a JSONL transcript per session. Each assistant line
// carries `message.model` and `message.usage` — so real per-model token
// consumption is already on disk, for free. There is no API for this: Claude
// Code publishes usage over OpenTelemetry only, and the 5-hour / weekly caps
// aren't published anywhere at all. Consumption we can measure; the ceiling
// we cannot, which is why cards here compare against a target you set.
//
// PRIVACY: this parser reads three things per line — timestamp, model, and
// the numeric usage counters. Message content is never read into a variable,
// never aggregated, and never leaves the process. The endpoint returns
// integers only.
const USAGE_DIR = env.CLAUDE_PROJECTS_DIR || "";

// $ per million tokens. cache reads bill ~0.1x input, cache writes ~1.25x.
const MODEL_PRICES = {
  "claude-fable-5":   { in: 10, out: 50 },
  "claude-mythos-5":  { in: 10, out: 50 },
  "claude-opus-5":    { in: 5,  out: 25 },
  "claude-opus-4-8":  { in: 5,  out: 25 },
  "claude-opus-4-7":  { in: 5,  out: 25 },
  "claude-sonnet-5":  { in: 3,  out: 15 },
  "claude-sonnet-4-6":{ in: 3,  out: 15 },
  "claude-haiku-4-5": { in: 1,  out: 5  }
};

function priceFor(model) {
  if (MODEL_PRICES[model]) return MODEL_PRICES[model];
  // Unknown//future model: fall back by family so cost stays a useful
  // estimate instead of silently reading zero.
  if (/fable|mythos/.test(model)) return MODEL_PRICES["claude-fable-5"];
  if (/opus/.test(model))         return MODEL_PRICES["claude-opus-5"];
  if (/haiku/.test(model))        return MODEL_PRICES["claude-haiku-4-5"];
  if (/sonnet/.test(model))       return MODEL_PRICES["claude-sonnet-5"];
  return null;
}

function emptyBucket() {
  return { messages: 0, input: 0, output: 0, cacheRead: 0, cacheWrite: 0, cost: 0 };
}

function addUsage(bucket, u, model) {
  const inTok    = Number(u.input_tokens) || 0;
  const outTok   = Number(u.output_tokens) || 0;
  const cacheR   = Number(u.cache_read_input_tokens) || 0;
  const cacheW   = Number(u.cache_creation_input_tokens) || 0;
  bucket.messages += 1;
  bucket.input += inTok;
  bucket.output += outTok;
  bucket.cacheRead += cacheR;
  bucket.cacheWrite += cacheW;
  const p = priceFor(model);
  if (p) {
    bucket.cost += (inTok * p.in + cacheR * p.in * 0.1 + cacheW * p.in * 1.25 + outTok * p.out) / 1e6;
  }
}

// Re-parsing ~13 MB on every 30s refresh would be wasteful, so results are
// cached and only invalidated when a transcript's size or mtime changes.
let usageCache = { key: "", at: 0, data: null };

async function listTranscripts(dir) {
  const out = [];
  async function walk(d, depth) {
    if (depth > 6) return;
    let entries;
    try { entries = await fsp.readdir(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) await walk(full, depth + 1);
      else if (e.isFile() && e.name.endsWith(".jsonl")) out.push(full);
    }
  }
  await walk(dir, 0);
  return out;
}

// `tzOffsetMin` is the browser's Date#getTimezoneOffset() — minutes that UTC
// leads local time (240 for EDT). Without it the container computes "today" in
// UTC, so after ~8pm Eastern it rolls over early and reports a near-empty day.
// The viewer's clock is the only correct authority here, so the dashboard
// sends it and the server never guesses.
async function readClaudeCodeUsage(tzOffsetMin = 0) {
  if (!USAGE_DIR) {
    throw new Error("CLAUDE_PROJECTS_DIR is not set, so there are no local transcripts to read.");
  }
  const files = await listTranscripts(USAGE_DIR);
  if (!files.length) {
    throw new Error(`No .jsonl transcripts found under ${USAGE_DIR}. Check the mount path.`);
  }

  const stats = await Promise.all(files.map(async f => {
    try { const s = await fsp.stat(f); return `${f}:${s.size}:${s.mtimeMs}`; } catch { return f; }
  }));
  // Buckets depend on the offset, so it belongs in the cache key.
  const key = `${tzOffsetMin}|${stats.join("|")}`;
  if (usageCache.key === key && Date.now() - usageCache.at < 300000) return usageCache.data;

  const day = 86400000;
  const offsetMs = tzOffsetMin * 60000;
  // Shift into the viewer's local frame, floor to midnight, shift back.
  const startOfToday = Math.floor((Date.now() - offsetMs) / day) * day + offsetMs;
  const periods = {
    today: startOfToday,
    week:  startOfToday - 6 * day,
    month: startOfToday - 29 * day,
    all:   0
  };

  const totals = {};
  const byModel = {};
  for (const p of Object.keys(periods)) { totals[p] = emptyBucket(); byModel[p] = {}; }
  const sessions = new Set();
  let firstSeen = Infinity, lastSeen = 0, skipped = 0;

  for (const file of files) {
    let text;
    try { text = await fsp.readFile(file, "utf8"); } catch { continue; }
    for (const line of text.split("\n")) {
      // Cheap pre-filter: most lines are user turns with no usage at all.
      if (line.length < 40 || line.indexOf('"usage"') === -1) continue;
      let o;
      try { o = JSON.parse(line); } catch { skipped++; continue; }
      const u = o && o.message && o.message.usage;
      if (!u || typeof u !== "object") continue;
      const ts = o.timestamp ? Date.parse(o.timestamp) : NaN;
      if (!Number.isFinite(ts)) continue;
      const model = String((o.message && o.message.model) || "unknown");
      // Synthetic entries carry no real spend and would skew model counts.
      if (model === "<synthetic>") continue;

      if (ts < firstSeen) firstSeen = ts;
      if (ts > lastSeen) lastSeen = ts;
      if (o.sessionId) sessions.add(String(o.sessionId));

      for (const [name, from] of Object.entries(periods)) {
        if (ts < from) continue;
        addUsage(totals[name], u, model);
        if (!byModel[name][model]) byModel[name][model] = emptyBucket();
        addUsage(byModel[name][model], u, model);
      }
    }
  }

  const models = [...new Set(Object.values(byModel).flatMap(m => Object.keys(m)))].sort();
  const data = {
    generatedAt: new Date().toISOString(),
    tzOffsetMin,
    dayStartedAt: new Date(startOfToday).toISOString(),
    transcripts: files.length,
    // Older transcripts predate the sessionId field; one file is one session,
    // so fall back to the file count rather than reporting a bogus 0 or 1.
    sessions: Math.max(sessions.size, files.length),
    unparsableLines: skipped,
    firstActivity: Number.isFinite(firstSeen) ? new Date(firstSeen).toISOString() : null,
    lastActivity: lastSeen ? new Date(lastSeen).toISOString() : null,
    models,
    totals,
    byModel
  };
  usageCache = { key, at: Date.now(), data };
  return data;
}

// ---------------------------------------------------------------------------
// Subscription plan limits — the windows Claude Code's /usage shows.
//
// The local transcripts can tell you what you consumed, but not how much of
// your 5-hour and weekly caps that represents. The documented Usage & Cost
// Admin API doesn't cover it (API-key spend only, and unavailable to
// individual accounts). Claude Code reads it from an OAuth endpoint, using
// the token already on this machine, and so does this.
//
// UNDOCUMENTED. Anthropic can change or withdraw it without notice. When that
// happens the card reports the failure rather than showing a stale number.
//
// Two constraints, both enforced here rather than trusted to callers:
//   1. The User-Agent must identify as claude-code/<version>. Without it the
//      endpoint returns 429 immediately and keeps doing so for that token.
//   2. One call per 180s per token. Polling faster gets the token throttled,
//      which would break Claude Code itself.
//
// The token is read at request time, used for exactly one outbound call, and
// never logged, cached, or returned. Only integers reach the browser.
const CLAUDE_CREDENTIALS_FILE = env.CLAUDE_CREDENTIALS_FILE || "";
const CLAUDE_CODE_UA = env.CLAUDE_CODE_USER_AGENT || "claude-code/2.1.220";
const PLAN_MIN_INTERVAL_MS = 180000;

// Multiple Claude accounts.
//
// `claude setup-token` mints a long-lived token per account; put one per
// identity in .env as CLAUDE_TOKEN_<NAME>. The dashboard sends only the NAME
// — never a token — so a card can't be edited into exfiltrating a credential,
// and an unknown name is refused rather than silently falling back.
//
//   CLAUDE_TOKEN_PERSONAL=sk-ant-oat01-...
//   CLAUDE_TOKEN_WORK=sk-ant-oat01-...
function claudeTokenAccounts() {
  const names = new Set();
  for (const [k, v] of Object.entries(env)) {
    if (!String(v || "").trim()) continue;
    if (/^CLAUDE_TOKEN_.+/.test(k)) names.add(k.slice("CLAUDE_TOKEN_".length).toLowerCase());
    else if (/^CLAUDE_CREDENTIALS_FILE_.+/.test(k)) names.add(k.slice("CLAUDE_CREDENTIALS_FILE_".length).toLowerCase());
  }
  return [...names].sort();
}

const accountKey = a => String(a).toUpperCase().replace(/[^A-Z0-9_]/g, "_");

function claudeTokenFor(account) {
  const val = String(env["CLAUDE_TOKEN_" + accountKey(account)] || "").trim();
  return val || null;
}

// The better path for several subscriptions at once.
//
// Claude Code isolates its whole auth state per CLAUDE_CONFIG_DIR, so you can
// sign three Gmail accounts in simultaneously, each into its own profile
// directory, with no logging in and out. Point one of these at each profile's
// .credentials.json and every account stays live at the same time.
//
//   CLAUDE_CREDENTIALS_FILE_MAX20=/profiles/max20/.credentials.json
//
// Preferred over CLAUDE_TOKEN_* because it uses the same session token we
// know works against the usage endpoint, and it refreshes itself when the
// CLI renews — a pasted token eventually goes stale.
function claudeCredentialFileFor(account) {
  const val = String(env["CLAUDE_CREDENTIALS_FILE_" + accountKey(account)] || "").trim();
  return val || null;
}

// One cache slot per account — a 180s floor shared across accounts would
// starve every account but the first.
const planCaches = new Map();

// The credentials file shape is not contractual, so walk it for a plausible
// access token rather than hard-coding a path into it. Scored rather than
// first-match: a file can hold a refresh token, an id token and an access
// token side by side, and picking the wrong one fails confusingly later.
function collectTokenCandidates(node, path = "", depth = 0, out = []) {
  if (!node || typeof node !== "object" || depth > 8) return out;
  for (const [k, v] of Object.entries(node)) {
    const here = path ? `${path}.${k}` : k;
    if (typeof v === "string" && v.length >= 20) {
      let score = 0;
      if (/access_?token/i.test(k)) score += 100;
      else if (/^token$/i.test(k)) score += 60;
      else if (/token/i.test(k) && !/refresh|id_?token/i.test(k)) score += 40;
      // Anthropic OAuth tokens carry a recognisable prefix.
      if (/^sk-ant-oat/i.test(v)) score += 50;
      if (/refresh/i.test(k)) score -= 200;
      // This file also holds MCP plugin OAuth tokens (Linear, Canva, …).
      // Those authenticate nothing here, and sending one as the bearer would
      // fail confusingly — score them out rather than risk selecting one.
      if (/^mcpOAuth\b/i.test(here)) score -= 500;
      if (score > 0) out.push({ path: here, value: v, score });
    } else if (v && typeof v === "object") {
      collectTokenCandidates(v, here, depth + 1, out);
    }
  }
  return out;
}

function findAccessToken(parsed) {
  const found = collectTokenCandidates(parsed).sort((a, b) => b.score - a.score);
  return found.length ? found[0].value : null;
}

// Key names only — never values. Enough to diagnose a shape change without
// putting anything sensitive in an error message or a log.
function describeCredentialShape(node, path = "", depth = 0, out = []) {
  if (!node || typeof node !== "object" || depth > 3) return out;
  for (const [k, v] of Object.entries(node)) {
    const here = path ? `${path}.${k}` : k;
    if (v && typeof v === "object" && !Array.isArray(v)) describeCredentialShape(v, here, depth + 1, out);
    else out.push(`${here}:${Array.isArray(v) ? "array" : typeof v}`);
  }
  return out;
}

const PLAN_LABELS = {
  five_hour: "Current session",
  seven_day: "Weekly · all models",
  seven_day_opus: "Weekly · Opus",
  seven_day_sonnet: "Weekly · Sonnet",
  seven_day_fable: "Weekly · Fable"
};

async function readClaudePlanUsage(account = "") {
  const named = String(account || "").trim().toLowerCase();
  const cacheKey = named || "__default";
  const cached = planCaches.get(cacheKey);
  if (cached && Date.now() - cached.at < PLAN_MIN_INTERVAL_MS) {
    return { ...cached.data, cached: true, cacheAgeMs: Date.now() - cached.at };
  }

  let token = null;

  // A named account resolves ONLY to something configured on this server.
  if (named) {
    token = claudeTokenFor(named);

    // No pasted token? Try that account's own profile credentials file.
    if (!token) {
      const file = claudeCredentialFileFor(named);
      if (file) {
        try {
          token = findAccessToken(JSON.parse(await fsp.readFile(file, "utf8")));
        } catch (e) {
          throw new Error(`Could not read the credentials file for "${named}" (${file}): ${e.message}`);
        }
        if (!token) {
          throw new Error(
            `The profile for "${named}" has no Claude session token yet. ` +
            `Sign that profile in with: CLAUDE_CONFIG_DIR=<its folder> claude auth login`
          );
        }
      }
    }

    if (!token) {
      const known = claudeTokenAccounts();
      throw new Error(
        `No token configured for account "${named}". ` +
        (known.length ? `Known accounts: ${known.join(", ")}.` : "No CLAUDE_TOKEN_* entries are set in the server's .env.") +
        " Run `claude setup-token` for that account and add it as CLAUDE_TOKEN_" +
        named.toUpperCase().replace(/[^A-Z0-9_]/g, "_") + "."
      );
    }
  }

  // Unnamed falls back to the signed-in CLI's credential file, which is the
  // single-account case.
  if (!token) {
    if (!CLAUDE_CREDENTIALS_FILE) {
      const known = claudeTokenAccounts();
      throw new Error(
        known.length
          ? `This card has no account selected. Configured accounts: ${known.join(", ")}.`
          : "No Claude token available. Either set CLAUDE_TOKEN_<NAME> entries in .env, or sign in with `claude auth login`."
      );
    }
    let parsed;
    try {
      parsed = JSON.parse(await fsp.readFile(CLAUDE_CREDENTIALS_FILE, "utf8"));
      token = findAccessToken(parsed);
    } catch (e) {
      throw new Error(`Could not read ${CLAUDE_CREDENTIALS_FILE}: ${e.message}`);
    }
    if (!token) {
      // Report candidate PATHS and scores — never values — so a format change
      // is diagnosable instead of just "didn't work".
      const cands = collectTokenCandidates(parsed)
        .sort((a, b) => b.score - a.score).slice(0, 8)
        .map(c => `${c.path}(${c.score})`);
      throw new Error(
        "No Claude subscription OAuth token found. Candidates scored: " +
        (cands.length ? cands.join(", ") : "(none)") +
        ". This file may hold only MCP plugin tokens. Easiest fix: run " +
        "`claude setup-token` and add the result to .env as CLAUDE_TOKEN_<NAME>."
      );
    }
  }

  const res = await httpsRequest("https://api.anthropic.com/api/oauth/usage", {
    headers: {
      "Authorization": `Bearer ${token}`,
      "anthropic-beta": "oauth-2025-04-20",
      "User-Agent": CLAUDE_CODE_UA,
      "Content-Type": "application/json",
      "Accept": "application/json"
    }
  });

  if (res.status === 401 || res.status === 403) {
    throw new Error("Claude rejected the stored OAuth token. Open Claude Code to re-authenticate.");
  }
  if (res.status === 429) {
    throw new Error("Rate limited by the usage endpoint (429). One call per 180s per token — check the User-Agent.");
  }
  if (res.status < 200 || res.status >= 300) {
    throw new Error(`Usage endpoint returned HTTP ${res.status}.`);
  }

  let raw;
  try { raw = JSON.parse(res.body.toString("utf8")); }
  catch { throw new Error("Usage endpoint returned a response that wasn't JSON."); }

  // Pick up ANY {utilization, resets_at} key rather than hard-coding window
  // names, so a new per-model cap appears with no code change.
  const series = [];
  for (const [key, val] of Object.entries(raw)) {
    if (!val || typeof val !== "object") continue;
    // extra_usage carries a `utilization` too but is NOT a limit window — it
    // describes paid overage credits. Harvesting it by shape alone labelled
    // it "Weekly · extra usage" and drew it as a third cap, which is wrong.
    // It's reported separately under `extra`.
    if (key === "extra_usage") continue;
    const util = Number(val.utilization);
    if (!Number.isFinite(util)) continue;
    series.push({
      key,
      label: PLAN_LABELS[key] ||
        ("Weekly · " + key.replace(/^seven_day_?/, "").replace(/_/g, " ")).trim(),
      used: Math.round(util * 10) / 10,
      totalLimit: 100,
      unit: "%",
      resetTime: val.resets_at || null
    });
  }
  if (!series.length) {
    throw new Error("Usage endpoint returned no recognisable limit windows.");
  }

  // Session first, then combined weekly, then per-model — matches /usage.
  const rank = k => (k === "five_hour" ? 0 : k === "seven_day" ? 1 : 2);
  series.sort((a, b) => rank(a.key) - rank(b.key) || a.key.localeCompare(b.key));

  const extra = raw.extra_usage && typeof raw.extra_usage === "object" ? {
    enabled: !!raw.extra_usage.is_enabled,
    utilization: Number.isFinite(Number(raw.extra_usage.utilization)) ? Number(raw.extra_usage.utilization) : null
  } : null;

  const data = { generatedAt: new Date().toISOString(), account: named || null, series, extra, cached: false, cacheAgeMs: 0 };
  planCaches.set(cacheKey, { at: Date.now(), data });
  return data;
}

const USAGE_SOURCES = {
  "claude-code": { needs: "CLAUDE_PROJECTS_DIR", run: readClaudeCodeUsage },
  "claude-plan": { needs: "CLAUDE_CREDENTIALS_FILE", ready: () => claudeTokenAccounts().length > 0 || !!CLAUDE_CREDENTIALS_FILE, run: readClaudePlanUsage }
};

async function handleProxy(req, res, cors, segments, url) {
  const name = segments[1];
  const provider = PROXY_PROVIDERS[name];
  if (!provider) return send(res, 404, { error: `Unknown proxy provider "${name}".` }, cors);
  if (!provider.host) return send(res, 500, { error: provider.missing }, cors);

  const injected = provider.headers();
  if (injected === null) return send(res, 500, { error: provider.missing }, cors);

  const upstreamPath = "/" + segments.slice(2).join("/") + (url.search || "");
  const body = ["GET", "HEAD"].includes(req.method) ? null : await readBody(req);

  const headers = { host: provider.host, accept: "application/json", ...injected };
  if (body && req.headers["content-type"]) headers["content-type"] = req.headers["content-type"];

  let upstream;
  try {
    upstream = await httpsRequest(`https://${provider.host}${upstreamPath}`, { method: req.method, headers, body });
  } catch (e) {
    return send(res, 502, { error: `Upstream request failed: ${e.message}` }, cors);
  }

  res.writeHead(upstream.status, {
    "content-type": upstream.headers["content-type"] || "application/json",
    "cache-control": "no-store",
    ...cors
  });
  res.end(upstream.body);
}

// ---------------------------------------------------------------------------
// Route: POST /token/<provider>/refresh
// ---------------------------------------------------------------------------
async function handleTokenRefresh(req, res, cors, segments) {
  const name = segments[1];
  const provider = OAUTH_PROVIDERS[name];
  if (!provider) return send(res, 404, { error: `Unknown OAuth provider "${name}".` }, cors);

  const clientId = provider.clientId();
  if (!clientId) return send(res, 500, { error: `${name.toUpperCase()}_CLIENT_ID is not set in the server's .env file.` }, cors);

  const refreshToken = state.refreshTokens[name] || provider.seedRefreshToken();
  if (!refreshToken) {
    return send(res, 400, {
      error: `No refresh token for ${name}. Complete the OAuth flow once, then put the refresh token in the server's .env as ${name.toUpperCase()}_REFRESH_TOKEN.`
    }, cors);
  }

  const form = new URLSearchParams({ grant_type: "refresh_token", refresh_token: refreshToken, client_id: clientId });
  const headers = { "content-type": "application/x-www-form-urlencoded" };
  const secret = provider.clientSecret();
  if (secret) headers["authorization"] = "Basic " + Buffer.from(`${clientId}:${secret}`).toString("base64");

  let upstream;
  try {
    upstream = await httpsRequest(provider.tokenUrl, { method: "POST", headers, body: form.toString() });
  } catch (e) {
    return send(res, 502, { error: `Token endpoint unreachable: ${e.message}` }, cors);
  }

  let data;
  try { data = JSON.parse(upstream.body.toString("utf8")); }
  catch (e) { return send(res, 502, { error: "Token endpoint returned a non-JSON response." }, cors); }

  if (upstream.status >= 400 || !data.access_token) {
    const detail = data.error_description || data.error || `HTTP ${upstream.status}`;
    return send(res, upstream.status || 502, { error: `Refresh failed: ${detail}` }, cors);
  }

  // Fitbit (and others) hand back a NEW refresh token each time and
  // invalidate the old one — persisting it is what stops the chain breaking.
  if (data.refresh_token && data.refresh_token !== refreshToken) {
    state.refreshTokens[name] = data.refresh_token;
    await persistState();
  }

  // The refresh token is never returned to the browser.
  send(res, 200, { access_token: data.access_token, expires_in: data.expires_in || null }, cors);
}

// ---------------------------------------------------------------------------
// Optional static hosting
// ---------------------------------------------------------------------------
const MIME = {
  ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8",
  ".css": "text/css; charset=utf-8", ".json": "application/json",
  ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon",
  ".md": "text/markdown; charset=utf-8"
};

// Anything dot-prefixed anywhere in the path, plus a few known-sensitive
// names. This matters because STATIC_DIR is usually the whole project
// folder, which contains server/.env — serving that would hand out the
// bearer token and every API key.
const DENIED_PATH = /(^|[\\/])\.[^\\/]/;
const DENIED_NAMES = new Set(["state.json", "docker-compose.yml", "dockerfile", "server.mjs"]);

async function handleStatic(req, res, url) {
  if (!STATIC_DIR) return send(res, 404, { error: "Not found." });

  let rel;
  try { rel = decodeURIComponent(url.pathname); }
  catch (e) { return send(res, 400, { error: "Bad path." }); }

  const target = rel === "/" ? "/index.html" : rel;
  const base = path.resolve(STATIC_DIR);
  const resolved = path.resolve(base, "." + target);

  // Traversal guard: the resolved path must stay inside STATIC_DIR. The
  // separator check stops "/dashboard-secrets" matching "/dashboard".
  if (resolved !== base && !resolved.startsWith(base + path.sep)) {
    return send(res, 403, { error: "Forbidden." });
  }
  // Only serve recognised web assets, and never dotfiles or server internals.
  const ext = path.extname(resolved).toLowerCase();
  if (DENIED_PATH.test(target) || DENIED_NAMES.has(path.basename(resolved).toLowerCase()) || !MIME[ext]) {
    return send(res, 404, { error: "Not found." });
  }

  try {
    const buf = await fsp.readFile(resolved);
    res.writeHead(200, { "content-type": MIME[ext] });
    res.end(buf);
  } catch (e) {
    send(res, 404, { error: "Not found." });
  }
}

// ---------------------------------------------------------------------------
// Server
// ---------------------------------------------------------------------------
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host || "localhost"}`);
  const origin = req.headers.origin || "";
  const cors = corsHeaders(origin) || {};
  const segments = url.pathname.split("/").filter(Boolean);

  if (req.method === "OPTIONS") {
    if (!corsHeaders(origin)) return send(res, 403, { error: `Origin "${origin}" is not in ALLOWED_ORIGINS.` });
    res.writeHead(204, cors);
    return res.end();
  }

  if (url.pathname === "/health") {
    return send(res, 200, {
      ok: true,
      proxies: Object.keys(PROXY_PROVIDERS).filter(k => PROXY_PROVIDERS[k].host),
      oauth: Object.keys(OAUTH_PROVIDERS).filter(k => OAUTH_PROVIDERS[k].clientId()),
      // Only checks whose targets are actually configured are reported ready.
      security: Object.keys(SECURITY_CHECKS).filter(k => csv(env[SECURITY_CHECKS[k].needs]).length),
      usage: Object.keys(USAGE_SOURCES).filter(k => {
        const s = USAGE_SOURCES[k];
        return s.ready ? s.ready() : (env[s.needs] || "").trim();
      }),
      claudeAccounts: claudeTokenAccounts(),
      staticHosting: !!STATIC_DIR,
      authRequired: !!DASHBOARD_TOKEN
    }, cors);
  }

  const isApi = segments[0] === "proxy" || segments[0] === "token" ||
                segments[0] === "security" || segments[0] === "usage";
  if (isApi) {
    if (origin && !corsHeaders(origin)) {
      return send(res, 403, { error: `Origin "${origin}" is not in ALLOWED_ORIGINS.` });
    }
    if (!authorized(req)) {
      return send(res, 401, {
        error: DASHBOARD_TOKEN
          ? "Bad or missing bearer token."
          : "Server has no DASHBOARD_TOKEN set, so every request is refused. Set one in .env."
      }, cors);
    }
  }

  try {
    if (segments[0] === "proxy") return await handleProxy(req, res, cors, segments, url);
    if (segments[0] === "token" && segments[2] === "refresh" && req.method === "POST") {
      return await handleTokenRefresh(req, res, cors, segments);
    }
    if (segments[0] === "security") {
      const name = segments[1];
      const check = SECURITY_CHECKS[name];
      if (!check) {
        return send(res, 404, {
          error: `Unknown security check "${name}".`,
          available: Object.keys(SECURITY_CHECKS)
        }, cors);
      }
      const started = Date.now();
      const result = await check.run();
      return send(res, 200, { check: name, tookMs: Date.now() - started, ...result }, cors);
    }
    if (segments[0] === "usage") {
      const name = segments[1];
      const source = USAGE_SOURCES[name];
      if (!source) {
        return send(res, 404, {
          error: `Unknown usage source "${name}".`,
          available: Object.keys(USAGE_SOURCES)
        }, cors);
      }
      // Clamped to the real-world range so a bad value can't shift buckets wildly.
      const rawTz = Number(url.searchParams.get("tzOffsetMin"));
      const tz = Number.isFinite(rawTz) ? Math.max(-840, Math.min(840, Math.trunc(rawTz))) : 0;
      const started = Date.now();
      const account = (url.searchParams.get("account") || "").slice(0, 64);
      const result = await source.run(name === "claude-plan" ? account : tz);
      return send(res, 200, { source: name, tookMs: Date.now() - started, ...result }, cors);
    }
    return await handleStatic(req, res, url);
  } catch (e) {
    console.error("[error]", e);
    send(res, 500, { error: e.message || "Internal error." }, cors);
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Dashboard backend listening on http://${HOST}:${PORT}`);
  if (!DASHBOARD_TOKEN) console.warn("[warn] DASHBOARD_TOKEN is empty — /proxy and /token will refuse everything.");
  if (!ALLOWED_ORIGINS.length) console.warn("[warn] ALLOWED_ORIGINS is empty — browser calls will be blocked.");
  if (ALLOWED_ORIGINS.includes("*")) console.warn("[warn] ALLOWED_ORIGINS contains '*' — any site you visit can call this server.");
  if (STATIC_DIR) console.log(`Serving dashboard from ${STATIC_DIR}`);
});
