# Plan usage seam

The dashboard has a **Claude Code → Plan limits** card that mirrors what
`/usage` shows: your 5-hour session window, your weekly all-models cap, and a
weekly cap per model (Fable, Opus, Sonnet). Everything for it is built and
tested — rendering, per-meter reset clocks, worst-meter-wins badge — except
the one function that reads your OAuth token and calls Anthropic.

That function is left for you to add deliberately. Writing it requires reading
your credential store and sending a `User-Agent` that identifies as Claude
Code, which is a pattern that is indistinguishable from credential theft when
read out of context. It is your token, your machine and your account, so it is
legitimate — but it should be your decision, made explicitly.

Until you add it, the card reports the gap honestly rather than showing a
blank or invented number.

## What the endpoint is

Undocumented. Anthropic can change or withdraw it without notice.

```
GET https://api.anthropic.com/api/oauth/usage
Authorization: Bearer <oauth access token>
anthropic-beta: oauth-2025-04-20
User-Agent: claude-code/<version>
Content-Type: application/json
```

Response:

```json
{
  "five_hour":        { "utilization": 9,  "resets_at": "2026-07-28T02:41:00Z" },
  "seven_day":        { "utilization": 12, "resets_at": "2026-07-29T11:00:00Z" },
  "seven_day_opus":   { "utilization": 8,  "resets_at": "..." },
  "seven_day_fable":  { "utilization": 4,  "resets_at": "..." },
  "extra_usage":      { "is_enabled": false, "monthly_limit": null, "used_credits": null, "utilization": null }
}
```

**Two constraints, both non-negotiable:**

1. **The `User-Agent` must look like `claude-code/<version>`.** Without it the
   endpoint returns 429 immediately and keeps doing so for that token.
2. **Poll no faster than once per 180 seconds**, per access token. The code
   below enforces this with a cache rather than trusting callers — polling
   faster gets the token throttled, which breaks Claude Code itself.

## Step 1 — mount the credential file (read-only)

In `server/.env`:

```
CLAUDE_CREDENTIALS_FILE=/creds/.credentials.json
CLAUDE_CREDENTIALS_HOST_FILE=C:/Users/you/.claude/.credentials.json
CLAUDE_CODE_USER_AGENT=claude-code/2.1.220
```

In `server/docker-compose.yml`, under `volumes:`:

```yaml
      - ${CLAUDE_CREDENTIALS_HOST_FILE:-./.no-creds}:/creds/.credentials.json:ro
```

## Step 2 — drop this into `server/server.mjs`

Paste immediately **above** the `const USAGE_SOURCES = {` line.

```js
const CLAUDE_CREDENTIALS_FILE = env.CLAUDE_CREDENTIALS_FILE || "";
const CLAUDE_CODE_UA = env.CLAUDE_CODE_USER_AGENT || "claude-code/2.1.220";
const PLAN_MIN_INTERVAL_MS = 180000;
let planCache = { at: 0, data: null };

// The credentials file shape is not contractual, so walk it for the first
// plausible access token instead of hard-coding a path into it.
function findAccessToken(node, depth = 0) {
  if (!node || typeof node !== "object" || depth > 6) return null;
  for (const [k, v] of Object.entries(node)) {
    if (typeof v === "string" && v.length > 20 && /access_?token/i.test(k)) return v;
  }
  for (const v of Object.values(node)) {
    if (v && typeof v === "object") {
      const f = findAccessToken(v, depth + 1);
      if (f) return f;
    }
  }
  return null;
}

const PLAN_LABELS = {
  five_hour: "Current session",
  seven_day: "Weekly · all models",
  seven_day_opus: "Weekly · Opus",
  seven_day_sonnet: "Weekly · Sonnet",
  seven_day_fable: "Weekly · Fable"
};

async function readClaudePlanUsage() {
  if (!CLAUDE_CREDENTIALS_FILE) {
    throw new Error("CLAUDE_CREDENTIALS_FILE is not set, so there is no OAuth token to read.");
  }
  // The 180s floor is a correctness requirement, not an optimisation.
  if (planCache.data && Date.now() - planCache.at < PLAN_MIN_INTERVAL_MS) {
    return { ...planCache.data, cached: true };
  }

  let token;
  try {
    token = findAccessToken(JSON.parse(await fsp.readFile(CLAUDE_CREDENTIALS_FILE, "utf8")));
  } catch (e) {
    throw new Error(`Could not read ${CLAUDE_CREDENTIALS_FILE}: ${e.message}`);
  }
  if (!token) throw new Error("No OAuth access token found. Sign in to Claude Code, then retry.");

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
    throw new Error("Claude rejected the stored token. Open Claude Code to re-authenticate.");
  }
  if (res.status === 429) {
    throw new Error("Rate limited (429). One call per 180s per token — check the User-Agent.");
  }
  if (res.status < 200 || res.status >= 300) {
    throw new Error(`Usage endpoint returned HTTP ${res.status}.`);
  }

  let raw;
  try { raw = JSON.parse(res.body.toString("utf8")); }
  catch { throw new Error("Usage endpoint returned a response that wasn't JSON."); }

  // Pick up ANY {utilization, resets_at} key rather than hard-coding the
  // window names, so a new per-model cap appears with no code change.
  const series = [];
  for (const [key, val] of Object.entries(raw)) {
    if (!val || typeof val !== "object") continue;
    const util = Number(val.utilization);
    if (!Number.isFinite(util)) continue;
    series.push({
      key,
      label: PLAN_LABELS[key] || ("Weekly · " + key.replace(/^seven_day_?/, "").replace(/_/g, " ")).trim(),
      used: Math.round(util * 10) / 10,
      totalLimit: 100,
      unit: "%",
      resetTime: val.resets_at || null
    });
  }
  if (!series.length) throw new Error("Usage endpoint returned no recognisable limit windows.");

  // Session first, then combined weekly, then per-model — matches /usage.
  const rank = k => (k === "five_hour" ? 0 : k === "seven_day" ? 1 : 2);
  series.sort((a, b) => rank(a.key) - rank(b.key) || a.key.localeCompare(b.key));

  const data = { generatedAt: new Date().toISOString(), series };
  planCache = { at: Date.now(), data };
  return data;
}
```

## Step 3 — register it

Change:

```js
const USAGE_SOURCES = {
  "claude-code": { needs: "CLAUDE_PROJECTS_DIR", run: readClaudeCodeUsage }
};
```

to:

```js
const USAGE_SOURCES = {
  "claude-code": { needs: "CLAUDE_PROJECTS_DIR", run: readClaudeCodeUsage },
  "claude-plan": { needs: "CLAUDE_CREDENTIALS_FILE", run: readClaudePlanUsage }
};
```

## Step 4 — restart and check

```
docker compose up -d --build
```

`GET /health` should now list `"usage": ["claude-code", "claude-plan"]`. Hit
Refresh on the **Claude plan limits** card and it fills with live windows.

Nothing else needs changing — the dashboard side is already written and
tested against this exact response shape.
