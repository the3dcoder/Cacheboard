# Cacheboard — Status & Outstanding Work

> **See also [ROADMAP.md](ROADMAP.md)** — post-audit milestone plan (3 principal-level
> audits, 2026-07-27) covering bugs found, security hardening, and the Home Assistant
> control-surface direction. **All eight milestones are complete.**

**Security self-assessment** of your own network runs through the backend: open-port drift
against a saved baseline (with risky services like unauthenticated Ollama or Moonraker
called out by name), days until your soonest certificate expires, and missing HTTP security
headers. All passive — a TCP connect, a TLS handshake, an HTTP GET. Targets live in the
server's `.env` and can never be set from the page.

**Optional backend companion** lives in [`server/`](server/README.md). The dashboard works
without it; it exists for the three things a browser can't do — reach CORS-blocked APIs
(OpenAI), hold a secret the page must not see, and keep OAuth refresh tokens alive so
Fitbit stops needing a re-Connect every 8 hours. Zero npm dependencies, one
`docker compose up`.

**The dashboard now controls, not just monitors.** Home Assistant cards can toggle lights
and switches, run scenes and scripts, lock/unlock, open/close covers, nudge a thermostat,
drive a media player, and show camera snapshots — alongside the read-only sensor and status
cards. Connect once in **Settings**, then use **Browse** to pick entities; you never type an
entity id. **None of this is required** — with no Home Assistant configured, every other
platform works exactly as before.

**Two kinds of card.** Depletion cards (quotas, budgets, credit limits) read "% left" and
go Warning/Exhausted as they run down. Growth cards (subscribers, stars, portfolio value,
step goals) read "% of target", stay neutral **In progress** until the goal is met, then
show **Target reached** — they never go red, because being early toward a goal isn't a
failure. Every account has a *Higher/Lower is better* selector in its editor, defaulting
per account type, so a "free disk" sensor and a "CPU temp" sensor can share a platform.

**Manual cards have an Update button, not Refresh** — they open the editor instead of
inventing a number. Only cards backed by a real API get Refresh.

**No runtime CDN dependencies.** Tailwind is vendored inline as plain CSS and MSAL is
pinned to an exact version with an SRI hash, so nothing third-party executes on load and
the page styles correctly with no network at all.

> ⚠️ **Adding a Tailwind utility class to the markup means adding its rule to the vendored
> `<style>` block.** There is no JIT compiler anymore — an unlisted class silently does
> nothing. The class audit snippet is in the [Testing](#testing) section below; run it
> after any markup change.

**Attention layer.** A summary strip above the grid counts what needs attention, what
errored, and what hasn't refreshed today; each count is a clickable filter. Cards needing
attention float to the top, and everything else keeps the order you put it in.

**Trend history.** Each account keeps a rolling window of real readings (60 points / 90
days) and shows a sparkline plus a signed change vs a named period. Only genuine readings
are recorded — a successful live fetch, or a number you typed yourself. Simulated jitter
is never stored.

Single-file dashboard (`index.html`) tracking usage/limits across AI services, cloud,
finance, home lab, social, and health. No backend, no build step, nothing to install.

**Last updated:** 2026-07-27 · **31 example cards across 12 platforms**

---

## Starting from scratch

The dashboard ships example cards so a first run isn't an empty page. To clear them:
**Settings → Cards → Remove all cards**. *Restore examples* appends them back (it never
replaces what you've added).

An empty dashboard is a **saved state**, not a missing one — clearing your cards sticks
across reloads. Examples are only seeded when there's no stored data at all, i.e. a genuine
first run or after clearing browser storage.

---

## Running it

Double-clicking `index.html` works for everything **except OAuth** (Azure, Twitch, Fitbit).
OAuth providers cannot redirect back to a `file://` URL — that's a hard rule in every OAuth
implementation, not a fixable bug. For those you need a real origin.

Three ways to get one, best first:

| How | Command / step | Notes |
|---|---|---|
| **From Home Assistant** | copy `index.html` → `/config/www/cacheboard/index.html` | Reach it at `http://homeassistant.local:8123/local/cacheboard/index.html`. Same-origin with HA, so **no CORS config needed**, and one permanent LAN URL. |
| **From the backend container** | `cd server && docker compose up -d` | Serves the dashboard *and* the API on `http://localhost:8787`. Needs only Docker. |
| **Any static server** | e.g. `npx serve .` | ⚠️ Requires Node, which **is not installed on this machine** — `node`, `npm`, `npx` and Python are all absent. Use one of the options above unless you install it. |

Whichever you pick, register **that exact origin** as the redirect URI in each provider's
console, and keep the port stable or you'll be re-registering constantly.

---

## Platform status

### ✅ Live and verified working

| Platform | What it reads | Auth |
|---|---|---|
| **Anthropic (Claude)** | Real rate-limit headers | API key |
| **Cloudflare** | Zone requests, month-to-date | API token |
| **CoinGecko** (crypto) | Live coin price × your quantity | None needed |
| **Finnhub** (stocks) | Live share price × your quantity | Free API key |
| **YouTube** | Subscriber count | Public API key |
| **GitHub repos** | Star count | Optional token |
| **Discord** | Online member count | None needed |

### ⚙️ Built, needs your credentials

| Platform | Blocker | See section |
|---|---|---|
| **GitHub Copilot** | Needs a PAT; personal-account access unconfirmed | [Copilot](#github-copilot) |
| **Azure** (cost/quota/health) | Needs app registration + served over http(s) | [Azure](#azure) |
| **Home Assistant** | Hardware not set up yet; needs CORS config | [Home Assistant](#home-assistant) |
| **Home Lab** (generic) | Hardware not set up yet | [Home Lab](#home-lab-generic-json) |
| **Twitch** | Needs app registration + served over http(s) | [Twitch](#twitch) |
| **Fitbit** | Needs app registration + served over http(s) | [Fitbit](#fitbit) |

### 📝 Manual by design (no API exists)

- **ChatGPT / OpenAI consumer** (Plus/Team) — no public API exposes per-account quota for
  consumer plans, from any origin. Manual regardless of the backend.
  *(The API-key card is no longer manual — it works through the backend companion, which
  holds the key server-side. Needs an org-scoped admin key for the costs endpoint.)*
- **Consumer subscriptions** (Claude Pro, Copilot Individual fallback) —
  no public API exposes per-account quota for consumer plans.
- **Financial** (PNC, Amex, Consumers Energy, DTE) — real aggregation requires Plaid or
  similar, which mandates a server-side secret. See [Financial](#financial-plaid).
- **Pixel Watch** — Health Connect is Android-on-device-only. Google Fit's REST API is
  shut down. There is genuinely nothing to call from a browser.

### 🚧 Documented, not built

- **Instagram / Facebook / TikTok** — blocked on account approval, not code. See
  [Meta & TikTok](#meta--tiktok).
- **X (Twitter)** — no free tier since Feb 2026; ~$0.01 per profile read. Skipped by choice.
- **Reddit** — unauthenticated JSON access ended May 2026; new OAuth apps need approval under
  the Responsible Builder Policy, often unanswered. Skipped by choice.
- **LinkedIn** — partner-gated, unavailable for individual use.
- **Printables / 3D print sites** — no public API exists. Only scraping, which is fragile
  and generally against ToS. Not built deliberately.

---

## Setup instructions

### GitHub Copilot

1. GitHub → Settings → Developer settings → **Personal access tokens (classic)**
2. Scope: `manage_billing:copilot`
3. Edit the "GitHub Copilot — the3dcoder" card, paste token + username, Save → Refresh

**Open question:** GitHub moved Copilot to "AI Credits" billing on 2026-06-01. The
endpoint `/users/{username}/settings/billing/ai_credit/usage` exists, but GitHub's docs
mainly describe org/enterprise admin access. A personal account may get a 403.

- **If it 403s:** personal accounts can't self-serve this yet → leave the card manual.
- **If it 404s:** the endpoint path changed → use the **Endpoint override** field on the
  card to try an alternate path without touching code. Overrides are restricted to
  `api.github.com` (a relative path like `/users/x/settings/...` works too) so the
  override box can never send your PAT to another host.
- The card reports *spend*, not a plan cap. Set "Total limit" to your plan's monthly AI
  Credit allotment ($15 Pro / $70 Pro+ / **$200 Max**).

### Azure

Covers three card types (cost, quota, health) sharing one sign-in.

1. [portal.azure.com](https://portal.azure.com) → **Microsoft Entra ID** → App registrations → New
2. Redirect URI: platform **Single-page application (SPA)**, value = your served origin
   (e.g. `http://localhost:3000`)
3. **API permissions** → Add → **Azure Service Management** → Delegated →
   `user_impersonation` → grant consent
4. Copy **Application (client) ID** and **Directory (tenant) ID** from Overview
5. Get your **Subscription ID** from Portal → Subscriptions
6. In each Azure card: paste all three, click **Connect Microsoft Account**, then Refresh

One sign-in per Tenant/Client ID pair covers all Azure cards.

- **Cost** — month-to-date spend vs. a budget you set (Azure enforces no budget itself).
- **Quota** — real limit *and* real usage from Azure's usages API. Set resource provider
  (e.g. `Microsoft.Compute`), location (e.g. `eastus`), and quota item name (partial
  match, e.g. "Total Regional vCPUs"). Different providers use different API versions —
  if the default 404s, put an alternate path in **Endpoint override** (restricted to
  `management.azure.com`; a relative path works too).
- **Health** — Available/Degraded/Unavailable mapped to Active/Warning/Exhausted on a
  synthetic 0–100 scale (a status isn't naturally a percentage). Needs the full
  **Resource ID** from the resource's Overview page.

### Twitch

1. [dev.twitch.tv/console/apps](https://dev.twitch.tv/console/apps) → Register Your Application
2. **OAuth Redirect URL** = this page's exact served URL
3. Application Type: **Public** (no client secret is used)
4. Copy the **Client ID**
5. In the Twitch card: paste Client ID + your channel login, **Save**, then **Connect Twitch**

Uses implicit flow — Twitch returns a token directly, no secret, no exchange step.
Reading a *total* follower count requires signing in as that channel
(`moderator:read:followers` scope).

### Fitbit

1. [dev.fitbit.com/apps/new](https://dev.fitbit.com/apps/new)
2. **OAuth 2.0 Application Type: Client** (this selects PKCE — no secret)
3. **Redirect URL** = this page's exact served URL
4. Copy the **Client ID**
5. In the Fitbit card: paste Client ID, pick a metric, **Save**, then **Connect Fitbit**

**Known limitation:** Fitbit access tokens expire after ~8 hours. This dashboard does
not store refresh tokens — doing that safely is a backend concern. When a refresh starts
failing with an auth error, click **Connect Fitbit** again.

### Home Assistant

**Connect once, then everything else is a Browse click.**

1. HA → your profile (bottom-left) → **Security** → **Long-Lived Access Tokens** → Create
2. Dashboard → **Settings** → paste the base URL (e.g. `http://homeassistant.local:8123`)
   and the token → **Test connection** (it reports how many entities it can see)
3. Add a card, pick a Home Assistant type, click **Browse**, pick the entity

**CORS:** add this page's origin under `http: cors_allowed_origins` in
`configuration.yaml`, then restart HA:

```yaml
http:
  cors_allowed_origins:
    - http://localhost:3000   # must exactly match your served origin
```

**Or skip CORS entirely** by serving the dashboard from HA itself: copy `index.html` to
`/config/www/cacheboard/index.html` and open `http://homeassistant.local:8123/local/cacheboard/index.html`.
It's then same-origin, so no CORS config is needed at all — and you get one permanent URL
that every device on the LAN can reach and that OAuth providers can redirect back to.

**Card types:** numeric sensor (meter), read-only status, toggle (light/switch/fan/input
boolean/siren/humidifier — the domain comes from the entity id), lock, cover, scene ·
script · automation, climate, media player, camera snapshot.

**Control behaviour:** pressing an action calls the HA service, waits briefly for HA to
apply it, then re-reads that entity — so a card is never stale right after you act on it.
Unlock asks for confirmation first. Cameras show a still image, refreshed on demand; a
continuous stream is deliberately out of scope.

Since HA has official UniFi, Pi-hole, and
Frigate integrations, routing everything through HA is usually easier than hitting each
device's own API — one CORS config instead of several.

### Home Lab (generic JSON)

Deliberately generic rather than per-device, because device APIs vary by version
(Pi-hole changed auth substantially between v5 and v6) and none could be tested from
outside your LAN.

Fill in:
- **URL** — anything returning JSON
- **Auth header name/value** — optional (e.g. `X-API-KEY`)
- **JSON field path** — supports nesting and array indices: `dns_queries_today`,
  `cameras.front_door.fps`, `list[0].value`

**If it fails with a vague network error rather than an HTTP status:** the device sent no
CORS headers at all, so the browser blocked it before any response was readable. Options:
1. Route it through Home Assistant instead (recommended — it has integrations for most of this)
2. Put a reverse proxy in front that adds `Access-Control-Allow-Origin`
3. Check whether the device has a CORS setting of its own

---

## Blockers needing a decision

### ~~OpenAI API usage~~ — resolved in M7

Now works through the [backend companion](server/README.md), which holds the API key
server-side and forwards the request. Needs an **org-scoped admin key** for the costs
endpoint. ChatGPT Plus/Team consumer quota still has no API from any origin and stays
manual.

### ~~Fitbit 8-hour tokens~~ — resolved in M7

The backend holds the refresh token and mints access tokens on demand; the dashboard
retries automatically on a 401. Rotated refresh tokens are persisted, so the chain doesn't
break. Put `FITBIT_CLIENT_ID` and `FITBIT_REFRESH_TOKEN` in `server/.env`.

### Financial (Plaid)

Real bank/card data (PNC, Amex) requires an aggregator like Plaid, which **mandates a
server-side secret** — there is no public-client browser flow, unlike Azure. Utilities
(Consumers Energy, DTE) likely have no aggregator coverage at all.

**To resolve:** stand up a small local backend (Node/Python) holding the Plaid secret and
exposing one endpoint this dashboard can call. That backend would also unlock **ChatGPT
usage** (the OpenAI CORS problem) and **Fitbit token refresh** — three problems, one fix.

**Current state:** manual entry. Perfectly functional, just not live.

### Meta & TikTok

All three are blocked on **account approval, not code**. Multi-week timelines — worth
starting now if you want them.

**Instagram** (requires Business/Creator account linked to a Facebook Page):
1. [developers.facebook.com](https://developers.facebook.com) → create a **Business**-type app
2. Add the **Instagram Graph API** product
3. Convert Instagram to Business/Creator, link to a Facebook Page
4. Complete **Business Verification** in Meta Business Manager (needs business documents)
5. Submit **App Review** — each permission needs a screencast, privacy policy URL, and
   data deletion instructions
6. Timeline: ~2–4 weeks

**Facebook** (same app — do them together):
1. Request **Page Public Content Access**
2. Same App Review + Business Verification
3. Generate a **system user access token**; follower count field is `fan_count`

**TikTok** ([developers.tiktok.com](https://developers.tiktok.com)):
1. Register as developer, create app, get authorized
2. OAuth 2.0 authorization-code flow
3. Follower data via **Creator Search Insights API**

⚠️ **TikTok caveat:** access tokens expire every **24 hours** and require refresh-token
logic, which wants server-side storage. TikTok is the weakest fit for a browser-only
dashboard of anything on this list — it's the strongest argument for the backend
described under [Financial](#financial-plaid).

---

## Architecture notes

### Adding a new platform

**Write one `PLATFORMS` entry and one `fetchXxx` function. That's it.** Icons, colours,
badge tints, dropdown options, the refresh dispatch, the credential form, validation and
persistence are all derived from the entry.

```js
mything: {
  label: "My Thing",
  hue: "#3987e5",                       // badge tint is derived from this
  icon: '<path d="..."/>',              // inner SVG, 24x24 viewBox
  note: "What's real vs. manual, and any gotchas.",
  accountTypes: [
    {
      value: "usage",
      label: "Usage vs. quota",
      fetch: fetchMyThing,              // presence of this === the card is "Live"
      direction: "growth",              // optional; default "depletion"
      display: "status",                // optional; hides the meter, shows a state word
      connect: "azure",                 // optional; renders an OAuth Connect button
      fields: [
        { key: "myToken", label: "API token", type: "password", required: true },
        { key: "myId",    label: "Resource ID", type: "text", required: true, full: true }
      ],
      help: "Where to get the token."
    }
  ]
}
```

`fetchMyThing(acc)` receives credentials as **plain properties** (`acc.myToken`) and
returns `{ totalLimit, used, resetTime }`, optionally `unit`. Storage namespaces them
under `acc.creds`; the fetcher gets a flattened view.

Field options: `type` is `text | password | number | select | hidden`; `full: true` spans
both columns; `options: [[value, label], …]` for selects; `required: true` blocks saving a
Live card with that field empty.

⚠️ If your markup uses a Tailwind class not already in the vendored `<style>` block, add
its rule — see the warning at the top of this file.

### Conventions

- **A type is "Live" iff it has a `fetch` reference.** There is no separate flag to keep
  in sync — the badge and the dispatch read the same property.
- **Status thresholds:** >20% left = Active, 5–20% = Warning, ≤5% = Exhausted.
- **"Total limit" is overloaded on purpose.** For AI quotas it's a real cap. For
  Azure cost, Cloudflare, Investments, and Social it's a *target you set* — so
  "% left" means distance to goal, not depletion. Only Azure **quota** returns a real
  limit from the API itself.
- **Auto-reset:** manual/simulated accounts roll over automatically at `resetTime`.
  Real-data accounts show "reset pending — refresh to confirm" instead, so no numbers are
  ever fabricated. Credit cards and targets use a ~100-year interval to effectively disable it.
- **Credentials** live under `acc.creds` in `localStorage` only and are sent only to their
  own provider. Anyone with access to this browser profile can read them via dev tools —
  prefer low-privilege, restricted-scope keys.
- **Schema version lives inside the payload** (`{version, accounts}`), never in the storage
  key. The key is frozen at `.v1` forever; bumping it would orphan saved credentials.
  Migrations run in `normalizeAccount()` — currently v3.

### OAuth implementation

Azure uses MSAL.js. Twitch and Fitbit use a hand-rolled popup flow
(`openOAuthPopup`) since no equivalent library exists for them:

- The popup lands back on `index.html`; `handleOAuthRedirectIfPopup()` detects this,
  `postMessage`s the result to the opener, and closes. It returns early **before** the
  dashboard boots, so the popup never renders a second dashboard.
- `state` is validated to prevent cross-flow mixups; popup-closed and popup-blocked both
  reject with clear messages rather than hanging.
- Fitbit's PKCE challenge was verified against the **RFC 7636 Appendix B test vector**.

### Testing

There's no test framework here. The verification approach used during development, which
works well and is worth reusing:

```js
// Run from the browser console on the page:
fetch('index.html', {cache:'no-store'}).then(r=>r.text()).then(html => {
  const src = [...html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g)]
    .map(m=>m[1]).filter(s=>s.trim()).pop();
  new Function(src);                       // throws on syntax error
  const patched = src.replace('document.addEventListener("DOMContentLoaded", init);',
                              'window.__testInit = init;');
  localStorage.clear();
  (0,eval)(patched); window.__testInit();  // boot in isolation
  console.log(document.querySelectorAll('[data-card-id]').length, 'cards');
});
```

Checking a new API's CORS support before writing any integration code saves a lot of
wasted effort — a real HTTP error (401/403) means it's reachable; a network/CORS error
means it isn't:

```js
fetch('https://api.example.com/endpoint', {headers:{Authorization:'Bearer fake'}})
  .then(r => r.text()).then(t => console.log('reached:', t.slice(0,200)))
  .catch(e => console.log('CORS blocked:', e.message));
```

---

## Suggested next steps

1. **Test the credentials you already can** — Copilot, Cloudflare, YouTube, Discord, and
   the investment cards all work today with a key and no OAuth setup.
2. **Serve it properly** (`cd server && docker compose up -d`) and set up the Azure app registration — that
   unlocks three card types at once.
3. **Start the Meta/TikTok approval clock** if you want those — it's the longest pole.
4. **Wire home lab gear** once the hardware is up; prefer routing through Home Assistant.
5. **Decide on the backend question** — it's the single unlock for Plaid/financial,
   ChatGPT usage, Fitbit token refresh, and TikTok. Four blockers, one solution.
