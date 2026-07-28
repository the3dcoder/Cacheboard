# Backend companion (optional)

**The dashboard works fine without this.** It exists only for the three things a browser
genuinely cannot do:

1. **Reach APIs that refuse browser calls** — OpenAI sends no CORS headers, by design
2. **Hold a secret the browser must not see** — any `client_secret`
3. **Keep a refresh token alive** — Fitbit's access tokens expire in ~8 hours

It's a single file with **zero npm dependencies** — Node's standard library covers all of
it. No lockfile, no supply chain, no install step.

## Quick start

```bash
cd server
cp .env.example .env
```

Set `DASHBOARD_TOKEN` in `.env` to something long and random, then:

```bash
docker compose up -d
```

Open **http://localhost:8787** — the container serves the dashboard *and* the API from one
origin, so no CORS setup is needed for the default case. Then in the dashboard:
**Settings → Backend companion** → URL `http://localhost:8787`, token = your `DASHBOARD_TOKEN`
→ **Test backend**.

Without Docker, `node server.mjs` works too (Node 18+), with `STATIC_DIR=..` if you want it
to serve the dashboard.

## What it exposes

| Route | Auth | Purpose |
|---|---|---|
| `GET /health` | none | Which providers and checks are configured |
| `* /proxy/<provider>/<path>` | bearer | Forwards to that provider's **one allowlisted host**, injecting the secret |
| `POST /token/<provider>/refresh` | bearer | Swaps the stored refresh token for a fresh access token |
| `GET /security/<check>` | bearer | Runs a named self-assessment check against **your own** hosts |
| `GET /<file>` | none | The dashboard itself, when `STATIC_DIR` is set |

## Security model

Honest about what this is: a home-LAN service holding real API keys.

- **Bearer token on every API route.** An unset `DASHBOARD_TOKEN` refuses *everything*
  rather than defaulting open.
- **Exact-match origin allowlist.** `ALLOWED_ORIGINS` must list the browser's exact origin.
  `*` is accepted but warns loudly at startup — with it, any site you visit can call this.
- **The host is never caller-controlled.** `/proxy/openai/...` can only ever reach
  `api.openai.com`; only the path comes from the request. A caller cannot redirect your
  injected key somewhere else.
- **Static serving refuses dotfiles**, `state.json`, and anything that isn't a known web
  asset — and the compose file mounts the dashboard file-by-file rather than the whole
  folder, so `.env` is never inside the web root to begin with.
- **Refresh tokens never reach the browser.** The dashboard receives only short-lived
  access tokens.
- **Secrets live in `.env`**, which is gitignored. `state.json` (rotated refresh tokens) is
  gitignored too.

**Not included:** HTTPS. On a trusted LAN the bearer token travels in the clear. If that
matters to you, put it behind a reverse proxy with a cert, or restrict access at the
firewall.

## Security self-assessment

Continuous checks against **your own** hosts, surfaced as dashboard cards. A browser can't
open a raw socket or complete a TLS handshake against another host, which is why these live
here.

| Check | What it reports | Configure |
|---|---|---|
| `port-drift` | Ports that opened or closed since a saved baseline, plus risky services | `SECURITY_HOSTS`, optional `SECURITY_PORTS` |
| `tls-expiry` | Days until the soonest certificate expiry across all hosts | `SECURITY_TLS_HOSTS` |
| `http-headers` | Count of missing security headers across your services | `SECURITY_HTTP_URLS` |

**Targets come from `.env`, never from the request.** A caller names a *check*; the server
decides what runs and against what. That's deliberate — a network tool exposed over HTTP
that accepts caller-supplied targets is a scan-anything service, and this one holds your
API keys.

All three are passive: a TCP connect, a TLS handshake, an HTTP GET. Nothing is exploited
and nothing is written to.

**Port drift** records a baseline on its first run rather than reporting every open port as
a change. Only ports actually probed in the current run are compared, so narrowing
`SECURITY_PORTS` later won't produce a wave of false "now closed" alerts. Risky services
are named even when unchanged — Telnet and FTP (plaintext credentials), exposed databases,
VNC, and the two that catch people out on a home lab: **Ollama** (port 11434, no auth by
default — anyone on your network can use your models) and **Moonraker/Klipper** (7125, full
printer control, frequently unauthenticated).

**Certificate expiry** reports the *soonest* expiry across every host, so one card covers
the estate. Self-signed and untrusted certs are flagged in the detail rather than treated
as failures — a home lab legitimately has them.

### Checks that need external tools

Not implemented, and honestly why:

| Check | Blocker |
|---|---|
| `arp-scan` / new-device detection | Raw sockets + host networking. Linux only — will not work under Docker Desktop on Windows. |
| `nuclei` | Needs the binary and its template corpus. |
| Suricata / Zeek alerts | Needs an IDS already running, plus log mounts. |
| Default-credential probes | Needs per-device protocol handling. |

To add one: install the tool in the `Dockerfile`, then add an entry to `SECURITY_CHECKS`
whose `run()` shells out with **fixed arguments** and targets read from `.env`.

⚠️ Never interpolate anything from the HTTP request into a command. The name-based dispatch
exists precisely so a caller cannot influence what executes.

## Adding a provider

**A proxy target** — one entry in `PROXY_PROVIDERS`:

```js
myprovider: {
  host: "api.example.com",                       // the only host it can reach
  headers: () => ({ authorization: `Bearer ${env.MY_KEY}` }),
  missing: "MY_KEY is not set in the server's .env file."
}
```

**An OAuth refresh** — one entry in `OAUTH_PROVIDERS`:

```js
myprovider: {
  tokenUrl: "https://example.com/oauth/token",
  clientId: () => env.MY_CLIENT_ID,
  clientSecret: () => env.MY_CLIENT_SECRET || "",   // omit under PKCE
  seedRefreshToken: () => env.MY_REFRESH_TOKEN
}
```

Fitbit, Google, Spotify and Strava are already wired — they just need credentials in `.env`.

There's also a generic `custom` proxy slot (`CUSTOM_PROXY_HOST` / `_HEADER` / `_VALUE`) for
a one-off host with no code change at all.

## Fitbit setup

The point of this is to stop re-clicking **Connect Fitbit** every 8 hours.

1. Connect Fitbit once in the dashboard as normal
2. Grab the **refresh token** from that exchange
3. Put it in `.env` as `FITBIT_REFRESH_TOKEN`, along with `FITBIT_CLIENT_ID`
4. `docker compose restart`

From then on the dashboard asks the backend for a fresh access token whenever Fitbit
returns 401, and retries automatically. Fitbit rotates refresh tokens on every use, so the
server persists the new one to `state.json` — that's what keeps the chain from breaking.

## OpenAI setup

Put `OPENAI_API_KEY` in `.env` and restart. The card totals API spend over a window you
choose (default 30 days) against a budget you set as "Total limit".

⚠️ The costs endpoint needs an **org-scoped admin key**. A plain project key returns no
data, and the card will say so rather than showing a fabricated zero.

⚠️ This covers **API-key spend only**. There is no API for ChatGPT Plus/Team consumer
quota from any origin, so those cards stay manual no matter what.
