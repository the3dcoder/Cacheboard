# Limit Tracker Dashboard

A single-file, dark-mode dashboard for everything in my life that fluctuates daily —
AI service quotas, cloud spend, home lab telemetry, investments, social metrics, and health.

One `index.html`. No build step, no install, no backend.

![platforms](https://img.shields.io/badge/platforms-11-blue) ![accounts](https://img.shields.io/badge/accounts-25-green)

## What it tracks

| | |
|---|---|
| **AI** | Claude (live), ChatGPT, GitHub Copilot |
| **Cloud** | Azure cost, quota, and resource health |
| **Web** | Cloudflare zone traffic |
| **Money** | Credit cards, utility bills, crypto & stock holdings (live prices) |
| **Home lab** | Home Assistant — sensors *and* controls (lights, locks, covers, scenes, climate, media, cameras); generic JSON metrics from any local device |
| **Social** | YouTube, GitHub stars, Discord, Twitch |
| **Health** | Fitbit (live), manual entry for Pixel Watch |
| **Security** | Open-port drift vs a baseline, certificate expiry, missing security headers — your own hosts only |

Each card shows a live progress bar, a status badge, a countdown to reset, a sparkline of
recent readings, and a **Refresh** button that pulls real data where an API allows it.
Home Assistant cards can also *act* — toggles, scenes, setpoints and transport controls.

## Quick start

Double-click `index.html` and it runs — no build, no install.

For OAuth-based cards (Azure, Twitch, Fitbit) you need a real `http(s)` origin, since OAuth
providers can't redirect back to a `file://` URL. Easiest option:

```bash
cd server && docker compose up -d
```

That serves the dashboard *and* the optional backend on `http://localhost:8787`. If you run
Home Assistant, dropping `index.html` into `/config/www/` is even better — same-origin with
HA, so no CORS setup at all. See [NOTES.md](NOTES.md).

## Design principle

**Never fake a number.** Where a real API exists, the card calls it and shows a Live
badge. Where one genuinely doesn't — OpenAI blocks browser calls by design, consumer AI
subscriptions expose no quota API, banks need a server-side secret, Pixel Watch data never
leaves the device — the card says **Manual** and you fill it in yourself. Every platform's
note field explains exactly which it is and why.

## Credentials

API keys and tokens are stored in your browser's `localStorage` and are sent only to their
own provider. **Nothing is committed to this repo.** Anyone with access to your browser
profile can read them via dev tools, so prefer low-privilege, restricted-scope keys.

## Setup, status, and outstanding work

See **[NOTES.md](NOTES.md)** — per-platform setup instructions, what's blocked and why,
architecture notes, and how to add a new platform.
