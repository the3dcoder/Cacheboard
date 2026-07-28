# ROADMAP — Post-Audit Milestones

Three principal-level audits (Architecture, UI/UX, QA) were run against the live app on
2026-07-27. QA reproduced every finding in a live harness; UI/UX measured the rendered
DOM; Architecture traced all findings to line numbers. This file is the deduplicated
synthesis, organized into executable milestones.

**Status: ALL MILESTONES COMPLETE (approved and executed 2026-07-27).**

**M8 result:** three security checks, all pure Node — no nmap, no raw sockets, nothing
privileged — so they run in the stock container. Verified against real hosts: the TLS check
correctly reported an expired certificate at **−4,125 days** and flagged self-signed ones;
port drift was proven by doctoring a stored baseline and confirming it reported both the
newly-open and newly-closed port.

- **Targets live in the server's `.env`, never in a request.** A caller names a *check*;
  the server decides what runs and against what. A network tool over HTTP that accepts
  caller-supplied targets is a scan-anything service — in a process holding API keys.
- **Risky-service flagging** names what actually bites on this kind of network: Telnet/FTP
  plaintext, exposed databases, VNC, and the two that catch people out — **Ollama** (11434,
  no auth by default) and **Moonraker/Klipper** (7125, unauthenticated printer control).
- **"0 findings is healthy" needed no new machinery** — it's the depletion direction from
  M3, exactly as predicted when M8 was first sketched. Cert expiry uses growth instead,
  since more days remaining is better.
- `arp-scan`, `nuclei`, IDS parsing and default-credential probes are **documented hooks,
  not shipped wrappers** — per the interview answer. Each needs binaries or host networking
  the container doesn't have, and shipping shell-outs I couldn't test would repeat the trap
  the generic home-lab card was designed to dodge.

**Bugs found by verification, both mine, both from this milestone:**

1. **A temporal-dead-zone crash that blanked the entire dashboard.** The three security
   fetchers were `const` arrows; `PLATFORMS` (a const initialised earlier) references them
   by name. Function declarations hoist — const arrows don't — so the whole script aborted
   before `init` was ever registered. The page rendered zero cards with *no console error
   visible*, and it was the isolation harness that surfaced the real cause. Every other
   fetcher in the file is a `function` declaration, which is why this had never bitten.
2. **A false-alarm generator in port drift.** Comparing the full baseline against a
   narrowed scan set would report every no-longer-scanned port as "now closed" — an alert
   storm caused purely by editing config. Now only ports probed in the current run are
   compared.

Also fixed: JSON responses lacked `charset=utf-8`, so clients guessing latin-1 mangled the
`·` in detail lines.

**M7 was the first milestone verifiable against a real running process**, not just a
harness: the container was built, started, and exercised. The proxy reached OpenAI's real
API and returned OpenAI's own error about the fake key — i.e. the CORS wall is genuinely
crossed. Auth rejection, unknown providers, missing config, traversal attempts and the
served dashboard were all checked from a real browser origin.

**Two real bugs found by running it, that reading the code would not have caught:**

1. **`server/.env` was being served over HTTP** — the compose file mounted the whole
   project into the web root, so the bearer token and every API key were downloadable.
   Fixed at both layers: the server now refuses dotfiles, `state.json`, server internals
   and any non-web-asset extension; the compose file mounts the dashboard file-by-file so
   secrets are never in the web root at all.
2. **`env_file` silently disabled static hosting.** A blank `STATIC_DIR=` in `.env`
   overrides the Dockerfile's value, so the "serve the dashboard too" feature quietly did
   nothing. `.env.example` now says not to set it under Docker.

**Also corrected: a documentation bug shipped since M2.** Every milestone told the user to
run `npx serve .` — this machine has no Node, npm, npx or Python at all. Docs now lead with
Home Assistant hosting and the Docker container, with the Node option explicitly flagged.

**Scope, per interview:** OpenAI proxy, Fitbit token refresh, generic proxy slot. Plaid was
offered and declined — correctly, it's an application process rather than an afternoon.
Google/Spotify/Strava OAuth are wired but dormant, needing only credentials.

**M6 partly superseded justification #1.** Serving from Home Assistant already solved the
stable-origin problem, so the backend's static hosting is a convenience rather than the
reason it exists. The three genuine reasons remain: CORS-blocked APIs, server-held secrets,
and refresh-token lifetime.

**M6 scope, decided by interview:** all four control families, entity browser, polling with
instant re-read after any action, and both hosting modes. The dashboard remains fully
usable with no Home Assistant configured at all — that was an explicit requirement.

- **Nine HA card types**, up from one: numeric sensor, read-only status, toggle, lock,
  cover, scene/script/automation, climate, media, camera snapshot. Most ride one generic
  `POST /api/services/{domain}/{service}` path, which is why the "cheap wins" (fans,
  locks, covers, sirens, humidifiers, input booleans) came almost free — `turn_on` /
  `turn_off` is a shared contract across HA domains, so the toggle card covers all of them
  and derives the domain from the entity id.
- **Connection is global, not per-card.** This was forced by the interview answers rather
  than chosen: an entity browser must talk to HA *before* any card exists, and re-typing a
  long-lived admin token into twenty cards is untenable. Cards now carry only an entity id.
- **Actions re-read the entity after firing** (with a 400 ms settle, since HA applies
  service calls asynchronously). This is what makes polling acceptable for controls —
  the card you just touched is never stale, even if changes made elsewhere lag.
- **Camera snapshots go through `fetch` → blob → object URL** rather than an `<img src>`,
  because the endpoint needs the auth header and a token must never land in a URL.
- **Schema v4** lifts existing per-card HA credentials into the global setting. Verified:
  base URL and token lifted, `haEntityId` renamed to `entityId`, per-card copies removed.

**Deliberately not built:** WebSocket push. It was offered and the answer was polling.
Worth revisiting once the control tiles are confirmed against real hardware.

**Harness lesson:** a test left `window.fetch` stubbed and the next test silently loaded a
404 body instead of the file, producing a confusing failure. Verification snippets now
take a pristine `fetch` from a throwaway iframe and restore it in a `finally`.

**M5 result:** the file went from 3,316 to 2,654 lines (‑662) while gaining
functionality. Adding a platform is now one `PLATFORMS` entry.

- **`real:` is gone.** A type is live iff it has a `fetch` reference, and the dispatch
  is that same reference — the badge and the behaviour cannot disagree, because they
  are the same fact. The 15-branch chain became four lines. Verified: live/manual
  counts came out 16/9, identical to the hand-maintained flags.
- **Credentials are declarative.** Each type lists its `fields`; the DOM id, the read,
  the required-check and the persisted key all derive from one `key`. This deleted the
  16-branch `renderCredentialFields`, the `REQUIRED_CREDENTIALS` map, 36 `getElementById`
  lines and 36 property assignments.
- **`acc.creds` migration (schema v3).** Verified a v2 record with a real key survives:
  key preserved, flat property removed, empty legacy values not copied.
- **Fetchers were left untouched.** They receive a flattened `credView(acc)` rather than
  having ~60 property references rewritten by hand — rewriting them would have been the
  exact typo risk this milestone exists to remove.
- Seeds: 404 lines → a 25-row table. Icons and colours moved onto the platform entry,
  deleting 22 CSS variables and a parallel icon lookup; the badge tint is now derived
  from the hue so the two can't drift.

**Caught during verification:** `sm:col-span-2`, newly emitted by the generic field
renderer, was missing from the vendored CSS — the same silent-failure mode as
`overflow-x-auto` in M4. The class audit now also covers classes emitted from JS
template literals, not just static markup.

**M4 additions beyond the audit's list**, agreed during the milestone:

- **M4.9 Trend history + sparklines.** A rolling window of readings per account
  (60 points / 90 days), a 12-point sparkline and a signed delta vs a named period.
  Only *real* readings are recorded — a successful live fetch or a hand-typed edit.
  Live-simulation jitter is deliberately excluded, because a sparkline drawn from
  invented data is the same class of dishonesty M3 existed to remove.
- **Ordering: problems float, healthy cards never reshuffle.** The audit specified a
  strict urgency sort; that reorders a dashboard you check daily and destroys the
  muscle memory of where things live. Sorting is stable on original index, so only
  Exhausted/Warning/unknown cards get promoted.
- **The modal caps its own height** rather than merely collapsing its notes. Collapsing
  alone only took Azure/quota from 1,275px to 1,259px — the form is simply long. It now
  maxes at `100dvh - 4rem`, scrolls internally, and keeps Save pinned in a sticky bar.

**Caught during verification:** the vendored Tailwind CSS from M2 had `.overflow-y-auto`
but no `.overflow-x-auto`, so the new scrolling filter bar was silently inert and the page
still scrolled sideways at 375px. The class audit now runs against the file's own `<style>`
blocks after every markup change; it currently reports zero missing rules across 106 used
classes (excluding three intentional JS-hook classes).

**Two decisions made during M3 that differ from the audit's literal prescription:**

1. **Growth cards never go red.** The audit said "status thresholds flip," which would
   render a channel at 20% of its subscriber goal as a red *Exhausted* card. Being early
   toward a goal is not a failure, so growth cards use a neutral **In progress** badge
   until the target is met, then **Target reached**. A growth card has no critical state —
   the dashboard has no history, so it genuinely cannot tell "growing slowly" from
   "declining," and inventing alarm from a single data point would repeat the class of
   dishonesty this milestone existed to remove.
2. **Direction is per-account, not per-type.** Home Assistant and Home Lab sensors are
   the same account type but opposite polarity (free disk vs. CPU temp), so a
   *Higher/Lower is better* selector was added to the editor, defaulting per type. This
   also means M8's security cards ("0 findings is healthy") need no new machinery.

Every M1/M2 fix below was verified by reproducing the original failure first, then
confirming the fix. Notable verification details: the malformed-storage case was replayed
with six broken record shapes; the endpoint allowlist was tested against a lookalike
domain (`api.github.com.evil.com`) as well as an obviously hostile one; the vendored CSS
was measured against the rendered geometry at 375/800/1280px rather than eyeballed.

---

## Audit headline

The good news: the OAuth flows are sound (PKCE verified against RFC 7636, no
double-settles, no stalls), repeated-refresh is correctly guarded, the modal survives the
render loop, and `name`/`unit`/`lastError` are properly XSS-escaped.

The bad news clusters in one root cause the architect identified precisely: **there is
no boundary between "the shape of an account" and "the code that reads an account."**
No load-time validation, three hand-synced string lists per credential field, and a
`real:` flag that nothing ties to the actual fetch dispatch.

Notable: **every fresh install has a visibly broken card within 60 seconds** (Bug 1.3 —
the seeded Anthropic account's countdown permanently sticks on "reset pending").

---

## Milestone 1 — Stability & Data Integrity 🚨 ✅ DONE

*Every reproduced bug that corrupts data or leaves the app unusable. No design decisions
required; all fixes specified by the audits. Effort: S–M total.*

| # | Bug (all reproduced) | Fix |
|---|---|---|
| 1.1 | **One malformed localStorage record takes down the entire dashboard** — blank page, unresponsive buttons, no recovery without devtools. `loadAccounts()` has zero validation; `render()` runs before listeners are wired; `tick()` re-throws every second | Add `normalizeAccount()` (drop unknown platforms, default missing numerics, validate dates, coerce non-arrays); guard `renderCard` against unknown platforms; move first `render()` after listener wiring; try/catch `tick()`; bring `saveAccounts()` inside error handling. **Version inside the payload — do NOT bump the storage key** (that would silently abandon saved credentials) |
| 1.2 | **`_refreshing: true` gets persisted** → card's Refresh button permanently disabled with a stuck spinner after any mid-flight persist | Strip `_`-prefixed keys in `saveAccounts()` |
| 1.3 | **`_resetDue` never cleared on real accounts** → countdown permanently reads "reset pending" even after successful refresh. Hits the seeded Anthropic card within 60s of first load | Clear in `refreshAccount` success path and whenever `remainingMs > 0` |
| 1.4 | **Browsing the Platform dropdown while editing silently wipes credentials** (7 of 11 platforms; unrecoverable on single-type platforms) and silently converts account types (Live→Manual). Green "saved" toast throughout | Platform-change handler must pass `acc \|\| {}` like the type handler does; preserve current accountType across the option rebuild |
| 1.5 | **Fetch returning non-numeric data renders a healthy green card** — NaN persists as `null`, reloads as "100% left, Active." Fabricated health on YouTube (hidden sub counts), Azure unlimited quotas, etc. | `Number.isFinite` guard before applying any fetch result; throw into the existing error path ("numbers left unchanged") |
| 1.6 | **Unbounded reset-interval input freezes the app permanently** (`1e15` hours → RangeError every tick, `used` zeroed before the throw) | Clamp interval; add input `max`; contained by 1.1's try/catch |
| 1.7 | **Editing during an in-flight refresh discards the result and drops the concurrency guard** — success toast for data that was thrown away | Re-resolve account by id after every `await` |
| 1.8 | **Open-then-save silently discards over-limit values** ($250 spend on a $200 cap becomes $200) | Stop clamping `used` to `totalLimit` at save; clamp only at render (already done) |
| 1.9 | **XSS: `accountType` and `id` interpolated unescaped** (name/unit/lastError are escaped; these two sinks were missed) | Two `escapeHtml()` calls |
| 1.10 | **OAuth `state` validation skippable** (missing state passes); state mismatch and popup-close race both misreport as "window was closed" | Fix the conditional; grace-period the closedTimer |
| 1.11 | Smaller reproduced items: `formatNumber` renders "1000K / 1M"; filtered-empty state says "No accounts yet" while 24 exist; `min` attributes contradict the JS clamps (sub-1 targets impossible); NaN renders green "Active" | Per-item one-liners |

## Milestone 2 — Security Hardening 🔒 ✅ DONE

*Small, high-value. Effort: S.*

| # | Finding | Fix |
|---|---|---|
| 2.1 | **Endpoint-override fields send live bearer tokens to arbitrary hosts** (GitHub PAT, Azure ARM token, HA admin token) — and NOTES.md currently *teaches* pasting full URLs | `resolveEndpoint()` with per-platform host allowlist in 4 places; relative overrides start working as a bonus; correct NOTES.md |
| 2.2 | **Unpinned CDN deps** — `msal-browser@3` floats (SRI impossible); `cdn.tailwindcss.com` is the largest supply-chain surface in a file holding ~6 credential types, and the page is unstyled offline | Pin MSAL to exact version + `integrity`/`crossorigin`; vendor Tailwind's generated CSS inline (one-time build, not a build step — also makes double-click mode work offline) |

## Milestone 3 — Semantic Truth 📊 ✅ DONE

*The dashboard currently tells the opposite of the truth on 8 cards. Effort: M.*

| # | Finding | Fix |
|---|---|---|
| 3.1 | **Growth cards invert the metaphor**: YouTube at 96% of goal renders red "Exhausted"; Bitcoin down 75% renders green "Active." Measured, not theoretical | `direction: "depletion" \| "growth"` per account type; growth cards read "96% of target," bar fills toward goal, status thresholds flip |
| 3.2 | **Health cards read as nonsense** ("0.0% left · 100/100 Unavailable · Exhausted") | `display: "status"` mode: state word as hero, badge mapping kept, bar/ratio hidden |
| 3.3 | **"resets in 36499d 23h" on 52% of cards** — sentinel leaking into UI, diluting real countdowns | Hide countdown when interval > ~1 year |
| 3.4 | **Manual "Refresh" fabricates numbers identically to real refresh** — same button, same green toast, on money/health cards | Label "Simulate" on manual types; distinct toast wording |
| 3.5 | **`fetchAzureCost` reports $0 on an empty result** (fabricated zero vs. quota's correct throw); CoinGecko/HomeLab/Twitch error paths eat useful messages; HomeLab (most misconfiguration-prone platform) has the worst error UX | Shared `httpFail()` helper; empty-result guard; JSON-parse guard on HomeLab |
| 3.6 | `unit` field is overloaded (currency, targets, thresholds, live status strings) | Drains naturally out of 3.1 + 3.2 |

## Milestone 4 — UX & Accessibility Overhaul ♿ ✅ DONE

*Effort: M–L. The render fix is the keystone — most other interactivity depends on it.*

| # | Finding | Fix |
|---|---|---|
| 4.1 | **1s full re-render = total keyboard lockout** (focus lost within 1s on all 80 tabbable elements, text unselectable, clicks droppable) | Countdown text updates in place on cached nodes; full `render()` only on state change; never rebuild filterBar on tick |
| 4.2 | **No attention layer**: 23 of 25 cards identical green across 6,600px; insertion-order layout scatters related cards | Summary strip ("2 need attention · 23 healthy · 6 never refreshed", clickable filters) + urgency sort (Exhausted → Warning → stale). Use the dataviz skill for this layer |
| 4.3 | **Mobile broken**: filter bar 901px wide in a 375px viewport (page scrolls sideways, modal clipped off-screen); unconditional `grid-cols-2` in modal; touch targets under 44px | `overflow-x-auto` pills; responsive modal grids; target sizing |
| 4.4 | **Contrast failures on the most urgent states**: "Exhausted" badge 3.22:1, "Active" 4.39:1 (needs 4.5:1) | Text-safe tints for badge/banner text; keep saturated hues for bars/dots |
| 4.5 | **Active filter pill visually inert** — inline styles beat the `[data-active]` CSS rule; only a 1.22:1 background shift survives | Move color/border out of inline styles |
| 4.6 | **Screen readers get ~nothing**: 1 role + 1 aria-label in 2,120 lines; anonymous progressbars; silent toasts; zero headings; no dialog semantics; no author focus styles on buttons | `aria-label`/`aria-valuetext` on bars, `aria-pressed` pills, `role="status"` toasts, `<h3>` card names, dialog roles, `:focus-visible` styles |
| 4.7 | **Modal**: 1,275px tall on Azure/quota; up to 1,280 chars of always-expanded prose; zero required credential fields (save empty Live accounts); no Esc-close, no scroll lock, no focus management; stale defaults survive type switches (`unit: "tokens"` on an Azure quota card) | Collapsible setup notes; per-type `defaults`; save-time credential validation with inline errors; dialog behaviors; sticky action bar |
| 4.8 | Cleanup batch: stale header subtitle ("more coming later" on 11 platforms); no Refresh-all; errors shown twice with no dismiss; error banners stretch sibling cards (`align-items: start`) | Per-item one-liners + "Refresh all stale" alongside 4.2 |

## Milestone 5 — Table-Driven Platform Architecture 🏗️ ✅ DONE

*~600 lines shorter; adding a platform becomes one object literal. Effort: M (one
focused session). Sequenced after M1 because load-time normalization is what makes the
schema migration safe.*

| # | Finding | Fix |
|---|---|---|
| 5.1 | **`real:` flag and the 15-branch dispatch chain are hand-synced lists** — divergence puts a green "● Live" badge on random numbers. The worst failure mode in the file, currently unrepresentable-by-luck | `fetch:` reference on each accountType entry; `real` becomes derived (`!!type.fetch`); dispatch collapses to 4 lines |
| 5.2 | **38 credential fields × 3 unlinked string contracts** (DOM id ↔ getElementById ↔ property read; 72 calls) — a typo in any one silently breaks a field while the UI looks fine | Declarative `fields:` array per accountType; generic render + save paths |
| 5.3 | 25 seed objects × 20 lines of ~950 empty strings | `creds` sub-object migration (inside 1.1's normalize); unknown fields default naturally |
| 5.4 | 9 touch-points per new platform (CSS vars, config, icons, options, fetch, dispatch, cred UI, save, seeds) | Collapses to 1 (the `PLATFORMS` entry) — icons/colors/options generated |

## Milestone 6 — Home Assistant Control Surface 🏠 ✅ DONE

*NEW direction from the user: evolve toward an easier-to-control replacement for a Home
Assistant dashboard. Scope pending interview. Effort: L.*

What's technically established already:
- HA's REST API supports **calling services** (`POST /api/services/light/turn_on`, etc.)
  with the same CORS config + long-lived token the sensor card already uses — so
  toggles/buttons/scenes are feasible browser-side today
- HA also has a **WebSocket API** with push state updates (`home-assistant-js-websocket`
  is a small MIT library that could be vendored inline) — real-time without polling,
  but depends on M4.1's render fix landing first
- Frigate cameras can embed via MJPEG/snapshot endpoints; richer streams (WebRTC via
  go2rtc) are heavier
- **Serving the dashboard from HA itself** (`/config/www/` → `/local/earl/index.html`)
  would give it a permanent same-network origin — removes the `file://` vs `npx serve`
  split for good, and every LAN device + OAuth redirect gets one stable URL

Open-source references to draw patterns from (not dependencies):
- `home-assistant/frontend` (Lovelace) — entity/card interaction patterns
- Mushroom cards / button-card — the compact control-tile aesthetic
- Dashy, Homarr, Glance — home-lab dashboard layout/grouping patterns

Candidate scope (interview will decide): entity control tiles (lights/switches/scenes),
live state push, camera snapshot cards, climate/media controls, entity browser for
adding cards without typing entity IDs.

## Milestone 7 — Backend Companion (optional) 🖧 ✅ DONE

*Architect verdict: reasoning holds ("3.5 of 4" — the ChatGPT unlock applies only to
API-key accounts, not consumer Plus; NOTES.md corrected accordingly). Effort: M server,
S dashboard-side. Gated on user decision; M6's hosting answer may supersede parts.*

Minimal shape (~150 lines, `node server.mjs`, loopback-only):
1. Static-serve `index.html` → stable origin, no more two-modes split
2. `GET /proxy/<provider>/<path>` → strict host allowlist, secrets from gitignored file (OpenAI API-key usage, Plaid)
3. `POST /token/<provider>/refresh` → refresh-token vault (Fitbit 8h, TikTok 24h)

Rules: optional and additive (blank `backendBaseUrl` = today's behavior); localStorage
stays the source of truth — the server is a vault + proxy, never the storage layer.

## Milestone 8 — Home Lab Security Monitoring 🛡️ ✅ DONE

*Continuous self-assessment of the user's own network, surfaced as dashboard cards.
Hard dependency on M7: a browser cannot run `nmap`, `nuclei`, or read system logs — every
card here is the dashboard rendering JSON that the M7 backend produces. Effort: L.*

**Scope: the user's own home lab and devices only.** Every scan target is LAN-local and
owner-operated.

Candidate cards (all read-only assessment / monitoring):

| Card | Source | Metric shape |
|---|---|---|
| New device on network | `arp-scan` diff vs. known-device inventory | count of unrecognized MACs (target 0) |
| Open-port drift | `nmap` port-state diff vs. a saved baseline | count of ports changed since baseline |
| Web service findings | `nuclei` against own hosts | findings by severity |
| TLS/cert expiry | direct TLS handshake per host | days until soonest expiry |
| IoT firmware inventory | device APIs / HA device registry | devices behind latest firmware |
| Default-credential check | own-device auth probes against a known-default list | devices still on factory credentials |
| DNS anomalies | Pi-hole query log | blocked-domain spikes, new upstream destinations |
| Auth failures | `journalctl` / auth log parse | failed logins per hour |
| IDS alerts | Suricata / Zeek | alerts by severity |

Fits the existing card model cleanly — each is a number against a threshold, and most
should read "0 is healthy," which is exactly the `direction:` work landing in M3.1.

Note on scope boundaries: cards that would run *active exploitation or payload delivery*
(e.g. Metasploit `exploit` runs, C2 beacons, credential spraying) are deliberately not
pre-scoped here. That's normal purple-team work, but each one wants a specific decision
about what's being validated rather than a blanket "add offensive tooling" line item —
so those get added individually on request.

---

## Recommended execution order

**~~M1~~ → ~~M2~~ → ~~M3~~ → ~~M4~~ → ~~M5~~ → ~~M6~~ → ~~M7~~ → ~~M8~~** — **all milestones complete.**

M1 first is non-negotiable (active credential loss + fabricated numbers + unrecoverable
storage). M2 is an afternoon. M3/M4 fix what users see. M5 pays for itself the moment
M6 starts adding entity-control account types. M6/M7 shaped by interview answers. M8 is
last because it is entirely gated on M7's backend existing.

## Deferred / rejected by audit

- Storage-key bump to `.v2` — **explicitly rejected**: silently abandons saved credentials
- Framework adoption — out of scope per constraints
- Plaid without a backend — structurally impossible, stays in M7
