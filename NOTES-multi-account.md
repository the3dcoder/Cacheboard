# Notes — running several Claude accounts on one PC

Research triggered by [claude-code#70665](https://github.com/anthropics/claude-code/issues/70665)
and the **Multi Instance for Claude Desktop** app
([Microsoft Store](https://apps.microsoft.com/detail/9ng247tj47p0)).

## What that app does

Third-party tool by Carlos De La Torre. Runs several **Claude Desktop**
instances side by side, each fully isolated:

- Own profile, session, account, and a **colour identifier**
- Dashboard UI to create / launch / delete instances — no CLI
- Technically: passes Electron's `--user-data-dir` per instance, copies the
  portable binary, and isolates MCP servers, config and auth tokens
- Windows only today; macOS planned via `open -n -a Claude --args …`
- Anthropic closed the underlying issue as **not planned**, so this stays a
  community solution

## Why it matters to us

**It validates the architecture we already chose.** `--user-data-dir` is the
Electron equivalent of `CLAUDE_CONFIG_DIR`, which is what our profiles use:

| | Desktop app | Our setup |
|---|---|---|
| Isolation switch | `--user-data-dir` | `CLAUDE_CONFIG_DIR` |
| Scope | Desktop GUI sessions | Claude Code CLI sessions |
| Result | N desktop windows, N accounts | N profiles, N accounts |

Both confirmed working on this machine simultaneously: the desktop app on one
account, the CLI default profile on a second, and the `max20` profile on a
third — no logging out.

**It also confirms a limitation is inherent, not our bug.** That app notes
*"each instance requires one-time manual sign-in"* because the `claude://`
protocol handler is registered globally. We hit the same wall: every account
needs one interactive browser sign-in, and no amount of scripting removes it.

## Worth borrowing

1. **Colour per identity.** The app gives each instance a colour. Our `owner`
   field is currently text only. Assigning a colour per owner and tinting the
   card border would make a mixed dashboard scannable at a glance — cheap to
   add, works with the existing owner pills.

2. **Profile management in Settings.** They have a dashboard for
   create/launch/delete. We could list detected profiles under
   `~/claude-profiles`, show which account each is signed into, and flag any
   whose token has expired.

3. **Launch action on a card.** A button that opens Claude Code in that
   account's profile:
   `$env:CLAUDE_CONFIG_DIR='…\max20'; claude`
   Turns the dashboard from read-only into a launcher. Only works when the
   dashboard is served locally, since a browser cannot start a process.

## Not worth borrowing

- Copying the binary per instance. Fine for Electron; pointless for us — the
  CLI already isolates cleanly on one binary via an env var.
- Bundling/distribution. Ours is a local dashboard, not a shipped app.

## Name profiles after the email, never the plan

The first pass named profiles `max20` / `max5` / `pro`. Checked on 2026-07-28,
every one of them was wrong: the profile called `max20` held the **Max 5x**
account, and the Max 20x account sat in the `default` profile. The CLI is no
help here — `subscriptionType` reported `"max"` for the 5x and `"pro"` for the
20x, so it does not distinguish the tiers and cannot be used to label anything.

Profiles are now named for the identity that owns them (`earl`, `bbpyderz`,
`ehayestrainer`), with the plan carried only as a display string in
`CLAUDE_LABEL_<NAME>`. Plans change; the email does not.

## Open problem this does NOT solve

**Access tokens expire.** Profile credentials hold a session access token that
dies after roughly 8–12 hours. Verified on 2026-07-28: two profiles returned
`401 — token rejected` after ~11 hours, and running `claude auth status` did
**not** rewrite the credentials file (mtime unchanged at `02:01:19` before and
after), so a status check does not force a refresh.

**`claude setup-token` is a dead end — tested, not assumed.** It mints a
long-lived token, but an inference-scoped one: `/api/oauth/usage` rejects it
with `403 — "OAuth token does not meet scope requirement user:profile"`. Do
not spend time on this route.

Remaining options:

1. **Refresh in the server.** The credentials file carries a refresh token and
   the OAuth `client_id` is visible in the authorize URL
   (`9d1c250a-e61b-44d9-88ed-5944d1962f5e`); the token endpoint is
   `https://api.anthropic.com/token`, from the provider's own
   `.well-known/oauth-authorization-server`. The refreshed token can be held in
   memory, since the mount is read-only. Removes the expiry problem entirely.
2. **Keepalive.** A scheduled task running one trivial CLI command per profile
   every ~6 hours, letting the CLI do its own refresh. No credential-handling
   code at all, at the cost of a background task.

Until one lands, plan-limit cards go stale overnight and need a re-sign-in,
which is not acceptable as a steady state.

## Unrelated failure worth recording

Cards showed `getaddrinfo ENOTFOUND api.anthropic.com` while the internet was
fine. Cause: the LAN router was the machine's only configured nameserver and
stopped answering on udp/53, so every lookup inside the container failed.
`docker-compose.yml` now sets `dns: [1.1.1.1, 8.8.8.8]`, which makes the
backend independent of the router. Symptom to recognise: a fetch error naming
DNS, with `Test-NetConnection <public-ip> -Port 443` still succeeding.
