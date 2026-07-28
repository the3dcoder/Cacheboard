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

## Open problem this does NOT solve

**Access tokens expire.** Profile credentials hold a session access token that
dies after roughly 8–12 hours. Verified on 2026-07-28: `max20` and the default
profile both returned `401 — token rejected` after ~11 hours, and running
`claude auth status` did **not** rewrite the credentials file (mtime unchanged
at `02:01:19` before and after), so a status check does not force a refresh.

Two candidate fixes, in order of preference:

1. **`claude setup-token`** — mints a long-lived token by design. Store it as
   `CLAUDE_TOKEN_<NAME>`. Unverified: it may be scoped for inference only and
   rejected by `/api/oauth/usage`. Test on one account before doing all three.
2. **Refresh in the server** — the credentials file carries a refresh token,
   and the OAuth `client_id` is visible in the authorize URL
   (`9d1c250a-e61b-44d9-88ed-5944d1962f5e`). Would need the token endpoint,
   which is not documented; the refreshed token could be held in memory since
   the mount is read-only. More work, but removes the expiry problem entirely.

Until one of these lands, plan-limit cards go stale overnight and need a
re-sign-in — which is not acceptable as a steady state.
