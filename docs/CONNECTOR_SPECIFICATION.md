# SKYLA PRIME — Connector Specification (PRIME CONNECT)

## Contract

Every connector implements: `name`, `display_name`, `capabilities`,
`auth`, `mode` (`live`|`mock`), `detail`. Connectors without credentials
run in **explicit mock mode** with fixture data — never labeled live.

## Implemented connectors

| Connector | Capabilities | Auth | Status |
|---|---|---|---|
| Gmail | search, read, draft reply, summarize | OAuth2 refresh token | Mock (live-ready) |
| Google Calendar | list, availability, create, invite, find slots | OAuth2 refresh token | Mock (live-ready) |
| Telegram | send message, commands, notifications | Bot token | Mock (live-ready) |

## Live enablement

- **Google (Gmail/Calendar):** create a Google Cloud OAuth client, complete
  the consent flow once, store the refresh token as `GOOGLE_REFRESH_TOKEN`
  with `GOOGLE_OAUTH_CLIENT_ID/SECRET`. Scopes: `gmail.readonly`,
  `calendar` (or narrower as needed).
- **Telegram:** create a bot via @BotFather, set `TELEGRAM_BOT_TOKEN`.

## Roadmap (Phase 3 order)

Outlook → Zoom/Google Meet → Google Drive → Slack/Teams → GitHub → Notion →
HubSpot/Salesforce. Each connector must pass the acceptance suite in
docs/BENCHMARK_STRATEGY.md §Integration acceptance before being marked live.

## Safety rules

- Writes require autonomy Level 2+; sends require explicit authorization.
- Idempotency keys required for non-idempotent provider operations
  (Phase-3 hardening).
- Provider confirmation ≠ business completion: workflows report the exact
  provider state (e.g. `draft-prepared-not-sent` in mock mode).
