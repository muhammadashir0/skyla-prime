# Outbound Connection Inventory — v0.2.3 Mission 1

Every outbound network operation in the repository, enumerated before any code was changed.

**Headline finding: there were eleven independent `httpx.AsyncClient(...)` constructions and not one passed `proxy=`. Nothing in the application ever set `HTTPS_PROXY`.** The egress proxy existed as a module and a document; no application code used it. Every operation below therefore dialled the internet directly.

- Audited at: `a3bf461`, remediated at `5bace07`
- Method: import graph + `grep -rn "httpx\|socket\|subprocess"`, then each site read individually

---

## 1. Inventory

| # | Operation | Source file | Calling service | Process | Destinations | Mechanism | Auth | Network path **before** | Path **after** | Required permitted destinations |
|---|---|---|---|---|---|---|---|---|---|---|
| 1 | Web research / URL retrieval | `skyla/knowledge/research.py:38` (`fetch_url`) | `workflow_research`, `research.fetch_url` | API | any http(s) URL, 3 redirect hops | `httpx.AsyncClient` (was) → `egress_client("research")` | none | **direct** | gateway, policy `research` | `*.wikipedia.org`, `wikipedia.org`, `example.com`, `*.example.com`, `pypi.org`, `files.pythonhosted.org` |
| 2 | Model provider health check | `skyla/models/http_provider.py:58` (`health_check`) | `GET /api/providers/health` | API | `{base_url}/models` | `httpx` → `egress_client("model-provider")` | `Bearer <api_key>` | **direct** | gateway, policy `model-provider` | `api.openai.com`, `api.deepseek.com`, `dashscope.aliyuncs.com`, `api.z.ai` |
| 3 | Model chat completion | `skyla/models/http_provider.py:88` (`chat`) | `Orchestrator`, every agent | API | `{base_url}/chat/completions` | `httpx` → `egress_client("model-provider")` | `Bearer <api_key>` | **direct** | gateway, policy `model-provider` | same as #2 |
| 4 | Model inference — custom endpoint | `skyla/models/router.py:57` | `ModelRouter` | API | `SKYLA_CUSTOM_BASE_URL` (operator-supplied, e.g. local vLLM) | `httpx` → `egress_client("model-provider")` | `Bearer <custom_api_key or "local">` | **direct** | gateway, policy `model-provider` | **operator must add the host to the policy** — see §3 |
| 5 | OAuth token refresh (Gmail) | `skyla/integrations/gmail.py:42` (`_access_token`) | Gmail connector | API | `oauth2.googleapis.com/token` | `httpx` → `egress_client("connector-google")` | `client_id`, `client_secret`, `refresh_token` | **direct** | gateway, policy `connector-google` | `oauth2.googleapis.com` |
| 6 | Gmail search | `skyla/integrations/gmail.py:57` (`search`) | `workflow_inbox`, gmail connector | API | `gmail.googleapis.com/gmail/v1/users/me/messages` | `httpx` → same | `Bearer <access_token>` | **direct** | same | `gmail.googleapis.com` |
| 7 | Gmail draft | `skyla/integrations/gmail.py:77` (`draft_reply`) | `POST /api/workflows/gmail/draft` | API | `gmail.googleapis.com/.../drafts` | `httpx` → same | `Bearer <access_token>` | **direct** | same | `gmail.googleapis.com` |
| 8 | OAuth token refresh (Calendar) | `skyla/integrations/calendar.py:33` (`_access_token`) | Calendar connector | API | `oauth2.googleapis.com/token` | `httpx` → same | refresh token | **direct** | same | `oauth2.googleapis.com` |
| 9 | Calendar list events | `skyla/integrations/calendar.py:52` (`list_events`) | `workflow_meeting` | API | `www.googleapis.com/calendar/v3/...` | `httpx` → same | `Bearer` | **direct** | same | `www.googleapis.com` |
| 10 | Calendar create event | `skyla/integrations/calendar.py:69` (`create_event`) | Calendar connector | API | `www.googleapis.com/calendar/v3/...` | `httpx` → same | `Bearer` | **direct** | same | `www.googleapis.com` |
| 11 | Telegram send message | `skyla/integrations/telegram.py:32` (`send_message`) | `workflow_telegram_command` | API | `api.telegram.org/bot<token>/sendMessage` | `httpx` → `egress_client("connector-telegram")` | bot token in URL | **direct** | gateway, policy `connector-telegram` | `api.telegram.org` |
| 12 | Telegram `getMe` | `skyla/integrations/telegram.py:42` (`get_me`) | connector registry | API | `api.telegram.org/bot<token>/getMe` | `httpx` → same | bot token | **direct** | same | `api.telegram.org` |
| 13 | Connector registry metadata | `skyla/integrations/registry.py` | `GET /api/connectors` | API | none | — | — | no network | — | — |
| 14 | Untrusted Python execution | `skyla/execution/workload.py:224` | `POST /api/execute/python` | child, `unshare -Urmpf -n` | none possible | `subprocess.Popen` | — | **already isolated** (no interfaces, seccomp denies `socket()`) | unchanged | none |
| 15 | Legacy sandbox runner | `skyla/execution/sandbox.py:31` | provider `local` | child | none | `subprocess.run` | — | inherits host network — **see §4** | unchanged | none |
| 16 | Provider subprocess | `skyla/execution/providers.py:89` | namespace provider | child | none | `subprocess.run` | — | `unshare -n` wrapper | unchanged | none |
| 17 | Perimeter commands | `skyla/perimeter.py:141` | setup/verify | root helper | none | `subprocess.run` (`ip`, `iptables`) | root | host netns (admin only) | unchanged | — |
| 18 | SQLite | `skyla/db.py` | everything | API | file only | `sqlite3` | — | no network | — | — |

**No connector webhooks or inbound callbacks exist.** Telegram is polled/sent, not received; there is no HTTP listener for provider callbacks. Checked: no `@app.post` route is provider-facing.

## 2. Shared client, or not?

**Not shared — that was the defect.** Each of the eleven sites constructed its own client with its own timeout (15 s health, 30 s connectors, 120 s chat, `research_timeout_s`). This mattered in three ways:

1. No single place to apply a proxy, so no proxy was applied.
2. No single place to apply a policy, so every call was unpoliced.
3. Divergent timeouts and redirect handling meant a fix at one site would not have covered the others.

All eleven now go through `skyla/egress_client.client()`. A twelfth added tomorrow will too, or it will be refused a client — see `API_NETWORK_ISOLATION_DESIGN.md`.

## 3. Compatibility limits an operator must know

- **Custom model endpoints (#4) are not in any policy.** `SKYLA_CUSTOM_BASE_URL` points at an operator-chosen host (typically a LAN address such as `http://10.0.0.5:8000/v1`). Under the perimeter two independent controls block it: the policy has no entry, and `netguard` rejects private addresses. **An operator using a custom endpoint must add the host to the `model-provider` policy and consciously decide about the private-address rule.** This is a real deployment constraint, not an oversight; it is documented rather than silently allowed.
- **Telegram sends the bot token in the URL path.** The proxy sees the full target for `CONNECT` targets but rewrites nothing. The token is therefore visible in the proxy's audit record for `api.telegram.org` — the audit stores host and port, not the path, so the token is not persisted. Verified in `Decision` construction: only `host`, `port`, `method` are recorded.
- **Gmail/Calendar share one capability.** They are the same OAuth client and the same Google API family; splitting them would add policy entries without adding a boundary.

## 4. One gap found and not fixed

`skyla/execution/sandbox.py` (`local` provider) runs a child process that **inherits the host network namespace**. It is not the default (`SKYLA_EXECUTION_PROVIDER=namespace`), and `workload.py` is the isolated path. It is listed here because an audit that silently omitted it would be incomplete.

Not fixed in this milestone: changing the fallback provider's networking is outside B-01's boundary and would alter an execution contract other tests depend on. Recorded as an open item in `B01_REMEDIATION_EVIDENCE.md` §7 rather than quietly enclosed.

## 5. Verification

The inventory was produced before remediation and then re-derived afterwards. Both passes agree on 18 rows; the "network path" column is the only difference, and every "direct" became "gateway". The `grep` used:

```bash
# Before: 11 constructions across 6 application modules.
# After:  3, all inside skyla/egress_client.py — the transport-injection path
#         and the legacy path, both of which cannot reach a proxy-less socket
#         in enforce mode. Zero remain in application modules.
grep -rn "httpx.AsyncClient(\|httpx.Client(" --include=*.py skyla/ | wc -l   # 3
grep -rn "httpx.AsyncClient(\|httpx.Client(" --include=*.py skyla/integrations \
     skyla/knowledge skyla/models                                    # empty
grep -rn "trust_env\|proxy=" --include=*.py skyla/ | grep -v egress_client  # empty
grep -rn "subprocess\." --include=*.py skyla/ | wc -l                        # 15
```

The 15 subprocess sites cover rows 14–17 (workload launch and termination,
provider wrappers, sandbox runner, perimeter commands). They are counted, not
individually tabulated, because only `sandbox.py` has an inherited-network
concern and that row is called out in §4.
