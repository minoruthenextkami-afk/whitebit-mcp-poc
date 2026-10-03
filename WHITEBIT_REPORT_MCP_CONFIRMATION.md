# WhiteBIT MCP Server — Financial-Operation Confirmation Gate Is Advisory Only, Not Enforced Server-Side

**HackenProof 9-field report — program "WhiteBIT"**

---

## 1. Title

WhiteBIT MCP server (`whitebit-mcp` v1.1.0) — the advertised two-step "preview then confirm" gate for withdrawals, transfers, order placement and sub-account API-key issuance is enforced only as prompt text, not server-side. `confirmed=true` in a single tool call executes the operation.

## 2. Severity

**Medium** (proposed).

Rationale for not claiming High: exploiting this requires the attacker to already be able to influence the input context of an LLM client that holds a valid WhiteBIT API key. It does **not** by itself grant access to an account, API key, or funds — an attacker who already holds the API key can call the REST API directly. It is therefore a *broken/missing security control* with a credible indirect-prompt-injection path to fund loss, not an authentication bypass.

Suggested mapping to WhiteBIT's published reward table: *"Other vulnerability with clear potential for financial or data loss — up to $500."*

## 3. Affected asset / endpoint

| Item | Value |
|---|---|
| Host | `https://mcp.whitebit.com/mcp` |
| Service | `whitebit-mcp` v1.1.0 (JSON-RPC 2.0 / MCP Streamable HTTP) |
| Source | `https://github.com/whitebit-exchange/whitebit-mcp` (Apache-2.0, created 2026-02-03) |
| Docs | `https://docs.whitebit.com/guides/mcp-server` |
| In-scope mapping | Subdomain of `whitebit.com`. WhiteBIT's own Bug Bounty Policy (`whitebit.com/terms/bug-bounty-policy`) lists **`whitebit.com`** as a resource available for vulnerability detection. |
| Affected tools | 37 tools exposing a `confirmed` flag, of which 36 do **not** require it — see §4 |

Representative high-impact tools: `main_account__withdraw`, `main_account__transfer`, `spot__create_market_order`, `spot__create_limit_order`, `collateral__create_market_order`, `sub_account__transfer`, `sub_account__create_api_key`, `sub_account__reset_api_key_secret`, `codes__create_code`.

## 4. Description

### 4.1 The documented control

On `initialize`, the server returns its own agent instructions, which state a mandatory two-step confirmation flow for all financial operations:

> **Global rules (always apply, regardless of which skill is active):**
> Financial operations (placing/cancelling/modifying orders, withdrawals, transfers) use a two-step confirmation flow:
> 1. Call the tool WITHOUT `confirmed=true` to get a parameter preview (no funds move).
> 2. Show the user the parameters and ask for explicit approval.
> 3. After approval, call again WITH `confirmed=true` to execute.

### 4.2 What is actually enforced

`confirmed` is declared in each financial tool's JSON Schema as:

```json
"confirmed": {
  "description": "Set to true to confirm and execute this financial operation",
  "type": "boolean"
}
```

It is **optional** — absent from `required` in every affected tool. Critically, there is **no server-issued artefact** binding a step-1 preview to a step-2 execution: no `preview_id`, no nonce, no confirmation token, no server-side session state. The server cannot distinguish a call that follows a genuine human approval from one that was injected.

### 4.3 The contrast that proves intent and the gap

`convert__confirm` is the one financial tool that *does* bind the two steps server-side:

```json
{ "properties": { "confirmed": {...}, "query_id": {
    "description": "Query ID returned from convert__estimate", "type": "string" } },
  "required": ["query_id"] }
```

`convert__estimate` issues the `query_id`; `convert__confirm` will not act without it. So the codebase demonstrably knows how to implement server-enforced preview→execute binding — and does so for conversions — but every other financial tool accepts a bare client-supplied boolean.

The result: **a single `tools/call` carrying `confirmed=true` is sufficient to execute a withdrawal, transfer, order, or API-key issuance.** The "user approval" step exists only as English text aimed at the LLM. It is a behavioural instruction, not an access control.

### 4.4 Concrete attack path

The same server ships tools that pull **attacker-influenceable third-party content** into the LLM context:

- `skill_sentiment` — "Fetches crypto news from CryptoPanic and scores market sentiment per coin traded on WhiteBIT."
- `skill_user_support` — ingests `help.whitebit.com` / `docs.whitebit.com` content.

A user who has connected their API key to an AI client running this MCP server, and who asks the agent to analyse a coin, can have hostile instructions injected via that news/support content. Because the confirmation gate is advisory, a single injected `main_account__withdraw` call with `confirmed=true` moves funds with **no prompt to the user and no server-side gate** — even though the user believes, from the server's own instructions, that they are protected by a mandatory approval step.

## 5. Steps to reproduce

All of the following is unauthenticated and read-only.

```bash
# 1. initialize with NO credentials
curl -s -D headers.txt -X POST https://mcp.whitebit.com/mcp \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  -d '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{
        "protocolVersion":"2024-11-05","capabilities":{},
        "clientInfo":{"name":"poc","version":"1.0"}}}'
# => HTTP 200, mcp-session-id issued. Read the "instructions" field (§4.1).

SID=$(grep -i '^mcp-session-id' headers.txt | tr -d '\r' | awk '{print $2}')

# 2. enumerate all tools with NO credentials
curl -s -X POST https://mcp.whitebit.com/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H "mcp-session-id: $SID" \
  -d '{"jsonrpc":"2.0","id":2,"method":"tools/list"}'
# => HTTP 200, 99 tools returned

# 3. observe that "confirmed" is optional on every financial tool
curl -s -X POST https://mcp.whitebit.com/mcp \
  -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' \
  -H "mcp-session-id: $SID" \
  -d '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{
        "name":"main_account__withdraw","arguments":{}}}'
# => "required": ["ticker","amount","address","unique_id"]   <-- "confirmed" NOT required
```

Automated version (produces the full 37-tool table): `poc_mcp_confirmation_bypass.py`.

### 5.1 Completing the proof on your own account

I did **not** execute a financial operation — I hold no account and did not touch funds. To close the loop, use a dedicated sub-account holding a trivial amount, exactly as WhiteBIT's own *"Safe account practices"* section recommends:

```bash
export WB_KEY=... WB_SECRET=... WB_ADDRESS=<your own address>
export WB_TICKER=USDT WB_AMOUNT=1 WB_NETWORK=TRC20
RUN_LIVE=1 python3 poc_mcp_confirmation_bypass.py
```

This issues **one** `main_account__withdraw` with `confirmed=true` and **no prior preview call**. A completed withdrawal demonstrates the missing gate directly.

## 6. Impact

- The control WhiteBIT tells its own users protects them ("ask for explicit approval") **provides no actual protection**. It is enforced only by the honesty of the LLM in the loop.
- A user with a live, funded API key is one indirect prompt injection away from an unattended, unreviewed withdrawal — via the server's own `skill_sentiment` / `skill_user_support` news and help-centre ingestion paths.
- Blast radius includes withdrawals, main↔trade transfers, sub-account transfers, live order placement, and **creation or secret-rotation of sub-account API keys** (`sub_account__create_api_key`, `sub_account__reset_api_key_secret`) — so an attacker may be able to escalate from "spend funds" to "mint persistent API credentials".
- Trust impact: the documented safeguard is inaccurate, which is worse than having no safeguard, because it changes user behaviour.

## 7. Proof of concept

- Script: `poc_mcp_confirmation_bypass.py` (self-contained, stdlib only, runs as-is).
- Safe by default: it performs `initialize`, `tools/list`, one public `server__ping`, and one *account-scoped read* with no credentials to locate the auth boundary. It never calls a financial tool.
- Live single-call execution is hard-gated behind `RUN_LIVE=1` plus operator-supplied credentials.

**Verified output (2026-10-03):**

```
[1] initialize (no credentials)  -> HTTP 200   serverInfo: {'name':'whitebit-mcp','version':'1.1.0'}
[2] tools/list (no credentials)   -> HTTP 200  (99 tools)
[3] financial tools exposing a 'confirmed' flag: 37
    'confirmed' OPTIONAL : 37
    'confirmed' REQUIRED : 0
    tools binding a server-issued token to execution: ['convert__confirm']
[4a] server__ping (no creds)                   -> HTTP 200 : ["pong"]
[4b] main_account__get_custom_fee (no creds)   -> 401 This action is unauthorized.
```

Note on scope honesty: `mcp.whitebit.com` returns `401` for every account-scoped tool, so **no unauthorised account access was obtained**. This report does not claim otherwise.

## 8. Remediation

Make the confirmation gate a server-side control rather than a prompt instruction:

1. **Issue a server-side confirmation token.** On a call without `confirmed=true`, generate and return an opaque `preview_id` bound to the exact normalised parameters plus the authenticated principal, with a short TTL. Require that `preview_id` (not a boolean) to execute — mirroring what `convert__confirm` already does correctly with `query_id`.
2. **Bind the token to parameters.** Reject execution if the submitted parameters differ in any material field from the previewed set, so an approved preview cannot be swapped for a different destination or amount.
3. **Require affirmative opt-in per operation.** Treat `confirmed` as opt-in rather than opt-out, and default it to a non-executing preview.
4. **Add limits independent of confirmation.** Per-call and per-session notional caps, destination allowlists, and a cooling-off window for first-time withdrawal destinations.
5. **Reduce blast radius by default.** Recommend (and ideally default to) read-only API keys and dedicated, minimally-funded sub-agents for agentic access.
6. **Treat ingested third-party content as untrusted.** Delimit and label `skill_sentiment` / `skill_user_support` output as data, never instructions, so it cannot carry directives back into the tool-calling loop.
7. **Fix the documentation/config drift.** See the secondary observation below.

## 9. Classification and references

- **CWE-602:** Client-Side Enforcement of Server-Side Security (the control exists only in the client/LLM).
- **CWE-693:** Protection Mechanism Failure.
- **Related:** CWE-284 Improper Access Control (missing server-side authorisation for a privileged operation).
- Weakness class: *Prompt-injection-driven abuse of an unenforced confirmation gate in an MCP server exposing exchange funds.* The same class has been reported against other exchange MCP servers — e.g. finding SAR-04 in the bnbchain-mcp security audit, *"Financial tools lack transfer limits, confirmation, and rate limiting"* (Medium) — and unauthenticated MCP deployments are tracked as CVEs (e.g. CVE-2026-49257, mcp-pinot, for a different confused-deputy variant).
- **Duplicate check:** searched public disclosures and WhiteBIT's published channels; no existing disclosure of this confirmation-gate weakness on `mcp.whitebit.com` was found. Note WhiteBIT's policy — reward goes to the first reporter.

---

## Appendix A — Secondary observation (separate report or a note, not a bounty claim)

`https://mcp.whitebit.com/mcp` deviates from WhiteBIT's own documented behaviour. `https://docs.whitebit.com/guides/mcp-server` states:

> "On the HTTP transport the `/mcp` endpoint still answers `401` to a connection that carries no credentials at all, so the client must be configured with keys even for public data."

Observed on the hosted instance: `initialize`, `tools/list`, `resources/list`, `resources/read` and public tools such as `server__ping` all succeed with **zero** credentials, and the complete privileged tool surface — 37 financial tools with full parameter schemas, including `sub_account__create_api_key` — is enumerable anonymously.

**I am not claiming this as a bounty-eligible finding.** No account access, no data disclosure, and no privilege gain results: every account-scoped call returns `401`. It is worth fixing for config hygiene, since the MCP server is documented as *self-hosted / "Runs locally — API keys never leave the machine"*, and shipping a publicly reachable instance both widens the reconnaissance surface for anyone targeting WhiteBIT API keys and contradicts the documented `401` behaviour. Raised here for completeness because the drift is what made this finding reachable without any credential at all.
