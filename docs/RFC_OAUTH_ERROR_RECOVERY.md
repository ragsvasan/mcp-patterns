# RFC: OAuth Error State Recovery for MCP Connectors

> **File location:** `docs/RFC_OAUTH_ERROR_RECOVERY.md` in `mcp-patterns` repo  
> **Gap #:** 6  
> **Status:** Draft — ready to pitch  
> **Date:** 2026-04-20  
> **Discovered in:** Production MCP server on Claude.ai

---

## Problem

MCP clients record a connector as "authorization failed" when an OAuth error callback is received. The MCP spec defines the OAuth authorization flow but says nothing about what a client should do next: how long to retain the error state, whether to offer a retry path, or how a server can signal that it is now healthy. Every client implements its own error state management with no interoperability guarantee for developers.

---

## Real-World Scenario

We operate a production MCP server. A temporary OAuth routing misconfiguration caused our server to return an error at the authorization callback. Our MCP client recorded the connector as failed.

Once we corrected the server-side routing, the connector remained stuck. Clicking "Connect" no longer opened a popup to our server's authorization endpoint — instead the client routed through its own session cache, found the recorded failure, and took no further action. The only resolution was removing the connector entirely and re-adding it from scratch.

That workaround required two destructive operations (losing any customizations on the connector) instead of one non-destructive "Re-authorize" click. The server was healthy; the client had no spec-defined mechanism to discover this.

---

## What the Spec Currently Says

The MCP authorization specification (2025-03-26) fully defines the OAuth 2.1 authorization flow for initial connector setup. It does not define:

- **Connector lifecycle states:** there is no standard enumeration of states a connector can be in (connected, failed, expired, revoked)
- **Error persistence:** how long a client should retain an authorization failure before considering it stale
- **Recovery semantics:** what actions a client must expose when authorization has failed
- **Server recovery hints:** no mechanism for a server to signal "I'm now healthy — please retry"

Result: each MCP client (Claude.ai, VS Code, Cursor, Windsurf, etc.) independently implements error state management. Developers have no predictable recovery path across clients.

---

## Related Issues

- **#2349** "Clarify client-side scope accumulation behaviour during step-up authorization" (CLOSED) — adjacent: covers scope accumulation during step-up flows but does not address persistent error states or re-authorization paths
- **#1939** "Define behavior when Last-Event-ID is unresumable (unknown/expired/wrong session)" (OPEN) — same class of problem: stale client-side state with no spec-defined recovery path
- **#2173** "Add server-side lifecycle state machine and gating rules to Lifecycle docs" (CLOSED) — server lifecycle is now documented; client-side OAuth connector lifecycle remains undefined

**Status: NOVEL** — No existing spec issue directly addresses OAuth error state recovery for connectors.

---

## Proposed Spec Changes

### 1. Connector State Model

Define a standard set of connector states that all MCP clients MUST implement:

```
DISCONNECTED ──► AUTHORIZING ──► CONNECTED
                      │
                      ▼
                 AUTH_FAILED ──► [retry] ──► AUTHORIZING
                      │
                      ▼
                 [force_reauthorize] ──► AUTHORIZING (clears cached failure)
                      │
                      ▼
                 [remove] ──► DISCONNECTED (destructive)
```

**State definitions:**

| State | Meaning |
|---|---|
| `DISCONNECTED` | No authorization attempt made, or connector manually removed |
| `AUTHORIZING` | OAuth flow in progress (popup open or callback pending) |
| `CONNECTED` | Valid access token held; tool calls can proceed |
| `AUTH_FAILED` | Authorization attempt returned an error; no valid token |

Transitions:
- `AUTH_FAILED → AUTHORIZING`: via "Re-authorize" or "Retry" — clears cached failure, restarts OAuth from the server's authorization endpoint
- `AUTH_FAILED → DISCONNECTED`: via "Remove" (destructive, user-initiated)
- `CONNECTED → AUTH_FAILED`: on 401/403 from tool call, or explicit error callback

---

### 2. Server: `retry_after` Error Hint

Allow servers to return a recovery hint in the OAuth error response body:

```json
{
  "error": "access_denied",
  "error_description": "OAuth routing error — please retry authorization",
  "retry_after": 0
}
```

**Semantics:**
- `retry_after: 0` — server believes it is healthy; client SHOULD offer immediate re-authorization
- `retry_after: N` (seconds) — server is temporarily unavailable; client SHOULD suppress retry UI until N seconds have elapsed
- Omitted — no hint; client uses its own retry policy

This mirrors the pattern established in HTTP 429/503 responses and RFC 6749's existing `error_description` field. No new fields are required beyond `retry_after`.

**Client behavior:**
- If `retry_after: 0` is present in the error response, the client SHOULD surface a "Re-authorize" prompt immediately (not just "Remove")
- If `retry_after: N` is present, the client MAY show the remaining wait time in the connector status UI

---

### 3. Client: Required Re-authorize Action

When a connector is in `AUTH_FAILED` state, clients MUST expose a "Re-authorize" (or equivalent) action that:

1. Clears the `AUTH_FAILED` state (does not remove connector configuration or customizations)
2. Restarts the OAuth flow from the server's authorization endpoint — not from a cached session check
3. On success, transitions to `CONNECTED`
4. On failure, returns to `AUTH_FAILED` (with updated error)

**Implementation note:** The re-authorize flow must initiate a fresh popup/redirect to `authorization_endpoint`, not reuse a stored session or cached token. The goal is to give the user a path to recovery that does not require removing the connector.

**This is required** because without it, any server-side fix is invisible to users until they discover the remove-and-re-add workaround — which is not documented in the spec or in any standard client UI.

---

### 4. Error State TTL

`AUTH_FAILED` state SHOULD expire after a client-defined TTL. Suggested default: **24 hours**.

When the TTL expires:
- Connector transitions from `AUTH_FAILED` to `DISCONNECTED`
- User is notified that the connector needs re-authorization
- No destructive operations occur (connector configuration is preserved)

**Rationale:** A connector that failed authorization due to a transient server misconfiguration should not be permanently blocked. A 24-hour TTL ensures that server-side fixes eventually surface to users even if they never manually retry.

Clients MAY allow users to configure or disable the TTL. Clients SHOULD store the TTL expiry timestamp persistently (survives app restarts).

---

## Reference Implementation

We encountered this scenario operating a production MCP server on Claude.ai. The fix required:

1. Remove the connector (destroys connector customization)
2. Re-add the connector from scratch
3. Re-authorize (new OAuth flow)

A spec-compliant client with "Re-authorize" would have resolved this in a single click after the server-side fix landed.

We have documented the pattern and can contribute a reference implementation to https://github.com/ragsvasan/mcp-patterns as an addition to the existing OAuth pattern collection.

---

## Impact Assessment

| Party | Current | With This Change |
|---|---|---|
| Server developers | Cannot signal "retry" to client; must wait for users to find remove + re-add | Can set `retry_after: 0` to surface re-authorization immediately |
| Client developers | No spec guidance on error state lifecycle or required UI | Clear state machine + required "Re-authorize" action to implement |
| End users | Only recovery path is destructive (remove + re-add connector, lose customizations) | Non-destructive re-authorization; predictable behavior across all MCP clients |

---

## Open Questions

1. **State persistence format:** Should the connector state model define a standard serialization (JSON schema) that clients persist locally? Or is the state machine sufficient without mandating a wire format?
2. **`retry_after` in OAuth callbacks:** The `retry_after` field is proposed for the error response body. Should it also appear as an HTTP header (matching 429 semantics) for clients that inspect headers before parsing body?
3. **TTL default:** Is 24 hours the right default? Some enterprise environments may prefer a shorter TTL (e.g., 1 hour) for security reasons. Should the server be able to suggest a TTL in the error response?
4. **Scope of "Re-authorize":** Should re-authorization reuse the existing `client_id` and registered redirect URI, or should it re-discover the authorization server from scratch? (Relevant if the server's OAuth metadata endpoint changed.)

---

## Contributing

We've submitted related MCP patterns (PII scrubbing, async timeout handling) to https://github.com/ragsvasan/mcp-patterns. We're prepared to:

- Contribute a reference implementation of the connector state model (client-side, framework-agnostic)
- Draft the spec language for the state machine and `retry_after` extension
- Pilot the `retry_after` field in our production server and document the results

Open to feedback on state model design, `retry_after` semantics, and TTL policy.

@localden @jspahrsummers — thoughts?
