# mcpecho

A development MCP server over Streamable HTTP. Its `echo` tool returns the caller's identity as
the gateway forwarded it: `X-ANS-Name` and, for an instance-mode caller, `X-ANS-JKT`,
`X-ANS-Instance-Sub`, `X-ANS-Act` and `X-ANS-Scope`. Its `secret` tool exists to be denied by the
gateway's `mcpAuthorization` rules.

```bash
go run ./examples/mcpecho --listen 127.0.0.1:3001
```

## Instance mode

`ans-authz-instance.yaml` admits local agent instances that hold only a P-256 key, alongside
callers with their own ANS identity certificate. Run it with the MCP gateway recipe:

```bash
go run ./examples/mcpecho --listen 127.0.0.1:3001
bin/ans-authz --config examples/mcpecho/ans-authz-instance.yaml
agentgateway -f examples/agentgateway/config-mcp.yaml
```

Before you start it, set four values in `ans-authz-instance.yaml`:

- `allowedIssuers`: your issuer's host.
- `issuers`: for that host, the issuer's ANS agent id and the `transparencyLogs` entry that serves
  its status token. The verifier fetches `<baseURL>/v1/agents/<agentId>/status-token` at startup
  and every `maxStatusAge`/2 (two minutes for the shipped 240 s), so a revoked issuer's instances
  are refused within `maxStatusAge` plus the TL's publish delay, whatever status token a client
  sends.
- `expectedAud`: the host your clients mint tokens for.
- `transparencyLogs`: the log that signs the issuer's status token.

If the TL cannot be reached at startup, `ans-authz` still starts, logs the issuer, and refuses
its instance requests (`status_stale`) until a background fetch succeeds.

A version bump or re-registration gives the issuer a new agent id, and the TL then answers `410`
for the old one, so its instances are refused. Update `issuers[].agentId` to the new id and
restart `ans-authz`; the log names the issuer's host and the agent id the TL refused.

The `mcpAuthorization` rule in `config-mcp.yaml` matches `extauthz.ans_name`. For an instance
caller, `ans_name` is the issuer's ANS name, so name the issuer there.

`echo` then reports `X-ANS-Instance-Sub` (the user), `X-ANS-JKT` (the instance key) and
`X-ANS-Act` (the actor, for a child token). An upstream attributes each call to one instance by
`X-ANS-JKT`, or by `act.sub` in `X-ANS-Act`.

The token format, the order of the checks and every reason code are described in the top-level
README, under "Instance mode".
