# agentgateway recipes

Three agentgateway v1.6.0 configurations that authenticate callers with `ans-authz` over
Envoy ext_authz. Each was validated with `agentgateway --validate-only` against the pinned
release and is exercised by the end-to-end suite in `tests/agentgateway`.

| Gateway config | Verifier config | What it shows |
|---|---|---|
| `config-http.yaml` | `ans-authz.yaml` | HTTP route: body-bound DPoP proof, identity headers at the upstream, fail-closed denials |
| `config-mcp.yaml` | `ans-authz.yaml` | MCP listener: every MCP request authenticated, per-tool authorization on the verified ANS name |
| `config-oauth.yaml` | `ans-authz-oauth.yaml` | DPoP-bound OAuth access token validated by the gateway and bound to the proof key by the verifier |

## Run it

```bash
make run-example            # http recipe: echo upstream, ans-authz, agentgateway
make run-example EXAMPLE=mcp
```

The verifier config trusts the local ANS reference stack's transparency log at
`http://localhost:18081`; point `transparencyLogs[].baseURL` (or `rootKeys`) at yours. Then send
a signed request (a client built on the SDK's `pop.AttachIdentity`; `tests/agentgateway` shows
one) to `http://127.0.0.1:8080/echo` and read the `X-ANS-*` headers in the echoed request. A
request without identity gets `401` and `WWW-Authenticate: DPoP algs="ES256"`.

## The ext_authz block

```yaml
extAuthz:
  host: 127.0.0.1:9191            # the verifier; a shared service also needs policies.backendTLS
  failureMode:
    denyWithStatus: 503           # never `allow`
  includeRequestBody:
    maxRequestBytes: 1048576      # v1.6.0 defaults to 0, which rejects every request with a body
    allowPartialMessage: false
    packAsBytes: true
  protocol:
    grpc:
      context:
        ans-authz: body-forwarded # sentinel the verifier requires (requiredContext)
```

followed by `authorization: {rules: [{require: 'has(extauthz.ans_name)'}]}` so a route that
loses its ext_authz policy fails closed. Do not add an ext_authz `cache`: proofs are single-use.

The verifier's `trustedHosts` must list every authority agents sign for with the scheme they use
(`http://127.0.0.1:8080` for the local recipe); behind TLS termination set `externalAuthority`.

## MCP

`config-mcp.yaml` puts the same block on an `mcp` listener. ext_authz runs on every MCP request
(`initialize`, `tools/list`, `tools/call`), the `X-ANS-*` headers reach HTTP MCP targets, and
`mcpAuthorization` rules can use the verified identity:

```yaml
mcpAuthorization:
  rules:
  - 'extauthz.ans_name == "ans://v1.0.0.caller.example" && mcp.tool.name == "echo"'
```

Headers do not reach stdio targets; use the metadata rules there.

## OAuth composition

`config-oauth.yaml` adds a `jwtAuth` policy that validates an access token presented with the
`DPoP` scheme (`location: {header: {name: Authorization, prefix: "DPoP "}}`, `mode: strict`,
`preserveToken: true`) and forwards the validated claims to the verifier:

```yaml
protocol:
  grpc:
    context: {ans-authz: body-forwarded}
    metadata: {ans-authz: '{"jwt_payload": jwt}'}
```

The verifier (with `requireTokenClaims: true`, the default) compares the token's `cnf.jkt` with
the proof key and rejects a mismatch, a token without `cnf`, or a request where no claims were
forwarded. The expression is required: the verifier reads claims only from the namespace named
by its `grpc.tokenClaimsNamespace` (`ans-authz` here) and never from the Envoy `jwt_authn`
namespace agentgateway fills on its own, so a route that validates the token but omits the
expression is reported as `MISCONFIGURED` (503), exactly like one that validates no token at all.
The CEL rule
`has(jwt.cnf) && jwt.cnf.jkt == extauthz.jkt` is the second layer. A token presented as `Bearer`
is rejected by strict `jwtAuth` before the verifier runs. The `jwks.file` path resolves against
agentgateway's working directory. The shipped `jwks.rfc7515-a3.example.json` is the ES256 key
from RFC 7515 Appendix A.3, whose private half is published in the RFC: it exists so anyone can
mint a demo token (sign a JWT with that key, `cnf.jkt` set to the agent's proof-key thumbprint)
and must never trust production traffic.

## What is not covered

`run-example` and the e2e suite exercise agentgateway v1.6.0 only. The recipes leave the
ext_authz timeout at agentgateway's default budget of 2 s; `checkTimeout` (1500 ms) stays below
it. No Kubernetes manifests ship yet; the sidecar and shared-service topologies in the root README
describe the probes, mounts and TLS wiring to encode.

## Ports

| Port | Process |
|---|---|
| 8080 | gateway HTTP listener (`config-http.yaml`, `config-oauth.yaml`) |
| 3000 | gateway MCP listener (`config-mcp.yaml`) |
| 8081 | echo upstream |
| 3001 | MCP upstream |
| 9191 | ans-authz gRPC |
| 9192 | ans-authz health and metrics |
| 15000, 15020, 15021 | agentgateway admin, stats, readiness |
