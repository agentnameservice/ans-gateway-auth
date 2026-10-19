# Agent Router: authenticating agents with the Agent Name Service

This recipe puts proof-of-possession agent authentication in front of [Agent Router](https://theagentrouter.ai)
(the former Envoy AI Gateway) without changing Agent Router. Every request to a protected route
must carry an [RFC 9449 DPoP](https://www.rfc-editor.org/rfc/rfc9449) proof signed with the
agent's identity key, plus the agent's SCITT receipt and status token from an Agent Name Service
transparency log ([draft-narajala-courtney-ansv2](https://datatracker.ietf.org/doc/draft-narajala-courtney-ansv2/),
ANS-6 Method B). An external authorizer, `ans-authz`, verifies the three together and tells Envoy
who the caller is; Envoy's own authorization rules then decide what that caller may do.

Agent Router runs on Envoy Gateway, so the hook is Envoy Gateway's `SecurityPolicy.extAuth`
(Envoy `ext_authz` over gRPC) with body forwarding. The verifier is a separate process: a
sidecar, a shared Deployment, or a local process next to `aigw run`. Nothing here is specific
to one registry: the trusted transparency-log keys are configuration, and the verifier accepts
any log whose keys you list.

## What the gateway enforces

| Check | Mechanism | Outcome |
|---|---|---|
| Possession | DPoP proof (ES256) bound to method, URL, time, nonce and request body | 401 `WWW-Authenticate: DPoP algs="ES256"` on failure |
| Identity | SCITT receipt names the agent in a trusted transparency log | 401 |
| Liveness | status token says ACTIVE and vouches for the certificate fingerprint | 401 |
| Replay | each proof's `jti` is accepted once per verifier process | 401 |
| Authorization | Envoy Gateway `authorization` rules or MCPRoute CEL on `x-ans-agent-id` | 403 |

On every allowed request the verifier sets `X-ANS-Name`, `X-ANS-Agent-Id`, `X-ANS-Fingerprint`
and `X-ANS-JKT` (plus `x-ai-eg-mcp-subject`, see MCP below), overwriting anything the client
sent, and removes the proof, receipt and status token so the upstream never sees credentials.
Dynamic metadata `{ans_name, agent_id, fingerprint, jkt}` is emitted alongside for Envoy-level
policies.

## Files

| File | Purpose |
|---|---|
| `ans-authz.yaml` | Verifier configuration shared by both recipes; loadable as shipped against the local ANS demo stack |
| `standalone/aigw-ans-llm.yaml` | `aigw run` config: an LLM route behind the verifier plus an authorization rule |
| `standalone/aigw-ans-mcp.yaml` | `aigw run` config: an MCP route with identity-based tool rules and header forwarding |
| `kubernetes/ans-verifier.yaml` | ConfigMap, Deployment (one replica), Service for `ans-authz` |
| `kubernetes/networkpolicy.yaml` | Who may reach the verifier, the Envoy pods' internal ports, and the MCP tool server |
| `kubernetes/securitypolicy-gateway.yaml` | Gateway-wide authentication plus an authorization rule for AIGatewayRoutes |
| `kubernetes/mcproute-ans.yaml` | An MCPRoute with authentication, identity-based tool rules and header forwarding |
| `kubernetes/envoyproxy-accesslog.yaml` | Access-log sinks that record rejections |

## Standalone quick start (`aigw run`)

Prerequisites: `aigw` (Agent Router v1.2.0 or later), Go 1.25+, and this repository.

```bash
go build -o bin/ans-authz ./cmd/ans-authz
go build -o bin/ans-dev-identity ./cmd/ans-dev-identity
go build -o bin/ans-curl ./cmd/ans-curl
```

1. Mint a development identity. This uses the SDK's demo kit: a throwaway transparency-log key
   signs a one-hour status token and receipt for the agent. Production agents get these from a
   real registry and log.

   ```bash
   bin/ans-dev-identity --out ./dev-identity --ans-name ans://v1.0.0.demo.example --agent-id demo-agent-1
   ```

   Replace the `transparencyLogs` entry in `ans-authz.yaml` with the one the tool prints. Re-run
   after an hour (the token expires) and paste again, because every run mints a new log key, then
   restart the verifier.

2. Start the verifier.

   ```bash
   bin/ans-authz --config examples/agent-router/ans-authz.yaml
   ```

3. Start Agent Router with an OpenAI-compatible upstream on port 11434 (Ollama works) or set
   `UPSTREAM_PORT`.

   ```bash
   aigw run examples/agent-router/standalone/aigw-ans-llm.yaml
   ```

4. Call the route.

   ```bash
   bin/ans-curl --identity ./dev-identity -X POST -H 'Content-Type: application/json' \
     -d '{"model":"qwen2.5:0.5b","messages":[{"role":"user","content":"Say this is a test"}]}' \
     http://127.0.0.1:1975/v1/chat/completions
   ```

   Without `--identity`, `curl` gets `401` with `WWW-Authenticate: DPoP algs="ES256"`. Add
   `--replay` to send the same signed request twice and watch the second one fail.

`standalone/aigw-ans-mcp.yaml` does the same for an MCP server on port 1063 (`MCP_UPSTREAM_PORT`),
forwards `X-ANS-Name` and `X-ANS-Agent-Id` to it, admits any verified agent to every tool and
reserves `sum` for the listed agent.

The standalone files are self-contained on purpose (each is one `aigw run` input), so the
Gateway plumbing and the access-log sinks appear in both. `AIGW_PORT` must match the verifier's
`trustedHosts`, and `ANS_MAX_BODY` must not exceed its `maxContentBytes`.

## Kubernetes

Apply order matters because the gateway fails closed:

1. `kubernetes/ans-verifier.yaml` after editing the ConfigMap (transparency log, `trustedHosts`,
   image digest), then wait for `kubectl rollout status deployment/ans-authz` and a 200 from
   `/readyz`. Config changes take effect only after `kubectl rollout restart`, a short fail-closed
   window, so Kubernetes deployments should point at a real transparency log rather than hourly
   development keys.
2. `kubernetes/networkpolicy.yaml` and `kubernetes/envoyproxy-accesslog.yaml`.
3. A canary: `kubernetes/securitypolicy-gateway.yaml` with `targetRefs` pointed at one HTTPRoute
   (the name of one AIGatewayRoute) and a client that already signs.
4. The Gateway-scoped policy, and `kubernetes/mcproute-ans.yaml` for MCP routes.

To roll back, replace the policy's `authorization` with `defaultAction: Deny` and no rules, or
point `targetRefs` back at the canary route. Deleting the policy serves the routes
unauthenticated.

These manifests are validated for syntax and consistency by the unit suite (the ConfigMap must
match `ans-authz.yaml` apart from its documented overrides, and every `extAuth` block must carry
the sentinel, `statusOnError: 503` and a circuit breaker); they have not been executed against a
cluster in this repository.

### Topology and the replay cache

The replay cache is per verifier process. ANS-6 requires every verifier instance that serves one
externally visible authority to share it, so:

| Topology | Replay protection | Use when |
|---|---|---|
| One local process (`aigw run`) | complete | development and tests |
| One Deployment, `replicas: 1` | complete; a rollout, drain or preemption is a short fail-closed window | the default |
| Sidecar per Envoy pod | complete only with one Envoy replica | single-replica gateways |
| Several replicas with the `redis` replay backend | complete; a Redis outage is a fail-closed 503, so run Redis highly available | high availability |

Do not scale the memory-backed Deployment: two in-memory caches each accept a replayed proof
once. Consistent-hash load balancing on the `DPoP` header does not help, because Envoy hashes the
headers of its own gRPC `Check` call, which never carries the client's `DPoP` header. Give the
single replica a high `priorityClassName`; a PodDisruptionBudget with one replica only blocks
drains. `replay.maxEntries` bounds the proofs remembered for the 120 s skew window and fails
closed above it (`REPLAY_CACHE_FULL`), so size it at peak requests per second times 240 and watch
the verifier's `/metrics`.

### Triage

| Status | Detail (`%RESPONSE_CODE_DETAILS%`) | Meaning | Action |
|---|---|---|---|
| 401 | `ext_authz_denied`, `WWW-Authenticate: DPoP` | proof, receipt or status token rejected; body names the category; `ans.agent_id` empty | check the client's identity material and clock; `MISSING_HEADERS` means an unsigned client |
| 403 | `rbac_access_denied`, `ans.agent_id` set | verified agent not allowed by the authorization rule | adjust the rule |
| 413 | `request_payload_too_large` | body above `bodyToExtAuth.maxRequestBytes` | raise the cap (see below) |
| 500 | `response_payload_too_large` | a response above the same cap | raise the cap |
| 503 | `ext_authz_error` | verifier unreachable, over `timeout`, or over the circuit breaker | verifier health, `cluster.<verifier>.upstream_*` stats |
| 503 | `ext_authz_denied`, body `TIMEOUT`, `MISCONFIGURED`, `REPLAY_CACHE_UNAVAILABLE`, `REPLAY_CACHE_FULL` | the verifier itself refused | verifier logs; `MISCONFIGURED` usually means a route without the `contextExtensions` sentinel |

Envoy counts the first 503 under `cluster.<route cluster>.ext_authz.error` and the second under
`.ext_authz.denied`; alert on both, and on the verifier's own `/metrics`. The rejection sink logs
`ans.agent_id` and `:authority`, so 403s can be attributed to an agent and htu mismatches to a
host name.

### Body size and concurrency

`bodyToExtAuth.maxRequestBytes` is how much of the request Envoy buffers for the verifier. Envoy
also applies it as the stream's buffer limit, so it caps buffered **responses** on the same
routes, including the ones Agent Router's processor holds while translating; a response above it
fails with 500 `response_payload_too_large`, and raising `ClientTrafficPolicy.connection.bufferLimit`
does not change that (Agent Router issue 2843). Size the cap for the largest response the gateway
holds, keep it at or below the verifier's `maxContentBytes` and the verifier's gRPC receive limit,
and raise the three together.

Each in-flight check holds roughly three times the body in the verifier, so the recipes bound
concurrency with `extAuth.grpc.backendSettings.circuitBreaker.maxParallelRequests` (64) and size
the verifier's memory as about 64 MiB plus three times the cap times that bound. Raise the cap,
the bound and the memory request together, and pair a large cap with Envoy connection limits or
a rate limit so unauthenticated traffic cannot exhaust the gateway before it is rejected.

### How identity reaches authorization

- Envoy Gateway `SecurityPolicy.authorization` rules match `x-ans-agent-id` because the RBAC filter
  runs after ext_authz has overwritten the header (`kubernetes/securitypolicy-gateway.yaml`).
- MCPRoute `securityPolicy.authorization` rules are evaluated in order, the first match decides,
  and `defaultAction: Deny` covers the rest; their CEL sees `request.headers["x-ans-agent-id"]`
  and `request.mcp.tool`. Guard header access with `in`, since an evaluation error denies the
  request.
- MCP backends receive only the headers listed in `forwardHeaders`.
- The verifier sets `x-ai-eg-mcp-subject` to the agent id (`extraIdentityHeaders`), which Agent
  Router's MCP proxy uses to bind a session to the agent that created it; another agent
  presenting that session id is rejected. The header is Agent Router's internal contract between
  its Envoy filters and its proxy, so pin the Agent Router version when relying on it.

### Caveats

- (a) **MCP OAuth on the same MCPRoute does not combine with DPoP.** `securityPolicy.oauth` is
  Bearer-only and rewrites every 401 challenge on the route to `WWW-Authenticate: Bearer`. Use
  separate routes until Agent Router accepts non-Bearer token extraction.
- (b) Keep `failOpen: false`. A verifier outage is a 503, never an open door.
- (c) `trustedHosts` must equal the authority clients put in their proofs. Behind a TLS-terminating
  edge, set `externalAuthority` on the verifier; the request's own scheme and Host are never trusted.
- (d) Agent Router's MCP proxy (port 9856) trusts the headers it receives, because ext_authz already
  ran in Envoy; under `aigw run` it listens on all interfaces and answers unsigned requests that
  carry the route header. On Kubernetes `networkpolicy.yaml` closes it to other pods; under
  `aigw run`, run on a trusted host.
- (e) The Envoy-to-verifier gRPC hop is plaintext unless `grpc.tls` is configured on the verifier.
  Keep it inside the pod or behind the NetworkPolicy.
- (f) Non-UTF-8 request bodies are rejected: Envoy Gateway forwards the body as a protobuf string
  and the verifier's decoder refuses invalid UTF-8, which fails closed. JSON bodies are unaffected.
- (g) The identity headers (`X-ANS-*` and `x-ai-eg-mcp-subject`) reach the upstream. Remove them
  with the AIServiceBackend's `headerMutation.remove` when a third-party provider should not see
  them.
- (h) Replay protection is per verifier process until the `redis` replay backend is configured.
- (i) With `requireTokenClaims: false`, the `cnf.jkt` binding of a DPoP-bound OAuth access token is
  not checked at the gateway, because Envoy Gateway forwards no validated claims to ext_authz.
  These recipes consume no access tokens; an upstream that does must verify the binding itself.
- (j) Every MCPRoute needs the full `extAuth` block. A route that omits it is served
  unauthenticated and the verifier's sentinel cannot detect that.

### Tests

`go test ./tests/agentrouter/` (no tag) checks the recipes: the shipped `ans-authz.yaml` loads,
the Kubernetes ConfigMap matches it apart from its overrides, and every `extAuth` block carries
the contract. `make e2e-agentrouter AIGW_BIN=/path/to/aigw` (or
`AIGW_BIN=/path/to/aigw go test -tags e2e -p 1 ./tests/agentrouter/ -v`) runs `aigw run` with
these configurations against `ans-authz` built from this tree: a wiring spike
with a stub authorizer, then signed, unsigned, replayed, tampered, wrong-authority, untrusted-root,
missing-receipt, unauthorized, oversize-response and verifier-outage requests on the LLM route,
tool rules, forwarded headers, forged headers and session binding on the MCP route, and the
documented MCP-proxy bypass. `AIGW_BIN` is required: build it with `go build -o bin/aigw ./cmd/aigw`
in an Agent Router checkout, or use a release binary.
