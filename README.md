# ans-gateway-auth

Verifier service and gateway recipes for Agent Name Service (ANS) caller authentication as
specified by ANS-6 (Agent-to-Agent Authentication) Method B in the ANS registry specification: an
RFC 9449 DPoP proof bound to a transparency-logged identity certificate, carried with a SCITT
receipt and a status token. The identity layer itself (domain-anchored names, the transparency
log) is the one draft-narajala-courtney-ansv2 describes.

`ans-authz` is an Envoy ext_authz verifier built and tested for agentgateway and Agent Router.
Any gateway that speaks the Envoy external authorization protocol can call it, but the
defaults (the 2 s ext_authz budget, body forwarding, header folding) are agentgateway's; stock
Envoy's ext_authz timeout defaults to 200 ms and must be raised above `checkTimeout`, and the
Envoy `header_map` and partial-body paths are covered by unit tests only. The verifier checks the
three identity headers offline against cached transparency-log root keys, rejects replays, and
returns the caller's identity to the gateway as upstream headers and dynamic metadata, or a `401`
with a `WWW-Authenticate: DPoP algs="ES256"` challenge.

```
agent ──DPoP + X-SCITT-Receipt + X-ANS-Status-Token──▶ gateway ──ext_authz Check──▶ ans-authz
                                                          │ ◀── allow + X-ANS-* / deny ──┘
                                                          ▼
                                                      upstream (sees X-ANS-Name, X-ANS-Agent-Id,
                                                                X-ANS-Fingerprint, X-ANS-JKT)
```

Recipes: [agentgateway](examples/agentgateway/README.md),
[Agent Router](examples/agent-router/README.md).

## What the verifier checks

For every request, in the order ANS-6 section 7.4 prescribes:

1. Exactly one `DPoP`, `Authorization`, `X-SCITT-Receipt` and `X-ANS-Status-Token` header each.
2. The request authority is one this verifier answers for (`trustedHosts`), or the configured
   `externalAuthority` is used; the request's own scheme and `Host` are never trusted
   (ANS-6 section 7.7).
3. The gateway forwarded the request body (the `requiredContext` sentinel and a `Content-Length`
   that matches), and the body is within `maxContentBytes`.
4. The receipt and status token parse, verify against a trusted transparency-log root key, name
   the same agent as the identity certificate, and the status is not terminal.
5. The DPoP proof verifies under the certificate's key, binds the method, the URL and the body
   digest, is fresh within `popSkew`, and carries a `jti` that has not been seen (the replay check
   runs last and fails closed when the cache is unavailable, ANS-6 section 7.6).
6. When the request carries `Authorization: DPoP <token>`, the proof's `ath` matches the token
   and `cnf.jkt` matches the proof key, read from the gateway-forwarded validated claims and,
   when the token is a JWS, from the token itself (ANS-6 sections 7.8 and 11.7). A JWS token
   carrying `cnf.jkt` offered as `Bearer` is rejected (RFC 9449 section 7.2). An opaque token can
   only be checked through forwarded claims, which `requireTokenClaims` demands; with it set to
   false the upstream owns the check for opaque tokens.

An allowed request reaches the upstream with `X-ANS-Name`, `X-ANS-Agent-Id`, `X-ANS-Fingerprint`
(hex SHA-256 of the identity certificate) and `X-ANS-JKT` set by the gateway with overwrite
semantics, so any client-supplied value of those names is replaced, and the identity published as
dynamic metadata for gateway policy (`extauthz.ans_name`, `extauthz.agent_id`,
`extauthz.fingerprint`, `extauthz.jkt`). `extraIdentityHeaders` adds more header names carrying
one of those four attributes, for gateways or upstreams that key on their own name (for example a
gateway's MCP session-binding header set to `agent_id`). The verifier never lists a header it
sets for removal, because Envoy applies removals after additions. Every identity value is checked
as a valid HTTP field value before it is set, even though it comes from signed material. Upstreams that fold header names (CGI-style
`HTTP_X_ANS_NAME`) must also drop underscore variants such as `X_ANS_Name`, which the gateway does
not normalise; the verifier only governs the exact names it sets.

Every denial is a fixed JSON body naming only the category, for example `{"error":"REPLAY"}`:

| HTTP | Categories |
|---|---|
| 401 | `MISSING_HEADERS`, `MALFORMED_PROOF`, `HTTP_BINDING_MISMATCH`, `SCITT_HEADER_INVALID`, `RECEIPT_INVALID`, `STATUS_INVALID`, `REPLAY`, `TOKEN_BINDING_MISMATCH`, `CONTENT_UNREADABLE`, the other RFC 9449 proof failures |
| 413 | `CONTENT_UNREADABLE` (body over `maxContentBytes`, or truncated by the gateway) |
| 503 | `REPLAY_CACHE_FULL`, `REPLAY_CACHE_UNAVAILABLE`, `MISCONFIGURED`, `TIMEOUT`, `CLIENT_GONE`, `INTERNAL_ERROR` |
| 400 | `MALFORMED_REQUEST` (a CheckRequest without HTTP attributes) |

## Running it

```bash
make build                       # bin/ans-authz
bin/ans-authz --config ans-authz.yaml
bin/ans-authz --config ans-authz.yaml --check   # validate and exit
```

Flags: `--config` (or `ANS_AUTHZ_CONFIG`), `--grpc-listen`, `--http-listen`, `--log-level`
(or `ANS_AUTHZ_GRPC_LISTEN`, `ANS_AUTHZ_HTTP_LISTEN`, `ANS_AUTHZ_LOG_LEVEL`; flags win), `--check`,
`--version`. Only those operational settings can be overridden; policy lives in the file.

Endpoints: gRPC `envoy.service.auth.v3.Authorization` plus `grpc.health.v1.Health` on
`grpc.listen` (default `127.0.0.1:9191`); `GET /healthz`, `GET /readyz` and `GET /metrics` on
`httpListen` (default `127.0.0.1:9192`).

Container: `make docker` builds a distroless image with no configuration inside. Mount yours at
`/etc/ans-authz/config.yaml`; the image sets `ANS_AUTHZ_HTTP_LISTEN=:9192` so probes and scrapes
reach it, and keeps the gRPC listener on loopback unless the file or `ANS_AUTHZ_GRPC_LISTEN` says
otherwise.

## Configuration

```yaml
transparencyLogs:              # at least one; nothing is trusted by default
- name: prod-tl
  baseURL: https://tl.example.com   # fetched at startup (retried until startupTimeout) and every keyRefreshInterval
  rootKeys: [...]                   # C2SP verifier lines; always trusted, and they let a restart succeed during a log outage
  timeout: 1s                       # must stay below checkTimeout
trustedHosts: [https://api.example.com]   # or externalAuthority: https://api.example.com
requiredContext: {key: ans-authz, value: body-forwarded}
requireTokenClaims: true       # 503 when a DPoP-bound token arrives without gateway-validated claims
extraIdentityHeaders: {}       # e.g. {x-ai-eg-mcp-subject: agent_id}; values: ans_name, agent_id, fingerprint, jkt
maxContentBytes: 1048576
requireReceipt: true
allowedAnsNames: []            # optional allowlist
popSkew: 120s
stripIdentityHeaders: true     # remove the receipt, status token (and the proof when no token is bound) before the upstream
checkTimeout: 1500ms           # the whole verification budget; keep it below the gateway's ext_authz timeout
replay: {type: memory, maxEntries: 100000}
# replay:
#   type: redis
#   redis: {addr: replay-redis:6379, passwordEnv: ANS_AUTHZ_REDIS_PASSWORD, tls: true, timeout: 500ms}
grpc:
  listen: 127.0.0.1:9191
  tokenClaimsNamespace: ans-authz   # the only filter_metadata namespace read for forwarded token claims
  # tls: {certFile: ..., keyFile: ..., clientCAFile: ...}   # required for a non-loopback listener; loaded at startup, rotation needs a restart
  # allowInsecureListen: true                               # only inside a mesh that provides mutual TLS
httpListen: 127.0.0.1:9192
logLevel: info
keyRefreshInterval: 24h
startupTimeout: 30s
readiness: {requireReplayBackend: true}
```

Durations are strings (`1500ms`, `2s`, `24h`). Unknown keys are errors. Validation fails startup
when no authority is configured, when a transparency log has neither `baseURL` nor `rootKeys` or
pins the same key id twice, when `http://` is used without `allowInsecure`, when a non-loopback
gRPC listener has no TLS, when TLS material does not load, or when `checkTimeout` is not above
every fetch timeout. `--check` and startup warn when `checkTimeout` is not below the gateway's
two-second ext_authz budget, when root keys are fetched over plaintext from a non-loopback host
(pin `rootKeys` instead), and when `requiredContext` is unset.

### Trust material

A transparency log's trusted keys are the pinned `rootKeys` plus whatever its `/root-keys`
endpoint served at the last successful fetch. Each refresh replaces the fetched set rather than
accumulating, so a key the log withdraws stops being trusted at the next refresh (every
`keyRefreshInterval`, or on demand when a proof names an unknown key id, bounded by cooldowns).
Pinned keys are never dropped and fetched keys are trusted exactly like pinned ones, so the log
endpoint's TLS identity is part of the trust chain: use `https://` with a certificate you trust,
and treat `allowInsecure` as a loopback development setting. Status tokens are accepted up to
ten minutes past their expiry (an SDK constant), so revocation latency at the verifier is the
token lifetime plus ten minutes.

### Authority rule (ANS-6 section 7.7)

The DPoP `htu` is rebuilt from configuration, never from the request. With `trustedHosts`, the
request authority must match one entry and that entry's scheme is used. Behind a TLS terminator
or load balancer that rewrites the authority, set `externalAuthority` to the public origin agents
sign for. An authority listed under two schemes is rejected at startup.

## Topologies

| Topology | Verifier address | Replay scope | Notes |
|---|---|---|---|
| Loopback sidecar | `127.0.0.1:9191`, plaintext | per gateway replica | Add a readiness probe on `/readyz`; pin `rootKeys` so a transparency-log outage during a rollout cannot crash-loop the sidecar; set `readiness.requireReplayBackend: false` when the pod shares readiness with the gateway |
| Shared service | `ans-authz:9191` with `grpc.tls` (or mesh mTLS and `allowInsecureListen`) | one cache for every replica | The gateway side needs `backendTLS` toward the verifier; a shared replay cache is required for more than one verifier replica (ANS-6 section 7.6) |
| Local process | `127.0.0.1:9191` | one process | What `make run-example` does |

The in-memory replay cache is per process. With more than one verifier replica behind one
authority it is not conformant: a proof replayed to a second replica is accepted. Use the Redis
backend below for any deployment with more than one replica.

### Shared replay cache (Redis)

`replay: {type: redis, redis: {...}}` records every proof identifier in one standalone Redis 6.2+
instance (Sentinel and Cluster are not supported yet). Requirements the verifier enforces at
startup and samples every 15 s:

- `maxmemory` set and `maxmemory-policy noeviction`: an evicting policy would drop replay
  records silently, so the verifier refuses to start against one and fails closed if the policy
  drifts later. Size for peak requests per second times (`popSkew` + 5 s) entries at roughly
  100 bytes each, plus headroom; when the limit is reached the store refuses writes and the
  verifier denies with `REPLAY_CACHE_FULL`.
- A dedicated instance: a logical database is not an isolation boundary against `FLUSHALL`,
  `CONFIG SET` or a co-tenant's memory. The ACL needs only `+set +get +info` (plus `+select` for
  a non-zero `db`), for example
  `ACL SETUSER ans-authz on >password ~ans-authz:* +set +get +info -@all` (every key the
  verifier writes carries the `ans-authz:` prefix).
- `tls: true` for any store that is not on loopback: proof identifiers and the keyspace sentinel
  otherwise travel in plaintext, which the verifier warns about at startup.
- `appendonly yes` with `appendfsync always` (or `everysec`, accepting one second of exposure):
  a restart that loses recent records is a replay window, so the verifier refuses to start
  against a store without AOF and fails closed if it is switched off later. Never restore the
  store from a snapshot without a `FLUSHALL` first; a snapshot keeps the sentinel but not the
  records written after it.

Keyspace loss is detected in the request path: a sentinel key written at first start travels
with every check, and when it disappears (flush, restart without persistence) every replica
fails closed with `REPLAY_CACHE_UNAVAILABLE` and a `Retry-After` covering `2 x popSkew + 5 s`,
the longest a proof from the lost keyspace could still be valid. A fresh store opens the same
window once. `/readyz` reports `keyspaceResetUntil` while a window is open, and
`ans_authz_replay_backend_keyspace_resets_total` counts the events. The password comes from the
environment variable named by `passwordEnv`, never from the file; because the file chooses the
variable and the address, grant write access to the verifier's configuration no more widely than
read access to that secret.

## Gateway-side rules

- `failureMode` must deny (`denyWithStatus: 503` is the operable choice). `allow` admits every
  request during a verifier outage with no identity attached.
- Keep an authorization rule such as `require: 'has(extauthz.ans_name)'` so a route that loses
  its ext_authz policy fails closed.
- Forward the body (`includeRequestBody`, `packAsBytes: true`, no partial messages) next to the
  `protocol.grpc.context` sentinel. The verifier detects a missing sentinel and a body-less
  request that declares a `Content-Length`; it cannot detect a route that keeps the sentinel but
  drops body forwarding for body-less requests, so keep the two settings together.
- The gateway's ext_authz timeout must stay above `checkTimeout`. The gateway's body cap bounds
  memory on both sides (roughly concurrency times cap). The verifier's gRPC receive limit is
  `maxContentBytes` plus 1 MiB of headroom for the identity headers and framing, so raise
  `maxContentBytes` together with the gateway's body cap.
- No ext_authz decision cache: a DPoP proof is single-use.
- Upstreams must be reachable only through the gateway; otherwise `X-ANS-*` can be forged.
- A gateway rate limit does not protect the verifier or the replay cache. In agentgateway v1.6.0
  `localRateLimit` runs after `extAuthz` and `authorization`, and listener policies have no rate
  limit at all, so every request is verified and its proof identifier recorded before the limit
  is charged; the `localRateLimit` in the recipes bounds upstream load only. A caller with any
  valid identity can therefore fill the replay cache with distinct proofs, and the cache then
  fails closed for every caller (`REPLAY_CACHE_FULL`) until the entries expire. Keep the
  capacity alerts below; the decision log carries the ANS name behind every allow, which
  identifies a flooding caller. A per-identity quota inside the verifier, applied before the
  record is written, is planned.
- The verifier reads forwarded token claims from one `filter_metadata` namespace,
  `grpc.tokenClaimsNamespace` (default `ans-authz`, the one the recipes' `protocol.grpc.metadata`
  writes), and never falls back to `envoy.filters.http.jwt_authn`: every filter in the chain can
  write there, so with `requireTokenClaims: true` a forged `cnf.jkt` in that namespace would pass
  the binding check. A gateway whose JWT filter can only write that namespace must name it
  explicitly, and the verifier warns about the trust it implies at startup.
- For DPoP-bound access tokens, validate the token at the gateway with the `DPoP` scheme and
  forward its claims to the verifier (see the OAuth recipe); the CEL rule
  `has(jwt.cnf) && jwt.cnf.jkt == extauthz.jkt` is the second layer. Do not accept `Bearer` and
  `DPoP` on the same route.

## Observability

Prometheus metrics on `/metrics`:

| Metric | Meaning |
|---|---|
| `ans_authz_decisions_total{result,category}` | decisions by result and deny category |
| `ans_authz_check_duration_seconds` | verification latency |
| `ans_authz_check_timeouts_total` | checks that exhausted `checkTimeout` |
| `ans_authz_key_refresh_total{tl,result}` | on-demand root-key refreshes |
| `ans_authz_root_keys{tl}`, `ans_authz_root_keys_last_refresh_timestamp_seconds{tl}` | trust material state |
| `ans_authz_replay_cache_entries`, `ans_authz_replay_cache_capacity` | memory cache occupancy |
| `ans_authz_replay_backend_duration_seconds{op}`, `ans_authz_replay_backend_errors_total{op}`, `ans_authz_replay_backend_up{backend}` | replay backend health |
| `ans_authz_replay_backend_used_memory_bytes`, `_maxmemory_bytes`, `_noeviction`, `_evicted_keys_total`, `_keyspace_resets_total`, `_restarts_total`, `_aof_enabled` | Redis guard rails (per instance; alert with `max()`, not `sum()`) |

Alerts worth having:

| Condition | Meaning |
|---|---|
| `replay_cache_entries / replay_cache_capacity > 0.8` for 5m, or `decisions_total{category="REPLAY_CACHE_FULL"}` rising | replay cache capacity, or one caller flooding distinct proofs (a gateway rate limit does not stop this; the decision log names the caller); raise `maxEntries` (about 100 bytes per entry, size for peak RPS times `popSkew` plus 5 s) |
| `decisions_total{category="REPLAY_CACHE_UNAVAILABLE"}` rising, `replay_backend_errors_total` rising, or `replay_backend_up == 0` | replay backend outage; requests are failing closed |
| `key_refresh_total{result="failure"}` rising with a stale `root_keys_last_refresh_timestamp_seconds` | transparency-log key rotation trouble |
| `check_timeouts_total > 0` | the verification budget is under pressure; check the replay backend and transparency-log latency |
| `decisions_total{category="MISCONFIGURED"}` rising | a route lost body forwarding or token-claim forwarding; the verifier log names the authority |
| `increase(replay_backend_evicted_keys_total) > 0` | the store evicted replay records: replay protection is compromised, critical |
| `increase(replay_backend_keyspace_resets_total) > 0` | the keyspace was lost; every replica fails closed for `2 x popSkew + 5 s`, critical |
| `replay_backend_up == 1 and (maxmemory_bytes == 0 or noeviction == 0 or aof_enabled == 0)` | the store is misconfigured, critical |
| `used_memory_bytes / maxmemory_bytes > 0.8` for 5m | store capacity |
| `increase(replay_backend_restarts_total) > 0` | the store restarted (informational when AOF restored it) |

Logs are JSON on stderr: one `decision` line per check (request id with its source, gateway or
client, method, authority, path without query, result, HTTP status, category, the verifier-side
reason, ANS name, duration) at INFO for allows and 4xx denials and at WARN for 5xx denials, plus
rate-limited errors for misconfiguration. Credentials, DPoP, Authorization and SCITT header
values are never logged; the reason may quote a bounded fragment of a rejected proof's decoded
header fields, and client-influenced fields are truncated.

`/readyz` returns 200 only while serving with root keys for every transparency log and, when
`readiness.requireReplayBackend` is set, a reachable replay backend; it is 503 while starting and
from the moment shutdown begins. It stays 200 during a keyspace-reset fail-closed window on
purpose: that event is store-wide, so taking every replica out of the Service would leave no
endpoints where fast 503s with `Retry-After` serve clients better; a single replica that cannot
reach the store is what `requireReplayBackend` removes from rotation. Per-log status carries the
class of the last fetch failure as `lastErrorKind` (`timeout`, `dns_error`, `tls_error`,
`connection_error`, `http_error`, `other`); the error text, with hostnames, stays in the log. The
root-key fetch never follows a redirect: the configured URL is the trust anchor, and a 3xx from it
fails the fetch. On `SIGTERM` the health service flips to `NOT_SERVING`, in-flight
checks drain for up to ten seconds, then the process exits. The HTTP listener binds only after the
trust material is loaded, which can take up to `startupTimeout` per transparency log, so give the
container a startup probe on `/readyz` whose `failureThreshold x periodSeconds` covers that, or pin
`rootKeys` so startup does not wait on the network.

## Development

```bash
make test            # unit tests with -race
make cover           # coverage gate (95%) on the service packages
make lint            # golangci-lint
make e2e             # end-to-end against a local ANS stack and the pinned agentgateway binary
make run-example     # echo upstream + ans-authz + agentgateway, HTTP recipe
```

The end-to-end suite needs an ANS reference checkout (`ANS_E2E_ANS_REPO`, defaulting to a
sibling `opensource-ans` directory) with its demo stack running (registration authority on 18080,
transparency log on 18081), or `ANS_E2E_START_STACK=1` to start it. Missing prerequisites skip the
suite; `ANS_E2E_REQUIRED=1` turns a skip into a failure where a stack is available. CI runs the
unit suites, lint, govulncheck and the recipe validation; both end-to-end suites are run by the
maintainers before a release. See
[tests/agentgateway](tests/agentgateway). `make run-example` builds the upstream and starts the
HTTP recipe; `make run-example EXAMPLE=mcp` starts the MCP recipe with the `examples/mcpecho`
upstream.

## Layout

| Path | Purpose |
|---|---|
| `cmd/ans-authz` | the verifier binary |
| `authz` | transport-neutral verification pipeline |
| `extauthz` | Envoy ext_authz face, gRPC server, metrics |
| `replay` | replay-cache contract and backends |
| `config` | YAML configuration |
| `examples/agentgateway` | agentgateway recipes |
| `examples/agent-router` | Agent Router recipes (standalone and Kubernetes) |
| `examples/echo` | development upstream that echoes the request |
| `examples/mcpecho` | development MCP upstream with `echo` and `secret` tools |
| `identity`, `testidentity` | identity bundle handling and test fixtures shared by the tools and suites |
| `cmd/ans-curl`, `cmd/ans-dev-identity` | signed-request client and development identity tooling |
| `tests/agentgateway`, `tests/agentrouter` | end-to-end tests |

## Contributing

This repository follows [ANS governance](https://github.com/agentnameservice/governance/blob/main/GOVERNANCE.md).
See [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidance and
[MAINTAINERS.md](MAINTAINERS.md) for the repository's Maintainers.
The [Code of Conduct](CODE_OF_CONDUCT.md) applies to participation;
report vulnerabilities privately using [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE).
