# agentgateway end-to-end tests

Build tag `e2e`. The suite builds `ans-authz`, starts an echo upstream, the verifier and the
pinned agentgateway release, provisions a real agent against a local ANS reference stack and
drives signed requests through the gateway.

```bash
make e2e                 # HTTP, OAuth and MCP suites
make e2e E2E_FLAGS=-v
```

| Variable | Default | Purpose |
|---|---|---|
| `ANS_E2E_RA_URL` | `http://localhost:18080` | registration authority |
| `ANS_E2E_TL_URL` | `http://localhost:18081` | transparency log |
| `ANS_E2E_RA_API_KEY` | the reference stack's development key | registration API key |
| `ANS_E2E_ANS_REPO` | required (`make e2e` defaults it to a sibling `opensource-ans` directory) | ANS reference checkout; its `scripts/demo/register.sh` provisions the test agent |
| `ANS_E2E_REQUIRED` | unset | `1` turns a missing prerequisite into a failure instead of a skip (use in CI) |
| `ANS_E2E_START_STACK` | unset | `1` starts and stops the stack from `ANS_E2E_ANS_REPO` |
| `ANS_E2E_AGENTGATEWAY_BIN` | `.cache/agentgateway-<os>-<arch>` | the binary `make agentgateway-bin` fetched and verified |

The suite skips (or, with `ANS_E2E_REQUIRED=1`, fails) when the stack, the checkout or the
gateway binary is missing, and fails when ports 8080, 8081, 3000, 3001, 9191, 9192, 15000, 15020
or 15021 are in use. The reference stack's demo data directory is locked for the duration of
provisioning so parallel suites do not race. `make test` type-checks this package and `make lint`
lints it, so SDK signature changes surface without a live stack.
