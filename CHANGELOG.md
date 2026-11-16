# Changelog

## 0.1.0 (2026-11-05)


### Features

* **agent-router:** Agent Router recipes, identity tooling and suite ([05948f6](https://github.com/agentnameservice/ans-gateway-auth/commit/05948f617f591d2a866a68f70a06753cc51ef18e))
* **agentgateway:** per-source rate limit in the recipes ([05948f6](https://github.com/agentnameservice/ans-gateway-auth/commit/05948f617f591d2a866a68f70a06753cc51ef18e))
* **agentgateway:** recipes, development upstreams and end-to-end suite ([05948f6](https://github.com/agentnameservice/ans-gateway-auth/commit/05948f617f591d2a866a68f70a06753cc51ef18e))
* **authz:** ANS-6 Method B verification pipeline and keyring ([05948f6](https://github.com/agentnameservice/ans-gateway-auth/commit/05948f617f591d2a866a68f70a06753cc51ef18e))
* **cmd:** ans-authz service binary and container image ([05948f6](https://github.com/agentnameservice/ans-gateway-auth/commit/05948f617f591d2a866a68f70a06753cc51ef18e))
* **config:** YAML configuration, validation and example verifier configs ([05948f6](https://github.com/agentnameservice/ans-gateway-auth/commit/05948f617f591d2a866a68f70a06753cc51ef18e))
* **extauthz:** Envoy ext_authz gRPC server and Prometheus metrics ([05948f6](https://github.com/agentnameservice/ans-gateway-auth/commit/05948f617f591d2a866a68f70a06753cc51ef18e))
* **replay:** replay-cache contract with memory and Redis backends ([05948f6](https://github.com/agentnameservice/ans-gateway-auth/commit/05948f617f591d2a866a68f70a06753cc51ef18e))


### Bug Fixes

* **agent-router:** address review findings on the first import ([05948f6](https://github.com/agentnameservice/ans-gateway-auth/commit/05948f617f591d2a866a68f70a06753cc51ef18e))
* **agent-router:** apply the final review to the recipes, identity and CLIs ([05948f6](https://github.com/agentnameservice/ans-gateway-auth/commit/05948f617f591d2a866a68f70a06753cc51ef18e))
* **agent-router:** pin the Envoy version in the e2e harness and harden the Kubernetes recipe ([05948f6](https://github.com/agentnameservice/ans-gateway-auth/commit/05948f617f591d2a866a68f70a06753cc51ef18e))
* **authz:** reject bearer-presented bound tokens and padded JWS evasion ([05948f6](https://github.com/agentnameservice/ans-gateway-auth/commit/05948f617f591d2a866a68f70a06753cc51ef18e))
* **cmd:** drop withdrawn root keys on refresh and bound the health listener ([05948f6](https://github.com/agentnameservice/ans-gateway-auth/commit/05948f617f591d2a866a68f70a06753cc51ef18e))
* **config:** warn when token claims are not required ([05948f6](https://github.com/agentnameservice/ans-gateway-auth/commit/05948f617f591d2a866a68f70a06753cc51ef18e))
* **identity:** close a refused redirect hop's body and let -d select POST ([05948f6](https://github.com/agentnameservice/ans-gateway-auth/commit/05948f617f591d2a866a68f70a06753cc51ef18e))
* **identity:** refuse redirect hops that would carry identity to another host ([05948f6](https://github.com/agentnameservice/ans-gateway-auth/commit/05948f617f591d2a866a68f70a06753cc51ef18e))
* **recipes:** correct the rate-limit claim and apply the review to delivery and suites ([05948f6](https://github.com/agentnameservice/ans-gateway-auth/commit/05948f617f591d2a866a68f70a06753cc51ef18e))
* **verifier:** address review comments on trust-anchor fetches, claims namespace and readiness ([05948f6](https://github.com/agentnameservice/ans-gateway-auth/commit/05948f617f591d2a866a68f70a06753cc51ef18e))
* **verifier:** apply the final review to the verifier packages ([05948f6](https://github.com/agentnameservice/ans-gateway-auth/commit/05948f617f591d2a866a68f70a06753cc51ef18e))


### Documentation

* audit corrections in the README ([05948f6](https://github.com/agentnameservice/ans-gateway-auth/commit/05948f617f591d2a866a68f70a06753cc51ef18e))
* **recipes:** the OAuth recipe must forward claims to the configured namespace ([05948f6](https://github.com/agentnameservice/ans-gateway-auth/commit/05948f617f591d2a866a68f70a06753cc51ef18e))


### Miscellaneous

* **deps:** Bump golang from 1.26-bookworm to 1.27-bookworm ([#6](https://github.com/agentnameservice/ans-gateway-auth/issues/6)) ([05d1095](https://github.com/agentnameservice/ans-gateway-auth/commit/05d109592fb876849eb6115e160ede768f7002d1))
* **deps:** Bump goreleaser/goreleaser-action from 7.2.3 to 7.3.0 ([#8](https://github.com/agentnameservice/ans-gateway-auth/issues/8)) ([98601de](https://github.com/agentnameservice/ans-gateway-auth/commit/98601de510b67c381efecf6e308e9f04d4138f6b))
* repository skeleton, license and community files ([a1a52f5](https://github.com/agentnameservice/ans-gateway-auth/commit/a1a52f5e6a12365c0aca021cf4fa8d4ba041433b))
