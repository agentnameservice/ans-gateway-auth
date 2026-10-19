package authz

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/agentnameservice/ans-sdk-go/pop"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"

	"github.com/agentnameservice/ans-gateway-auth/replay"
)

const (
	otherPathTarget = "https://api.example/other"
	publicTarget    = "https://public.example/v1/resource"
	contextKey      = "ans-authz"
	contextValue    = "body-forwarded"
)

func withDPoPToken(tok string) func(*http.Request) {
	return func(req *http.Request) { req.Header.Set("Authorization", "DPoP "+tok) }
}

func withBearerToken(req *http.Request) { req.Header.Set("Authorization", "Bearer opaque") }

// jwsToken renders an unsigned JWS compact serialization carrying claims, the
// shape of a real access token whose cnf the verifier can read.
func jwsToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"ES256","typ":"at+jwt"}`)) + "." +
		base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString([]byte("sig"))
}

func mustRawURLDecode(t *testing.T, s string) []byte {
	t.Helper()
	b, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func cnfClaims(jkt string) map[string]any {
	return map[string]any{"cnf": map[string]any{"jkt": jkt}}
}

func requireContext(c *Config) {
	c.RequiredContext = &RequiredContext{Key: contextKey, Value: contextValue}
}

func externalOnly(c *Config) {
	c.TrustedHosts = nil
	c.ExternalAuthority = "https://public.example"
}

func externalWithTrusted(c *Config) { c.ExternalAuthority = "https://public.example" }

// signedGet is the plain allow request every mutation starts from.
func signedGet(t *testing.T, f *fixture) *Request {
	t.Helper()
	return f.signed(t, http.MethodGet, fixtureTarget, nil, nil)
}

type decisionCase struct {
	name           string
	cfg            func(*Config)
	keys           func(t *testing.T, f *fixture) *Keyring
	request        func(t *testing.T, f *fixture) *Request
	wantAllow      bool
	wantStatus     int
	wantCategory   string
	wantOneOf      []string
	wantRetryAfter time.Duration
}

func allowCases() []decisionCase {
	return []decisionCase{
		{name: "GET without body", request: signedGet, wantAllow: true},
		{name: "POST with body", request: func(t *testing.T, f *fixture) *Request {
			return f.signed(t, http.MethodPost, fixtureTarget, []byte(`{"a":1}`), nil)
		}, wantAllow: true},
		{name: "query is not part of htu", request: func(t *testing.T, f *fixture) *Request {
			return f.signed(t, http.MethodGet, fixtureTarget+"?x=1&y=2", nil, nil)
		}, wantAllow: true},
		{name: "request scheme is ignored", request: func(t *testing.T, f *fixture) *Request {
			r := signedGet(t, f)
			r.Scheme = "http"
			return r
		}, wantAllow: true},
		{name: "default port is normalized", request: func(t *testing.T, f *fixture) *Request {
			r := signedGet(t, f)
			r.Authority = "api.example:443"
			return r
		}, wantAllow: true},
		{name: "authority case is normalized", request: func(t *testing.T, f *fixture) *Request {
			r := signedGet(t, f)
			r.Authority = "API.Example"
			return r
		}, wantAllow: true},
		{name: "DPoP token with matching cnf claim", request: func(t *testing.T, f *fixture) *Request {
			r := f.signed(t, http.MethodGet, fixtureTarget, nil, withDPoPToken(f.token(t)))
			r.TokenClaims = cnfClaims(f.signer.JKT())
			return r
		}, wantAllow: true},
		{name: "DPoP token without claims when not required", cfg: func(c *Config) { c.RequireTokenClaims = false },
			request: func(t *testing.T, f *fixture) *Request {
				return f.signed(t, http.MethodGet, fixtureTarget, nil, withDPoPToken(f.token(t)))
			}, wantAllow: true},
		{name: "JWS token bound to the proof key without claims when not required", cfg: func(c *Config) { c.RequireTokenClaims = false },
			request: func(t *testing.T, f *fixture) *Request {
				return f.signed(t, http.MethodGet, fixtureTarget, nil, withDPoPToken(jwsToken(t, cnfClaims(f.signer.JKT()))))
			}, wantAllow: true},
		{name: "JWS token without cnf when not required", cfg: func(c *Config) { c.RequireTokenClaims = false },
			request: func(t *testing.T, f *fixture) *Request {
				return f.signed(t, http.MethodGet, fixtureTarget, nil, withDPoPToken(jwsToken(t, map[string]any{"sub": "x"})))
			}, wantAllow: true},
		{name: "JWS token with a non-JSON payload when not required", cfg: func(c *Config) { c.RequireTokenClaims = false },
			request: func(t *testing.T, f *fixture) *Request {
				return f.signed(t, http.MethodGet, fixtureTarget, nil, withDPoPToken("eyJhbGciOiJub25lIn0.bm90LWpzb24.sig"))
			}, wantAllow: true},
		{name: "opaque DPoP token without claims when not required", cfg: func(c *Config) { c.RequireTokenClaims = false },
			request: func(t *testing.T, f *fixture) *Request {
				return f.signed(t, http.MethodGet, fixtureTarget, nil, withDPoPToken("opaque-token-value"))
			}, wantAllow: true},
		{name: "JWS-shaped token with an unreadable payload when not required", cfg: func(c *Config) { c.RequireTokenClaims = false },
			request: func(t *testing.T, f *fixture) *Request {
				return f.signed(t, http.MethodGet, fixtureTarget, nil, withDPoPToken("a.!!.c"))
			}, wantAllow: true},
		{name: "Bearer token without cnf claim", request: func(t *testing.T, f *fixture) *Request {
			r := f.signed(t, http.MethodGet, fixtureTarget, nil, withBearerToken)
			r.TokenClaims = map[string]any{"sub": "x"}
			return r
		}, wantAllow: true},
		{name: "Bearer JWS token without cnf is not sender-constrained", request: func(t *testing.T, f *fixture) *Request {
			return f.signed(t, http.MethodGet, fixtureTarget, nil, func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer "+jwsToken(t, map[string]any{"sub": "x"}))
			})
		}, wantAllow: true},
		{name: "receipt optional", cfg: func(c *Config) { c.RequireReceipt = false },
			request: func(t *testing.T, f *fixture) *Request {
				r := signedGet(t, f)
				r.Header.Del(scitt.HeaderReceipt)
				return r
			}, wantAllow: true},
		{name: "external authority replaces the request authority", cfg: externalOnly,
			request: func(t *testing.T, f *fixture) *Request {
				r := f.signed(t, http.MethodGet, publicTarget, nil, nil)
				r.Authority = "internal-gw:8080"
				return r
			}, wantAllow: true},
		{name: "external authority with an allowlisted request authority", cfg: externalWithTrusted,
			request: func(t *testing.T, f *fixture) *Request {
				r := f.signed(t, http.MethodGet, publicTarget, nil, nil)
				r.Authority = "api.example"
				return r
			}, wantAllow: true},
		{name: "allowed ans name matches", cfg: func(c *Config) { c.AllowedAnsNames = []string{fixtureAnsName} },
			request: signedGet, wantAllow: true},
		{name: "required context present", cfg: requireContext, request: func(t *testing.T, f *fixture) *Request {
			r := signedGet(t, f)
			r.Context = map[string]string{contextKey: contextValue}
			return r
		}, wantAllow: true},
		{name: "Content-Length matches the forwarded body", request: func(t *testing.T, f *fixture) *Request {
			r := f.signed(t, http.MethodPost, fixtureTarget, []byte("payload"), nil)
			r.Header.Set("Content-Length", "7")
			return r
		}, wantAllow: true},
	}
}

func denyCases() []decisionCase {
	return slices.Concat(shapeDenyCases(), bindingDenyCases(), policyDenyCases(), tokenDenyCases())
}

func shapeDenyCases() []decisionCase {
	mutate := func(fn func(*Request)) func(*testing.T, *fixture) *Request {
		return func(t *testing.T, f *fixture) *Request {
			r := signedGet(t, f)
			fn(r)
			return r
		}
	}
	return []decisionCase{
		{name: "nil request", request: func(*testing.T, *fixture) *Request { return nil },
			wantStatus: http.StatusBadRequest, wantCategory: CategoryMalformedRequest},
		{name: "empty method", request: mutate(func(r *Request) { r.Method = "" }),
			wantStatus: http.StatusBadRequest, wantCategory: CategoryMalformedRequest},
		{name: "empty path", request: mutate(func(r *Request) { r.Path = "" }),
			wantStatus: http.StatusBadRequest, wantCategory: CategoryMalformedRequest},
		{name: "relative path", request: mutate(func(r *Request) { r.Path = "v1/resource" }),
			wantStatus: http.StatusBadRequest, wantCategory: CategoryMalformedRequest},
		{name: "nil header", request: func(*testing.T, *fixture) *Request {
			return &Request{Method: http.MethodGet, Authority: "api.example", Path: "/v1/resource"}
		}, wantStatus: http.StatusUnauthorized, wantCategory: CategoryMissingHeaders},
		{name: "no identity headers", request: func(t *testing.T, _ *fixture) *Request {
			return bare(t, http.MethodGet, fixtureTarget, nil)
		}, wantStatus: http.StatusUnauthorized, wantCategory: CategoryMissingHeaders},
		{name: "receipt required but missing", request: mutate(func(r *Request) {
			r.Header.Del(scitt.HeaderReceipt)
		}), wantStatus: http.StatusUnauthorized, wantCategory: CategoryMissingHeaders},
		{name: "duplicate DPoP header", request: mutate(func(r *Request) {
			r.Header.Add(pop.DPoPHeader, "second")
		}), wantStatus: http.StatusUnauthorized, wantCategory: CategoryMalformedProof},
		{name: "duplicate Authorization header", request: mutate(func(r *Request) {
			r.Header.Add("Authorization", "DPoP x")
			r.Header.Add("Authorization", "DPoP y")
		}), wantStatus: http.StatusUnauthorized, wantCategory: CategoryMalformedProof},
		{name: "duplicate receipt header", request: mutate(func(r *Request) {
			r.Header.Add(scitt.HeaderReceipt, "x")
		}), wantStatus: http.StatusUnauthorized, wantCategory: CategoryMalformedProof},
		{name: "duplicate status token header", request: mutate(func(r *Request) {
			r.Header.Add(scitt.HeaderStatusToken, "x")
		}), wantStatus: http.StatusUnauthorized, wantCategory: CategoryMalformedProof},
		{name: "comma-joined DPoP header", request: mutate(func(r *Request) {
			r.Header.Set(pop.DPoPHeader, r.Header.Get(pop.DPoPHeader)+", second")
		}), wantStatus: http.StatusUnauthorized, wantCategory: CategoryMalformedProof},
		{name: "comma-joined receipt header", request: mutate(func(r *Request) {
			r.Header.Set(scitt.HeaderReceipt, r.Header.Get(scitt.HeaderReceipt)+", x")
		}), wantStatus: http.StatusUnauthorized, wantCategory: CategoryMalformedProof},
		{name: "comma-joined status token header", request: mutate(func(r *Request) {
			r.Header.Set(scitt.HeaderStatusToken, r.Header.Get(scitt.HeaderStatusToken)+", x")
		}), wantStatus: http.StatusUnauthorized, wantCategory: CategoryMalformedProof},
		{name: "bad base64 receipt", request: mutate(func(r *Request) {
			r.Header.Set(scitt.HeaderReceipt, "not base64!!")
		}), wantStatus: http.StatusUnauthorized, wantCategory: CategorySCITTHeaderInvalid},
		{name: "bad base64 status token", request: mutate(func(r *Request) {
			r.Header.Set(scitt.HeaderStatusToken, "not base64!!")
		}), wantStatus: http.StatusUnauthorized, wantCategory: CategorySCITTHeaderInvalid},
	}
}

func bindingDenyCases() []decisionCase {
	mismatch := func(name string, cfg func(*Config), req func(*testing.T, *fixture) *Request) decisionCase {
		return decisionCase{name: name, cfg: cfg, request: req,
			wantStatus: http.StatusUnauthorized, wantCategory: CategoryHTTPBindingMismatch}
	}
	authority := func(a string) func(*testing.T, *fixture) *Request {
		return func(t *testing.T, f *fixture) *Request {
			r := signedGet(t, f)
			r.Authority = a
			return r
		}
	}
	publicAuthority := func(a string) func(*testing.T, *fixture) *Request {
		return func(t *testing.T, f *fixture) *Request {
			r := f.signed(t, http.MethodGet, publicTarget, nil, nil)
			r.Authority = a
			return r
		}
	}
	return []decisionCase{
		mismatch("untrusted authority", nil, authority("other.example")),
		mismatch("empty authority", nil, authority("")),
		mismatch("non-default port", nil, authority("api.example:8443")),
		mismatch("default port of the other scheme", func(c *Config) { c.TrustedHosts = []string{"http://api.example"} },
			func(t *testing.T, f *fixture) *Request {
				r := f.signed(t, http.MethodGet, "http://api.example/v1/resource", nil, nil)
				r.Authority = "api.example:443"
				return r
			}),
		mismatch("external authority mode rejects an empty authority", externalOnly, publicAuthority("")),
		mismatch("external authority with trusted hosts rejects an unlisted authority", externalWithTrusted,
			publicAuthority("other.example")),
		mismatch("proof for another path", nil, func(t *testing.T, f *fixture) *Request {
			r := f.signed(t, http.MethodGet, otherPathTarget, nil, nil)
			r.Path = "/v1/resource"
			return r
		}),
		mismatch("proof for another method", nil, func(t *testing.T, f *fixture) *Request {
			r := signedGet(t, f)
			r.Method = http.MethodPost
			return r
		}),
		mismatch("proof for another authority", nil, func(t *testing.T, f *fixture) *Request {
			r := f.signed(t, http.MethodGet, "https://other.example/v1/resource", nil, nil)
			r.Authority = "api.example"
			return r
		}),
		{name: "content mismatch", request: func(t *testing.T, f *fixture) *Request {
			r := f.signed(t, http.MethodPost, fixtureTarget, []byte("signed"), nil)
			r.Body = []byte("tampered")
			return r
		}, wantStatus: http.StatusUnauthorized, wantCategory: string(pop.ErrContentBindingMismatch)},
		{name: "body added after signing", request: func(t *testing.T, f *fixture) *Request {
			r := signedGet(t, f)
			r.Body = []byte("added")
			return r
		}, wantStatus: http.StatusUnauthorized, wantCategory: string(pop.ErrContentBindingMismatch)},
	}
}

func policyDenyCases() []decisionCase {
	return []decisionCase{
		{name: "caller not in allowed ans names",
			cfg:     func(c *Config) { c.AllowedAnsNames = []string{"ans://v1.0.0.other.example"} },
			request: signedGet, wantStatus: http.StatusUnauthorized, wantCategory: string(pop.ErrExpectedPeerMismatch)},
		{name: "required context missing", cfg: requireContext, request: signedGet,
			wantStatus: http.StatusServiceUnavailable, wantCategory: CategoryMisconfigured},
		{name: "required context wrong value", cfg: requireContext, request: func(t *testing.T, f *fixture) *Request {
			r := signedGet(t, f)
			r.Context = map[string]string{contextKey: "nope"}
			return r
		}, wantStatus: http.StatusServiceUnavailable, wantCategory: CategoryMisconfigured},
		{name: "Content-Length without body", request: func(t *testing.T, f *fixture) *Request {
			r := signedGet(t, f)
			r.Header.Set("Content-Length", "10")
			return r
		}, wantStatus: http.StatusServiceUnavailable, wantCategory: CategoryMisconfigured},
		{name: "body over cap", cfg: func(c *Config) { c.MaxContentBytes = 16 }, request: func(t *testing.T, f *fixture) *Request {
			return f.signed(t, http.MethodPost, fixtureTarget, bytes.Repeat([]byte("x"), 32), nil)
		}, wantStatus: http.StatusRequestEntityTooLarge, wantCategory: CategoryContentUnreadable},
		{name: "partial body", request: func(t *testing.T, f *fixture) *Request {
			r := f.signed(t, http.MethodPost, fixtureTarget, []byte("part"), nil)
			r.Partial = true
			return r
		}, wantStatus: http.StatusRequestEntityTooLarge, wantCategory: CategoryContentUnreadable},
		{name: "unknown transparency log key", keys: func(t *testing.T, _ *fixture) *Keyring {
			other := newFixture(t)
			return mustKeyring(t, NoopObserver{}, KeySource{Name: "other-tl", Lookup: other.lookup})
		}, request: signedGet, wantStatus: http.StatusUnauthorized,
			wantOneOf: []string{string(pop.ErrStatusInvalid), string(pop.ErrReceiptInvalid)}},
	}
}

func tokenDenyCases() []decisionCase {
	tokenBinding := func(name string, req func(*testing.T, *fixture) *Request) decisionCase {
		return decisionCase{name: name, request: req,
			wantStatus: http.StatusUnauthorized, wantCategory: CategoryTokenBindingMismatch}
	}
	withClaims := func(claims func(f *fixture) map[string]any) func(*testing.T, *fixture) *Request {
		return func(t *testing.T, f *fixture) *Request {
			r := f.signed(t, http.MethodGet, fixtureTarget, nil, withDPoPToken(f.token(t)))
			r.TokenClaims = claims(f)
			return r
		}
	}
	return []decisionCase{
		tokenBinding("Authorization changed after signing", func(t *testing.T, f *fixture) *Request {
			r := f.signed(t, http.MethodGet, fixtureTarget, nil, withDPoPToken(f.token(t)))
			r.Header.Set("Authorization", "DPoP other")
			r.TokenClaims = cnfClaims(f.signer.JKT())
			return r
		}),
		{name: "comma-joined Authorization", request: func(t *testing.T, f *fixture) *Request {
			tok := f.token(t)
			r := f.signed(t, http.MethodGet, fixtureTarget, nil, withDPoPToken(tok))
			r.Header.Set("Authorization", "DPoP "+tok+", DPoP other")
			r.TokenClaims = cnfClaims(f.signer.JKT())
			return r
		}, wantStatus: http.StatusUnauthorized, wantCategory: CategoryMalformedProof},
		{name: "JWS token bound to another key without forwarded claims", cfg: func(c *Config) { c.RequireTokenClaims = false },
			request: func(t *testing.T, f *fixture) *Request {
				return f.signed(t, http.MethodGet, fixtureTarget, nil, withDPoPToken(jwsToken(t, cnfClaims("someone-else"))))
			}, wantStatus: http.StatusUnauthorized, wantCategory: CategoryTokenBindingMismatch},
		{name: "padded JWS token bound to another key without forwarded claims", cfg: func(c *Config) { c.RequireTokenClaims = false },
			request: func(t *testing.T, f *fixture) *Request {
				tok := jwsToken(t, cnfClaims("someone-else"))
				parts := strings.Split(tok, ".")
				parts[1] = base64.URLEncoding.EncodeToString(mustRawURLDecode(t, parts[1]))
				return f.signed(t, http.MethodGet, fixtureTarget, nil, withDPoPToken(strings.Join(parts, ".")))
			}, wantStatus: http.StatusUnauthorized, wantCategory: CategoryTokenBindingMismatch},
		{name: "Bearer JWS token carrying cnf.jkt without forwarded claims", cfg: func(c *Config) { c.RequireTokenClaims = false },
			request: func(t *testing.T, f *fixture) *Request {
				return f.signed(t, http.MethodGet, fixtureTarget, nil, func(r *http.Request) {
					r.Header.Set("Authorization", "Bearer "+jwsToken(t, cnfClaims("someone-else")))
				})
			}, wantStatus: http.StatusUnauthorized, wantCategory: CategoryTokenBindingMismatch},
		{name: "Bearer JWS token bound to the proof key is still a scheme violation", request: func(t *testing.T, f *fixture) *Request {
			return f.signed(t, http.MethodGet, fixtureTarget, nil, func(r *http.Request) {
				r.Header.Set("Authorization", "Bearer "+jwsToken(t, cnfClaims(f.signer.JKT())))
			})
		}, wantStatus: http.StatusUnauthorized, wantCategory: CategoryTokenBindingMismatch},
		{name: "JWS token bound to another key despite matching forwarded claims", request: func(t *testing.T, f *fixture) *Request {
			r := f.signed(t, http.MethodGet, fixtureTarget, nil, withDPoPToken(jwsToken(t, cnfClaims("someone-else"))))
			r.TokenClaims = cnfClaims(f.signer.JKT())
			return r
		}, wantStatus: http.StatusUnauthorized, wantCategory: CategoryTokenBindingMismatch},
		tokenBinding("token presented without ath", func(t *testing.T, f *fixture) *Request {
			r := signedGet(t, f)
			r.Header.Set("Authorization", "DPoP "+f.token(t))
			r.TokenClaims = cnfClaims(f.signer.JKT())
			return r
		}),
		tokenBinding("cnf jkt mismatch", withClaims(func(*fixture) map[string]any { return cnfClaims("other") })),
		tokenBinding("claims without cnf", withClaims(func(*fixture) map[string]any { return map[string]any{"sub": "x"} })),
		tokenBinding("cnf not an object", withClaims(func(*fixture) map[string]any { return map[string]any{"cnf": "x"} })),
		tokenBinding("empty cnf jkt", withClaims(func(*fixture) map[string]any { return cnfClaims("") })),
		tokenBinding("cnf without jkt", withClaims(func(*fixture) map[string]any {
			return map[string]any{"cnf": map[string]any{"kid": "x"}}
		})),
		tokenBinding("empty claims", withClaims(func(*fixture) map[string]any { return map[string]any{} })),
		{name: "token claims required but absent", request: func(t *testing.T, f *fixture) *Request {
			return f.signed(t, http.MethodGet, fixtureTarget, nil, withDPoPToken(f.token(t)))
		}, wantStatus: http.StatusServiceUnavailable, wantCategory: CategoryMisconfigured},
		tokenBinding("cnf claim with a Bearer token", func(t *testing.T, f *fixture) *Request {
			r := f.signed(t, http.MethodGet, fixtureTarget, nil, withBearerToken)
			r.TokenClaims = cnfClaims(f.signer.JKT())
			return r
		}),
		tokenBinding("cnf claim without any token", func(t *testing.T, f *fixture) *Request {
			r := signedGet(t, f)
			r.TokenClaims = cnfClaims(f.signer.JKT())
			return r
		}),
	}
}

func TestVerifyDecisions(t *testing.T) {
	t.Parallel()
	for _, tc := range slices.Concat(allowCases(), denyCases()) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			cfg := testConfig()
			if tc.cfg != nil {
				tc.cfg(&cfg)
			}
			obs := &recObserver{}
			opts := []func(*verifierDeps){withObserver(obs)}
			if tc.keys != nil {
				opts = append(opts, withKeys(tc.keys(t, f)))
			}
			v := f.verifier(t, cfg, opts...)
			var r *Request
			if tc.request != nil {
				r = tc.request(t, f)
			}
			d := v.Verify(t.Context(), r)
			checkDecision(t, d, tc)

			recs := obs.decisionRecords()
			if len(recs) != 1 {
				t.Fatalf("observer saw %d decisions, want 1", len(recs))
			}
			wantResult, wantCategory := ResultAllow, ""
			if !tc.wantAllow {
				wantResult, wantCategory = ResultDeny, d.Deny.Category
			}
			if recs[0].result != wantResult || recs[0].category != wantCategory || recs[0].duration < 0 {
				t.Fatalf("observer saw %+v, want %s/%s", recs[0], wantResult, wantCategory)
			}
		})
	}
}

func checkDecision(t *testing.T, d Decision, tc decisionCase) {
	t.Helper()
	if tc.wantAllow {
		if !d.Allowed || d.Deny != nil || d.Identity == nil {
			t.Fatalf("Verify() = %+v, want allow", d)
		}
		if d.Identity.AnsName != fixtureAnsName || d.Identity.AgentID != fixtureAgentID {
			t.Fatalf("Identity = %+v, want %s/%s", d.Identity, fixtureAnsName, fixtureAgentID)
		}
		return
	}
	if d.Allowed || d.Deny == nil || d.Identity != nil || d.Headers != nil || d.Metadata != nil || d.RemoveHeaders != nil {
		t.Fatalf("Verify() = %+v, want a bare denial", d)
	}
	if d.Deny.HTTPStatus != tc.wantStatus {
		t.Fatalf("HTTPStatus = %d (%s), want %d", d.Deny.HTTPStatus, d.Deny.Category, tc.wantStatus)
	}
	if len(tc.wantOneOf) > 0 {
		if !slices.Contains(tc.wantOneOf, d.Deny.Category) {
			t.Fatalf("Category = %q, want one of %v", d.Deny.Category, tc.wantOneOf)
		}
	} else if d.Deny.Category != tc.wantCategory {
		t.Fatalf("Category = %q, want %q", d.Deny.Category, tc.wantCategory)
	}
	if d.Deny.RetryAfter != tc.wantRetryAfter {
		t.Fatalf("RetryAfter = %v, want %v", d.Deny.RetryAfter, tc.wantRetryAfter)
	}
}

func TestNewVerifierErrors(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	keys := f.keyring(t)
	cache := replay.NewMemory(t.Context(), 10, nil)
	t.Cleanup(func() { _ = cache.Close() })
	noHosts := testConfig()
	noHosts.TrustedHosts = nil
	tests := []struct {
		name    string
		cfg     Config
		keys    *Keyring
		cache   replay.Cache
		wantErr string
	}{
		{name: "invalid config", cfg: noHosts, keys: keys, cache: cache, wantErr: "trustedHosts"},
		{name: "nil keyring", cfg: testConfig(), cache: cache, wantErr: "keyring"},
		{name: "nil cache", cfg: testConfig(), keys: keys, wantErr: "replay cache"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			v, err := NewVerifier(tc.cfg, tc.keys, tc.cache, nil, nil)
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("NewVerifier() = %v, %v; want error containing %q", v, err, tc.wantErr)
			}
		})
	}
}

func TestNewVerifierDefaults(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	cache := replay.NewMemory(t.Context(), 10, nil)
	defer cache.Close()
	v, err := NewVerifier(testConfig(), f.keyring(t), cache, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := v.obs.(NoopObserver); !ok {
		t.Fatalf("observer defaulted to %T, want NoopObserver", v.obs)
	}
	if v.logger == nil {
		t.Fatal("logger must default to a discarding logger")
	}
}

func TestVerifyReplay(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	v := f.verifier(t, testConfig())
	r := signedGet(t, f)
	if d := v.Verify(t.Context(), r); !d.Allowed {
		t.Fatalf("first use denied: %+v", d.Deny)
	}
	d := v.Verify(t.Context(), r)
	if d.Allowed || d.Deny.HTTPStatus != http.StatusUnauthorized || d.Deny.Category != CategoryReplay {
		t.Fatalf("replayed request = %+v, want 401 %s", d, CategoryReplay)
	}
}

// switchLookup knows the fixture's key only once a refresh has switched it on.
type switchLookup struct {
	real scitt.KeyLookup
	on   atomic.Bool
}

func (s *switchLookup) Get(kid [4]byte) (*scitt.TrustedKey, error) {
	if !s.on.Load() {
		return nil, errors.New("miss")
	}
	return s.real.Get(kid)
}

func TestVerifyUnknownKidRefresh(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		refresh   func(sw *switchLookup) error
		wantAllow bool
	}{
		{name: "refresh gains the key", refresh: func(sw *switchLookup) error { sw.on.Store(true); return nil }, wantAllow: true},
		{name: "refresh fails", refresh: func(*switchLookup) error { return errors.New("tl down") }},
		{name: "refresh succeeds without the key", refresh: func(*switchLookup) error { return nil }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			sw := &switchLookup{real: f.lookup}
			var attempts atomic.Int32
			obs := &recObserver{}
			keys := mustKeyring(t, obs, KeySource{Name: "tl", Lookup: sw, Refresh: func(context.Context) error {
				attempts.Add(1)
				return tc.refresh(sw)
			}})
			v := f.verifier(t, testConfig(), withKeys(keys), withObserver(obs))
			d := v.Verify(t.Context(), signedGet(t, f))
			if d.Allowed != tc.wantAllow {
				t.Fatalf("Verify() = %+v, want allowed=%v", d, tc.wantAllow)
			}
			if !tc.wantAllow && (d.Deny.HTTPStatus != http.StatusUnauthorized || d.Deny.Category != string(pop.ErrStatusInvalid)) {
				t.Fatalf("Verify() denial = %+v, want 401 %s", d.Deny, pop.ErrStatusInvalid)
			}
			if got := attempts.Load(); got != 1 {
				t.Fatalf("%d refresh attempts, want exactly 1", got)
			}
			if got := obs.refreshRecords(); len(got) != 1 || got[0].name != "tl" {
				t.Fatalf("observer saw %+v, want one refresh for tl", got)
			}
		})
	}
}

func TestVerifyReplayCacheFull(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	mem := replay.NewMemory(t.Context(), 1, nil)
	defer mem.Close()
	v := f.verifier(t, testConfig(), withCache(mem))
	if d := v.Verify(t.Context(), signedGet(t, f)); !d.Allowed {
		t.Fatalf("first request denied: %+v", d.Deny)
	}
	d := v.Verify(t.Context(), signedGet(t, f))
	want := Denial{HTTPStatus: http.StatusServiceUnavailable, Category: CategoryReplayCacheFull, RetryAfter: time.Second}
	if d.Allowed || withoutDetail(d.Deny) != want {
		t.Fatalf("second request = %+v, want %+v", d, want)
	}
}

// withoutDetail strips the log-only reason so denials compare on their contract.
func withoutDetail(d *Denial) Denial {
	if d == nil {
		return Denial{}
	}
	got := *d
	got.Detail = ""
	return got
}

func TestVerifyReplayBackendOutcomes(t *testing.T) {
	t.Parallel()
	const stall = 30 * time.Millisecond
	tests := []struct {
		name         string
		check        func(ctx context.Context) (bool, error)
		checkTimeout time.Duration
		want         Denial
		wantTimeouts int
	}{
		{name: "unavailable", check: func(context.Context) (bool, error) {
			return false, &pop.ProofError{Type: pop.ErrReplayCacheFull, Message: "down", Cause: replay.ErrUnavailable}
		}, want: Denial{HTTPStatus: http.StatusServiceUnavailable, Category: CategoryReplayCacheUnavailable, RetryAfter: time.Second}},
		{name: "keyspace reset", check: func(context.Context) (bool, error) {
			return false, &pop.ProofError{Type: pop.ErrReplayCacheFull, Message: "reset", Cause: replay.ErrKeyspaceReset}
		}, want: Denial{HTTPStatus: http.StatusServiceUnavailable, Category: CategoryReplayCacheUnavailable, RetryAfter: time.Second}},
		{name: "full", check: func(context.Context) (bool, error) {
			return false, &pop.ProofError{Type: pop.ErrReplayCacheFull, Message: "full", Cause: replay.ErrFull}
		}, want: Denial{HTTPStatus: http.StatusServiceUnavailable, Category: CategoryReplayCacheFull, RetryAfter: time.Second}},
		{name: "unclassified error", check: func(context.Context) (bool, error) {
			return false, errors.New("boom")
		}, want: Denial{HTTPStatus: http.StatusServiceUnavailable, Category: CategoryMisconfigured}},
		{name: "plain error wrapping unavailable", check: func(context.Context) (bool, error) {
			return false, fmt.Errorf("dial: %w", replay.ErrUnavailable)
		}, want: Denial{HTTPStatus: http.StatusServiceUnavailable, Category: CategoryReplayCacheUnavailable, RetryAfter: time.Second}},
		{name: "plain error wrapping full", check: func(context.Context) (bool, error) {
			return false, fmt.Errorf("set: %w", replay.ErrFull)
		}, want: Denial{HTTPStatus: http.StatusServiceUnavailable, Category: CategoryReplayCacheFull, RetryAfter: time.Second}},
		{name: "misconfigured proof error passes through", check: func(context.Context) (bool, error) {
			return false, &pop.ProofError{Type: pop.ErrMisconfigured, Message: "wiring"}
		}, want: Denial{HTTPStatus: http.StatusServiceUnavailable, Category: CategoryMisconfigured}},
		{name: "client gone proof error passes through", check: func(context.Context) (bool, error) {
			return false, &pop.ProofError{Type: pop.ErrClientGone, Message: "gone"}
		}, want: Denial{HTTPStatus: http.StatusServiceUnavailable, Category: CategoryClientGone}},
		{name: "seen", check: func(context.Context) (bool, error) { return true, nil },
			want: Denial{HTTPStatus: http.StatusUnauthorized, Category: CategoryReplay}},
		{name: "stalls past the check timeout", checkTimeout: stall, check: func(ctx context.Context) (bool, error) {
			<-ctx.Done()
			return false, ctx.Err()
		}, want: Denial{HTTPStatus: http.StatusServiceUnavailable, Category: CategoryTimeout}, wantTimeouts: 1},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			cfg := testConfig()
			if tc.checkTimeout > 0 {
				cfg.CheckTimeout = tc.checkTimeout
			}
			obs := &recObserver{}
			cache := &fakeCache{check: func(ctx context.Context, _ string, _ time.Time) (bool, error) { return tc.check(ctx) }}
			v := f.verifier(t, cfg, withCache(cache), withObserver(obs))
			d := v.Verify(t.Context(), signedGet(t, f))
			if d.Allowed || d.Deny == nil {
				t.Fatalf("Verify() = %+v, want a denial", d)
			}
			got := *d.Deny
			if got.Detail == "" {
				t.Fatal("backend denial must carry a detail for the decision log")
			}
			got.Detail = ""
			if got != tc.want {
				t.Fatalf("Verify() = %+v, want %+v", got, tc.want)
			}
			if got := obs.timeoutCount(); got != tc.wantTimeouts {
				t.Fatalf("CheckTimeout observed %d times, want %d", got, tc.wantTimeouts)
			}
		})
	}
}

func TestVerifyCallerContext(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	t.Run("cancelled before the check", func(t *testing.T) {
		t.Parallel()
		obs := &recObserver{}
		v := f.verifier(t, testConfig(), withObserver(obs))
		ctx, cancel := context.WithCancel(t.Context())
		cancel()
		d := v.Verify(ctx, signedGet(t, f))
		want := Denial{HTTPStatus: http.StatusServiceUnavailable, Category: CategoryClientGone}
		if d.Allowed || withoutDetail(d.Deny) != want || obs.timeoutCount() != 0 {
			t.Fatalf("Verify() = %+v (timeouts %d), want %+v", d, obs.timeoutCount(), want)
		}
	})
	t.Run("deadline already passed", func(t *testing.T) {
		t.Parallel()
		obs := &recObserver{}
		v := f.verifier(t, testConfig(), withObserver(obs))
		ctx, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
		defer cancel()
		d := v.Verify(ctx, signedGet(t, f))
		want := Denial{HTTPStatus: http.StatusServiceUnavailable, Category: CategoryTimeout}
		if d.Allowed || withoutDetail(d.Deny) != want || obs.timeoutCount() != 1 {
			t.Fatalf("Verify() = %+v (timeouts %d), want %+v", d, obs.timeoutCount(), want)
		}
	})
	t.Run("gateway hangs up during the replay call", func(t *testing.T) {
		t.Parallel()
		ctx, cancel := context.WithCancel(t.Context())
		defer cancel()
		cache := &fakeCache{check: func(context.Context, string, time.Time) (bool, error) {
			cancel()
			return false, ctx.Err()
		}}
		v := f.verifier(t, testConfig(), withCache(cache))
		d := v.Verify(ctx, signedGet(t, f))
		want := Denial{HTTPStatus: http.StatusServiceUnavailable, Category: CategoryClientGone}
		if d.Allowed || withoutDetail(d.Deny) != want {
			t.Fatalf("Verify() = %+v, want %+v", d, want)
		}
	})
}

func TestVerifyAllowContract(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		strip      bool
		withToken  bool
		wantRemove []string
	}{
		{name: "strip without token", strip: true, wantRemove: []string{"x-scitt-receipt", "x-ans-status-token", "dpop"}},
		{name: "strip with DPoP token", strip: true, withToken: true, wantRemove: []string{"x-scitt-receipt", "x-ans-status-token"}},
		{name: "no strip"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			f := newFixture(t)
			cfg := testConfig()
			cfg.StripIdentityHeaders = tc.strip
			cfg.RequireTokenClaims = false
			v := f.verifier(t, cfg)
			var before func(*http.Request)
			if tc.withToken {
				before = withDPoPToken(f.token(t))
			}
			d := v.Verify(t.Context(), f.signed(t, http.MethodGet, fixtureTarget, nil, before))
			if !d.Allowed {
				t.Fatalf("denied: %+v", d.Deny)
			}
			fp := sha256.Sum256(f.bundle.CertDER)
			wantHeaders := map[string]string{
				"X-ANS-Name":        fixtureAnsName,
				"X-ANS-Agent-Id":    fixtureAgentID,
				"X-ANS-Fingerprint": hex.EncodeToString(fp[:]),
				"X-ANS-JKT":         f.signer.JKT(),
			}
			if len(d.Headers) != len(wantHeaders) {
				t.Fatalf("Headers = %v, want %v", d.Headers, wantHeaders)
			}
			for k, want := range wantHeaders {
				if d.Headers[k] != want {
					t.Fatalf("Headers[%s] = %q, want %q", k, d.Headers[k], want)
				}
			}
			wantMeta := map[string]any{
				"ans_name": fixtureAnsName, "agent_id": fixtureAgentID,
				"fingerprint": hex.EncodeToString(fp[:]), "jkt": f.signer.JKT(),
			}
			if len(d.Metadata) != len(wantMeta) {
				t.Fatalf("Metadata = %v, want %v", d.Metadata, wantMeta)
			}
			for k, want := range wantMeta {
				if d.Metadata[k] != want {
					t.Fatalf("Metadata[%s] = %v, want %v", k, d.Metadata[k], want)
				}
			}
			if !slices.Equal(d.RemoveHeaders, tc.wantRemove) {
				t.Fatalf("RemoveHeaders = %v, want %v", d.RemoveHeaders, tc.wantRemove)
			}
			for name := range d.Headers {
				if slices.Contains(d.RemoveHeaders, strings.ToLower(name)) {
					t.Fatalf("%s is both set and removed; Envoy applies removals after additions", name)
				}
			}
			if d.Identity.JKT != f.signer.JKT() || d.Identity.FingerprintHex() != hex.EncodeToString(fp[:]) {
				t.Fatalf("Identity = %+v", d.Identity)
			}
		})
	}
}

func TestVerifyMisconfigurationLogs(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	cfg := testConfig()
	cfg.TrustedHosts = []string{"https://api.example", "https://alt.example"}
	requireContext(&cfg)
	var buf bytes.Buffer
	v := f.verifier(t, cfg, withLogger(slog.New(slog.NewTextHandler(&buf, nil))))
	clock := newFakeClock()
	v.now = clock.now
	errorLines := func() int { return strings.Count(buf.String(), "level=ERROR") }

	for range 3 {
		if d := v.Verify(t.Context(), signedGet(t, f)); d.Allowed || d.Deny.Category != CategoryMisconfigured {
			t.Fatalf("Verify() = %+v, want %s", d, CategoryMisconfigured)
		}
	}
	if got := errorLines(); got != 1 {
		t.Fatalf("%d error lines after three denials inside one minute, want 1", got)
	}
	clock.advance(61 * time.Second)
	v.Verify(t.Context(), signedGet(t, f))
	if got := errorLines(); got != 2 {
		t.Fatalf("%d error lines after the window elapsed, want 2", got)
	}
	v.Verify(t.Context(), f.signed(t, http.MethodGet, "https://alt.example/v1/resource", nil, nil))
	if got := errorLines(); got != 3 {
		t.Fatalf("%d error lines after a second authority, want 3", got)
	}

	withContext := signedGet(t, f)
	withContext.Context = map[string]string{contextKey: contextValue}
	withContext.Header.Set("Content-Length", "10")
	if d := v.Verify(t.Context(), withContext); d.Allowed || d.Deny.Category != CategoryMisconfigured {
		t.Fatalf("Verify() = %+v, want %s", d, CategoryMisconfigured)
	}
	if got := errorLines(); got != 4 {
		t.Fatalf("%d error lines after a missing body, want 4", got)
	}
	tokenReq := f.signed(t, http.MethodGet, fixtureTarget, nil, withDPoPToken(f.token(t)))
	tokenReq.Context = map[string]string{contextKey: contextValue}
	if d := v.Verify(t.Context(), tokenReq); d.Allowed || d.Deny.Category != CategoryMisconfigured {
		t.Fatalf("Verify() = %+v, want %s", d, CategoryMisconfigured)
	}
	if got := errorLines(); got != 5 {
		t.Fatalf("%d error lines after missing token claims, want 5", got)
	}
	if proof := tokenReq.Header.Get(pop.DPoPHeader); strings.Contains(buf.String(), proof) {
		t.Fatal("log output must never carry header values")
	}
}

func TestVerifyObserverDecisions(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	obs := &recObserver{}
	v := f.verifier(t, testConfig(), withObserver(obs))
	v.Verify(t.Context(), signedGet(t, f))
	v.Verify(t.Context(), bare(t, http.MethodGet, fixtureTarget, nil))
	recs := obs.decisionRecords()
	want := []decisionRecord{{result: ResultAllow}, {result: ResultDeny, category: CategoryMissingHeaders}}
	if len(recs) != len(want) {
		t.Fatalf("observer saw %+v, want %+v", recs, want)
	}
	for i := range want {
		if recs[i].result != want[i].result || recs[i].category != want[i].category || recs[i].duration < 0 {
			t.Fatalf("decision %d = %+v, want %+v", i, recs[i], want[i])
		}
	}
}

func TestVerifyExtraIdentityHeaders(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	cfg := testConfig()
	cfg.ExtraIdentityHeaders = map[string]string{"x-ai-eg-mcp-subject": MetadataAgentID, "X-Caller": MetadataANSName, "x-caller-key": MetadataJKT}
	v := f.verifier(t, cfg)
	d := v.Verify(t.Context(), signedGet(t, f))
	if !d.Allowed {
		t.Fatalf("denied: %+v", d.Deny)
	}
	want := map[string]string{"x-ai-eg-mcp-subject": fixtureAgentID, "X-Caller": fixtureAnsName, "x-caller-key": f.signer.JKT()}
	for name, value := range want {
		if d.Headers[name] != value {
			t.Fatalf("Headers[%s] = %q, want %q", name, d.Headers[name], value)
		}
	}
	if len(d.Headers) != 4+len(want) {
		t.Fatalf("Headers = %v, want the four standard headers plus %d extra", d.Headers, len(want))
	}
	for name := range d.Headers {
		if slices.Contains(d.RemoveHeaders, strings.ToLower(name)) {
			t.Fatalf("%s is both set and removed", name)
		}
	}
}

func TestIdentityHeadersRejectUnsafeValues(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	v := f.verifier(t, testConfig())
	tests := []struct {
		name string
		id   pop.CallerIdentity
		ok   bool
	}{
		{name: "clean identity", id: pop.CallerIdentity{AnsName: fixtureAnsName, AgentID: fixtureAgentID, JKT: "thumb"}, ok: true},
		{name: "CRLF in the name", id: pop.CallerIdentity{AnsName: "ans://x\r\nX-Injected: 1", AgentID: fixtureAgentID}},
		{name: "control byte in the agent id", id: pop.CallerIdentity{AnsName: fixtureAnsName, AgentID: "agent\x00"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			headers, err := v.identityHeaders(&tc.id)
			if (err == nil) != tc.ok {
				t.Fatalf("identityHeaders() = %v, %v; want ok=%v", headers, err, tc.ok)
			}
			if tc.ok && headers[HeaderANSName] != tc.id.AnsName {
				t.Fatalf("Headers = %v", headers)
			}
		})
	}
}

func TestVerifyKeyspaceResetRetryAfter(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	clock := newFakeClock()
	until := clock.now().Add(30 * time.Second)
	cache := &fakeCache{check: func(context.Context, string, time.Time) (bool, error) {
		return false, &pop.ProofError{Type: pop.ErrReplayCacheFull, Message: "reset", Cause: &replay.KeyspaceResetError{Until: until}}
	}}
	v := f.verifier(t, testConfig(), withCache(cache))
	v.now = clock.now
	d := v.Verify(t.Context(), signedGet(t, f))
	if d.Allowed || d.Deny.Category != CategoryReplayCacheUnavailable || d.Deny.RetryAfter != 30*time.Second {
		t.Fatalf("Verify() = %+v, want REPLAY_CACHE_UNAVAILABLE with Retry-After 30s", d.Deny)
	}
	if !strings.Contains(d.Deny.Detail, "reset") {
		t.Fatalf("Detail = %q, want the backend reason", d.Deny.Detail)
	}
}

func TestVerifyDenialDetail(t *testing.T) {
	t.Parallel()
	f := newFixture(t)
	v := f.verifier(t, testConfig())
	if d := v.Verify(t.Context(), bare(t, http.MethodGet, fixtureTarget, nil)); d.Deny == nil || d.Deny.Detail == "" {
		t.Fatalf("SDK denial must carry a detail: %+v", d.Deny)
	}
	if d := v.Verify(t.Context(), nil); d.Deny == nil || d.Deny.Detail != "" {
		t.Fatalf("shape denial must not carry a detail: %+v", d.Deny)
	}
}
