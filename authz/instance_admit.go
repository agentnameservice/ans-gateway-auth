package authz

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/agentnameservice/ans-sdk-go/pop"
	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

// admitInstance applies the per-sub cap and then records the proof's jti. A
// cap slot taken for a request the replay check then refuses is given back.
func (v *Verifier) admitInstance(ctx context.Context, it *instanceToken, proof *instanceProof, now int64) error {
	c := it.claims
	added := false
	if v.instances != nil {
		var ok bool
		if added, ok = v.instances.admit(c.iss+"\x00"+c.sub, c.jkt, c.exp, now); !ok {
			return refusePolicy(codeInstanceCap, fmt.Sprintf("%s already holds %d live instance keys",
				echoValue(c.sub), v.cfg.InstanceMode.MaxInstancesPerSub))
		}
	}
	err := v.recordInstanceJTI(ctx, proof)
	if err != nil && added {
		v.instances.forget(c.iss+"\x00"+c.sub, c.jkt)
	}
	return err
}

func (v *Verifier) recordInstanceJTI(ctx context.Context, proof *instanceProof) error {
	key := sha256.Sum256([]byte(instanceReplayPrefix + proof.jti))
	exp := time.Unix(proof.iat, 0).Add(v.cfg.PoPSkew + instanceReplayGrace)
	seen, err := v.cache.CheckAndStore(ctx, b64url(key[:]), exp)
	if err != nil {
		return err
	}
	if seen {
		return refuse(codeReplay, CategoryReplay, "DPoP jti already used")
	}
	return nil
}

// instanceAllow builds the identity contract. Every header is set with
// overwrite semantics; an optional header the token does not carry is
// removed instead, so a client-supplied value never survives.
func (v *Verifier) instanceAllow(it *instanceToken, st *scitt.VerifiedStatusToken) (Decision, error) {
	c := it.claims
	id := &pop.CallerIdentity{AnsName: c.ansName, AgentID: st.Payload.AgentID,
		Fingerprint: sha256.Sum256(it.certDER), JKT: c.jkt}
	fingerprint := hex.EncodeToString(id.Fingerprint[:])
	attributes := map[string]string{
		// agent_id names the instance, not the issuer, for extraIdentityHeaders:
		// a gateway keying a session subject on it must not merge every
		// instance an issuer signs into one session.
		MetadataANSName: id.AnsName, MetadataAgentID: c.jkt, MetadataFingerprint: fingerprint, MetadataJKT: c.jkt,
	}
	headers := map[string]string{
		HeaderANSName: id.AnsName, HeaderANSAgentID: id.AgentID, HeaderANSFingerprint: fingerprint,
		HeaderANSJKT: id.JKT, HeaderANSInstanceSub: c.sub,
	}
	metadata := map[string]any{
		MetadataANSName: id.AnsName, MetadataAgentID: id.AgentID, MetadataFingerprint: fingerprint,
		MetadataJKT: id.JKT, MetadataInstanceSub: c.sub,
	}
	var remove []string
	optional := []struct {
		header, metadata, value string
		present                 bool
	}{
		{HeaderANSScope, MetadataScope, c.scope, c.hasScope},
		{HeaderANSAct, MetadataAct, compactJSON(c.act), c.act != nil},
		{HeaderANSAuthorizationDetails, "", compactJSON(c.authorizationDetails), c.authorizationDetails != nil},
	}
	for _, o := range optional {
		if !o.present {
			remove = append(remove, strings.ToLower(o.header))
			continue
		}
		headers[o.header] = o.value
		if o.metadata != "" {
			metadata[o.metadata] = o.value
		}
	}
	for _, e := range v.extra {
		headers[e.name] = attributes[e.attribute]
	}
	for name, value := range headers {
		if !validHeaderValue(value) {
			return Decision{}, fmt.Errorf("identity attribute for header %s is not a valid header field value", name)
		}
	}
	if v.cfg.StripIdentityHeaders {
		// The verifier is the token's audience and has consumed the proof, so
		// neither is meant for the upstream.
		remove = append(remove, strings.ToLower(scitt.HeaderReceipt), strings.ToLower(scitt.HeaderStatusToken),
			strings.ToLower(pop.DPoPHeader), strings.ToLower(headerAuthorization))
	}
	return Decision{Allowed: true, Identity: id, Headers: headers, RemoveHeaders: remove, Metadata: metadata}, nil
}

// instanceCap counts the distinct instance keys each issuer sub presents
// while their tokens are live.
type instanceCap struct {
	max       int
	mu        sync.Mutex
	subs      map[string]map[string]int64 // sub key -> jkt -> token exp
	lastSweep int64
}

func newInstanceCap(limit int) *instanceCap {
	if limit <= 0 {
		return nil
	}
	return &instanceCap{max: limit, subs: make(map[string]map[string]int64)}
}

// admit counts jkt for key until exp. ok is false when key already holds the
// maximum number of other live keys; added reports a newly counted key.
func (c *instanceCap) admit(key, jkt string, exp, now int64) (bool, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if now-c.lastSweep >= capSweepInterval {
		for k, keys := range c.subs {
			pruneExpired(keys, now)
			if len(keys) == 0 {
				delete(c.subs, k)
			}
		}
		c.lastSweep = now
	}
	keys := c.subs[key]
	if keys == nil {
		keys = make(map[string]int64)
		c.subs[key] = keys
	}
	pruneExpired(keys, now)
	if prev, known := keys[jkt]; known {
		keys[jkt] = max(prev, exp)
		return false, true
	}
	if len(keys) >= c.max {
		return false, false
	}
	keys[jkt] = exp
	return true, true
}

func (c *instanceCap) forget(key, jkt string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if keys := c.subs[key]; keys != nil {
		delete(keys, jkt)
		if len(keys) == 0 {
			delete(c.subs, key)
		}
	}
}

func pruneExpired(keys map[string]int64, now int64) {
	for jkt, exp := range keys {
		if now >= exp {
			delete(keys, jkt)
		}
	}
}
