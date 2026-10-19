package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/agentnameservice/ans-sdk-go/verify/scitt"
)

// fakeLog serves a scripted /root-keys answer.
type fakeLog struct {
	mu    sync.Mutex
	lines []string
	err   error
	calls int
}

func (f *fakeLog) set(lines []string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lines, f.err = lines, err
}

func (f *fakeLog) FetchRootKeys(context.Context) ([]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.lines, f.err
}

func (*fakeLog) FetchReceipt(context.Context, string) ([]byte, error) {
	return nil, errors.New("unused")
}
func (*fakeLog) FetchStatusToken(context.Context, string) ([]byte, error) {
	return nil, errors.New("unused")
}

type testKey struct {
	line string
	kid  [4]byte
}

func newTestKey(t *testing.T, name string) testKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	spki, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(spki)
	var kid [4]byte
	copy(kid[:], sum[:4])
	return testKey{line: c2spLine(t, name, &priv.PublicKey), kid: kid}
}

func mustStore(t *testing.T, lines ...string) *scitt.KeyStore {
	t.Helper()
	s, err := scitt.NewKeyStore(lines)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestKeyStoreStatic(t *testing.T) {
	t.Parallel()
	pinned := newTestKey(t, "pinned")
	s := newKeyStore("tl", mustStore(t, pinned.line), nil, discardLogger())
	if err := s.DoRefresh(context.Background()); err != nil {
		t.Fatalf("DoRefresh = %v", err)
	}
	if s.LastRefreshed() != nil || s.Len() != 1 || s.IsEmpty() {
		t.Fatalf("static store state: last=%v len=%d", s.LastRefreshed(), s.Len())
	}
	if _, err := s.Get(pinned.kid); err != nil {
		t.Fatalf("Get(pinned) = %v", err)
	}
}

func TestKeyStoreRefreshReplacesFetchedKeys(t *testing.T) {
	t.Parallel()
	pinned, a, b := newTestKey(t, "pinned"), newTestKey(t, "a"), newTestKey(t, "b")
	log := &fakeLog{lines: []string{a.line}}
	rec := &recordingLog{}
	s := newKeyStore("tl", mustStore(t, pinned.line), log, rec.logger())

	steps := []struct {
		name     string
		serve    []string
		err      error
		wantKeys []testKey
		wantGone []testKey
		wantErr  bool
	}{
		{name: "first fetch adds a", serve: []string{a.line}, wantKeys: []testKey{pinned, a}},
		{name: "log rotates to b and withdraws a", serve: []string{b.line}, wantKeys: []testKey{pinned, b}, wantGone: []testKey{a}},
		{name: "fetch failure keeps the previous snapshot", serve: nil, err: errors.New("503"), wantKeys: []testKey{pinned, b}, wantGone: []testKey{a}, wantErr: true},
		{name: "unparseable payload keeps the previous snapshot", serve: []string{"<html>", "503 Service Unavailable"}, wantKeys: []testKey{pinned, b}, wantGone: []testKey{a}, wantErr: true},
		{name: "empty payload keeps the previous snapshot", serve: []string{}, wantKeys: []testKey{pinned, b}, wantGone: []testKey{a}, wantErr: true},
		{name: "log serves the pinned key only", serve: []string{pinned.line}, wantKeys: []testKey{pinned}, wantGone: []testKey{a, b}},
	}
	var lastRefreshed = s.LastRefreshed()
	for _, st := range steps {
		log.set(st.serve, st.err)
		err := s.DoRefresh(context.Background())
		if (err != nil) != st.wantErr {
			t.Fatalf("%s: DoRefresh = %v", st.name, err)
		}
		for _, k := range st.wantKeys {
			if _, err := s.Get(k.kid); err != nil {
				t.Fatalf("%s: Get(%s) = %v, want present", st.name, k.line[:6], err)
			}
		}
		for _, k := range st.wantGone {
			if _, err := s.Get(k.kid); err == nil {
				t.Fatalf("%s: withdrawn key still trusted", st.name)
			}
		}
		if s.Len() != len(st.wantKeys) {
			t.Fatalf("%s: Len = %d, want %d", st.name, s.Len(), len(st.wantKeys))
		}
		if st.wantErr {
			if s.LastRefreshed() != lastRefreshed {
				t.Fatalf("%s: a failed fetch must not count as a refresh", st.name)
			}
			continue
		}
		if s.LastRefreshed() == nil || s.LastRefreshed() == lastRefreshed {
			t.Fatalf("%s: LastRefreshed not advanced", st.name)
		}
		lastRefreshed = s.LastRefreshed()
	}
	if log.calls != len(steps) {
		t.Fatalf("fetches = %d, want %d", log.calls, len(steps))
	}
	logs := rec.String()
	if !strings.Contains(logs, "root keys refreshed") {
		t.Fatalf("key-set changes must be logged: %s", logs)
	}
	if !strings.Contains(logs, "level=WARN") || !strings.Contains(logs, fmt.Sprintf("a/%x", a.kid)) {
		t.Fatalf("withdrawing a key must be logged at WARN naming the key: %s", logs)
	}
	if !strings.Contains(logs, fmt.Sprintf("b/%x", b.kid)) {
		t.Fatalf("adding a key must be logged naming the key: %s", logs)
	}
}
