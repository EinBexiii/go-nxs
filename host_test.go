package nxs

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"testing"
	"time"

	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-nxs/admission"
)

func TestVerifierReleasesKey(t *testing.T) {
	h := &host{log: testLog(), report: func(event) {}, conns: make(map[uint64]*attempt), gameOutcomes: true,
		audience: admission.Audience("00000000000000000000000000000000")}
	key := admission.Key{ID: "K001", Secret: "fake-provider-secret-at-least-32-bytes"}
	identity, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	binding, _ := key.Binding(h.audience, &identity.PublicKey)
	claims := admission.Claims{ExpiresAt: time.Now().Add(time.Minute), IdentityBinding: binding}

	a := &attempt{}
	verify := h.verifier(a, key, claims)
	if err := verify(&identity.PublicKey); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if a.key.Load() != nil {
		t.Fatal("a verified login should release its key")
	}
	if verify(&identity.PublicKey) == nil {
		t.Fatal("verify should be one-shot")
	}

	a = &attempt{}
	other, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if h.verifier(a, key, claims)(&other.PublicKey) == nil || a.key.Load() != nil {
		t.Fatal("a mismatched login should be rejected and release its key")
	}

	a = &attempt{}
	verify = h.verifier(a, key, admission.Claims{ExpiresAt: time.Now().Add(100 * time.Millisecond), IdentityBinding: binding})
	waitFor(t, func() bool { return a.key.Load() == nil })
	if verify(&identity.PublicKey) == nil {
		t.Fatal("an expired login should be rejected")
	}

	a = &attempt{}
	verify = h.verifier(a, key, claims)
	h.fail(a, "closed", nil)
	if a.key.Load() != nil || verify(&identity.PublicKey) == nil {
		t.Fatal("a failed admission should release its key")
	}

	a = &attempt{connectionID: 1}
	verify = h.verifier(a, key, claims)
	h.conns[1] = a
	h.gameOutcome(&nethernet.Addr{ConnectionID: 1}, "ticket.game_rejected", "banned")
	if a.key.Load() != nil || verify(&identity.PublicKey) == nil {
		t.Fatal("a rejected login should release its key")
	}
}
