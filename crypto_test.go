package nxs

import (
	"crypto/sha256"
	"encoding/json"
	"os"
	"testing"
)

type nxsFixture struct {
	PublicKeyJwk   jwk
	Challenge      challenge
	ProofNonce     string
	IdempotencyKey string
	Proof          struct{ Payload, Signature string }
	Request        struct {
		Input struct {
			Audience, Method, Path, InstanceID, KeyID, IdempotencyKey, Body string
			Timestamp, Generation, Sequence                                 int64
		}
		Payload, Signature string
	}
}

func loadNXSFixture(t *testing.T) nxsFixture {
	t.Helper()
	b, err := os.ReadFile("testdata/nxs-v1.fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var f nxsFixture
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestFixtureProof(t *testing.T) {
	f := loadNXSFixture(t)
	pub, err := f.PublicKeyJwk.publicKey()
	if err != nil {
		t.Fatal(err)
	}
	if got := f.PublicKeyJwk.thumbprint(); got != f.Challenge.Thumbprint {
		t.Fatalf("thumbprint: got %s, want %s", got, f.Challenge.Thumbprint)
	}
	if err := f.Challenge.validate("https://provider.example", f.Challenge.Thumbprint); err != nil {
		t.Fatalf("validate challenge: %v", err)
	}
	proof, err := f.Challenge.proof(f.ProofNonce, f.IdempotencyKey)
	if err != nil {
		t.Fatal(err)
	}
	if string(proof) != f.Proof.Payload {
		t.Fatalf("proof payload:\n got %s\nwant %s", proof, f.Proof.Payload)
	}
	if !verify(pub, proof, f.Proof.Signature) {
		t.Fatal("fixture proof signature did not verify")
	}
}

func TestFixtureRequest(t *testing.T) {
	f := loadNXSFixture(t)
	in := f.Request.Input
	payload, err := requestPayload(in.Audience, in.Method, in.Path, in.Timestamp, in.InstanceID, in.KeyID, in.IdempotencyKey, in.Generation, in.Sequence, []byte(in.Body))
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != f.Request.Payload {
		t.Fatalf("request payload:\n got %s\nwant %s", payload, f.Request.Payload)
	}
	pub, _ := f.PublicKeyJwk.publicKey()
	if !verify(pub, payload, f.Request.Signature) {
		t.Fatal("fixture request signature did not verify")
	}
}

func TestSign(t *testing.T) {
	key, err := generateMachineKey()
	if err != nil {
		t.Fatal(err)
	}
	sig, err := sign(key, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	pub, err := publicJWK(&key.PublicKey).publicKey()
	if err != nil {
		t.Fatal(err)
	}
	if !verify(pub, []byte("payload"), sig) || verify(pub, []byte("other"), sig) {
		t.Fatal("signature verification mismatch")
	}
	encoded, err := encodePrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodePrivateKey(encoded)
	if err != nil || !decoded.Equal(key) {
		t.Fatalf("private key round trip: %v", err)
	}
}

func TestProofOfWork(t *testing.T) {
	f := loadNXSFixture(t)
	c := f.Challenge
	c.Pow.Difficulty = 12
	nonce, err := c.solve("intent", func() bool { return false })
	if err != nil {
		t.Fatal(err)
	}
	p, _ := c.proof(nonce, "intent")
	if leadingZeroBits(sha256.Sum256(p)) < 12 {
		t.Fatal("proof does not meet difficulty")
	}
}

func TestNormalizeOrigin(t *testing.T) {
	for in, want := range map[string]string{
		"https://Provider.Example":       "https://provider.example",
		"https://provider.example:443":   "https://provider.example",
		"https://provider.example:8443/": "https://provider.example:8443",
		"http://127.0.0.1:8080":          "http://127.0.0.1:8080",
		"http://[::1]:80":                "http://[::1]",
	} {
		if got, err := normalizeOrigin(in); err != nil || got != want {
			t.Errorf("normalizeOrigin(%q) = %q, %v, want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"http://provider.example", "https://user@provider.example", "https://provider.example/path", "https://provider.example?q", "ftp://provider.example"} {
		if _, err := normalizeOrigin(in); err == nil {
			t.Errorf("normalizeOrigin(%q) should fail", in)
		}
	}
}

func TestParsePong(t *testing.T) {
	s, ok := parsePong([]byte("MCPE;My Server;1000;1.26.0;3;20;123;world;Creative;1;19132;19132;0;0;"))
	if !ok || s.Name != "My Server" || s.Level != "world" || s.MaxPlayers != 20 || s.GameType != 1 {
		t.Fatalf("unexpected status %+v", s)
	}
}
