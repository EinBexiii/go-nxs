package nxs

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

type diagnosticFixtures struct {
	Vectors []struct {
		Name, Offer, RemoteUfrag string
	}
	Answers []struct {
		Name, HostFingerprintHex, Answer string
	}
}

func loadDiagnosticFixtures(t testing.TB) diagnosticFixtures {
	b, err := os.ReadFile("testdata/diagnostic-v1.fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var f diagnosticFixtures
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestAnswerFixtures(t *testing.T) {
	for _, a := range loadDiagnosticFixtures(t).Answers {
		if strings.HasSuffix(a.Name, "assisted") {
			continue
		}
		fp, _ := hex.DecodeString(a.HostFingerprintHex)
		line := sdpField(a.Answer, "candidate")
		f := strings.Fields(line)
		c := candidate{Address: f[4], Type: f[7]}
		var port int
		for _, r := range f[5] {
			port = port*10 + int(r-'0')
		}
		c.Port = uint16(port)
		got := answer(sdpField(a.Answer, "ice-ufrag"), sdpField(a.Answer, "ice-pwd"), "sha-256 "+colonHex(fp), []candidate{c})
		if got != a.Answer {
			t.Errorf("%s: answer mismatch:\n got %q\nwant %q", a.Name, got, a.Answer)
		}
	}
}

func TestParseOfferFixtures(t *testing.T) {
	for _, v := range loadDiagnosticFixtures(t).Vectors {
		o, err := parseOffer(v.Offer)
		if err != nil {
			t.Fatalf("%s: %v", v.Name, err)
		}
		if o.ufrag != v.RemoteUfrag || len(o.candidates) != 1 || len(o.fingerprint) != 32 {
			t.Fatalf("%s: unexpected offer %+v", v.Name, o)
		}
	}
	for _, bad := range []string{
		"",
		strings.Replace(loadDiagnosticFixtures(t).Vectors[0].Offer, "actpass", "active", 1),
		strings.Replace(loadDiagnosticFixtures(t).Vectors[0].Offer, "262144", "65536", 1),
		strings.Replace(loadDiagnosticFixtures(t).Vectors[0].Offer, "a=candidate", "a=x-candidate", 1),
		loadDiagnosticFixtures(t).Vectors[0].Offer + "a=ice-lite\r\n",
	} {
		if _, err := parseOffer(bad); err == nil {
			t.Errorf("offer should be rejected: %q", bad)
		}
	}
}

func FuzzParseOffer(f *testing.F) {
	for _, v := range loadDiagnosticFixtures(f).Vectors {
		f.Add(v.Offer)
	}
	f.Fuzz(func(t *testing.T, s string) { _, _ = parseOffer(s) })
}

func FuzzDecodeAssistedJoin(f *testing.F) {
	f.Add([]byte(`{"kind":"assisted-join","version":1,"id":"0123456789abcdef0123456789abcdef"}`))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = decodeAssistedJoin(b) })
}

func FuzzParsePong(f *testing.F) {
	f.Add([]byte("MCPE;Test;1000;1.26.0;0;10;1;world;Survival;1;0;0;0;0;"))
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = parsePong(b) })
}
