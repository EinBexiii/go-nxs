package admission

import (
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestDiagnosticFixtures(t *testing.T) {
	b, err := os.ReadFile("testdata/diagnostic-v1.fixtures.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		Context struct{ Incarnation string }
		Key     struct{ KeyID, Secret string }
		Vectors []struct {
			Name   string
			Claims struct {
				ExpiresAt                                      int64
				AttemptIdHex, OfferDigestHex, TargetAddressHex string
				CandidateRevision                              uint64
				Family, TargetPort, Profile                    int
			}
			RemoteUfrag, NonceHex, LocalUfrag, IcePwd string
		}
	}
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	_ = json.Unmarshal(b, &raw)
	key := Key{ID: f.Key.KeyID, Secret: f.Key.Secret}
	audience := Audience(f.Context.Incarnation)
	for i, v := range f.Vectors {
		claims := raw["vectors"].([]any)[i].(map[string]any)["claims"].(map[string]any)
		c := Claims{
			ExpiresAt:      time.UnixMilli(v.Claims.ExpiresAt),
			SCTPPort:       5000,
			MaxMessageSize: 262144,
			Password:       claims["clientIcePwd"].(string),
		}
		fp, _ := hex.DecodeString(claims["clientFingerprintHex"].(string))
		copy(c.Fingerprint[:], fp)
		id, _ := hex.DecodeString(v.Claims.AttemptIdHex)
		copy(c.IdentityBinding[:], id)
		d := &Diagnostic{CandidateRevision: v.Claims.CandidateRevision, Profile: v.Claims.Profile}
		digest, _ := hex.DecodeString(v.Claims.OfferDigestHex)
		copy(d.OfferDigest[:], digest)
		addr, _ := hex.DecodeString(v.Claims.TargetAddressHex)
		ip := netip.AddrFrom16([16]byte(addr))
		if v.Claims.Family == 4 {
			ip = netip.AddrFrom4([4]byte(addr[12:]))
		}
		d.Target = netip.AddrPortFrom(ip, uint16(v.Claims.TargetPort))
		c.Diagnostic = d

		var nonce [12]byte
		n, _ := hex.DecodeString(v.NonceHex)
		copy(nonce[:], n)
		token, err := key.Seal(audience, v.RemoteUfrag, c, nonce)
		if err != nil {
			t.Fatalf("%s: seal: %v", v.Name, err)
		}
		if token != v.LocalUfrag {
			t.Fatalf("%s: token mismatch:\n got %s\nwant %s", v.Name, token, v.LocalUfrag)
		}
		if pwd := key.ICEPassword(audience, token); pwd != v.IcePwd {
			t.Fatalf("%s: ICE password mismatch", v.Name)
		}
		opened, err := key.Open(audience, token, v.RemoteUfrag)
		if err != nil {
			t.Fatalf("%s: open: %v", v.Name, err)
		}
		if opened.NetworkID != 0 || opened.Diagnostic == nil || *opened.Diagnostic != *d || opened.IdentityBinding != c.IdentityBinding {
			t.Fatalf("%s: unexpected claims %+v", v.Name, opened)
		}
	}
}
