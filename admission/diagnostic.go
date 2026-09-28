package admission

import (
	"encoding/binary"
	"net/netip"
)

// Diagnostic profiles.
const (
	// ProfileDirect names the target endpoint of the diagnostic.
	ProfileDirect = 1
	// ProfileAssisted leaves the destination to an assisted join.
	ProfileAssisted = 2
)

// Diagnostic is the extension of a diagnostic token.
type Diagnostic struct {
	// OfferDigest is the SHA-256 digest of the exact offer of the prober.
	OfferDigest [32]byte
	// CandidateRevision is the candidate revision the target was published in.
	CandidateRevision uint64
	// Profile is ProfileDirect or ProfileAssisted.
	Profile int
	// Target is the targeted endpoint. For ProfileAssisted, it only carries the address family.
	Target netip.AddrPort
}

// Family returns 4 or 6 for the address family of the diagnostic.
func (d *Diagnostic) Family() int {
	if d.Target.Addr().Is6() {
		return 6
	}
	return 4
}

func decodeDiagnostic(b []byte) (*Diagnostic, error) {
	if len(b) != diagnosticBytes {
		return nil, ErrInvalid
	}
	d := &Diagnostic{CandidateRevision: binary.BigEndian.Uint64(b[32:40]), Profile: int(b[40] & 127)}
	copy(d.OfferDigest[:], b[:32])
	v6 := b[40]&128 != 0
	var raw [16]byte
	copy(raw[:], b[41:57])
	port := binary.BigEndian.Uint16(b[57:59])
	addr := netip.AddrFrom16(raw)
	if !v6 {
		if raw != [16]byte{} && [12]byte(raw[:12]) != [12]byte{} {
			return nil, ErrInvalid
		}
		addr = netip.AddrFrom4([4]byte(raw[12:]))
	} else if addr.Is4In6() {
		return nil, ErrInvalid
	}
	d.Target = netip.AddrPortFrom(addr, port)
	if !d.valid() {
		return nil, ErrInvalid
	}
	return d, nil
}

func (d *Diagnostic) valid() bool {
	if d.CandidateRevision < 1 || d.CandidateRevision > 1<<53-1 {
		return false
	}
	switch d.Profile {
	case ProfileDirect:
		return d.Target.Port() != 0
	case ProfileAssisted:
		return d.Target.Port() == 0 && d.Target.Addr().IsUnspecified()
	}
	return false
}

func (d *Diagnostic) encode() []byte {
	b := make([]byte, diagnosticBytes)
	copy(b[:32], d.OfferDigest[:])
	binary.BigEndian.PutUint64(b[32:40], d.CandidateRevision)
	b[40] = byte(d.Profile)
	if d.Family() == 6 {
		b[40] |= 128
	}
	raw := d.Target.Addr().As16()
	if d.Family() == 4 {
		raw = [16]byte{}
		v4 := d.Target.Addr().As4()
		copy(raw[12:], v4[:])
	}
	copy(b[41:57], raw[:])
	binary.BigEndian.PutUint16(b[57:59], d.Target.Port())
	return b
}
