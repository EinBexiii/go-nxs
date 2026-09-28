package nxs

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"time"

	"github.com/pion/stun/v4"
)

// mapping returns the server-reflexive address of the gameplay socket as observed by
// a STUN server.
func (h *host) mapping(ctx context.Context, server string) (netip.AddrPort, error) {
	network := "udp4"
	if local := h.Addr(); local.IP != nil && local.IP.To4() == nil && !local.IP.IsUnspecified() {
		network = "udp6"
	}
	raddr, err := net.ResolveUDPAddr(network, server)
	if err != nil {
		return netip.AddrPort{}, err
	}
	msg, err := stun.Build(stun.TransactionID, stun.BindingRequest, stun.Fingerprint)
	if err != nil {
		return netip.AddrPort{}, err
	}
	responses := make(chan *stun.Message, 1)
	defer h.conn.expect(msg.TransactionID, responses)()

	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		if _, err := h.conn.WriteToUDPAddrPort(msg.Raw, raddr.AddrPort()); err != nil {
			return netip.AddrPort{}, err
		}
		select {
		case resp := <-responses:
			var addr stun.XORMappedAddress
			if resp.Type.Class != stun.ClassSuccessResponse || addr.GetFrom(resp) != nil {
				return netip.AddrPort{}, errors.New("nxs: invalid STUN response")
			}
			ip, ok := netip.AddrFromSlice(addr.IP)
			if !ok {
				return netip.AddrPort{}, errors.New("nxs: invalid STUN mapped address")
			}
			return netip.AddrPortFrom(ip.Unmap(), uint16(addr.Port)), nil
		case <-ticker.C:
		case <-ctx.Done():
			return netip.AddrPort{}, ctx.Err()
		}
	}
}

// localEndpoints returns the usable addresses of the gameplay socket, public ones first.
func (h *host) localEndpoints() (public, private []netip.AddrPort) {
	local := h.Addr()
	port := uint16(local.Port)
	var addrs []netip.Addr
	if ip, ok := netip.AddrFromSlice(local.IP); ok && !ip.IsUnspecified() {
		addrs = []netip.Addr{ip.Unmap()}
	} else if ifaces, err := net.InterfaceAddrs(); err == nil {
		for _, a := range ifaces {
			if n, ok := a.(*net.IPNet); ok {
				if ip, ok := netip.AddrFromSlice(n.IP); ok {
					addrs = append(addrs, ip.Unmap())
				}
			}
		}
	}
	for _, ip := range addrs {
		switch {
		case !ip.IsGlobalUnicast() || ip.IsLinkLocalUnicast():
		case ip.IsPrivate() || isShared(ip):
			private = append(private, netip.AddrPortFrom(ip, port))
		default:
			public = append(public, netip.AddrPortFrom(ip, port))
		}
	}
	return public, private
}

// isShared reports whether ip is in the carrier-grade NAT range 100.64.0.0/10.
func isShared(ip netip.Addr) bool {
	return netip.MustParsePrefix("100.64.0.0/10").Contains(ip)
}

// candidates returns the candidates published in the host profile.
func candidates(defined []netip.AddrPort, public, reflexive, private []netip.AddrPort) []candidate {
	type endpoint struct {
		addr netip.AddrPort
		typ  string
	}
	var endpoints []endpoint
	add := func(addrs []netip.AddrPort, typ string) {
		for _, a := range addrs {
			if !slices.ContainsFunc(endpoints, func(e endpoint) bool { return e.addr == a }) {
				endpoints = append(endpoints, endpoint{a, typ})
			}
		}
	}
	if len(defined) > 0 {
		add(defined, "host")
	} else {
		add(public, "host")
		add(reflexive, "srflx")
		// Private addresses remain useful for players on the same network.
		add(private, "host")
	}
	out := make([]candidate, 0, min(len(endpoints), 32))
	for i, e := range endpoints[:min(len(endpoints), 32)] {
		out = append(out, candidate{
			Foundation: strconv.Itoa(i + 1),
			Component:  1,
			Protocol:   "udp",
			Priority:   uint32(2130706431 - i*256),
			Address:    e.addr.Addr().String(),
			Port:       e.addr.Port(),
			Type:       e.typ,
		})
	}
	return out
}
