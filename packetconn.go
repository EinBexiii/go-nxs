package nxs

import (
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/pion/stun/v4"
)

// packetConn wraps the gameplay socket for the ICE mux. It lets the host answer its
// own STUN transactions on the same socket and replay retained requests to the mux.
type packetConn struct {
	*net.UDPConn

	packets chan packet
	closed  chan struct{}
	once    sync.Once

	mu           sync.Mutex
	transactions map[[stun.TransactionIDSize]byte]chan<- *stun.Message
}

type packet struct {
	b    []byte
	addr netip.AddrPort
}

func newPacketConn(conn *net.UDPConn) *packetConn {
	p := &packetConn{
		UDPConn:      conn,
		packets:      make(chan packet, 256),
		closed:       make(chan struct{}),
		transactions: make(map[[stun.TransactionIDSize]byte]chan<- *stun.Message),
	}
	go p.read()
	return p
}

func (p *packetConn) read() {
	defer p.once.Do(func() { close(p.closed) })
	for {
		b := make([]byte, 1500)
		n, addr, err := p.ReadFromUDPAddrPort(b)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return
		}
		if p.intercept(b[:n]) {
			continue
		}
		select {
		case p.packets <- packet{b: b[:n], addr: addr}:
		case <-p.closed:
			return
		}
	}
}

// intercept delivers responses to transactions started by expect.
func (p *packetConn) intercept(b []byte) bool {
	if !stun.IsMessage(b) {
		return false
	}
	var id [stun.TransactionIDSize]byte
	copy(id[:], b[8:20])
	p.mu.Lock()
	ch, ok := p.transactions[id]
	p.mu.Unlock()
	if !ok {
		return false
	}
	msg := &stun.Message{Raw: append([]byte(nil), b...)}
	if msg.Decode() == nil && msg.Type.Class != stun.ClassRequest {
		select {
		case ch <- msg:
		default:
		}
	}
	return true
}

// expect routes responses of the transaction to ch until the returned function is called.
func (p *packetConn) expect(id [stun.TransactionIDSize]byte, ch chan<- *stun.Message) func() {
	p.mu.Lock()
	p.transactions[id] = ch
	p.mu.Unlock()
	return func() {
		p.mu.Lock()
		delete(p.transactions, id)
		p.mu.Unlock()
	}
}

// inject queues a packet as if it had been received from addr.
func (p *packetConn) inject(b []byte, addr netip.AddrPort) {
	select {
	case p.packets <- packet{b: b, addr: addr}:
	default:
	}
}

// ReadFrom ...
func (p *packetConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, addr, err := p.ReadFromAddrPort(b)
	if err != nil {
		return 0, nil, err
	}
	return n, net.UDPAddrFromAddrPort(addr), nil
}

// ReadFromAddrPort ...
func (p *packetConn) ReadFromAddrPort(b []byte) (int, netip.AddrPort, error) {
	select {
	case pk := <-p.packets:
		return copy(b, pk.b), pk.addr, nil
	case <-p.closed:
		return 0, netip.AddrPort{}, net.ErrClosed
	}
}

// WriteToAddrPort ...
func (p *packetConn) WriteToAddrPort(b []byte, addr netip.AddrPort) (int, error) {
	return p.WriteToUDPAddrPort(b, addr)
}

// SetReadDeadline is a no-op, as reads are served from the packet queue.
func (p *packetConn) SetReadDeadline(time.Time) error { return nil }

// SetDeadline only applies to writes.
func (p *packetConn) SetDeadline(t time.Time) error { return p.UDPConn.SetWriteDeadline(t) }

// Close ...
func (p *packetConn) Close() error {
	p.once.Do(func() { close(p.closed) })
	return p.UDPConn.Close()
}
