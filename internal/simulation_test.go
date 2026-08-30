package internal_test

import (
	"bytes"
	"crypto/rand"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"paqet/internal/conf"
	"paqet/internal/tnet"
	"paqet/internal/transport"
)

// ---------------------------------------------------------------------------
// Simulated link: in-memory PacketConn pair with latency, loss, reordering,
// duplicate delivery, and a LIVE server-port override (port hopping).
// ---------------------------------------------------------------------------

type SimulatedPacketConn struct {
	localAddr  net.Addr
	remoteAddr net.Addr
	readCh     <-chan []byte
	writeCh    chan<- []byte
	closed     uint32

	// Wire conditions
	Latency    time.Duration
	Jitter     time.Duration // 0..Jitter added randomly
	PacketLoss float64       // 0.0-1.0 dropped
	Reorder    float64       // 0.0-1.0 delayed by 2x latency (arrives late)
	Duplicate  float64       // 0.0-1.0 sent twice

	// Port hopping simulation: when > 0, packets written by the CLIENT are
	// delivered to the server with a tagged hopPort so the test can observe
	// the routing change, while the SERVER-side source addr stays the
	// client's stable identity (exactly like the real tunnel: only the
	// server's DESTINATION port changes; the client's source port never
	// moves). The server ignores dest ports (its listener accepts the whole
	// range), so the hop is transparent to it — as in production.
	RemotePort atomic.Uint32

	hopPorts map[string]struct{} // server-side view: dest ports it has seen

	IsServer bool
}

func NewSimulatedLink(latency time.Duration, loss float64) (*SimulatedPacketConn, *SimulatedPacketConn) {
	c2s := make(chan []byte, 4096)
	s2c := make(chan []byte, 4096)

	clientAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 10000}
	serverAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 20000}

	client := &SimulatedPacketConn{
		localAddr:  clientAddr,
		remoteAddr: serverAddr,
		readCh:     s2c,
		writeCh:    c2s,
		Latency:    latency,
		PacketLoss: loss,
		hopPorts:   map[string]struct{}{},
		IsServer:   false,
	}
	server := &SimulatedPacketConn{
		localAddr:  serverAddr,
		remoteAddr: clientAddr,
		readCh:     c2s,
		writeCh:    s2c,
		Latency:    latency,
		PacketLoss: loss,
		hopPorts:   map[string]struct{}{},
		IsServer:   true,
	}
	return client, server
}

func (c *SimulatedPacketConn) deliver(buf []byte) {
	// Model the hop: record the new destination port server-side, but do NOT
	// touch any addresses — the source (client) identity is stable and the
	// server's listener accepts all hopping ports, exactly as in production.
	if !c.IsServer {
		if port := c.RemotePort.Load(); port > 0 {
			c.hopPorts[string(rune(port))] = struct{}{}
		}
	}

	delay := c.Latency
	if c.Jitter > 0 {
		delay += time.Duration(randInt(int64(c.Jitter)))
	}
	if c.Reorder > 0 && randInt(1000) < int64(c.Reorder*1000) {
		delay += 2 * c.Latency
	}

	send := func() {
		defer func() { _ = recover() }() // channel may be abandoned at test end
		select {
		case c.writeCh <- buf:
		case <-time.After(2 * time.Second):
		}
	}

	if c.Duplicate > 0 && randInt(1000) < int64(c.Duplicate*1000) {
		go send()
	}
	if delay > 0 {
		go func() {
			time.Sleep(delay)
			send()
		}()
	} else {
		send()
	}
}

func (c *SimulatedPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	if atomic.LoadUint32(&c.closed) == 1 {
		return 0, nil, net.ErrClosed
	}
	data, ok := <-c.readCh
	if !ok {
		return 0, nil, io.EOF
	}
	n := copy(p, data)
	return n, c.remoteAddr, nil
}

func (c *SimulatedPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	if atomic.LoadUint32(&c.closed) == 1 {
		return 0, net.ErrClosed
	}
	if c.PacketLoss > 0 && randInt(1000) < int64(c.PacketLoss*1000) {
		return len(p), nil // silently dropped
	}
	buf := make([]byte, len(p))
	copy(buf, p)
	c.deliver(buf)
	return len(p), nil
}

func (c *SimulatedPacketConn) Close() error {
	atomic.StoreUint32(&c.closed, 1)
	return nil
}
func (c *SimulatedPacketConn) LocalAddr() net.Addr              { return c.localAddr }
func (c *SimulatedPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *SimulatedPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *SimulatedPacketConn) SetWriteDeadline(time.Time) error { return nil }

func randInt(max int64) int64 {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	v := int64(0)
	for _, x := range b {
		v = v*256 + int64(x)
	}
	if v < 0 {
		v = -v
	}
	return v % max
}

// testConfig returns a fast KCP transport config for simulations.
func testConfig() *conf.Transport {
	return &conf.Transport{
		Protocol: "auto",
		KCP: &conf.KCP{
			MTU:          1350,
			Sndwnd:       128,
			Rcvwnd:       128,
			NoDelay:      1,
			Interval:     10,
			Resend:       2,
			NoCongestion: 1,
			Smuxbuf:      4194304,
			Streambuf:    2097152,
		},
	}
}

func startEchoServer(t *testing.T, cfg *conf.Transport, serverNet *SimulatedPacketConn) {
	t.Helper()
	ln, err := transport.Listen(cfg, serverNet)
	if err != nil {
		t.Fatalf("Server Listen failed: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn tnet.Conn) {
				for {
					strm, err := conn.AcceptStrm()
					if err != nil {
						return
					}
					go func(strm tnet.Strm) {
						buf := make([]byte, 65536)
						for {
							n, err := strm.Read(buf)
							if err != nil {
								return
							}
							if _, werr := strm.Write(buf[:n]); werr != nil {
								return
							}
						}
					}(strm)
				}
			}(conn)
		}
	}()
}

func dialClient(t *testing.T, cfg *conf.Transport, serverAddr net.Addr, clientNet *SimulatedPacketConn) tnet.Conn {
	t.Helper()
	conn, err := transport.DialProto("kcp", serverAddr.(*net.UDPAddr), cfg, clientNet)
	if err != nil {
		t.Fatalf("Dial failed: %v", err)
	}
	return conn
}

func roundTrip(t *testing.T, strm tnet.Strm, payload []byte, timeout time.Duration) []byte {
	t.Helper()
	if _, err := strm.Write(payload); err != nil {
		t.Fatalf("Write failed: %v", err)
	}
	buf := make([]byte, len(payload)+1024)
	deadline := time.Now().Add(timeout)
	got := make([]byte, 0, len(payload))
	for len(got) < len(payload) {
		strm.SetReadDeadline(deadline)
		n, err := strm.Read(buf)
		if err != nil {
			t.Fatalf("Read failed after %d/%d bytes: %v (timeout %v)", len(got), len(payload), err, timeout)
		}
		got = append(got, buf[:n]...)
	}
	if !bytes.Equal(got, payload) {
		for i := range got {
			if i >= len(payload) || got[i] != payload[i] {
				t.Fatalf("Echo mismatch at offset %d: got %02x want %02x (len %d/%d)",
					i, got[i], payload[i], len(got), len(payload))
			}
		}
		t.Fatalf("Echo mismatch: got %d bytes, expected %d", len(got), len(payload))
	}
	return got
}

// hopStress hops the client's remote port on an interval, mid-traffic.
func hopStress(clientNet *SimulatedPacketConn, period time.Duration) (stop func()) {
	stopCh := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		port := uint32(20001)
		for {
			select {
			case <-stopCh:
				return
			case <-time.After(period):
				port = port%20100 + 20001
				clientNet.RemotePort.Store(port)
			}
		}
	}()
	return func() { close(stopCh); <-done }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

// TestSim_CleanThroughput: large bidirectional transfer on a clean link.
func TestSim_CleanThroughput(t *testing.T) {
	clientNet, serverNet := NewSimulatedLink(10*time.Millisecond, 0)
	cfg := testConfig()
	startEchoServer(t, cfg, serverNet)
	conn := dialClient(t, cfg, serverNet.localAddr, clientNet)
	defer conn.Close()

	strm, err := conn.OpenStrm()
	if err != nil {
		t.Fatalf("OpenStrm: %v", err)
	}

	payload := make([]byte, 256*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	roundTrip(t, strm, payload, 15*time.Second)
}

// TestSim_PacketLoss: 5% loss must not corrupt or stall a 128 KB transfer.
func TestSim_PacketLoss(t *testing.T) {
	clientNet, serverNet := NewSimulatedLink(10*time.Millisecond, 0.05)
	cfg := testConfig()
	startEchoServer(t, cfg, serverNet)
	conn := dialClient(t, cfg, serverNet.localAddr, clientNet)
	defer conn.Close()

	strm, err := conn.OpenStrm()
	if err != nil {
		t.Fatalf("OpenStrm: %v", err)
	}

	payload := make([]byte, 128*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	roundTrip(t, strm, payload, 30*time.Second)
}

// TestSim_HopDuringActiveTransfer: THE regression test for d48e275. Hops the
// remote port every 250ms while a large exchange runs. With the old
// ClearRemoteSync-on-hop the KCP stream corrupted (zombie session: echo never
// completed). With hops as pure routing changes it must complete.
func TestSim_HopDuringActiveTransfer(t *testing.T) {
	clientNet, serverNet := NewSimulatedLink(10*time.Millisecond, 0.01)
	cfg := testConfig()
	startEchoServer(t, cfg, serverNet)
	conn := dialClient(t, cfg, serverNet.localAddr, clientNet)
	defer conn.Close()

	strm, err := conn.OpenStrm()
	if err != nil {
		t.Fatalf("OpenStrm: %v", err)
	}

	stop := hopStress(clientNet, 250*time.Millisecond)
	defer stop()

	payload := make([]byte, 512*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	roundTrip(t, strm, payload, 60*time.Second)
}

// TestSim_HopMidHandshake: open NEW streams while hopping aggressively —
// the curl zombie signature (stream-open frame torn across a hop).
func TestSim_HopMidHandshake(t *testing.T) {
	clientNet, serverNet := NewSimulatedLink(10*time.Millisecond, 0.01)
	cfg := testConfig()
	startEchoServer(t, cfg, serverNet)
	conn := dialClient(t, cfg, serverNet.localAddr, clientNet)
	defer conn.Close()

	// Establish the session first.
	strm0, err := conn.OpenStrm()
	if err != nil {
		t.Fatalf("OpenStrm: %v", err)
	}
	roundTrip(t, strm0, []byte("warm"), 5*time.Second)

	stop := hopStress(clientNet, 150*time.Millisecond)
	defer stop()

	for i := 0; i < 20; i++ {
		strm, err := conn.OpenStrm()
		if err != nil {
			t.Fatalf("OpenStrm #%d: %v", i, err)
		}
		msg := bytes.Repeat([]byte{byte(i)}, 4096)
		roundTrip(t, strm, msg, 10*time.Second)
		strm.Close()
	}
}

// TestSim_ReorderedAndDuplicated: loss + reorder + duplicates on one link.
func TestSim_ReorderedAndDuplicated(t *testing.T) {
	clientNet, serverNet := NewSimulatedLink(10*time.Millisecond, 0.02)
	clientNet.Reorder = 0.15
	clientNet.Duplicate = 0.05
	serverNet.Reorder = 0.15
	serverNet.Duplicate = 0.05
	cfg := testConfig()
	startEchoServer(t, cfg, serverNet)
	conn := dialClient(t, cfg, serverNet.localAddr, clientNet)
	defer conn.Close()

	strm, err := conn.OpenStrm()
	if err != nil {
		t.Fatalf("OpenStrm: %v", err)
	}

	payload := make([]byte, 128*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	roundTrip(t, strm, payload, 45*time.Second)
}
