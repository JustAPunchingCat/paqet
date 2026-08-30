package transport

import (
	"bytes"
	"context"
	"io"
	"net"
	"net/http"
	"net/url"
	"paqet/internal/conf"
	"paqet/internal/pkg/buffer"
	"paqet/internal/tnet"
	"paqet/internal/tnet/kcp"
	"sync"
	"testing"
	"time"
)

// mockPacketConn is an in-memory net.PacketConn for testing.
// Writes go into a buffer; reads come from a channel.
type mockPacketConn struct {
	incoming chan mockPkt
	written  []mockPkt
	mu       sync.Mutex
	closed   bool
	local    net.Addr
}

type mockPkt struct {
	data []byte
	addr net.Addr
}

func newMockPacketConn() *mockPacketConn {
	return &mockPacketConn{
		incoming: make(chan mockPkt, 64),
		local:    &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234},
	}
}

func (m *mockPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	pkt, ok := <-m.incoming
	if !ok {
		return 0, nil, net.ErrClosed
	}
	n := copy(p, pkt.data)
	return n, pkt.addr, nil
}

func (m *mockPacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	data := make([]byte, len(p))
	copy(data, p)
	m.written = append(m.written, mockPkt{data: data, addr: addr})
	return len(p), nil
}

func (m *mockPacketConn) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.closed {
		m.closed = true
		close(m.incoming)
	}
	return nil
}

func (m *mockPacketConn) LocalAddr() net.Addr                { return m.local }
func (m *mockPacketConn) SetDeadline(t time.Time) error      { return nil }
func (m *mockPacketConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *mockPacketConn) SetWriteDeadline(t time.Time) error { return nil }

// inject sends a packet into the mock conn's read path.
func (m *mockPacketConn) inject(data []byte, addr net.Addr) {
	d := make([]byte, len(data))
	copy(d, data)
	m.incoming <- mockPkt{data: d, addr: addr}
}

// getWritten returns all written packets.
func (m *mockPacketConn) getWritten() []mockPkt {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]mockPkt, len(m.written))
	copy(out, m.written)
	return out
}

var testAddr = &net.UDPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 5000}

// --- ProtoTag / ProtoName ---

func TestProtoTagMapping(t *testing.T) {
	tests := []struct {
		name string
		tag  byte
	}{
		{"kcp", TagKCP},
		{"quic", TagQUIC},
		{"udp", TagUDP},
	}
	for _, tt := range tests {
		if got := ProtoTag(tt.name); got != tt.tag {
			t.Errorf("ProtoTag(%q) = 0x%02x, want 0x%02x", tt.name, got, tt.tag)
		}
		if got := ProtoName(tt.tag); got != tt.name {
			t.Errorf("ProtoName(0x%02x) = %q, want %q", tt.tag, got, tt.name)
		}
	}
}

func TestProtoTagUnknown(t *testing.T) {
	if got := ProtoTag("websocket"); got != 0 {
		t.Errorf("ProtoTag(unknown) = 0x%02x, want 0", got)
	}
	if got := ProtoName(0xFF); got != "unknown" {
		t.Errorf("ProtoName(0xFF) = %q, want unknown", got)
	}
}

// --- VirtualPacketConn ---

func TestVirtualPacketConnWritePrependsTag(t *testing.T) {
	mock := newMockPacketConn()
	v := NewVirtualPacketConn(mock, TagKCP)

	payload := []byte("hello")
	n, err := v.WriteTo(payload, testAddr)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != len(payload) {
		t.Errorf("WriteTo returned %d, want %d", n, len(payload))
	}

	pkts := mock.getWritten()
	if len(pkts) != 1 {
		t.Fatalf("expected 1 written packet, got %d", len(pkts))
	}
	if pkts[0].data[0] != TagKCP {
		t.Errorf("tag byte = 0x%02x, want 0x%02x", pkts[0].data[0], TagKCP)
	}
	if !bytes.Equal(pkts[0].data[1:], payload) {
		t.Errorf("payload = %q, want %q", pkts[0].data[1:], payload)
	}
}

func TestVirtualPacketConnReadStripsTag(t *testing.T) {
	mock := newMockPacketConn()
	v := NewVirtualPacketConn(mock, TagQUIC)

	payload := []byte("world")
	tagged := append([]byte{TagQUIC}, payload...)
	mock.inject(tagged, testAddr)

	buf := make([]byte, 1500)
	n, addr, err := v.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Errorf("read data = %q, want %q", buf[:n], payload)
	}
	if addr == nil {
		t.Error("addr should not be nil")
	}
}

func TestVirtualPacketConnReadDropsWrongTag(t *testing.T) {
	mock := newMockPacketConn()
	v := NewVirtualPacketConn(mock, TagKCP)

	// Inject a packet with wrong tag.
	wrongTagged := append([]byte{TagQUIC}, []byte("data")...)
	mock.inject(wrongTagged, testAddr)

	buf := make([]byte, 1500)
	n, _, err := v.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 bytes for wrong tag, got %d", n)
	}
}

func TestVirtualPacketConnReadDropsTooShort(t *testing.T) {
	mock := newMockPacketConn()
	v := NewVirtualPacketConn(mock, TagKCP)

	// Inject a 1-byte packet (tag only, no payload).
	mock.inject([]byte{TagKCP}, testAddr)

	buf := make([]byte, 1500)
	n, _, err := v.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 bytes for too-short packet, got %d", n)
	}
}

func TestVirtualPacketConnWriteReadRoundTrip(t *testing.T) {
	// Simulate client write → wire → client read on same VirtualPacketConn.
	mock := newMockPacketConn()
	v := NewVirtualPacketConn(mock, TagUDP)

	payload := []byte("round-trip test payload with some length to it")
	_, err := v.WriteTo(payload, testAddr)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}

	// Take what was written to the mock and inject it back.
	pkts := mock.getWritten()
	mock.inject(pkts[0].data, testAddr)

	buf := make([]byte, 1500)
	n, _, err := v.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Errorf("round-trip mismatch: got %q, want %q", buf[:n], payload)
	}
}

// --- DemuxedPacketConn ---

func TestDemuxedPacketConnDeliverAndRead(t *testing.T) {
	mock := newMockPacketConn()
	dc := newDemuxedPacketConn(TagKCP, mock)
	defer dc.Close()

	payload := []byte("demuxed packet data")
	dc.deliver(payload, testAddr)

	buf := make([]byte, 1500)
	n, addr, err := dc.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Errorf("got %q, want %q", buf[:n], payload)
	}
	if addr == nil {
		t.Error("addr should not be nil (was the critical bug)")
	}
	if !addr.(*net.UDPAddr).IP.Equal(testAddr.IP) {
		t.Errorf("addr IP = %v, want %v", addr, testAddr)
	}
}

func TestDemuxedPacketConnWritePrependsTag(t *testing.T) {
	mock := newMockPacketConn()
	dc := newDemuxedPacketConn(TagQUIC, mock)
	defer dc.Close()

	payload := []byte("tagged write")
	n, err := dc.WriteTo(payload, testAddr)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != len(payload) {
		t.Errorf("WriteTo returned %d, want %d", n, len(payload))
	}

	pkts := mock.getWritten()
	if len(pkts) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(pkts))
	}
	if pkts[0].data[0] != TagQUIC {
		t.Errorf("tag = 0x%02x, want 0x%02x", pkts[0].data[0], TagQUIC)
	}
	if !bytes.Equal(pkts[0].data[1:], payload) {
		t.Errorf("payload = %q, want %q", pkts[0].data[1:], payload)
	}
}

func TestDemuxedPacketConnReadAfterClose(t *testing.T) {
	mock := newMockPacketConn()
	dc := newDemuxedPacketConn(TagKCP, mock)
	dc.Close()

	buf := make([]byte, 1500)
	_, _, err := dc.ReadFrom(buf)
	if err != net.ErrClosed {
		t.Errorf("expected net.ErrClosed, got %v", err)
	}
}

func TestDemuxedPacketConnDeliverAfterClose(t *testing.T) {
	mock := newMockPacketConn()
	dc := newDemuxedPacketConn(TagKCP, mock)
	dc.Close()

	// Should not panic.
	dc.deliver([]byte("late packet"), testAddr)
}

func TestDemuxedPacketConnCloseIdempotent(t *testing.T) {
	mock := newMockPacketConn()
	dc := newDemuxedPacketConn(TagKCP, mock)

	// Closing twice should not panic.
	dc.Close()
	dc.Close()
}

// --- ProtoDemux ---

func TestProtoDemuxRoutesCorrectly(t *testing.T) {
	mock := newMockPacketConn()
	demux := NewProtoDemux(mock, TagKCP, TagQUIC, TagUDP)

	kcpConn := demux.Conn(TagKCP)
	quicConn := demux.Conn(TagQUIC)
	udpConn := demux.Conn(TagUDP)

	if kcpConn == nil || quicConn == nil || udpConn == nil {
		t.Fatal("all protocol conns should be non-nil")
	}

	// Inject tagged packets.
	kcpPayload := []byte("kcp-data")
	quicPayload := []byte("quic-data")
	udpPayload := []byte("udp-data")

	mock.inject(append([]byte{TagKCP}, kcpPayload...), testAddr)
	mock.inject(append([]byte{TagQUIC}, quicPayload...), testAddr)
	mock.inject(append([]byte{TagUDP}, udpPayload...), testAddr)

	// Read from each protocol conn.
	buf := make([]byte, 1500)

	n, _, err := kcpConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("KCP ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], kcpPayload) {
		t.Errorf("KCP got %q, want %q", buf[:n], kcpPayload)
	}

	n, _, err = quicConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("QUIC ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], quicPayload) {
		t.Errorf("QUIC got %q, want %q", buf[:n], quicPayload)
	}

	n, _, err = udpConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("UDP ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], udpPayload) {
		t.Errorf("UDP got %q, want %q", buf[:n], udpPayload)
	}

	demux.Close()
}

func TestProtoDemuxDropsUnknownTag(t *testing.T) {
	mock := newMockPacketConn()
	demux := NewProtoDemux(mock, TagKCP)

	kcpConn := demux.Conn(TagKCP)

	// Inject unknown tag, then a valid KCP packet.
	mock.inject(append([]byte{0xFF}, []byte("unknown")...), testAddr)
	mock.inject(append([]byte{TagKCP}, []byte("valid")...), testAddr)

	buf := make([]byte, 1500)
	n, _, err := kcpConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	// Should get the valid packet, unknown was dropped.
	if !bytes.Equal(buf[:n], []byte("valid")) {
		t.Errorf("got %q, want %q", buf[:n], "valid")
	}

	demux.Close()
}

func TestProtoDemuxDropsTooShort(t *testing.T) {
	mock := newMockPacketConn()
	demux := NewProtoDemux(mock, TagKCP)
	kcpConn := demux.Conn(TagKCP)

	// Inject a 1-byte packet (tag only, no data) — should be dropped.
	mock.inject([]byte{TagKCP}, testAddr)
	// Then a valid packet.
	mock.inject(append([]byte{TagKCP}, []byte("ok")...), testAddr)

	buf := make([]byte, 1500)
	n, _, err := kcpConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if !bytes.Equal(buf[:n], []byte("ok")) {
		t.Errorf("got %q, want %q", buf[:n], "ok")
	}

	demux.Close()
}

func TestProtoDemuxPreservesAddr(t *testing.T) {
	mock := newMockPacketConn()
	demux := NewProtoDemux(mock, TagKCP)
	kcpConn := demux.Conn(TagKCP)

	srcAddr := &net.UDPAddr{IP: net.IPv4(192, 168, 1, 50), Port: 9999}
	mock.inject(append([]byte{TagKCP}, []byte("data")...), srcAddr)

	buf := make([]byte, 1500)
	_, addr, err := kcpConn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("ReadFrom: %v", err)
	}
	if addr == nil {
		t.Fatal("addr is nil, demux must preserve source address")
	}
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok {
		t.Fatalf("expected *net.UDPAddr, got %T", addr)
	}
	if !udpAddr.IP.Equal(srcAddr.IP) || udpAddr.Port != srcAddr.Port {
		t.Errorf("addr = %v, want %v", udpAddr, srcAddr)
	}

	demux.Close()
}

func TestProtoDemuxConnLookup(t *testing.T) {
	mock := newMockPacketConn()
	demux := NewProtoDemux(mock, TagKCP, TagQUIC)

	if demux.Conn(TagKCP) == nil {
		t.Error("Conn(TagKCP) should not be nil")
	}
	if demux.Conn(TagQUIC) == nil {
		t.Error("Conn(TagQUIC) should not be nil")
	}
	// TagUDP was not registered.
	if demux.Conn(TagUDP) != nil {
		t.Error("Conn(TagUDP) should be nil when not registered")
	}

	demux.Close()
}

// --- Pool correctness ---

func TestGetDemuxBufSmall(t *testing.T) {
	pool, ptr, buf := getDemuxBuf(100)
	if pool == nil {
		t.Fatal("pool should not be nil")
	}
	if len(buf) != 100 {
		t.Errorf("buf len = %d, want 100", len(buf))
	}
	if cap(buf) < 100 {
		t.Errorf("buf cap = %d, want >= 100", cap(buf))
	}
	pool.Put(ptr)
}

func TestGetDemuxBufLarge(t *testing.T) {
	pool, ptr, buf := getDemuxBuf(2000)
	if pool == nil {
		t.Fatal("pool should not be nil")
	}
	if len(buf) != 2000 {
		t.Errorf("buf len = %d, want 2000", len(buf))
	}
	pool.Put(ptr)
}

// --- Concurrency stress ---

func TestDemuxConcurrentDeliver(t *testing.T) {
	mock := newMockPacketConn()
	dc := newDemuxedPacketConn(TagKCP, mock)
	defer dc.Close()

	const numPackets = 1000
	var wg sync.WaitGroup
	wg.Add(numPackets)

	for i := range numPackets {
		go func(idx int) {
			defer wg.Done()
			data := []byte{byte(idx & 0xFF)}
			dc.deliver(data, testAddr)
		}(i)
	}

	wg.Wait()

	// Drain what was delivered (some may have been dropped if channel full).
	drained := 0
	for {
		select {
		case <-dc.ch:
			drained++
		default:
			goto done
		}
	}
done:
	if drained == 0 {
		t.Error("expected at least some packets delivered")
	}
	t.Logf("delivered %d/%d packets (channel capacity 512)", drained, numPackets)
}

func TestProtoDemuxConcurrentReads(t *testing.T) {
	mock := newMockPacketConn()
	demux := NewProtoDemux(mock, TagKCP, TagQUIC)
	defer demux.Close()

	kcpConn := demux.Conn(TagKCP)
	quicConn := demux.Conn(TagQUIC)

	const perProto = 50
	// Inject alternating KCP and QUIC packets.
	for i := range perProto {
		mock.inject(append([]byte{TagKCP}, byte(i)), testAddr)
		mock.inject(append([]byte{TagQUIC}, byte(i)), testAddr)
	}

	// Read from both in parallel.
	var wg sync.WaitGroup
	readN := func(dc *DemuxedPacketConn, n int) {
		defer wg.Done()
		buf := make([]byte, 1500)
		for range n {
			_, _, err := dc.ReadFrom(buf)
			if err != nil {
				t.Errorf("ReadFrom error: %v", err)
				return
			}
		}
	}

	wg.Add(2)
	go readN(kcpConn, perProto)
	go readN(quicConn, perProto)
	wg.Wait()
}

// --- WriteTo pooling (no allocation check) ---

func TestVirtualPacketConnWriteLargePayload(t *testing.T) {
	mock := newMockPacketConn()
	v := NewVirtualPacketConn(mock, TagKCP)

	// 1400 bytes — typical MTU payload.
	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	n, err := v.WriteTo(payload, testAddr)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != len(payload) {
		t.Errorf("n = %d, want %d", n, len(payload))
	}

	pkts := mock.getWritten()
	if len(pkts[0].data) != 1+len(payload) {
		t.Errorf("wire len = %d, want %d", len(pkts[0].data), 1+len(payload))
	}
	if pkts[0].data[0] != TagKCP {
		t.Error("tag byte missing")
	}
	if !bytes.Equal(pkts[0].data[1:], payload) {
		t.Error("payload corrupted")
	}
}

func TestDemuxedPacketConnWriteLargePayload(t *testing.T) {
	mock := newMockPacketConn()
	dc := newDemuxedPacketConn(TagQUIC, mock)
	defer dc.Close()

	payload := make([]byte, 1400)
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	n, err := dc.WriteTo(payload, testAddr)
	if err != nil {
		t.Fatalf("WriteTo: %v", err)
	}
	if n != len(payload) {
		t.Errorf("n = %d, want %d", n, len(payload))
	}

	pkts := mock.getWritten()
	if pkts[0].data[0] != TagQUIC {
		t.Error("tag byte missing")
	}
	if !bytes.Equal(pkts[0].data[1:], payload) {
		t.Error("payload corrupted")
	}
}

func TestE2E_FullDuplex_KCP_Tunnel_Streaming(t *testing.T) {
	// 1. Setup real UDP loopback sockets
	srvUDP, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listenPacket srv: %v", err)
	}
	defer srvUDP.Close()
	srvAddr := srvUDP.LocalAddr().(*net.UDPAddr)

	cliUDP, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listenPacket cli: %v", err)
	}
	defer cliUDP.Close()

	// 2. Start KCP Listener on Server
	kcpCfg := &conf.KCP{
		Mode:      "fast2",
		Smuxbuf:   4 * 1024 * 1024,
		Streambuf: 2 * 1024 * 1024,
	}
	listener, err := kcp.Listen(kcpCfg, srvUDP)
	if err != nil {
		t.Fatalf("kcp.Listen: %v", err)
	}
	defer listener.Close()

	// Server accept and echo loop
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c tnet.Conn) {
				defer c.Close()
				for {
					strm, err := c.AcceptStrm()
					if err != nil {
						return
					}
					go func(s tnet.Strm) {
						defer s.Close()
						_, _ = io.Copy(s, s) // Echo all incoming data back
					}(strm)
				}
			}(conn)
		}
	}()

	// 3. Client Dials Server
	cliConn, err := kcp.Dial(srvAddr, kcpCfg, cliUDP)
	if err != nil {
		t.Fatalf("kcp.Dial: %v", err)
	}
	defer cliConn.Close()

	// 4. Open Stream and transfer 2MB of random payload
	strm, err := cliConn.OpenStrm()
	if err != nil {
		t.Fatalf("OpenStrm: %v", err)
	}
	defer strm.Close()

	testSize := 2 * 1024 * 1024 // 2MB
	sendData := make([]byte, testSize)
	for i := range sendData {
		sendData[i] = byte((i*7 + 13) % 256)
	}

	recvData := make([]byte, testSize)
	var readErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, readErr = io.ReadFull(strm, recvData)
	}()

	_, writeErr := strm.Write(sendData)
	if writeErr != nil {
		t.Fatalf("strm.Write: %v", writeErr)
	}

	wg.Wait()
	if readErr != nil {
		t.Fatalf("io.ReadFull: %v", readErr)
	}

	if !bytes.Equal(sendData, recvData) {
		t.Fatalf("E2E data mismatch! Transferred 2MB was corrupted.")
	}
	t.Logf("Successfully transferred and verified %d bytes (2MB) over KCP tunnel with 100%% integrity!", testSize)
}

func TestE2E_SOCKS5_HTTP_Proxy_Through_Tunnel(t *testing.T) {
	// 1. Start a local HTTP Target Server
	httpListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("target http listen: %v", err)
	}
	defer httpListener.Close()

	httpServer := &http.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method == http.MethodPost {
				body, _ := io.ReadAll(r.Body)
				w.Header().Set("Content-Type", "application/octet-stream")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write(body)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("HELLO FROM REAL TARGET VIA PROXY"))
		}),
	}
	go httpServer.Serve(httpListener)
	defer httpServer.Close()

	targetAddr := httpListener.Addr().String()

	// 2. Setup Paqet KCP Server
	srvUDP, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("srvUDP listen: %v", err)
	}
	defer srvUDP.Close()
	srvAddr := srvUDP.LocalAddr().(*net.UDPAddr)

	kcpCfg := &conf.KCP{
		Mode:      "fast2",
		Smuxbuf:   4 * 1024 * 1024,
		Streambuf: 2 * 1024 * 1024,
	}
	listener, err := kcp.Listen(kcpCfg, srvUDP)
	if err != nil {
		t.Fatalf("kcp.Listen: %v", err)
	}
	defer listener.Close()

	// Server accepts stream, dials targetAddr, and runs RelayTCP
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c tnet.Conn) {
				defer c.Close()
				for {
					strm, err := c.AcceptStrm()
					if err != nil {
						return
					}
					go func(s tnet.Strm) {
						defer s.Close()
						// Dial real target server
						targetConn, err := net.Dial("tcp", targetAddr)
						if err != nil {
							return
						}
						defer targetConn.Close()
						_ = buffer.RelayTCP(ctx, targetConn, s)
					}(strm)
				}
			}(conn)
		}
	}()

	// 3. Setup Paqet KCP Client
	cliUDP, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cliUDP listen: %v", err)
	}
	defer cliUDP.Close()

	cliConn, err := kcp.Dial(srvAddr, kcpCfg, cliUDP)
	if err != nil {
		t.Fatalf("kcp.Dial: %v", err)
	}
	defer cliConn.Close()

	// 4. Setup Local SOCKS5 Proxy Listener
	socksListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("socksListener: %v", err)
	}
	defer socksListener.Close()
	socksAddr := socksListener.Addr().String()

	go func() {
		for {
			c, err := socksListener.Accept()
			if err != nil {
				return
			}
			go func(clientConn net.Conn) {
				defer clientConn.Close()
				// Simplified SOCKS5 negotiation for testing
				buf := make([]byte, 256)
				_, _ = clientConn.Read(buf)                 // Auth request
				_, _ = clientConn.Write([]byte{0x05, 0x00}) // Auth response
				_, _ = clientConn.Read(buf)                 // Connect request

				// Open tunnel stream
				strm, err := cliConn.OpenStrm()
				if err != nil {
					return
				}
				defer strm.Close()

				// Send SOCKS5 RepSuccess
				_, _ = clientConn.Write([]byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0})

				// Relay full-duplex traffic
				_ = buffer.RelayTCP(ctx, clientConn, strm)
			}(c)
		}
	}()

	// 5. Test HTTP GET via SOCKS5 Proxy
	proxyURL, _ := url.Parse("socks5://" + socksAddr)
	httpClient := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 5 * time.Second,
	}

	resp, err := httpClient.Get("http://" + targetAddr)
	if err != nil {
		t.Fatalf("HTTP GET via SOCKS5 failed: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ReadAll body: %v", err)
	}
	if string(body) != "HELLO FROM REAL TARGET VIA PROXY" {
		t.Fatalf("unexpected body: %q", string(body))
	}
	t.Logf("GET Request succeeded via SOCKS5 Tunnel! Response: %q", string(body))

	// 6. Test 5MB POST Upload & Echo via SOCKS5 Proxy (Stress test speedtest simulation)
	uploadSize := 5 * 1024 * 1024 // 5 Megabytes
	uploadData := make([]byte, uploadSize)
	for i := range uploadData {
		uploadData[i] = byte((i*11 + 3) % 256)
	}

	postResp, err := httpClient.Post("http://"+targetAddr, "application/octet-stream", bytes.NewReader(uploadData))
	if err != nil {
		t.Fatalf("HTTP POST via SOCKS5 failed: %v", err)
	}
	defer postResp.Body.Close()

	echoData, err := io.ReadAll(postResp.Body)
	if err != nil {
		t.Fatalf("ReadAll POST body: %v", err)
	}

	if len(echoData) != uploadSize {
		t.Fatalf("Echo size mismatch: got %d, want %d", len(echoData), uploadSize)
	}
	if !bytes.Equal(uploadData, echoData) {
		t.Fatalf("POST upload data corrupted during streaming!")
	}
	t.Logf("5MB Upload + Download Speedtest Simulation PASSED 100%% via SOCKS5 tunnel!")
}

// multiPortServerConn aggregates multiple UDP listening sockets into one PacketConn
type multiPortServerConn struct {
	listeners []*net.UDPConn
	incoming  chan mockPkt
	closed    chan struct{}
	once      sync.Once
}

func newMultiPortServerConn(ports []int) (*multiPortServerConn, error) {
	m := &multiPortServerConn{
		incoming: make(chan mockPkt, 1024),
		closed:   make(chan struct{}),
	}
	for _, p := range ports {
		l, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: p})
		if err != nil {
			m.Close()
			return nil, err
		}
		m.listeners = append(m.listeners, l)
		go func(conn *net.UDPConn) {
			buf := make([]byte, 65536)
			for {
				n, rAddr, err := conn.ReadFrom(buf)
				if err != nil {
					return
				}
				pktData := make([]byte, n)
				copy(pktData, buf[:n])
				select {
				case m.incoming <- mockPkt{data: pktData, addr: rAddr}:
				case <-m.closed:
					return
				}
			}
		}(l)
	}
	return m, nil
}

func (m *multiPortServerConn) ReadFrom(p []byte) (int, net.Addr, error) {
	select {
	case pkt, ok := <-m.incoming:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		n := copy(p, pkt.data)
		return n, pkt.addr, nil
	case <-m.closed:
		return 0, nil, net.ErrClosed
	}
}

func (m *multiPortServerConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	if len(m.listeners) > 0 {
		return m.listeners[0].WriteTo(p, addr)
	}
	return 0, net.ErrClosed
}

func (m *multiPortServerConn) Close() error {
	m.once.Do(func() {
		close(m.closed)
		for _, l := range m.listeners {
			_ = l.Close()
		}
	})
	return nil
}

func (m *multiPortServerConn) LocalAddr() net.Addr                { return m.listeners[0].LocalAddr() }
func (m *multiPortServerConn) SetDeadline(t time.Time) error      { return nil }
func (m *multiPortServerConn) SetReadDeadline(t time.Time) error  { return nil }
func (m *multiPortServerConn) SetWriteDeadline(t time.Time) error { return nil }

// hoppingClientConn applies port hopping on outgoing packets and normalizes incoming packets
type hoppingClientConn struct {
	base    net.PacketConn
	ports   []int
	current int
	minPort int
	mu      sync.Mutex
}

func (h *hoppingClientConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, addr, err := h.base.ReadFrom(p)
	if err != nil {
		return n, addr, err
	}
	// Normalize port to minPort
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		normalized := *udpAddr
		normalized.Port = h.minPort
		return n, &normalized, nil
	}
	return n, addr, nil
}

func (h *hoppingClientConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	h.mu.Lock()
	hopPort := h.ports[h.current]
	h.mu.Unlock()

	// Rewrite destination port
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		hopped := *udpAddr
		hopped.Port = hopPort
		return h.base.WriteTo(p, &hopped)
	}
	return h.base.WriteTo(p, addr)
}

func (h *hoppingClientConn) hopNext() {
	h.mu.Lock()
	h.current = (h.current + 1) % len(h.ports)
	h.mu.Unlock()
}

func (h *hoppingClientConn) Close() error                       { return h.base.Close() }
func (h *hoppingClientConn) LocalAddr() net.Addr                { return h.base.LocalAddr() }
func (h *hoppingClientConn) SetDeadline(t time.Time) error      { return h.base.SetDeadline(t) }
func (h *hoppingClientConn) SetReadDeadline(t time.Time) error  { return h.base.SetReadDeadline(t) }
func (h *hoppingClientConn) SetWriteDeadline(t time.Time) error { return h.base.SetWriteDeadline(t) }

func TestE2E_PortHopping_During_Active_Streaming(t *testing.T) {
	// 1. Setup multi-port server listening on 4 different ports
	ports := []int{24101, 24102, 24103, 24104}
	srvMulti, err := newMultiPortServerConn(ports)
	if err != nil {
		t.Fatalf("newMultiPortServerConn: %v", err)
	}
	defer srvMulti.Close()

	// 2. Start KCP Listener on Multi-Port Server
	kcpCfg := &conf.KCP{
		Mode:      "fast2",
		Smuxbuf:   4 * 1024 * 1024,
		Streambuf: 2 * 1024 * 1024,
	}
	srvListener, err := kcp.Listen(kcpCfg, srvMulti)
	if err != nil {
		t.Fatalf("kcp.Listen: %v", err)
	}
	defer srvListener.Close()

	// Server echoes all stream data back
	go func() {
		for {
			conn, err := srvListener.Accept()
			if err != nil {
				return
			}
			go func(c tnet.Conn) {
				defer c.Close()
				for {
					strm, err := c.AcceptStrm()
					if err != nil {
						return
					}
					go func(s tnet.Strm) {
						defer s.Close()
						_, _ = io.Copy(s, s)
					}(strm)
				}
			}(conn)
		}
	}()

	// 3. Setup Client with Port Hopping PacketConn
	cliUDP, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("cliUDP: %v", err)
	}
	defer cliUDP.Close()

	hopConn := &hoppingClientConn{
		base:    cliUDP,
		ports:   ports,
		current: 0,
		minPort: ports[0],
	}

	// Dial using canonical base port
	canonicalAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: ports[0]}
	cliConn, err := kcp.Dial(canonicalAddr, kcpCfg, hopConn)
	if err != nil {
		t.Fatalf("kcp.Dial: %v", err)
	}
	defer cliConn.Close()

	// 4. Open Stream
	strm, err := cliConn.OpenStrm()
	if err != nil {
		t.Fatalf("OpenStrm: %v", err)
	}
	defer strm.Close()

	// 5. Stream 3MB of data while actively hopping ports every 50 milliseconds
	totalBytes := 3 * 1024 * 1024 // 3MB
	chunkSize := 32 * 1024        // 32KB chunks
	numChunks := totalBytes / chunkSize

	sendData := make([]byte, totalBytes)
	for i := range sendData {
		sendData[i] = byte((i*17 + 7) % 256)
	}
	recvData := make([]byte, totalBytes)

	var readErr error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		_, readErr = io.ReadFull(strm, recvData)
	}()

	// Start aggressive port hopper in background
	hopDone := make(chan struct{})
	hopCount := 0
	go func() {
		ticker := time.NewTicker(30 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				hopConn.hopNext()
				hopCount++
			case <-hopDone:
				return
			}
		}
	}()

	// Write 3MB in 32KB chunks with small delays to allow hops to occur during active transfer
	for i := 0; i < numChunks; i++ {
		start := i * chunkSize
		end := start + chunkSize
		_, writeErr := strm.Write(sendData[start:end])
		if writeErr != nil {
			t.Fatalf("strm.Write at chunk %d: %v", i, writeErr)
		}
		time.Sleep(3 * time.Millisecond)
	}

	wg.Wait()
	close(hopDone)

	if readErr != nil {
		t.Fatalf("io.ReadFull: %v", readErr)
	}

	if !bytes.Equal(sendData, recvData) {
		t.Fatalf("Data corrupted during active port hopping!")
	}

	t.Logf("Active Port Hopping E2E Test PASSED! Transferred %d bytes (3MB) across %d dynamic port hops with 100%% data integrity!", totalBytes, hopCount)
}
