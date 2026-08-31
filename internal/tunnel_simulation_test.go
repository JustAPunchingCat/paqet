package internal_test

// Tunnel-level simulation: drive the REAL socket.PacketConn fake-TCP stack
// (SendHandle.writeRaw, RecvHandle decode, hopping plugin, echo routing,
// client port rotation) over an in-memory wire, then run KCP/smux through
// transport.DialProto/Listen on top — the exact production path.

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"paqet/internal/conf"
	"paqet/internal/socket"
	"paqet/internal/tnet"
	"paqet/internal/transport"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type rawPacket struct {
	srcIP   net.IP
	srcPort uint16
	dstIP   net.IP
	dstPort uint16
	payload []byte
}

type simWire struct {
	mu             sync.Mutex
	client         chan rawPacket
	server         chan rawPacket
	latency        time.Duration
	loss           float64
	clientPublicIP net.IP
	natEnabled     bool
	closed         chan struct{}
	closeOnce      sync.Once
}

func newSimWire(latency time.Duration, loss float64) *simWire {
	return &simWire{
		client:         make(chan rawPacket, 4096),
		server:         make(chan rawPacket, 4096),
		latency:        latency,
		loss:           loss,
		clientPublicIP: net.ParseIP("203.0.113.10"),
		natEnabled:     true,
		closed:         make(chan struct{}),
	}
}

func (w *simWire) close() { w.closeOnce.Do(func() { close(w.closed) }) }

func decodeRaw(data []byte) (rawPacket, bool) {
	p := rawPacket{}
	var eth layers.Ethernet
	var ip4 layers.IPv4
	var tcp layers.TCP
	var udp layers.UDP
	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet, &eth, &ip4, &tcp, &udp)
	parser.IgnoreUnsupported = true
	decoded := []gopacket.LayerType{}
	if err := parser.DecodeLayers(data, &decoded); err != nil {
		return p, false
	}
	for _, lt := range decoded {
		switch lt {
		case layers.LayerTypeTCP:
			p.srcPort = uint16(tcp.SrcPort)
			p.dstPort = uint16(tcp.DstPort)
			// COPY: the input buffer is pooled and reused by writeRaw as
			// soon as WritePacketData returns — keeping a slice would race
			// with the next write (single-byte corruption under load).
			p.payload = append([]byte(nil), tcp.Payload...)
		case layers.LayerTypeUDP:
			p.srcPort = uint16(udp.SrcPort)
			p.dstPort = uint16(udp.DstPort)
			p.payload = append([]byte(nil), udp.Payload...)
		case layers.LayerTypeIPv4:
			p.srcIP = append(net.IP(nil), ip4.SrcIP...)
			p.dstIP = append(net.IP(nil), ip4.DstIP...)
		}
	}
	if p.srcIP == nil || p.payload == nil {
		return p, false
	}
	return p, true
}

func encodeRaw(pkt rawPacket, srcPort uint16) []byte {
	eth := &layers.Ethernet{
		SrcMAC:       []byte{2, 0, 0, 0, 0, 2},
		DstMAC:       []byte{2, 0, 0, 0, 0, 1},
		EthernetType: layers.EthernetTypeIPv4,
	}
	ip := &layers.IPv4{
		Version:  4,
		TTL:      64,
		SrcIP:    pkt.srcIP,
		DstIP:    pkt.dstIP,
		Protocol: layers.IPProtocolUDP,
	}
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(srcPort),
		DstPort: layers.UDPPort(pkt.dstPort),
	}
	udp.SetNetworkLayerForChecksum(ip)
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{ComputeChecksums: true, FixLengths: true}
	if err := gopacket.SerializeLayers(buf, opts, eth, ip, udp, gopacket.Payload(pkt.payload)); err != nil {
		return nil
	}
	return buf.Bytes()
}

type clientInjector struct {
	w      *simWire
	sent   int64
	badDec int64
}

func (c *clientInjector) WritePacketData(data []byte) error {
	pkt, ok := decodeRaw(data)
	if !ok {
		c.badDec++
		var eth layers.Ethernet
		var ip4 layers.IPv4
		var tcp layers.TCP
		var udp layers.UDP
		parser := gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &eth, &ip4, &tcp, &udp)
		decoded := []gopacket.LayerType{}
		derr := parser.DecodeLayers(data, &decoded)
		if c.badDec == 1 {
			println("DECODE-ERR:", fmt.Sprint(derr), "decoded:", fmt.Sprint(decoded), "len:", len(data))
		}
		return nil
	}
	c.sent++
	if c.w.natEnabled {
		pkt.srcIP = c.w.clientPublicIP
	}

	select {
	case c.w.server <- pkt:
	default:
	}
	return nil
}
func (c *clientInjector) Close() {}

type serverInjector struct {
	w    *simWire
	sent int64
}

func (s *serverInjector) WritePacketData(data []byte) error {
	pkt, ok := decodeRaw(data)
	if !ok {
		println("SERVER-INJ BADDEC", len(data))
		return nil
	}
	s.sent++
	select {
	case s.w.client <- pkt:
	default:
	}
	return nil
}
func (s *serverInjector) Close() {}

type clientSource struct {
	w    *simWire
	port uint16
	seen int64
	mu   sync.Mutex
}

func (c *clientSource) ReadPacketData() ([]byte, error) {
	select {
	case pkt := <-c.w.client:
		c.mu.Lock()
		c.port = pkt.dstPort
		c.seen++
		c.mu.Unlock()
		return encodeRaw(pkt, pkt.srcPort), nil
	case <-c.w.closed:
		return nil, net.ErrClosed
	}
}
func (c *clientSource) Close()                              {}
func (c *clientSource) RebindPort(int, time.Duration) error { return nil }

type serverSource struct {
	w        *simWire
	seen     int64
	firstHex string
}

func (s *serverSource) ReadPacketData() ([]byte, error) {
	select {
	case pkt := <-s.w.server:
		s.seen++
		if s.firstHex == "" && len(pkt.payload) > 0 {
			n := len(pkt.payload)
			if n > 24 {
				n = 24
			}
			s.firstHex = fmt.Sprintf("len=%d % x", len(pkt.payload), pkt.payload[:n])
		}
		return encodeRaw(pkt, pkt.srcPort), nil
	case <-s.w.closed:
		return nil, net.ErrClosed
	}
}
func (s *serverSource) Close()                              {}
func (s *serverSource) RebindPort(int, time.Duration) error { return nil }

type simTunnel struct {
	wire        *simWire
	clientConn  *socket.PacketConn
	serverConn  *socket.PacketConn
	cSrc        *clientSource
	sSrc        *serverSource
	srvCounting *countingConn
}

const (
	simClientBasePort = 40000
	simServerHopped   = 20000
)

func newSimTunnel(t *testing.T, latency time.Duration, loss float64) *simTunnel {
	t.Helper()
	w := newSimWire(latency, loss)

	routerMAC, _ := net.ParseMAC("02:00:00:00:00:01")
	iface := &net.Interface{
		Index:        1,
		MTU:          1500,
		Name:         "sim",
		HardwareAddr: routerMAC,
		Flags:        net.FlagUp,
	}

	clientCfg := &conf.Network{
		Role:       "client",
		Port:       simClientBasePort,
		Interface_: "sim",
		Interface:  iface,
		Driver:     "testing",
		Transport:  testTunnelConfig(),
		IPv4: conf.Addr{
			Addr:   &net.UDPAddr{IP: net.ParseIP("172.30.250.2").To4(), Port: 0},
			Router: routerMAC,
		},
	}
	clientCfg.TCP.LF = []conf.TCPF{{PSH: true, ACK: true}}
	clientCfg.TCP.RF = []conf.TCPF{{PSH: true, ACK: true}}

	serverCfg := &conf.Network{
		Role:       "server",
		Port:       10000,
		Interface_: "sim",
		Interface:  iface,
		Driver:     "testing",
		Transport:  testTunnelConfig(),
		IPv4: conf.Addr{
			Addr:   &net.UDPAddr{IP: net.ParseIP("38.49.208.35").To4(), Port: 0},
			Router: routerMAC,
		},
	}
	serverCfg.TCP.LF = []conf.TCPF{{PSH: true, ACK: true}}
	serverCfg.TCP.RF = []conf.TCPF{{PSH: true, ACK: true}}

	clientConn, err := socket.NewWithTestingPipes(context.Background(), clientCfg, nil, true, nil)
	if err != nil {
		t.Fatalf("client PacketConn: %v", err)
	}
	serverConn, err := socket.NewWithTestingPipes(context.Background(), serverCfg, nil, false, nil)
	if err != nil {
		t.Fatalf("server PacketConn: %v", err)
	}

	cSrc := &clientSource{w: w}
	sSrc := &serverSource{w: w}
	cInj := &clientInjector{w: w}
	clientConn.InjectTestingInjector(cInj)
	clientConn.InjectTestingSource(cSrc)
	sInj := &serverInjector{w: w}
	serverConn.InjectTestingInjector(sInj)
	serverConn.InjectTestingSource(sSrc)
	clientConn.Start()
	serverConn.Start()

	t.Cleanup(func() {
		t.Logf("wire: cInj sent=%d badDec=%d; sInj sent=%d; clientSrc saw=%d; serverSrc saw=%d",
			cInj.sent, cInj.badDec, sInj.sent, cSrc.seen, sSrc.seen)
	})

	return &simTunnel{wire: w, clientConn: clientConn, serverConn: serverConn, cSrc: cSrc, sSrc: sSrc}
}

func testTunnelConfig() *conf.Transport {
	return &conf.Transport{
		Protocol: "kcp",
		KCP: &conf.KCP{
			MTU:          1300,
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

type countingConn struct {
	net.PacketConn
	readN int64
}

func (c *countingConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, a, err := c.PacketConn.ReadFrom(p)
	if err == nil {
		c.readN++
	}
	return n, a, err
}

func (st *simTunnel) dial(t *testing.T, cfg *conf.Transport) tnet.Conn {
	t.Helper()
	serverAddr := &net.UDPAddr{IP: net.ParseIP("38.49.208.35"), Port: simServerHopped}
	cc := &countingConn{PacketConn: st.serverConn}
	st.srvCounting = cc
	t.Cleanup(func() {
		t.Logf("kcpReads on server: %d; first payload: %s", cc.readN, st.sSrc.firstHex)
	})
	cfg.Protocol = "auto"
	ln, err := transport.ListenMulti(cfg, cc)
	if err != nil {
		t.Fatalf("server Listen: %v", err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go serveEcho(conn)
		}
	}()
	conn, err := transport.DialProto("kcp", serverAddr, cfg, st.clientConn)
	if err != nil {
		t.Fatalf("client Dial: %v", err)
	}
	return conn
}

func serveEcho(conn tnet.Conn) {
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
}

func TestTunnel_CleanThroughput(t *testing.T) {
	st := newSimTunnel(t, 5*time.Millisecond, 0)
	defer st.wire.close()
	defer st.clientConn.Close()
	defer st.serverConn.Close()

	cfg := testTunnelConfig()
	conn := st.dial(t, cfg)
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

// TestTunnel_PatternEcho: deterministic pattern isolates the corrupting
// layer (client->server vs server->client) by offset/shape.
func TestTunnel_PatternEcho(t *testing.T) {
	st := newSimTunnel(t, 5*time.Millisecond, 0)
	defer st.wire.close()
	defer st.clientConn.Close()
	defer st.serverConn.Close()

	cfg := testTunnelConfig()
	conn := st.dial(t, cfg)
	defer conn.Close()

	strm, err := conn.OpenStrm()
	if err != nil {
		t.Fatalf("OpenStrm: %v", err)
	}
	payload := make([]byte, 32*1024)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	roundTrip(t, strm, payload, 15*time.Second)
}

// TestTunnel_SmallEcho: 4KB echo — isolates size-dependent corruption.
func TestTunnel_SmallEcho(t *testing.T) {
	st := newSimTunnel(t, 5*time.Millisecond, 0)
	defer st.wire.close()
	defer st.clientConn.Close()
	defer st.serverConn.Close()

	cfg := testTunnelConfig()
	conn := st.dial(t, cfg)
	defer conn.Close()

	strm, err := conn.OpenStrm()
	if err != nil {
		t.Fatalf("OpenStrm: %v", err)
	}
	payload := make([]byte, 4096)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	roundTrip(t, strm, payload, 15*time.Second)
}

// TestTunnel_RotationMidStream: THE regression test for the rotation saga.
func TestTunnel_RotationMidStream(t *testing.T) {
	st := newSimTunnel(t, 5*time.Millisecond, 0)
	defer st.wire.close()
	defer st.clientConn.Close()
	defer st.serverConn.Close()

	cfg := testTunnelConfig()
	conn := st.dial(t, cfg)
	defer conn.Close()

	strm, err := conn.OpenStrm()
	if err != nil {
		t.Fatalf("OpenStrm: %v", err)
	}

	roundTrip(t, strm, []byte("warm"), 5*time.Second)

	newPort, err := st.clientConn.RotateLocalPort(2*time.Second)
	if err != nil {
		t.Fatalf("RotateLocalPort: %v", err)
	}
	t.Logf("rotated client source port to %d mid-stream", newPort)

	payload := make([]byte, 256*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	roundTrip(t, strm, payload, 45*time.Second)

	if _, err := st.clientConn.RotateLocalPort(2*time.Second); err != nil {
		t.Fatalf("RotateLocalPort #2: %v", err)
	}
	roundTrip(t, strm, []byte("alive after second rotation"), 15*time.Second)
}

func TestTunnel_MultipleRotationsWithNewStreams(t *testing.T) {
	st := newSimTunnel(t, 5*time.Millisecond, 0)
	defer st.wire.close()
	defer st.clientConn.Close()
	defer st.serverConn.Close()

	cfg := testTunnelConfig()
	conn := st.dial(t, cfg)
	defer conn.Close()

	strm0, err := conn.OpenStrm()
	if err != nil {
		t.Fatalf("OpenStrm: %v", err)
	}
	roundTrip(t, strm0, []byte("warm"), 5*time.Second)

	for i := 0; i < 5; i++ {
		if _, err := st.clientConn.RotateLocalPort(2*time.Second); err != nil {
			t.Fatalf("rotation %d: %v", i, err)
		}
		strm, err := conn.OpenStrm()
		if err != nil {
			t.Fatalf("post-rotation stream %d: %v", i, err)
		}
		msg := make([]byte, 32*1024)
		if _, err := rand.Read(msg); err != nil {
			t.Fatal(err)
		}
		roundTrip(t, strm, msg, 20*time.Second)
		strm.Close()
	}
}

// TestTunnel_ReplySourcePortMatchesHop: regression for the ':10000 source
// port' bug — replies must come from the server port the client writes to.
func TestTunnel_ReplySourcePortMatchesHop(t *testing.T) {
	st := newSimTunnel(t, 5*time.Millisecond, 0)
	defer st.wire.close()
	defer st.clientConn.Close()
	defer st.serverConn.Close()

	cfg := testTunnelConfig()
	conn := st.dial(t, cfg)
	defer conn.Close()

	strm, err := conn.OpenStrm()
	if err != nil {
		t.Fatalf("OpenStrm: %v", err)
	}
	roundTrip(t, strm, []byte("pre-hop"), 5*time.Second)

	if _, err := st.clientConn.RotateLocalPort(2*time.Second); err != nil {
		t.Fatalf("RotateLocalPort: %v", err)
	}

	for i := 0; i < 10; i++ {
		roundTrip(t, strm, []byte("post-hop ping"), 5*time.Second)
	}
}

func TestTunnel_Lossy(t *testing.T) {
	st := newSimTunnel(t, 5*time.Millisecond, 0.03)
	defer st.wire.close()
	defer st.clientConn.Close()
	defer st.serverConn.Close()

	cfg := testTunnelConfig()
	conn := st.dial(t, cfg)
	defer conn.Close()

	strm, err := conn.OpenStrm()
	if err != nil {
		t.Fatalf("OpenStrm: %v", err)
	}
	payload := make([]byte, 64*1024)
	if _, err := rand.Read(payload); err != nil {
		t.Fatal(err)
	}
	roundTrip(t, strm, payload, 60*time.Second)
}

// TestWireCodec_RoundTrip: encode/decode must be lossless for random
// payloads — isolates gopacket codec corruption from stack corruption.
func TestWireCodec_RoundTrip(t *testing.T) {
	for i := 0; i < 500; i++ {
		n := 1 + randInt(int64(1400))
		payload := make([]byte, n)
		if _, err := rand.Read(payload); err != nil {
			t.Fatal(err)
		}
		pkt := rawPacket{
			srcIP:   net.ParseIP("203.0.113.10").To4(),
			srcPort: 40000,
			dstIP:   net.ParseIP("38.49.208.35").To4(),
			dstPort: 20000,
			payload: payload,
		}
		frame := encodeRaw(pkt, pkt.srcPort)
		got, ok := decodeRaw(frame)
		if !ok {
			t.Fatalf("iter %d: decode failed (len %d)", i, len(frame))
		}
		if !bytes.Equal(got.payload, payload) {
			for j := range got.payload {
				if got.payload[j] != payload[j] {
					t.Fatalf("iter %d: payload corrupt at %d: got %02x want %02x (len %d)", i, j, got.payload[j], payload[j], n)
				}
			}
		}
		if got.srcPort != 40000 || got.dstPort != 20000 {
			t.Fatalf("iter %d: ports wrong", i)
		}
	}
}
