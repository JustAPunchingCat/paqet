package internal_test

// TestTunnel_MultiConnDistinctCanonicalAddr is the regression test for the
// field "conn:8 unstable / packets merge or lost" bug.
//
// Root cause (fixed): the server canonicalized every client by IP ONLY, so
// all conn:N connections from one client collapsed into a SINGLE kcp session
// (kcp-go keys sessions by addr.String()). Now each client PacketConn stamps
// a stable per-conn ID (survives local-port rotation, distinct across conns),
// and the server reports the canonical addr as IP:connID — so N conns become
// N distinct sessions.
//
// This test drives the REAL production path (WriteTo stamp + workerLoop
// strip + ReadFrom canonical keying) with two clients behind one NAT (same
// public IP, different source ports) and asserts the server sees two DISTINCT
// canonical addrs with the payload intact.
import (
	"context"
	"net"
	"testing"
	"time"

	"paqet/internal/conf"
	"paqet/internal/socket"
)

func TestTunnel_MultiConnDistinctCanonicalAddr(t *testing.T) {
	w := newSimWire(0, 0)
	defer w.close()

	routerMAC, _ := net.ParseMAC("02:00:00:00:00:01")
	iface := &net.Interface{
		Index:        1,
		MTU:          1500,
		Name:         "sim",
		HardwareAddr: routerMAC,
		Flags:        net.FlagUp,
	}

	newClient := func(port int) *socket.PacketConn {
		t.Helper()
		cfg := &conf.Network{
			Role:       "client",
			Port:       port,
			Interface_: "sim",
			Interface:  iface,
			Driver:     "testing",
			Transport:  testTunnelConfig(),
			IPv4: conf.Addr{
				Addr:   &net.UDPAddr{IP: net.ParseIP("172.30.250.2").To4(), Port: 0},
				Router: routerMAC,
			},
		}
		cfg.TCP.LF = []conf.TCPF{{PSH: true, ACK: true}}
		cfg.TCP.RF = []conf.TCPF{{PSH: true, ACK: true}}
		c, err := socket.NewWithTestingPipes(context.Background(), cfg, nil, true, nil)
		if err != nil {
			t.Fatalf("client PacketConn: %v", err)
		}
		c.InjectTestingInjector(&clientInjector{w: w})
		c.InjectTestingSource(&clientSource{w: w})
		c.Start()
		return c
	}

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
	server, err := socket.NewWithTestingPipes(context.Background(), serverCfg, nil, false, nil)
	if err != nil {
		t.Fatalf("server PacketConn: %v", err)
	}
	server.InjectTestingInjector(&serverInjector{w: w})
	server.InjectTestingSource(&serverSource{w: w})
	server.Start()
	defer server.Close()
	_ = server.SetReadDeadline(time.Now().Add(10 * time.Second))

	c1 := newClient(40001)
	defer c1.Close()
	c2 := newClient(40002)
	defer c2.Close()

	serverAddr := &net.UDPAddr{IP: net.ParseIP("38.49.208.35"), Port: 20000}

	payload1 := []byte("hello-from-conn-1")
	payload2 := []byte("hello-from-conn-2")
	if _, err := c1.WriteTo(payload1, serverAddr); err != nil {
		t.Fatalf("c1 WriteTo: %v", err)
	}
	if _, err := c2.WriteTo(payload2, serverAddr); err != nil {
		t.Fatalf("c2 WriteTo: %v", err)
	}

	// Read two packets back. The canonical addrs MUST differ (per-conn ID)
	// and the payloads MUST be intact (conn ID stripped server-side).
	buf := make([]byte, 65536)
	n1, a1, err := server.ReadFrom(buf)
	if err != nil {
		t.Fatalf("server ReadFrom #1: %v", err)
	}
	got1 := string(buf[:n1])
	n2, a2, err := server.ReadFrom(buf)
	if err != nil {
		t.Fatalf("server ReadFrom #2: %v", err)
	}
	got2 := string(buf[:n2])

	u1, ok1 := a1.(*net.UDPAddr)
	u2, ok2 := a2.(*net.UDPAddr)
	if !ok1 || !ok2 {
		t.Fatalf("canonical addrs not UDP: %T %T", a1, a2)
	}
	if u1.Port == u2.Port {
		t.Fatalf("multi-conn collapsed into one canonical addr: %v == %v (conn IDs not distinct)", a1, a2)
	}
	if u1.IP.String() != u2.IP.String() {
		t.Fatalf("expected same NAT public IP for both conns, got %v vs %v", u1.IP, u2.IP)
	}
	if (got1 != string(payload1) && got1 != string(payload2)) ||
		(got2 != string(payload1) && got2 != string(payload2)) ||
		got1 == got2 {
		t.Fatalf("payload not round-tripped: got %q and %q (want %q and %q)", got1, got2, payload1, payload2)
	}
	t.Logf("distinct canonical addrs: %v vs %v (payloads %q / %q)", a1, a2, got1, got2)
}
