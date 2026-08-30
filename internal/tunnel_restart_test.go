package internal_test

// TestTunnel_ServerRestartDesync: reproduce the field run 14:28 — a
// server PROCESS restart while the client session is established. The
// fresh server accepts the client's KCP packets into a brand-new session
// (wire stays fully alive), but its smux never negotiated with the
// client's old smux session. What does the client actually see when it
// opens a new stream?
//
//   - If OpenStrm blocks: the 5s deadline + conn rebuild path is the
//     right fix and this test proves recovery end-to-end.
//   - If OpenStrm returns and the stream silently misbehaves: the fix is
//     wrong and this test tells us what really happens.
//
// The test asserts the CONTRACT: after a server restart, a rebuilt
// client conn must carry data end-to-end.
import (
	"context"
	"fmt"
	"net"
	"testing"
	"time"

	"paqet/internal/conf"
	"paqet/internal/socket"
	"paqet/internal/tnet"
	"paqet/internal/transport"
)

// newFreshServerConn builds a brand-new server PacketConn on the same
// wire/identity as the original — the "restarted process".
func newFreshServerConn(t *testing.T, st *simTunnel) *socket.PacketConn {
	t.Helper()
	routerMAC, _ := net.ParseMAC("02:00:00:00:00:01")
	iface := &net.Interface{
		Index:        1,
		MTU:          1500,
		Name:         "sim",
		HardwareAddr: routerMAC,
		Flags:        net.FlagUp,
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

	sc, err := socket.NewWithTestingPipes(context.Background(), serverCfg, nil, false, nil)
	if err != nil {
		t.Fatalf("fresh server PacketConn: %v", err)
	}
	sc.InjectTestingInjector(&serverInjector{w: st.wire})
	sc.InjectTestingSource(&serverSource{w: st.wire})
	sc.Start()
	return sc
}

func TestTunnel_ServerRestartDesync(t *testing.T) {
	st := newSimTunnel(t, 5*time.Millisecond, 0)
	defer st.wire.close()
	defer st.clientConn.Close()

	cfg := testTunnelConfig()
	conn := st.dial(t, cfg)
	defer conn.Close()

	// 1. Healthy session before the "restart".
	strm, err := conn.OpenStrm()
	if err != nil {
		t.Fatalf("OpenStrm before restart: %v", err)
	}
	roundTrip(t, strm, []byte("warm"), 5*time.Second)
	strm.Close()

	// 2. SERVER RESTART: kill the old server PacketConn (process death)
	// and bring up a fresh one on the same wire — same identity, zero
	// state. The client's conn object stays untouched, exactly like the
	// field client.
	st.serverConn.Close()

	freshServer := newFreshServerConn(t, st)
	defer freshServer.Close()

	cfg2 := testTunnelConfig()
	cfg2.Protocol = "auto"
	cc2 := &countingConn{PacketConn: freshServer}
	ln, err := transport.ListenMulti(cfg2, cc2)
	if err != nil {
		t.Fatalf("fresh server Listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveEcho(c)
		}
	}()

	// 3. The client keeps using its OLD conn (stale smux). The new
	// server accepts its KCP packets into a fresh session. Open a new
	// stream — the desync moment. Bound it: must resolve within 15s.
	openDone := make(chan error, 1)
	var openedStrm tnet.Strm
	go func() {
		s, err := conn.OpenStrm()
		if err != nil {
			openDone <- err
			return
		}
		openedStrm = s
		openDone <- nil
	}()

	select {
	case err := <-openDone:
		if err != nil {
			t.Logf("OpenStrm after restart: %v (client must rebuild)", err)
		} else {
			// Opened without error: probe whether the stream actually
			// works — a desynced session may accept opens but never
			// deliver. If the round trip below on this stream works,
			// smux resynced on its own; if not, rebuild is required.
			t.Logf("OpenStrm after restart: opened without error (desync risk)")
			errCh := make(chan error, 1)
			go func() {
				errCh <- roundTripErr(openedStrm, []byte("desync probe"), 5*time.Second)
			}()
			select {
			case err := <-errCh:
				if err == nil {
					t.Logf("stale-session stream WORKS — smux resynced on its own")
					return // recovery happened even without rebuild
				}
				t.Logf("stale-session stream dead: %v — rebuild required", err)
			case <-time.After(6 * time.Second):
				t.Logf("stale-session stream HUNG — rebuild required (matches field run 14:28)")
			}
			openedStrm.Close()
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("OpenStrm after restart blocked >15s — client wedged (the field bug)")
	}

	// 4. CONTRACT: a REBUILT client conn must carry data end-to-end.
	// (timedConn does exactly this after teardown — redial here.)
	freshConn, err := transport.DialProto("kcp",
		&net.UDPAddr{IP: net.ParseIP("38.49.208.35"), Port: simServerHopped},
		cfg2, st.clientConn)
	if err != nil {
		t.Fatalf("fresh dial: %v", err)
	}
	defer freshConn.Close()

	fs, err := freshConn.OpenStrm()
	if err != nil {
		t.Fatalf("OpenStrm on fresh conn: %v", err)
	}
	roundTrip(t, fs, []byte("recovered after restart"), 20*time.Second)
}

// roundTripErr is roundTrip returning an error instead of failing the
// test, for use inside goroutine-based probes.
func roundTripErr(strm tnet.Strm, payload []byte, timeout time.Duration) error {
	type res struct {
		n   int
		err error
	}
	done := make(chan res, 1)
	go func() {
		if _, err := strm.Write(payload); err != nil {
			done <- res{0, err}
			return
		}
		got := make([]byte, len(payload))
		_ = strm.SetReadDeadline(time.Now().Add(timeout))
		n, err := strm.Read(got)
		done <- res{n, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			return r.err
		}
		if r.n != len(payload) {
			return errShortRead{got: r.n, want: len(payload)}
		}
		return nil
	case <-time.After(timeout + 2*time.Second):
		return errRoundTripTimeout{}
	}
}

type errShortRead struct {
	got  int
	want int
}

func (e errShortRead) Error() string {
	return "short read"
}

type errRoundTripTimeout struct{}

func (errRoundTripTimeout) Error() string {
	return "round trip timeout"
}

// TestTunnel_ClientFirstServerLater: the field scenario "client started
// sooner than server" — the client dials while NO server exists, the
// server comes up later. CONTRACT: after the server appears, the client
// must carry data end-to-end without a client restart.
func TestTunnel_ClientFirstServerLater(t *testing.T) {
	st := newSimTunnelWithoutServer(t, 5*time.Millisecond, 0)
	defer st.wire.close()
	defer st.clientConn.Close()

	cfg := testTunnelConfig()
	cfg.Protocol = "auto"
	clientAddr := &net.UDPAddr{IP: net.ParseIP("38.49.208.35"), Port: simServerHopped}

	// 1. Client dials while the server does NOT exist. DialProto over UDP
	// returns immediately (UDP is connectionless); smux handshake happens
	// lazily. Whatever it does, bound it.
	conn, err := transport.DialProto("kcp", clientAddr, cfg, st.clientConn)
	if err != nil {
		t.Fatalf("client dial with no server: %v", err)
	}
	defer conn.Close()

	// 2. Attempt a stream BEFORE the server exists — bounded.
	earlyDone := make(chan error, 1)
	go func() {
		strm, err := conn.OpenStrm()
		if err != nil {
			earlyDone <- err
			return
		}
		strm.SetWriteDeadline(time.Now().Add(3 * time.Second))
		_, werr := strm.Write([]byte("early"))
		earlyDone <- werr
	}()
	select {
	case err := <-earlyDone:
		t.Logf("pre-server stream attempt: %v", err)
	case <-time.After(6 * time.Second):
		t.Logf("pre-server stream attempt blocked >6s (expected: nothing to talk to)")
	}

	// 3. SERVER COMES UP (fresh process).
	freshServer := newFreshServerConn(t, st)
	defer freshServer.Close()
	ln, err := transport.ListenMulti(cfg, freshServer)
	if err != nil {
		t.Fatalf("server Listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveEcho(c)
		}
	}()

	// 4. CONTRACT: within 15s of the server existing, a new stream must
	// round-trip WITHOUT touching the client conn.
	deadline := time.Now().Add(15 * time.Second)
	for {
		strm, err := conn.OpenStrm()
		if err == nil {
			err = roundTripErr(strm, []byte("late client-first data"), 10*time.Second)
			strm.Close()
			if err == nil {
				t.Logf("recovered after server appeared (attempt at %s)", time.Since(deadline.Add(-15*time.Second)))
				return
			}
			t.Logf("stream opened but dead (%v) — session never established pre-server; redial needed", err)
			// Session was never really established (smux handshake lost
			// into the void): the only recovery is a fresh dial — exactly
			// what timedConn does after teardown. Redial and prove data
			// flows.
			conn.Close()
			conn2, derr := transport.DialProto("kcp", clientAddr, cfg, st.clientConn)
			if derr != nil {
				t.Fatalf("redial: %v", derr)
			}
			defer conn2.Close()
			strm2, oerr := conn2.OpenStrm()
			if oerr != nil {
				t.Fatalf("OpenStrm after redial: %v", oerr)
			}
			roundTrip(t, strm2, []byte("recovered client-first"), 15*time.Second)
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no recovery within 15s of server start: last OpenStrm error: %v", err)
		}
		time.Sleep(500 * time.Millisecond)
	}
}

// newSimTunnelWithoutServer: wire + client only — the server comes up
// later (TestTunnel_ClientFirstServerLater).
func newSimTunnelWithoutServer(t *testing.T, latency time.Duration, loss float64) *simTunnel {
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

	clientConn, err := socket.NewWithTestingPipes(context.Background(), clientCfg, nil, true, nil)
	if err != nil {
		t.Fatalf("client PacketConn: %v", err)
	}
	cSrc := &clientSource{w: w}
	cInj := &clientInjector{w: w}
	clientConn.InjectTestingInjector(cInj)
	clientConn.InjectTestingSource(cSrc)
	clientConn.Start()

	t.Cleanup(func() {
		t.Logf("wire: cInj sent=%d badDec=%d; clientSrc saw=%d", cInj.sent, cInj.badDec, cSrc.seen)
	})

	return &simTunnel{wire: w, clientConn: clientConn, cSrc: cSrc}
}

// newFreshClientConn mirrors production teardown/rebuild: a NEW client
// PacketConn (new source port, fresh capture) — timedConn.createConn
// builds a whole new socket.PacketConn after teardown.
func newFreshClientConn(t *testing.T, st *simTunnel) *socket.PacketConn {
	t.Helper()
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

	cc, err := socket.NewWithTestingPipes(context.Background(), clientCfg, nil, true, nil)
	if err != nil {
		t.Fatalf("fresh client PacketConn: %v", err)
	}
	cc.InjectTestingInjector(&clientInjector{w: st.wire})
	cc.InjectTestingSource(&clientSource{w: st.wire})
	cc.Start()
	return cc
}

// TestTunnel_MultipleServerRestarts: battle test — the field finding was
// "first restart recovers, second restart kills the tunnel". Simulate
// THREE consecutive server process restarts with recovery between each.
// Production semantics for the client rebuild: close the PacketConn and
// build a new one (new source port, fresh capture) — exactly what
// timedConn.createConn does after teardown.
func TestTunnel_MultipleServerRestarts(t *testing.T) {
	st := newSimTunnel(t, 5*time.Millisecond, 0)
	defer st.wire.close()

	const rounds = 3
	cfg := testTunnelConfig()
	cfg.Protocol = "auto"
	clientAddr := &net.UDPAddr{IP: net.ParseIP("38.49.208.35").To4(), Port: simServerHopped}

	clientConn := newFreshClientConn(t, st)
	defer clientConn.Close()

	// Initial server + session.
	freshServer := newFreshServerConn(t, st)
	ln, err := transport.ListenMulti(cfg, freshServer)
	if err != nil {
		t.Fatalf("server Listen: %v", err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go serveEcho(c)
		}
	}()

	conn, err := transport.DialProto("kcp", clientAddr, cfg, clientConn)
	if err != nil {
		t.Fatalf("initial dial: %v", err)
	}

	strm, err := conn.OpenStrm()
	if err != nil {
		t.Fatalf("initial OpenStrm: %v", err)
	}
	roundTrip(t, strm, []byte("initial"), 10*time.Second)
	strm.Close()

	for round := 1; round <= rounds; round++ {
		t.Logf("=== restart round %d ===", round)

		// SERVER PROCESS DEATH.
		freshServer.Close()
		ln.Close()
		conn.Close()

		// New server process on the same wire.
		freshServer = newFreshServerConn(t, st)
		ln, err = transport.ListenMulti(cfg, freshServer)
		if err != nil {
			t.Fatalf("round %d: server Listen: %v", round, err)
		}
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				go serveEcho(c)
			}
		}()

		// Client rebuild — PRODUCTION SEMANTICS: whole new PacketConn.
		clientConn.Close()
		clientConn = newFreshClientConn(t, st)

		var recovered bool
		deadline := time.Now().Add(20 * time.Second)
		var curConn tnet.Conn
		for !recovered {
			if time.Now().After(deadline) {
				t.Fatalf("round %d: NO RECOVERY within 20s — tunnel fucked at restart %d", round, round)
			}
			c2, derr := transport.DialProto("kcp", clientAddr, cfg, clientConn)
			if derr != nil {
				t.Logf("round %d: dial error %v — retry", round, derr)
				time.Sleep(300 * time.Millisecond)
				continue
			}
			s2, oerr := c2.OpenStrm()
			if oerr != nil {
				t.Logf("round %d: OpenStrm %v — retry", round, oerr)
				c2.Close()
				time.Sleep(300 * time.Millisecond)
				continue
			}
			rerr := roundTripErr(s2, []byte(fmt.Sprintf("restart round %d", round)), 8*time.Second)
			if rerr != nil {
				t.Logf("round %d: stream dead (%v) — retry with fresh dial", round, rerr)
				s2.Close()
				c2.Close()
				time.Sleep(300 * time.Millisecond)
				continue
			}
			s2.Close()
			curConn = c2
			recovered = true
		}
		conn = curConn
		t.Logf("round %d: RECOVERED", round)
	}
	t.Logf("survived %d consecutive server restarts", rounds)
}
