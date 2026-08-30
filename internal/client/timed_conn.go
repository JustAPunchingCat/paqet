package client

import (
	"context"
	"fmt"
	"net"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/protocol"
	"paqet/internal/socket"
	"paqet/internal/tnet"
	"paqet/internal/transport"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

type timedConn struct {
	rootCfg       *conf.Conf
	srvCfg        *conf.ServerConfig
	conn          tnet.Conn
	pConn         *socket.PacketConn
	lastPort      int
	remoteAddr    *net.UDPAddr
	lastRotate    time.Time
	expire        time.Time
	ctx           context.Context
	mu            sync.Mutex
	activeStreams int
	lastIdle      time.Time
	lastRSTHop    atomic.Int64
	// consecutiveAutoRotates counts auto_rotate firings with no recovery
	// between them: 2 in a row means port rotation isn't fixing the deafness
	// — the SESSION is desynced (e.g. server restarted and never RST'd us);
	// only a full conn rebuild (fresh smux handshake) recovers then.
	autoRotateRun atomic.Int64
	// rebuildAt: when the conn was last torn down for a rebuild. auto_rotate
	// must not judge a newborn session (streams may be silent for seconds
	// during TLS handshakes — field-proven mid-curl kills).
	rebuildAt        atomic.Int64
	lastAutoRotateAt atomic.Int64
	// closeJobs: teardown closes are executed on a dedicated goroutine.
	// conn/pConn Close() contends the eBPF managerMu with hopping
	// rebinds; doing that inline (on the idle loop, under tc.mu, or on
	// the RST path) produced ABBA deadlocks — field runs 17:48/17:59/
	// 18:04. Enqueue here; never block the caller.
	closeJobs chan func()
	// createConnFn: test seam — overrides createConn when set.
	createConnFn func() (tnet.Conn, error)
	// rebuildMu single-flights createConn across concurrent requesters.
	rebuildMu sync.Mutex
}

func newTimedConn(ctx context.Context, rootCfg *conf.Conf, srvCfg *conf.ServerConfig) (*timedConn, error) {
	tc := timedConn{
		ctx:       ctx,
		rootCfg:   rootCfg,
		srvCfg:    srvCfg,
		lastIdle:  time.Now(),
		closeJobs: make(chan func(), 64),
	}
	// Dedicated closer: all conn/pConn Close() calls run here, never
	// under tc.mu, never on the idle loop, never on the RST path. The
	// eBPF close path can block on managerMu contention with hopping
	// rebinds — isolating it here makes caller-side deadlock impossible.
	go func() {
		for job := range tc.closeJobs {
			job()
		}
	}()

	var err error
	tc.conn, err = tc.createConn()
	if err != nil {
		return nil, err
	}

	// Wire the RST handler: a middlebox RST means the current
	// (clientPort, serverPort) tuple is being reset by a stateful box —
	// a forced hop to a fresh port is the capture-proven recovery.
	if tc.pConn != nil {
		tc.pConn.OnRST = tc.OnRST
	}

	go tc.idleCheckLoop()

	return &tc, nil
}

// newConn routes through the test seam when installed.
func (tc *timedConn) newConn() (tnet.Conn, error) {
	if tc.createConnFn != nil {
		return tc.createConnFn()
	}
	return tc.createConn()
}

func (tc *timedConn) createConn() (tnet.Conn, error) {
	netCfg := tc.rootCfg.Network
	if tc.rootCfg.Network.IPv4.Addr != nil {
		cloneAddr := *tc.rootCfg.Network.IPv4.Addr
		netCfg.IPv4.Addr = &cloneAddr
	}
	if tc.rootCfg.Network.IPv6.Addr != nil {
		cloneAddr := *tc.rootCfg.Network.IPv6.Addr
		netCfg.IPv6.Addr = &cloneAddr
	}
	// Use server-specific transport settings (e.g. Key) for this connection
	netCfg.Transport = &tc.srvCfg.Transport
	// Explicitly copy spoof config from root
	netCfg.Spoof = tc.rootCfg.Network.Spoof
	// Server-specific fake TCP handshake config
	netCfg.Handshake = &tc.srvCfg.Handshake
	// Server IP(s) for the eBPF XDP filter (drop all server traffic, no leak)
	if tc.srvCfg.Server.Addr != nil && tc.srvCfg.Server.Addr.IP != nil {
		netCfg.ServerIPs = []net.IP{tc.srvCfg.Server.Addr.IP}
	}

	// Explicitly use the server's obfuscation config
	// We do not propagate global obfuscation settings to allow mixing obfuscated
	// and non-obfuscated servers. If not configured for this server, it defaults
	// to disabled (zero value).
	obfsCfg := &tc.srvCfg.Obfuscation

	pConn, err := socket.NewWithHopping(tc.ctx, &netCfg, &tc.srvCfg.Hopping, true, obfsCfg, tc.srvCfg.Server.Addr.String())
	if err != nil {
		return nil, fmt.Errorf("could not create packet conn: %w", err)
	}
	// WIRE OnRST ON EVERY REBUILD: createConn can run at any time
	// (initial dial, auto_rotate escalation, OnRST teardown, idle
	// reaper). The initial newTimedConn wiring only covered the FIRST
	// PacketConn — every rebuilt conn came up with OnRST=nil, so all
	// subsequent server RSTs were dispatched into a nil handler and
	// silently dropped (field run 17:55: 'handler set: false' on every
	// RST, tunnel wedged in a kernel-RST loop until manual restart).
	if tc.pConn != nil {
		tc.pConn.OnRST = nil
	}
	pConn.OnRST = tc.OnRST
	tc.pConn = pConn
	tc.lastPort = pConn.GetCurrentPort()

	// Client local-port rotation: when hopping.rotate_client_port is set,
	// rebind the local source port every rotate_every hops (default 1) so
	// each NAT mapping gets a fresh return-path quota. No-op when disabled
	// or when the capture source cannot rebind (pcap/afpacket).
	if tc.srvCfg.Hopping.RotateClientPort {
		every := tc.srvCfg.Hopping.RotateEvery
		if every <= 0 {
			every = 1
		}
		pConn.SetOnHop(func(n uint32) {
			if n%uint32(every) == 0 {
				tc.rotateLocalPortIfConfigured()
			}
		})
	} else {
		// DIAGNOSTIC: rotation disabled at runtime — make the effective
		// value visible once at startup. A silent knob is indistinguishable
		// from a silently dropped config block.
		flog.Infof("rotate_client_port disabled for %s — client keeps its local port across hops", tc.srvCfg.Server.Addr.String())
	}
	// Guard: close pConn on any error path so background goroutines and file
	// descriptors are never orphaned when the server is offline or unreachable.
	success := false
	defer func() {
		if !success {
			pConn.Close()
		}
	}()

	// If hopping is enabled, the raw socket normalizes incoming packets to hopping.Min.
	// We must tell KCP to expect packets from this normalized port, ignoring the
	// static port defined in server.addr.
	remoteAddr := tc.srvCfg.Server.Addr
	if tc.srvCfg.Hopping.IsEnabled() {
		clone := *remoteAddr
		canonicalPort := tc.srvCfg.Hopping.Min
		if canonicalPort == 0 {
			if ranges, _ := tc.srvCfg.Hopping.GetRanges(); len(ranges) > 0 {
				canonicalPort = ranges[0].Min
			}
		}
		clone.Port = canonicalPort
		remoteAddr = &clone
	}
	tc.remoteAddr = remoteAddr

	var conn tnet.Conn

	// Calculate obfuscation overhead
	overhead := 0
	if obfsCfg.UseTLS {
		overhead = 5 + 2 + obfsCfg.Padding.Max
	} else if obfsCfg.Padding.Enabled {
		overhead = 2 + obfsCfg.Padding.Max
	}

	switch tc.srvCfg.Transport.Protocol {
	case "kcp":
		// Adjust MTU to account for obfuscation overhead
		// Make a shallow copy of Transport config to avoid modifying the global config
		tCfg := tc.srvCfg.Transport
		kcpCfg := *tCfg.KCP

		if kcpCfg.MTU == 0 {
			kcpCfg.MTU = 1350
		}
		if overhead > 0 {
			kcpCfg.MTU -= overhead
			flog.Debugf("Adjusted Client KCP MTU to %d (overhead: %d)", kcpCfg.MTU, overhead)
		}
		tCfg.KCP = &kcpCfg
		conn, err = transport.DialProto("kcp", remoteAddr, &tCfg, pConn)
	case "quic":
		conn, err = transport.DialProto("quic", remoteAddr, &tc.srvCfg.Transport, pConn)
	case "udp": // Also needs to pass `tc.rootCfg.Role` to `socket.NewWithHopping` when creating `newPConn` for probing.
		tCfg := tc.srvCfg.Transport // Create a copy of Transport config
		udpCfg := *tCfg.UDP
		if udpCfg.MTU == 0 {
			udpCfg.MTU = 1350
		}
		if overhead > 0 {
			udpCfg.MTU -= overhead
			flog.Debugf("Adjusted Client UDP MTU to %d (overhead: %d)", udpCfg.MTU, overhead)
		}
		tCfg.UDP = &udpCfg
		conn, err = transport.DialProto("udp", remoteAddr, &tCfg, pConn)
	case "auto":
		// Probe for best protocol
		// We need a factory to create new PacketConns for probing, ensuring the role is passed
		newPConn := func() (net.PacketConn, error) {
			return socket.NewWithHopping(tc.ctx, &netCfg, &tc.srvCfg.Hopping, true, obfsCfg, tc.srvCfg.Server.Addr.String())
		}
		results, err := transport.Probe(remoteAddr, &tc.srvCfg.Transport, newPConn)
		if err != nil {
			return nil, fmt.Errorf("auto probe failed: %w", err)
		}
		best, err := transport.SelectBest(results)
		if err != nil {
			return nil, err
		}

		conn, err = transport.DialProto(best, remoteAddr, &tc.srvCfg.Transport, pConn)
	default:
		return nil, fmt.Errorf("unsupported transport protocol: %s", tc.srvCfg.Transport.Protocol)
	}

	err = tc.sendTCPF(conn)
	if err != nil {
		conn.Close() // also releases pConn via the transport Close chain
		return nil, err
	}

	success = true
	return conn, nil
}

func (tc *timedConn) sendTCPF(conn tnet.Conn) error {
	// DEADLINE REQUIRED: this runs inside createConn while tc.mu is
	// held. smux OpenStrm sends a SYN and blocks for the server's ACK —
	// with the server offline it blocks FOREVER (kcp-go v5 has no
	// deadlink timer), wedging tc.mu permanently: tc.conn stays nil so
	// auto_rotate skips the wedged state, and every SOCKS retry blocks
	// on the mutex. Field-proven total wedge requiring manual client
	// restart. Bound it — on timeout createConn returns an error, the
	// mutex is released, SOCKS fails fast, and the next attempt runs
	// when the server is actually up.
	type openRes struct {
		strm tnet.Strm
		err  error
	}
	done := make(chan openRes, 1)
	go func() {
		s, e := conn.OpenStrm()
		done <- openRes{s, e}
	}()
	var strm tnet.Strm
	select {
	case res := <-done:
		if res.err != nil {
			return res.err
		}
		strm = res.strm
	case <-time.After(5 * time.Second):
		return fmt.Errorf("smux stream open timed out after 5s (server offline?)")
	}
	defer strm.Close()

	p := protocol.Proto{Type: protocol.PTCPF, TCPF: tc.rootCfg.Network.TCP.RF}
	if err := p.Write(strm); err != nil {
		return err
	}
	return nil
}

// sendGoodbyeRST emits a single fake-TCP RST on the current packet conn's
// source port before it is torn down, so the server's RST handler kills the
// orphaned KCP session immediately instead of retransmitting for ~30s (KCP
// DeadLink). Must be called while holding tc.mu and before tc.pConn.Close().
func (tc *timedConn) sendGoodbyeRST() {
	if tc.pConn == nil || tc.remoteAddr == nil || tc.remoteAddr.IP == nil {
		return
	}
	if err := tc.pConn.SendRST(tc.remoteAddr.IP, tc.remoteAddr.Port); err != nil {
		flog.Debugf("failed to send goodbye RST to %s: %v", tc.remoteAddr, err)
	}
}

func (tc *timedConn) close() {
	if tc.conn != nil {
		tc.sendGoodbyeRST()
		tc.conn.Close()
		if tc.pConn != nil {
			tc.pConn.Close()
		}
	}
}

// OnRST reacts to an incoming fake-TCP RST from the server's side. On the
// wire these carry a kernel fingerprint (seq = our ack, win 0): a stateful
// middlebox has dropped our (clientPort, serverPort) tuple and is resetting
// every packet we send on it. Retransmitting into a dead tuple is pointless
// — the capture-proven recovery is a FRESH tuple, which is exactly what a
// forced port hop produces (KCP session preserved, fake-TCP seq continues).
// Rate-limited to one forced hop per RST_TIMEOUT_INTERVAL so a storm of RSTs
// (one per retransmit) cannot churn ports.

// deferClose enqueues a teardown close on the dedicated closer
// goroutine — never blocks the caller, never takes tc.mu.
func (tc *timedConn) deferClose(conn tnet.Conn, pConn *socket.PacketConn) {
	if conn == nil && pConn == nil {
		return
	}
	job := func() {
		if conn != nil {
			conn.Close()
		}
		if pConn != nil {
			pConn.Close()
		}
	}
	select {
	case tc.closeJobs <- job:
	default:
		go job()
	}
}

func (tc *timedConn) OnRST(addr net.Addr) {
	const RST_TIMEOUT_INTERVAL = 3 * time.Second
	// Field rule: an RST that triggers NO reaction is invisible — the
	// 14:21 run had a real server-restart RST that never produced a log
	// line. Every early return now says why.
	last := tc.lastRSTHop.Load()
	now := time.Now().UnixNano()
	if last != 0 && now-last < int64(RST_TIMEOUT_INTERVAL) {
		flog.Debugf("RST ignored: debounce (%dms since last)", (now-last)/int64(time.Millisecond))
		return
	}
	if !tc.lastRSTHop.CompareAndSwap(last, now) {
		flog.Debugf("RST ignored: lost debounce race")
		return
	}
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || udpAddr.IP == nil {
		flog.Debugf("RST ignored: addr is not *net.UDPAddr (%T)", addr)
		return
	}
	// Snapshot remoteAddr: a concurrent teardown nils it between the
	// check and any use — the sim gate caught this exact race panic
	// (TestNoLongTcMuHold, OnRST vs teardown nil'ing remoteAddr).
	remote := tc.remoteAddr
	if remote == nil || remote.IP == nil || !udpAddr.IP.Equal(remote.IP) {
		// RST from some other server (multi-server config) — ignore.
		flog.Debugf("RST ignored: src %s != remote %v", udpAddr.IP, remote)
		return
	}
	flog.Warnf("RST from server %s — forcing port hop + full conn rebuild (server session state is gone)", udpAddr.String())
	// Snapshot pConn: racing teardown may nil it between check and use.
	if pConn := tc.pConn; pConn != nil {
		// ForceHop fires the OnHop callback, which already performs the
		// client local-port rotation when rotate_client_port is enabled.
		pConn.ForceHop()
	}
	// A server RST on our current tuple means the server does not know
	// this session: either a middlebox reset the flow or the SERVER
	// PROCESS RESTARTED and its KCP/smux state is fresh. Hopping the port
	// alone is not enough — the new server session never negotiated smux
	// with our existing session, so stream frames are misread and SOCKS
	// streams never recover (field-proven: wire alive, pings flow, but
	// every stream hangs after a server restart). Rebuild the whole conn:
	// smux re-negotiates on the new session; open streams error out
	// client-side (SOCKS clients retry) — inherent to a server restart.
	deadConn := tc.conn
	deadPConn := tc.pConn
	tc.lockDiag()
	tc.conn = nil
	tc.pConn = nil
	tc.rebuildAt.Store(time.Now().UnixNano())
	tc.mu.Unlock()
	// Close OUTSIDE tc.mu ONLY — no under-lock closes anywhere. The
	// close path contends managerMu with the hopping plugin's rebinds;
	// holding tc.mu across it wedged every subsequent request (field
	// run 16:40) and the double-close under lock deadlocked the rebuild
	// (field run 17:59: idleCheckLoop stuck >2s in lockDiag).
	if deadConn != nil {
		deadConn.Close()
	}
	if deadPConn != nil {
		deadPConn.Close()
	}
}

// rotateLocalPortIfConfigured rebinds the client's local source port when
// hopping.rotate_client_port is enabled. A fresh client port creates a fresh
// NAT mapping — the counter to middleboxes that throttle the return path of a
// matured mapping. All KCP/smux streams ride the rebind automatically (they
// share the one PacketConn); the fake 3WHS re-fires on the new tuple via the
// handshake latch re-arm inside RebindSource. Failures are non-fatal: the
// tunnel keeps hopping server ports without client rotation.
func (tc *timedConn) rotateLocalPortIfConfigured() {
	// tc.mu is held for the WHOLE rotation: the idle reaper (idleCheckLoop)
	// nulls tc.conn/tc.pConn under the same lock, and a rotation running
	// concurrently dereferenced a nulled pConn — field-proven SIGSEGV
	// ('panic: nil pointer dereference ... RotateLocalPort' at hop N after
	// the tunnel went idle). Holding the lock serializes rotation against
	// reaping; RotateLocalPort only touches the eBPF manager and the send
	// handle's port field, so the extra hold time is negligible.
	tc.lockDiag()
	defer tc.mu.Unlock()

	if tc.pConn == nil {
		return
	}
	if !tc.srvCfg.Hopping.RotateClientPort {
		// DIAGNOSTIC: rotation configured-off — say so once per hop so a
		// silently-dead rotation config is visible in field logs.
		flog.Debugf("hop: rotate_client_port disabled — keeping local port %d", tc.lastPort)
		return
	}
	// Idle tunnel: rotating a conn the idle reaper is about to tear down
	// races the reaper (field-proven 'bad file descriptor' goodbye) and
	// buys nothing — the next write rebuilds on a fresh port anyway. Skip.
	idle := tc.activeStreams == 0 && !tc.lastIdle.IsZero() && time.Since(tc.lastIdle) > 30*time.Second
	if idle {
		flog.Debugf("hop: tunnel idle — skipping local-port rotation (next write rotates)")
		return
	}
	// The server keys sessions by client ip:port. After the source port
	// changes, the OLD server session is orphaned and its own KCP
	// retransmit timer would spam the wire until the reaper fires. Cleanup
	// is SERVER-SIDE: session supersession (accept of the new session from
	// the same IP closes same-IP older sessions) — no goodbye packets, the
	// tunnel stays fully asymmetric.
	flog.Debugf("rotate: rotating local source port")
	newPort, err := tc.pConn.RotateLocalPort()
	if err != nil {
		flog.Warnf("client local-port rotation FAILED: %v (continuing with server-port hops only)", err)
		return
	}
	tc.lastPort = newPort
	flog.Infof("client source port rotated to %d (fresh NAT mapping)", newPort)
}

func (tc *timedConn) reconnect() {
	tc.lockDiag()
	defer tc.mu.Unlock()
	// Never tear down a connection with live streams: a rotation here would
	// kill active sessions (SSH, etc.) mid-flight.
	if tc.activeStreams > 0 {
		return
	}
	if !tc.lastRotate.IsZero() && time.Since(tc.lastRotate) < 5*time.Second {
		return
	}
	tc.lastRotate = time.Now()

	srvLabel := ""
	if tc.srvCfg != nil && tc.srvCfg.Server.Addr != nil {
		srvLabel = tc.srvCfg.Server.Addr.IP.String()
	}

	oldPort := tc.lastPort
	if tc.conn != nil {
		tc.sendGoodbyeRST()
		tc.conn.Close()
		if tc.pConn != nil {
			tc.pConn.Close()
		}
	}
	var err error
	tc.conn, err = tc.createConn()
	if err != nil {
		flog.Debugf("failed to reconnect timedConn [%s] on port %d: %v", srvLabel, oldPort, err)
		tc.conn = nil
	}
}

func (tc *timedConn) markDead() {
	tc.lockDiag()
	defer tc.mu.Unlock()
	// A connection with live streams is demonstrably alive — a transient
	// failure on a sibling path (e.g. a UDP probe) must not reap it. If the
	// peer is truly dead, the streams themselves will error and close, which
	// drops activeStreams to 0 and lets idleCheckLoop clean up naturally.
	if tc.activeStreams > 0 {
		return
	}
	if tc.conn != nil {
		tc.sendGoodbyeRST()
		tc.conn.Close()
		if tc.pConn != nil {
			tc.pConn.Close()
		}
		tc.conn = nil
		tc.pConn = nil
	}
}

// lockDiag acquires tc.mu with contention diagnostics: if the lock is
// held >2s, log the holder's goroutine dump — field run 17:48 wedged at
// 'acquiring tc.mu' forever with no visible holder.
func (tc *timedConn) lockDiag() {
	if tc.mu.TryLock() {
		return
	}
	// 10s: an offline-server rebuild storm (kernel RSTs every ~200ms →
	// rebuild → eBPF close+rebind per cycle) legitimately holds tc.mu
	// for seconds at a time through the managerMu contention — bounded
	// work, not a deadlock (field runs 18:14/18:18/18:29: all complete
	// and recover when the server returns). The dump fires once per
	// stuck acquisition beyond 10s; a TRUE deadlock shows a holder
	// stack that never changes across dumps.
	deadline := time.Now().Add(10 * time.Second)
	for {
		if tc.mu.TryLock() {
			return
		}
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<16)
			n := runtime.Stack(buf, true)
			flog.Errorf("tc.mu contention >10s — holder stack:\n%s", buf[:n])
			tc.mu.Lock()
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func (tc *timedConn) openAndSendProto(p *protocol.Proto) (tnet.Strm, error) {
	// Slow path single-flight: createConn (eBPF init, seconds) AND the
	// bounded OpenStrm wait (up to 5s when the server is offline) run
	// under rebuildMu — NEVER under tc.mu. tc.mu is only taken for
	// brief field reads/writes; holding it across either slow operation
	// starved the idle loop and every concurrent request (field runs
	// 18:08/18:14: >2s contention alarms from idleCheckLoop).
	tc.rebuildMu.Lock()
	defer tc.rebuildMu.Unlock()

	tc.lockDiag()
	if tc.conn != nil {
		// Fast path: conn exists — open a stream on it under tc.mu
		// (OpenStrm may wait up to the 5s deadline, but only when the
		// session is desynced; on the healthy path it returns in ms
		// and the brief hold is benign).
		return tc.openStreamOnConn(p)
	}

	flog.Infof("openAndSendProto: rebuilding conn — outside tc.mu")
	conn, err := tc.newConn()
	if err != nil {
		flog.Errorf("openAndSendProto: rebuild failed: %v", err)
		return nil, err
	}
	// Install under tc.mu (brief).
	tc.lockDiag()
	tc.conn = conn
	tc.lastPort = tc.pConn.GetCurrentPort()
	tc.mu.Unlock()

	// Open the first stream OUTSIDE tc.mu (up to 5s on a dead server).
	strm, err := tc.boundedOpenStrm(conn)
	if err != nil {
		flog.Warnf("stream open timed out after rebuild — session desynced, deferring teardown to watchdog")
		return nil, err
	}
	tc.lockDiag()
	tc.activeStreams++
	tc.lastIdle = time.Time{}
	strm.SetWriteDeadline(time.Now().Add(60 * time.Second))
	werr := p.Write(strm)
	strm.SetWriteDeadline(time.Time{})
	if werr != nil {
		tc.mu.Unlock()
		strm.Close()
		tc.deferClose(conn, tc.pConn)
		tc.lockDiag()
		tc.conn = nil
		tc.pConn = nil
		tc.rebuildAt.Store(time.Now().UnixNano())
		tc.mu.Unlock()
		return nil, werr
	}
	return &idleTrackedStrm{Strm: strm, tc: tc}, nil
}

// openStreamOnConn opens a stream on the EXISTING tc.conn with the
// bounded deadline. The OpenStrm wait (up to 5s on a desynced session)
// runs OUTSIDE tc.mu; teardown during the wait is handled by the
// watchdog/escalation paths (they nil tc.conn, and the returned stream
// simply errors). Caller must NOT hold tc.mu.
func (tc *timedConn) openStreamOnConn(p *protocol.Proto) (tnet.Strm, error) {
	conn := tc.conn
	strm, err := tc.boundedOpenStrm(conn)
	if err != nil {
		return nil, err
	}
	tc.lockDiag()
	if tc.conn != conn {
		// Conn was rebuilt while we opened — discard.
		tc.mu.Unlock()
		strm.Close()
		return nil, fmt.Errorf("conn rebuilt during stream open — retry")
	}
	tc.activeStreams++
	tc.lastIdle = time.Time{}
	strm.SetWriteDeadline(time.Now().Add(60 * time.Second))
	werr := p.Write(strm)
	strm.SetWriteDeadline(time.Time{})
	if werr != nil {
		tc.mu.Unlock()
		strm.Close()
		return nil, werr
	}
	return &idleTrackedStrm{Strm: strm, tc: tc}, nil
}

// boundedOpenStrm wraps OpenStrm with the 5s deadline — no tc.mu held.
func (tc *timedConn) boundedOpenStrm(conn tnet.Conn) (tnet.Strm, error) {
	type openResult struct {
		strm tnet.Strm
		err  error
	}
	done := make(chan openResult, 1)
	go func() {
		s, e := conn.OpenStrm()
		done <- openResult{s, e}
	}()
	select {
	case res := <-done:
		if res.err != nil {
			return nil, res.err
		}
		return res.strm, nil
	case <-time.After(5 * time.Second):
		return nil, fmt.Errorf("stream open timed out after 5s — smux session desynced (server restart?)")
	}
}

func (tc *timedConn) idleCheckLoop() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-tc.ctx.Done():
			return
		case <-ticker.C:
			tc.lockDiag()
			// --- AutoRotate: return-path liveness self-healing ---
			// The middlebox on our path kills the RETURN direction of a
			// tunnel tuple ~15s after creation while the forward direction
			// stays hot (field-proven via XDP consumed counters: server
			// keeps receiving, client XDP consumed frozen). A fresh client
			// source port revives the path instantly — the only thing that
			// ever worked in the field. When auto_rotate is on, watch the
			// wire: if we are actively sending but nothing has been
			// received for AutoRotateAfter seconds, rotate NOW instead of
			// waiting for the next hop tick.
			if tc.srvCfg.Hopping.AutoRotate && tc.pConn != nil && tc.conn != nil {
				after := tc.srvCfg.Hopping.AutoRotateAfter
				if after <= 0 {
					after = 15
				}
				sendN := tc.pConn.LastSendNano()
				recvN := tc.pConn.LastRecvNano()
				now := time.Now().UnixNano()
				sending := sendN > 0 && now-sendN < int64(after)*int64(time.Second)
				deaf := recvN == 0 || now-recvN > int64(after)*int64(time.Second)
				if sending && deaf {
					if rb := tc.rebuildAt.Load(); rb != 0 && time.Now().UnixNano()-rb < int64(15*time.Second) {
						// Fresh rebuild — give the new session its footing.
						tc.mu.Unlock()
						tc.lockDiag()
						continue
					}
					// A rotation that is followed by silence again means
					// the problem is NOT the tuple: the session itself is
					// desynced (field-proven: server restarted, never sent
					// an RST, kept accepting our KCP packets into a fresh
					// session whose smux never negotiated — wire alive,
					// streams dead). Escalate: two consecutive deaf
					// auto-rotates without recovery → full conn teardown;
					// the next stream open rebuilds KCP+smux from scratch.
					tc.lastAutoRotateAt.Store(time.Now().UnixNano())
					run := tc.autoRotateRun.Add(1)
					if run >= 2 {
						flog.Infof("auto_rotate: deaf again after rotation (%d consecutive) — session desynced, rebuilding conn", run)
						tc.autoRotateRun.Store(0)
						// Grab what needs closing, release tc.mu, THEN
						// close. Field run 16:40: conn.Close()/pConn.Close()
						// executed while holding tc.mu blocked FOREVER
						// (eBPF close path contends managerMu with the
						// hopping plugin's concurrent rebind) — every
						// openAndSendProto then wedged at 'acquiring
						// tc.mu' and the SOCKS proxy died with it.
						deadConn := tc.conn
						deadPConn := tc.pConn
						tc.conn = nil
						tc.pConn = nil
						tc.rebuildAt.Store(time.Now().UnixNano())
						tc.mu.Unlock()
						tc.deferClose(deadConn, deadPConn)
						tc.lockDiag()
						continue
					}
					flog.Infof("auto_rotate: sending but no inbound for %ds — rotating local port now", after)
					// rotateLocalPortIfConfigured takes tc.mu itself —
					// release, rotate, re-take (loop re-locks at top).
					tc.mu.Unlock()
					tc.rotateLocalPortIfConfigured()
					tc.lockDiag()
				} else if tc.pConn != nil {
					// Wire received something — but only count it as
					// RECOVERY if the inbound arrived AFTER our last
					// auto-rotate. The desynced-session zombie echoes
					// KCP ACKs constantly (field run 19:42: 63B replies
					// kept resetting the escalation counter, so the
					// rebuild never fired); those arrive at the OLD
					// rotate timestamp and must not clear the run.
					if r := tc.pConn.LastRecvNano(); r != 0 && r > tc.lastAutoRotateAt.Load() {
						tc.autoRotateRun.Store(0)
					}
				}
			}
			if tc.conn != nil && tc.activeStreams == 0 && !tc.lastIdle.IsZero() && time.Since(tc.lastIdle) > 60*time.Second {
				tc.sendGoodbyeRST()
				deadConn := tc.conn
				deadPConn := tc.pConn
				tc.conn = nil
				tc.pConn = nil
				tc.lastIdle = time.Time{}
				tc.mu.Unlock()
				tc.deferClose(deadConn, deadPConn)
				tc.lockDiag()
			}
			tc.mu.Unlock()
		}
	}
}

type idleTrackedStrm struct {
	tnet.Strm
	tc *timedConn
	// asymmetric liveness: a stream that has data WRITTEN to it but
	// produces NO read within firstReadWindow means the smux session is
	// desynced server-side (field-proven: the fresh server accepts our
	// KCP packets, wire looks alive, but the stream frames vanish into
	// a session whose smux never negotiated). No server packet is
	// needed to detect this — the client decides alone. On trigger:
	// tear the conn down; the SOCKS read errors and retries on the
	// rebuilt session.
	written     atomic.Bool
	firstRead   atomic.Bool
	watchdogRun atomic.Bool
}

const firstReadWindow = 20 * time.Second

func (t *idleTrackedStrm) armWatchdog() {
	if t.watchdogRun.Swap(true) {
		return
	}
	go func() {
		deadline := time.Now().Add(firstReadWindow)
		for time.Now().Before(deadline) {
			if t.firstRead.Load() {
				return
			}
			if !t.written.Load() {
				return // nothing written — no expectation of data
			}
			time.Sleep(500 * time.Millisecond)
		}
		if t.firstRead.Load() || !t.written.Load() {
			return
		}
		flog.Warnf("stream %d: written but no inbound for %v — session desynced, rebuilding conn", t.SID(), firstReadWindow)
		flog.Infof("watchdog teardown: acquiring tc.mu...")
		t.tc.lockDiag()
		deadConn := t.tc.conn
		deadPConn := t.tc.pConn
		t.tc.conn = nil
		t.tc.pConn = nil
		t.tc.rebuildAt.Store(time.Now().UnixNano())
		flog.Infof("watchdog teardown: complete — closing outside lock, next stream open rebuilds")
		t.tc.mu.Unlock()
		t.tc.deferClose(deadConn, deadPConn)
	}()
}

func (t *idleTrackedStrm) Write(b []byte) (int, error) {
	n, err := t.Strm.Write(b)
	if n > 0 {
		t.written.Store(true)
		t.armWatchdog()
	}
	return n, err
}

func (t *idleTrackedStrm) Read(b []byte) (int, error) {
	n, err := t.Strm.Read(b)
	if n > 0 {
		t.firstRead.Store(true)
	}
	return n, err
}

func (t *idleTrackedStrm) Close() error {
	t.tc.lockDiag()
	if t.tc.activeStreams > 0 {
		t.tc.activeStreams--
	}
	if t.tc.activeStreams == 0 {
		t.tc.lastIdle = time.Now()
	}
	t.tc.mu.Unlock()
	return t.Strm.Close()
}
