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
}

func newTimedConn(ctx context.Context, rootCfg *conf.Conf, srvCfg *conf.ServerConfig) (*timedConn, error) {
	tc := timedConn{
		ctx:      ctx,
		rootCfg:  rootCfg,
		srvCfg:   srvCfg,
		lastIdle: time.Now(),
	}

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
	tc.pConn = pConn
	tc.lastPort = pConn.GetCurrentPort()
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

	// Fire the raw socket TCP SYN to warm the connection state for DPI/Netfilter.
	// Eager mode only: the SYN is fired now (non-blocking 0-RTT) so the flow is
	// established before the first data. In lazy mode the SYN is fired on first
	// data instead (see SendHandle.Write).
	if tc.srvCfg.Handshake.IsEnabled() && !tc.srvCfg.Handshake.IsLazy() {
		pConn.PrewarmFlow(remoteAddr.IP, uint16(remoteAddr.Port))
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
	strm, err := conn.OpenStrm()
	if err != nil {
		return err
	}
	defer strm.Close()

	p := protocol.Proto{Type: protocol.PTCPF, TCPF: tc.rootCfg.Network.TCP.RF}
	err = p.Write(strm)
	if err != nil {
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
func (tc *timedConn) OnRST(addr net.Addr) {
	const RST_TIMEOUT_INTERVAL = 3 * time.Second
	last := tc.lastRSTHop.Load()
	now := time.Now().UnixNano()
	if last != 0 && now-last < int64(RST_TIMEOUT_INTERVAL) {
		return
	}
	if !tc.lastRSTHop.CompareAndSwap(last, now) {
		return
	}
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || udpAddr.IP == nil {
		return
	}
	if tc.remoteAddr == nil || tc.remoteAddr.IP == nil || !udpAddr.IP.Equal(tc.remoteAddr.IP) {
		// RST from some other server (multi-server config) — ignore.
		return
	}
	flog.Warnf("RST from server %s — forcing port hop to escape the blocked tuple", udpAddr.String())
	if tc.pConn != nil {
		tc.pConn.ForceHop()
	}
}

func (tc *timedConn) reconnect() {
	tc.mu.Lock()
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
	tc.mu.Lock()
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

func (tc *timedConn) openAndSendProto(p *protocol.Proto) (tnet.Strm, error) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	for attempt := 0; attempt < 2; attempt++ {
		// 1. If connection is nil, create it
		if tc.conn == nil {
			var err error
			tc.conn, err = tc.createConn()
			if err != nil {
				return nil, err
			}
		}

		// 2. Open stream
		strm, err := tc.conn.OpenStrm()
		if err != nil {
			// smux session is dead (server restarted or KCP DeadLink)
			tc.conn.Close()
			if tc.pConn != nil {
				tc.pConn.Close()
			}
			tc.conn = nil
			tc.pConn = nil
			continue
		}

		// 3. Send protocol header
		strm.SetWriteDeadline(time.Now().Add(60 * time.Second))
		err = p.Write(strm)
		strm.SetWriteDeadline(time.Time{})
		if err != nil {
			strm.Close()
			tc.conn.Close()
			if tc.pConn != nil {
				tc.pConn.Close()
			}
			tc.conn = nil
			tc.pConn = nil
			continue
		}

		// Stream is ready. KCP ARQ guarantees delivery; DPI warm-up is handled by
		// PrewarmFlow (sends SYN). If the DPI drops early KCP packets, KCP retransmits
		// naturally within ~400ms. Server restart is detected via RST in recv_handle.go.
		// NOTE: tc.mu is already held (locked at function entry, deferred unlock) — do not re-lock.
		tc.activeStreams++
		tc.lastIdle = time.Time{}

		return &idleTrackedStrm{Strm: strm, tc: tc}, nil
	}

	return nil, fmt.Errorf("failed to open stream after reconnection attempts")
}

func (tc *timedConn) idleCheckLoop() {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-tc.ctx.Done():
			return
		case <-ticker.C:
			tc.mu.Lock()
			if tc.conn != nil && tc.activeStreams == 0 && !tc.lastIdle.IsZero() && time.Since(tc.lastIdle) > 60*time.Second {
				tc.sendGoodbyeRST()
				tc.conn.Close()
				if tc.pConn != nil {
					tc.pConn.Close()
				}
				tc.conn = nil
				tc.pConn = nil
				tc.lastIdle = time.Time{}
			}
			tc.mu.Unlock()
		}
	}
}

type idleTrackedStrm struct {
	tnet.Strm
	tc *timedConn
}

func (t *idleTrackedStrm) Close() error {
	t.tc.mu.Lock()
	if t.tc.activeStreams > 0 {
		t.tc.activeStreams--
	}
	if t.tc.activeStreams == 0 {
		t.tc.lastIdle = time.Now()
	}
	t.tc.mu.Unlock()
	return t.Strm.Close()
}
