package socket

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/obfs"
	"paqet/internal/pkg/hash"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

var ErrRST = errors.New("connection reset by peer")

type processedPacket struct {
	data []byte
	addr net.Addr
	port int
	err  error
}

type rawJob struct {
	data []byte
	addr net.Addr
	port int
}

type PacketConn struct {
	cfg           *conf.Network
	sendHandle    *SendHandle
	recvHandle    *RecvHandle
	readDeadline  atomic.Value
	writeDeadline atomic.Value

	ctx    context.Context
	cancel context.CancelFunc

	plugins     *PluginManager
	clientPorts sync.Map

	// clientIPSeen tracks the last inbound-packet time per client IP (unix
	// nano). Updated unconditionally on every received client packet — used
	// by the server's RST gate to distinguish a live session from a stale
	// goodbye-RST straggler after client local-port rotation.
	clientIPSeen sync.Map

	// clientCanonical maps client IP string -> canonical *net.UDPAddr used
	// as the kcp-go session key on the server. Client local-port rotation
	// changes the wire source port every hop; kcp-go keys sessions by
	// addr.String(), so reporting the raw rotating port would mint a
	// duplicate session per hop and force supersession to kill the live
	// one (field-proven: latency test died at every hop). Instead the
	// server reports a STABLE canonical addr per client IP: kcp sees one
	// session for the whole client lifetime, streams survive hops, and
	// replies still follow the client's latest port via clientPorts.
	clientCanonical sync.Map

	// clientLatestAddr maps client IP string -> the client's latest REAL
	// wire *net.UDPAddr. The echo path sends here; the canonical port is
	// only a kcp session key.
	clientLatestAddr sync.Map

	// clientLatestSrvPort maps client IP string -> the SERVER-side port
	// (hopped dst) the client last wrote to. Echo replies originate from
	// it; the client drops inbound from any other server port.
	clientLatestSrvPort sync.Map

	lastRecv atomic.Int64
	lastSend atomic.Int64
	lastHop  atomic.Int64

	readQueue  chan processedPacket
	workerChs  []chan rawJob
	workersWg  sync.WaitGroup
	numWorkers int
	closeOnce  sync.Once

	OnRST func(addr net.Addr)
}

// &OpError{Op: "listen", Net: network, Source: nil, Addr: nil, Err: err}
func New(ctx context.Context, cfg *conf.Network) (*PacketConn, error) {
	return NewWithHopping(ctx, cfg, nil, false, nil)
}

func NewWithHopping(ctx context.Context, cfg *conf.Network, hopping *conf.Hopping, writeHopping bool, obfsCfg *conf.Obfuscation, labels ...string) (*PacketConn, error) {
	label := ""
	if len(labels) > 0 {
		label = labels[0]
	}
	connCfg := *cfg
	if connCfg.Port == 0 {
		// Use crypto-secure random port from ephemeral range (32768-65535)
		connCfg.Port = int(RandInRange(32768, 65535))
	}

	sendHandle, err := NewSendHandle(&connCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create send handle on %s: %v", connCfg.Interface.Name, err)
	}
	sendHandle.SetObfuscation(obfsCfg)

	// Only enable hopping on the receive handle if we are NOT hopping on writes (Server mode).
	// Clients (writeHopping=true) must listen on their specific source port, not the destination range.
	var recvHopping *conf.Hopping
	if !writeHopping { // Server mode or client not hopping on writes
		recvHopping = hopping
	}
	recvHandle, err := NewRecvHandle(&connCfg, recvHopping, connCfg.Role)
	if err != nil {
		return nil, fmt.Errorf("failed to create receive handle on %s: %v", connCfg.Interface.Name, err)
	}

	ctx, cancel := context.WithCancel(ctx)
	numWorkers := runtime.NumCPU()
	if numWorkers < 2 {
		numWorkers = 2
	}

	conn := &PacketConn{
		cfg:        &connCfg,
		sendHandle: sendHandle,
		recvHandle: recvHandle,
		ctx:        ctx,
		cancel:     cancel,
		plugins:    NewPluginManager(),
		readQueue:  make(chan processedPacket, 65536),
		workerChs:  make([]chan rawJob, numWorkers),
		numWorkers: numWorkers,
	}

	// Initialize worker channels and start worker goroutines
	conn.workersWg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		conn.workerChs[i] = make(chan rawJob, 4096)
		go conn.workerLoop(conn.workerChs[i])
	}

	// Start background packet reader
	go conn.backgroundReader()

	// Initialize plugins
	useObfs := false
	if obfsCfg != nil {
		useObfs = obfsCfg.UseTLS || obfsCfg.Padding.Enabled
	}

	if useObfs && connCfg.Transport != nil {
		var keyStr string
		if connCfg.Transport.KCP != nil && connCfg.Transport.KCP.Key != "" {
			keyStr = connCfg.Transport.KCP.Key
		} else if connCfg.Transport.QUIC != nil && connCfg.Transport.QUIC.Key != "" {
			keyStr = connCfg.Transport.QUIC.Key
		} else if connCfg.Transport.UDP != nil && connCfg.Transport.UDP.Key != "" {
			keyStr = connCfg.Transport.UDP.Key
		}
		key := []byte(keyStr)
		if o, err := obfs.New(obfsCfg, key); err == nil {
			conn.plugins.Add(NewObfuscationPlugin(o))
			flog.Debugf("Obfuscation initialized. Key prefix: %x...", key[:min(len(key), 4)])
		} else {
			flog.Warnf("failed to initialize obfuscation (check key length): %v", err)
		}
	}

	if hopping != nil && hopping.IsEnabled() {
		hp, err := NewHoppingPlugin(hopping, writeHopping, label)
		if err != nil {
			return nil, fmt.Errorf("invalid hopping configuration: %w", err)
		}
		hp.SetSendHandle(sendHandle)
		conn.plugins.Add(hp)
	}

	return conn, nil
}

func (c *PacketConn) ReadFrom(data []byte) (n int, addr net.Addr, err error) {
	var timer *time.Timer
	var deadline <-chan time.Time
	if d, ok := c.readDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer = time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadline = timer.C
	}

	select {
	case <-c.ctx.Done():
		return 0, nil, c.ctx.Err()
	case <-deadline:
		return 0, nil, os.ErrDeadlineExceeded
	case pkt, ok := <-c.readQueue:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		if pkt.err != nil {
			return 0, nil, pkt.err
		}

		// Record the client's REAL wire addr under its canonical identity —
		// the echo path sends here. One source of truth: the last place the
		// client actually spoke from. (The kcp session's remote is the
		// stable canonical addr; the client's wire port rotates.)
		udpAddr := pkt.addr.(*net.UDPAddr)
		if c.cfg.Role == "server" && udpAddr.IP != nil {
			c.clientLatestAddr.Store(udpAddr.IP.String(), udpAddr)
			// Record the SERVER port the client is currently writing to
			// (its current hop target) — echo replies must originate from
			// it or the client's receive path drops them.
			c.clientLatestSrvPort.Store(udpAddr.IP.String(), pkt.port)
		}

		// SERVER ROLE: report a STABLE canonical client addr to the
		// transport above (kcp-go keys sessions by addr.String()). Without
		// this, every client port rotation mints a duplicate session and
		// the live one gets torn down — killing all open streams.
		reportAddr := udpAddr
		if c.cfg.Role == "server" && udpAddr.IP != nil {
			key := udpAddr.IP.String()
			canonical := 45 * time.Second
			if val, ok := c.clientCanonical.Load(key); ok {
				reportAddr = &net.UDPAddr{IP: udpAddr.IP, Port: val.(int)}
			} else {
				c.clientCanonical.Store(key, udpAddr.Port)
			}
			_ = canonical
		}

		n = copy(data, pkt.data)
		return n, reportAddr, nil
	}
}

func (c *PacketConn) workerLoop(ch chan rawJob) {
	defer c.workersWg.Done()
	for {
		select {
		case <-c.ctx.Done():
			return
		case job, ok := <-ch:
			if !ok {
				return
			}
			payload, addr, err := c.plugins.OnRead(job.data, job.addr)
			if err != nil {
				// Drop invalid packet (e.g. obfuscation mismatch) — but
				// NEVER silently: this is the only silent drop in the recv
				// pipeline and it has hidden field bugs before.
				flog.Debugf("[trace] OnRead drop from %s: %v", job.addr, err)
				continue
			}
			select {
			case c.readQueue <- processedPacket{data: payload, addr: addr, port: job.port}:
			case <-c.ctx.Done():
				return
			}
		}
	}
}

type clientPortEntry struct {
	port       int
	switchTime int64
	lastSeen   int64
}

func (c *PacketConn) updateClientPort(udpAddr *net.UDPAddr, dstPort int) {
	key := hash.IPAddr(udpAddr.IP, uint16(udpAddr.Port))
	now := time.Now().UnixNano()

	if val, ok := c.clientPorts.Load(key); ok {
		entry := val.(*clientPortEntry)
		entry.lastSeen = now
		if entry.port != dstPort {
			// If the port changed recently (e.g. less than 1.5 seconds ago),
			// this is almost certainly a delayed packet from the old port.
			// Do not bounce back to the old port.
			if now-entry.switchTime < int64(1500*time.Millisecond) {
				return
			}
			c.clientPorts.Store(key, &clientPortEntry{port: dstPort, switchTime: now, lastSeen: now})
		}
	} else {
		c.clientPorts.Store(key, &clientPortEntry{port: dstPort, switchTime: now, lastSeen: now})
	}
}

// GetClientLastSeen returns the last time a packet was received from addr,
// or the zero time if the client is unknown.
func (c *PacketConn) GetClientLastSeen(addr net.Addr) time.Time {
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		key := hash.IPAddr(udpAddr.IP, uint16(udpAddr.Port))
		if val, ok := c.clientPorts.Load(key); ok {
			entry := val.(*clientPortEntry)
			return time.Unix(0, entry.lastSeen)
		}
	}
	return time.Time{}
}

// GetClientLastSeenByIP returns the last time ANY packet was received from
// the given client IP, regardless of which client port it came from. Used by
// the server's RST gate: a straggler goodbye-RST from an old client port must
// not tear down a session that is alive on the client's current port.
// GetClientLatestAddr returns the client's most recent real wire addr
// (ip:port) for the given IP, or nil. The echo path uses the same map.
func (c *PacketConn) GetClientLatestAddr(ip net.IP) *net.UDPAddr {
	if v, ok := c.clientLatestAddr.Load(ip.String()); ok {
		if a, ok2 := v.(*net.UDPAddr); ok2 {
			return a
		}
	}
	return nil
}

// GetClientLatestSrvPort returns the server port the client is currently
// writing to (its active hop target), or 0.
func (c *PacketConn) GetClientLatestSrvPort(ip net.IP) int {
	if v, ok := c.clientLatestSrvPort.Load(ip.String()); ok {
		if p, ok2 := v.(int); ok2 {
			return p
		}
	}
	return 0
}

func (c *PacketConn) GetClientLastSeenByIP(ip net.IP) time.Time {
	if v, ok := c.clientIPSeen.Load(ip.String()); ok {
		return time.Unix(0, v.(int64))
	}
	return time.Time{}
}

// markClientSeen records an inbound packet from a client IP unconditionally
// (all packet types, all ports) for the RST gate.
func (c *PacketConn) markClientSeen(udpAddr *net.UDPAddr) {
	if udpAddr == nil || udpAddr.IP == nil {
		return
	}
	c.clientIPSeen.Store(udpAddr.IP.String(), time.Now().UnixNano())
}

func (c *PacketConn) backgroundReader() {
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		payload, addr, dstPort, isForward, err := c.recvHandle.Read()
		if err != nil {
			if err == ErrRST {
				if c.OnRST != nil && addr != nil {
					c.OnRST(addr)
				}
				continue
			}
			if c.ctx.Err() == nil {
				select {
				case c.readQueue <- processedPacket{err: err}:
				case <-c.ctx.Done():
				}
			}
			return
		}
		if isForward && addr != nil && dstPort > 0 {
			if udpAddr, ok := addr.(*net.UDPAddr); ok {
				c.updateClientPort(udpAddr, dstPort)
			}
		}
		// Record client liveness for every inbound packet (RST gate uses
		// this to ignore stale goodbye-RSTs from old client ports).
		if udpAddr, ok := addr.(*net.UDPAddr); ok {
			c.markClientSeen(udpAddr)
		}

		if payload == nil {
			continue
		}
		c.lastRecv.Store(time.Now().UnixNano())

		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}

		// Consistent Hashing / Flow Pinning based on client IP & Port
		h := hash.IPAddr(udpAddr.IP, uint16(udpAddr.Port))
		workerID := int(h % uint64(c.numWorkers))

		c.lastSend.Store(time.Now().UnixNano())

		select {
		case c.workerChs[workerID] <- rawJob{data: payload, addr: addr, port: dstPort}:
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *PacketConn) WriteTo(data []byte, addr net.Addr) (n int, err error) {
	var timer *time.Timer
	var deadline <-chan time.Time
	if d, ok := c.writeDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer = time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadline = timer.C
	}

	select {
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	case <-deadline:
		return 0, os.ErrDeadlineExceeded
	default:
	}

	daddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, net.InvalidAddrError("invalid address")
	}

	srcPort := c.cfg.Port

	// Apply plugins (Hop Port, Obfuscate)
	data, addr, err = c.plugins.OnWrite(data, addr)
	if err != nil {
		return 0, err
	}

	// Server Echo logic (SERVER ROLE ONLY): reply from the port the client
	// last contacted. On the client this map would pin sends to a STALE local
	// port after a local-port rotation — the exact port rotation is meant to
	// retire — so it must never apply client-side.
	if c.cfg.Role == "server" {
		// The kcp session's remote is the CANONICAL client addr (stable
		// across the client's port rotations). Resolve the client's LATEST
		// real wire addr and send there — the canonical port is a session
		// key, not a mailbox.
		if val, ok := c.clientLatestAddr.Load(daddr.IP.String()); ok {
			latest := val.(*net.UDPAddr)
			daddr = latest
			// Also update `addr`: the plugins' return value is reassigned
			// into daddr right after this block and would otherwise
			// clobber the latest-addr rewrite (field-proven).
			addr = latest
		}
		// Source port: the server's CURRENT hopped port — the client only
		// accepts inbound from the server port it is actively writing to.
		// The previous clientPorts-based srcPort logic carried exactly this
		// and must survive the latest-addr rewrite.
		if val, ok := c.clientLatestSrvPort.Load(daddr.IP.String()); ok {
			if sp, ok2 := val.(int); ok2 && sp > 0 {
				srcPort = sp
			}
		}
		flog.Tracef("echo reply: to client %s from server port %d", daddr, srcPort)
	} else if c.cfg.Role == "client" && len(data) > 0 {
		// DIAGNOSTIC: prove which local port every client write actually
		// carries. A post-rotation write still on the old port shows up here
		// as srcPort != the freshly rotated one.
		flog.Tracef("writeto role=client srcPort=%d len=%d dst=%s", srcPort, len(data), addr)
	}

	// Cast again because plugins might return a generic net.Addr
	daddr, _ = addr.(*net.UDPAddr)
	err = c.sendHandle.Write(data, daddr, srcPort)
	if err != nil {
		return 0, err
	}

	// Outbound timestamp: lastSend must reflect ACTUAL sends. It used to
	// live in backgroundReader (inbound), which made any send/recv
	// liveness comparison meaningless — both counters moved on received
	// packets only.
	c.lastSend.Store(time.Now().UnixNano())

	return len(data), nil
}

// ClearRemoteSync is retained for API compatibility. The fake-TCP
// layer is stateless (synthetic seq/ack); there is nothing to clear.
func (c *PacketConn) ClearRemoteSync() {
}

// ReArmHandshake is retained for API compatibility. The fake-TCP
// layer is stateless; no handshake state to re-arm.
func (c *PacketConn) ReArmHandshake() {
}

// RotateLocalPort rebinds the client's local source port to a fresh random
// ephemeral port (same port family as NewWithHopping's initial bind). This
// creates a brand-new NAT mapping on the path — used to escape middleboxes
// that throttle/blackhole the return path of a matured mapping.
//
// Returns the new port. Supported only on sources that can re-target their
// capture (eBPF, which registers ports dynamically); pcap/afpacket capture is
// bound to a static BPF filter on the original port and returns an error —
// callers must treat rotation as unavailable and keep hopping server ports.
func (c *PacketConn) RotateLocalPort() (int, error) {
	if c.sendHandle == nil {
		return 0, fmt.Errorf("no send handle")
	}
	if c.recvHandle == nil || c.recvHandle.source == nil {
		return 0, fmt.Errorf("no capture source")
	}
	newPort := int(RandInRange(32768, 65535))

	// Re-target capture FIRST: it is the step that can fail (BPF map, source
	// capabilities). If it fails, nothing has been touched yet — the send
	// handle stays on the old port and the tunnel keeps its current flow
	// state. The previous order (send handle first, capture second, silent
	// rollback on failure) left the two halves split when the rollback
	// itself failed: SYN went out on the new port while data kept using the
	// old one, and the rollback's key-rewrite minted a fresh random seq
	// universe mid-stream (the split-brain seq jump seen in the field).
	flog.Debugf("rotate: step 1 — capture rebind to %d starting", newPort)
	if err := c.recvHandle.source.RebindPort(newPort, 2*time.Second); err != nil {
		return 0, fmt.Errorf("capture rebind to port %d failed: %w", newPort, err)
	}
	flog.Debugf("rotate: step 2 — capture on %d, rebinding send handle", newPort)
	if err := c.sendHandle.RebindSource(newPort); err != nil {
		// Capture already listens on newPort; roll ONLY the capture back and
		// report loudly. Never leave the halves split.
		if rbErr := c.recvHandle.source.RebindPort(int(c.cfg.Port), 2*time.Second); rbErr != nil {
			flog.Errorf("rotation capture rollback failed: %v (capture on %d, send handle on %d — MISMATCHED)", rbErr, newPort, c.cfg.Port)
		}
		return 0, fmt.Errorf("capture rebind to port %d failed: %w", newPort, err)
	}
	flog.Tracef("rotate: local port %d -> %d (cfg.Port and sendHandle in sync)", c.cfg.Port, newPort)
	c.cfg.Port = newPort
	return newPort, nil
}

// SetOnHop registers a callback fired after every client-side hop (interval
// or forced). Used by the client to rotate its local source port.
func (c *PacketConn) SetOnHop(fn func(hopCount uint32)) {
	if c.plugins == nil {
		return
	}
	for _, pl := range c.plugins.plugins {
		if hp, ok := pl.(*HoppingPlugin); ok {
			hp.OnHop = fn
			return
		}
	}
}

func (c *PacketConn) ForceHop() {
	if c.plugins != nil {
		for _, pl := range c.plugins.plugins {
			if hp, ok := pl.(*HoppingPlugin); ok {
				hp.ForceHop()
			}
		}
	}
}

func (c *PacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.cancel()
		c.plugins.Close()

		if c.sendHandle != nil {
			c.sendHandle.Close()
		}
		if c.recvHandle != nil {
			c.recvHandle.Close()
		}
	})
	return nil
}

func (c *PacketConn) LocalAddr() net.Addr {
	var ip net.IP
	if c.cfg.IPv4.Addr != nil {
		ip = c.cfg.IPv4.Addr.IP
	} else if c.cfg.IPv6.Addr != nil {
		ip = c.cfg.IPv6.Addr.IP
	}
	if ip == nil {
		ip = net.IPv4(0, 0, 0, 0)
	}
	return &net.UDPAddr{
		IP:   ip,
		Port: c.cfg.Port,
	}
}

func (c *PacketConn) GetClientPort(addr net.Addr) int {
	key := hash.IPAddr(addr.(*net.UDPAddr).IP, uint16(addr.(*net.UDPAddr).Port))
	if val, ok := c.clientPorts.Load(key); ok {
		return val.(*clientPortEntry).port
	}
	return 0
}

func (c *PacketConn) SetDeadline(t time.Time) error {
	c.readDeadline.Store(t)
	c.writeDeadline.Store(t)
	return nil
}

func (c *PacketConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Store(t)
	return nil
}

func (c *PacketConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Store(t)
	return nil
}

func (c *PacketConn) SetReadBuffer(bytes int) error {
	// Buffers are managed by the underlying driver (pcap/afpacket/ebpf) configuration
	return nil
}

func (c *PacketConn) SetWriteBuffer(bytes int) error {
	// Buffers are managed by the underlying driver (pcap/afpacket/ebpf) configuration
	return nil
}

func (c *PacketConn) SetDSCP(dscp int) error {
	return nil
}

func (c *PacketConn) SetClientTCPF(addr net.Addr, f []conf.TCPF) {
	c.sendHandle.setClientTCPF(addr, f)
}

// IsFlowWarmed is retained for API compatibility. With the stateless
// synthetic seq/ack every flow is always "warm".
func (c *PacketConn) IsFlowWarmed(dstIP net.IP, dstPort uint16) bool {
	return true
}
func (c *PacketConn) PrewarmFlow(dstIP net.IP, dstPort uint16) {
	if c.sendHandle != nil {
		c.sendHandle.PrewarmFlow(dstIP, dstPort)
	}
}

// SendRST emits a goodbye RST on this connection's source port so the remote
// tears down the associated flow immediately. Safe no-op when no send handle
// is configured.
// SendRSTFrom sends the goodbye from an explicit client source port —
// used to tear down the server session orphaned by a local-port rotation.
func (c *PacketConn) SendRSTFrom(remoteIP net.IP, remotePort int, srcPort int) error {
	if c.sendHandle != nil {
		if remotePort <= 0 {
			return fmt.Errorf("no active server port for goodbye")
		}
		return c.sendHandle.SendRSTFrom(remoteIP, remotePort, srcPort)
	}
	return fmt.Errorf("no send handle")
}

func (c *PacketConn) SendRST(remoteIP net.IP, remotePort int) error {
	if c.sendHandle != nil {
		port := remotePort
		if c.cfg.Role == "client" {
			// Prefer the most recent port we actually wrote to: only that
			// flow is primed through the ISP NAT, so the goodbye FIN reaches
			// the server and the orphan session is torn down. A freshly
			// hopped (but never used) port is an un-primed flow — the FIN
			// gets dropped, the server session lives on and retransmits
			// forever (stale-tunnel noise).
			if hp := c.GetLastActivePort(); hp > 0 {
				port = hp
			} else if hp := c.GetCurrentPort(); hp > 0 {
				port = hp
			}
		}
		return c.sendHandle.SendRST(remoteIP, port)
	}
	return nil
}

// GetLastActivePort returns the most recent port this connection actually
// wrote to, or 0 if nothing has been sent yet. Client role only.
// LocalSrcPort returns the client's current local source port (the port
// KCP writes go out from). Distinct from GetCurrentPort, which is the
// hopped DESTINATION port.
func (c *PacketConn) LocalSrcPort() int {
	if c.sendHandle != nil {
		return c.sendHandle.SrcPort()
	}
	return 0
}

// canonicalPortFor returns the canonical port recorded for this client
// addr's IP (the addr itself if unknown). Used to key updateClientPort by
// the canonical client identity so the echo path always resolves to the
// client's LATEST wire port.
func (c *PacketConn) canonicalPortFor(addr *net.UDPAddr) int {
	if addr == nil || addr.IP == nil {
		return addr.Port
	}
	if val, ok := c.clientCanonical.Load(addr.IP.String()); ok {
		return val.(int)
	}
	return addr.Port
}

// ClearClientCanonical drops the stable-addr mapping for a client IP —
// called when the server reaps a stale session so a returning client
// starts a fresh session instead of feeding a dead one.
func (c *PacketConn) ClearClientCanonical(ip net.IP) {
	if ip != nil {
		c.clientCanonical.Delete(ip.String())
		c.clientLatestAddr.Delete(ip.String())
		c.clientLatestSrvPort.Delete(ip.String())
	}
}

func (c *PacketConn) GetLastActivePort() int {
	if c.plugins != nil {
		for _, pl := range c.plugins.plugins {
			if hp, ok := pl.(*HoppingPlugin); ok {
				if port := hp.LastActivePort(); port > 0 {
					return int(port)
				}
			}
		}
	}
	return 0
}

func (c *PacketConn) GetCurrentPort() int {
	if c.plugins != nil {
		for _, pl := range c.plugins.plugins {
			if hp, ok := pl.(*HoppingPlugin); ok {
				if port := hp.currentPort.Load(); port > 0 {
					return int(port)
				}
			}
		}
	}
	return c.cfg.Port
}

// LastRecvNano returns the Unix-nano timestamp of the last packet received
// from the server (0 = nothing received yet).
func (c *PacketConn) LastRecvNano() int64 {
	return c.lastRecv.Load()
}

// LastSendNano returns the Unix-nano timestamp of the last packet written
// to the server (0 = nothing sent yet).
func (c *PacketConn) LastSendNano() int64 {
	return c.lastSend.Load()
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
