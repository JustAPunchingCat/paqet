package socket

import (
	"context"
	"encoding/binary"
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

// ErrRSTClosed is a bare TCP RST (no FIN/ACK) — the peer's OS rejecting a
// packet to a CLOSED/BLOCKED destination port. It is distinct from a paqet
// goodbye (FIN, which maps to ErrRST). On the client it means "hop to another
// destination port", NOT "the session is gone": finding a new port and closing
// a session are two separate tasks and must never be coupled.
var ErrRSTClosed = errors.New("connection reset: port closed")

type processedPacket struct {
	data   []byte
	addr   net.Addr
	port   int
	connID uint16
	err    error
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

	plugins *PluginManager
	// clientIPSeen tracks the last inbound-packet time per client IP (unix
	// nano). Updated unconditionally on every received client packet — used
	// by the server's RST gate to distinguish a live session from a stale
	// goodbye-RST straggler after client local-port rotation.
	clientIPSeen sync.Map

	// clientLastSeen maps canonical client identity (IP:connID) -> last
	// inbound time (unix nano). Used by the server's stale-session reaper.
	clientLastSeen sync.Map

	// clientLatestAddr maps canonical identity (IP:connID) -> the client's
	// latest REAL wire *net.UDPAddr. The echo path sends here; the connID
	// port is only a session key, not a mailbox.
	clientLatestAddr sync.Map

	// clientLatestSrvPort maps canonical identity (IP:connID) -> the
	// SERVER-side port (hopped dst) the client last wrote to. Echo replies
	// originate from it; the client drops inbound from any other server port.
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

	// OnRSTClosed fires on a bare RST (closed/blocked destination port). The
	// client hops to another destination port WITHOUT tearing down the session.
	OnRSTClosed func(addr net.Addr)

	// connID is a stable per-connection identifier stamped into every
	// outbound packet by the client and read back by the server. It is
	// the ONLY identity that survives client local-port rotation while
	// remaining distinct across conn:N concurrent connections (which all
	// share one client IP). The server keys sessions and echo state by
	// (IP + connID); the wire source port is neither stable nor unique.
	connID uint16
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

	// Assign a stable per-connection ID (client only). The server reads
	// it from inbound packets; its own connID stays 0 and is never stamped.
	if connCfg.Role == "client" {
		conn.connID = CryptoRandUint16()
		if conn.connID == 0 {
			conn.connID = 1 // 0 reserved as "no conn ID"
		}
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

		// Per-conn identity is (IP + connID), NOT the wire source port
		// (which rotates) and NOT the bare IP (which all conn:N connections
		// share — previously collapsing them into one kcp session, the
		// field-proven "conn:8 merge/lost" bug). The canonical addr's port
		// IS the connID, so it is distinct per conn and stable across
		// local-port rotation.
		udpAddr := pkt.addr.(*net.UDPAddr)
		reportAddr := udpAddr
		if c.cfg.Role == "server" && udpAddr.IP != nil {
			canonical := &net.UDPAddr{IP: udpAddr.IP, Port: int(pkt.connID)}
			key := canonical.String()
			// Echo path: real wire addr + the server port the client is
			// writing to, keyed by canonical identity.
			c.clientLatestAddr.Store(key, udpAddr)
			c.clientLatestSrvPort.Store(key, pkt.port)
			// Reaper liveness.
			c.clientLastSeen.Store(key, time.Now().UnixNano())
			reportAddr = canonical
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
			// Strip the per-conn ID (server only): the client stamped it
			// before obfs, so it arrives here at the front of the unwrapped
			// payload. Carried to ReadFrom for per-conn session/echo keying.
			var connID uint16
			if c.cfg.Role == "server" && len(payload) >= 2 {
				connID = binary.BigEndian.Uint16(payload[:2])
				payload = payload[2:]
			}
			select {
			case c.readQueue <- processedPacket{data: payload, addr: addr, port: job.port, connID: connID}:
			case <-c.ctx.Done():
				return
			}
		}
	}
}

// GetClientLastSeen returns the last time a packet was received from the
// canonical client identity (IP:connID), or the zero time if unknown.
func (c *PacketConn) GetClientLastSeen(addr net.Addr) time.Time {
	if v, ok := c.clientLastSeen.Load(addr.String()); ok {
		return time.Unix(0, v.(int64))
	}
	return time.Time{}
}

// GetClientLastSeenByIP returns the last time ANY packet was received from
// the given client IP, regardless of which client port it came from. Used by
// the server's RST gate: a straggler goodbye-RST from an old client port must
// not tear down a session that is alive on the client's current port.
// GetClientLatestAddr returns the client's most recent real wire addr
// (ip:port) for the given canonical identity (IP:connID), or nil.
func (c *PacketConn) GetClientLatestAddr(addr net.Addr) *net.UDPAddr {
	if addr == nil {
		return nil
	}
	if v, ok := c.clientLatestAddr.Load(addr.String()); ok {
		if a, ok2 := v.(*net.UDPAddr); ok2 {
			return a
		}
	}
	return nil
}

// GetClientLatestSrvPort returns the server port the client is currently
// writing to (its active hop target) for the given canonical identity, or 0.
func (c *PacketConn) GetClientLatestSrvPort(addr net.Addr) int {
	if addr == nil {
		return 0
	}
	if v, ok := c.clientLatestSrvPort.Load(addr.String()); ok {
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
				flog.Debugf("[trace] ErrRST surfaced — dispatching OnRST from %s (handler set: %v)", addr, c.OnRST != nil)
				if c.OnRST != nil && addr != nil {
					c.OnRST(addr)
				}
				continue
			}
			if err == ErrRSTClosed {
				flog.Debugf("[trace] ErrRSTClosed surfaced — dispatching OnRSTClosed from %s (handler set: %v)", addr, c.OnRSTClosed != nil)
				if c.OnRSTClosed != nil && addr != nil {
					c.OnRSTClosed(addr)
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
			// Per-conn state (latest wire addr / server port / liveness) is
			// recorded in ReadFrom where the connID is known — the old
			// wire-port-keyed clientPorts tracking collapsed conn:N and was
			// removed (conn:8 field bug).
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

	// Stamp the per-conn ID (client only) BEFORE obfs wraps — it rides
	// inside the obfuscation layer, so it is hidden from DPI and survives
	// local-port rotation (the ID is a property of the PacketConn, not the
	// rotating source port). 2 bytes: [connID][transport packet].
	if c.cfg.Role == "client" && c.connID != 0 {
		stamped := make([]byte, len(data)+2)
		binary.BigEndian.PutUint16(stamped[:2], c.connID)
		copy(stamped[2:], data)
		data = stamped
	}

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
		// daddr is the kcp session's remote = the CANONICAL addr (IP:connID).
		// Capture it as the identity key BEFORE resolving the mailbox, then
		// resolve the client's LATEST real wire addr + the server port it is
		// writing to (both keyed by that identity).
		canonicalKey := daddr.String()
		if latest := c.GetClientLatestAddr(daddr); latest != nil {
			daddr = latest
			// Also update `addr`: the plugins' return value is reassigned
			// into daddr right after this block and would otherwise clobber
			// the latest-addr rewrite (field-proven).
			addr = latest
		}
		// Source port: the server's CURRENT hopped port — the client only
		// accepts inbound from the server port it is actively writing to.
		if v, ok := c.clientLatestSrvPort.Load(canonicalKey); ok {
			if sp, ok2 := v.(int); ok2 && sp > 0 {
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
	return c.GetClientLatestSrvPort(addr)
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

// ClearClient drops the per-conn state (latest wire addr / server port /
// liveness) for the given canonical identity (IP:connID). Called when the
// server reaps a stale session so a returning client starts fresh.
func (c *PacketConn) ClearClient(addr net.Addr) {
	if addr == nil {
		return
	}
	key := addr.String()
	c.clientLatestAddr.Delete(key)
	c.clientLatestSrvPort.Delete(key)
	c.clientLastSeen.Delete(key)
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

// SetActivityForTest is a test seam: forces lastSend/lastRecv so the
// client's idle/auto-rotate loop can be exercised deterministically in
// unit tests (which cannot open a real capture socket).
func (c *PacketConn) SetActivityForTest(sendNano, recvNano int64) {
	c.lastSend.Store(sendNano)
	c.lastRecv.Store(recvNano)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
