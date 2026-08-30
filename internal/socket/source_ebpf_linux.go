//go:build linux && !noebpf

package socket

import (
	"encoding/binary"
	"fmt"
	"net"
	"paqet/internal/conf"
	"paqet/internal/flog"
	ebpf_gen "paqet/internal/socket/ebpf"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// ipv4LPMKey mirrors the C struct ipv4_lpm_key (u32 prefixlen + 4-byte address).
type ipv4LPMKey struct {
	PrefixLen uint32
	Data      [4]byte
}

// ipv6LPMKey mirrors the C struct ipv6_lpm_key (u32 prefixlen + 16-byte address
// + 4 bytes padding, so the key size is a multiple of 8 for older kernels).
type ipv6LPMKey struct {
	PrefixLen uint32
	Data      [16]byte
	Pad       [4]byte
}

// Global manager to ensure only one XDP program runs per interface
var (
	managerMu sync.Mutex
	managers  = make(map[int]*ebpfManager)
)

type ebpfManager struct {
	ifaceIndex int
	refCount   int
	mu         sync.RWMutex

	// BPF resources
	objs   interface{} // Keep reference to prevent GC
	link   link.Link
	reader PacketReader

	// Maps
	portsMap     *ebpf.Map
	ip4Map       *ebpf.Map
	ip6Map       *ebpf.Map
	clientIP4Map *ebpf.Map
	clientIP6Map *ebpf.Map

	// Dispatcher
	listeners map[uint16]chan []byte
	done      chan struct{}
}

type PacketReader interface {
	Read() (PacketRecord, error)
	Close() error
}

type PacketRecord struct {
	RawSample []byte
}

// Wrapper for optimal ringbuf.Reader (No header)
type ringbufReader struct {
	*ringbuf.Reader
}

func (r *ringbufReader) Read() (PacketRecord, error) {
	rec, err := r.Reader.Read()
	return PacketRecord{RawSample: rec.RawSample}, err
}

// Wrapper for compat ringbuf.Reader (Has 4-byte length header)
type ringbufCompatReader struct {
	*ringbuf.Reader
}

func (r *ringbufCompatReader) Read() (PacketRecord, error) {
	rec, err := r.Reader.Read()
	if err != nil {
		return PacketRecord{}, err
	}
	// Ringbuf workaround uses a 4-byte length header
	if len(rec.RawSample) < 4 {
		return PacketRecord{RawSample: rec.RawSample}, nil // Should not happen
	}
	dataLen := binary.LittleEndian.Uint32(rec.RawSample[:4])
	return PacketRecord{RawSample: rec.RawSample[4 : 4+dataLen]}, nil
}

// Wrapper for perf.Reader to satisfy PacketReader
type perfReader struct {
	*perf.Reader
}

func (r *perfReader) Read() (PacketRecord, error) {
	rec, err := r.Reader.Read()
	return PacketRecord{RawSample: rec.RawSample}, err
}

type sharedEBPFSource struct {
	mgr     *ebpfManager
	ch      chan []byte
	done    chan struct{}
	portsMu sync.Mutex
	ports   []uint16 // Track registered ports to remove on close
	ipv4    net.IP
	ipv6    net.IP
}

func newEBPFSource(cfg *conf.Network, hopping *conf.Hopping) (PacketSource, error) {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock limit: %w", err)
	}

	managerMu.Lock()
	defer managerMu.Unlock()

	idx := cfg.Interface.Index
	mgr, ok := managers[idx]
	if !ok {
		// Initialize new manager for this interface
		var err error
		mgr, err = newManager(cfg)
		if err != nil {
			return nil, err
		}
		managers[idx] = mgr
	}

	mgr.refCount++

	// Create the source
	s := &sharedEBPFSource{
		mgr:  mgr,
		ch:   make(chan []byte, 65536),
		done: make(chan struct{}),
	}

	// Register IP(s): for the client, register the remote SERVER IP(s) so the XDP
	// filter drops all packets to/from the server (source OR dest) regardless of
	// port, instead of leaking stale-port packets to the kernel (which emits an
	// RST and tears the tunnel down). For the server, register its own IP.
	if cfg.Role == "client" {
		for _, sip := range cfg.ServerIPs {
			if sip == nil {
				continue
			}
			if v4 := sip.To4(); v4 != nil {
				if s.ipv4 == nil {
					s.ipv4 = v4
				}
				if err := mgr.addIPv4(v4); err != nil {
					s.Close()
					return nil, err
				}
			} else {
				if s.ipv6 == nil {
					s.ipv6 = sip
				}
				if err := mgr.addIPv6(sip); err != nil {
					s.Close()
					return nil, err
				}
			}
		}
		if len(cfg.ServerIPs) == 0 {
			flog.Warnf("eBPF client has no server IPs registered; XDP filter will not capture tunnel traffic")
		}
	} else {
		if cfg.IPv4.Addr != nil {
			s.ipv4 = cfg.IPv4.Addr.IP
			if err := mgr.addIPv4(s.ipv4); err != nil {
				s.Close()
				return nil, err
			}
		}
		if cfg.IPv6.Addr != nil {
			s.ipv6 = cfg.IPv6.Addr.IP
			if err := mgr.addIPv6(s.ipv6); err != nil {
				s.Close()
				return nil, err
			}
		}
	}

	// Register Ports (Main port + Hopping ranges on server)
	ports := []uint16{uint16(cfg.Port)}
	if cfg.Role == "server" && hopping != nil && hopping.IsEnabled() {
		ranges, err := hopping.GetRanges()
		if err == nil {
			for _, r := range ranges {
				for p := r.Min; p <= r.Max; p++ {
					ports = append(ports, uint16(p))
				}
			}
		}
	}

	if err := mgr.registerPorts(ports, s.ch); err != nil {
		s.Close()
		return nil, err
	}
	if len(ports) > 10 {
		flog.Debugf("eBPF registered ports: %v... (total %d) for IP: %s", ports[:10], len(ports), s.ipv4)
	} else {
		flog.Debugf("eBPF registered ports: %v for IP: %s", ports, s.ipv4)
	}
	s.ports = ports

	return s, nil
}

func (s *sharedEBPFSource) ReadPacketData() ([]byte, error) {
	select {
	case data, ok := <-s.ch:
		if !ok {
			return nil, fmt.Errorf("ebpf source closed")
		}
		return data, nil
	case <-s.done:
		return nil, fmt.Errorf("ebpf source closed")
	}
}

// RebindPort atomically swaps the captured local port: registers newPort and
// unregisters the old one. Used by client local-port rotation — the XDP
// program starts accepting server->client traffic to the new port on the next
// received packet; the old port is kept registered for a grace period so
// in-flight replies from the previous mapping are not dropped mid-switch.
func (s *sharedEBPFSource) RebindPort(newPort int, gracePeriod time.Duration) error {
	if newPort <= 0 || newPort > 65535 {
		return fmt.Errorf("invalid port %d", newPort)
	}
	// NOTE: do NOT hold m.mu across this call — registerPorts takes m.mu
	// itself and sync.Mutex is not reentrant. Holding it here self-deadlocks
	// the rotation goroutine (field-proven: 'hop dispatched' logged, then
	// nothing; dispatch frozen; subsequent hops stop).
	flog.Debugf("rebind: entered for port %d (acquiring m.mu)", newPort)
	oldPorts := s.ports
	if err := s.mgr.registerPorts([]uint16{uint16(newPort)}, s.ch); err != nil {
		return fmt.Errorf("failed to register port %d: %w", newPort, err)
	}

	flog.Debugf("rebind: registerPorts done, updating tracked ports")
	s.portsMu.Lock()
	s.ports = append(s.ports, uint16(newPort))
	s.portsMu.Unlock()

	// Release the old registration after the grace period. The lock copy
	// avoids racing with a second rebind or Close.
	go func(old []uint16) {
		time.Sleep(gracePeriod)
		s.mgr.unregisterPorts(old)
	}(oldPorts)

	flog.Debugf("ebpf capture rebound to local port %d (old ports held %v for %v)", newPort, oldPorts, gracePeriod)
	return nil
}

func (s *sharedEBPFSource) Close() {
	managerMu.Lock()
	defer managerMu.Unlock()

	s.mgr.unregisterPorts(s.ports)
	// Note: We don't remove IPs because other clients might share them.

	// Signal closure via `done` rather than closing `ch`: dispatch() may still
	// hold a reference to `ch` (read under RLock) and send on it, which would
	// panic on a closed channel. Leaving `ch` open lets any in-flight send fall
	// through the non-blocking default case harmlessly.
	close(s.done)

	s.mgr.refCount--
	// Intentionally do NOT tear down the manager when refCount drops to zero.
	// The XDP program must stay attached for the lifetime of the process so a
	// reconnect (new source) can reuse the already-loaded program instead of
	// triggering an expensive unload/reload cycle — which re-runs the optimal
	// verifier failure and the compat fallback on every rotation. The kernel
	// detaches the program automatically on process exit.
}

// --- Manager Implementation ---

func newManager(cfg *conf.Network) (*ebpfManager, error) {
	// 1. Try Optimal Ringbuf (Modern kernels 5.8+)
	mgr, err := loadRingbuf(cfg)
	if err == nil {
		flog.Infof("eBPF Ringbuf loader successful (modern path)")
		return mgr, nil
	}
	flog.Debugf("eBPF Ringbuf (optimal) failed: %v. Trying compatibility mode...", err)

	// 2. Try Compat Ringbuf (Kernels ~5.10 with strict verifier)
	mgr, err = loadRingbufCompat(cfg)
	if err == nil {
		flog.Infof("eBPF Ringbuf loader successful (compatibility path)")
		return mgr, nil
	}
	flog.Warnf("eBPF Ringbuf failed: %v. Falling back to Perf Event Array...", err)

	// 3. Fallback to Perf (Old kernels)
	return loadPerf(cfg)
}

// Helper to initialize common manager fields
func initManager(cfg *conf.Network, objs interface{}, link link.Link, rd PacketReader, ports, ip4, ip6, clientIP4, clientIP6, configMap *ebpf.Map) *ebpfManager {
	if configMap != nil {
		zero := uint32(0)
		val := uint8(0)
		if cfg.Role == "client" {
			val = 1
		}
		_ = configMap.Put(&zero, &val)
	}

	mgr := &ebpfManager{
		ifaceIndex:   cfg.Interface.Index,
		refCount:     0, // Will be incremented by caller
		objs:         objs,
		link:         link,
		reader:       rd,
		portsMap:     ports,
		ip4Map:       ip4,
		ip6Map:       ip6,
		clientIP4Map: clientIP4,
		clientIP6Map: clientIP6,
		listeners:    make(map[uint16]chan []byte),
		done:         make(chan struct{}),
	}

	mgr.configureClientAllowlist(cfg, configMap)

	go mgr.dispatch()
	go mgr.dumpXDPStats()
	return mgr
}

// dumpXDPStats logs the XDP per-branch counters every 15s. Field runs
// showed return-path packets vanishing after client port rotation; these
// counters prove whether frames reach the NIC and which XDP branch takes
// them: 0=pass-not-ours 1=consumed(ringbuf) 2=ringbuf-full-passed
// 3=dropped 4=parse-fail. Access by name so it works regardless of when
// the generated object structs were last regenerated.
func (m *ebpfManager) dumpXDPStats() {
	t := time.NewTicker(15 * time.Second)
	defer t.Stop()

	var stats *ebpf.Map
	// bpf2go typed structs embed ebpf.Collection; Maps is accessed via the
	// embedded collection's map store, by name — no regen dependency.
	switch o := m.objs.(type) {
	case *ebpf_gen.BpfRingbufCompatObjects:
		stats = o.Maps["xdp_stats"]
	case *ebpf_gen.BpfRingbufObjects:
		stats = o.Maps["xdp_stats"]
	}
	if stats == nil {
		flog.Debugf("[trace] xdp stats map unavailable")
		return
	}
	names := []string{"pass-not-ours", "consumed", "ringbuf-full", "dropped", "parse-fail"}
	prev := make([]uint64, len(names))
	for {
		select {
		case <-m.done:
			return
		case <-t.C:
			total := make([]uint64, len(names))
			var key uint32
			var perCPU []uint64
			iter := stats.Iterate()
			for iter.Next(&key, &perCPU) {
				if int(key) < len(total) {
					for _, v := range perCPU {
						total[key] += v
					}
				}
			}
			parts := make([]string, len(names))
			delta := make([]string, len(names))
			for i, n := range names {
				parts[i] = n + "=" + strconv.FormatUint(total[i], 10)
				d := total[i] - prev[i]
				if d > 0 {
					delta[i] = n + "=+" + strconv.FormatUint(d, 10)
				}
				prev[i] = total[i]
			}
			flog.Debugf("[trace] xdp stats: %s | delta: %s",
				strings.Join(parts, " "), strings.Join(delta, " "))
		}
	}
}

// configureClientAllowlist populates the eBPF source-IP allowlist (LPM trie)
// and sets config_map[1] to enable the early drop. Exact IPs are stored as /32
// (or /128) and CIDRs as their prefix length, so the eBPF filter mirrors the
// Go layer's allowlist against the raw source IP. Empty lists leave the flag at
// zero (allow all).
func (m *ebpfManager) configureClientAllowlist(cfg *conf.Network, configMap *ebpf.Map) {
	if len(cfg.AllowedClientIPs) == 0 {
		return
	}

	val := uint8(1)
	armed := false
	for _, s := range cfg.AllowedClientIPs {
		var ip net.IP
		var prefixLen int
		if addr, ipnet, err := net.ParseCIDR(s); err == nil {
			ip = addr
			ones, _ := ipnet.Mask.Size()
			prefixLen = ones
		} else if parsed := net.ParseIP(s); parsed != nil {
			ip = parsed
			if parsed.To4() != nil {
				prefixLen = 32
			} else {
				prefixLen = 128
			}
		} else {
			flog.Warnf("Invalid IP/CIDR in allowed_client_ips: %s", s)
			continue
		}

		if v4 := ip.To4(); v4 != nil {
			if m.clientIP4Map == nil {
				continue
			}
			key := ipv4LPMKey{PrefixLen: uint32(prefixLen)}
			copy(key.Data[:], v4)
			if err := m.clientIP4Map.Put(&key, &val); err != nil {
				flog.Warnf("failed to add %s to eBPF allowlist: %v", s, err)
				continue
			}
		} else {
			if m.clientIP6Map == nil {
				continue
			}
			key := ipv6LPMKey{PrefixLen: uint32(prefixLen)}
			copy(key.Data[:], ip.To16())
			if err := m.clientIP6Map.Put(&key, &val); err != nil {
				flog.Warnf("failed to add %s to eBPF allowlist: %v", s, err)
				continue
			}
		}
		armed = true
	}

	if !armed || configMap == nil {
		return
	}
	one := uint32(1)
	on := uint8(1)
	_ = configMap.Put(&one, &on)
}

func loadRingbuf(cfg *conf.Network) (*ebpfManager, error) {
	objs := ebpf_gen.BpfRingbufObjects{}
	if err := ebpf_gen.LoadBpfRingbufObjects(&objs, nil); err != nil {
		return nil, err
	}

	opts := link.XDPOptions{
		Program:   objs.XdpMain,
		Interface: cfg.Interface.Index,
	}
	if cfg.Driver == "ebpf-generic" {
		opts.Flags = link.XDPGenericMode
	}

	l, err := link.AttachXDP(opts)
	if err != nil {
		objs.Close()
		return nil, err
	}

	rd, err := ringbuf.NewReader(objs.Packets)
	if err != nil {
		l.Close()
		objs.Close()
		return nil, err
	}

	return initManager(cfg, &objs, l, &ringbufReader{rd}, objs.AllowedPorts, objs.AllowedIpsV4, objs.AllowedIpsV6, objs.AllowedClientIpsV4, objs.AllowedClientIpsV6, objs.ConfigMap), nil
}

func loadRingbufCompat(cfg *conf.Network) (*ebpfManager, error) {
	objs := ebpf_gen.BpfRingbufCompatObjects{}
	if err := ebpf_gen.LoadBpfRingbufCompatObjects(&objs, nil); err != nil {
		return nil, err
	}

	opts := link.XDPOptions{
		Program:   objs.XdpMain,
		Interface: cfg.Interface.Index,
	}
	if cfg.Driver == "ebpf-generic" {
		opts.Flags = link.XDPGenericMode
	}

	l, err := link.AttachXDP(opts)
	if err != nil {
		objs.Close()
		return nil, err
	}

	flog.Tracef("ebpf XDP attached: driver=%s iface=%d generic=%v", cfg.Driver, cfg.Interface.Index, cfg.Driver == "ebpf-generic")

	rd, err := ringbuf.NewReader(objs.Packets)
	if err != nil {
		l.Close()
		objs.Close()
		return nil, err
	}

	return initManager(cfg, &objs, l, &ringbufCompatReader{rd}, objs.AllowedPorts, objs.AllowedIpsV4, objs.AllowedIpsV6, objs.AllowedClientIpsV4, objs.AllowedClientIpsV6, objs.ConfigMap), nil
}

func loadPerf(cfg *conf.Network) (*ebpfManager, error) {
	objs := ebpf_gen.BpfPerfObjects{}
	if err := ebpf_gen.LoadBpfPerfObjects(&objs, nil); err != nil {
		return nil, err
	}

	opts := link.XDPOptions{
		Program:   objs.XdpMain,
		Interface: cfg.Interface.Index,
	}
	if cfg.Driver == "ebpf-generic" {
		opts.Flags = link.XDPGenericMode
	}

	l, err := link.AttachXDP(opts)
	if err != nil {
		objs.Close()
		return nil, err
	}

	// Open perf reader
	rd, err := perf.NewReader(objs.Packets, 4096) // 4096 pages per CPU
	if err != nil {
		l.Close()
		objs.Close()
		return nil, err
	}

	return initManager(cfg, &objs, l, &perfReader{rd}, objs.AllowedPorts, objs.AllowedIpsV4, objs.AllowedIpsV6, objs.AllowedClientIpsV4, objs.AllowedClientIpsV6, objs.ConfigMap), nil
}

func (m *ebpfManager) registerPorts(ports []uint16, ch chan []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	val := uint8(1)
	for _, p := range ports {
		m.listeners[p] = ch
		if err := m.portsMap.Put(p, &val); err != nil {
			return fmt.Errorf("failed to add port %d to BPF map: %w", p, err)
		}
	}
	return nil
}

func (m *ebpfManager) unregisterPorts(ports []uint16) {
	m.mu.Lock()
	defer m.mu.Unlock()

	for _, p := range ports {
		delete(m.listeners, p)
		m.portsMap.Delete(p)
	}
}

func (m *ebpfManager) addIPv4(ip net.IP) error {
	// Use [4]byte to ensure the bytes are written to the map in Network Byte Order,
	// matching the raw packet data (ip->daddr) regardless of host endianness.
	var key [4]byte
	copy(key[:], ip.To4())
	val := uint8(1)
	return m.ip4Map.Put(&key, &val)
}

func (m *ebpfManager) addIPv6(ip net.IP) error {
	val := uint8(1)
	return m.ip6Map.Put(ip.To16(), &val)
}

func (m *ebpfManager) close() {
	close(m.done)
	m.reader.Close()
	m.link.Close()
	// Close the objects struct (which closes maps)
	if closer, ok := m.objs.(interface{ Close() error }); ok {
		closer.Close()
	}
}

func (m *ebpfManager) dispatch() {
	for {
		select {
		case <-m.done:
			return
		default:
			record, err := m.reader.Read()
			if err != nil {
				if err == ringbuf.ErrClosed || err == perf.ErrClosed {
					return
				}
				continue
			}

			// Parse packet to find destination port
			port := parsePort(record.RawSample)
			if port == 0 {
				flog.Debugf("eBPF dispatch: failed to parse port from packet len=%d", len(record.RawSample))
				continue
			}

			m.mu.RLock()
			ch, ok := m.listeners[port]
			m.mu.RUnlock()

			flog.Tracef("ebpf dispatch: port=%d listener=%v len=%d", port, ok, len(record.RawSample))

			if !ok {
				// DIAGNOSTIC: packet on a port we don't listen on — a missed
				// rebind would show up here as return traffic vanishing.
				flog.Tracef("ebpf dispatch DROP: port=%d not registered", port)
			}

			if ok {
				// Copy data because the ringbuf memory might be reused
				data := make([]byte, len(record.RawSample))
				copy(data, record.RawSample)
				select {
				case ch <- data:
				default:
					// Drop if channel full
					flog.Debugf("eBPF dispatch: channel full for port %d", port)
				}
			} else {
				flog.Debugf("eBPF dispatch: no listener for port %d", port)
			}
		}
	}
}

func parsePort(data []byte) uint16 {
	if len(data) < 20 {
		return 0
	}

	var ipOffset int
	var isIPv4 bool

	if len(data) >= 14 {
		ethType := binary.BigEndian.Uint16(data[12:14])
		offset := 14

		// Handle VLANs (802.1Q: 0x8100, 802.1ad: 0x88A8)
		for ethType == 0x8100 || ethType == 0x88A8 {
			if len(data) < offset+4 {
				return 0
			}
			ethType = binary.BigEndian.Uint16(data[offset+2 : offset+4])
			offset += 4
		}

		if ethType == 0x0800 {
			ipOffset = offset
			isIPv4 = true
		} else if ethType == 0x86DD {
			ipOffset = offset
			isIPv4 = false
		}
	}

	if ipOffset == 0 {
		// Fallback for direct IP (no Ethernet header, e.g. PPP, TUN, direct XDP)
		ver := data[0] >> 4
		if ver == 4 {
			ipOffset = 0
			isIPv4 = true
		} else if ver == 6 {
			ipOffset = 0
			isIPv4 = false
		} else {
			return 0
		}
	}

	if isIPv4 {
		if len(data) < ipOffset+20 {
			return 0
		}
		ihl := data[ipOffset] & 0x0F
		ipOffset += int(ihl) * 4
	} else {
		ipOffset += 40
	}

	if len(data) < ipOffset+4 {
		return 0
	}

	// TCP/UDP Dest Port is at offset 2 of transport header
	return binary.BigEndian.Uint16(data[ipOffset+2 : ipOffset+4])
}
