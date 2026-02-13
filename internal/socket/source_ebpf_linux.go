//go:build linux && !noebpf

package socket

import (
	"encoding/binary"
	"fmt"
	"net"
	"paqet/internal/conf"
	"paqet/internal/flog"
	ebpf_gen "paqet/internal/socket/ebpf"
	"sync"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

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
	portsMap *ebpf.Map
	ip4Map   *ebpf.Map
	ip6Map   *ebpf.Map

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
	mgr   *ebpfManager
	ch    chan []byte
	ports []uint16 // Track registered ports to remove on close
	ipv4  net.IP
	ipv6  net.IP
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
		mgr: mgr,
		ch:  make(chan []byte, 1024), // Buffer for high throughput
	}

	// Register IP
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

	// Register Ports (Main port + Hopping ranges)
	ports := []uint16{uint16(cfg.Port)}
	if hopping != nil && hopping.Enabled {
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
	flog.Debugf("eBPF registered ports: %v for IP: %s", ports, s.ipv4)
	s.ports = ports

	return s, nil
}

func (s *sharedEBPFSource) ReadPacketData() ([]byte, error) {
	data, ok := <-s.ch
	if !ok {
		return nil, fmt.Errorf("ebpf source closed")
	}
	return data, nil
}

func (s *sharedEBPFSource) Close() {
	managerMu.Lock()
	defer managerMu.Unlock()

	s.mgr.unregisterPorts(s.ports)
	// Note: We don't remove IPs because other clients might share them.

	s.mgr.refCount--
	if s.mgr.refCount == 0 {
		s.mgr.close()
		delete(managers, s.mgr.ifaceIndex)
	}
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
func initManager(cfg *conf.Network, objs interface{}, link link.Link, rd PacketReader, ports, ip4, ip6 *ebpf.Map) *ebpfManager {
	mgr := &ebpfManager{
		ifaceIndex: cfg.Interface.Index,
		refCount:   0, // Will be incremented by caller
		objs:       objs,
		link:       link,
		reader:     rd,
		portsMap:   ports,
		ip4Map:     ip4,
		ip6Map:     ip6,
		listeners:  make(map[uint16]chan []byte),
		done:       make(chan struct{}),
	}
	go mgr.dispatch()
	return mgr
}

func loadRingbuf(cfg *conf.Network) (*ebpfManager, error) {
	objs := ebpf_gen.BpfRingbufObjects{}
	if err := ebpf_gen.LoadBpfRingbufObjects(&objs, nil); err != nil {
		return nil, err
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpMain,
		Interface: cfg.Interface.Index,
	})
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

	return initManager(cfg, &objs, l, &ringbufReader{rd}, objs.AllowedPorts, objs.AllowedIpsV4, objs.AllowedIpsV6), nil
}

func loadRingbufCompat(cfg *conf.Network) (*ebpfManager, error) {
	objs := ebpf_gen.BpfRingbufCompatObjects{}
	if err := ebpf_gen.LoadBpfRingbufCompatObjects(&objs, nil); err != nil {
		return nil, err
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpMain,
		Interface: cfg.Interface.Index,
	})
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

	return initManager(cfg, &objs, l, &ringbufCompatReader{rd}, objs.AllowedPorts, objs.AllowedIpsV4, objs.AllowedIpsV6), nil
}

func loadPerf(cfg *conf.Network) (*ebpfManager, error) {
	objs := ebpf_gen.BpfPerfObjects{}
	if err := ebpf_gen.LoadBpfPerfObjects(&objs, nil); err != nil {
		return nil, err
	}

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpMain,
		Interface: cfg.Interface.Index,
	})
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

	return initManager(cfg, &objs, l, &perfReader{rd}, objs.AllowedPorts, objs.AllowedIpsV4, objs.AllowedIpsV6), nil
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
	if len(data) < 14 {
		return 0
	}
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

	var ipOffset int

	if ethType == 0x0800 { // IPv4
		ipOffset = offset
		if len(data) < ipOffset+20 {
			return 0
		}
		ihl := data[ipOffset] & 0x0F
		ipOffset += int(ihl) * 4
	} else if ethType == 0x86DD { // IPv6
		ipOffset = offset + 40
	} else {
		return 0
	}

	if len(data) < ipOffset+4 {
		return 0
	}

	// TCP Dest Port is at offset 2
	return binary.BigEndian.Uint16(data[ipOffset+2 : ipOffset+4])
}
