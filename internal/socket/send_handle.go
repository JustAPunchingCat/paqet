package socket

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math/big"
	mrand "math/rand"
	"net"
	"paqet/internal/conf"
	"paqet/internal/pkg/hash"
	"paqet/internal/pkg/iterator"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

type TCPF struct {
	tcpF       iterator.Iterator[conf.TCPF]
	clientTCPF map[uint64]*iterator.Iterator[conf.TCPF]
	mu         sync.RWMutex
}

type SendHandle struct {
	handle      *pcap.Handle
	srcIPv4     net.IP
	srcIPv4RHWA net.HardwareAddr
	srcIPv6     net.IP
	srcIPv6RHWA net.HardwareAddr
	srcPort     uint16
	synOptions  []layers.TCPOption
	ackOptions  []layers.TCPOption
	time        uint32
	tsCounter   uint32
	ipId        uint32
	padding     int
	tcpF        TCPF
	hopping     *conf.Hopping
	portRanges  []conf.PortRange
	currentPort atomic.Uint32
	stopHopping chan struct{}
	ethPool     sync.Pool
	ipv4Pool    sync.Pool
	ipv6Pool    sync.Pool
	tcpPool     sync.Pool
	bufPool     sync.Pool
}

func NewSendHandle(cfg *conf.Network) (*SendHandle, error) {
	handle, err := newHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap handle: %w", err)
	}

	// SetDirection is not fully supported on Windows Npcap, so skip it
	if runtime.GOOS != "windows" {
		if err := handle.SetDirection(pcap.DirectionOut); err != nil {
			return nil, fmt.Errorf("failed to set pcap direction out: %v", err)
		}
	}

	synOptions := []layers.TCPOption{
		{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}},
		{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
		{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: make([]byte, 8)},
		{OptionType: layers.TCPOptionKindNop},
		{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{8}},
	}

	ackOptions := []layers.TCPOption{
		{OptionType: layers.TCPOptionKindNop},
		{OptionType: layers.TCPOptionKindNop},
		{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: make([]byte, 8)},
	}

	sh := &SendHandle{
		handle:     handle,
		srcPort:    uint16(cfg.Port),
		synOptions: synOptions,
		ackOptions: ackOptions,
		tcpF:       TCPF{tcpF: iterator.Iterator[conf.TCPF]{Items: cfg.TCP.LF}, clientTCPF: make(map[uint64]*iterator.Iterator[conf.TCPF])},
		time:       uint32(time.Now().UnixNano() / int64(time.Millisecond)),
		ipId:       uint32(time.Now().UnixNano()),
		ethPool: sync.Pool{
			New: func() any {
				return &layers.Ethernet{SrcMAC: cfg.Interface.HardwareAddr}
			},
		},
		ipv4Pool: sync.Pool{
			New: func() any {
				return &layers.IPv4{}
			},
		},
		ipv6Pool: sync.Pool{
			New: func() any {
				return &layers.IPv6{}
			},
		},
		tcpPool: sync.Pool{
			New: func() any {
				return &layers.TCP{}
			},
		},
		bufPool: sync.Pool{
			New: func() any {
				return gopacket.NewSerializeBuffer()
			},
		},
	}
	if cfg.IPv4.Addr != nil {
		sh.srcIPv4 = cfg.IPv4.Addr.IP
		sh.srcIPv4RHWA = cfg.IPv4.Router
	}
	if cfg.IPv6.Addr != nil {
		sh.srcIPv6 = cfg.IPv6.Addr.IP
		sh.srcIPv6RHWA = cfg.IPv6.Router
	}
	return sh, nil
}

func (h *SendHandle) buildIPv4Header(dstIP net.IP) *layers.IPv4 {
	ip := h.ipv4Pool.Get().(*layers.IPv4)
	id := atomic.AddUint32(&h.ipId, 1)
	*ip = layers.IPv4{
		Version:  4,
		IHL:      5,
		TOS:      184,
		Id:       uint16(id),
		TTL:      uint8(64 + (id % 32)),
		Flags:    layers.IPv4DontFragment,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    h.srcIPv4,
		DstIP:    dstIP,
	}
	return ip
}

func (h *SendHandle) buildIPv6Header(dstIP net.IP) *layers.IPv6 {
	ip := h.ipv6Pool.Get().(*layers.IPv6)
	id := atomic.LoadUint32(&h.ipId)
	*ip = layers.IPv6{
		Version:      6,
		TrafficClass: 184,
		HopLimit:     uint8(64 + (id % 32)),
		NextHeader:   layers.IPProtocolTCP,
		SrcIP:        h.srcIPv6,
		DstIP:        dstIP,
	}
	return ip
}

func (h *SendHandle) buildTCPHeader(srcPort, dstPort uint16, f conf.TCPF) *layers.TCP {
	tcp := h.tcpPool.Get().(*layers.TCP)
	*tcp = layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		FIN:     f.FIN, SYN: f.SYN, RST: f.RST, PSH: f.PSH, ACK: f.ACK, URG: f.URG, ECE: f.ECE, CWR: f.CWR, NS: f.NS,
		Window: 65535,
	}

	counter := atomic.AddUint32(&h.tsCounter, 1)
	tsVal := h.time + (counter >> 3)
	if f.SYN {
		binary.BigEndian.PutUint32(h.synOptions[2].OptionData[0:4], tsVal)
		binary.BigEndian.PutUint32(h.synOptions[2].OptionData[4:8], 0)
		tcp.Options = h.synOptions
		tcp.Seq = 1 + (counter & 0x7)
		tcp.Ack = 0
		if f.ACK {
			tcp.Ack = tcp.Seq + 1
		}
	} else {
		tsEcr := tsVal - (counter%200 + 50)
		binary.BigEndian.PutUint32(h.ackOptions[2].OptionData[0:4], tsVal)
		binary.BigEndian.PutUint32(h.ackOptions[2].OptionData[4:8], tsEcr)
		tcp.Options = h.ackOptions
		seq := h.time + (counter << 7)
		tcp.Seq = seq
		tcp.Ack = seq - (counter & 0x3FF) + 1400
	}

	return tcp
}

func (h *SendHandle) Write(payload []byte, addr *net.UDPAddr, srcPort int) error {
	buf := h.bufPool.Get().(gopacket.SerializeBuffer)
	ethLayer := h.ethPool.Get().(*layers.Ethernet)
	defer func() {
		buf.Clear()
		h.bufPool.Put(buf)
		h.ethPool.Put(ethLayer)
	}()

	dstIP := addr.IP
	dstPort := uint16(addr.Port)

	// FRAMING: Prepend 2-byte length of the real payload.
	// This allows the receiver to distinguish real data from padding.
	realLen := len(payload)
	framed := make([]byte, 2+realLen)
	binary.BigEndian.PutUint16(framed, uint16(realLen))
	copy(framed[2:], payload)
	payload = framed

	if h.hopping != nil && h.hopping.Enabled {
		if p := h.currentPort.Load(); p > 0 {
			dstPort = uint16(p)
		}
	}

	if h.padding > 0 {
		padLen := mrand.Intn(h.padding + 1)
		if padLen > 0 {
			padding := make([]byte, padLen)
			rand.Read(padding)
			payload = append(payload, padding...)
		}
	}

	f := h.getClientTCPF(dstIP, dstPort)
	tcpLayer := h.buildTCPHeader(uint16(srcPort), dstPort, f)
	defer h.tcpPool.Put(tcpLayer)

	var ipLayer gopacket.SerializableLayer
	if dstIP.To4() != nil {
		ip := h.buildIPv4Header(dstIP)
		defer h.ipv4Pool.Put(ip)
		ipLayer = ip
		tcpLayer.SetNetworkLayerForChecksum(ip)
		ethLayer.DstMAC = h.srcIPv4RHWA
		ethLayer.EthernetType = layers.EthernetTypeIPv4
	} else {
		ip := h.buildIPv6Header(dstIP)
		defer h.ipv6Pool.Put(ip)
		ipLayer = ip
		tcpLayer.SetNetworkLayerForChecksum(ip)
		ethLayer.DstMAC = h.srcIPv6RHWA
		ethLayer.EthernetType = layers.EthernetTypeIPv6
	}

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	if err := gopacket.SerializeLayers(buf, opts, ethLayer, ipLayer, tcpLayer, gopacket.Payload(payload)); err != nil {
		return err
	}
	return h.handle.WritePacketData(buf.Bytes())
}

func (h *SendHandle) getClientTCPF(dstIP net.IP, dstPort uint16) conf.TCPF {
	h.tcpF.mu.RLock()
	defer h.tcpF.mu.RUnlock()
	if ff := h.tcpF.clientTCPF[hash.IPAddr(dstIP, dstPort)]; ff != nil {
		return ff.Next()
	}
	return h.tcpF.tcpF.Next()
}

func (h *SendHandle) setClientTCPF(addr net.Addr, f []conf.TCPF) {
	a := *addr.(*net.UDPAddr)
	h.tcpF.mu.Lock()
	h.tcpF.clientTCPF[hash.IPAddr(a.IP, uint16(a.Port))] = &iterator.Iterator[conf.TCPF]{Items: f}
	h.tcpF.mu.Unlock()
}

func (h *SendHandle) SetPadding(padding int) {
	h.padding = padding
}

func (h *SendHandle) SetHopping(hopping *conf.Hopping) error {
	if hopping == nil || !hopping.Enabled {
		return nil
	}
	ranges, err := hopping.GetRanges()
	if err != nil {
		return err
	}
	h.hopping = hopping
	h.portRanges = ranges
	h.stopHopping = make(chan struct{})
	h.updateCurrentPort()
	go h.startHopping()
	return nil
}

func (h *SendHandle) startHopping() {
	ticker := time.NewTicker(time.Duration(h.hopping.Interval) * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			h.updateCurrentPort()
		case <-h.stopHopping:
			return
		}
	}
}

func (h *SendHandle) updateCurrentPort() {
	if len(h.portRanges) == 0 {
		return
	}

	idx, err := randInt(len(h.portRanges))
	if err != nil {
		idx = mrand.Intn(len(h.portRanges))
	}
	r := h.portRanges[idx]

	rangeSize := r.Max - r.Min + 1
	offset := 0
	if rangeSize > 1 {
		o, err := randInt(rangeSize)
		if err != nil {
			offset = mrand.Intn(rangeSize)
		} else {
			offset = o
		}
	}

	newPort := uint32(r.Min + offset)
	h.currentPort.Store(newPort)
}

func (h *SendHandle) Close() {
	if h.stopHopping != nil {
		close(h.stopHopping)
	}
	if h.handle != nil {
		h.handle.Close()
	}
}

func randInt(max int) (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}
