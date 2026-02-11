package socket

import (
	"crypto/rand"
	"encoding/binary"
	"math/big"
	"net"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/pkg/hash"
	"paqet/internal/pkg/iterator"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type PacketInjector interface {
	WritePacketData(data []byte) error
	Close()
}

type TCPF struct {
	tcpF       iterator.Iterator[conf.TCPF]
	clientTCPF map[uint64]*iterator.Iterator[conf.TCPF]
	mu         sync.Mutex
}

type SendHandle struct {
	injector    PacketInjector
	cfg         *conf.Network
	driver      string
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
	obfuscation *conf.Obfuscation
	// Fingerprinting fields
	tos       uint8
	ttl       uint8
	baseTS    uint32
	startTime time.Time

	tcpF        TCPF
	ethPool     sync.Pool
	ipv4Pool    sync.Pool
	ipv6Pool    sync.Pool
	tcpPool     sync.Pool
	bufPool     sync.Pool
	closeOnce   sync.Once
	lastErrTime time.Time
	errMu       sync.Mutex
	reopenMu    sync.Mutex
}

// randUint32 returns a cryptographically random uint32.
func randUint32() uint32 {
	var b [4]byte
	rand.Read(b[:])
	return binary.BigEndian.Uint32(b[:])
}

// randRange returns a cryptographically random int in [lo, hi].
func randRange(lo, hi int) int {
	n, _ := rand.Int(rand.Reader, big.NewInt(int64(hi-lo+1)))
	return lo + int(n.Int64())
}

func NewSendHandle(cfg *conf.Network) (*SendHandle, error) {
	var injector PacketInjector
	var err error
	switch cfg.Driver {
	case "ebpf":
		injector, err = newRawInjector(cfg)
	default:
		injector, err = newPcapInjector(cfg)
	}
	if err != nil {
		return nil, err
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

	// Pick randomized fingerprint values at creation time
	tosChoices := []uint8{0x00, 0x10, 0x08}
	tos := tosChoices[randRange(0, len(tosChoices)-1)]
	ttl := uint8(randRange(60, 68))

	sh := &SendHandle{
		injector:   injector,
		cfg:        cfg,
		driver:     cfg.Driver,
		srcPort:    uint16(cfg.Port),
		synOptions: synOptions,
		ackOptions: ackOptions,
		tcpF:       TCPF{tcpF: iterator.Iterator[conf.TCPF]{Items: cfg.TCP.LF}, clientTCPF: make(map[uint64]*iterator.Iterator[conf.TCPF])},
		time:       uint32(time.Now().UnixNano() / int64(time.Millisecond)),
		ipId:       uint32(time.Now().UnixNano()),
		tos:        tos,
		ttl:        ttl,
		baseTS:     randUint32(),
		startTime:  time.Now(),
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

	tos := h.tos
	ttl := h.ttl

	if h.obfuscation != nil && h.obfuscation.Headers.RandomizeTOS {
		tos = GenerateRealisticTOS()
	}
	if h.obfuscation != nil && h.obfuscation.Headers.RandomizeTTL {
		ttl = GenerateRealisticTTL()
	}

	*ip = layers.IPv4{
		Version:  4,
		IHL:      5,
		TOS:      tos,
		Id:       uint16(id),
		TTL:      ttl,
		Flags:    layers.IPv4DontFragment,
		Protocol: layers.IPProtocolTCP,
		SrcIP:    h.srcIPv4,
		DstIP:    dstIP,
	}
	return ip
}

func (h *SendHandle) buildIPv6Header(dstIP net.IP) *layers.IPv6 {
	ip := h.ipv6Pool.Get().(*layers.IPv6)

	tclass := h.tos
	hopLimit := h.ttl

	if h.obfuscation != nil && h.obfuscation.Headers.RandomizeTOS {
		tclass = GenerateRealisticTOS()
	}
	if h.obfuscation != nil && h.obfuscation.Headers.RandomizeTTL {
		hopLimit = GenerateRealisticTTL()
	}

	*ip = layers.IPv6{
		Version:      6,
		TrafficClass: tclass,
		HopLimit:     hopLimit,
		NextHeader:   layers.IPProtocolTCP,
		SrcIP:        h.srcIPv6,
		DstIP:        dstIP,
	}
	return ip
}

func (h *SendHandle) buildTCPHeader(srcPort, dstPort uint16, f conf.TCPF) *layers.TCP {
	tcp := h.tcpPool.Get().(*layers.TCP)

	winSize := uint16(randRange(64240, 65535))
	if h.obfuscation != nil && h.obfuscation.Headers.RandomizeWindow {
		winSize = GenerateRealisticWindow()
	}

	*tcp = layers.TCP{
		SrcPort: layers.TCPPort(srcPort),
		DstPort: layers.TCPPort(dstPort),
		FIN:     f.FIN, SYN: f.SYN, RST: f.RST, PSH: f.PSH, ACK: f.ACK, URG: f.URG, ECE: f.ECE, CWR: f.CWR, NS: f.NS,
		Window: winSize,
	}

	counter := atomic.AddUint32(&h.tsCounter, 1)

	// Compute realistic TCP timestamp from real elapsed time + random base + jitter
	elapsed := time.Since(h.startTime)
	tsVal := h.baseTS + uint32(elapsed.Milliseconds()) + uint32(randRange(0, 9))

	// Unified Sequence Number Generation
	// Use the same formula for SYN and Data so they appear to be in the same window.
	seq := h.baseTS + (counter << 7) // Use baseTS for sequence base too

	// Use local slice for options to avoid data race on h.synOptions/h.ackOptions
	// We must allocate new OptionData for the timestamp to avoid racing on the backing array.
	if f.SYN {
		opts := make([]layers.TCPOption, len(h.synOptions))
		copy(opts, h.synOptions)

		tsData := make([]byte, 8)
		binary.BigEndian.PutUint32(tsData[0:4], tsVal)
		binary.BigEndian.PutUint32(tsData[4:8], 0)
		opts[2].OptionData = tsData

		tcp.Options = opts
		tcp.Seq = seq
		tcp.Ack = 0
		if f.ACK {
			tcp.Ack = tcp.Seq + 1
		}
	} else {
		opts := make([]layers.TCPOption, len(h.ackOptions))
		copy(opts, h.ackOptions)

		tsData := make([]byte, 8)
		tsEcr := tsVal - uint32(randRange(50, 250))
		binary.BigEndian.PutUint32(tsData[0:4], tsVal)
		binary.BigEndian.PutUint32(tsData[4:8], tsEcr)
		opts[2].OptionData = tsData

		tcp.Options = opts
		tcp.Seq = seq
		tcp.Ack = seq - (counter & 0x3FF) + 1400
	}

	return tcp
}

func (h *SendHandle) Write(payload []byte, addr *net.UDPAddr, srcPort int) error {
	buf := h.bufPool.Get().(gopacket.SerializeBuffer)
	defer func() {
		buf.Clear()
		h.bufPool.Put(buf)
	}()

	var ethLayer *layers.Ethernet
	if h.driver != "tun" {
		ethLayer = h.ethPool.Get().(*layers.Ethernet)
		defer h.ethPool.Put(ethLayer)
	}

	dstIP := addr.IP
	dstPort := uint16(addr.Port)

	f := h.getClientTCPF(dstIP, dstPort)
	tcpLayer := h.buildTCPHeader(uint16(srcPort), dstPort, f)
	defer h.tcpPool.Put(tcpLayer)

	var ipLayer gopacket.SerializableLayer
	if dstIP.To4() != nil {
		ip := h.buildIPv4Header(dstIP)
		defer h.ipv4Pool.Put(ip)
		ipLayer = ip
		tcpLayer.SetNetworkLayerForChecksum(ip)
		if ethLayer != nil {
			ethLayer.DstMAC = h.srcIPv4RHWA
			ethLayer.EthernetType = layers.EthernetTypeIPv4
		}
	} else {
		ip := h.buildIPv6Header(dstIP)
		defer h.ipv6Pool.Put(ip)
		ipLayer = ip
		tcpLayer.SetNetworkLayerForChecksum(ip)
		if ethLayer != nil {
			ethLayer.DstMAC = h.srcIPv6RHWA
			ethLayer.EthernetType = layers.EthernetTypeIPv6
		}
	}

	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	layersToSerialize := []gopacket.SerializableLayer{ipLayer, tcpLayer}
	if len(payload) > 0 {
		layersToSerialize = append(layersToSerialize, gopacket.Payload(payload))
	}
	if ethLayer != nil {
		layersToSerialize = append([]gopacket.SerializableLayer{ethLayer}, layersToSerialize...)
	}

	if err := gopacket.SerializeLayers(buf, opts, layersToSerialize...); err != nil {
		return err
	}
	err := h.injector.WritePacketData(buf.Bytes())
	if err != nil {
		// Suppress log spam for common Windows Npcap "device not functioning" error (code 31)
		if strings.Contains(err.Error(), "device attached to the system is not functioning") {
			// Attempt to reopen the handle to recover from the device error
			if reopenErr := h.reopen(); reopenErr != nil {
				flog.Errorf("Failed to reopen injection handle: %v", reopenErr)
			}

			h.errMu.Lock()
			if time.Since(h.lastErrTime) > 5*time.Second {
				flog.Errorf("Packet injection failed (device error), attempting recovery: %v", err)
				h.lastErrTime = time.Now()
			}
			h.errMu.Unlock()
			// Return nil to prevent upper layers from spamming "send error" logs.
			return nil
		}
	}
	return err
}

func (h *SendHandle) reopen() error {
	h.reopenMu.Lock()
	defer h.reopenMu.Unlock()

	// Close existing injector
	if h.injector != nil {
		h.injector.Close()
	}

	// Create new injector
	var newInjector PacketInjector
	var err error
	switch h.driver {
	case "ebpf":
		newInjector, err = newRawInjector(h.cfg)
	default:
		newInjector, err = newPcapInjector(h.cfg)
	}

	if err != nil {
		return err
	}

	h.injector = newInjector
	return nil
}

func (h *SendHandle) getClientTCPF(dstIP net.IP, dstPort uint16) conf.TCPF {
	h.tcpF.mu.Lock()
	defer h.tcpF.mu.Unlock()
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

func (h *SendHandle) SetObfuscation(obfs *conf.Obfuscation) {
	h.obfuscation = obfs
}

func (h *SendHandle) Close() {
	h.closeOnce.Do(func() {
		if h.injector != nil {
			h.injector.Close()
		}
	})
}
