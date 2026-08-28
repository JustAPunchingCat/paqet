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
	"strconv"
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

// lazyWarmupTimeout bounds how long a lazy-mode write blocks waiting for the
// fake handshake's SYN-ACK before falling back to 0-RTT.
const lazyWarmupTimeout = time.Second

type TCPF struct {
	tcpF       iterator.Iterator[conf.TCPF]
	clientTCPF map[uint64]*iterator.Iterator[conf.TCPF]
	mu         sync.Mutex
}

type FlowUpdater interface {
	UpdateRemoteFlow(srcIP net.IP, srcPort int, dstIP net.IP, dstPort int, remoteSeq uint32, remoteAck uint32, payloadLen uint32, tsVal uint32)
	SendSYNACK(remoteIP net.IP, remotePort int, localPort int, clientSeq uint32, clientTSval uint32) error
	SendACK(remoteIP net.IP, remotePort int, localPort int, serverSeq uint32, serverTSval uint32) error
}

type flowState struct {
	ipId        uint32
	baseTS      uint32
	seq         uint32
	tsCounter   uint32
	synSent     uint32
	remoteSeq   uint32
	remoteLen   uint32
	remoteTSval uint32
	hasRemote   uint32
}

type targetSpoofRule struct {
	targetNet *net.IPNet
	targetIP  net.IP
	spoofIPs  []net.IP
	spoofNets []*net.IPNet
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
	obfuscation *conf.Obfuscation
	// Fingerprinting fields
	spoofNets        []*net.IPNet
	spoofIPs         []net.IP
	targetSpoofRules []targetSpoofRule
	nameMapping      map[string]string

	tos       uint8
	ttl       uint8
	startTime time.Time

	tcpF          TCPF
	handshake     bool
	handshakeLazy bool
	role          string
	ethPool       sync.Pool
	ipv4Pool      sync.Pool
	ipv6Pool      sync.Pool
	tcpPool       sync.Pool
	bufPool       sync.Pool
	packetPool    sync.Pool

	globalState *flowState
	spoofStates map[string]*flowState
	statesMu    sync.Mutex
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
	case "ebpf", "ebpf-generic":
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

	hs := cfg.Handshake
	if hs == nil {
		hs = &conf.Handshake{}
	}

	sh := &SendHandle{
		injector:      injector,
		cfg:           cfg,
		driver:        cfg.Driver,
		srcPort:       uint16(cfg.Port),
		role:          cfg.Role,
		synOptions:    synOptions,
		ackOptions:    ackOptions,
		tcpF:          TCPF{tcpF: iterator.Iterator[conf.TCPF]{Items: cfg.TCP.LF}, clientTCPF: make(map[uint64]*iterator.Iterator[conf.TCPF])},
		handshake:     hs.IsEnabled(),
		handshakeLazy: hs.IsLazy(),
		time:          uint32(time.Now().UnixNano() / int64(time.Millisecond)),
		tos:           tos,
		ttl:           ttl,
		startTime:     time.Now(),
		globalState:   &flowState{ipId: randUint32(), baseTS: randUint32(), seq: randUint32()},
		spoofStates:   make(map[string]*flowState),
		nameMapping:   make(map[string]string),
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
		packetPool: sync.Pool{
			New: func() any {
				b := make([]byte, 65536)
				return &b
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

	// Parse spoofing addresses
	if cfg.Spoof != nil && cfg.Spoof.Enabled {
		// Build name mapping for log masking
		for _, c := range cfg.Spoof.Clients {
			if c.Name != "" {
				for _, ip := range c.RealClientIPs {
					sh.nameMapping[ip] = c.Name
				}
			}
		}
		for _, s := range cfg.Spoof.Servers {
			if s.Name != "" {
				for _, ip := range s.RealServerIPs {
					sh.nameMapping[ip] = s.Name
				}
			}
		}

		for _, s := range cfg.Spoof.Addrs {
			// Try parsing as CIDR
			ip, ipNet, err := net.ParseCIDR(s)
			if err == nil {
				// If it's a /32 or /128, treat it as a single IP
				ones, bits := ipNet.Mask.Size()
				if ones == bits {
					sh.spoofIPs = append(sh.spoofIPs, ip)
				} else {
					sh.spoofNets = append(sh.spoofNets, ipNet)
				}
				continue
			}

			// Try parsing as single IP
			ip = net.ParseIP(s)
			if ip != nil {
				sh.spoofIPs = append(sh.spoofIPs, ip)
				continue
			}
			flog.Warnf("Invalid spoofing address (not a CIDR or IP): %s", s)
		}

		if cfg.Spoof.TargetSpoofAddrs != nil {
			for targetStr, addrs := range cfg.Spoof.TargetSpoofAddrs {
				var rule targetSpoofRule
				_, ipNet, err := net.ParseCIDR(targetStr)
				if err == nil {
					rule.targetNet = ipNet
				} else {
					ip := net.ParseIP(targetStr)
					if ip != nil {
						rule.targetIP = ip
					} else {
						targetDisp := targetStr
						if name, ok := sh.nameMapping[targetStr]; ok {
							targetDisp = name
						}
						flog.Warnf("Invalid target IP/CIDR in target_spoof_addrs: %s", targetDisp)
						continue
					}
				}

				for _, s := range addrs {
					ip, ipNet, err := net.ParseCIDR(s)
					if err == nil {
						ones, bits := ipNet.Mask.Size()
						if ones == bits {
							rule.spoofIPs = append(rule.spoofIPs, ip)
						} else {
							rule.spoofNets = append(rule.spoofNets, ipNet)
						}
						continue
					}

					ip = net.ParseIP(s)
					if ip != nil {
						rule.spoofIPs = append(rule.spoofIPs, ip)
						continue
					}
					targetDisp := targetStr
					if name, ok := sh.nameMapping[targetStr]; ok {
						targetDisp = name
					}
					flog.Warnf("Invalid spoofing address for target %s: %s", targetDisp, s)
				}
				sh.targetSpoofRules = append(sh.targetSpoofRules, rule)
			}
		}

		var totalIPs, totalNets int
		totalIPs += len(sh.spoofIPs)
		totalNets += len(sh.spoofNets)
		for _, rule := range sh.targetSpoofRules {
			totalIPs += len(rule.spoofIPs)
			totalNets += len(rule.spoofNets)
		}
		if totalIPs > 0 || totalNets > 0 {
			flog.Infof("Outgoing IP spoofing enabled with %d IPs and %d networks.", totalIPs, totalNets)
		}
	}
	return sh, nil
}

func (h *SendHandle) buildIPv4Header(srcIP, dstIP net.IP, isSpoofed bool, state *flowState) *layers.IPv4 {
	ip := h.ipv4Pool.Get().(*layers.IPv4)
	id := atomic.AddUint32(&state.ipId, 1)

	tos := h.tos
	ttl := h.ttl

	if h.obfuscation != nil && h.obfuscation.Headers.RandomizeTOS {
		tos = GenerateRealisticTOS()
	}
	if h.obfuscation != nil && h.obfuscation.Headers.RandomizeTTL {
		ttl = GenerateRealisticTTL()
	} else if isSpoofed {
		// Deterministic TTL based on the spoofed IP so every IP has its own unique, stable distance!
		sum := 0
		if ipBytes := srcIP.To4(); ipBytes != nil {
			for _, b := range ipBytes {
				sum += int(b)
			}
			ttl = uint8(60 + (sum % 9)) // Stable TTL between 60 and 68 for this specific IP
		}
	}

	*ip = layers.IPv4{
		Version: 4,
		IHL:     5,
		TOS:     tos,
		Id:      uint16(id),
		TTL:     ttl,
		Flags:   layers.IPv4DontFragment, Protocol: layers.IPProtocolTCP,
		SrcIP: srcIP,
		DstIP: dstIP,
	}
	return ip
}

func (h *SendHandle) buildIPv6Header(srcIP, dstIP net.IP, isSpoofed bool, state *flowState) *layers.IPv6 {
	ip := h.ipv6Pool.Get().(*layers.IPv6)

	tclass := h.tos
	hopLimit := h.ttl

	if h.obfuscation != nil && h.obfuscation.Headers.RandomizeTOS {
		tclass = GenerateRealisticTOS()
	}
	if h.obfuscation != nil && h.obfuscation.Headers.RandomizeTTL {
		hopLimit = GenerateRealisticTTL()
	} else if isSpoofed {
		// Deterministic TTL based on the spoofed IPv6 address
		sum := 0
		if ipBytes := srcIP.To16(); ipBytes != nil {
			for _, b := range ipBytes {
				sum += int(b)
			}
			hopLimit = uint8(60 + (sum % 9))
		}
	}

	*ip = layers.IPv6{
		Version:      6,
		TrafficClass: tclass,
		HopLimit:     hopLimit,
		NextHeader:   layers.IPProtocolTCP,
		SrcIP:        srcIP,
		DstIP:        dstIP,
	}
	return ip
}

func (h *SendHandle) buildTCPHeader(srcPort, dstPort uint16, f conf.TCPF, state *flowState) *layers.TCP {
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

	counter := atomic.AddUint32(&state.tsCounter, 1)

	// Compute realistic TCP timestamp from real elapsed time + random base + jitter
	elapsed := time.Since(h.startTime)
	tsVal := state.baseTS + uint32(elapsed.Milliseconds()) + uint32(randRange(0, 9))

	// Unified Sequence Number Generation
	// Use the same formula for SYN and Data so they appear to be in the same window.
	seq := state.seq + (counter << 7)

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

// checksum calculates the ones' complement checksum of a single byte slice.
func checksum(data []byte) uint16 {
	var sum uint32
	n := len(data)
	for i := 0; i < n-1; i += 2 {
		sum += uint32(data[i])<<8 | uint32(data[i+1])
	}
	if n%2 == 1 {
		sum += uint32(data[n-1]) << 8
	}
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(^sum)
}

// checksumMultiple calculates the ones' complement checksum of multiple contiguous slices without copying or allocating.
func checksumMultiple(slices ...[]byte) uint16 {
	var sum uint32
	var oddByte uint8
	var hasOdd bool

	for _, slice := range slices {
		n := len(slice)
		if n == 0 {
			continue
		}

		i := 0
		if hasOdd {
			// Combine the odd byte from the previous slice with the first byte of this slice
			sum += uint32(oddByte)<<8 | uint32(slice[0])
			i = 1
			hasOdd = false
		}

		for ; i < n-1; i += 2 {
			sum += uint32(slice[i])<<8 | uint32(slice[i+1])
		}

		if i < n {
			oddByte = slice[i]
			hasOdd = true
		}
	}

	if hasOdd {
		sum += uint32(oddByte) << 8
	}

	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(^sum)
}

func (h *SendHandle) Write(payload []byte, addr *net.UDPAddr, srcPort int) error {
	dstIP := addr.IP
	dstPort := uint16(addr.Port)

	// Lazy warm-up: fire the fake SYN and block for the SYN-ACK before the
	// first data packet goes out, so strict DPI/Netfilter sees an established
	// flow. Client-side only; the server responds to SYNs instead of sending
	// them. Bounded by lazyWarmupTimeout, after which we fall back to 0-RTT.
	if h.role == "client" && h.handshake && h.handshakeLazy && !h.IsFlowWarmed(dstIP, dstPort) {
		h.PrewarmFlow(dstIP, dstPort)
		h.WaitFlowWarm(dstIP, dstPort, lazyWarmupTimeout)
	}

	isIPv4 := dstIP.To4() != nil
	srcIP, isSpoofed := h.resolveSrcIP(isIPv4, dstIP)

	state := h.getFlowState(srcIP, srcPort, dstIP, dstPort)
	f := h.getClientTCPF(dstIP, dstPort)

	return h.writeRaw(payload, addr, srcPort, f, srcIP, isIPv4, isSpoofed, state)
}

func (h *SendHandle) writeRaw(payload []byte, addr *net.UDPAddr, srcPort int, f conf.TCPF, srcIP net.IP, isIPv4 bool, isSpoofed bool, state *flowState) error {
	dstIP := addr.IP
	dstPort := uint16(addr.Port)

	// Fetch dynamic header variables
	tos := h.tos
	ttl := h.ttl
	if h.obfuscation != nil && h.obfuscation.Headers.RandomizeTOS {
		tos = GenerateRealisticTOS()
	}
	if h.obfuscation != nil && h.obfuscation.Headers.RandomizeTTL {
		ttl = GenerateRealisticTTL()
	} else if isSpoofed && isIPv4 {
		sum := 0
		if ipBytes := srcIP.To4(); ipBytes != nil {
			for _, b := range ipBytes {
				sum += int(b)
			}
			ttl = uint8(60 + (sum % 9))
		}
	}

	winSize := uint16(randRange(64240, 65535))
	if h.obfuscation != nil && h.obfuscation.Headers.RandomizeWindow {
		winSize = GenerateRealisticWindow()
	}

	id := atomic.AddUint32(&state.ipId, 1)

	elapsed := time.Since(h.startTime)
	tsVal := state.baseTS + uint32(elapsed.Milliseconds())

	payloadLen := uint32(len(payload))
	advanceLen := payloadLen
	if advanceLen == 0 && f.SYN {
		advanceLen = 1
	}
	seq := atomic.AddUint32(&state.seq, advanceLen) - advanceLen

	var ack uint32
	var tsEcr uint32
	if atomic.LoadUint32(&state.hasRemote) == 1 {
		ack = atomic.LoadUint32(&state.remoteSeq) + atomic.LoadUint32(&state.remoteLen)
		tsEcr = atomic.LoadUint32(&state.remoteTSval)
	} else {
		if f.SYN && !f.ACK {
			ack = 0
		} else {
			// Use the randomized baseTS as a completely arbitrary but CONSTANT
			// initial ACK number until the server actually replies.
			ack = atomic.LoadUint32(&state.baseTS)
		}
		if !f.SYN {
			tsEcr = tsVal - uint32(randRange(50, 250))
		}
	}

	// Calculate header lengths
	var ethLen int
	if h.driver != "tun" {
		ethLen = 14
	}

	var ipLen int
	if isIPv4 {
		ipLen = 20
	} else {
		ipLen = 40
	}

	var tcpLen int
	if f.SYN {
		tcpLen = 40 // 20 bytes basic + 20 bytes options
	} else {
		tcpLen = 32 // 20 bytes basic + 12 bytes options
	}

	totalLen := ethLen + ipLen + tcpLen + len(payload)

	// Retrieve a packet buffer from the pool
	bufPtr := h.packetPool.Get().(*[]byte)
	defer h.packetPool.Put(bufPtr)
	buf := *bufPtr

	// 1. Ethernet Header (if not TUN driver)
	if ethLen == 14 {
		var dstMAC net.HardwareAddr
		if isIPv4 {
			dstMAC = h.srcIPv4RHWA
		} else {
			dstMAC = h.srcIPv6RHWA
		}
		copy(buf[0:6], dstMAC)
		copy(buf[6:12], h.cfg.Interface.HardwareAddr)
		if isIPv4 {
			binary.BigEndian.PutUint16(buf[12:14], 0x0800) // EthernetTypeIPv4
		} else {
			binary.BigEndian.PutUint16(buf[12:14], 0x86dd) // EthernetTypeIPv6
		}
	}

	// 2. IP Header
	ipStart := ethLen
	if isIPv4 {
		buf[ipStart] = 0x45 // Version 4, IHL 5
		buf[ipStart+1] = tos
		binary.BigEndian.PutUint16(buf[ipStart+2:ipStart+4], uint16(ipLen+tcpLen+len(payload)))
		binary.BigEndian.PutUint16(buf[ipStart+4:ipStart+6], uint16(id))
		binary.BigEndian.PutUint16(buf[ipStart+6:ipStart+8], 0x4000) // DF Flag set, FragmentOffset = 0
		buf[ipStart+8] = ttl
		buf[ipStart+9] = 6                                        // TCP protocol
		binary.BigEndian.PutUint16(buf[ipStart+10:ipStart+12], 0) // Checksum initially 0
		copy(buf[ipStart+12:ipStart+16], srcIP.To4())
		copy(buf[ipStart+16:ipStart+20], dstIP.To4())

		// Compute and set IPv4 Header Checksum
		ipChecksum := checksum(buf[ipStart : ipStart+20])
		binary.BigEndian.PutUint16(buf[ipStart+10:ipStart+12], ipChecksum)
	} else {
		// IPv6
		tclass := h.tos
		hopLimit := h.ttl
		if h.obfuscation != nil && h.obfuscation.Headers.RandomizeTOS {
			tclass = GenerateRealisticTOS()
		}
		if h.obfuscation != nil && h.obfuscation.Headers.RandomizeTTL {
			hopLimit = GenerateRealisticTTL()
		} else if isSpoofed {
			sum := 0
			if ipBytes := srcIP.To16(); ipBytes != nil {
				for _, b := range ipBytes {
					sum += int(b)
				}
				hopLimit = uint8(60 + (sum % 9))
			}
		}

		vtf := 0x60000000 | (uint32(tclass) << 20)
		binary.BigEndian.PutUint32(buf[ipStart:ipStart+4], vtf)
		binary.BigEndian.PutUint16(buf[ipStart+4:ipStart+6], uint16(tcpLen+len(payload)))
		buf[ipStart+6] = 6 // Next Header is TCP
		buf[ipStart+7] = hopLimit
		copy(buf[ipStart+8:ipStart+24], srcIP.To16())
		copy(buf[ipStart+24:ipStart+40], dstIP.To16())
	}

	// 3. TCP Header
	tcpStart := ipStart + ipLen
	binary.BigEndian.PutUint16(buf[tcpStart:tcpStart+2], uint16(srcPort))
	binary.BigEndian.PutUint16(buf[tcpStart+2:tcpStart+4], dstPort)
	binary.BigEndian.PutUint32(buf[tcpStart+4:tcpStart+8], seq)
	binary.BigEndian.PutUint32(buf[tcpStart+8:tcpStart+12], ack)

	// Data Offset & Reserved & Flags
	var offsetByte byte
	if f.SYN {
		offsetByte = 10 << 4 // 40 bytes / 4 = 10
	} else {
		offsetByte = 8 << 4 // 32 bytes / 4 = 8
	}
	buf[tcpStart+12] = offsetByte

	var flags byte
	if f.FIN {
		flags |= 0x01
	}
	if f.SYN {
		flags |= 0x02
	}
	if f.RST {
		flags |= 0x04
	}
	if f.PSH {
		flags |= 0x08
	}
	if f.ACK {
		flags |= 0x10
	}
	if f.URG {
		flags |= 0x20
	}
	if f.ECE {
		flags |= 0x40
	}
	if f.CWR {
		flags |= 0x80
	}
	buf[tcpStart+13] = flags

	binary.BigEndian.PutUint16(buf[tcpStart+14:tcpStart+16], winSize)
	binary.BigEndian.PutUint16(buf[tcpStart+16:tcpStart+18], 0) // Checksum initially 0
	binary.BigEndian.PutUint16(buf[tcpStart+18:tcpStart+20], 0) // Urgent pointer

	// Write TCP Options
	if f.SYN {
		// Option 1: MSS. Type 2, Length 4, Value 1460 (0x05b4)
		buf[tcpStart+20] = 2
		buf[tcpStart+21] = 4
		binary.BigEndian.PutUint16(buf[tcpStart+22:tcpStart+24], 1460)

		// Option 2: SACK Permitted. Type 4, Length 2
		buf[tcpStart+24] = 4
		buf[tcpStart+25] = 2

		// Option 3: Timestamps. Type 8, Length 10, TSval, TSecr
		buf[tcpStart+26] = 8
		buf[tcpStart+27] = 10
		binary.BigEndian.PutUint32(buf[tcpStart+28:tcpStart+32], tsVal)
		binary.BigEndian.PutUint32(buf[tcpStart+32:tcpStart+36], tsEcr)

		// Option 4: Nop. Type 1
		buf[tcpStart+36] = 1

		// Option 5: Window Scale. Type 3, Length 3, Value 8
		buf[tcpStart+37] = 3
		buf[tcpStart+38] = 3
		buf[tcpStart+39] = 8
	} else {
		// Option 1: Nop
		buf[tcpStart+20] = 1
		// Option 2: Nop
		buf[tcpStart+21] = 1
		// Option 3: Timestamps. Type 8, Length 10, TSval, TSecr
		buf[tcpStart+22] = 8
		buf[tcpStart+23] = 10
		binary.BigEndian.PutUint32(buf[tcpStart+24:tcpStart+28], tsVal)
		binary.BigEndian.PutUint32(buf[tcpStart+28:tcpStart+32], tsEcr)
	}

	// 4. Copy Payload
	if len(payload) > 0 {
		copy(buf[tcpStart+tcpLen:], payload)
	}

	// 5. Compute and write TCP Checksum using the pseudo-header and the contiguous TCP segment
	var pseudo [40]byte
	var pseudoSlice []byte
	if isIPv4 {
		copy(pseudo[0:4], srcIP.To4())
		copy(pseudo[4:8], dstIP.To4())
		pseudo[8] = 0
		pseudo[9] = 6 // TCP Protocol
		binary.BigEndian.PutUint16(pseudo[10:12], uint16(tcpLen+len(payload)))
		pseudoSlice = pseudo[:12]
	} else {
		copy(pseudo[0:16], srcIP.To16())
		copy(pseudo[16:32], dstIP.To16())
		binary.BigEndian.PutUint32(pseudo[32:36], uint32(tcpLen+len(payload)))
		pseudo[36] = 0
		pseudo[37] = 0
		pseudo[38] = 0
		pseudo[39] = 6 // TCP Protocol
		pseudoSlice = pseudo[:40]
	}

	tcpSegment := buf[tcpStart : tcpStart+tcpLen+len(payload)]
	tcpChecksum := checksumMultiple(pseudoSlice, tcpSegment)
	binary.BigEndian.PutUint16(buf[tcpStart+16:tcpStart+18], tcpChecksum)

	// Inject the packet
	flog.Tracef("send %s:%d -> %s:%d syn=%v ack=%v rst=%v psh=%v seq=%d payload=%d",
		srcIP, srcPort, dstIP, dstPort, f.SYN, f.ACK, f.RST, f.PSH, seq, len(payload))
	err := h.injector.WritePacketData(buf[:totalLen])
	if err != nil {
		if strings.Contains(err.Error(), "device attached to the system is not functioning") {
			if reopenErr := h.reopen(); reopenErr != nil {
				flog.Errorf("Failed to reopen injection handle: %v", reopenErr)
			}

			h.errMu.Lock()
			if time.Since(h.lastErrTime) > 5*time.Second {
				flog.Errorf("Packet injection failed (device error), attempting recovery: %v", err)
				h.lastErrTime = time.Now()
			}
			h.errMu.Unlock()
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
	case "ebpf", "ebpf-generic":
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

// randIPFromCIDR generates a random IP address from a given CIDR.
func randIPFromCIDR(cidr *net.IPNet) net.IP {
	if cidr.IP.To4() != nil {
		// IPv4
		mask := cidr.Mask
		netAddr := binary.BigEndian.Uint32(cidr.IP.To4())

		ones, bits := mask.Size()
		if ones == bits { // /32
			return cidr.IP
		}

		hostBits := bits - ones
		numHosts := uint32(1) << hostBits

		// Generate a random offset within the host range
		randOffset, err := rand.Int(rand.Reader, big.NewInt(int64(numHosts)))
		if err != nil {
			// Fallback for safety, though crypto/rand should not fail here
			randOffset = big.NewInt(int64(randUint32() % numHosts))
		}

		// Add offset to network address
		randIPint := netAddr + uint32(randOffset.Int64())

		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, randIPint)
		return ip
	} else {
		// IPv6
		mask := cidr.Mask

		randBytes := make([]byte, 16)
		rand.Read(randBytes) // Generate 16 random bytes

		ip := make(net.IP, 16)
		for i := 0; i < 16; i++ {
			// Combine network part (from cidr.IP) with random host part
			ip[i] = (cidr.IP[i] & mask[i]) | (randBytes[i] &^ mask[i])
		}
		return ip
	}
}

func pickRandomIP(isIPv4 bool, ips []net.IP, nets []*net.IPNet) net.IP {
	var validIPs []net.IP
	var validNets []*net.IPNet

	for _, ip := range ips {
		if (ip.To4() != nil) == isIPv4 {
			validIPs = append(validIPs, ip)
		}
	}
	for _, n := range nets {
		if (n.IP.To4() != nil) == isIPv4 {
			validNets = append(validNets, n)
		}
	}

	totalChoices := len(validIPs) + len(validNets)
	if totalChoices == 0 {
		return nil
	}

	choice, _ := rand.Int(rand.Reader, big.NewInt(int64(totalChoices)))
	idx := int(choice.Int64())

	if idx < len(validIPs) {
		return validIPs[idx]
	} else {
		netIdx := idx - len(validIPs)
		return randIPFromCIDR(validNets[netIdx])
	}
}

func (h *SendHandle) getSpoofedIP(isIPv4 bool, dstIP net.IP) net.IP {
	for _, rule := range h.targetSpoofRules {
		if (rule.targetNet != nil && rule.targetNet.Contains(dstIP)) || (rule.targetIP != nil && rule.targetIP.Equal(dstIP)) {
			ip := pickRandomIP(isIPv4, rule.spoofIPs, rule.spoofNets)
			if ip != nil {
				return ip
			}
		}
	}
	return pickRandomIP(isIPv4, h.spoofIPs, h.spoofNets)
}

// hasSpoofing reports whether any source-IP spoofing is configured.
func (h *SendHandle) hasSpoofing() bool {
	return len(h.spoofIPs) > 0 || len(h.spoofNets) > 0 || len(h.targetSpoofRules) > 0
}

// resolveSrcIP returns the source IP for an outbound packet to dstIP, applying
// per-target and global spoofing rules exactly as the data path does.
func (h *SendHandle) resolveSrcIP(isIPv4 bool, dstIP net.IP) (net.IP, bool) {
	var srcIP net.IP
	if isIPv4 {
		srcIP = h.srcIPv4
	} else {
		srcIP = h.srcIPv6
	}
	if h.hasSpoofing() {
		if spoofedIP := h.getSpoofedIP(isIPv4, dstIP); spoofedIP != nil {
			return spoofedIP, true
		}
	}
	return srcIP, false
}

func (h *SendHandle) getFlowState(srcIP net.IP, srcPort int, dstIP net.IP, dstPort uint16) *flowState {
	key := srcIP.String() + ":" + strconv.Itoa(srcPort) + "->" + dstIP.String() + ":" + strconv.Itoa(int(dstPort))
	h.statesMu.Lock()
	defer h.statesMu.Unlock()

	if state, ok := h.spoofStates[key]; ok {
		return state
	}

	if len(h.spoofStates) > 4096 {
		clear(h.spoofStates)
	}

	state := &flowState{
		ipId:   randUint32(),
		baseTS: randUint32(),
		seq:    randUint32(),
	}
	h.spoofStates[key] = state
	return state
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
	if len(h.tcpF.clientTCPF) > 4096 {
		clear(h.tcpF.clientTCPF)
	}
	h.tcpF.clientTCPF[hash.IPAddr(a.IP, uint16(a.Port))] = &iterator.Iterator[conf.TCPF]{Items: f}
	h.tcpF.mu.Unlock()
}

func (h *SendHandle) UpdateRemoteFlow(srcIP net.IP, srcPort int, dstIP net.IP, dstPort int, remoteSeq uint32, remoteAck uint32, payloadLen uint32, tsVal uint32) {
	// The incoming packet arrived from (srcIP:srcPort) to our local (dstIP:dstPort).
	// Our corresponding outgoing flow is keyed by (dstIP:dstPort -> srcIP:srcPort).
	state := h.getFlowState(dstIP, dstPort, srcIP, uint16(srcPort))

	// Sync our sequence number to the remote's ACK to prevent massive TCP AckNum jumps
	// when the first reply arrives, which stateful firewalls drop as out-of-state.
	// This must ONLY be done on the server, since the client initiated the connection
	// and its state.seq is already correct.
	if atomic.LoadUint32(&state.hasRemote) == 0 && remoteAck > 0 && h.role == "server" {
		atomic.StoreUint32(&state.seq, remoteAck)
	}

	atomic.StoreUint32(&state.remoteSeq, remoteSeq)
	atomic.StoreUint32(&state.remoteLen, payloadLen)
	if tsVal > 0 {
		atomic.StoreUint32(&state.remoteTSval, tsVal)
	}
	atomic.StoreUint32(&state.hasRemote, 1)
}

func (h *SendHandle) SendSYNACK(remoteIP net.IP, remotePort int, localPort int, clientSeq uint32, clientTSval uint32) error {
	addr := &net.UDPAddr{IP: remoteIP, Port: remotePort}
	isIPv4 := remoteIP.To4() != nil
	var srcIP net.IP
	if isIPv4 {
		srcIP = h.srcIPv4
	} else {
		srcIP = h.srcIPv6
	}

	state := h.getFlowState(srcIP, localPort, remoteIP, uint16(remotePort))
	atomic.StoreUint32(&state.remoteSeq, clientSeq+1)
	atomic.StoreUint32(&state.remoteLen, 0)
	if clientTSval > 0 {
		atomic.StoreUint32(&state.remoteTSval, clientTSval)
	}
	atomic.StoreUint32(&state.hasRemote, 1)

	synAckF := conf.TCPF{SYN: true, ACK: true}
	return h.writeRaw(nil, addr, localPort, synAckF, srcIP, isIPv4, false, state)
}

func (h *SendHandle) SendACK(remoteIP net.IP, remotePort int, localPort int, serverSeq uint32, serverTSval uint32) error {
	addr := &net.UDPAddr{IP: remoteIP, Port: remotePort}
	isIPv4 := remoteIP.To4() != nil
	var srcIP net.IP
	if isIPv4 {
		srcIP = h.srcIPv4
	} else {
		srcIP = h.srcIPv6
	}

	state := h.getFlowState(srcIP, localPort, remoteIP, uint16(remotePort))
	atomic.StoreUint32(&state.remoteSeq, serverSeq+1)
	atomic.StoreUint32(&state.remoteLen, 0)
	if serverTSval > 0 {
		atomic.StoreUint32(&state.remoteTSval, serverTSval)
	}
	atomic.StoreUint32(&state.hasRemote, 1)

	ackF := conf.TCPF{ACK: true}
	return h.writeRaw(nil, addr, localPort, ackF, srcIP, isIPv4, false, state)
}

// SendRST emits a bare fake-TCP RST from this handle's source port to the
// remote. Clients use it as an orderly goodbye so the server's RST handler
// tears the orphaned flow down immediately instead of retransmitting for the
// full KCP DeadLink (~30s). Skipped when source-IP spoofing is active: the
// source IP is ephemeral there, so the RST can't reliably match the server's
// session key and would risk leaking the real IP — the server falls back to
// DeadLink teardown.
func (h *SendHandle) SendRST(remoteIP net.IP, remotePort int) error {
	if h.hasSpoofing() {
		return nil
	}
	addr := &net.UDPAddr{IP: remoteIP, Port: remotePort}
	isIPv4 := remoteIP.To4() != nil
	var srcIP net.IP
	if isIPv4 {
		srcIP = h.srcIPv4
	} else {
		srcIP = h.srcIPv6
	}

	state := h.getFlowState(srcIP, int(h.srcPort), remoteIP, uint16(remotePort))
	rstF := conf.TCPF{RST: true, ACK: true}
	return h.writeRaw(nil, addr, int(h.srcPort), rstF, srcIP, isIPv4, false, state)
}

func (h *SendHandle) PrewarmFlow(dstIP net.IP, dstPort uint16) {
	if !h.handshake || dstIP == nil {
		return
	}
	isIPv4 := dstIP.To4() != nil
	var srcIP net.IP
	if isIPv4 {
		srcIP = h.srcIPv4
	} else {
		srcIP = h.srcIPv6
	}

	state := h.getFlowState(srcIP, int(h.srcPort), dstIP, dstPort)
	if atomic.CompareAndSwapUint32(&state.synSent, 0, 1) {
		addr := &net.UDPAddr{IP: dstIP, Port: int(dstPort)}
		synF := conf.TCPF{SYN: true}
		_ = h.writeRaw(nil, addr, int(h.srcPort), synF, srcIP, isIPv4, false, state)

		// Background retry if SYN is dropped by network jitter
		go func() {
			for i := 0; i < 4; i++ {
				time.Sleep(150 * time.Millisecond)
				if atomic.LoadUint32(&state.hasRemote) == 1 {
					return
				}
				_ = h.writeRaw(nil, addr, int(h.srcPort), synF, srcIP, isIPv4, false, state)
			}
		}()
	}
}

func (h *SendHandle) IsFlowWarmed(dstIP net.IP, dstPort uint16) bool {
	if !h.handshake || dstIP == nil {
		return true
	}
	isIPv4 := dstIP.To4() != nil
	var srcIP net.IP
	if isIPv4 {
		srcIP = h.srcIPv4
	} else {
		srcIP = h.srcIPv6
	}
	state := h.getFlowState(srcIP, int(h.srcPort), dstIP, dstPort)
	return atomic.LoadUint32(&state.hasRemote) == 1
}

// WaitFlowWarm blocks until the SYN-ACK for the given flow has been received
// (handshake complete) or timeout elapses. Used by lazy warm-up mode so the
// fake handshake finishes before the first data packet is sent. Returns early
// when the handshake is disabled or the flow is already warmed.
func (h *SendHandle) WaitFlowWarm(dstIP net.IP, dstPort uint16, timeout time.Duration) {
	if !h.handshake || dstIP == nil {
		return
	}
	isIPv4 := dstIP.To4() != nil
	var srcIP net.IP
	if isIPv4 {
		srcIP = h.srcIPv4
	} else {
		srcIP = h.srcIPv6
	}
	state := h.getFlowState(srcIP, int(h.srcPort), dstIP, dstPort)
	deadline := time.Now().Add(timeout)
	for atomic.LoadUint32(&state.hasRemote) == 0 {
		if time.Now().After(deadline) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
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

func (h *SendHandle) ResetFlow() {
	if h.role == "client" && h.globalState != nil {
		atomic.StoreUint32(&h.globalState.hasRemote, 0)
		atomic.StoreUint32(&h.globalState.synSent, 0)
		atomic.StoreUint32(&h.globalState.seq, randUint32())
		atomic.StoreUint32(&h.globalState.baseTS, randUint32())
		atomic.StoreUint32(&h.globalState.tsCounter, 0)
		atomic.StoreUint32(&h.globalState.ipId, randUint32())
	}
}

