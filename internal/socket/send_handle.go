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

type flowState struct {
	ipId      uint32
	baseTS    uint32
	seq       uint32
	tsCounter uint32
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

	tcpF     TCPF
	ethPool  sync.Pool
	ipv4Pool sync.Pool
	ipv6Pool sync.Pool
	tcpPool  sync.Pool
	bufPool  sync.Pool

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

	sh := &SendHandle{
		injector:    injector,
		cfg:         cfg,
		driver:      cfg.Driver,
		srcPort:     uint16(cfg.Port),
		synOptions:  synOptions,
		ackOptions:  ackOptions,
		tcpF:        TCPF{tcpF: iterator.Iterator[conf.TCPF]{Items: cfg.TCP.LF}, clientTCPF: make(map[uint64]*iterator.Iterator[conf.TCPF])},
		time:        uint32(time.Now().UnixNano() / int64(time.Millisecond)),
		tos:         tos,
		ttl:         ttl,
		startTime:   time.Now(),
		globalState: &flowState{ipId: randUint32(), baseTS: randUint32(), seq: randUint32()},
		spoofStates: make(map[string]*flowState),
		nameMapping: make(map[string]string),
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
		flog.Infof("Source IP spoofing enabled with %d IPs and %d networks.", len(sh.spoofIPs), len(sh.spoofNets))
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

	isIPv4 := dstIP.To4() != nil
	var srcIP net.IP
	var isSpoofed bool

	if isIPv4 {
		srcIP = h.srcIPv4
	} else {
		srcIP = h.srcIPv6
	}

	if len(h.spoofIPs) > 0 || len(h.spoofNets) > 0 || len(h.targetSpoofRules) > 0 {
		if spoofedIP := h.getSpoofedIP(isIPv4, dstIP); spoofedIP != nil {
			srcIP = spoofedIP
			isSpoofed = true
			// flog.Debugf("Spoofing packet to %s with source %s", dstIP, spoofedIP)
		}
	}

	var state *flowState
	if isSpoofed {
		state = h.getFlowState(srcIP)
	} else {
		state = h.globalState
	}

	f := h.getClientTCPF(dstIP, dstPort)
	tcpLayer := h.buildTCPHeader(uint16(srcPort), dstPort, f, state)
	defer h.tcpPool.Put(tcpLayer)

	var ipLayer gopacket.SerializableLayer
	if isIPv4 {
		ip := h.buildIPv4Header(srcIP, dstIP, isSpoofed, state)
		defer h.ipv4Pool.Put(ip)
		ipLayer = ip
		tcpLayer.SetNetworkLayerForChecksum(ip)
		if ethLayer != nil {
			ethLayer.DstMAC = h.srcIPv4RHWA
			ethLayer.EthernetType = layers.EthernetTypeIPv4
		}
	} else {
		ip := h.buildIPv6Header(srcIP, dstIP, isSpoofed, state)
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

func (h *SendHandle) getFlowState(ip net.IP) *flowState {
	ipStr := string(ip)
	h.statesMu.Lock()
	defer h.statesMu.Unlock()

	if state, ok := h.spoofStates[ipStr]; ok {
		return state
	}

	state := &flowState{
		ipId:   randUint32(),
		baseTS: randUint32(),
		seq:    randUint32(),
	}
	h.spoofStates[ipStr] = state
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
