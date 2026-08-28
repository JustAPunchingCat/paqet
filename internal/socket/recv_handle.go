package socket

import (
	"encoding/binary"
	"net"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"sync"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type PacketSource interface {
	ReadPacketData() ([]byte, error)
	Close()
}

type ipMapping struct {
	network *net.IPNet
	realIP  net.IP
}

type RecvHandle struct {
	source      PacketSource
	decoderPool sync.Pool
	mappings    []ipMapping
	allowedIPs  []net.IP
	allowedNets []*net.IPNet
	flowUpdater FlowUpdater
	handshake   bool
	role        string
}

func (h *RecvHandle) SetFlowUpdater(u FlowUpdater) {
	h.flowUpdater = u
}

// isAllowed reports whether ip is permitted by the client allowlist.
// An empty allowlist means "allow all".
func (h *RecvHandle) isAllowed(ip net.IP) bool {
	if len(h.allowedIPs) == 0 && len(h.allowedNets) == 0 {
		return true
	}
	for _, a := range h.allowedIPs {
		if a.Equal(ip) {
			return true
		}
	}
	for _, n := range h.allowedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

type packetDecoder struct {
	eth     layers.Ethernet
	ip4     layers.IPv4
	ip6     layers.IPv6
	tcp     layers.TCP
	udp     layers.UDP
	payload gopacket.Payload
	parser  *gopacket.DecodingLayerParser
	decoded []gopacket.LayerType
}

func NewRecvHandle(cfg *conf.Network, hopping *conf.Hopping, role string) (*RecvHandle, error) {
	var source PacketSource
	var err error

	switch cfg.Driver {
	case "ebpf", "ebpf-generic":
		source, err = newEBPFSource(cfg, hopping)
	case "afpacket":
		source, err = newAfpacketSource(cfg, hopping)
	default:
		source, err = newPcapSource(cfg, hopping)
	}

	if err != nil {
		return nil, err
	}

	var mappings []ipMapping
	if cfg.Spoof != nil && cfg.Spoof.Enabled {
		var targetMap map[string][]string
		if role == "client" {
			targetMap = cfg.Spoof.ServerMappings
		} else {
			targetMap = cfg.Spoof.ClientMappings
		}
		for spoofStr, realStrs := range targetMap {
			if len(realStrs) == 0 {
				continue
			}
			realStr := realStrs[0] // Use the first real IP for consistent reverse mapping
			realIP := net.ParseIP(realStr)
			if realIP == nil {
				flog.Warnf("Invalid real IP in spoof mapping: %s", realStr)
				continue
			}
			_, spoofNet, err := net.ParseCIDR(spoofStr)
			if err != nil {
				spoofIP := net.ParseIP(spoofStr)
				if spoofIP == nil {
					flog.Warnf("Invalid spoof IP/CIDR in mapping: %s", spoofStr)
					continue
				}
				var mask net.IPMask
				if spoofIP.To4() != nil {
					mask = net.CIDRMask(32, 32)
				} else {
					mask = net.CIDRMask(128, 128)
				}
				spoofNet = &net.IPNet{IP: spoofIP, Mask: mask}
			}
			mappings = append(mappings, ipMapping{network: spoofNet, realIP: realIP})
		}

		if len(mappings) > 0 {
			flog.Infof("Incoming IP spoofing reverse-mapping enabled with %d rules.", len(mappings))
		}
	}

	var allowedIPs []net.IP
	var allowedNets []*net.IPNet
	for _, s := range cfg.AllowedClientIPs {
		_, ipNet, err := net.ParseCIDR(s)
		if err == nil {
			allowedNets = append(allowedNets, ipNet)
		} else if ip := net.ParseIP(s); ip != nil {
			allowedIPs = append(allowedIPs, ip)
		} else {
			flog.Warnf("Invalid IP/CIDR in allowed_client_ips: %s", s)
		}
	}

	hs := cfg.Handshake
	if hs == nil {
		hs = &conf.Handshake{}
	}

	return &RecvHandle{
		source:      source,
		mappings:    mappings,
		allowedIPs:  allowedIPs,
		allowedNets: allowedNets,
		handshake:   hs.IsEnabled(),
		decoderPool: sync.Pool{
			New: func() any {
				d := &packetDecoder{
					decoded: make([]gopacket.LayerType, 0, 4),
				}
				d.parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &d.eth, &d.ip4, &d.ip6, &d.tcp, &d.udp, &d.payload)
				return d
			},
		},
		role: role,
	}, nil
}

func (h *RecvHandle) Read() ([]byte, net.Addr, int, error) {
	data, err := h.source.ReadPacketData()
	if err != nil {
		return nil, nil, 0, err
	}

	if len(data) < 20 {
		return nil, nil, 0, nil
	}

	var ipStart int
	var isIPv4 bool
	var ipLen int
	var srcIP, dstIP net.IP
	var protocol byte

	var hasEthernet bool
	// Check if there is an Ethernet header by parsing EtherType
	ipStart = 0
	if len(data) >= 14 {
		hasEthernet = true
		etherType := binary.BigEndian.Uint16(data[12:14])
		offset := 14

		// Handle VLANs (802.1Q: 0x8100, 802.1ad: 0x88A8)
		for etherType == 0x8100 || etherType == 0x88a8 {
			if len(data) < offset+4 {
				return nil, nil, 0, nil
			}
			etherType = binary.BigEndian.Uint16(data[offset+2 : offset+4])
			offset += 4
		}

		if etherType == 0x0800 {
			ipStart = offset
			isIPv4 = true
		} else if etherType == 0x86dd {
			ipStart = offset
			isIPv4 = false
		} else {
			// It has an ethernet header but is not IPv4/IPv6 (e.g., ARP)
			return nil, nil, 0, nil
		}
	}

	if !hasEthernet {
		// Fallback for direct IP (no Ethernet header, e.g. TUN)
		version := data[0] >> 4
		if version == 4 {
			ipStart = 0
			isIPv4 = true
		} else if version == 6 {
			ipStart = 0
			isIPv4 = false
		} else {
			return nil, nil, 0, nil // Unsupported link type or protocol
		}
	}

	if isIPv4 {
		if len(data) < ipStart+20 {
			return nil, nil, 0, nil
		}
		versionIHL := data[ipStart]
		version := versionIHL >> 4
		if version != 4 {
			return nil, nil, 0, nil
		}
		ihl := versionIHL & 0x0f
		ipLen = int(ihl) * 4
		if len(data) < ipStart+ipLen {
			return nil, nil, 0, nil
		}
		protocol = data[ipStart+9]
		srcIP = net.IP(data[ipStart+12 : ipStart+16])
		dstIP = net.IP(data[ipStart+16 : ipStart+20])
	} else {
		// IPv6
		if len(data) < ipStart+40 {
			return nil, nil, 0, nil
		}
		version := data[ipStart] >> 4
		if version != 6 {
			return nil, nil, 0, nil
		}
		ipLen = 40
		protocol = data[ipStart+6]
		srcIP = net.IP(data[ipStart+8 : ipStart+24])
		dstIP = net.IP(data[ipStart+24 : ipStart+40])
	}

	// Enforce the client allowlist against the raw wire source IP before
	// responding to anything (the stateless SYN-ACK handshake included), so
	// scanners and unknown IPs never get a reply. The allowlist is the single
	// source of truth and does NOT consult spoof mappings. An empty allowlist
	// means "allow all".
	if !h.isAllowed(srcIP) {
		return nil, nil, 0, nil
	}

	// Reverse-map a spoofed source IP to the real client IP for session routing
	// (the KCP session address). The allowlist check above deliberately uses the
	// raw source IP.
	realIP := srcIP
	if len(h.mappings) > 0 {
		for _, m := range h.mappings {
			if m.network.Contains(srcIP) {
				realIP = m.realIP
				break
			}
		}
	}

	// Only process TCP (6) or UDP (17)
	if protocol != 6 && protocol != 17 {
		return nil, nil, 0, nil
	}

	transStart := ipStart + ipLen
	if len(data) < transStart+4 {
		return nil, nil, 0, nil
	}

	srcPort := int(binary.BigEndian.Uint16(data[transStart : transStart+2]))
	dstPort := int(binary.BigEndian.Uint16(data[transStart+2 : transStart+4]))

	var payload []byte
	if protocol == 6 { // TCP
		if len(data) < transStart+20 {
			return nil, nil, 0, nil
		}
		remoteSeq := binary.BigEndian.Uint32(data[transStart+4 : transStart+8])
		remoteAck := binary.BigEndian.Uint32(data[transStart+8 : transStart+12])
		dataOffset := data[transStart+12] >> 4
		tcpLen := int(dataOffset) * 4
		if len(data) < transStart+tcpLen {
			return nil, nil, 0, nil
		}
		payload = data[transStart+tcpLen:]

		tcpFlags := data[transStart+13]
		isSYN := tcpFlags&0x02 != 0
		isACK := tcpFlags&0x10 != 0
		isRST := tcpFlags&0x04 != 0
		isFIN := tcpFlags&0x01 != 0

		flog.Tracef("recv %s:%d -> %s:%d flags=0x%02x syn=%v ack=%v rst=%v payload=%d",
			srcIP, srcPort, dstIP, dstPort, tcpFlags, isSYN, isACK, isRST, len(data)-transStart-tcpLen)

		// On clients, RST signifies the server's OS rejected our packet (e.g. server restarted and lost flow state).
		// Returning ErrClosed forcefully terminates the KCP session and triggers an immediate reconnect,
		// preventing the client from hanging for 30s while KCP DeadLink times out.
		// On servers, we ignore RSTs since PacketConn is shared across all clients.
		if isRST || isFIN {
			addr := &net.UDPAddr{
				IP:   srcIP,
				Port: srcPort,
			}
			return nil, addr, dstPort, ErrRST
		}

		if h.flowUpdater != nil {
			var tsVal uint32
			if tcpLen > 20 {
				optStart := transStart + 20
				optEnd := transStart + tcpLen
				for i := optStart; i < optEnd; {
					kind := data[i]
					if kind == 0 {
						break
					}
					if kind == 1 {
						i++
						continue
					}
					if i+1 >= optEnd {
						break
					}
					length := int(data[i+1])
					if length < 2 || i+length > optEnd {
						break
					}
					if kind == 8 && length == 10 && i+6 <= optEnd {
						tsVal = binary.BigEndian.Uint32(data[i+2 : i+6])
					}
					i += length
				}
			}
			h.flowUpdater.UpdateRemoteFlow(srcIP, srcPort, dstIP, dstPort, remoteSeq, remoteAck, uint32(len(payload)), tsVal)

			if h.handshake {
				if isSYN && !isACK && len(payload) == 0 {
					// Server received Client SYN -> Send SYN-ACK
					_ = h.flowUpdater.SendSYNACK(srcIP, srcPort, dstPort, remoteSeq, tsVal)
				} else if isSYN && isACK && len(payload) == 0 {
					// Client received Server SYN-ACK -> Send ACK
					_ = h.flowUpdater.SendACK(srcIP, srcPort, dstPort, remoteSeq, tsVal)
				}
			}
		}
	} else { // UDP
		if len(data) < transStart+8 {
			return nil, nil, 0, nil
		}
		udpLen := int(binary.BigEndian.Uint16(data[transStart+4 : transStart+6]))
		if len(data) < transStart+8 || udpLen < 8 {
			return nil, nil, 0, nil
		}
		pEnd := transStart + udpLen
		if pEnd > len(data) {
			pEnd = len(data)
		}
		payload = data[transStart+8 : pEnd]
	}

	addr := &net.UDPAddr{
		IP:   realIP,
		Port: srcPort,
	}

	if len(payload) == 0 {
		return nil, addr, dstPort, nil
	}

	return payload, addr, dstPort, nil
}

func (h *RecvHandle) Close() {
	if h.source != nil {
		h.source.Close()
	}
}
