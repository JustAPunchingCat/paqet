package socket

import (
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
	if cfg.Spoof != nil {
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
	}

	return &RecvHandle{
		source:   source,
		mappings: mappings,
		decoderPool: sync.Pool{
			New: func() any {
				d := &packetDecoder{
					decoded: make([]gopacket.LayerType, 0, 4),
				}
				d.parser = gopacket.NewDecodingLayerParser(layers.LayerTypeEthernet, &d.eth, &d.ip4, &d.ip6, &d.tcp, &d.udp, &d.payload)
				return d
			},
		},
	}, nil
}

func (h *RecvHandle) Read() ([]byte, net.Addr, int, error) {
	data, err := h.source.ReadPacketData()
	if err != nil {
		return nil, nil, 0, err
	}

	decoder := h.decoderPool.Get().(*packetDecoder)
	defer h.decoderPool.Put(decoder)

	// Reset decoded slice
	decoder.decoded = decoder.decoded[:0]

	// Ignore error because we check decoded layers manually
	_ = decoder.parser.DecodeLayers(data, &decoder.decoded)

	addr := &net.UDPAddr{}
	var dstPort int
	hasTransport := false

	for _, typ := range decoder.decoded {
		switch typ {
		case layers.LayerTypeIPv4:
			addr.IP = decoder.ip4.SrcIP
		case layers.LayerTypeIPv6:
			addr.IP = decoder.ip6.SrcIP
		case layers.LayerTypeTCP:
			addr.Port = int(decoder.tcp.SrcPort)
			dstPort = int(decoder.tcp.DstPort)
			hasTransport = true
		case layers.LayerTypeUDP:
			addr.Port = int(decoder.udp.SrcPort)
			dstPort = int(decoder.udp.DstPort)
			hasTransport = true
		}
	}

	if !hasTransport || addr.Port == 0 || len(decoder.payload) == 0 {
		return nil, nil, 0, nil
	}

	// Overwrite source IP if it matches a spoof mapping
	if len(h.mappings) > 0 {
		for _, m := range h.mappings {
			if m.network.Contains(addr.IP) {
				addr.IP = m.realIP
				break
			}
		}
	}

	return decoder.payload, addr, dstPort, nil
}

func (h *RecvHandle) Close() {
	if h.source != nil {
		h.source.Close()
	}
}
