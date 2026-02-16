package socket

import (
	"net"
	"paqet/internal/conf"
	"sync"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type PacketSource interface {
	ReadPacketData() ([]byte, error)
	Close()
}

type RecvHandle struct {
	source      PacketSource
	decoderPool sync.Pool
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

func NewRecvHandle(cfg *conf.Network, hopping *conf.Hopping) (*RecvHandle, error) {
	var source PacketSource
	var err error

	switch cfg.Driver {
	case "ebpf":
		source, err = newEBPFSource(cfg, hopping)
	case "afpacket":
		source, err = newAfpacketSource(cfg, hopping)
	default:
		source, err = newPcapSource(cfg, hopping)
	}

	if err != nil {
		return nil, err
	}

	return &RecvHandle{
		source: source,
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

	return decoder.payload, addr, dstPort, nil
}

func (h *RecvHandle) Close() {
	if h.source != nil {
		h.source.Close()
	}
}
