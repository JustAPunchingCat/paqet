package socket

import (
	"net"
	"paqet/internal/conf"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
)

type PacketSource interface {
	ReadPacketData() ([]byte, error)
	Close()
}

type RecvHandle struct {
	source     PacketSource
	driver     string
	SkipDecode bool
	RemoteAddr net.Addr
	LocalPort  int
}

func NewRecvHandle(cfg *conf.Network, hopping *conf.Hopping) (*RecvHandle, error) {
	var source PacketSource
	var err error

	switch cfg.Driver {
	case "ebpf":
		source, err = newEBPFSource(cfg, hopping)
	case "tun":
		source, err = newTunSource(cfg, hopping)
	default:
		source, err = newPcapSource(cfg, hopping)
	}

	if err != nil {
		return nil, err
	}

	return &RecvHandle{source: source, driver: cfg.Driver}, nil
}

func (h *RecvHandle) Read() ([]byte, net.Addr, int, error) {
	data, err := h.source.ReadPacketData()
	if err != nil {
		return nil, nil, 0, err
	}

	if h.SkipDecode {
		// If using netstack, we already have the payload.
		// We return the fixed remote address associated with the connection.
		// Note: dstPort (local port) is returned as h.LocalPort
		return data, h.RemoteAddr, h.LocalPort, nil
	}

	var decoder gopacket.Decoder
	if h.driver == "tun" {
		// TUN delivers raw IP packets. Check version from first byte.
		if len(data) > 0 {
			if data[0]>>4 == 6 {
				decoder = layers.LayerTypeIPv6
			} else {
				decoder = layers.LayerTypeIPv4
			}
		}
	} else {
		decoder = layers.LayerTypeEthernet
	}
	p := gopacket.NewPacket(data, decoder, gopacket.NoCopy)

	netLayer := p.NetworkLayer()
	if netLayer == nil {
		return nil, nil, 0, nil
	}

	addr := &net.UDPAddr{}
	switch netLayer.LayerType() {
	case layers.LayerTypeIPv4:
		addr.IP = netLayer.(*layers.IPv4).SrcIP
	case layers.LayerTypeIPv6:
		addr.IP = netLayer.(*layers.IPv6).SrcIP
	default:
		return nil, nil, 0, nil
	}

	trLayer := p.TransportLayer()
	if trLayer == nil {
		return nil, nil, 0, nil
	}

	var dstPort int
	switch trLayer.LayerType() {
	case layers.LayerTypeTCP:
		tcp := trLayer.(*layers.TCP)
		addr.Port = int(tcp.SrcPort)
		dstPort = int(tcp.DstPort)
	case layers.LayerTypeUDP:
		udp := trLayer.(*layers.UDP)
		addr.Port = int(udp.SrcPort)
		dstPort = int(udp.DstPort)
	default:
		return nil, nil, 0, nil
	}

	if addr.Port == 0 {
		return nil, nil, 0, nil
	}

	appLayer := p.ApplicationLayer()
	if appLayer == nil {
		return nil, nil, 0, nil
	}
	return appLayer.Payload(), addr, dstPort, nil
}

func (h *RecvHandle) Close() {
	if h.source != nil {
		h.source.Close()
	}
}
