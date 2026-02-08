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
	source PacketSource
}

func NewRecvHandle(cfg *conf.Network, hopping *conf.Hopping) (*RecvHandle, error) {
	var source PacketSource
	var err error

	switch cfg.Driver {
	case "ebpf":
		source, err = newEBPFSource(cfg, hopping)
	default:
		source, err = newPcapSource(cfg, hopping)
	}

	if err != nil {
		return nil, err
	}

	return &RecvHandle{source: source}, nil
}

func (h *RecvHandle) Read() ([]byte, net.Addr, int, error) {
	data, err := h.source.ReadPacketData()
	if err != nil {
		return nil, nil, 0, err
	}
	p := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)

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
