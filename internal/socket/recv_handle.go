package socket

import (
	"fmt"
	"net"
	"paqet/internal/conf"
	"runtime"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
)

type RecvHandle struct {
	handle *pcap.Handle
}

func NewRecvHandle(cfg *conf.Network, hopping *conf.Hopping) (*RecvHandle, error) {
	handle, err := newHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap handle: %w", err)
	}

	// SetDirection is not fully supported on Windows Npcap, so skip it
	if runtime.GOOS != "windows" {
		if err := handle.SetDirection(pcap.DirectionIn); err != nil {
			return nil, fmt.Errorf("failed to set pcap direction in: %v", err)
		}
	}

	filter := fmt.Sprintf("tcp and dst port %d", cfg.Port)
	if hopping != nil && hopping.Enabled {
		filter = fmt.Sprintf("tcp and dst portrange %d-%d", hopping.Min, hopping.Max)
	}
	if err := handle.SetBPFFilter(filter); err != nil {
		return nil, fmt.Errorf("failed to set BPF filter: %w", err)
	}

	return &RecvHandle{handle: handle}, nil
}

func (h *RecvHandle) Read() ([]byte, net.Addr, int, error) {
	data, _, err := h.handle.ZeroCopyReadPacketData()
	if err != nil {
		return nil, nil, 0, err
	}

	addr := &net.UDPAddr{}
	var dstPort int
	p := gopacket.NewPacket(data, layers.LayerTypeEthernet, gopacket.NoCopy)

	netLayer := p.NetworkLayer()
	if netLayer == nil {
		return nil, addr, 0, nil
	}
	switch netLayer.LayerType() {
	case layers.LayerTypeIPv4:
		addr.IP = netLayer.(*layers.IPv4).SrcIP
	case layers.LayerTypeIPv6:
		addr.IP = netLayer.(*layers.IPv6).SrcIP
	}

	trLayer := p.TransportLayer()
	if trLayer == nil {
		return nil, addr, 0, nil
	}
	switch trLayer.LayerType() {
	case layers.LayerTypeTCP:
		tcp := trLayer.(*layers.TCP)
		addr.Port = int(tcp.SrcPort)
		dstPort = int(tcp.DstPort)
	case layers.LayerTypeUDP:
		udp := trLayer.(*layers.UDP)
		addr.Port = int(udp.SrcPort)
		dstPort = int(udp.DstPort)
	}

	appLayer := p.ApplicationLayer()
	if appLayer == nil {
		return nil, addr, 0, nil
	}
	return appLayer.Payload(), addr, dstPort, nil
}

func (h *RecvHandle) Close() {
	if h.handle != nil {
		h.handle.Close()
	}
}
