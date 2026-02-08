package socket

import (
	"fmt"
	"net"
	"paqet/internal/conf"
	"runtime"
	"strings"

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
		ranges, err := hopping.GetRanges()
		if err == nil && len(ranges) > 0 {
			var parts []string
			for _, r := range ranges {
				if r.Min == r.Max {
					parts = append(parts, fmt.Sprintf("dst port %d", r.Min))
				} else {
					parts = append(parts, fmt.Sprintf("dst portrange %d-%d", r.Min, r.Max))
				}
			}
			filter = fmt.Sprintf("tcp and (%s)", strings.Join(parts, " or "))
		}
	}
	if err := handle.SetBPFFilter(filter); err != nil {
		return nil, fmt.Errorf("failed to set BPF filter: %w", err)
	}

	return &RecvHandle{handle: handle}, nil
}

func (h *RecvHandle) Read() ([]byte, net.Addr, int, error) {
	data, _, err := h.handle.ReadPacketData()
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
	if h.handle != nil {
		h.handle.Close()
	}
}
