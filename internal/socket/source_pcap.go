package socket

import (
	"fmt"
	"paqet/internal/conf"
	"runtime"
	"strings"

	"github.com/gopacket/gopacket/pcap"
)

type PcapSource struct {
	handle *pcap.Handle
}

func newPcapSource(cfg *conf.Network, hopping *conf.Hopping) (PacketSource, error) {
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

	return &PcapSource{handle: handle}, nil
}

func (s *PcapSource) ReadPacketData() ([]byte, error) {
	data, _, err := s.handle.ReadPacketData()
	return data, err
}

func (s *PcapSource) Close() {
	s.handle.Close()
}
