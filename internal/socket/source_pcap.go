//go:build !nopcap

package socket

import (
	"fmt"
	"paqet/internal/conf"
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

	// We do not set DirectionIn because in Gateway modes (where paqet binds to the LAN interface
	// but receives NAT'd packets from the WAN interface), the server's replies will appear as
	// outgoing packets on the LAN interface. Since we strictly filter by `dst host <our_ip>`,
	// we will never capture our own injected packets anyway.

	// Base filter: TCP
	filterParts := []string{"tcp"}

	// IP Filter
	var ipFilters []string
	if cfg.IPv4.Addr != nil && !cfg.IPv4.Addr.IP.IsUnspecified() {
		ipFilters = append(ipFilters, fmt.Sprintf("dst host %s", cfg.IPv4.Addr.IP.String()))
	}
	if cfg.IPv6.Addr != nil && !cfg.IPv6.Addr.IP.IsUnspecified() {
		ipFilters = append(ipFilters, fmt.Sprintf("dst host %s", cfg.IPv6.Addr.IP.String()))
	}
	if len(ipFilters) > 0 {
		filterParts = append(filterParts, fmt.Sprintf("(%s)", strings.Join(ipFilters, " or ")))
	}

	// Port Filter
	portFilter := fmt.Sprintf("dst port %d", cfg.Port)
	if hopping != nil && hopping.IsEnabled() {
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
			portFilter = fmt.Sprintf("(%s)", strings.Join(parts, " or "))
		}
	}
	filterParts = append(filterParts, portFilter)

	filter := strings.Join(filterParts, " and ")

	if err := handle.SetBPFFilter(filter); err != nil {
		return nil, fmt.Errorf("failed to set BPF filter: %w", err)
	}

	return &PcapSource{handle: handle}, nil
}

func (s *PcapSource) ReadPacketData() ([]byte, error) {
	for {
		data, _, err := s.handle.ReadPacketData()
		if err == pcap.NextErrorTimeoutExpired {
			continue
		}
		return data, err
	}
}

func (s *PcapSource) Close() {
	s.handle.Close()
}
