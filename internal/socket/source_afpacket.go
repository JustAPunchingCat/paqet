package socket

import (
	"fmt"
	"paqet/internal/conf"
	"strings"
)

type afpacketSource struct {
	handle RawHandle
}

func newAfpacketSource(cfg *conf.Network, hopping *conf.Hopping) (PacketSource, error) {
	handle, err := newAfpacketHandle(cfg)
	if err != nil {
		return nil, err
	}

	if err := handle.SetDirection(DirectionIn); err != nil {
		handle.Close()
		return nil, err
	}

	// Construct BPF filter to prevent waking up for every packet on the interface
	// Base filter: TCP
	filterParts := []string{"tcp"}

	// IP Filter: Only wake up for packets destined to our configured IPs
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
			portFilter = fmt.Sprintf("(%s)", strings.Join(parts, " or "))
		}
	}
	filterParts = append(filterParts, portFilter)

	filter := strings.Join(filterParts, " and ")

	// Apply the filter if the handle supports it
	if h, ok := handle.(interface{ SetBPFFilter(string) error }); ok {
		if err := h.SetBPFFilter(filter); err != nil {
			handle.Close()
			return nil, fmt.Errorf("failed to set BPF filter: %w", err)
		}
	}

	s := &afpacketSource{
		handle: handle,
	}

	return s, nil
}

func (s *afpacketSource) ReadPacketData() ([]byte, error) {
	for {
		data, _, err := s.handle.ZeroCopyReadPacketData()
		if err != nil {
			return nil, err
		}

		// Return a copy because the ring buffer slot will be reused
		return append([]byte(nil), data...), nil
	}
}

func (s *afpacketSource) Close() {
	s.handle.Close()
}
