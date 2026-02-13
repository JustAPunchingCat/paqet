package socket

import (
	"encoding/binary"
	"net"
	"paqet/internal/conf"
)

type afpacketSource struct {
	handle RawHandle
	port   int
	ipv4   net.IP
	ipv6   net.IP
	ranges []conf.PortRange
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

	s := &afpacketSource{
		handle: handle,
		port:   cfg.Port,
	}
	if cfg.IPv4.Addr != nil {
		s.ipv4 = cfg.IPv4.Addr.IP
	}
	if cfg.IPv6.Addr != nil {
		s.ipv6 = cfg.IPv6.Addr.IP
	}

	if hopping != nil && hopping.Enabled {
		if r, err := hopping.GetRanges(); err == nil {
			s.ranges = r
		}
	}

	return s, nil
}

func (s *afpacketSource) ReadPacketData() ([]byte, error) {
	for {
		data, _, err := s.handle.ZeroCopyReadPacketData()
		if err != nil {
			return nil, err
		}

		if !s.filter(data) {
			continue
		}

		// Return a copy because the ring buffer slot will be reused
		return append([]byte(nil), data...), nil
	}
}

func (s *afpacketSource) filter(data []byte) bool {
	if len(data) < 14 {
		return false
	}

	// Parse Ethernet header
	ethType := binary.BigEndian.Uint16(data[12:14])
	var ipOffset int
	var nextProto uint8

	if ethType == 0x0800 { // IPv4
		ipOffset = 14
		if len(data) < ipOffset+20 {
			return false
		}
		// IHL is the lower 4 bits of the first byte
		ihl := data[ipOffset] & 0x0F
		if ihl < 5 {
			return false
		}
		headerLen := int(ihl) * 4
		if len(data) < ipOffset+headerLen {
			return false
		}
		nextProto = data[ipOffset+9]

		if s.ipv4 != nil {
			dstIP := net.IP(data[ipOffset+16 : ipOffset+20])
			if !dstIP.Equal(s.ipv4) {
				return false
			}
		}

		ipOffset += headerLen
	} else if ethType == 0x86DD { // IPv6
		ipOffset = 14
		if len(data) < ipOffset+40 {
			return false
		}
		nextProto = data[ipOffset+6]

		if s.ipv6 != nil {
			dstIP := net.IP(data[ipOffset+24 : ipOffset+40])
			if !dstIP.Equal(s.ipv6) {
				return false
			}
		}

		ipOffset += 40
	} else {
		return false
	}

	// Only filter TCP packets (as per requirement "KCP over raw TCP")
	if nextProto != 6 {
		return false
	}

	if len(data) < ipOffset+4 {
		return false
	}

	// TCP Destination Port is at offset 2 (2 bytes)
	dstPort := int(binary.BigEndian.Uint16(data[ipOffset+2 : ipOffset+4]))

	if dstPort == s.port {
		return true
	}

	if len(s.ranges) > 0 {
		for _, r := range s.ranges {
			if dstPort >= r.Min && dstPort <= r.Max {
				return true
			}
		}
	}

	return false
}

func (s *afpacketSource) Close() {
	s.handle.Close()
}
