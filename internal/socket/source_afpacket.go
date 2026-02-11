package socket

import (
	"paqet/internal/conf"
)

type afpacketSource struct {
	handle RawHandle
}

func newAfpacketSource(cfg *conf.Network, hopping *conf.Hopping) (PacketSource, error) {
	handle, err := newAfpacketHandle(cfg)
	if err != nil {
		return nil, err
	}
	// Note: BPF filtering for hopping not fully implemented in pure Go yet
	return &afpacketSource{handle: handle}, nil
}

func (s *afpacketSource) ReadPacketData() ([]byte, error) {
	data, _, err := s.handle.ZeroCopyReadPacketData()
	if err != nil {
		return nil, err
	}
	// Return a copy because the ring buffer slot will be reused
	return append([]byte(nil), data...), nil
}

func (s *afpacketSource) Close() {
	s.handle.Close()
}
