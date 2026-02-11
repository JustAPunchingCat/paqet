package socket

import "paqet/internal/conf"

type afpacketInjector struct {
	handle RawHandle
}

func newAfpacketInjector(cfg *conf.Network) (PacketInjector, error) {
	handle, err := newAfpacketHandle(cfg)
	if err != nil {
		return nil, err
	}
	return &afpacketInjector{handle: handle}, nil
}

func (i *afpacketInjector) WritePacketData(data []byte) error {
	return i.handle.WritePacketData(data)
}

func (i *afpacketInjector) Close() {
	i.handle.Close()
}
