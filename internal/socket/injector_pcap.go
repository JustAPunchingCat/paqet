package socket

import (
	"fmt"
	"paqet/internal/conf"
	"runtime"

	"github.com/gopacket/gopacket/pcap"
)

type PcapInjector struct {
	handle *pcap.Handle
}

func newPcapInjector(cfg *conf.Network) (PacketInjector, error) {
	handle, err := newHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to open pcap handle: %w", err)
	}
	// SetDirection is not fully supported on Windows Npcap, so skip it
	if runtime.GOOS != "windows" {
		if err := handle.SetDirection(pcap.DirectionOut); err != nil {
			return nil, fmt.Errorf("failed to set pcap direction out: %v", err)
		}
	}
	return &PcapInjector{handle: handle}, nil
}

func (i *PcapInjector) WritePacketData(data []byte) error {
	return i.handle.WritePacketData(data)
}

func (i *PcapInjector) Close() {
	i.handle.Close()
}
