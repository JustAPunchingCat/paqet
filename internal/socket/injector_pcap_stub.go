//go:build nopcap

package socket

import (
	"fmt"
	"paqet/internal/conf"
)

func newPcapInjector(cfg *conf.Network) (PacketInjector, error) {
	return nil, fmt.Errorf("pcap support is disabled in this build")
}
