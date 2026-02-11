//go:build nopcap

package socket

import (
	"fmt"
	"paqet/internal/conf"
)

func newPcapSource(cfg *conf.Network, hopping *conf.Hopping) (PacketSource, error) {
	return nil, fmt.Errorf("pcap support is disabled in this build")
}
