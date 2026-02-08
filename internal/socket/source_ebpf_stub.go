//go:build !linux

package socket

import (
	"fmt"
	"paqet/internal/conf"
)

func newEBPFSource(cfg *conf.Network, hopping *conf.Hopping) (PacketSource, error) {
	return nil, fmt.Errorf("ebpf driver is only supported on Linux")
}
