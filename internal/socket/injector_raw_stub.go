//go:build !linux

package socket

import (
	"fmt"
	"paqet/internal/conf"
)

func newRawInjector(cfg *conf.Network) (PacketInjector, error) {
	return nil, fmt.Errorf("ebpf/raw driver is only supported on Linux")
}
