//go:build !linux || noebpf

package socket

import (
	"fmt"
	"paqet/internal/conf"
)

func newRawInjector(cfg *conf.Network) (PacketInjector, error) {
	return nil, fmt.Errorf("ebpf/raw support is disabled in this build")
}
