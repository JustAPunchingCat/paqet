//go:build !linux || noebpf

package socket

import (
	"fmt"
	"paqet/internal/conf"
)

func newEBPFSource(cfg *conf.Network, hopping *conf.Hopping) (PacketSource, error) {
	return nil, fmt.Errorf("ebpf support is disabled in this build")
}
