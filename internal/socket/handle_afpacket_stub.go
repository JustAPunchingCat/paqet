//go:build !linux

package socket

import (
	"fmt"
	"paqet/internal/conf"
)

func newAfpacketHandle(cfg *conf.Network) (RawHandle, error) {
	return nil, fmt.Errorf("AF_PACKET is only supported on Linux")
}
