//go:build !linux && !windows

package socket

import (
	"fmt"
	"paqet/internal/conf"
)

func newTunSource(cfg *conf.Network, hopping *conf.Hopping) (PacketSource, error) {
	return nil, fmt.Errorf("tun driver is not supported on this platform/build")
}

func newTunInjector(cfg *conf.Network) (PacketInjector, error) {
	return nil, fmt.Errorf("tun driver is not supported on this platform/build")
}
