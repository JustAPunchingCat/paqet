//go:build linux

package socket

import (
	"fmt"
	"net"
	"paqet/internal/conf"
	"syscall"
)

type RawInjector struct {
	fd   int
	addr syscall.SockaddrLinklayer
}

func newRawInjector(cfg *conf.Network) (PacketInjector, error) {
	iface, err := net.InterfaceByName(cfg.Interface.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to find interface %s: %w", cfg.Interface.Name, err)
	}

	// Create raw socket (AF_PACKET, SOCK_RAW, ETH_P_ALL)
	// ETH_P_ALL = 0x0003
	proto := htons(uint16(syscall.ETH_P_ALL))
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(proto))
	if err != nil {
		return nil, fmt.Errorf("failed to create raw socket: %w", err)
	}

	addr := syscall.SockaddrLinklayer{
		Protocol: proto,
		Ifindex:  iface.Index,
	}

	return &RawInjector{
		fd:   fd,
		addr: addr,
	}, nil
}

func (i *RawInjector) WritePacketData(data []byte) error {
	return syscall.Sendto(i.fd, data, 0, &i.addr)
}

func (i *RawInjector) Close() {
	syscall.Close(i.fd)
}

func htons(v uint16) uint16 {
	return (v << 8) | (v >> 8)
}
