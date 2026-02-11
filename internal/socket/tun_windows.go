//go:build windows

package socket

import (
	"fmt"
	"os"
	"paqet/internal/conf"
)

type TunDevice struct {
	file *os.File
}

func newTunDevice(cfg *conf.Network) (*TunDevice, error) {
	if cfg.TUN.FD > 0 {
		// On Windows, the FD is the Handle.
		// os.NewFile takes a uintptr, which matches the Handle size (32 or 64 bit).
		file := os.NewFile(uintptr(cfg.TUN.FD), cfg.TUN.Name)
		return &TunDevice{file: file}, nil
	}

	return nil, fmt.Errorf("creating a TUN device on Windows is not supported directly; please provide a pre-opened 'tun_fd' (Handle)")
}

func (t *TunDevice) ReadPacketData() ([]byte, error) {
	buf := make([]byte, 2048) // MTU + overhead
	n, err := t.file.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (t *TunDevice) WritePacketData(data []byte) error {
	_, err := t.file.Write(data)
	return err
}

func (t *TunDevice) Close() {
	t.file.Close()
}

func newTunSource(cfg *conf.Network, hopping *conf.Hopping) (PacketSource, error) {
	return newTunDevice(cfg)
}

func newTunInjector(cfg *conf.Network) (PacketInjector, error) {
	return newTunDevice(cfg)
}
