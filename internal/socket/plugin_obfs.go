package socket

import (
	"net"
	"paqet/internal/obfs"
)

type ObfuscationPlugin struct {
	obfuscator obfs.Obfuscator
}

func NewObfuscationPlugin(o obfs.Obfuscator) *ObfuscationPlugin {
	return &ObfuscationPlugin{obfuscator: o}
}

func (p *ObfuscationPlugin) OnRead(data []byte, addr net.Addr) ([]byte, net.Addr, error) {
	d, err := p.obfuscator.Unwrap(data)
	return d, addr, err
}

func (p *ObfuscationPlugin) OnWrite(data []byte, addr net.Addr) ([]byte, net.Addr, error) {
	d, err := p.obfuscator.Wrap(data)
	return d, addr, err
}

func (p *ObfuscationPlugin) Close() error {
	return nil
}
