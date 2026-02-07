package socket

import (
	"net"
)

type Plugin interface {
	OnRead(data []byte, addr net.Addr) ([]byte, net.Addr, error)
	OnWrite(data []byte, addr net.Addr) ([]byte, net.Addr, error)
	Close() error
}

type PluginManager struct {
	plugins []Plugin
}

func NewPluginManager() *PluginManager {
	return &PluginManager{}
}

func (pm *PluginManager) Add(p Plugin) {
	pm.plugins = append(pm.plugins, p)
}

func (pm *PluginManager) OnRead(data []byte, addr net.Addr) ([]byte, net.Addr, error) {
	var err error
	// Iterate in reverse order for read (unwrap layers)
	for i := len(pm.plugins) - 1; i >= 0; i-- {
		data, addr, err = pm.plugins[i].OnRead(data, addr)
		if err != nil {
			return nil, nil, err
		}
	}
	return data, addr, nil
}

func (pm *PluginManager) OnWrite(data []byte, addr net.Addr) ([]byte, net.Addr, error) {
	var err error
	for _, p := range pm.plugins {
		data, addr, err = p.OnWrite(data, addr)
		if err != nil {
			return nil, nil, err
		}
	}
	return data, addr, nil
}

func (pm *PluginManager) Close() error {
	for _, p := range pm.plugins {
		p.Close()
	}
	return nil
}
