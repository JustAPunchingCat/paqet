package socket

import (
	"net"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"sync/atomic"
	"time"
)

type HoppingPlugin struct {
	ranges      []conf.PortRange
	interval    time.Duration
	currentPort atomic.Uint32
	stop        chan struct{}
	minPort     int
	isClient    bool
	label       string
}

func NewHoppingPlugin(cfg *conf.Hopping, isClient bool, label string) (*HoppingPlugin, error) {
	ranges, err := cfg.GetRanges()
	if err != nil {
		return nil, err
	}

	minPort := cfg.Min
	if minPort == 0 && len(ranges) > 0 {
		minPort = ranges[0].Min
	}

	hp := &HoppingPlugin{
		ranges:   ranges,
		interval: time.Duration(cfg.Interval) * time.Second,
		stop:     make(chan struct{}),
		minPort:  minPort,
		isClient: isClient,
		label:    label,
	}
	if isClient {
		hp.updateCurrentPort()
		go hp.loop()
	}
	return hp, nil
}

func (p *HoppingPlugin) loop() {
	ticker := time.NewTicker(p.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.updateCurrentPort()
		case <-p.stop:
			return
		}
	}
}

func (p *HoppingPlugin) updateCurrentPort() {
	if len(p.ranges) == 0 {
		return
	}

	idx := int(RandInRange(0, uint32(len(p.ranges)-1)))
	r := p.ranges[idx]

	rangeSize := r.Max - r.Min + 1
	offset := 0
	if rangeSize > 1 {
		offset = int(RandInRange(0, uint32(rangeSize-1)))
	}

	newPort := uint32(r.Min + offset)
	p.currentPort.Store(newPort)
	if p.label != "" {
		flog.Debugf("Hopping: switched to port %d for %s", newPort, p.label)
	} else {
		flog.Debugf("Hopping: switched to port %d", newPort)
	}
}

func (p *HoppingPlugin) OnRead(data []byte, addr net.Addr) ([]byte, net.Addr, error) {
	if !p.isClient {
		return data, addr, nil
	}
	// Normalize incoming port to minPort
	if udpAddr, ok := addr.(*net.UDPAddr); ok {
		// Check if port is in any of our ranges
		for _, r := range p.ranges {
			if udpAddr.Port >= r.Min && udpAddr.Port <= r.Max {
				newAddr := *udpAddr
				newAddr.Port = p.minPort
				return data, &newAddr, nil
			}
		}
	}
	return data, addr, nil
}

func (p *HoppingPlugin) OnWrite(data []byte, addr net.Addr) ([]byte, net.Addr, error) {
	if !p.isClient {
		return data, addr, nil
	}
	// Override destination port
	if port := p.currentPort.Load(); port > 0 {
		if udpAddr, ok := addr.(*net.UDPAddr); ok {
			newAddr := *udpAddr
			newAddr.Port = int(port)
			return data, &newAddr, nil
		}
	}
	return data, addr, nil
}

func (p *HoppingPlugin) Close() error {
	if p.isClient {
		close(p.stop)
	}
	return nil
}
