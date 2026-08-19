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
	warmup      time.Duration
	stop        chan struct{}
	currentPort atomic.Uint32
	minPort     int
	isClient    bool
	label       string
	targetIP    net.IP
	sendHandle  *SendHandle
	autoRotate  bool
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

	var targetIP net.IP
	if label != "" {
		host, _, err := net.SplitHostPort(label)
		if err == nil {
			targetIP = net.ParseIP(host)
		} else {
			targetIP = net.ParseIP(label)
		}
	}

	warmup := time.Duration(cfg.Warmup) * time.Second
	if warmup <= 0 {
		warmup = 3 * time.Second
	}

	hp := &HoppingPlugin{
		ranges:     ranges,
		interval:   time.Duration(cfg.Interval) * time.Second,
		warmup:     warmup,
		stop:       make(chan struct{}),
		minPort:    minPort,
		isClient:   isClient,
		label:      label,
		targetIP:   targetIP,
		autoRotate: cfg.AutoRotate,
	}
	if isClient {
		hp.updateCurrentPort()
		go hp.loop()
	}
	return hp, nil
}

func (p *HoppingPlugin) SetSendHandle(sh *SendHandle) {
	p.sendHandle = sh
	if p.targetIP != nil && sh != nil {
		if port := p.currentPort.Load(); port > 0 {
			sh.PrewarmFlow(p.targetIP, uint16(port))
		}
	}
}

func (p *HoppingPlugin) pickNextPort() uint32 {
	if len(p.ranges) == 0 {
		return 0
	}

	idx := int(RandInRange(0, uint32(len(p.ranges)-1)))
	r := p.ranges[idx]

	rangeSize := r.Max - r.Min + 1
	offset := 0
	if rangeSize > 1 {
		offset = int(RandInRange(0, uint32(rangeSize-1)))
	}

	return uint32(r.Min + offset)
}

func (p *HoppingPlugin) loop() {
	leadTime := p.warmup
	if p.interval <= 2*p.warmup {
		leadTime = p.interval / 2
	}

	for {
		select {
		case <-time.After(p.interval - leadTime):
			var nextPort uint32
			for attempt := 0; attempt < 4; attempt++ {
				nextPort = p.pickNextPort()
				if nextPort > 0 && p.sendHandle != nil && p.targetIP != nil {
					p.sendHandle.PrewarmFlow(p.targetIP, uint16(nextPort))
				}
				if !p.autoRotate || p.sendHandle == nil || p.targetIP == nil {
					break
				}
				// Verify candidate port responsiveness
				warmed := false
				for i := 0; i < 4; i++ {
					time.Sleep(30 * time.Millisecond)
					if p.sendHandle.IsFlowWarmed(p.targetIP, uint16(nextPort)) {
						warmed = true
						break
					}
				}
				if warmed {
					break
				}
			}

			select {
			case <-time.After(leadTime):
				if nextPort > 0 {
					p.currentPort.Store(nextPort)
					if p.label != "" {
						flog.Infof("Hopping [%s]: interval hopped to port :%d", p.label, nextPort)
					} else {
						flog.Infof("Hopping: interval hopped to port :%d", nextPort)
					}
				}
			case <-p.stop:
				return
			}
		case <-p.stop:
			return
		}
	}
}

func (p *HoppingPlugin) updateCurrentPort() {
	newPort := p.pickNextPort()
	if newPort == 0 {
		return
	}
	p.currentPort.Store(newPort)
	if p.label != "" {
		flog.Debugf("Hopping: switched to port %d for %s", newPort, p.label)
	} else {
		flog.Debugf("Hopping: switched to port %d", newPort)
	}
}

func (p *HoppingPlugin) ForceHop() {
	if !p.isClient {
		return
	}
	newPort := p.pickNextPort()
	if newPort == 0 {
		return
	}
	if p.sendHandle != nil && p.targetIP != nil {
		p.sendHandle.PrewarmFlow(p.targetIP, uint16(newPort))
	}
	p.currentPort.Store(newPort)
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
