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
	lazyWarmup  bool
	prewarm     bool
	stop        chan struct{}
	currentPort atomic.Uint32
	minPort     int
	isClient    bool
	label       string
	targetIP    net.IP
	sendHandle  *SendHandle
}

func NewHoppingPlugin(cfg *conf.Hopping, isClient bool, label string, hs *conf.Handshake) (*HoppingPlugin, error) {
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

	if hs == nil {
		hs = &conf.Handshake{}
	}
	warmup := time.Duration(hs.EagerTime) * time.Second
	if warmup <= 0 {
		warmup = 3 * time.Second
	}

	hp := &HoppingPlugin{
		ranges:     ranges,
		interval:   time.Duration(cfg.Interval) * time.Second,
		warmup:     warmup,
		lazyWarmup: hs.IsLazy(),
		stop:       make(chan struct{}),
		minPort:    minPort,
		isClient:   isClient,
		label:      label,
		targetIP:   targetIP,
	}
	// Optionally pre-warm the next hop port with empty probe packets before
	// switching data to it (default: false). When enabled, this primes the
	// NAT/firewall flow, the server's reply-port mapping and the per-port
	// fake-TCP state, so the first real packet to the new port is not
	// dropped on stateful paths. Works with or without the fake handshake.
	hp.prewarm = false
	if cfg.Prewarm != nil {
		hp.prewarm = *cfg.Prewarm
	}
	if isClient {
		hp.updateCurrentPort()
		go hp.loop()
	}
	return hp, nil
}

func (p *HoppingPlugin) SetSendHandle(sh *SendHandle) {
	p.sendHandle = sh
	if !p.lazyWarmup && p.targetIP != nil && sh != nil {
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
			nextPort := p.pickNextPort()
			// Prime the new port's flow BEFORE switching data to it: NAT
			// entry, the server's reply-port mapping, and the per-port
			// fake-TCP state. Without this, the first real packet to the new
			// port can be dropped by stateful firewalls and KCP backoff costs
			// seconds of blackout. Runs in a goroutine so the hop cadence is
			// unaffected. Works with or without the fake handshake.
			if !p.lazyWarmup && nextPort > 0 && p.sendHandle != nil && p.targetIP != nil {
				p.sendHandle.PrewarmFlow(p.targetIP, uint16(nextPort))
			}
			if p.prewarm && nextPort > 0 && p.sendHandle != nil && p.targetIP != nil {
				go p.probePort(p.targetIP, uint16(nextPort))
			}

			select {
			case <-time.After(leadTime):
				if nextPort > 0 {
					p.currentPort.Store(nextPort)
					if p.label != "" {
						flog.Debugf("Hopping [%s]: interval hopped to port :%d", p.label, nextPort)
					} else {
						flog.Debugf("Hopping: interval hopped to port :%d", nextPort)
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

// probePort sends a few empty fake-TCP segments to the upcoming hop port so
// the NAT/firewall flow, the server's reply-port mapping and the per-port
// fake-TCP state are established before the data switch. The segments carry no
// KCP payload, so the peer's transport drops them without touching the stream;
// the socket layer has already recorded the new port by then.
func (p *HoppingPlugin) probePort(dstIP net.IP, port uint16) {
	for i := 0; i < 3; i++ {
		select {
		case <-p.stop:
			return
		default:
		}
		if p.sendHandle != nil {
			_ = p.sendHandle.ProbePort(dstIP, port)
		}
		time.Sleep(500 * time.Millisecond)
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
	if p.sendHandle != nil {
		p.sendHandle.ResetFlow()
		if !p.lazyWarmup && p.targetIP != nil {
			p.sendHandle.PrewarmFlow(p.targetIP, uint16(newPort))
		}
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
	// Override destination port. Lazy warm-up is handled in SendHandle.Write
	// so it applies uniformly whether hopping is enabled or not.
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
