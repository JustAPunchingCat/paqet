package socket

import (
	"net"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"sync/atomic"
	"time"
)

type HoppingPlugin struct {
	ranges         []conf.PortRange
	interval       time.Duration
	stop           chan struct{}
	currentPort    atomic.Uint32
	lastActivePort atomic.Uint32
	minPort        int
	isClient       bool
	label          string
	targetIP       net.IP
	sendHandle     *SendHandle
	// hopCount increments on every interval/forced hop (client only).
	hopCount atomic.Uint32
	// OnHop, when set (client only), fires after every hop. Used by the
	// client to rotate its local source port per rotate_client_port.
	OnHop func(hopCount uint32)
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

	hp := &HoppingPlugin{
		ranges:     ranges,
		interval:   time.Duration(cfg.Interval) * time.Second,
		stop:       make(chan struct{}),
		minPort:    minPort,
		isClient:   isClient,
		label:      label,
		targetIP:   targetIP,
	}
	if isClient {
		hp.updateCurrentPort()
		go hp.loop()
	}
	return hp, nil
}

func (p *HoppingPlugin) SetSendHandle(sh *SendHandle) {
	p.sendHandle = sh
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
	for {
		select {
		case <-time.After(p.interval):
			nextPort := p.pickNextPort()
			select {
			case <-time.After(p.interval):
				if nextPort > 0 {
					p.currentPort.Store(nextPort)
					// Re-fire the fake 3WHS against the fresh destination
					// port so the middlebox sees a handshake for the new
					// tuple (no-op when handshake is disabled). Flow state
					// (seq/ack/TS) deliberately untouched — the KCP stream
					// stays continuous.
					if p.isClient && p.OnHop != nil {
						n := p.hopCount.Add(1)
						go p.OnHop(n)
					}
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
	// No ClearRemoteSync here either: same rationale as the interval hop —
	// the flow key excludes the server port, state must survive hops.
	p.currentPort.Store(newPort)
	if p.OnHop != nil {
		n := p.hopCount.Add(1)
		go p.OnHop(n)
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
	// Override destination port. Lazy warm-up is handled in SendHandle.Write
	// so it applies uniformly whether hopping is enabled or not.
	if port := p.currentPort.Load(); port > 0 {
		if udpAddr, ok := addr.(*net.UDPAddr); ok {
			newAddr := *udpAddr
			newAddr.Port = int(port)
			// Remember the most recent port we actually wrote to. The goodbye
			// FIN (SendRST) must go to a port the client has already used —
			// only those flows are primed through the ISP NAT, so the server
			// actually receives the FIN and tears down the orphan session.
			// Sending it to the freshly hopped (but never used) port would be
			// dropped as an un-primed flow, leaving the server session alive
			// to retransmit forever (the stale-tunnel noise).
			p.lastActivePort.Store(port)
			return data, &newAddr, nil
		}
	}
	return data, addr, nil
}

// LastActivePort returns the most recent port this client actually wrote to,
// or 0 if nothing has been sent yet.
func (p *HoppingPlugin) LastActivePort() uint32 {
	return p.lastActivePort.Load()
}

func (p *HoppingPlugin) Close() error {
	if p.isClient {
		close(p.stop)
	}
	return nil
}
