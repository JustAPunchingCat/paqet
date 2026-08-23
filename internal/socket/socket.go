package socket

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/obfs"
	"paqet/internal/pkg/hash"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

var ErrRST = errors.New("connection reset by peer")

type processedPacket struct {
	data []byte
	addr net.Addr
	port int
	err  error
}

type rawJob struct {
	data []byte
	addr net.Addr
	port int
}

type PacketConn struct {
	cfg           *conf.Network
	sendHandle    *SendHandle
	recvHandle    *RecvHandle
	readDeadline  atomic.Value
	writeDeadline atomic.Value

	ctx    context.Context
	cancel context.CancelFunc

	plugins     *PluginManager
	clientPorts sync.Map

	lastRecv atomic.Int64
	lastHop  atomic.Int64

	readQueue  chan processedPacket
	workerChs  []chan rawJob
	workersWg  sync.WaitGroup
	numWorkers int
	closeOnce  sync.Once

	OnRST func(addr net.Addr)
}

// &OpError{Op: "listen", Net: network, Source: nil, Addr: nil, Err: err}
func New(ctx context.Context, cfg *conf.Network) (*PacketConn, error) {
	return NewWithHopping(ctx, cfg, nil, false, nil)
}

func NewWithHopping(ctx context.Context, cfg *conf.Network, hopping *conf.Hopping, writeHopping bool, obfsCfg *conf.Obfuscation, labels ...string) (*PacketConn, error) {
	label := ""
	if len(labels) > 0 {
		label = labels[0]
	}
	connCfg := *cfg
	if connCfg.Port == 0 {
		// Use crypto-secure random port from ephemeral range (32768-65535)
		connCfg.Port = int(RandInRange(32768, 65535))
	}

	sendHandle, err := NewSendHandle(&connCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create send handle on %s: %v", connCfg.Interface.Name, err)
	}
	sendHandle.SetObfuscation(obfsCfg)

	// Only enable hopping on the receive handle if we are NOT hopping on writes (Server mode).
	// Clients (writeHopping=true) must listen on their specific source port, not the destination range.
	var recvHopping *conf.Hopping
	if !writeHopping { // Server mode or client not hopping on writes
		recvHopping = hopping
	}
	recvHandle, err := NewRecvHandle(&connCfg, recvHopping, connCfg.Role)
	if err != nil {
		return nil, fmt.Errorf("failed to create receive handle on %s: %v", connCfg.Interface.Name, err)
	}
	recvHandle.SetFlowUpdater(sendHandle)

	ctx, cancel := context.WithCancel(ctx)
	numWorkers := runtime.NumCPU()
	if numWorkers < 2 {
		numWorkers = 2
	}

	conn := &PacketConn{
		cfg:        &connCfg,
		sendHandle: sendHandle,
		recvHandle: recvHandle,
		ctx:        ctx,
		cancel:     cancel,
		plugins:    NewPluginManager(),
		readQueue:  make(chan processedPacket, 65536),
		workerChs:  make([]chan rawJob, numWorkers),
		numWorkers: numWorkers,
	}

	// Initialize worker channels and start worker goroutines
	conn.workersWg.Add(numWorkers)
	for i := 0; i < numWorkers; i++ {
		conn.workerChs[i] = make(chan rawJob, 4096)
		go conn.workerLoop(conn.workerChs[i])
	}

	// Start background packet reader
	go conn.backgroundReader()

	// Initialize plugins
	useObfs := false
	if obfsCfg != nil {
		useObfs = obfsCfg.UseTLS || obfsCfg.Padding.Enabled
	}

	if useObfs && connCfg.Transport != nil {
		var keyStr string
		if connCfg.Transport.KCP != nil && connCfg.Transport.KCP.Key != "" {
			keyStr = connCfg.Transport.KCP.Key
		} else if connCfg.Transport.QUIC != nil && connCfg.Transport.QUIC.Key != "" {
			keyStr = connCfg.Transport.QUIC.Key
		} else if connCfg.Transport.UDP != nil && connCfg.Transport.UDP.Key != "" {
			keyStr = connCfg.Transport.UDP.Key
		}
		key := []byte(keyStr)
		if o, err := obfs.New(obfsCfg, key); err == nil {
			conn.plugins.Add(NewObfuscationPlugin(o))
			flog.Debugf("Obfuscation initialized. Key prefix: %x...", key[:min(len(key), 4)])
		} else {
			flog.Warnf("failed to initialize obfuscation (check key length): %v", err)
		}
	}

	if hopping != nil && hopping.Enabled {
		hp, err := NewHoppingPlugin(hopping, writeHopping, label, connCfg.Handshake)
		if err != nil {
			return nil, fmt.Errorf("invalid hopping configuration: %w", err)
		}
		hp.SetSendHandle(sendHandle)
		conn.plugins.Add(hp)
	}

	return conn, nil
}

func (c *PacketConn) ReadFrom(data []byte) (n int, addr net.Addr, err error) {
	var timer *time.Timer
	var deadline <-chan time.Time
	if d, ok := c.readDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer = time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadline = timer.C
	}

	select {
	case <-c.ctx.Done():
		return 0, nil, c.ctx.Err()
	case <-deadline:
		return 0, nil, os.ErrDeadlineExceeded
	case pkt, ok := <-c.readQueue:
		if !ok {
			return 0, nil, net.ErrClosed
		}
		if pkt.err != nil {
			return 0, nil, pkt.err
		}

		// Store client port for Server NAT routing
		key := hash.IPAddr(pkt.addr.(*net.UDPAddr).IP, uint16(pkt.addr.(*net.UDPAddr).Port))
		if lastPort, ok := c.clientPorts.Load(key); !ok || lastPort.(int) != pkt.port {
			c.clientPorts.Store(key, pkt.port)
		}

		n = copy(data, pkt.data)
		return n, pkt.addr, nil
	}
}

func (c *PacketConn) workerLoop(ch chan rawJob) {
	defer c.workersWg.Done()
	for {
		select {
		case <-c.ctx.Done():
			return
		case job, ok := <-ch:
			if !ok {
				return
			}
			payload, addr, err := c.plugins.OnRead(job.data, job.addr)
			if err != nil {
				// Drop invalid packet (e.g. obfuscation mismatch)
				continue
			}
			select {
			case c.readQueue <- processedPacket{data: payload, addr: addr, port: job.port}:
			case <-c.ctx.Done():
				return
			}
		}
	}
}

func (c *PacketConn) backgroundReader() {
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		payload, addr, dstPort, err := c.recvHandle.Read()
		if err != nil {
			if err == ErrRST {
				if c.OnRST != nil && addr != nil {
					c.OnRST(addr)
				}
				continue
			}
			if c.ctx.Err() == nil {
				select {
				case c.readQueue <- processedPacket{err: err}:
				case <-c.ctx.Done():
				}
			}
			return
		}
		if addr != nil && dstPort > 0 {
			if udpAddr, ok := addr.(*net.UDPAddr); ok {
				key := hash.IPAddr(udpAddr.IP, uint16(udpAddr.Port))
				c.clientPorts.Store(key, dstPort)
			}
		}

		if payload == nil {
			continue
		}
		c.lastRecv.Store(time.Now().UnixNano())

		udpAddr, ok := addr.(*net.UDPAddr)
		if !ok {
			continue
		}

		// Consistent Hashing / Flow Pinning based on client IP & Port
		h := hash.IPAddr(udpAddr.IP, uint16(udpAddr.Port))
		workerID := int(h % uint64(c.numWorkers))

		select {
		case c.workerChs[workerID] <- rawJob{data: payload, addr: addr, port: dstPort}:
		case <-c.ctx.Done():
			return
		}
	}
}

func (c *PacketConn) WriteTo(data []byte, addr net.Addr) (n int, err error) {
	var timer *time.Timer
	var deadline <-chan time.Time
	if d, ok := c.writeDeadline.Load().(time.Time); ok && !d.IsZero() {
		timer = time.NewTimer(time.Until(d))
		defer timer.Stop()
		deadline = timer.C
	}

	select {
	case <-c.ctx.Done():
		return 0, c.ctx.Err()
	case <-deadline:
		return 0, os.ErrDeadlineExceeded
	default:
	}

	daddr, ok := addr.(*net.UDPAddr)
	if !ok {
		return 0, net.InvalidAddrError("invalid address")
	}

	srcPort := c.cfg.Port

	// Apply plugins (Hop Port, Obfuscate)
	data, addr, err = c.plugins.OnWrite(data, addr)
	if err != nil {
		return 0, err
	}

	// Server Echo logic: try to reply from the port the client last contacted.
	key := hash.IPAddr(daddr.IP, uint16(daddr.Port))
	if lastPort, ok := c.clientPorts.Load(key); ok {
		srcPort = lastPort.(int)
	}

	// Cast again because plugins might return a generic net.Addr
	daddr, _ = addr.(*net.UDPAddr)
	err = c.sendHandle.Write(data, daddr, srcPort)
	if err != nil {
		return 0, err
	}

	return len(data), nil
}

func (c *PacketConn) ForceHop() {
	if c.plugins != nil {
		for _, pl := range c.plugins.plugins {
			if hp, ok := pl.(*HoppingPlugin); ok {
				hp.ForceHop()
			}
		}
	}
}

func (c *PacketConn) Close() error {
	c.closeOnce.Do(func() {
		c.cancel()
		c.plugins.Close()

		if c.sendHandle != nil {
			c.sendHandle.Close()
		}
		if c.recvHandle != nil {
			c.recvHandle.Close()
		}
	})
	return nil
}

func (c *PacketConn) LocalAddr() net.Addr {
	var ip net.IP
	if c.cfg.IPv4.Addr != nil {
		ip = c.cfg.IPv4.Addr.IP
	} else if c.cfg.IPv6.Addr != nil {
		ip = c.cfg.IPv6.Addr.IP
	}
	if ip == nil {
		ip = net.IPv4(0, 0, 0, 0)
	}
	return &net.UDPAddr{
		IP:   ip,
		Port: c.cfg.Port,
	}
}

func (c *PacketConn) GetClientPort(addr net.Addr) int {
	key := hash.IPAddr(addr.(*net.UDPAddr).IP, uint16(addr.(*net.UDPAddr).Port))
	if port, ok := c.clientPorts.Load(key); ok {
		return port.(int)
	}
	return 0
}

func (c *PacketConn) SetDeadline(t time.Time) error {
	c.readDeadline.Store(t)
	c.writeDeadline.Store(t)
	return nil
}

func (c *PacketConn) SetReadDeadline(t time.Time) error {
	c.readDeadline.Store(t)
	return nil
}

func (c *PacketConn) SetWriteDeadline(t time.Time) error {
	c.writeDeadline.Store(t)
	return nil
}

func (c *PacketConn) SetReadBuffer(bytes int) error {
	// Buffers are managed by the underlying driver (pcap/afpacket/ebpf) configuration
	return nil
}

func (c *PacketConn) SetWriteBuffer(bytes int) error {
	// Buffers are managed by the underlying driver (pcap/afpacket/ebpf) configuration
	return nil
}

func (c *PacketConn) SetDSCP(dscp int) error {
	return nil
}

func (c *PacketConn) SetClientTCPF(addr net.Addr, f []conf.TCPF) {
	c.sendHandle.setClientTCPF(addr, f)
}

func (c *PacketConn) IsFlowWarmed(dstIP net.IP, dstPort uint16) bool {
	if c.sendHandle != nil {
		return c.sendHandle.IsFlowWarmed(dstIP, dstPort)
	}
	return true
}

func (c *PacketConn) PrewarmFlow(dstIP net.IP, dstPort uint16) {
	if c.sendHandle != nil {
		c.sendHandle.PrewarmFlow(dstIP, dstPort)
	}
}

func (c *PacketConn) GetCurrentPort() int {
	if c.plugins != nil {
		for _, pl := range c.plugins.plugins {
			if hp, ok := pl.(*HoppingPlugin); ok {
				if port := hp.currentPort.Load(); port > 0 {
					return int(port)
				}
			}
		}
	}
	return c.cfg.Port
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
