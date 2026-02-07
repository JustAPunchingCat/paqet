package socket

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"os"
	"paqet/internal/conf"
	"sync"
	"sync/atomic"
	"time"
)

type PacketConn struct {
	cfg           *conf.Network
	sendHandle    *SendHandle
	recvHandle    *RecvHandle
	readDeadline  atomic.Value
	writeDeadline atomic.Value

	ctx    context.Context
	cancel context.CancelFunc

	hopping       *conf.Hopping
	hoppingRanges []conf.PortRange

	// Map to store the last destination port used by a remote client (for server echo)
	clientPorts sync.Map // map[string]int (RemoteAddr -> LocalPort)
}

// &OpError{Op: "listen", Net: network, Source: nil, Addr: nil, Err: err}
func New(ctx context.Context, cfg *conf.Network) (*PacketConn, error) {
	return NewWithHopping(ctx, cfg, nil, false, 0)
}

func NewWithHopping(ctx context.Context, cfg *conf.Network, hopping *conf.Hopping, writeHopping bool, padding int) (*PacketConn, error) {
	if cfg.Port == 0 {
		cfg.Port = 32768 + rand.Intn(32768)
	}

	sendHandle, err := NewSendHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create send handle on %s: %v", cfg.Interface.Name, err)
	}
	sendHandle.SetPadding(padding)

	// Only enable hopping on the receive handle if we are NOT hopping on writes (Server mode).
	// Clients (writeHopping=true) must listen on their specific source port, not the destination range.
	var recvHopping *conf.Hopping
	if !writeHopping {
		recvHopping = hopping
	}
	recvHandle, err := NewRecvHandle(cfg, recvHopping)
	if err != nil {
		return nil, fmt.Errorf("failed to create receive handle on %s: %v", cfg.Interface.Name, err)
	}

	ctx, cancel := context.WithCancel(ctx)
	conn := &PacketConn{
		cfg:        cfg,
		sendHandle: sendHandle,
		recvHandle: recvHandle,
		ctx:        ctx,
		cancel:     cancel,
	}

	if hopping != nil && hopping.Enabled && writeHopping {
		if err := sendHandle.SetHopping(hopping); err != nil {
			return nil, fmt.Errorf("invalid hopping configuration: %w", err)
		}
		conn.hopping = hopping
		conn.hoppingRanges, _ = hopping.GetRanges()
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
	default:
	}

	payload, addr, dstPort, err := c.recvHandle.Read()
	if err != nil {
		return 0, nil, err
	}

	// FRAMING: Strip padding based on length header.
	// Wire format: [Length (2B)] [Data] [Padding]
	if len(payload) < 2 {
		return 0, addr, nil // Packet too short to contain length header
	}
	dataLen := int(binary.BigEndian.Uint16(payload[:2]))
	if dataLen > len(payload)-2 {
		return 0, addr, nil // Malformed packet (length claims more data than received)
	}
	// Slice the payload to keep only the real data
	payload = payload[2 : 2+dataLen]

	// If hopping is enabled (Client mode), normalize the remote port to the Min port.
	// This ensures KCP accepts the packet even if the server replies from a different
	// port within the range (or if the user configured a different port in the range).
	if c.hopping != nil && c.hopping.Enabled && len(c.hoppingRanges) > 0 {
		if udpAddr, ok := addr.(*net.UDPAddr); ok {
			if c.isInRange(udpAddr.Port) {
				canonicalPort := c.hopping.Min
				if canonicalPort == 0 && len(c.hoppingRanges) > 0 {
					canonicalPort = c.hoppingRanges[0].Min
				}
				udpAddr.Port = canonicalPort // Normalize to canonical port
			}
		}
	}

	// Store the destination port this packet was sent to, so we can reply from the same port.
	// This is critical for Server mode to support NAT traversal when clients hop ports.
	// Optimization: Only update if the port has changed to avoid contention on the sync.Map.
	if lastPort, ok := c.clientPorts.Load(addr.String()); !ok || lastPort.(int) != dstPort {
		c.clientPorts.Store(addr.String(), dstPort)
	}

	n = copy(data, payload)

	return n, addr, nil
}

func (c *PacketConn) isInRange(port int) bool {
	for _, r := range c.hoppingRanges {
		if port >= r.Min && port <= r.Max {
			return true
		}
	}
	return false
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
	if c.hopping == nil {
		// If not hopping (Server mode), try to reply from the port the client last contacted.
		if lastPort, ok := c.clientPorts.Load(daddr.String()); ok {
			srcPort = lastPort.(int)
		}
	}

	err = c.sendHandle.Write(data, daddr, srcPort)
	if err != nil {
		return 0, err
	}

	return len(data), nil
}

func (c *PacketConn) Close() error {
	c.cancel()

	if c.sendHandle != nil {
		go c.sendHandle.Close()
	}
	if c.recvHandle != nil {
		go c.recvHandle.Close()
	}

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
	if port, ok := c.clientPorts.Load(addr.String()); ok {
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

func (c *PacketConn) SetDSCP(dscp int) error {
	return nil
}

func (c *PacketConn) SetClientTCPF(addr net.Addr, f []conf.TCPF) {
	c.sendHandle.setClientTCPF(addr, f)
}
