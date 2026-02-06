package socket

import (
	"context"
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

	hopping     *conf.Hopping
	currentPort int
	lastHop     time.Time
	mu          sync.Mutex

	// Map to store the last destination port used by a remote client (for server echo)
	clientPorts sync.Map // map[string]int (RemoteAddr -> LocalPort)
}

// &OpError{Op: "listen", Net: network, Source: nil, Addr: nil, Err: err}
func New(ctx context.Context, cfg *conf.Network) (*PacketConn, error) {
	return NewWithHopping(ctx, cfg, nil, false)
}

func NewWithHopping(ctx context.Context, cfg *conf.Network, hopping *conf.Hopping, writeHopping bool) (*PacketConn, error) {
	if cfg.Port == 0 {
		cfg.Port = 32768 + rand.Intn(32768)
	}

	sendHandle, err := NewSendHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create send handle on %s: %v", cfg.Interface.Name, err)
	}

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
		conn.hopping = hopping
		conn.currentPort = hopping.Min
		conn.lastHop = time.Now()
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

	// If hopping is enabled (Client mode), normalize the remote port to the Min port.
	// This ensures KCP accepts the packet even if the server replies from a different
	// port within the range (or if the user configured a different port in the range).
	if c.hopping != nil && c.hopping.Enabled {
		if udpAddr, ok := addr.(*net.UDPAddr); ok && udpAddr.Port >= c.hopping.Min && udpAddr.Port <= c.hopping.Max {
			udpAddr.Port = c.hopping.Min
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
	if c.hopping != nil && c.hopping.Enabled {
		c.mu.Lock()
		if time.Since(c.lastHop) > time.Duration(c.hopping.Interval)*time.Second {
			rangeSize := c.hopping.Max - c.hopping.Min + 1
			if rangeSize > 1 {
				// Ensure we pick a different port than the current one
				for {
					offset := rand.Intn(rangeSize)
					newPort := c.hopping.Min + offset
					if newPort != c.currentPort {
						c.currentPort = newPort
						break
					}
				}
			}
			c.lastHop = time.Now()
		}
		targetPort := c.currentPort
		c.mu.Unlock()

		newAddr := *daddr
		newAddr.Port = targetPort
		daddr = &newAddr
	} else {
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
	return nil
	// return &net.UDPAddr{
	// 	IP:   append([]byte(nil), c.cfg.PrimaryAddr().IP...),
	// 	Port: c.cfg.PrimaryAddr().Port,
	// 	Zone: c.cfg.PrimaryAddr().Zone,
	// }
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
