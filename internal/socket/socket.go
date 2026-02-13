package socket

import (
	"context"
	"fmt"
	"net"
	"os"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/obfs"
	"paqet/internal/pkg/hash"
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

	plugins     *PluginManager
	clientPorts sync.Map
}

// &OpError{Op: "listen", Net: network, Source: nil, Addr: nil, Err: err}
func New(ctx context.Context, cfg *conf.Network) (*PacketConn, error) {
	return NewWithHopping(ctx, cfg, nil, false, nil)
}

func NewWithHopping(ctx context.Context, cfg *conf.Network, hopping *conf.Hopping, writeHopping bool, obfsCfg *conf.Obfuscation) (*PacketConn, error) {
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
	if !writeHopping {
		recvHopping = hopping
	}
	recvHandle, err := NewRecvHandle(&connCfg, recvHopping)
	if err != nil {
		return nil, fmt.Errorf("failed to create receive handle on %s: %v", connCfg.Interface.Name, err)
	}

	ctx, cancel := context.WithCancel(ctx)
	conn := &PacketConn{
		cfg:        &connCfg,
		sendHandle: sendHandle,
		recvHandle: recvHandle,
		ctx:        ctx,
		cancel:     cancel,
		plugins:    NewPluginManager(),
	}

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
		hp, err := NewHoppingPlugin(hopping, writeHopping)
		if err != nil {
			return nil, fmt.Errorf("invalid hopping configuration: %w", err)
		}
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

	for {
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
		if payload == nil {
			continue
		}

		newPayload, newAddr, err := c.plugins.OnRead(payload, addr)
		if err != nil {
			// Drop invalid packet (e.g. obfuscation mismatch) and continue

			// Heuristic: Check if it looks like HTTP/SSH to hint at port overlap
			isCleartext := false
			if len(payload) >= 4 {
				head := string(payload[:4])
				if head == "HTTP" || head == "SSH-" || head == "GET " || head == "POST" {
					isCleartext = true
				}
			}

			if isCleartext {
				flog.Debugf("dropped invalid packet from %s: looks like cleartext traffic (HTTP/SSH). Check for port range overlap with OS ephemeral ports.", addr)
			} else {
				flog.Debugf("dropped invalid packet from %s: %v (len=%d, hex=%x)", addr, err, len(payload), payload[:min(len(payload), 16)])
			}
			continue
		}
		payload = newPayload
		addr = newAddr

		// Store the destination port this packet was sent to, so we can reply from the same port.
		// This is critical for Server mode to support NAT traversal when clients hop ports.
		// Optimization: Only update if the port has changed to avoid contention on the sync.Map.
		key := hash.IPAddr(addr.(*net.UDPAddr).IP, uint16(addr.(*net.UDPAddr).Port))
		if lastPort, ok := c.clientPorts.Load(key); !ok || lastPort.(int) != dstPort {
			c.clientPorts.Store(key, dstPort)
		}

		n = copy(data, payload)

		return n, addr, nil
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

func (c *PacketConn) Close() error {
	c.cancel()
	c.plugins.Close()

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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
