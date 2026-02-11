package socket

import (
	"context"
	"fmt"
	"net"
	"os"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/obfs"
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
	closeOnce   sync.Once
}

// &OpError{Op: "listen", Net: network, Source: nil, Addr: nil, Err: err}
func New(ctx context.Context, cfg *conf.Network) (*PacketConn, error) {
	return NewWithHopping(ctx, cfg, nil, false, nil)
}

func NewWithHopping(ctx context.Context, cfg *conf.Network, hopping *conf.Hopping, writeHopping bool, obfsCfg *conf.Obfuscation) (*PacketConn, error) {
	if cfg.Port == 0 {
		// Use crypto-secure random port from ephemeral range (32768-65535)
		cfg.Port = int(RandInRange(32768, 65535))
	}

	var nsConn net.Conn
	var nsListener net.Listener

	if cfg.Driver == "tun" {
		// 1. Create TUN device (without starting read loop)
		dev, err := newTunDevice(cfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create TUN device: %v", err)
		}

		// 2. Initialize gVisor Netstack for TUN
		// Note: This assumes Client mode.
		// In a real app, you'd likely want to Dial per-connection in the Client struct,
		// not here in PacketConn. But for this architecture:
		ns, err := NewTunNetstack(dev.File(), cfg.IPv4.Addr.IP)
		if err != nil {
			return nil, err
		}

		// For Client: We need a target to Dial.
		// Since PacketConn is generic, we might need to defer Dialing.
		// But to fit the existing interface, let's assume we are connecting to the first server.
		// (This is a simplification for the example)
		// nsConn, err = ns.DialTCP(...)
	} else {
		// For Server (Pcap/EBPF) - Optional: Enable Netstack to handle TCP handshake
		// You can control this via a config flag, e.g., cfg.TCP.UseNetstack
		// For now, let's assume we want it if we are a server (writeHopping=false)
		if !writeHopping {
			// Create raw source/injector
			source, err := NewRecvHandle(cfg, hopping)
			if err != nil {
				return nil, err
			}
			injector, err := NewSendHandle(cfg)
			if err != nil {
				return nil, err
			}

			// Wrap in gVisor
			ep := NewPaqetLinkEndpoint(source.source, injector.injector)
			ns, err := NewNetstack(ep, cfg.IPv4.Addr.IP)
			if err != nil {
				return nil, err
			}

			// Listen
			nsListener, err = ns.ListenTCP(cfg.Port)
			if err != nil {
				return nil, err
			}
		}
	}

	// If we have a Netstack Listener (Server mode), we need to accept a connection
	// This breaks the PacketConn abstraction slightly because PacketConn is datagram-based.
	// However, since we are wrapping KCP, we can accept one connection and use it.
	if nsListener != nil {
		// Accept in background or block?
		// For simplicity, we accept one connection to establish the tunnel.
		// In production, you'd handle multiple connections.
		go func() {
			conn, _ := nsListener.Accept()
			nsConn = conn
		}()
	}

	// ... (Rest of the function uses nsConn if set)
	sendHandle, err := NewSendHandle(cfg)
	if err != nil {
		return nil, fmt.Errorf("failed to create send handle on %s: %v", cfg.Interface.Name, err)
	}

	if nsConn != nil {
		sendHandle.injector = &NetstackInjector{conn: nsConn}
		sendHandle.SkipHeaders = true
	}

	sendHandle.SetObfuscation(obfsCfg)

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

	if nsConn != nil {
		recvHandle.source = &NetstackSource{conn: nsConn}
		recvHandle.SkipDecode = true
		recvHandle.RemoteAddr = nsConn.RemoteAddr()
		recvHandle.LocalPort = cfg.Port
	}

	ctx, cancel := context.WithCancel(ctx)
	conn := &PacketConn{
		cfg:        cfg,
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

	if useObfs && cfg.Transport != nil && cfg.Transport.KCP != nil {
		key := []byte(cfg.Transport.KCP.Key)
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
		if lastPort, ok := c.clientPorts.Load(addr.String()); !ok || lastPort.(int) != dstPort {
			c.clientPorts.Store(addr.String(), dstPort)
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
	if lastPort, ok := c.clientPorts.Load(daddr.String()); ok {
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
	c.closeOnce.Do(func() {
		c.cancel()
		c.plugins.Close()

		if c.sendHandle != nil {
			go c.sendHandle.Close()
		}
		if c.recvHandle != nil {
			go c.recvHandle.Close()
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

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
