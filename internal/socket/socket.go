package socket

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/obfs"
	"paqet/internal/pkg/hash"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
)

type rawPacket struct {
	payload []byte
	addr    net.Addr
	dstPort int
	err     error
}

type tcpPacket struct {
	data []byte
	addr net.Addr
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

	// Asymmetric Upstream Fields
	upstreamConn net.Conn
	upstreamMu   sync.Mutex
	tcpRxChan    chan tcpPacket
	rawRxChan    chan rawPacket
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
		hp, err := NewHoppingPlugin(hopping, writeHopping, label)
		if err != nil {
			return nil, fmt.Errorf("invalid hopping configuration: %w", err)
		}
		conn.plugins.Add(hp)
	}

	if cfg.Role == "server" && cfg.UpstreamListen != "" {
		conn.tcpRxChan = make(chan tcpPacket, 1024)
		conn.rawRxChan = make(chan rawPacket, 1024)
		go conn.listenUpstream(cfg.UpstreamListen)
		go conn.pollRaw()
	}

	if cfg.Role == "client" && cfg.UpstreamSOCKS5 != "" {
		go conn.dialUpstreamKeepalive(cfg.UpstreamSOCKS5, cfg.UpstreamTarget)
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
		var payload []byte
		var dstPort int

		if c.tcpRxChan != nil {
			select {
			case <-c.ctx.Done():
				return 0, nil, c.ctx.Err()
			case <-deadline:
				return 0, nil, os.ErrDeadlineExceeded
			case pkt := <-c.tcpRxChan:
				payload = pkt.data
				addr = pkt.addr
				dstPort = c.cfg.Port
			case raw := <-c.rawRxChan:
				if raw.err != nil {
					return 0, nil, raw.err
				}
				payload = raw.payload
				addr = raw.addr
				dstPort = raw.dstPort
			}
		} else {
			select {
			case <-c.ctx.Done():
				return 0, nil, c.ctx.Err()
			case <-deadline:
				return 0, nil, os.ErrDeadlineExceeded
			default:
			}
			var errRead error
			payload, addr, dstPort, errRead = c.recvHandle.Read()
			if errRead != nil {
				return 0, nil, errRead
			}
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

	// Route via Upstream SOCKS5 if active (Client Outbound)
	c.upstreamMu.Lock()
	uConn := c.upstreamConn
	c.upstreamMu.Unlock()

	if uConn != nil {
		header := make([]byte, 4)
		binary.BigEndian.PutUint16(header[0:2], uint16(srcPort))
		binary.BigEndian.PutUint16(header[2:4], uint16(len(data)))
		c.upstreamMu.Lock()
		_, err1 := uConn.Write(header)
		_, err2 := uConn.Write(data)
		c.upstreamMu.Unlock()
		if err1 != nil {
			return 0, err1
		}
		if err2 != nil {
			return 0, err2
		}
		return len(data), nil
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

	c.upstreamMu.Lock()
	if c.upstreamConn != nil {
		c.upstreamConn.Close()
		c.upstreamConn = nil
	}
	c.upstreamMu.Unlock()

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

func (c *PacketConn) pollRaw() {
	for {
		payload, addr, dstPort, err := c.recvHandle.Read()
		select {
		case <-c.ctx.Done():
			return
		case c.rawRxChan <- rawPacket{payload, addr, dstPort, err}:
		}
	}
}

func dialSOCKS5(proxyAddr, targetAddr string) (net.Conn, error) {
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		return nil, err
	}
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return nil, err
	}
	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	if buf[0] != 0x05 || buf[1] != 0x00 {
		return nil, fmt.Errorf("socks5 auth failed")
	}
	host, portStr, _ := net.SplitHostPort(targetAddr)
	port, _ := strconv.Atoi(portStr)
	req := []byte{0x05, 0x01, 0x00}
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			req = append(req, 0x01)
			req = append(req, ip4...)
		} else {
			req = append(req, 0x04)
			req = append(req, ip.To16()...)
		}
	} else {
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	}
	req = append(req, byte(port>>8), byte(port))
	if _, err := conn.Write(req); err != nil {
		return nil, err
	}
	resp := make([]byte, 10)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return nil, err
	}
	if resp[1] != 0x00 {
		return nil, fmt.Errorf("socks5 connect failed: %x", resp[1])
	}
	return conn, nil
}

func (c *PacketConn) dialUpstreamKeepalive(proxyAddr, targetAddr string) {
	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}
		conn, err := dialSOCKS5(proxyAddr, targetAddr)
		if err != nil {
			flog.Errorf("Upstream SOCKS5 connect failed: %v", err)
			time.Sleep(2 * time.Second)
			continue
		}
		flog.Infof("Upstream SOCKS5 connected to %s via %s", targetAddr, proxyAddr)
		c.upstreamMu.Lock()
		c.upstreamConn = conn
		c.upstreamMu.Unlock()

		buf := make([]byte, 1)
		_, err = conn.Read(buf)

		c.upstreamMu.Lock()
		if c.upstreamConn != nil {
			c.upstreamConn.Close()
			c.upstreamConn = nil
		}
		c.upstreamMu.Unlock()
		flog.Warnf("Upstream SOCKS5 disconnected: %v. Reconnecting...", err)
		time.Sleep(1 * time.Second)
	}
}

func (c *PacketConn) listenUpstream(addr string) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		flog.Errorf("UpstreamListen failed: %v", err)
		return
	}
	go func() {
		<-c.ctx.Done()
		l.Close()
	}()
	flog.Infof("Server Upstream TCP listening on %s for inbound SOCKS5 connections", addr)
	for {
		conn, err := l.Accept()
		if err != nil {
			select {
			case <-c.ctx.Done():
				return
			default:
				continue
			}
		}
		flog.Infof("Accepted inbound upstream TCP from %s", conn.RemoteAddr())
		go func(conn net.Conn) {
			defer conn.Close()
			header := make([]byte, 4)
			for {
				if _, err := io.ReadFull(conn, header); err != nil {
					return
				}
				clientPort := binary.BigEndian.Uint16(header[0:2])
				length := binary.BigEndian.Uint16(header[2:4])
				data := make([]byte, length)
				if _, err := io.ReadFull(conn, data); err != nil {
					return
				}

				taddr := conn.RemoteAddr().(*net.TCPAddr)
				mappedIP := c.recvHandle.MapIP(taddr.IP)
				newAddr := &net.UDPAddr{IP: mappedIP, Port: int(clientPort)}

				select {
				case <-c.ctx.Done():
					return
				case c.tcpRxChan <- tcpPacket{data: data, addr: newAddr}:
				}
			}
		}(conn)
	}
}
