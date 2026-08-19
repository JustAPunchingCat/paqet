package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/protocol"
	"paqet/internal/socket"
	"paqet/internal/tnet"
	"paqet/internal/transport"
	"sync"
	"time"
)

type timedConn struct {
	rootCfg    *conf.Conf
	srvCfg     *conf.ServerConfig
	conn       tnet.Conn
	pConn      *socket.PacketConn
	lastPort   int
	lastRotate time.Time
	expire     time.Time
	ctx        context.Context
	mu         sync.Mutex
}

func newTimedConn(ctx context.Context, rootCfg *conf.Conf, srvCfg *conf.ServerConfig) (*timedConn, error) {
	tc := timedConn{
		ctx:     ctx,
		rootCfg: rootCfg,
		srvCfg:  srvCfg,
	}

	var err error
	tc.conn, err = tc.createConn()
	if err != nil {
		return nil, err
	}

	return &tc, nil
}

func (tc *timedConn) createConn() (tnet.Conn, error) {
	netCfg := tc.rootCfg.Network
	if tc.rootCfg.Network.IPv4.Addr != nil {
		cloneAddr := *tc.rootCfg.Network.IPv4.Addr
		netCfg.IPv4.Addr = &cloneAddr
	}
	if tc.rootCfg.Network.IPv6.Addr != nil {
		cloneAddr := *tc.rootCfg.Network.IPv6.Addr
		netCfg.IPv6.Addr = &cloneAddr
	}
	// Use server-specific transport settings (e.g. Key) for this connection
	netCfg.Transport = &tc.srvCfg.Transport
	// Explicitly copy spoof config from root
	netCfg.Spoof = tc.rootCfg.Network.Spoof

	// Explicitly use the server's obfuscation config
	// We do not propagate global obfuscation settings to allow mixing obfuscated
	// and non-obfuscated servers. If not configured for this server, it defaults
	// to disabled (zero value).
	obfsCfg := &tc.srvCfg.Obfuscation

	pConn, err := socket.NewWithHopping(tc.ctx, &netCfg, &tc.srvCfg.Hopping, true, obfsCfg, tc.srvCfg.Server.Addr.String())
	if err != nil {
		return nil, fmt.Errorf("could not create packet conn: %w", err)
	}
	tc.pConn = pConn
	tc.lastPort = pConn.GetCurrentPort()
	// Guard: close pConn on any error path so background goroutines and file
	// descriptors are never orphaned when the server is offline or unreachable.
	success := false
	defer func() {
		if !success {
			pConn.Close()
		}
	}()

	// If hopping is enabled, the raw socket normalizes incoming packets to hopping.Min.
	// We must tell KCP to expect packets from this normalized port, ignoring the
	// static port defined in server.addr.
	remoteAddr := tc.srvCfg.Server.Addr
	if tc.srvCfg.Hopping.Enabled {
		clone := *remoteAddr
		canonicalPort := tc.srvCfg.Hopping.Min
		if canonicalPort == 0 {
			if ranges, _ := tc.srvCfg.Hopping.GetRanges(); len(ranges) > 0 {
				canonicalPort = ranges[0].Min
			}
		}
		clone.Port = canonicalPort
		remoteAddr = &clone
	}

	var conn tnet.Conn

	// Calculate obfuscation overhead
	overhead := 0
	if obfsCfg.UseTLS {
		overhead = 5 + 2 + obfsCfg.Padding.Max
	} else if obfsCfg.Padding.Enabled {
		overhead = 2 + obfsCfg.Padding.Max
	}

	// Wait for the raw socket flow to be warmed by the background SYN/SYN-ACK handshake.
	// This prevents transports from blasting data packets into Netfilter before the state is ESTABLISHED,
	// which would cause Netfilter to drop the packets as INVALID.
	pConn.PrewarmFlow(remoteAddr.IP, uint16(remoteAddr.Port))
	for i := 0; i < 150; i++ { // Wait up to 1.5s
		if pConn.IsFlowWarmed(remoteAddr.IP, uint16(remoteAddr.Port)) {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	switch tc.srvCfg.Transport.Protocol {
	case "kcp":
		// Adjust MTU to account for obfuscation overhead
		// Make a shallow copy of Transport config to avoid modifying the global config
		tCfg := tc.srvCfg.Transport
		kcpCfg := *tCfg.KCP

		if kcpCfg.MTU == 0 {
			kcpCfg.MTU = 1350
		}
		if overhead > 0 {
			kcpCfg.MTU -= overhead
			flog.Debugf("Adjusted Client KCP MTU to %d (overhead: %d)", kcpCfg.MTU, overhead)
		}
		tCfg.KCP = &kcpCfg
		conn, err = transport.DialProto("kcp", remoteAddr, &tCfg, pConn)
	case "quic":
		conn, err = transport.DialProto("quic", remoteAddr, &tc.srvCfg.Transport, pConn)
	case "udp": // Also needs to pass `tc.rootCfg.Role` to `socket.NewWithHopping` when creating `newPConn` for probing.
		tCfg := tc.srvCfg.Transport // Create a copy of Transport config
		udpCfg := *tCfg.UDP
		if udpCfg.MTU == 0 {
			udpCfg.MTU = 1350
		}
		if overhead > 0 {
			udpCfg.MTU -= overhead
			flog.Debugf("Adjusted Client UDP MTU to %d (overhead: %d)", udpCfg.MTU, overhead)
		}
		tCfg.UDP = &udpCfg
		conn, err = transport.DialProto("udp", remoteAddr, &tCfg, pConn)
	case "auto":
		// Probe for best protocol
		// We need a factory to create new PacketConns for probing, ensuring the role is passed
		newPConn := func() (net.PacketConn, error) {
			return socket.NewWithHopping(tc.ctx, &netCfg, &tc.srvCfg.Hopping, true, obfsCfg, tc.srvCfg.Server.Addr.String())
		}
		results, err := transport.Probe(remoteAddr, &tc.srvCfg.Transport, newPConn)
		if err != nil {
			return nil, fmt.Errorf("auto probe failed: %w", err)
		}
		best, err := transport.SelectBest(results)
		if err != nil {
			return nil, err
		}

		conn, err = transport.DialProto(best, remoteAddr, &tc.srvCfg.Transport, pConn)
	default:
		return nil, fmt.Errorf("unsupported transport protocol: %s", tc.srvCfg.Transport.Protocol)
	}

	err = tc.sendTCPF(conn)
	if err != nil {
		conn.Close() // also releases pConn via the transport Close chain
		return nil, err
	}

	success = true
	return conn, nil
}

func (tc *timedConn) sendTCPF(conn tnet.Conn) error {
	strm, err := conn.OpenStrm()
	if err != nil {
		return err
	}
	defer strm.Close()

	p := protocol.Proto{Type: protocol.PTCPF, TCPF: tc.rootCfg.Network.TCP.RF}
	err = p.Write(strm)
	if err != nil {
		return err
	}
	return nil
}

func (tc *timedConn) close() {
	if tc.conn != nil {
		tc.conn.Close()
	}
}

func (tc *timedConn) reconnect() {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if !tc.lastRotate.IsZero() && time.Since(tc.lastRotate) < 5*time.Second {
		return
	}
	tc.lastRotate = time.Now()

	srvLabel := ""
	if tc.srvCfg != nil && tc.srvCfg.Server.Addr != nil {
		srvLabel = tc.srvCfg.Server.Addr.IP.String()
	}

	oldPort := tc.lastPort
	if tc.conn != nil {
		tc.conn.Close()
	}
	var err error
	tc.conn, err = tc.createConn()
	if err != nil {
		flog.Debugf("failed to reconnect timedConn [%s] on port %d: %v", srvLabel, oldPort, err)
		tc.conn = nil
	}
}

func (tc *timedConn) markDead() {
	tc.mu.Lock()
	defer tc.mu.Unlock()
	if tc.conn != nil {
		tc.conn.Close()
		tc.conn = nil
	}
}

func (tc *timedConn) openAndSendProto(p *protocol.Proto) (tnet.Strm, error) {
	tc.mu.Lock()
	defer tc.mu.Unlock()

	for attempt := 0; attempt < 2; attempt++ {
		// 1. If connection is nil, create it
		if tc.conn == nil {
			var err error
			tc.conn, err = tc.createConn()
			if err != nil {
				return nil, err
			}
		}

		// 2. Open stream
		strm, err := tc.conn.OpenStrm()
		if err != nil {
			tc.conn.Close()
			tc.conn = nil
			continue
		}

		// 3. Send protocol header
		strm.SetWriteDeadline(time.Now().Add(1500 * time.Millisecond))
		err = p.Write(strm)
		strm.SetWriteDeadline(time.Time{})
		if err != nil {
			strm.Close()
			tc.conn.Close()
			tc.conn = nil
			continue
		}

		// 4. For TCP streams, read the 1-byte readiness confirmation from server
		// to verify the connection is 100% alive and the remote target was reached.
		if p.Type == protocol.PTCP {
			strm.SetReadDeadline(time.Now().Add(1500 * time.Millisecond))
			var ack [1]byte
			_, err = io.ReadFull(strm, ack[:])
			strm.SetReadDeadline(time.Time{})
			if err != nil {
				// Server was restarted while idle: session is dead
				flog.Debugf("stale connection detected during stream handshake: %v, re-dialing...", err)
				strm.Close()
				tc.conn.Close()
				tc.conn = nil
				continue
			}
		}

		return strm, nil
	}

	return nil, fmt.Errorf("failed to open stream after reconnection attempts")
}

