package client

import (
	"context"
	"fmt"
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
	rootCfg *conf.Conf
	srvCfg  *conf.ServerConfig
	conn    tnet.Conn
	expire  time.Time
	ctx     context.Context
	mu      sync.Mutex
}

func newTimedConn(ctx context.Context, rootCfg *conf.Conf, srvCfg *conf.ServerConfig) (*timedConn, error) {
	var err error
	tc := timedConn{rootCfg: rootCfg, srvCfg: srvCfg, ctx: ctx}
	tc.conn, err = tc.createConn()
	if err != nil {
		return nil, err
	}

	return &tc, nil
}

func (tc *timedConn) createConn() (tnet.Conn, error) {
	netCfg := tc.rootCfg.Network
	// Use server-specific transport settings (e.g. Key) for this connection
	netCfg.Transport = &tc.srvCfg.Transport

	// Explicitly use the server's obfuscation config
	// We do not propagate global obfuscation settings to allow mixing obfuscated
	// and non-obfuscated servers. If not configured for this server, it defaults
	// to disabled (zero value).
	obfsCfg := &tc.srvCfg.Obfuscation

	pConn, err := socket.NewWithHopping(tc.ctx, &netCfg, &tc.srvCfg.Hopping, true, obfsCfg, tc.srvCfg.Server.Addr.String())
	if err != nil {
		return nil, fmt.Errorf("could not create packet conn: %w", err)
	}

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

	switch tc.srvCfg.Transport.Protocol {
	case "kcp":
		// Adjust MTU to account for obfuscation overhead
		// Make a shallow copy of Transport config to avoid modifying the global config
		tCfg := tc.srvCfg.Transport
		kcpCfg := *tCfg.KCP
		if overhead > 0 {
			if kcpCfg.MTU == 0 {
				kcpCfg.MTU = 1350
			}
			kcpCfg.MTU -= overhead
			flog.Debugf("Adjusted Client KCP MTU to %d (overhead: %d)", kcpCfg.MTU, overhead)
		}
		tCfg.KCP = &kcpCfg
		conn, err = transport.DialProto("kcp", remoteAddr, &tCfg, pConn)
	case "quic":
		conn, err = transport.DialProto("quic", remoteAddr, &tc.srvCfg.Transport, pConn)
	case "udp":
		tCfg := tc.srvCfg.Transport
		udpCfg := *tCfg.UDP
		if overhead > 0 {
			if udpCfg.MTU == 0 {
				udpCfg.MTU = 1350
			}
			udpCfg.MTU -= overhead
			flog.Debugf("Adjusted Client UDP MTU to %d (overhead: %d)", udpCfg.MTU, overhead)
		}
		tCfg.UDP = &udpCfg
		conn, err = transport.DialProto("udp", remoteAddr, &tCfg, pConn)
	case "auto":
		// Probe for best protocol
		// We need a factory to create new PacketConns for probing
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
		return nil, fmt.Errorf("unsupported protocol: %s", tc.srvCfg.Transport.Protocol)
	}

	if err != nil {
		return nil, err
	}
	err = tc.sendTCPF(conn)
	if err != nil {
		return nil, err
	}
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
