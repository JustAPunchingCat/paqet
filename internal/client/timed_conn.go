package client

import (
	"context"
	"fmt"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/protocol"
	"paqet/internal/socket"
	"paqet/internal/tnet"
	"paqet/internal/tnet/kcp"
	"time"
)

type timedConn struct {
	rootCfg *conf.Conf
	srvCfg  *conf.ServerConfig
	conn    tnet.Conn
	pConn   *socket.PacketConn
	expire  time.Time
	ctx     context.Context
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

	pConn, err := socket.NewWithHopping(tc.ctx, &netCfg, &tc.srvCfg.Hopping, true, obfsCfg)
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

	// Adjust MTU to account for obfuscation overhead
	kcpCfg := *tc.srvCfg.Transport.KCP
	overhead := 0
	if obfsCfg.UseTLS {
		overhead = 5 + 2 + obfsCfg.Padding.Max
	} else if obfsCfg.Padding.Enabled {
		overhead = 2 + obfsCfg.Padding.Max
	}
	if overhead > 0 {
		if kcpCfg.MTU == 0 {
			kcpCfg.MTU = 1350
		}
		kcpCfg.MTU -= overhead
		flog.Debugf("Adjusted Client KCP MTU to %d (overhead: %d)", kcpCfg.MTU, overhead)
	}

	// NAT Hole Punching: Send a raw SYN packet to initialize stateful firewalls/NATs.
	// Without this, routers will drop our PSH-ACK packets because they never saw a handshake.
	synFlag := []conf.TCPF{{SYN: true}}
	pConn.SetClientTCPF(remoteAddr, synFlag)
	pConn.WriteTo(nil, remoteAddr) // Send empty SYN
	time.Sleep(50 * time.Millisecond)

	// Restore default flags (e.g., PSH-ACK) for data transmission
	pConn.SetClientTCPF(remoteAddr, tc.rootCfg.Network.TCP.LF)

	conn, err := kcp.Dial(remoteAddr, &kcpCfg, pConn)
	if err != nil {
		pConn.Close()
		return nil, err
	}
	err = tc.sendTCPF(conn)
	if err != nil {
		pConn.Close()
		return nil, err
	}

	if tc.pConn != nil {
		tc.pConn.Close()
	}
	tc.pConn = pConn

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
	if tc.pConn != nil {
		tc.pConn.Close()
	}
}
