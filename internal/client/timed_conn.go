package client

import (
	"context"
	"fmt"
	"paqet/internal/conf"
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
	pConn, err := socket.NewWithHopping(tc.ctx, &netCfg, &tc.srvCfg.Hopping, true)
	if err != nil {
		return nil, fmt.Errorf("could not create raw packet conn: %w", err)
	}

	// If hopping is enabled, the raw socket normalizes incoming packets to hopping.Min.
	// We must tell KCP to expect packets from this normalized port, ignoring the
	// static port defined in server.addr.
	remoteAddr := tc.srvCfg.Server.Addr
	if tc.srvCfg.Hopping.Enabled {
		clone := *remoteAddr
		clone.Port = tc.srvCfg.Hopping.Min
		remoteAddr = &clone
	}

	conn, err := kcp.Dial(remoteAddr, tc.srvCfg.Transport.KCP, pConn)
	if err != nil {
		return nil, err
	}
	err = tc.sendTCPF(conn)
	if err != nil {
		return nil, err
	}
	return conn, nil
}

func (tc *timedConn) waitConn() tnet.Conn {
	for {
		if c, err := tc.createConn(); err == nil {
			return c
		} else {
			time.Sleep(time.Second)
		}
	}
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
