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
	cfg    *conf.Conf
	conn   tnet.Conn
	expire time.Time
	ctx    context.Context
}

func newTimedConn(ctx context.Context, cfg *conf.Conf) (*timedConn, error) {
	var err error
	tc := timedConn{cfg: cfg, ctx: ctx}
	tc.conn, err = tc.createConn()
	if err != nil {
		return nil, err
	}

	return &tc, nil
}

func (tc *timedConn) createConn() (tnet.Conn, error) {
	netCfg := tc.cfg.Network
	pConn, err := socket.NewWithHopping(tc.ctx, &netCfg, &tc.cfg.Hopping, true)
	if err != nil {
		return nil, fmt.Errorf("could not create raw packet conn: %w", err)
	}

	// If hopping is enabled, the raw socket normalizes incoming packets to hopping.Min.
	// We must tell KCP to expect packets from this normalized port, ignoring the
	// static port defined in server.addr.
	remoteAddr := tc.cfg.Server.Addr
	if tc.cfg.Hopping.Enabled {
		clone := *remoteAddr
		clone.Port = tc.cfg.Hopping.Min
		remoteAddr = &clone
	}

	conn, err := kcp.Dial(remoteAddr, tc.cfg.Transport.KCP, pConn)
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

	p := protocol.Proto{Type: protocol.PTCPF, TCPF: tc.cfg.Network.TCP.RF}
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
