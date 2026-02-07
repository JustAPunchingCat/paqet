package client

import (
	"fmt"
	"paqet/internal/flog"
	"paqet/internal/tnet"
	"time"
)

func (c *Client) newConn(serverIdx int) (tnet.Conn, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if serverIdx < 0 || serverIdx >= len(c.iters) || c.iters[serverIdx] == nil {
		return nil, fmt.Errorf("invalid server index: %d", serverIdx)
	}

	autoExpire := 300
	tc := c.iters[serverIdx].Next()
	go tc.sendTCPF(tc.conn)
	err := tc.conn.Ping(false)
	if err != nil {
		flog.Infof("connection lost to %s, retrying....", tc.srvCfg.Server.Addr)
		if tc.conn != nil {
			tc.conn.Close()
		}
		if c, err := tc.createConn(); err == nil {
			tc.conn = c
		}
		tc.expire = time.Now().Add(time.Duration(autoExpire) * time.Second)
	}
	return tc.conn, nil
}

func (c *Client) newStrm(serverIdx int) (tnet.Strm, error) {
	conn, err := c.newConn(serverIdx)
	if err != nil {
		flog.Debugf("session creation failed, retrying")
		return c.newStrm(serverIdx)
	}
	strm, err := conn.OpenStrm()
	if err != nil {
		flog.Debugf("failed to open stream, retrying: %v", err)
		return c.newStrm(serverIdx)
	}
	return strm, nil
}
