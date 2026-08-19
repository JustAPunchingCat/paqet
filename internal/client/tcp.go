package client

import (
	"io"
	"paqet/internal/flog"
	"paqet/internal/protocol"
	"paqet/internal/tnet"
	"strings"
	"time"
)

type clientStrm struct {
	tnet.Strm
	tc *timedConn
}

func (s *clientStrm) Read(b []byte) (int, error) {
	n, err := s.Strm.Read(b)
	if err != nil && isFatalNetworkError(err) {
		if s.tc != nil {
			s.tc.markDead()
		}
	}
	return n, err
}

func (s *clientStrm) Write(b []byte) (int, error) {
	n, err := s.Strm.Write(b)
	if err != nil && isFatalNetworkError(err) {
		if s.tc != nil {
			s.tc.markDead()
		}
	}
	return n, err
}

func isFatalNetworkError(err error) bool {
	if err == nil || err == io.EOF {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "closed network connection") ||
		strings.Contains(msg, "closed pipe") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "connection reset") ||
		strings.Contains(msg, "timeout")
}

func (c *Client) TCP(addr string) (tnet.Strm, error) {
	return c.TCPByIndex(0, addr)
}

func (c *Client) TCPByIndex(serverIdx int, addr string) (tnet.Strm, error) {
	strm, tc, err := c.newStrm(serverIdx)
	if err != nil {
		flog.Debugf("failed to create stream for TCP %s: %v", addr, err)
		return nil, err
	}

	tAddr, err := tnet.NewAddr(addr)
	if err != nil {
		flog.Debugf("invalid TCP address %s: %v", addr, err)
		strm.Close()
		return nil, err
	}

	p := protocol.Proto{Type: protocol.PTCP, Addr: tAddr}
	strm.SetWriteDeadline(time.Now().Add(5 * time.Second))
	err = p.Write(strm)
	strm.SetWriteDeadline(time.Time{})
	if err != nil {
		flog.Debugf("failed to write TCP protocol header for %s on stream %d: %v", addr, strm.SID(), err)
		strm.Close()
		if tc != nil {
			tc.markDead()
		}
		return nil, err
	}

	flog.Debugf("TCP stream %d created for %s", strm.SID(), addr)
	return &clientStrm{Strm: strm, tc: tc}, nil
}
