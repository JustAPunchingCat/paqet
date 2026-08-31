package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"paqet/internal/flog"
	"paqet/internal/pkg/buffer"
	"paqet/internal/protocol"
	"paqet/internal/tnet"
	"strings"
	"time"
)

func (s *Server) handleTCPProtocol(ctx context.Context, strm tnet.Strm, p *protocol.Proto) error {
	clientInfo := strm.RemoteAddr().String()
	if s.pConn != nil {
		if actualPort := s.pConn.GetClientPort(strm.RemoteAddr()); actualPort > 0 {
			clientInfo = fmt.Sprintf("%s (via :%d)", strm.RemoteAddr(), actualPort)
		}
	}
	flog.Infof("accepted TCP stream %d: %s -> %s", strm.SID(), clientInfo, p.Addr.String())
	return s.handleTCP(ctx, strm, p.Addr.String())
}

func (s *Server) handleTCP(ctx context.Context, strm tnet.Strm, addr string) error {
	dialer := &net.Dialer{
		Timeout: 30 * time.Second,
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		flog.Errorf("failed to establish TCP connection to %s for stream %d: %v", addr, strm.SID(), err)
		strm.Close()
		return err
	}
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
		// Fix ENOBUFS ("no buffer space available") under high throughput
		// (speedtest etc.): the kernel-default SO_SNDBUF/SO_RCVBUF is too
		// small for the tunnel's bursty relay, and the zero-copy relay
		// path fails instead of back-pressuring. Raise both explicitly.
		tcpConn.SetWriteBuffer(s.cfg.Transport.SockBuf)
		tcpConn.SetReadBuffer(s.cfg.Transport.SockBuf)
	}
	defer func() {
		conn.Close()
		strm.Close()
		flog.Debugf("closed TCP connection %s for stream %d", addr, strm.SID())
	}()
	flog.Debugf("TCP connection established to %s for stream %d", addr, strm.SID())

	if err := buffer.RelayTCP(ctx, conn, strm); err != nil && err != io.EOF {
		msg := err.Error()
		if strings.Contains(msg, "forcibly closed") || strings.Contains(msg, "connection reset") || strings.Contains(msg, "broken pipe") {
			flog.Debugf("TCP stream %d to %s closed (remote disconnect): %v", strm.SID(), addr, err)
			return nil
		}
		flog.Errorf("TCP stream %d to %s failed: %v", strm.SID(), addr, err)
		return err
	}
	return nil
}
