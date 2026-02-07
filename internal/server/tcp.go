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
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		flog.Errorf("failed to establish TCP connection to %s for stream %d: %v", addr, strm.SID(), err)
		return err
	}
	defer func() {
		conn.Close()
		flog.Debugf("closed TCP connection %s for stream %d", addr, strm.SID())
	}()
	flog.Debugf("TCP connection established to %s for stream %d", addr, strm.SID())

	errChan := make(chan error, 2)
	go func() {
		err := buffer.CopyT(conn, strm)
		errChan <- err
	}()
	go func() {
		err := buffer.CopyT(strm, conn)
		errChan <- err
	}()

	select {
	case err := <-errChan:
		if err != nil && err != io.EOF {
			flog.Errorf("TCP stream %d to %s failed: %v", strm.SID(), addr, err)
			return err
		}
	case <-ctx.Done():
	}
	return nil
}
