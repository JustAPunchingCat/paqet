package server

import (
	"context"
	"fmt"
	"io"
	"strings"

	"paqet/internal/flog"
	"paqet/internal/protocol"
	"paqet/internal/tnet"
)

func (s *Server) handleConn(ctx context.Context, conn tnet.Conn) {
	// Ensure connection is closed when context is cancelled to unblock AcceptStrm
	// Use a child context to ensure the monitoring goroutine exits when handleConn returns
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	for {
		select {
		case <-ctx.Done():
			flog.Debugf("stopping smux session for %s due to context cancellation", conn.RemoteAddr())
			return
		default:
		}
		strm, err := conn.AcceptStrm()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if strings.Contains(err.Error(), "closed network connection") {
				flog.Debugf("connection from %s closed", conn.RemoteAddr())
				return
			}
			flog.Errorf("failed to accept stream on %s: %v", conn.RemoteAddr(), err)
			return
		}
		s.wg.Go(func() {
			defer strm.Close()
			if err := s.handleStrm(ctx, strm); err != nil && err != io.EOF {
				flog.Errorf("stream %d from %s closed with error: %v", strm.SID(), strm.RemoteAddr(), err)
			} else {
				flog.Debugf("stream %d from %s closed", strm.SID(), strm.RemoteAddr())
			}
		})
	}
}

func (s *Server) handleStrm(ctx context.Context, strm tnet.Strm) error {
	var p protocol.Proto
	err := p.Read(strm)
	if err != nil {
		if err == io.EOF {
			return err
		}
		msg := err.Error()
		if strings.Contains(msg, "forcibly closed") || strings.Contains(msg, "connection reset") || strings.Contains(msg, "broken pipe") {
			return nil
		}
		flog.Errorf("failed to read protocol message from stream %d: %v", strm.SID(), err)
		return err
	}

	switch p.Type {
	case protocol.PPING:
		return s.handlePing(strm)
	case protocol.PTCPF:
		if len(p.TCPF) != 0 {
			s.pConn.SetClientTCPF(strm.RemoteAddr(), p.TCPF)
		}
		return nil
	case protocol.PTCP:
		return s.handleTCPProtocol(ctx, strm, &p)
	case protocol.PUDP:
		return s.handleUDPProtocol(ctx, strm, &p)
	case protocol.PUDPDGM:
		return s.handleDatagramProtocol(ctx, strm, &p)
	default:
		flog.Errorf("unknown protocol type %d on stream %d", p.Type, strm.SID())
		return fmt.Errorf("unknown protocol type: %d", p.Type)
	}
}
