package server

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"paqet/internal/flog"
	"paqet/internal/protocol"
	"paqet/internal/tnet"
)

func (s *Server) handleConn(ctx context.Context, conn tnet.Conn) {
	// Stale-session guard (field-proven, run 14:53): after a server
	// restart, a client whose smux session predates the restart keeps
	// sending data frames; the fresh smux session accepts them as a
	// corrupted handshake and then nothing ever works — silently. A REAL
	// client opens its first stream within seconds. Bound the first
	// AcceptStrm: no stream within 20s of accept = stale desynced client
	// → RST it (the client's OnRST rebuilds from scratch with a fresh
	// smux handshake) instead of leaving a zombie session.
	first := true
	for {
		select {
		case <-ctx.Done():
			flog.Debugf("stopping smux session for %s due to context cancellation", conn.RemoteAddr())
			return
		default:
		}
		var strm tnet.Strm
		var err error
		if first {
			acceptDone := make(chan struct{})
			var acceptErr error
			go func() {
				strm, acceptErr = conn.AcceptStrm()
				close(acceptDone)
			}()
			select {
			case <-acceptDone:
				if acceptErr != nil {
					err = acceptErr
					strm = nil
				}
			case <-time.After(20 * time.Second):
				flog.Warnf("no stream within 20s from %s — stale/desynced session, closing", conn.RemoteAddr())
				if s.pConn != nil {
					if udp, ok := conn.RemoteAddr().(*net.UDPAddr); ok && udp.IP != nil {
						// udp is the CANONICAL addr (IP:connID), not the wire
						// tuple. Resolve the zombie's OWN wire tuple (keyed by its
						// connID) and RST exactly that — with per-conn identity
						// this can no longer spill onto the client's healthy
						// rebuilt session (different connID). Field 19:23-19:26.
						dst := udp
						if latest := s.pConn.GetClientLatestAddr(udp); latest != nil && latest.IP != nil {
							dst = latest
						}
						s.pConn.SendRSTFrom(dst.IP, dst.Port, s.pConn.GetClientLatestSrvPort(udp))
					}
				}
				conn.Close()
				return
			}
			first = false
		} else {
			strm, err = conn.AcceptStrm()
		}
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			if strings.Contains(err.Error(), "closed network connection") || strings.Contains(err.Error(), "closed pipe") {
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
		if strings.Contains(msg, "forcibly closed") || strings.Contains(msg, "connection reset") || strings.Contains(msg, "broken pipe") || strings.Contains(msg, "closed pipe") {
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
