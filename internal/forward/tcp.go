package forward

import (
	"context"
	"io"
	"net"
	"paqet/internal/flog"
	"paqet/internal/pkg/buffer"
	"strings"
)

func (f *Forward) listenTCP(ctx context.Context) error {
	listener, err := net.Listen("tcp", f.listenAddr)
	if err != nil {
		flog.Errorf("failed to bind TCP socket on %s: %v", f.listenAddr, err)
		return err
	}
	defer listener.Close()
	go func() {
		<-ctx.Done()
		listener.Close()
	}()
	flog.Infof("TCP forwarder listening on %s -> %s", f.listenAddr, f.targetAddr)

	for {
		conn, err := listener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				flog.Errorf("failed to accept TCP connection on %s: %v", f.listenAddr, err)
				continue
			}
		}

		f.wg.Go(func() {
			defer conn.Close()
			if err := f.handleTCPConn(ctx, conn); err != nil {
				flog.Errorf("TCP connection %s -> %s closed with error: %v", conn.RemoteAddr(), f.targetAddr, err)
			} else {
				flog.Debugf("TCP connection %s -> %s closed", conn.RemoteAddr(), f.targetAddr)
			}
		})
	}
}

func (f *Forward) handleTCPConn(ctx context.Context, conn net.Conn) error {
	if tcpConn, ok := conn.(*net.TCPConn); ok {
		tcpConn.SetNoDelay(true)
	}

	strm, err := f.client.TCPByIndex(f.ServerIdx, f.targetAddr)
	if err != nil && err != io.EOF {
		msg := err.Error()
		if strings.Contains(msg, "forcibly closed") || strings.Contains(msg, "connection reset") || strings.Contains(msg, "broken pipe") {
			flog.Debugf("TCP stream %d closed (client disconnect) for %s -> %s: %v", strm.SID(), conn.RemoteAddr(), f.targetAddr, err)
		} else {
			flog.Errorf("TCP stream %d failed for %s -> %s: %v", strm.SID(), conn.RemoteAddr(), f.targetAddr, err)
		}
		return err
	}
	defer func() {
		flog.Debugf("TCP stream closed for %s -> %s", conn.RemoteAddr(), f.targetAddr)
		go strm.Close() // Prevents smux FIN deadlock
	}()
	flog.Infof("accepted TCP connection %s -> %s via %s", conn.RemoteAddr(), f.targetAddr, strm.RemoteAddr())

	if err := buffer.RelayTCP(ctx, conn, strm); err != nil && err != io.EOF {
		flog.Errorf("TCP stream %d failed for %s -> %s: %v", strm.SID(), conn.RemoteAddr(), f.targetAddr, err)
		if f.client != nil {
			f.client.MarkServerStale(f.ServerIdx)
		}
		return err
	}

	return nil
}
