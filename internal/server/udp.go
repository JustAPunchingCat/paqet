package server

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"paqet/internal/flog"
	"paqet/internal/protocol"
	"paqet/internal/tnet"
	"paqet/internal/tnet/udp"
	"strings"
	"sync"
	"time"
)

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 65535+2)
		return &b
	},
}

func (s *Server) handleDatagramProtocol(ctx context.Context, strm tnet.Strm, p *protocol.Proto) error {
	// Enable unordered mode for this stream to avoid Head-of-Line blocking
	// This is now the default for the custom UDP muxer, but we can be explicit.
	if udpStrm, ok := strm.(*udp.Strm); ok {
		udpStrm.SetUnordered(true)
	} else if unorderable, ok := strm.(interface{ SetUnordered(bool) }); ok {
		unorderable.SetUnordered(true)
	}

	clientInfo := strm.RemoteAddr().String()
	if s.pConn != nil {
		if actualPort := s.pConn.GetClientPort(strm.RemoteAddr()); actualPort > 0 {
			clientInfo = fmt.Sprintf("%s (via :%d)", strm.RemoteAddr(), actualPort)
		}
	}

	flog.Infof("accepted UDP Datagram stream %d: %s -> %s", strm.SID(), clientInfo, p.Addr.String())
	// Use a handler that deals with raw datagrams, not length-prefixed streams.
	return s.handleDatagram(ctx, strm, p.Addr.String())
}

func (s *Server) handleUDPProtocol(ctx context.Context, strm tnet.Strm, p *protocol.Proto) error {
	clientInfo := strm.RemoteAddr().String()
	if s.pConn != nil {
		if actualPort := s.pConn.GetClientPort(strm.RemoteAddr()); actualPort > 0 {
			clientInfo = fmt.Sprintf("%s (via :%d)", strm.RemoteAddr(), actualPort)
		}
	}

	flog.Infof("accepted UDP stream %d: %s -> %s", strm.SID(), clientInfo, p.Addr.String())
	return s.handleUDP(ctx, strm, p.Addr.String())
}

const udpIdleTimeout = 30 * time.Second

func (s *Server) handleUDP(ctx context.Context, strm tnet.Strm, addr string) error {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		flog.Errorf("failed to establish UDP connection to %s for stream %d: %v", addr, strm.SID(), err)
		strm.Close()
		return err
	}
	defer func() {
		conn.Close()
		strm.Close()
		flog.Debugf("closed UDP connection %s for stream %d", addr, strm.SID())
	}()
	flog.Debugf("UDP connection established to %s for stream %d", addr, strm.SID())

	errChan := make(chan error, 2)
	go func() {
		err := s.udpToStream(conn, strm)
		errChan <- err
	}()
	go func() {
		err := s.streamToUDP(strm, conn)
		errChan <- err
	}()

	select {
	case err := <-errChan:
		// Ignore errors caused by normal closing or timeouts which are expected
		if err != nil && err != io.EOF &&
			!strings.Contains(err.Error(), "use of closed network connection") &&
			!strings.Contains(err.Error(), "timeout") &&
			!strings.Contains(err.Error(), "i/o timeout") {
			flog.Errorf("UDP stream %d to %s failed: %v", strm.SID(), addr, err)
			return err
		}
	case <-ctx.Done():
		return nil
	}

	return nil
}

func (s *Server) udpToStream(conn net.Conn, strm tnet.Strm) error {
	bufp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufp)
	buf := *bufp

	for {
		conn.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		n, err := conn.Read(buf[2:])
		if err != nil {
			return err
		}

		// Write length prefix (2 bytes) + Data
		binary.BigEndian.PutUint16(buf[:2], uint16(n))

		strm.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, errWrite := strm.Write(buf[:2+n])
		strm.SetWriteDeadline(time.Time{})
		if errWrite != nil {
			return errWrite
		}
	}
}

func (s *Server) handleDatagram(ctx context.Context, strm tnet.Strm, addr string) error {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		flog.Errorf("failed to establish UDP connection to %s for datagram stream %d: %v", addr, strm.SID(), err)
		strm.Close()
		return err
	}
	defer func() {
		conn.Close()
		strm.Close()
		flog.Debugf("closed UDP connection %s for datagram stream %d", addr, strm.SID())
	}()
	flog.Debugf("UDP datagram connection established to %s for stream %d", addr, strm.SID())

	errChan := make(chan error, 2)
	go func() {
		bufp := bufPool.Get().(*[]byte)
		defer bufPool.Put(bufp)
		buf := *bufp
		for {
			strm.SetReadDeadline(time.Now().Add(udpIdleTimeout))
			n, err := strm.Read(buf)
			if err != nil {
				errChan <- err
				return
			}
			conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, err = conn.Write(buf[:n])
			conn.SetWriteDeadline(time.Time{})
			if err != nil {
				errChan <- err
				return
			}
		}
	}()
	go func() {
		bufp := bufPool.Get().(*[]byte)
		defer bufPool.Put(bufp)
		buf := *bufp
		for {
			conn.SetReadDeadline(time.Now().Add(udpIdleTimeout))
			n, err := conn.Read(buf)
			if err != nil {
				errChan <- err
				return
			}
			strm.SetWriteDeadline(time.Now().Add(5 * time.Second))
			_, err = strm.Write(buf[:n])
			strm.SetWriteDeadline(time.Time{})
			if err != nil {
				errChan <- err
				return
			}
		}
	}()

	select {
	case err := <-errChan:
		// Ignore errors caused by normal closing or timeouts which are expected
		if err != nil && err != io.EOF &&
			!strings.Contains(err.Error(), "use of closed network connection") &&
			!strings.Contains(err.Error(), "timeout") &&
			!strings.Contains(err.Error(), "i/o timeout") {
			flog.Errorf("UDP datagram stream %d to %s failed: %v", strm.SID(), addr, err)
			return err
		}
	case <-ctx.Done():
		return nil
	}

	return nil
}

func (s *Server) streamToUDP(strm tnet.Strm, conn net.Conn) error {
	bufp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufp)
	buf := *bufp

	for {
		strm.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		if _, err := io.ReadFull(strm, buf[:2]); err != nil {
			return err
		}
		length := int(binary.BigEndian.Uint16(buf[:2]))

		if _, err := io.ReadFull(strm, buf[:length]); err != nil {
			return err
		}

		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, err := conn.Write(buf[:length])
		conn.SetWriteDeadline(time.Time{})
		if err != nil {
			return err
		}
	}
}

