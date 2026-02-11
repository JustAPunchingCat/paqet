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
	"sync"
	"time"
)

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 65535+2)
		return &b
	},
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

func (s *Server) handleUDP(ctx context.Context, strm tnet.Strm, addr string) error {
	conn, err := net.Dial("udp", addr)
	if err != nil {
		flog.Errorf("failed to establish UDP connection to %s for stream %d: %v", addr, strm.SID(), err)
		return err
	}
	if udpConn, ok := conn.(*net.UDPConn); ok {
		// Increase socket buffers to 4MB to prevent drops during bursts
		udpConn.SetReadBuffer(4 * 1024 * 1024)
		udpConn.SetWriteBuffer(4 * 1024 * 1024)
	}
	defer func() {
		conn.Close()
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
		if err != nil && err != io.EOF {
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
		conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		// Read into buf starting at offset 2 to leave room for header
		n, err := conn.Read(buf[2:])
		if err != nil {
			return err
		}

		// Write length prefix (2 bytes) + Data
		binary.BigEndian.PutUint16(buf[:2], uint16(n))

		strm.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if _, err := strm.Write(buf[:2+n]); err != nil {
			return err
		}
	}
}

func (s *Server) streamToUDP(strm tnet.Strm, conn net.Conn) error {
	bufp := bufPool.Get().(*[]byte)
	defer bufPool.Put(bufp)
	buf := *bufp

	for {
		strm.SetReadDeadline(time.Now().Add(30 * time.Second))
		// Read length prefix into the first 2 bytes of buf
		if _, err := io.ReadFull(strm, buf[:2]); err != nil {
			return err
		}
		length := int(binary.BigEndian.Uint16(buf[:2]))

		// Read payload into buf starting at 0 (overwriting header, which is fine)
		if _, err := io.ReadFull(strm, buf[:length]); err != nil {
			return err
		}

		conn.SetWriteDeadline(time.Now().Add(30 * time.Second))
		if _, err := conn.Write(buf[:length]); err != nil {
			return err
		}
	}
}
