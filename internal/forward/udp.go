package forward

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"paqet/internal/flog"
	"paqet/internal/pkg/buffer"
	"paqet/internal/tnet"
	"strings"
	"time"
)

func (f *Forward) listenUDP(ctx context.Context) {
	laddr, err := net.ResolveUDPAddr("udp", f.listenAddr)
	if err != nil {
		flog.Errorf("failed to resolve UDP listen address '%s': %v", f.listenAddr, err)
		return
	}

	conn, err := net.ListenUDP("udp", laddr)
	if err != nil {
		flog.Errorf("failed to bind UDP socket on %s: %v", laddr, err)
		return
	}
	defer conn.Close()
	go func() {
		<-ctx.Done()
		conn.Close()
	}()

	flog.Infof("UDP forwarder listening on %s -> %s", laddr, f.targetAddr)

	bufp := buffer.UPool.Get().(*[]byte)
	defer buffer.UPool.Put(bufp)
	buf := *bufp

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := f.handleUDPPacket(ctx, conn, buf); err != nil {
			if ctx.Err() == nil {
				flog.Errorf("UDP packet handling failed on %s: %v", f.listenAddr, err)
			}
		}
	}
}

func (f *Forward) handleUDPPacket(ctx context.Context, conn *net.UDPConn, buf []byte) error {
	n, caddr, err := conn.ReadFromUDP(buf)
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}

	strm, new, k, err := f.client.UDPByIndex(f.ServerIdx, caddr.String(), f.targetAddr)
	if err != nil {
		flog.Errorf("failed to establish UDP stream for %s -> %s: %v", caddr, f.targetAddr, err)
		f.client.CloseUDP(f.ServerIdx, k)
		return err
	}

	strm.SetWriteDeadline(time.Now().Add(30 * time.Second))

	// Write length prefix (2 bytes) + Data
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(n))
	strm.Write(lenBuf)
	if _, err := strm.Write(buf[:n]); err != nil {
		flog.Errorf("failed to forward %d bytes from %s -> %s: %v", n, caddr, f.targetAddr, err)
		f.client.CloseUDP(f.ServerIdx, k)
		strm.SetWriteDeadline(time.Time{})
		return err
	}
	strm.SetWriteDeadline(time.Time{})
	if new {
		flog.Infof("accepted UDP connection %d for %s -> %s", strm.SID(), caddr, f.targetAddr)
		go f.handleUDPStrm(ctx, k, strm, conn, caddr)
	}

	return nil
}

func (f *Forward) handleUDPStrm(ctx context.Context, k uint64, strm tnet.Strm, conn *net.UDPConn, caddr *net.UDPAddr) {
	bufp := buffer.UPool.Get().(*[]byte)
	defer func() {
		buffer.UPool.Put(bufp)
		flog.Debugf("UDP stream %d closed for %s -> %s", strm.SID(), caddr, f.targetAddr)
		f.client.CloseUDP(f.ServerIdx, k)
	}()
	buf := *bufp

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}
		strm.SetDeadline(time.Now().Add(30 * time.Second))
		err := CopyU(strm, conn, caddr, buf)
		strm.SetDeadline(time.Time{})
		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "closed") {
				flog.Errorf("UDP stream %d failed for %s -> %s: %v", strm.SID(), caddr, f.targetAddr, err)
			} else {
				flog.Debugf("UDP stream %d closed for %s -> %s: %v", strm.SID(), caddr, f.targetAddr, err)
			}
			return
		}
	}
}

func CopyU(dst io.ReadWriter, src *net.UDPConn, addr *net.UDPAddr, buf []byte) error {
	// Read length prefix
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(dst, lenBuf); err != nil {
		return err
	}
	length := int(binary.BigEndian.Uint16(lenBuf))

	// Read payload
	if _, err := io.ReadFull(dst, buf[:length]); err != nil {
		return err
	}

	_, err := src.WriteToUDP(buf[:length], addr)
	return err
}
