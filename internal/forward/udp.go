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
	// Increase socket buffers to 4MB to handle high-throughput bursts (e.g. QUIC/Hysteria)
	// Default OS buffers (~200KB) are too small and cause packet drops.
	conn.SetReadBuffer(4 * 1024 * 1024)
	conn.SetWriteBuffer(4 * 1024 * 1024)
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

	// Write length prefix (2 bytes) + Data
	// Combine into a single write to ensure atomicity
	// Optimization: Use buffer pool
	bufp := buffer.UPool.Get().(*[]byte)
	defer buffer.UPool.Put(bufp)
	payload := *bufp
	if cap(payload) < 2+n {
		payload = make([]byte, 2+n)
	}
	payload = payload[:2+n]
	binary.BigEndian.PutUint16(payload, uint16(n))
	copy(payload[2:], buf[:n])
	if _, err := strm.Write(payload); err != nil {
		flog.Errorf("failed to forward %d bytes from %s -> %s: %v", n, caddr, f.targetAddr, err)
		f.client.CloseUDP(f.ServerIdx, k)
		return err
	}
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

	lenBuf := make([]byte, 2)
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		// Inline CopyU logic to avoid function call overhead and reuse lenBuf
		if _, err := io.ReadFull(strm, lenBuf); err != nil {
			flog.Debugf("UDP stream %d closed/error: %v", strm.SID(), err)
			return
		}
		length := int(binary.BigEndian.Uint16(lenBuf))
		if _, err := io.ReadFull(strm, buf[:length]); err != nil {
			flog.Errorf("UDP stream %d payload read error: %v", strm.SID(), err)
			return
		}
		_, err := conn.WriteToUDP(buf[:length], caddr)

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
