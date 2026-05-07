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
	// Set UDP socket buffer sizes to handle high-throughput bursts
	// Requires corresponding net.core.rmem_max/wmem_max sysctl increases on Linux.
	conn.SetReadBuffer(f.sockBuf)
	conn.SetWriteBuffer(f.sockBuf)
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

	// Try Datagram Mode first (Best for UDP transports like QUIC/Hysteria)
	sess, newDgm, kDgm, errDgm := f.client.UDPDatagramByIndex(f.ServerIdx, caddr.String(), f.targetAddr)
	if errDgm == nil && sess != nil {
		if err := sess.Send(buf[:n]); err != nil {
			flog.Errorf("failed to forward %d bytes from %s -> %s: %v", n, caddr, f.targetAddr, err)
			f.client.CloseUDP(f.ServerIdx, kDgm)
			return err
		}
		if newDgm {
			flog.Infof("accepted UDP datagram connection %d for %s -> %s", sess.SID(), caddr, f.targetAddr)
			go f.handleUDPDatagram(ctx, kDgm, sess, conn, caddr)
		}
		return nil
	}

	// Fallback: Stream Mode with Length Prefixes (Required if using KCP transport)
	strm, newStrm, kStrm, errStrm := f.client.UDPByIndex(f.ServerIdx, caddr.String(), f.targetAddr)
	if errStrm != nil {
		flog.Errorf("failed to establish UDP stream for %s -> %s: %v", caddr, f.targetAddr, errStrm)
		return errStrm
	}

	if f.unordered {
		if unorderable, ok := strm.(interface{ SetUnordered(bool) }); ok {
			unorderable.SetUnordered(true)
		}
	}

	bufp := buffer.UPool.Get().(*[]byte)
	defer buffer.UPool.Put(bufp)
	payload := *bufp
	if cap(payload) < 2+n {
		payload = make([]byte, 2+n)
		*bufp = payload // Ensure the newly grown slice is returned to the pool!
	}
	payload = payload[:2+n]
	binary.BigEndian.PutUint16(payload, uint16(n))
	copy(payload[2:], buf[:n])

	if _, err := strm.Write(payload); err != nil {
		flog.Errorf("failed to forward %d bytes from %s -> %s: %v", n, caddr, f.targetAddr, err)
		f.client.CloseUDP(f.ServerIdx, kStrm)
		return err
	}
	if newStrm {
		flog.Infof("accepted UDP stream connection %d for %s -> %s", strm.SID(), caddr, f.targetAddr)
		go f.handleUDPStrm(ctx, kStrm, strm, conn, caddr)
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

func (f *Forward) handleUDPDatagram(ctx context.Context, k uint64, sess tnet.Strm, conn *net.UDPConn, caddr *net.UDPAddr) {
	bufp := buffer.UPool.Get().(*[]byte)
	defer func() {
		buffer.UPool.Put(bufp)
		flog.Debugf("UDP datagram stream %d closed for %s -> %s", sess.SID(), caddr, f.targetAddr)
		f.client.CloseUDP(f.ServerIdx, k)
	}()
	buf := *bufp

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		n, err := sess.Read(buf)
		if err != nil {
			flog.Debugf("UDP datagram stream %d closed/error: %v", sess.SID(), err)
			return
		}
		_, err = conn.WriteToUDP(buf[:n], caddr)
		if err != nil {
			if err != io.EOF && !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "closed") {
				flog.Errorf("UDP datagram stream %d failed for %s -> %s: %v", sess.SID(), caddr, f.targetAddr, err)
			} else {
				flog.Debugf("UDP datagram stream %d closed for %s -> %s: %v", sess.SID(), caddr, f.targetAddr, err)
			}
			return
		}
	}
}
