package udp

import (
	"net"
	"paqet/internal/conf"
	"paqet/internal/tnet"
)

func Dial(addr *net.UDPAddr, cfg *conf.UDP, pConn net.PacketConn) (tnet.Conn, error) {
	cipher, err := newCipher(cfg.Key)
	if err != nil {
		return nil, err
	}

	// Create adapter to make PacketConn look like net.Conn for smux
	// Client writes MagicClient, expects MagicServer
	adapter := newConnAdapter(pConn, addr, cipher, MagicServer, MagicClient)

	// Start a read loop to feed the adapter
	// NOTE: In a real implementation with Demux, this loop would be centralized.
	// For a simple client Dial, we assume pConn is dedicated or filtered.
	go func() {
		buf := make([]byte, 65536)
		for {
			n, srcAddr, err := pConn.ReadFrom(buf)
			if err != nil {
				adapter.Close()
				return
			}

			// Critical: Filter out packets not from the server.
			// We must compare IP and Port strictly.
			rAddr, ok := srcAddr.(*net.UDPAddr)
			if !ok || !rAddr.IP.Equal(addr.IP) || rAddr.Port != addr.Port {
				// flog.Debugf("UDP Dial: dropped packet from %s (expected %s)", srcAddr, addr)
				continue
			}

			// Copy to avoid race conditions since decryption is now in-place
			pkt := make([]byte, n)
			copy(pkt, buf[:n])

			// Decrypt
			dec := cipher.decrypt(pkt)
			adapter.pushInput(dec)
		}
	}()

	// Force default ordered mode. Specific UDP streams will opt-in to unordered.
	return newConn(adapter, false, false, cfg.MTU), nil
}
