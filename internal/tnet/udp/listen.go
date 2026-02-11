package udp

import (
	"net"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/tnet"
)

// Listener implements tnet.Listener for raw UDP transport.
type Listener struct {
	packetConn net.PacketConn
	cfg        *conf.UDP
	demux      *Demux
}

// Listen creates a UDP listener that demuxes incoming packets by source address.
func Listen(cfg *conf.UDP, pConn net.PacketConn) (tnet.Listener, error) {
	cipher, err := newCipher(cfg.Key)
	if err != nil {
		return nil, err
	}

	demux := NewDemux(pConn, cipher)
	flog.Debugf("UDP listener started with packet demuxing")

	return &Listener{packetConn: pConn, cfg: cfg, demux: demux}, nil
}

func (l *Listener) Accept() (tnet.Conn, error) {
	cc, err := l.demux.Accept()
	if err != nil {
		return nil, err
	}

	// Server writes MagicServer, expects MagicClient
	reader := newClientConnReader(cc, l.packetConn, l.demux.cipher, MagicClient, MagicServer)

	return newConn(reader, true, l.cfg.Unordered), nil
}

func (l *Listener) Close() error {
	if l.demux != nil {
		l.demux.Close()
	}
	return nil
}

func (l *Listener) Addr() net.Addr {
	return l.packetConn.LocalAddr()
}
