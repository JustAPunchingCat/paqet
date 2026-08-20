package client

import (
	"context"
	"fmt"
	"net"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/protocol"
	"paqet/internal/socket"
	"paqet/internal/tnet"
	"paqet/internal/transport"
	"sync"
	"time"
)

type timedConn struct {
	rootCfg *conf.Conf
	srvCfg  *conf.ServerConfig
	conn    tnet.Conn
	expire  time.Time
	ctx     context.Context
	mu      sync.Mutex
}

func newTimedConn(ctx context.Context, rootCfg *conf.Conf, srvCfg *conf.ServerConfig) (*timedConn, error) {
	var err error
	tc := timedConn{rootCfg: rootCfg, srvCfg: srvCfg, ctx: ctx}
	tc.conn, err = tc.createConn()
	if err != nil {
		return nil, err
	}

	return &tc, nil
}

func (tc *timedConn) createConn() (tnet.Conn, error) {
	netCfg := tc.rootCfg.Network
	// Use server-specific transport settings (e.g. Key) for this connection
	netCfg.Transport = &tc.srvCfg.Transport
	// Explicitly copy spoof config from root
	netCfg.Spoof = tc.rootCfg.Network.Spoof

	// Explicitly use the server's obfuscation config
	// We do not propagate global obfuscation settings to allow mixing obfuscated
	// and non-obfuscated servers. If not configured for this server, it defaults
	// to disabled (zero value).
	obfsCfg := &tc.srvCfg.Obfuscation

	pConn, err := socket.NewWithHopping(tc.ctx, &netCfg, &tc.srvCfg.Hopping, true, obfsCfg, tc.srvCfg.Server.Addr.String())
	if err != nil {
		return nil, fmt.Errorf("could not create packet conn: %w", err)
	}

	// If hopping is enabled, the raw socket normalizes incoming packets to hopping.Min.
	// We must tell KCP to expect packets from this normalized port, ignoring the
	// static port defined in server.addr.
	remoteAddr := tc.srvCfg.Server.Addr
	if tc.srvCfg.Hopping.Enabled {
		clone := *remoteAddr
		canonicalPort := tc.srvCfg.Hopping.Min
		if canonicalPort == 0 {
			if ranges, _ := tc.srvCfg.Hopping.GetRanges(); len(ranges) > 0 {
				canonicalPort = ranges[0].Min
			}
		}
		clone.Port = canonicalPort
		remoteAddr = &clone
	}

	var conn tnet.Conn

	var isAutoMTU bool
	var baseMTU int

	// Calculate obfuscation overhead
	overhead := 0
	if obfsCfg.UseTLS {
		overhead = 5 + 2 + obfsCfg.Padding.Max
	} else if obfsCfg.Padding.Enabled {
		overhead = 2 + obfsCfg.Padding.Max
	}

	switch tc.srvCfg.Transport.Protocol {
	case "kcp":
		// Adjust MTU to account for obfuscation overhead
		// Make a shallow copy of Transport config to avoid modifying the global config
		tCfg := tc.srvCfg.Transport
		kcpCfg := *tCfg.KCP

		isAutoMTU = kcpCfg.MTU == 0
		if isAutoMTU {
			// Start with a safe 1380 MTU for Auto PMTUD before probing upward
			kcpCfg.MTU = 1380
			baseMTU = 1380
			flog.Infof("Auto PMTUD enabled: Starting KCP with safe MTU %d", kcpCfg.MTU)
		}

		if overhead > 0 {
			kcpCfg.MTU -= overhead
			flog.Debugf("Adjusted Client KCP MTU to %d (overhead: %d)", kcpCfg.MTU, overhead)
		}
		tCfg.KCP = &kcpCfg
		conn, err = transport.DialProto("kcp", remoteAddr, &tCfg, pConn)
	case "quic":
		conn, err = transport.DialProto("quic", remoteAddr, &tc.srvCfg.Transport, pConn)
	case "udp": // Also needs to pass `tc.rootCfg.Role` to `socket.NewWithHopping` when creating `newPConn` for probing.
		tCfg := tc.srvCfg.Transport // Create a copy of Transport config
		udpCfg := *tCfg.UDP

		isAutoMTU = udpCfg.MTU == 0
		if isAutoMTU {
			udpCfg.MTU = 1380
			baseMTU = 1380
			flog.Infof("Auto PMTUD enabled: Starting UDP with safe MTU %d", udpCfg.MTU)
		}

		if overhead > 0 {
			udpCfg.MTU -= overhead
			flog.Debugf("Adjusted Client UDP MTU to %d (overhead: %d)", udpCfg.MTU, overhead)
		}
		tCfg.UDP = &udpCfg
		conn, err = transport.DialProto("udp", remoteAddr, &tCfg, pConn)
	case "auto":
		// Probe for best protocol
		// We need a factory to create new PacketConns for probing, ensuring the role is passed
		newPConn := func() (net.PacketConn, error) {
			return socket.NewWithHopping(tc.ctx, &netCfg, &tc.srvCfg.Hopping, true, obfsCfg, tc.srvCfg.Server.Addr.String())
		}
		results, err := transport.Probe(remoteAddr, &tc.srvCfg.Transport, newPConn)
		if err != nil {
			return nil, fmt.Errorf("auto probe failed: %w", err)
		}
		best, err := transport.SelectBest(results)
		if err != nil {
			return nil, err
		}
		conn, err = transport.DialProto(best, remoteAddr, &tc.srvCfg.Transport, pConn)
	default:
		return nil, fmt.Errorf("unsupported protocol: %s", tc.srvCfg.Transport.Protocol)
	}

	if err != nil {
		return nil, err
	}
	err = tc.sendTCPF(conn)
	if err != nil {
		return nil, err
	}

	if isAutoMTU {
		tc.startPMTUD(conn, baseMTU, overhead)
	}

	return conn, nil
}

func (tc *timedConn) sendTCPF(conn tnet.Conn) error {
	strm, err := conn.OpenStrm()
	if err != nil {
		return err
	}
	defer strm.Close()

	p := protocol.Proto{Type: protocol.PTCPF, TCPF: tc.rootCfg.Network.TCP.RF}
	err = p.Write(strm)
	if err != nil {
		return err
	}
	return nil
}

func (tc *timedConn) close() {
	if tc.conn != nil {
		tc.conn.Close()
	}
}

func (tc *timedConn) startPMTUD(conn tnet.Conn, baseMTU, overhead int) {
	go func() {
		// Give the connection a moment to stabilize
		time.Sleep(1 * time.Second)

		type mtuSetter interface {
			SetMtu(int) bool
		}
		setter, ok := conn.(mtuSetter)
		if !ok {
			return
		}

		// Standard MTU steps to probe
		probeSizes := []int{1400, 1420, 1440, 1460, 1492, 1500}
		bestPayloadMTU := baseMTU - overhead

		for _, targetMTU := range probeSizes {
			testPayloadMTU := targetMTU - overhead
			if testPayloadMTU <= bestPayloadMTU {
				continue
			}

			// Dynamically update the transport MTU limit
			setter.SetMtu(testPayloadMTU)

			strm, err := conn.OpenStrm()
			if err != nil {
				break
			}

			// Send a PPING header to the server
			p := protocol.Proto{Type: protocol.PPING}
			if err := p.Write(strm); err != nil {
				strm.Close()
				break
			}

			// Write dummy data to force the transport layer to generate full-sized MTU packets.
			// We write 2x the MTU size to guarantee it fragments at the exact new MTU boundary.
			dummy := make([]byte, testPayloadMTU*2)
			strm.Write(dummy)

			// Wait for the PPONG response from the server
			strm.SetReadDeadline(time.Now().Add(2 * time.Second))
			err = p.Read(strm)
			strm.Close()

			if err != nil || p.Type != protocol.PPONG {
				flog.Infof("Auto PMTUD: Network bottleneck reached. Packet dropped at %d bytes.", targetMTU)
				break
			}

			bestPayloadMTU = testPayloadMTU
			flog.Debugf("Auto PMTUD: Successfully probed MTU %d (Payload MTU: %d)", targetMTU, testPayloadMTU)
		}

		// Lock in the highest successful MTU
		setter.SetMtu(bestPayloadMTU)
		flog.Infof("Auto PMTUD completed. Optimal Payload MTU set to: %d", bestPayloadMTU)
	}()
}
