package socket

import (
	"context"
	"fmt"

	"paqet/internal/conf"
)

// Testing support: drive the REAL fake-TCP stack (SendHandle writeRaw,
// RecvHandle decode, hopping plugin, echo routing) over in-memory pipes
// instead of raw sockets. The simulation tests in internal/ use these to
// exercise the exact production path end-to-end.

// InjectTestingInjector replaces the send handle's packet sink. Only for
// tests; production code must never call this.
func (h *SendHandle) InjectTestingInjector(inj PacketInjector) {
	h.injector = inj
}

// InjectTestingSource replaces the receive handle's packet source. Only
// for tests.
func (h *RecvHandle) InjectTestingSource(src PacketSource) {
	h.source = src
}

// NewWithTestingPipes is NewWithHopping with driver="testing": no raw
// sockets are opened. Wire the pipes with InjectTestingInjector /
// InjectTestingSource before use. Both MUST be set before any traffic
// flows; a nil injector/source makes the conn a silent black hole.
func NewWithTestingPipes(ctx context.Context, cfg *conf.Network, hopping *conf.Hopping, writeHopping bool, obfsCfg *conf.Obfuscation, labels ...string) (*PacketConn, error) {
	testCfg := *cfg
	testCfg.Driver = "testing"
	// Source/injector construction is skipped for the testing driver; the
	// handles are built normally (fingerprints, ports, obfuscation state)
	// and the pipes are injected afterwards.
	if testCfg.Port == 0 {
		testCfg.Port = int(RandInRange(32768, 65535))
	}

	sendHandle, err := NewTestingSendHandle(&testCfg)
	if err != nil {
		return nil, fmt.Errorf("testing send handle: %v", err)
	}
	sendHandle.SetObfuscation(obfsCfg)

	recvHopping := hopping
	if writeHopping {
		// Clients (writeHopping=true) capture on their source port, not
		// the hopping range — mirror NewWithHopping.
		recvHopping = nil
	}
	recvHandle, err := NewTestingRecvHandle(&testCfg, recvHopping, testCfg.Role)
	if err != nil {
		return nil, fmt.Errorf("testing recv handle: %v", err)
	}

	return newPacketConn(ctx, &testCfg, sendHandle, recvHandle, hopping, writeHopping, obfsCfg, labels...)
}

// newPacketConn assembles the PacketConn from pre-built handles (shared by
// NewWithHopping and the testing constructor).
func newPacketConn(ctx context.Context, connCfg *conf.Network, sendHandle *SendHandle, recvHandle *RecvHandle, hopping *conf.Hopping, writeHopping bool, obfsCfg *conf.Obfuscation, labels ...string) (*PacketConn, error) {
	label := ""
	if len(labels) > 0 {
		label = labels[0]
	}

	innerCtx, cancel := context.WithCancel(ctx)
	conn := &PacketConn{
		cfg:        connCfg,
		sendHandle: sendHandle,
		recvHandle: recvHandle,
		ctx:        innerCtx,
		cancel:     cancel,
		plugins:    NewPluginManager(),
		readQueue:  make(chan processedPacket, 65536),
		workerChs:  make([]chan rawJob, 2),
		numWorkers: 2,
	}

	conn.workersWg.Add(conn.numWorkers)
	for i := 0; i < conn.numWorkers; i++ {
		conn.workerChs[i] = make(chan rawJob, 4096)
		go conn.workerLoop(conn.workerChs[i])
	}
	// backgroundReader is started by Start() so tests can inject pipes
	// between construction and traffic.
	if connCfg.Driver != "testing" {
		go conn.backgroundReader()
	}

	useObfs := false
	if obfsCfg != nil {
		useObfs = obfsCfg.UseTLS || obfsCfg.Padding.Enabled
	}
	if useObfs && connCfg.Transport != nil {
		var keyStr string
		if connCfg.Transport.KCP != nil && connCfg.Transport.KCP.Key != "" {
			keyStr = connCfg.Transport.KCP.Key
		} else if connCfg.Transport.QUIC != nil && connCfg.Transport.QUIC.Key != "" {
			keyStr = connCfg.Transport.QUIC.Key
		} else if connCfg.Transport.UDP != nil && connCfg.Transport.UDP.Key != "" {
			keyStr = connCfg.Transport.UDP.Key
		}
		_ = keyStr
	}

	if hopping != nil && hopping.IsEnabled() {
		hp, err := NewHoppingPlugin(hopping, writeHopping, label)
		if err != nil {
			return nil, fmt.Errorf("invalid hopping configuration: %w", err)
		}
		hp.SetSendHandle(sendHandle)
		conn.plugins.Add(hp)
	}
	return conn, nil
}

// InjectTestingInjector replaces the conn's packet sink (SendHandle).
func (c *PacketConn) InjectTestingInjector(inj PacketInjector) {
	c.sendHandle.InjectTestingInjector(inj)
}

// InjectTestingSource replaces the conn's packet source (RecvHandle).
func (c *PacketConn) InjectTestingSource(src PacketSource) {
	c.recvHandle.InjectTestingSource(src)
}

// Start launches the background reader. Required for testing conns after
// pipe injection; production conns self-start in NewWithHopping.
func (c *PacketConn) Start() {
	go c.backgroundReader()
}
