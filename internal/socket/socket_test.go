package socket

import (
	"encoding/binary"
	"net"
	"paqet/internal/conf"
	"paqet/internal/pkg/iterator"
	"sync"
	"testing"
	"time"

	"github.com/gopacket/gopacket/layers"
)

type captureInjector struct {
	mu      sync.Mutex
	packets [][]byte
}

func (c *captureInjector) WritePacketData(data []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	b := make([]byte, len(data))
	copy(b, data)
	c.packets = append(c.packets, b)
	return nil
}

func (c *captureInjector) Close() {}

func TestStatefulTCPDisguiseProgression(t *testing.T) {
	hw, _ := net.ParseMAC("00:11:22:33:44:55")
	dstHW, _ := net.ParseMAC("66:77:88:99:aa:bb")
	srcIP := net.ParseIP("192.168.1.100").To4()
	dstIP := net.ParseIP("1.2.3.4").To4()

	cfg := &conf.Network{
		Interface: &net.Interface{HardwareAddr: hw},
		Driver:    "ebpf",
		Port:      12345,
		IPv4: conf.Addr{
			Addr:   &net.UDPAddr{IP: srcIP, Port: 12345},
			Router: dstHW,
		},
		TCP: conf.TCP{
			LF_: []string{"PA"},
		},
	}
	cfg.TCP.LF = []conf.TCPF{{PSH: true, ACK: true}}

	synOptions := []layers.TCPOption{
		{OptionType: layers.TCPOptionKindMSS, OptionLength: 4, OptionData: []byte{0x05, 0xb4}},
		{OptionType: layers.TCPOptionKindSACKPermitted, OptionLength: 2},
		{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: make([]byte, 8)},
		{OptionType: layers.TCPOptionKindNop},
		{OptionType: layers.TCPOptionKindWindowScale, OptionLength: 3, OptionData: []byte{8}},
	}
	ackOptions := []layers.TCPOption{
		{OptionType: layers.TCPOptionKindNop},
		{OptionType: layers.TCPOptionKindNop},
		{OptionType: layers.TCPOptionKindTimestamps, OptionLength: 10, OptionData: make([]byte, 8)},
	}

	inj := &captureInjector{}
	sh := &SendHandle{
		injector:    inj,
		cfg:         cfg,
		driver:      cfg.Driver,
		srcPort:     12345,
		srcIPv4:     srcIP,
		srcIPv4RHWA: dstHW,
		synOptions:  synOptions,
		ackOptions:  ackOptions,
		tcpF:        TCPF{tcpF: iterator.Iterator[conf.TCPF]{Items: cfg.TCP.LF}, clientTCPF: make(map[uint64]*iterator.Iterator[conf.TCPF])},
		startTime:   time.Now(),
		globalState: &flowState{ipId: 100, baseTS: 1000, seq: 100000},
		spoofStates: make(map[string]*flowState),
		nameMapping: make(map[string]string),
		packetPool: sync.Pool{
			New: func() any {
				b := make([]byte, 65536)
				return &b
			},
		},
	}

	targetAddr := &net.UDPAddr{IP: dstIP, Port: 10000}

	// 1. Send Packet 1: 500 bytes
	p1 := make([]byte, 500)
	if err := sh.Write(p1, targetAddr, 12345); err != nil {
		t.Fatalf("Write 1 failed: %v", err)
	}

	// 2. Send Packet 2: 1350 bytes
	p2 := make([]byte, 1350)
	if err := sh.Write(p2, targetAddr, 12345); err != nil {
		t.Fatalf("Write 2 failed: %v", err)
	}

	// 3. Send Packet 3: 80 bytes
	p3 := make([]byte, 80)
	if err := sh.Write(p3, targetAddr, 12345); err != nil {
		t.Fatalf("Write 3 failed: %v", err)
	}

	if len(inj.packets) != 3 {
		t.Fatalf("expected 3 packets, got %d", len(inj.packets))
	}

	// Parse sequence numbers from TCP header (offset 34 + 4 = 38 in Ethernet+IPv4 packet)
	seq1 := binary.BigEndian.Uint32(inj.packets[0][38:42])
	seq2 := binary.BigEndian.Uint32(inj.packets[1][38:42])
	seq3 := binary.BigEndian.Uint32(inj.packets[2][38:42])

	if seq1 != 100000 {
		t.Errorf("expected seq1=100000, got %d", seq1)
	}
	if seq2 != seq1+500 {
		t.Errorf("expected seq2=%d (seq1+500), got %d", seq1+500, seq2)
	}
	if seq3 != seq2+1350 {
		t.Errorf("expected seq3=%d (seq2+1350), got %d", seq2+1350, seq3)
	}

	// 4. Simulate remote peer incoming packet: Seq = 50000, PayloadLen = 1200, TSval = 888888
	sh.UpdateRemoteFlow(dstIP, 50000, 1200, 888888)

	// 5. Send Packet 4: 200 bytes
	p4 := make([]byte, 200)
	if err := sh.Write(p4, targetAddr, 12345); err != nil {
		t.Fatalf("Write 4 failed: %v", err)
	}

	pkt4 := inj.packets[3]
	seq4 := binary.BigEndian.Uint32(pkt4[38:42])
	ack4 := binary.BigEndian.Uint32(pkt4[42:46])
	tsEcr4 := binary.BigEndian.Uint32(pkt4[62:66]) // Timestamp echo in TCP options

	if seq4 != seq3+80 {
		t.Errorf("expected seq4=%d (seq3+80), got %d", seq3+80, seq4)
	}
	if ack4 != 51200 { // 50000 + 1200
		t.Errorf("expected ack4=51200, got %d", ack4)
	}
	if tsEcr4 != 888888 {
		t.Errorf("expected tsEcr4=888888, got %d", tsEcr4)
	}
}
