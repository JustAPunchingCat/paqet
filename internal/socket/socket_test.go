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
		handshake:   true,
		role:        "client",
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

	// 0. Prewarm the flow (emits 1 empty SYN packet)
	sh.PrewarmFlow(targetAddr.IP, uint16(targetAddr.Port))

	// 1. Send Packet 1: 500 bytes (data packet)
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

	// Expect 4 packets total: 1 auto-SYN + 3 data packets
	if len(inj.packets) != 4 {
		t.Fatalf("expected 4 packets, got %d", len(inj.packets))
	}

	// Packet 0: Auto-SYN packet (length = 0 payload, Flags = SYN (0x02))
	flags0 := inj.packets[0][47] // TCP flags byte (offset 14 + 20 + 13 = 47)
	if flags0&0x02 == 0 {
		t.Errorf("expected packet 0 to have SYN flag set, got 0x%02x", flags0)
	}
	seq0 := binary.BigEndian.Uint32(inj.packets[0][38:42])

	// Parse sequence numbers from TCP header (offset 34 + 4 = 38 in Ethernet+IPv4 packet)
	seq1 := binary.BigEndian.Uint32(inj.packets[1][38:42])
	seq2 := binary.BigEndian.Uint32(inj.packets[2][38:42])
	seq3 := binary.BigEndian.Uint32(inj.packets[3][38:42])

	if seq1 != seq0+1 { // SYN consumed 1 sequence number
		t.Errorf("expected seq1=%d (seq0+1), got %d", seq0+1, seq1)
	}
	if seq2 != seq1+500 {
		t.Errorf("expected seq2=%d (seq1+500), got %d", seq1+500, seq2)
	}
	if seq3 != seq2+1350 {
		t.Errorf("expected seq3=%d (seq2+1350), got %d", seq2+1350, seq3)
	}

	// 4. Simulate remote peer incoming packet: from dstIP:10000 to srcIP:12345, Seq = 50000, PayloadLen = 1200, TSval = 888888
	sh.UpdateRemoteFlow(dstIP, 10000, srcIP, 12345, 50000, 1200, 888888)

	// 5. Send Packet 4: 200 bytes
	p4 := make([]byte, 200)
	if err := sh.Write(p4, targetAddr, 12345); err != nil {
		t.Fatalf("Write 4 failed: %v", err)
	}

	pkt4 := inj.packets[4]
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

func TestStateless3WayHandshake(t *testing.T) {
	hw, _ := net.ParseMAC("00:11:22:33:44:55")
	dstHW, _ := net.ParseMAC("66:77:88:99:aa:bb")
	srcIP := net.ParseIP("192.168.1.100").To4()
	dstIP := net.ParseIP("1.2.3.4").To4()

	cfg := &conf.Network{
		Interface: &net.Interface{HardwareAddr: hw},
		Driver:    "ebpf",
		Port:      10000,
		IPv4: conf.Addr{
			Addr:   &net.UDPAddr{IP: srcIP, Port: 10000},
			Router: dstHW,
		},
		TCP: conf.TCP{
			LF_: []string{"PA"},
		},
	}
	cfg.TCP.LF = []conf.TCPF{{PSH: true, ACK: true}}

	inj := &captureInjector{}
	sh := &SendHandle{
		injector:    inj,
		cfg:         cfg,
		driver:      cfg.Driver,
		srcPort:     10000,
		srcIPv4:     srcIP,
		srcIPv4RHWA: dstHW,
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

	// 1. Server receives Client SYN -> emits SYN-ACK
	if err := sh.SendSYNACK(dstIP, 50000, 10000, 1234567, 8888); err != nil {
		t.Fatalf("SendSYNACK failed: %v", err)
	}

	if len(inj.packets) != 1 {
		t.Fatalf("expected 1 packet, got %d", len(inj.packets))
	}

	synAckPkt := inj.packets[0]
	flags := synAckPkt[47]
	if flags != 0x12 { // SYN | ACK
		t.Errorf("expected flags=0x12 (SYN+ACK), got 0x%02x", flags)
	}
	ackNum := binary.BigEndian.Uint32(synAckPkt[42:46])
	if ackNum != 1234568 { // clientSeq + 1
		t.Errorf("expected ackNum=1234568, got %d", ackNum)
	}

	// 2. Client receives Server SYN-ACK -> emits ACK
	if err := sh.SendACK(dstIP, 10000, 50000, 7654321, 9999); err != nil {
		t.Fatalf("SendACK failed: %v", err)
	}

	if len(inj.packets) != 2 {
		t.Fatalf("expected 2 packets, got %d", len(inj.packets))
	}

	ackPkt := inj.packets[1]
	ackFlags := ackPkt[47]
	if ackFlags != 0x10 { // ACK
		t.Errorf("expected flags=0x10 (ACK), got 0x%02x", ackFlags)
	}
	ackAckNum := binary.BigEndian.Uint32(ackPkt[42:46])
	if ackAckNum != 7654322 { // serverSeq + 1
		t.Errorf("expected ackAckNum=7654322, got %d", ackAckNum)
	}
}
