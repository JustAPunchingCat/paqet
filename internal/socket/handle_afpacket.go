//go:build linux

package socket

import (
	"fmt"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"time"

	"github.com/gopacket/gopacket"
	"github.com/gopacket/gopacket/afpacket"
	"github.com/gopacket/gopacket/layers"
	"github.com/gopacket/gopacket/pcap"
	"golang.org/x/net/bpf"
)

const (
	afpacketFrameSize = 4096       // Frame size for TPacket ring buffer
	afpacketBlockSize = 512 * 1024 // 512KB per block
)

// afpacketHandle wraps an AF_PACKET TPacket to implement RawHandle.
type afpacketHandle struct {
	tpacket   *afpacket.TPacket
	srcMAC    []byte
	ifaceName string
	direction Direction
}

func newAfpacketHandle(cfg *conf.Network) (RawHandle, error) {
	ifaceName := cfg.Interface.Name

	numBlocks := cfg.PCAP.Sockbuf / afpacketBlockSize
	if numBlocks < 2 {
		numBlocks = 2
	}
	if numBlocks > 128 {
		numBlocks = 128
	}

	tpacket, err := afpacket.NewTPacket(
		afpacket.OptInterface(ifaceName),
		afpacket.OptFrameSize(afpacketFrameSize),
		afpacket.OptBlockSize(afpacketBlockSize),
		afpacket.OptNumBlocks(numBlocks),
		afpacket.OptPollTimeout(200*time.Millisecond),
		afpacket.TPacketVersion2,
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create AF_PACKET handle on %s: %v", ifaceName, err)
	}

	flog.Infof("AF_PACKET: created handle on %s with %d blocks (%d MB buffer)",
		ifaceName, numBlocks, (numBlocks*afpacketBlockSize)/(1024*1024))

	return &afpacketHandle{
		tpacket:   tpacket,
		srcMAC:    cfg.Interface.HardwareAddr,
		ifaceName: ifaceName,
		direction: DirectionInOut,
	}, nil
}

func (h *afpacketHandle) ZeroCopyReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	for {
		data, ci, err := h.tpacket.ZeroCopyReadPacketData()
		if err != nil {
			if err == afpacket.ErrTimeout {
				continue // Retry on timeout
			}
			return nil, ci, err
		}

		// Software direction filtering
		if h.direction != DirectionInOut && len(data) >= 14 && len(h.srcMAC) == 6 {
			pktSrcMAC := data[6:12]
			isOutgoing := macEqual(pktSrcMAC, h.srcMAC)

			if h.direction == DirectionIn && isOutgoing {
				continue
			}
			if h.direction == DirectionOut && !isOutgoing {
				continue
			}
		}

		return data, ci, nil
	}
}

func (h *afpacketHandle) WritePacketData(data []byte) error {
	return h.tpacket.WritePacketData(data)
}

func (h *afpacketHandle) SetBPFFilter(filter string) error {
	rawBPF, err := compileBPFFilter(filter)
	if err != nil {
		return fmt.Errorf("failed to compile BPF filter: %v", err)
	}
	return h.tpacket.SetBPF(rawBPF)
}

func (h *afpacketHandle) SetDirection(dir Direction) error {
	h.direction = dir
	return nil
}

func (h *afpacketHandle) Close() {
	if h.tpacket != nil {
		h.tpacket.Close()
		h.tpacket = nil
	}
}

func macEqual(a, b []byte) bool {
	if len(a) != 6 || len(b) != 6 {
		return false
	}
	return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] &&
		a[3] == b[3] && a[4] == b[4] && a[5] == b[5]
}

func compileBPFFilter(filter string) ([]bpf.RawInstruction, error) {
	// Use pcap to compile the BPF filter for Ethernet
	pcapBPF, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, 65535, filter)
	if err != nil {
		return nil, err
	}

	raw := make([]bpf.RawInstruction, len(pcapBPF))
	for i, ins := range pcapBPF {
		raw[i] = bpf.RawInstruction{
			Op: ins.Code,
			Jt: ins.Jt,
			Jf: ins.Jf,
			K:  ins.K,
		}
	}
	return raw, nil
}
