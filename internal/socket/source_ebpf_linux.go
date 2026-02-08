package socket

import (
	"encoding/binary"
	"errors"
	"fmt"
	"paqet/internal/conf"
	"paqet/internal/socket/ebpf"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type EBPFSource struct {
	objs *ebpf.BpfObjects
	link link.Link
	rd   *ringbuf.Reader
}

func newEBPFSource(cfg *conf.Network, hopping *conf.Hopping) (PacketSource, error) {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock limit: %w", err)
	}

	// Load pre-compiled programs and maps into the kernel.
	objs := ebpf.BpfObjects{}
	if err := ebpf.LoadBpfObjects(&objs, nil); err != nil {
		return nil, fmt.Errorf("loading objects: %w", err)
	}

	// Populate allowed ports map
	ports := make(map[uint16]uint8)
	ports[uint16(cfg.Port)] = 1

	if hopping != nil && hopping.Enabled {
		ranges, err := hopping.GetRanges()
		if err == nil {
			for _, r := range ranges {
				for p := r.Min; p <= r.Max; p++ {
					ports[uint16(p)] = 1
				}
			}
		}
	}

	for p := range ports {
		key := p
		val := uint8(1)
		if err := objs.AllowedPorts.Put(&key, &val); err != nil {
			objs.Close()
			return nil, fmt.Errorf("failed to update port map: %w", err)
		}
	}

	// Attach the program to the interface using TC
	l, err := link.AttachTCX(link.TCXOptions{
		Interface: cfg.Interface.Index,
		Program:   objs.ClsMain,
		Attach:    link.TCXAttachIngress,
	})
	if err != nil {
		// Fallback to legacy TC if TCX is not supported (older kernels)
		// Note: cilium/ebpf link.AttachTCX is for newer kernels (5.10+ with CONFIG_BPF_JIT)
		// For broad compatibility, one might use netlink to attach to clsact qdisc.
		// But link.AttachTCX is the modern way.
		objs.Close()
		return nil, fmt.Errorf("failed to attach TCX: %w", err)
	}

	// Open a ringbuf reader from userspace to receive packets
	rd, err := ringbuf.NewReader(objs.Packets)
	if err != nil {
		l.Close()
		objs.Close()
		return nil, fmt.Errorf("opening ringbuf reader: %w", err)
	}

	return &EBPFSource{
		objs: &objs,
		link: l,
		rd:   rd,
	}, nil
}

func (s *EBPFSource) ReadPacketData() ([]byte, error) {
	record, err := s.rd.Read()
	if err != nil {
		return nil, err
	}

	// Parse length from the beginning of the sample
	if len(record.RawSample) < 4 {
		return nil, errors.New("packet too short from ringbuf")
	}
	pktLen := binary.LittleEndian.Uint32(record.RawSample[:4])
	if int(pktLen) > len(record.RawSample)-4 {
		return nil, errors.New("malformed packet length in ringbuf")
	}

	// Copy data to a new slice (RecvHandle expects to own the data)
	data := make([]byte, pktLen)
	copy(data, record.RawSample[4:4+pktLen])
	return data, nil
}

func (s *EBPFSource) Close() {
	s.rd.Close()
	s.link.Close()
	s.objs.Close()
}
