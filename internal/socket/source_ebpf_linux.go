//go:build linux

package socket

import (
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

	// Attach the program to the interface using XDP (Faster than TC)
	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpMain,
		Interface: cfg.Interface.Index,
	})
	if err != nil {
		objs.Close()
		return nil, fmt.Errorf("failed to attach XDP: %w", err)
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

	// Copy data to a new slice (RecvHandle expects to own the data)
	data := make([]byte, len(record.RawSample))
	copy(data, record.RawSample)
	return data, nil
}

func (s *EBPFSource) Close() {
	s.rd.Close()
	s.link.Close()
	s.objs.Close()
}
