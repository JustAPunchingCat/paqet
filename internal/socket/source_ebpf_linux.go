//go:build linux

package socket

import (
	"encoding/binary"
	"fmt"
	"paqet/internal/conf"
	"paqet/internal/flog"
	"paqet/internal/socket/ebpf"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

type EBPFSource struct {
	// We hold references to close them later.
	// Since we might use Ringbuf OR Perf, we use generic interfaces or specific fields.
	// To keep it simple, we'll store the closers.
	objsClose func()
	link      link.Link
	rd        PacketReader
}

type PacketReader interface {
	Read() (PacketRecord, error)
	Close() error
}

type PacketRecord struct {
	RawSample []byte
}

// Wrapper for optimal ringbuf.Reader (No header)
type ringbufReader struct {
	*ringbuf.Reader
}

func (r *ringbufReader) Read() (PacketRecord, error) {
	rec, err := r.Reader.Read()
	return PacketRecord{RawSample: rec.RawSample}, err
}

// Wrapper for compat ringbuf.Reader (Has 4-byte length header)
type ringbufCompatReader struct {
	*ringbuf.Reader
}

func (r *ringbufCompatReader) Read() (PacketRecord, error) {
	rec, err := r.Reader.Read()
	if err != nil {
		return PacketRecord{}, err
	}
	// Ringbuf workaround uses a 4-byte length header
	if len(rec.RawSample) < 4 {
		return PacketRecord{RawSample: rec.RawSample}, nil // Should not happen
	}
	dataLen := binary.LittleEndian.Uint32(rec.RawSample[:4])
	return PacketRecord{RawSample: rec.RawSample[4 : 4+dataLen]}, nil
}

// Wrapper for perf.Reader to satisfy PacketReader
type perfReader struct {
	*perf.Reader
}

func (r *perfReader) Read() (PacketRecord, error) {
	rec, err := r.Reader.Read()
	return PacketRecord{RawSample: rec.RawSample}, err
}

func newEBPFSource(cfg *conf.Network, hopping *conf.Hopping) (PacketSource, error) {
	// Allow the current process to lock memory for eBPF resources.
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("failed to remove memlock limit: %w", err)
	}

	// 1. Try Optimal Ringbuf (Modern kernels 5.8+)
	source, err := loadRingbuf(cfg, hopping)
	if err == nil {
		flog.Infof("eBPF Ringbuf loader successful (modern path)")
		return source, nil
	}
	flog.Debugf("eBPF Ringbuf (optimal) failed: %v. Trying compatibility mode...", err)

	// 2. Try Compat Ringbuf (Kernels ~5.10 with strict verifier)
	source, err = loadRingbufCompat(cfg, hopping)
	if err == nil {
		flog.Infof("eBPF Ringbuf loader successful (compatibility path)")
		return source, nil
	}
	flog.Warnf("eBPF Ringbuf failed: %v. Falling back to Perf Event Array...", err)

	// 3. Fallback to Perf (Old kernels)
	return loadPerf(cfg, hopping)
}

func loadRingbuf(cfg *conf.Network, hopping *conf.Hopping) (PacketSource, error) {
	objs := ebpf.BpfRingbufObjects{}
	if err := ebpf.LoadBpfRingbufObjects(&objs, nil); err != nil {
		return nil, err
	}

	// Populate map
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

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpMain,
		Interface: cfg.Interface.Index,
	})
	if err != nil {
		objs.Close()
		return nil, err
	}

	rd, err := ringbuf.NewReader(objs.Packets)
	if err != nil {
		l.Close()
		objs.Close()
		return nil, err
	}

	return &EBPFSource{
		objsClose: func() { objs.Close() },
		link:      l,
		rd:        &ringbufReader{rd},
	}, nil
}

func loadRingbufCompat(cfg *conf.Network, hopping *conf.Hopping) (PacketSource, error) {
	objs := ebpf.BpfRingbufCompatObjects{}
	if err := ebpf.LoadBpfRingbufCompatObjects(&objs, nil); err != nil {
		return nil, err
	}

	// Populate map
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

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpMain,
		Interface: cfg.Interface.Index,
	})
	if err != nil {
		objs.Close()
		return nil, err
	}

	rd, err := ringbuf.NewReader(objs.Packets)
	if err != nil {
		l.Close()
		objs.Close()
		return nil, err
	}

	return &EBPFSource{
		objsClose: func() { objs.Close() },
		link:      l,
		rd:        &ringbufCompatReader{rd},
	}, nil
}

func loadPerf(cfg *conf.Network, hopping *conf.Hopping) (PacketSource, error) {
	objs := ebpf.BpfPerfObjects{}
	if err := ebpf.LoadBpfPerfObjects(&objs, nil); err != nil {
		return nil, err
	}

	// Populate map
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

	l, err := link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpMain,
		Interface: cfg.Interface.Index,
	})
	if err != nil {
		objs.Close()
		return nil, err
	}

	// Open perf reader
	rd, err := perf.NewReader(objs.Packets, 4096) // 4096 pages per CPU
	if err != nil {
		l.Close()
		objs.Close()
		return nil, err
	}

	return &EBPFSource{
		objsClose: func() { objs.Close() },
		link:      l,
		rd:        &perfReader{rd},
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
	if s.objsClose != nil {
		s.objsClose()
	}
}
