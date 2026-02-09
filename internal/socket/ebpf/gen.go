package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cflags "-I/usr/include/x86_64-linux-gnu" BpfRingbuf xdp_ringbuf.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cflags "-I/usr/include/x86_64-linux-gnu" BpfRingbufCompat xdp_ringbuf_compat.c
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cflags "-I/usr/include/x86_64-linux-gnu" BpfPerf xdp_perf.c
