package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target native -cflags "-I/usr/include/x86_64-linux-gnu" Bpf bpf.c
