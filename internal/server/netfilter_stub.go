//go:build !windows

package server

import "fmt"

// spawnNetfilter is a stub on non-Windows platforms. Linux suppresses kernel
// RSTs with the eBPF driver's XDP_DROP (or the `paqet iptables` helper on the
// pcap/afpacket drivers), so no external WinDivert process is involved and
// the config default leaves netfilter disabled there.
func spawnNetfilter(path, filter string) (*netfilterProc, error) {
	return nil, fmt.Errorf("netfilter RST suppression is Windows-only (path %q)", path)
}
