package conf

import "runtime"

// DefaultNetfilterPath is where paqet looks for netfilter.exe (the WinDivert
// sample firewall) on Windows. The binary is NOT bundled with paqet — the
// operator installs WinDivert and points netfilter.path at their own copy.
const DefaultNetfilterPath = `C:\windows\system32\netfilter.exe`

// Netfilter configures the Windows-only kernel-RST suppressor.
//
// Why this exists: on Windows the network driver is pcap (Npcap), and pcap
// only COPIES packets to userspace — it cannot drop them from the kernel
// path. The OS kernel therefore still sees every fake-TCP segment addressed
// to a tunnel port, finds no matching socket, and answers with a TCP RST.
// The client classifies that bare RST as "closed destination port", hops
// away, and the tunnel never stabilises. netfilter.exe (WinDivert) drops
// those outbound RSTs before they leave the host — the Windows equivalent of
//
//	iptables -t mangle -A OUTPUT -p tcp --sport <PORT> --tcp-flags RST RST -j DROP
//
// which is what the Linux pcap/afpacket path requires (see `paqet iptables`).
// With the eBPF driver no suppressor is needed: XDP_DROP keeps the packets
// from reaching the kernel at all.
type Netfilter struct {
	// Enabled: nil means "auto" — true on Windows in server mode, false
	// everywhere else. Set it explicitly to override the heuristic.
	Enabled *bool `yaml:"enabled"`
	// Path to netfilter.exe. Defaults to DefaultNetfilterPath.
	Path string `yaml:"path"`
}

func (nf *Netfilter) setDefaults(role string) {
	if nf == nil {
		return
	}
	if nf.Path == "" {
		nf.Path = DefaultNetfilterPath
	}
	if nf.Enabled == nil {
		auto := runtime.GOOS == "windows" && role == "server"
		nf.Enabled = &auto
	}
}

// IsEnabled reports whether the RST suppressor should be launched.
func (nf *Netfilter) IsEnabled() bool {
	return nf != nil && nf.Enabled != nil && *nf.Enabled
}
