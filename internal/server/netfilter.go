package server

import (
	"fmt"
	"sort"
	"strings"

	"paqet/internal/conf"
	"paqet/internal/flog"
)

// netfilterProc is a running netfilter.exe child process. Stop is a no-op on
// a nil receiver, so callers can `defer proc.Stop()` unconditionally.
type netfilterProc struct {
	stop func()
}

// Stop terminates the child process.
func (p *netfilterProc) Stop() {
	if p != nil && p.stop != nil {
		p.stop()
	}
}

// serverPortRanges returns every port the server listens on for the tunnel:
// the advertised listen port plus all hopping ranges. This mirrors the port
// set the Linux `paqet iptables` helper installs rules for, and is merged so
// that N configured ranges do not become N filter clauses.
func serverPortRanges(cfg *conf.Conf) []conf.PortRange {
	if cfg == nil {
		return nil
	}
	var rs []conf.PortRange
	if cfg.Listen.Addr != nil && cfg.Listen.Addr.Port > 0 {
		p := cfg.Listen.Addr.Port
		rs = append(rs, conf.PortRange{Min: p, Max: p})
	}
	if cfg.Hopping.IsEnabled() {
		ranges, err := cfg.Hopping.GetRanges()
		if err != nil {
			flog.Warnf("netfilter: cannot resolve hopping ranges: %v", err)
		} else {
			rs = append(rs, ranges...)
		}
	}
	return mergePortRanges(rs)
}

// mergePortRanges drops invalid entries, normalises reversed bounds, sorts,
// and merges overlapping/adjacent ranges.
func mergePortRanges(in []conf.PortRange) []conf.PortRange {
	valid := make([]conf.PortRange, 0, len(in))
	for _, r := range in {
		if r.Min <= 0 || r.Max <= 0 {
			continue
		}
		if r.Min > r.Max {
			r.Min, r.Max = r.Max, r.Min
		}
		if r.Max > 65535 {
			r.Max = 65535
		}
		valid = append(valid, r)
	}
	if len(valid) == 0 {
		return nil
	}

	sort.Slice(valid, func(i, j int) bool { return valid[i].Min < valid[j].Min })

	out := []conf.PortRange{valid[0]}
	for _, r := range valid[1:] {
		last := &out[len(out)-1]
		if r.Min <= last.Max+1 { // overlapping or exactly adjacent
			if r.Max > last.Max {
				last.Max = r.Max
			}
			continue
		}
		out = append(out, r)
	}
	return out
}

// buildNetfilterFilter renders the WinDivert filter that drops outbound TCP
// RSTs originating from the server's tunnel ports. Examples:
//
//	outbound and tcp and tcp.Rst and tcp.SrcPort == 1080
//	outbound and tcp and tcp.Rst and (tcp.SrcPort == 1080 or (tcp.SrcPort >= 15000 and tcp.SrcPort <= 30000))
//
// Returns "" when there is nothing to filter.
func buildNetfilterFilter(ranges []conf.PortRange) string {
	if len(ranges) == 0 {
		return ""
	}
	parts := make([]string, 0, len(ranges))
	for _, r := range ranges {
		if r.Min == r.Max {
			parts = append(parts, fmt.Sprintf("tcp.SrcPort == %d", r.Min))
		} else {
			parts = append(parts, fmt.Sprintf("(tcp.SrcPort >= %d and tcp.SrcPort <= %d)", r.Min, r.Max))
		}
	}
	expr := parts[0]
	if len(parts) > 1 {
		expr = "(" + strings.Join(parts, " or ") + ")"
	}
	return "outbound and tcp and tcp.Rst and " + expr
}

// startServerNetfilter launches the Windows RST suppressor when configured.
// It returns nil when disabled, when no tunnel ports could be resolved, or on
// non-Windows platforms (spawnNetfilter is a stub there). It never fails the
// server start: a missing binary is a loud error, not a fatal one, because
// the tunnel still runs — just with the kernel resetting it.
func startServerNetfilter(cfg *conf.Conf) *netfilterProc {
	if cfg == nil || !cfg.Network.Netfilter.IsEnabled() {
		return nil
	}
	nf := cfg.Network.Netfilter

	filter := buildNetfilterFilter(serverPortRanges(cfg))
	if filter == "" {
		flog.Warnf("netfilter: no tunnel ports resolved — not launching %s", nf.Path)
		return nil
	}

	proc, err := spawnNetfilter(nf.Path, filter)
	if err != nil {
		flog.Errorf("netfilter: failed to launch %s: %v — the OS kernel will keep resetting the fake-TCP wire", nf.Path, err)
		return nil
	}
	flog.Infof("netfilter: dropping outbound TCP RSTs via %s (filter: %s)", nf.Path, filter)
	return proc
}
