package server

import (
	"net"
	"testing"

	"paqet/internal/conf"
)

func boolPtr(v bool) *bool { return &v }

func TestMergePortRanges(t *testing.T) {
	cases := []struct {
		name string
		in   []conf.PortRange
		want []conf.PortRange
	}{
		{
			name: "empty",
			in:   nil,
			want: nil,
		},
		{
			name: "single port",
			in:   []conf.PortRange{{Min: 1080, Max: 1080}},
			want: []conf.PortRange{{Min: 1080, Max: 1080}},
		},
		{
			name: "overlapping ranges merge",
			in: []conf.PortRange{
				{Min: 15000, Max: 20000},
				{Min: 19000, Max: 21000},
			},
			want: []conf.PortRange{{Min: 15000, Max: 21000}},
		},
		{
			name: "adjacent ranges merge",
			in: []conf.PortRange{
				{Min: 100, Max: 200},
				{Min: 201, Max: 300},
			},
			want: []conf.PortRange{{Min: 100, Max: 300}},
		},
		{
			name: "disjoint ranges stay separate and sorted",
			in: []conf.PortRange{
				{Min: 25000, Max: 25000},
				{Min: 1080, Max: 1080},
				{Min: 15000, Max: 20000},
			},
			want: []conf.PortRange{
				{Min: 1080, Max: 1080},
				{Min: 15000, Max: 20000},
				{Min: 25000, Max: 25000},
			},
		},
		{
			name: "reversed bounds normalised and invalid dropped",
			in: []conf.PortRange{
				{Min: 500, Max: 100},
				{Min: 0, Max: 10},
				{Min: -5, Max: 5},
			},
			want: []conf.PortRange{{Min: 100, Max: 500}},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := mergePortRanges(tc.in)
			if len(got) != len(tc.want) {
				t.Fatalf("got %d ranges %v, want %d ranges %v", len(got), got, len(tc.want), tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("ranges[%d] = %+v, want %+v (all: %v)", i, got[i], tc.want[i], got)
				}
			}
		})
	}
}

func TestBuildNetfilterFilter(t *testing.T) {
	cases := []struct {
		name   string
		ranges []conf.PortRange
		want   string
	}{
		{
			name:   "no ranges",
			ranges: nil,
			want:   "",
		},
		{
			name:   "single fixed port",
			ranges: []conf.PortRange{{Min: 1080, Max: 1080}},
			want:   "outbound and tcp and tcp.Rst and tcp.SrcPort == 1080",
		},
		{
			name:   "single range",
			ranges: []conf.PortRange{{Min: 15000, Max: 30000}},
			want:   "outbound and tcp and tcp.Rst and (tcp.SrcPort >= 15000 and tcp.SrcPort <= 30000)",
		},
		{
			name: "listen port plus range",
			ranges: []conf.PortRange{
				{Min: 1080, Max: 1080},
				{Min: 15000, Max: 30000},
			},
			want: "outbound and tcp and tcp.Rst and (tcp.SrcPort == 1080 or (tcp.SrcPort >= 15000 and tcp.SrcPort <= 30000))",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := buildNetfilterFilter(tc.ranges); got != tc.want {
				t.Fatalf("filter mismatch\n got: %s\nwant: %s", got, tc.want)
			}
		})
	}
}

func TestServerPortRanges(t *testing.T) {
	t.Run("fixed listen port only", func(t *testing.T) {
		cfg := &conf.Conf{
			Listen:  conf.Server{Addr: &net.UDPAddr{Port: 1080}},
			Hopping: conf.Hopping{Enabled: boolPtr(false)},
		}
		got := serverPortRanges(cfg)
		want := []conf.PortRange{{Min: 1080, Max: 1080}}
		if len(got) != 1 || got[0] != want[0] {
			t.Fatalf("got %v, want %v", got, want)
		}
		if filter := buildNetfilterFilter(got); filter != "outbound and tcp and tcp.Rst and tcp.SrcPort == 1080" {
			t.Fatalf("unexpected filter: %s", filter)
		}
	})

	t.Run("listen port plus hopping range", func(t *testing.T) {
		cfg := &conf.Conf{
			Listen: conf.Server{Addr: &net.UDPAddr{Port: 1080}},
			Hopping: conf.Hopping{
				Enabled: boolPtr(true),
				Ports:   []string{"15000-30000"},
			},
		}
		got := serverPortRanges(cfg)
		if len(got) != 2 {
			t.Fatalf("got %d ranges %v, want 2", len(got), got)
		}
		if got[0] != (conf.PortRange{Min: 1080, Max: 1080}) || got[1] != (conf.PortRange{Min: 15000, Max: 30000}) {
			t.Fatalf("unexpected ranges: %v", got)
		}
	})

	t.Run("listen port inside hopping range collapses", func(t *testing.T) {
		cfg := &conf.Conf{
			Listen: conf.Server{Addr: &net.UDPAddr{Port: 15000}},
			Hopping: conf.Hopping{
				Enabled: boolPtr(true),
				Ports:   []string{"15000-30000"},
			},
		}
		got := serverPortRanges(cfg)
		if len(got) != 1 || got[0] != (conf.PortRange{Min: 15000, Max: 30000}) {
			t.Fatalf("got %v, want a single 15000-30000 range", got)
		}
	})

	t.Run("nil config", func(t *testing.T) {
		if got := serverPortRanges(nil); got != nil {
			t.Fatalf("got %v, want nil", got)
		}
	})
}
