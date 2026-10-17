package conf

import "testing"

func boolPtr(v bool) *bool { return &v }

func TestNetfilterDefaults(t *testing.T) {
	t.Run("empty path falls back to the documented default", func(t *testing.T) {
		nf := Netfilter{}
		nf.setDefaults("client")
		if nf.Path != DefaultNetfilterPath {
			t.Fatalf("path = %q, want %q", nf.Path, DefaultNetfilterPath)
		}
	})

	t.Run("explicit path and enabled are respected", func(t *testing.T) {
		nf := Netfilter{Enabled: boolPtr(false), Path: `D:\tools\nf.exe`}
		nf.setDefaults("server")
		if nf.IsEnabled() {
			t.Fatal("explicit enabled:false was overridden by the auto heuristic")
		}
		if nf.Path != `D:\tools\nf.exe` {
			t.Fatalf("explicit path overwritten: %q", nf.Path)
		}
	})

	t.Run("explicit enabled:true sticks", func(t *testing.T) {
		nf := Netfilter{Enabled: boolPtr(true)}
		nf.setDefaults("client")
		if !nf.IsEnabled() {
			t.Fatal("explicit enabled:true was overridden")
		}
	})

	t.Run("auto never enables for the client role", func(t *testing.T) {
		nf := Netfilter{}
		nf.setDefaults("client")
		if nf.IsEnabled() {
			t.Fatal("netfilter must not auto-enable for the client role")
		}
	})
}

func TestNetworkDefaultsIncludeNetfilter(t *testing.T) {
	// setDefaults on Network must propagate the netfilter defaults
	// (path + auto-enable heuristic) or the server never launches it.
	n := Network{Interface_: "lo"}
	n.Netfilter = Netfilter{}
	n.setDefaults("server")
	if n.Netfilter.Path != DefaultNetfilterPath {
		t.Fatalf("netfilter path not defaulted: %q", n.Netfilter.Path)
	}
	if n.Netfilter.Enabled == nil {
		t.Fatal("netfilter enabled was left nil (auto heuristic did not run)")
	}
}
