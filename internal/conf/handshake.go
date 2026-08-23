package conf

import "fmt"

// Handshake configures the fake TCP 3-way handshake used to satisfy strict
// DPI/Netfilter middleboxes that drop flows without a proper SYN exchange.
// It is server-dependent (each remote server enables it independently) and
// applies regardless of whether port hopping is enabled.
type Handshake struct {
	Enabled   *bool  `yaml:"enabled"`    // Fake handshake on/off (default: false)
	Mode      string `yaml:"mode"`       // "lazy" (default) or "eager"
	EagerTime int    `yaml:"eager_time"` // Eager-mode lead time in seconds (default: 3)
}

// IsEnabled reports whether the fake handshake is enabled. Defaults to false.
func (h *Handshake) IsEnabled() bool {
	return h.Enabled != nil && *h.Enabled
}

// IsLazy reports whether the fake handshake should be performed lazily, i.e.
// fire the SYN and wait for the SYN-ACK right before the first data packet.
// Defaults to lazy when unset.
func (h *Handshake) IsLazy() bool {
	return h.Mode != "eager"
}

func (h *Handshake) setDefaults() {
	if h.Enabled == nil {
		def := false
		h.Enabled = &def
	}
	if h.Mode == "" {
		h.Mode = "lazy"
	}
	if h.EagerTime == 0 {
		h.EagerTime = 3
	}
}

func (h *Handshake) validate() []error {
	if h.Mode != "lazy" && h.Mode != "eager" {
		return []error{fmt.Errorf("handshake mode must be 'lazy' or 'eager'")}
	}
	return nil
}
