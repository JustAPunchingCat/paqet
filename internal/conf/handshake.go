package conf

// Handshake is a deprecated config block, retained so existing yaml files
// parse. The fake 3-way handshake was retired: the fake-TCP layer is now
// stateless (synthetic seq/ack), so there is no handshake state to maintain
// and no warm-up to perform. The block is parsed and ignored; enabling it
// has no effect.
type Handshake struct {
	Enabled   *bool  `yaml:"enabled"`
	Mode      string `yaml:"mode"`
	EagerTime int    `yaml:"eager_time"`
}

func (h *Handshake) IsEnabled() bool { return false }
func (h *Handshake) IsLazy() bool    { return true }

func (h *Handshake) setDefaults() {}
func (h *Handshake) validate() []error {
	return nil
}
