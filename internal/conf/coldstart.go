package conf

// ColdStart tunes TCP slow-start pacing for freshly admitted 5-tuples.
//
// Rationale: a brand-new tuple that opens with a large burst (the KCP backlog
// queued at a port hop) gets flagged by stateful middleboxes and BOTH
// directions of that tuple die for its whole lifetime. Real TCP never does
// this — RFC 6928 IW10 + slow-start ramp. When enabled, the send path paces
// each tuple's opening burst accordingly and disables itself once the tuple
// is warm. Disabled by default.
//
// Client config: per-server section (cold_start under each servers: entry).
// A server section that does not set it inherits the top-level cold_start.
// Server config: top-level cold_start (applied to the server's send path).
type ColdStart struct {
	Enabled  *bool `yaml:"enabled"`  // default: false (opt-in)
	Window   int   `yaml:"window"`   // seconds a tuple is considered cold; default: 5
	IW       int   `yaml:"iw"`       // initial-window packet budget at fixed spacing; default: 10
	Interval int   `yaml:"interval"` // ms spacing inside the initial window; default: 20
}

func (c *ColdStart) setDefaults() {
	if c.Window <= 0 {
		c.Window = 5
	}
	if c.IW <= 0 {
		c.IW = 10
	}
	if c.Interval <= 0 {
		c.Interval = 20
	}
}

// IsEnabled reports whether cold-start pacing is turned on.
func (c *ColdStart) IsEnabled() bool {
	return c.Enabled != nil && *c.Enabled
}

// IsConfigured reports whether this section was explicitly set in YAML
// (as opposed to an inherited/zero value).
func (c *ColdStart) IsConfigured() bool {
	return c.Enabled != nil
}
