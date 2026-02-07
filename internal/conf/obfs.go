package conf

import "fmt"

// Obfuscation configuration for traffic obfuscation and randomization
type Obfuscation struct {
	UseTLS bool `yaml:"use_tls"`

	// Padding mode settings
	Padding struct {
		Enabled bool `yaml:"enabled"`
		Min     int  `yaml:"min"` // Minimum padding bytes (default: 16)
		Max     int  `yaml:"max"` // Maximum padding bytes (default: 128)
	} `yaml:"padding"`

	// Header randomization settings
	Headers struct {
		RandomizeTOS    bool `yaml:"randomize_tos"`    // Enable TOS randomization
		RandomizeTTL    bool `yaml:"randomize_ttl"`    // Enable TTL randomization
		RandomizeWindow bool `yaml:"randomize_window"` // Enable window randomization
	} `yaml:"headers"`
}

func (o *Obfuscation) setDefaults() {
	// Padding defaults
	if o.Padding.Min == 0 {
		o.Padding.Min = 16
	}
	if o.Padding.Max == 0 {
		o.Padding.Max = 128
	}

	// Headers defaults - enable randomization by default when obfuscation is enabled
	if o.UseTLS || o.Padding.Enabled {
		if !o.Headers.RandomizeTOS {
			o.Headers.RandomizeTOS = true
		}
		if !o.Headers.RandomizeTTL {
			o.Headers.RandomizeTTL = true
		}
		if !o.Headers.RandomizeWindow {
			o.Headers.RandomizeWindow = true
		}
	}
}

func (o *Obfuscation) validate() []error {
	var errors []error

	// Validate padding settings
	if o.Padding.Min < 0 || o.Padding.Min > 255 {
		errors = append(errors, fmt.Errorf("padding min must be between 0-255"))
	}
	if o.Padding.Max < o.Padding.Min || o.Padding.Max > 255 {
		errors = append(errors, fmt.Errorf("padding max must be between min-255"))
	}

	return errors
}
