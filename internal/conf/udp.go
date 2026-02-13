package conf

import "fmt"

type UDP struct {
	Key       string `yaml:"key"`
	MTU       int    `yaml:"mtu"`
	Unordered bool   `yaml:"unordered"`
}

func (u *UDP) setDefaults() {
	if u.MTU == 0 {
		u.MTU = 1280
	}
}

func (u *UDP) validate() []error {
	var errors []error
	if u.Key == "" {
		errors = append(errors, fmt.Errorf("UDP key is required"))
	}
	if u.MTU < 50 || u.MTU > 1500 {
		errors = append(errors, fmt.Errorf("UDP MTU must be between 50-1500 bytes"))
	}
	return errors
}
