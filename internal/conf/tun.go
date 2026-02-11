package conf

type TUN struct {
	Name string `yaml:"name"`
	FD   int    `yaml:"fd"`
}

func (t *TUN) setDefaults() {
	if t.Name == "" {
		t.Name = "tun0"
	}
}

func (t *TUN) validate() []error {
	return nil
}
