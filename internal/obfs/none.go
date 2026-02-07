package obfs

// NoneObfuscator implements a pass-through obfuscator (no-op)
type NoneObfuscator struct{}

func NewNoneObfuscator(key []byte) (Obfuscator, error) {
	return &NoneObfuscator{}, nil
}

func (o *NoneObfuscator) Name() string {
	return "none"
}

func (o *NoneObfuscator) Wrap(data []byte) ([]byte, error) {
	return data, nil
}

func (o *NoneObfuscator) Unwrap(data []byte) ([]byte, error) {
	return data, nil
}

func (o *NoneObfuscator) Overhead() int {
	return 0
}
