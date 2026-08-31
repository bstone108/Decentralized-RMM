//go:build !windows && !linux && !darwin

package consolegui

func newNativeBackend() Backend {
	return unsupportedNative{}
}

type unsupportedNative struct{}

func (unsupportedNative) Name() string { return "none" }

func (unsupportedNative) Open(string) (Window, error) { return nil, ErrNoDisplay }
