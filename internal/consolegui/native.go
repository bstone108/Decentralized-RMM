package consolegui

// Native returns the OS-native GUI backend for this binary.
// It is not a TUI and not a web server. Toolkits: Win32, X11, Aqua.
func Native() Backend {
	return newNativeBackend()
}
