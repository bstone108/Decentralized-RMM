//go:build darwin

package host

func enrich(s *Snapshot) {
	s.InitSystem = "launchd"
	s.DisplayServer = "aqua"
	s.SessionType = "graphical"
	s.Distro = "macos"
}
