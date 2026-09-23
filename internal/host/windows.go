//go:build windows

package host

func enrich(s *Snapshot) {
	s.InitSystem = "windows-service"
	s.DisplayServer = "win32"
	s.SessionType = "graphical"
	s.Distro = "windows"
}
