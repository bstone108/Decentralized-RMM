//go:build linux

package host

import (
	"bufio"
	"os"
	"strings"
)

func enrich(s *Snapshot) {
	s.Kernel = readFirstLine("/proc/sys/kernel/osrelease")
	s.Distro, s.DistroVersion = parseOSRelease("/etc/os-release")
	s.InitSystem = detectInit()
	s.SessionType, s.DisplayServer, s.GraphicalSessionUser = detectSession()
}

func parseOSRelease(path string) (id, version string) {
	f, err := os.Open(path)
	if err != nil {
		return "", ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	vars := map[string]string{}
	for sc.Scan() {
		line := sc.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		v = strings.Trim(v, `"'`)
		vars[k] = v
	}
	return vars["ID"], vars["VERSION_ID"]
}

func detectInit() string {
	if st, err := os.Stat("/run/systemd/system"); err == nil && st.IsDir() {
		return "systemd"
	}
	if _, err := os.Stat("/sbin/openrc-run"); err == nil {
		return "openrc"
	}
	if _, err := os.Stat("/sbin/init"); err == nil {
		return "sysv"
	}
	return "unknown"
}

func detectSession() (sessionType, displayServer, user string) {
	sessionType = firstNonEmpty(os.Getenv("XDG_SESSION_TYPE"), "none")
	wayland := os.Getenv("WAYLAND_DISPLAY")
	x11 := os.Getenv("DISPLAY")
	switch {
	case wayland != "" && x11 != "":
		displayServer = "both"
	case wayland != "":
		displayServer = "wayland"
	case x11 != "":
		displayServer = "x11"
	default:
		displayServer = "none"
	}
	user = firstNonEmpty(os.Getenv("USER"), os.Getenv("LOGNAME"))
	if sessionType == "none" && displayServer != "none" {
		sessionType = "graphical"
	}
	return sessionType, displayServer, user
}

func readFirstLine(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.SplitN(string(b), "\n", 2)[0])
}

func firstNonEmpty(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
