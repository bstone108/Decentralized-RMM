package host

import (
	"os"
	"runtime"
	"time"
)

type Snapshot struct {
	Hostname             string    `json:"hostname"`
	OS                   string    `json:"os"`
	Arch                 string    `json:"arch"`
	GoVersion            string    `json:"goVersion"`
	Kernel               string    `json:"kernel,omitempty"`
	Distro               string    `json:"distro,omitempty"`
	DistroVersion        string    `json:"distroVersion,omitempty"`
	InitSystem           string    `json:"initSystem,omitempty"`
	SessionType          string    `json:"sessionType,omitempty"`
	DisplayServer        string    `json:"displayServer,omitempty"`
	GraphicalSessionUser string    `json:"graphicalSessionUser,omitempty"`
	CollectedAt          time.Time `json:"collectedAt"`
}

func Collect() Snapshot {
	hn, _ := os.Hostname()
	s := Snapshot{
		Hostname:    hn,
		OS:          runtime.GOOS,
		Arch:        runtime.GOARCH,
		GoVersion:   runtime.Version(),
		CollectedAt: time.Now().UTC(),
	}
	enrich(&s)
	return s
}
