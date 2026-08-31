package consoleui

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"

	"github.com/bstone108/Decentralized-RMM/internal/enroll"
)

// Presenter shows enrollment/update policy in a native operator surface.
// The product console is the native GUI in internal/consolegui; this package
// is POLICY visibility only. It is not a TUI and not a mandatory web console.
type Presenter interface {
	ShowPolicy(title, body string) error
}

type Recorder struct {
	LastTitle string
	LastBody  string
}

func (r *Recorder) ShowPolicy(title, body string) error {
	r.LastTitle = title
	r.LastBody = body
	return nil
}

// Native tries an OS dialog (zenity/kdialog/osascript) when present, then
// always writes POLICY visibility to a file the operator/console can audit.
type Native struct {
	PolicyFile string
}

func (n Native) ShowPolicy(title, body string) error {
	if n.PolicyFile != "" {
		if err := os.WriteFile(n.PolicyFile, []byte(title+"\n\n"+body), 0o644); err != nil {
			return err
		}
	}
	switch runtime.GOOS {
	case "linux":
		if os.Getenv("DISPLAY") != "" || os.Getenv("WAYLAND_DISPLAY") != "" {
			if p, err := exec.LookPath("zenity"); err == nil {
				_ = exec.Command(p, "--info", "--title", title, "--text", body).Run()
			}
		}
	case "darwin":
		if p, err := exec.LookPath("osascript"); err == nil {
			script := fmt.Sprintf(`display dialog %q with title %q buttons {"OK"} default button 1`, body, title)
			_ = exec.Command(p, "-e", script).Run()
		}
	}
	return nil
}

func EnrollmentPolicy(m enroll.Manifest) (title, body string) {
	return "RMM enrollment policy", enroll.PolicyText(m)
}
