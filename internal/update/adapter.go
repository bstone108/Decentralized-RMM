package update

import "runtime"

// RestartPlan is an OS-native apply/restart recipe. Commands are not executed
// by the library; the caller (service manager or operator) applies them after
// independent verification and staging.
type RestartPlan struct {
	Component Component
	OS        string
	Commands  [][]string
	Relisten  bool
	Reason    string
}

type Adapter interface {
	Name() string
	Restart(component Component) RestartPlan
}

func NativeAdapter() Adapter {
	switch runtime.GOOS {
	case "windows":
		return windowsAdapter{}
	case "darwin":
		return darwinAdapter{}
	default:
		return linuxAdapter{}
	}
}

type linuxAdapter struct{}

func (linuxAdapter) Name() string { return "systemd" }

func (linuxAdapter) Restart(component Component) RestartPlan {
	unit := "rmm-agent"
	if component == ComponentConsole {
		unit = "rmm-console"
	}
	return RestartPlan{
		Component: component,
		OS:        "linux",
		Commands:  [][]string{{"systemctl", "restart", unit + ".service"}},
		Relisten:  true,
		Reason:    "systemd restart then authenticated mesh reconnect",
	}
}

type darwinAdapter struct{}

func (darwinAdapter) Name() string { return "launchd" }

func (darwinAdapter) Restart(component Component) RestartPlan {
	label := "io.rmm.agent"
	if component == ComponentConsole {
		label = "io.rmm.console"
	}
	return RestartPlan{
		Component: component,
		OS:        "darwin",
		Commands: [][]string{
			{"launchctl", "kickstart", "-k", "system/" + label},
		},
		Relisten: true,
		Reason:   "launchd kickstart then authenticated mesh reconnect",
	}
}

type windowsAdapter struct{}

func (windowsAdapter) Name() string { return "scm" }

func (windowsAdapter) Restart(component Component) RestartPlan {
	svc := "RMMAgent"
	if component == ComponentConsole {
		svc = "RMMConsole"
	}
	return RestartPlan{
		Component: component,
		OS:        "windows",
		Commands: [][]string{
			{"sc.exe", "stop", svc},
			{"sc.exe", "start", svc},
		},
		Relisten: true,
		Reason:   "Service Control Manager restart then authenticated mesh reconnect",
	}
}
