//go:build darwin

package consolegui

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
)

// aquaBackend is the CGO-free macOS native GUI adapter. It talks to Aqua
// through osascript, not a TUI and not a web view. Cross-compilation from
// Linux stays CGO_ENABLED=0.
type aquaBackend struct{}

func newNativeBackend() Backend { return aquaBackend{} }

func (aquaBackend) Name() string { return "aqua" }

func (aquaBackend) Open(title string) (Window, error) {
	if os.Getenv("RMM_GUI_HEADLESS") == "1" {
		return nil, ErrNoDisplay
	}
	if _, err := exec.LookPath("osascript"); err != nil {
		return nil, ErrNoDisplay
	}
	cmd := exec.Command("osascript", "-e", `tell application "System Events" to get name`)
	if err := cmd.Run(); err != nil {
		return nil, ErrNoDisplay
	}
	w := &aquaWindow{
		title:    title,
		events:   make(chan Event, 16),
		done:     make(chan struct{}),
		paintAck: make(chan struct{}, 1),
	}
	go w.menuLoop()
	return w, nil
}

type aquaWindow struct {
	title    string
	events   chan Event
	done     chan struct{}
	paintAck chan struct{}
	closed   atomic.Bool
	mu       sync.Mutex
	status   Status
}

func (w *aquaWindow) Toolkit() string { return "aqua" }

func (w *aquaWindow) Paint(status Status) {
	w.mu.Lock()
	w.status = status
	w.mu.Unlock()
	signalPaint(w.paintAck)
}

func (w *aquaWindow) ShowPolicy(title, body string) error {
	script := fmt.Sprintf(
		`display dialog %s with title %s buttons {"OK"} default button "OK"`,
		osaQuote(clip(body, 800)), osaQuote(title),
	)
	return exec.Command("osascript", "-e", script).Run()
}

func (w *aquaWindow) Confirm(prompt string) (bool, error) {
	script := fmt.Sprintf(
		`display dialog %s with title %s buttons {"Cancel", "Authorize"} default button "Cancel"`,
		osaQuote(clip(prompt, 800)), osaQuote("Authorize management intent"),
	)
	out, err := exec.Command("osascript", "-e", script).CombinedOutput()
	if err != nil {
		return false, nil
	}
	return strings.Contains(string(out), "Authorize"), nil
}

func (w *aquaWindow) Events() <-chan Event { return w.events }

func (w *aquaWindow) Close() error {
	if w.closed.Swap(true) {
		return nil
	}
	close(w.done)
	return nil
}

func (w *aquaWindow) menuLoop() {
	if !waitPaint(w.done, w.paintAck) {
		return
	}
	for !w.closed.Load() {
		w.mu.Lock()
		body := w.status.Line()
		w.mu.Unlock()
		script := fmt.Sprintf(
			`display dialog %s with title %s buttons {"Quit", "Show policy", "Collect inventory"} default button "Collect inventory"`,
			osaQuote(clip(body, 800)), osaQuote(w.title),
		)
		out, err := exec.Command("osascript", "-e", script).CombinedOutput()
		if err != nil || w.closed.Load() {
			w.send(Event{Kind: EventQuit})
			return
		}
		s := string(out)
		switch {
		case strings.Contains(s, "Collect inventory"):
			w.send(Event{Kind: EventCollectInventory})
		case strings.Contains(s, "Show policy"):
			w.send(Event{Kind: EventShowPolicy})
		default:
			w.send(Event{Kind: EventQuit})
			return
		}
		if !waitPaint(w.done, w.paintAck) {
			return
		}
	}
}

func (w *aquaWindow) send(ev Event) {
	select {
	case <-w.done:
	case w.events <- ev:
	}
}

func osaQuote(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return `"` + s + `"`
}
