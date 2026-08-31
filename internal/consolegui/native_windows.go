//go:build windows

package consolegui

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

// win32Backend is the CGO-free Windows native GUI adapter (user32 MessageBoxW).
// It is not a TUI and not a browser. Cross-compilation from Linux stays CGO_ENABLED=0.
type win32Backend struct{}

func newNativeBackend() Backend { return win32Backend{} }

func (win32Backend) Name() string { return "win32" }

func (win32Backend) Open(title string) (Window, error) {
	if os.Getenv("RMM_GUI_HEADLESS") == "1" {
		return nil, ErrNoDisplay
	}
	user32 := windows.NewLazySystemDLL("user32.dll")
	proc := user32.NewProc("MessageBoxW")
	if err := proc.Find(); err != nil {
		return nil, ErrNoDisplay
	}
	w := &win32Window{
		title:      title,
		messageBox: proc,
		events:     make(chan Event, 16),
		done:       make(chan struct{}),
		paintAck:   make(chan struct{}, 1),
	}
	go w.menuLoop()
	return w, nil
}

type win32Window struct {
	title      string
	messageBox *windows.LazyProc
	events     chan Event
	done       chan struct{}
	paintAck   chan struct{}
	closed     atomic.Bool
	mu         sync.Mutex
	status     Status
}

func (w *win32Window) Toolkit() string { return "win32" }

func (w *win32Window) Paint(status Status) {
	w.mu.Lock()
	w.status = status
	w.mu.Unlock()
	signalPaint(w.paintAck)
}

func (w *win32Window) ShowPolicy(title, body string) error {
	_, err := w.box(title, body, 0x00000040) // MB_ICONINFORMATION
	return err
}

func (w *win32Window) Confirm(prompt string) (bool, error) {
	r, err := w.box("Authorize management intent", prompt, 0x00000004|0x00000020) // MB_YESNO|MB_ICONQUESTION
	if err != nil {
		return false, err
	}
	return r == 6, nil // IDYES
}

func (w *win32Window) Events() <-chan Event { return w.events }

func (w *win32Window) Close() error {
	if w.closed.Swap(true) {
		return nil
	}
	close(w.done)
	return nil
}

func (w *win32Window) menuLoop() {
	if !waitPaint(w.done, w.paintAck) {
		return
	}
	for !w.closed.Load() {
		w.mu.Lock()
		body := w.status.Line() + "\n\nYes = collect inventory\nNo = show policy\nCancel = quit"
		w.mu.Unlock()
		r, err := w.box(w.title, body, 0x00000003) // MB_YESNOCANCEL
		if err != nil || w.closed.Load() {
			w.send(Event{Kind: EventQuit})
			return
		}
		switch r {
		case 6: // IDYES
			w.send(Event{Kind: EventCollectInventory})
		case 7: // IDNO
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

func (w *win32Window) send(ev Event) {
	select {
	case <-w.done:
	case w.events <- ev:
	}
}

func (w *win32Window) box(title, body string, flags uintptr) (uintptr, error) {
	if w.messageBox == nil {
		return 0, ErrNoDisplay
	}
	if len(body) > 1500 {
		body = body[:1500] + "…"
	}
	bp, err := windows.UTF16PtrFromString(body)
	if err != nil {
		return 0, err
	}
	tp, err := windows.UTF16PtrFromString(title)
	if err != nil {
		return 0, err
	}
	r, _, callErr := w.messageBox.Call(
		0,
		uintptr(unsafe.Pointer(bp)),
		uintptr(unsafe.Pointer(tp)),
		flags,
	)
	if r == 0 {
		if callErr != nil && callErr != windows.ERROR_SUCCESS {
			return 0, fmt.Errorf("MessageBoxW: %w", callErr)
		}
		return 0, ErrNoDisplay
	}
	return r, nil
}
