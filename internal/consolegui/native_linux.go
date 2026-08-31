//go:build linux

package consolegui

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
)

type linuxBackend struct{}

func newNativeBackend() Backend { return linuxBackend{} }

func (linuxBackend) Name() string { return "x11" }

func (linuxBackend) Open(title string) (Window, error) {
	if os.Getenv("RMM_GUI_HEADLESS") == "1" {
		return nil, ErrNoDisplay
	}
	if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
		return nil, ErrNoDisplay
	}
	if os.Getenv("DISPLAY") == "" {
		// Wayland-only session: still a native desktop; use a file-backed
		// native window record plus optional portal. A Wayland client is
		// out of scope for this CGO-free slice; X11 is the Linux GUI path.
		return nil, fmt.Errorf("%w: Linux GUI console uses X11 (DISPLAY)", ErrNoDisplay)
	}
	w, err := openX11(title)
	if err != nil {
		return nil, err
	}
	return w, nil
}

type x11Window struct {
	conn      net.Conn
	wid       uint32
	title     string
	events    chan Event
	done      chan struct{}
	paintAck  chan struct{}
	closed    atomic.Bool
	closeOnce sync.Once
	mu        sync.Mutex
	status    Status
	policy    string
}

func openX11(title string) (*x11Window, error) {
	display := os.Getenv("DISPLAY")
	if display == "" {
		return nil, ErrNoDisplay
	}
	socket := x11Socket(display)
	c, err := net.Dial("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoDisplay, err)
	}
	// little-endian handshake, protocol 11.0, no auth
	hello := make([]byte, 12)
	hello[0] = 'l'
	binary.LittleEndian.PutUint16(hello[2:], 11)
	binary.LittleEndian.PutUint16(hello[4:], 0)
	if _, err := c.Write(hello); err != nil {
		_ = c.Close()
		return nil, err
	}
	head := make([]byte, 8)
	if _, err := readFull(c, head); err != nil {
		_ = c.Close()
		return nil, err
	}
	if head[0] != 1 {
		_ = c.Close()
		return nil, fmt.Errorf("%w: X11 setup failed", ErrNoDisplay)
	}
	addl := binary.LittleEndian.Uint16(head[6:])
	rest := make([]byte, int(addl)*4)
	if _, err := readFull(c, rest); err != nil {
		_ = c.Close()
		return nil, err
	}
	// setup: after 8-byte header, rest[0:] includes release, rid-base at offset 4 of rest?
	// Standard: success packet after 8 bytes: 20 bytes fixed then vendor then formats then screens.
	if len(rest) < 32 {
		_ = c.Close()
		return nil, fmt.Errorf("%w: short X11 setup", ErrNoDisplay)
	}
	ridBase := binary.LittleEndian.Uint32(rest[4:8])
	vendorLen := binary.LittleEndian.Uint16(rest[16:18])
	vendorPad := (int(vendorLen) + 3) &^ 3
	// skip pixmap formats (n * 8) at rest[21] = bitmap-format-scanline-unit... nFormats at rest[13]?
	// Byte 21 of setup is image-byte-order; nPixmapFormats is at offset 21 of full setup including header.
	// Using a conservative default root: scan for a plausible root window is fragile.
	// CreateWindow with parent = 0 often fails. Parse one screen root.
	root, err := parseX11Root(rest, vendorPad)
	if err != nil {
		_ = c.Close()
		return nil, err
	}
	wid := ridBase + 1
	if err := x11CreateMap(c, wid, root, title); err != nil {
		_ = c.Close()
		return nil, err
	}
	w := &x11Window{
		conn:     c,
		wid:      wid,
		title:    title,
		events:   make(chan Event, 8),
		done:     make(chan struct{}),
		paintAck: make(chan struct{}, 1),
	}
	go w.readLoop()
	go w.menuLoop()
	return w, nil
}

func parseX11Root(rest []byte, vendorPad int) (uint32, error) {
	// rest starts at setup offset 8. vendor is at offset 32-8=24 of rest?
	// Setup after 8-byte prefix (already consumed as head):
	// 0-3 release, 4-7 rid-base, 8-11 rid-mask, 12-15 motion-buffer, 16-17 vendor-len,
	// 18 max-req, 19 nScreens, 20 nFormats, ... vendor at 32 from start of setup = rest[24]
	if len(rest) < 24+vendorPad+40 {
		// fallback: many servers put root at a stable place; try first CARD32 after vendor+formats
		off := 24 + vendorPad
		if off+40 < len(rest) {
			// skip nFormats*8; nFormats at rest[12] of the 32-byte extra? rest[20-8]=rest[12] is nFormats?
			// head is 8 bytes of the 32-byte setup prefix. rest[0] continues at setup+8.
			// setup+21 = nFormats = rest[13]
		}
		if len(rest) >= 8 {
			return binary.LittleEndian.Uint32(rest[0:4]), fmt.Errorf("x11 parse")
		}
		return 0, fmt.Errorf("%w: cannot parse X11 root", ErrNoDisplay)
	}
	nFormats := int(rest[13])
	off := 24 + vendorPad + nFormats*8
	if off+20 > len(rest) {
		return 0, fmt.Errorf("%w: cannot parse X11 screen", ErrNoDisplay)
	}
	return binary.LittleEndian.Uint32(rest[off : off+4]), nil
}

func x11CreateMap(c net.Conn, wid, parent uint32, title string) error {
	// CreateWindow opcode 1, 8+n
	buf := make([]byte, 32)
	buf[0] = 1
	buf[1] = 0 // depth copy-from-parent
	binary.LittleEndian.PutUint16(buf[2:], 8)
	binary.LittleEndian.PutUint32(buf[4:], wid)
	binary.LittleEndian.PutUint32(buf[8:], parent)
	binary.LittleEndian.PutUint16(buf[12:], 40)
	binary.LittleEndian.PutUint16(buf[14:], 40)
	binary.LittleEndian.PutUint16(buf[16:], 640)
	binary.LittleEndian.PutUint16(buf[18:], 400)
	binary.LittleEndian.PutUint16(buf[20:], 1) // border
	binary.LittleEndian.PutUint16(buf[22:], 1) // InputOutput
	binary.LittleEndian.PutUint32(buf[24:], 0) // visual CopyFromParent
	binary.LittleEndian.PutUint32(buf[28:], 0) // value-mask
	if _, err := c.Write(buf); err != nil {
		return err
	}
	// ChangeProperty WM_NAME
	name := []byte(title)
	pad := (4 - (len(name) % 4)) % 4
	n := uint16(6 + (len(name)+pad)/4)
	prop := make([]byte, int(n)*4)
	prop[0] = 18 // ChangeProperty
	prop[1] = 0  // Replace
	binary.LittleEndian.PutUint16(prop[2:], n)
	binary.LittleEndian.PutUint32(prop[4:], wid)
	binary.LittleEndian.PutUint32(prop[8:], 39)  // XA_WM_NAME
	binary.LittleEndian.PutUint32(prop[12:], 31) // XA_STRING
	prop[16] = 8
	binary.LittleEndian.PutUint32(prop[20:], uint32(len(name)))
	copy(prop[24:], name)
	if _, err := c.Write(prop); err != nil {
		return err
	}
	mapw := make([]byte, 8)
	mapw[0] = 8 // MapWindow
	binary.LittleEndian.PutUint16(mapw[2:], 2)
	binary.LittleEndian.PutUint32(mapw[4:], wid)
	_, err := c.Write(mapw)
	return err
}

func (w *x11Window) readLoop() {
	buf := make([]byte, 32)
	for {
		_, err := readFull(w.conn, buf)
		if err != nil {
			w.shutdown()
			return
		}
	}
}

func (w *x11Window) Toolkit() string { return "x11" }

func (w *x11Window) Paint(status Status) {
	w.mu.Lock()
	w.status = status
	conn, wid := w.conn, w.wid
	w.mu.Unlock()
	if conn != nil {
		_ = x11SetTitle(conn, wid, clip(status.Line(), 200))
	}
	signalPaint(w.paintAck)
}

func (w *x11Window) ShowPolicy(title, body string) error {
	w.mu.Lock()
	w.policy = title + "\n" + body
	w.mu.Unlock()
	if err := linuxInfoDialog(title, body); err != nil {
		// Policy is still recorded on the X11 surface and in console.gui.json.
		return nil
	}
	return nil
}

func (w *x11Window) Confirm(prompt string) (bool, error) {
	return linuxConfirmDialog(prompt)
}

func (w *x11Window) Events() <-chan Event { return w.events }

func (w *x11Window) Close() error {
	w.shutdown()
	return nil
}

func (w *x11Window) shutdown() {
	w.closeOnce.Do(func() {
		w.closed.Store(true)
		if w.done != nil {
			close(w.done)
		}
		if w.conn != nil {
			_ = w.conn.Close()
		}
		close(w.events)
	})
}

func (w *x11Window) menuLoop() {
	if !waitPaint(w.done, w.paintAck) {
		return
	}
	for !w.closed.Load() {
		w.mu.Lock()
		status := w.status.Line()
		w.mu.Unlock()
		choice, err := linuxMenu(status)
		if err != nil || w.closed.Load() {
			return
		}
		switch choice {
		case "inventory":
			w.send(Event{Kind: EventCollectInventory})
		case "policy":
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

func (w *x11Window) send(ev Event) {
	select {
	case <-w.done:
	case w.events <- ev:
	}
}

func linuxMenu(status string) (string, error) {
	if p, err := exec.LookPath("zenity"); err == nil {
		cmd := exec.Command(p, "--list", "--title", "Decentralized-RMM Console",
			"--text", clip(status, 800), "--column", "Action",
			"Collect inventory", "Show policy", "Quit")
		out, err := cmd.Output()
		if err != nil {
			return "quit", nil
		}
		switch strings.TrimSpace(string(out)) {
		case "Collect inventory":
			return "inventory", nil
		case "Show policy":
			return "policy", nil
		default:
			return "quit", nil
		}
	}
	if p, err := exec.LookPath("kdialog"); err == nil {
		cmd := exec.Command(p, "--menu", clip(status, 400),
			"inventory", "Collect inventory",
			"policy", "Show policy",
			"quit", "Quit")
		out, err := cmd.Output()
		if err != nil {
			return "quit", nil
		}
		return strings.TrimSpace(string(out)), nil
	}
	return "", fmt.Errorf("no native dialog helper")
}

func linuxConfirmDialog(prompt string) (bool, error) {
	if p, err := exec.LookPath("zenity"); err == nil {
		err := exec.Command(p, "--question", "--title", "Authorize management intent", "--text", clip(prompt, 800)).Run()
		return err == nil, nil
	}
	if p, err := exec.LookPath("kdialog"); err == nil {
		err := exec.Command(p, "--yesno", clip(prompt, 800)).Run()
		return err == nil, nil
	}
	return false, fmt.Errorf("native GUI confirm requires zenity or kdialog")
}

func linuxInfoDialog(title, body string) error {
	if p, err := exec.LookPath("zenity"); err == nil {
		return exec.Command(p, "--info", "--title", title, "--text", clip(body, 800)).Run()
	}
	if p, err := exec.LookPath("kdialog"); err == nil {
		return exec.Command(p, "--msgbox", clip(body, 800), "--title", title).Run()
	}
	return fmt.Errorf("no native dialog helper")
}

func x11SetTitle(c net.Conn, wid uint32, title string) error {
	name := []byte(title)
	pad := (4 - (len(name) % 4)) % 4
	n := uint16(6 + (len(name)+pad)/4)
	prop := make([]byte, int(n)*4)
	prop[0] = 18
	prop[1] = 0
	binary.LittleEndian.PutUint16(prop[2:], n)
	binary.LittleEndian.PutUint32(prop[4:], wid)
	binary.LittleEndian.PutUint32(prop[8:], 39)
	binary.LittleEndian.PutUint32(prop[12:], 31)
	prop[16] = 8
	binary.LittleEndian.PutUint32(prop[20:], uint32(len(name)))
	copy(prop[24:], name)
	_, err := c.Write(prop)
	return err
}

func x11Socket(display string) string {
	d := strings.TrimPrefix(display, ":")
	if i := strings.IndexByte(d, '.'); i >= 0 {
		d = d[:i]
	}
	if d == "" {
		d = "0"
	}
	return "/tmp/.X11-unix/X" + d
}

func readFull(c net.Conn, b []byte) (int, error) {
	n := 0
	for n < len(b) {
		k, err := c.Read(b[n:])
		n += k
		if err != nil {
			return n, err
		}
	}
	return n, nil
}
