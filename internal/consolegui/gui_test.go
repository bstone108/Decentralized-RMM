package consolegui

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/bstone108/Decentralized-RMM/internal/consolemesh"
	"github.com/bstone108/Decentralized-RMM/internal/desktop"
	"github.com/bstone108/Decentralized-RMM/internal/intent"
	"github.com/bstone108/Decentralized-RMM/internal/localpeer"
	"github.com/bstone108/Decentralized-RMM/internal/node"
	"github.com/bstone108/Decentralized-RMM/internal/store"
	"github.com/bstone108/Decentralized-RMM/internal/trust"
)

func TestNativeToolkitName(t *testing.T) {
	got := Native().Name()
	switch runtime.GOOS {
	case "linux":
		if got != "x11" {
			t.Fatalf("linux native GUI toolkit %s", got)
		}
	case "windows":
		if got != "win32" {
			t.Fatalf("windows native GUI toolkit %s", got)
		}
	case "darwin":
		if got != "aqua" {
			t.Fatalf("darwin native GUI toolkit %s", got)
		}
	}
}

func TestNativeOpenRequiresDisplay(t *testing.T) {
	t.Run("headless env", func(t *testing.T) {
		t.Setenv("RMM_GUI_HEADLESS", "1")
		_, err := Native().Open("test")
		if !errors.Is(err, ErrNoDisplay) {
			t.Fatalf("got %v", err)
		}
	})
	t.Run("no display", func(t *testing.T) {
		if runtime.GOOS != "linux" {
			t.Skip("DISPLAY contract is the Linux X11 path")
		}
		t.Setenv("RMM_GUI_HEADLESS", "")
		t.Setenv("DISPLAY", "")
		t.Setenv("WAYLAND_DISPLAY", "")
		_, err := Native().Open("test")
		if !errors.Is(err, ErrNoDisplay) {
			t.Fatalf("got %v", err)
		}
	})
}

func TestNoTUIWebOrCGOToolkitImports(t *testing.T) {
	forbidden := []string{
		"github.com/charmbracelet/bubbletea",
		"github.com/charmbracelet/lipgloss",
		"github.com/gdamore/tcell",
		"fyne.io",
		"github.com/wailsapp/wails",
		"gioui.org",
		"net/http",
		"github.com/zserge/lorca",
		"github.com/webview/webview",
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		f, err := parser.ParseFile(fset, e.Name(), nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			for _, bad := range forbidden {
				if path == bad || strings.HasPrefix(path, bad+"/") {
					t.Errorf("%s imports %s (TUI/web/CGO GUI is not the product console)", e.Name(), path)
				}
			}
		}
	}
}

func TestLocalAgentPreferredStatus(t *testing.T) {
	console, agent, rt := pairedLocalAgent(t)
	defer agent.Close()
	sess := NewSession(rt, "identity-signed enrollment policy")
	st := sess.Status()
	if !st.PrefersLocalAgent || !st.Authenticated {
		t.Fatalf("status %+v", st)
	}
	if st.HasAgentFunction {
		t.Fatal("console must not expose an agent function")
	}
	if st.LocalAgentNodeID != agent.ID.Public.NodeID {
		t.Fatalf("local agent %s", st.LocalAgentNodeID)
	}
	if st.ConsoleNodeID != console.ID.Public.NodeID {
		t.Fatalf("console %s", st.ConsoleNodeID)
	}
	if console.HasListener() {
		t.Fatal("console must not listen when preferring the local agent")
	}
	if !strings.Contains(st.Line(), "prefers local agent: true") {
		t.Fatalf("%s", st.Line())
	}
}

func TestAuthorizeRefusesUnsafeIntents(t *testing.T) {
	console, agent, rt := pairedLocalAgent(t)
	defer agent.Close()
	sess := NewSession(rt, "")
	if a := sess.Authorize(Proposal{Kind: intent.KindCommandRun, TargetNodeID: agent.ID.Public.NodeID, OperatorConfirm: true}); a.Allowed {
		t.Fatal("command.run must fail closed")
	}
	if a := sess.Authorize(Proposal{Kind: intent.KindInventoryCollect, TargetNodeID: console.ID.Public.NodeID, OperatorConfirm: true}); a.Allowed {
		t.Fatal("self-target must fail")
	}
	if a := sess.Authorize(Proposal{Kind: intent.KindInventoryCollect, TargetNodeID: "rmm1:not-paired", OperatorConfirm: true}); a.Allowed {
		t.Fatal("untrusted target must fail")
	}
	if a := sess.Authorize(Proposal{Kind: intent.KindInventoryCollect, TargetNodeID: agent.ID.Public.NodeID}); a.Allowed {
		t.Fatal("missing operator confirm must fail")
	}
	payload, _ := json.Marshal(map[string]string{"mode": string(desktop.ModeUnattended)})
	if a := sess.Authorize(Proposal{
		Kind: intent.KindDesktopModeChange, TargetNodeID: agent.ID.Public.NodeID,
		Payload: payload, OperatorConfirm: true,
	}); a.Allowed {
		t.Fatal("unattended desktop without elevation must fail")
	}
	ok := sess.Authorize(Proposal{Kind: intent.KindInventoryCollect, TargetNodeID: agent.ID.Public.NodeID, OperatorConfirm: true})
	if !ok.Allowed {
		t.Fatalf("%+v", ok)
	}
}

func TestHeadlessGUIInventoryOverLocalAgentMesh(t *testing.T) {
	console, agent, rt := pairedLocalAgent(t)
	defer agent.Close()
	state := t.TempDir()
	sess := NewSession(rt, "identity-signed enrollment policy")
	h := NewHeadless()
	app := NewApp(sess, h)
	app.StateDir = state
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- app.Run(ctx) }()

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if h.Window.status.Authenticated && h.Window.status.PrefersLocalAgent {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !h.Window.status.Authenticated || !h.Window.status.PrefersLocalAgent {
		t.Fatalf("GUI status not painted: %+v", h.Window.status)
	}
	if h.Window.Toolkit() == "" || strings.Contains(strings.ToLower(h.Window.Toolkit()), "tui") {
		t.Fatalf("toolkit %s", h.Window.Toolkit())
	}

	h.Push(Event{Kind: EventShowPolicy})
	h.Push(Event{Kind: EventCollectInventory})

	deadline = time.Now().Add(10 * time.Second)
	var receipt string
	for time.Now().Before(deadline) {
		st := sess.Status()
		if st.LastReceipt != "" {
			receipt = st.LastReceipt
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if receipt == "" {
		t.Fatalf("expected inventory receipt, last auth=%s", sess.Status().LastAuthorization)
	}

	raw, err := os.ReadFile(filepath.Join(state, "console.gui.json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(bytes.ToLower(raw), []byte("password")) {
		t.Fatal("console.gui.json must not contain passwords")
	}
	var dumped Status
	if err := json.Unmarshal(raw, &dumped); err != nil {
		t.Fatal(err)
	}
	if !dumped.PrefersLocalAgent || !dumped.Authenticated || dumped.HasAgentFunction {
		t.Fatalf("gui json %+v", dumped)
	}
	if !strings.Contains(h.Window.policy, "identity-signed") {
		t.Fatalf("policy %s", h.Window.policy)
	}
	if !strings.Contains(h.Window.lastPrompt, "inventory.collect") {
		t.Fatalf("confirm prompt %s", h.Window.lastPrompt)
	}

	if _, _, err := console.HandleIntent(intent.New("gui-self", "gui-self", agent.ID.Public.NodeID, console.ID.Public.NodeID, intent.KindInventoryCollect, nil)); err == nil {
		t.Fatal("console HandleIntent must fail closed")
	}

	h.Push(Event{Kind: EventQuit})
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(3 * time.Second):
		cancel()
		t.Fatal("GUI event loop did not exit")
	}
}

func TestOperatorDeclineStopsIntent(t *testing.T) {
	_, agent, rt := pairedLocalAgent(t)
	defer agent.Close()
	sess := NewSession(rt, "")
	h := NewHeadless()
	h.Window.deny = true
	app := NewApp(sess, h)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- app.Run(ctx) }()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !h.Window.status.Authenticated {
		time.Sleep(10 * time.Millisecond)
	}
	h.Push(Event{Kind: EventCollectInventory})
	deadline = time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(sess.Status().LastAuthorization, "declined") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(sess.Status().LastAuthorization, "declined") {
		t.Fatalf("got %q", sess.Status().LastAuthorization)
	}
	h.Push(Event{Kind: EventQuit})
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		cancel()
	}
}

func TestBuiltinMeshStatusAuthenticated(t *testing.T) {
	st := store.NewMemory()
	c, err := node.Open(st, node.RoleConsole, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	rt, err := consolemesh.Start(c, t.TempDir(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	sess := NewSession(rt, "")
	got := sess.Status()
	if got.PrefersLocalAgent || !got.Authenticated || got.BuiltinMeshAddr == "" {
		t.Fatalf("%+v", got)
	}
	if got.HasAgentFunction {
		t.Fatal("agent function")
	}
}

func pairedLocalAgent(t *testing.T) (*node.Node, *node.Node, *consolemesh.Runtime) {
	t.Helper()
	dir := t.TempDir()
	agent, err := node.Open(store.NewMemory(), node.RoleAgent, nil)
	if err != nil {
		t.Fatal(err)
	}
	console, err := node.Open(store.NewMemory(), node.RoleConsole, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.Pair(trust.Offer(console.ID, "console")); err != nil {
		t.Fatal(err)
	}
	if err := console.Pair(trust.Offer(agent.ID, "agent")); err != nil {
		t.Fatal(err)
	}
	agent.SetPresenceDir(dir)
	if _, err := agent.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := localpeer.Read(dir); err != nil || !ok {
		t.Fatalf("advertise %v %v", ok, err)
	}
	rt, err := consolemesh.Start(console, dir, "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	if !rt.PrefersLocalAgent() {
		t.Fatalf("%+v", rt)
	}
	return console, agent, rt
}
