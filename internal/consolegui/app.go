package consolegui

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/bstone108/Decentralized-RMM/internal/intent"
)

var (
	ErrNoDisplay = errors.New("no native desktop display for the GUI console")
	errQuit      = errors.New("quit")
)

type EventKind string

const (
	EventQuit             EventKind = "quit"
	EventShowPolicy       EventKind = "show_policy"
	EventCollectInventory EventKind = "collect_inventory"
	EventConfirmIntent    EventKind = "confirm_intent"
	EventPaint            EventKind = "paint"
)

type Event struct {
	Kind     EventKind
	Proposal *Proposal
}

// Window is a native (not TUI, not web) operator surface.
type Window interface {
	Toolkit() string
	Paint(status Status)
	ShowPolicy(title, body string) error
	Confirm(prompt string) (bool, error)
	Events() <-chan Event
	Close() error
}

// Backend opens a native GUI window for the current OS.
type Backend interface {
	Name() string
	Open(title string) (Window, error)
}

// App is the separately deployable GUI console. It is not an agent.
type App struct {
	Session  *Session
	Backend  Backend
	StateDir string
	window   Window
}

func NewApp(session *Session, backend Backend) *App {
	return &App{Session: session, Backend: backend}
}

func (a *App) Run(ctx context.Context) error {
	if a.Backend == nil {
		a.Backend = Native()
	}
	w, err := a.Backend.Open("Decentralized-RMM Console")
	if err != nil {
		return err
	}
	a.window = w
	defer w.Close()
	a.paint()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case ev, ok := <-w.Events():
			if !ok {
				return nil
			}
			err := a.handle(ctx, ev)
			if errors.Is(err, errQuit) {
				return nil
			}
			if err != nil && a.Session != nil {
				a.Session.status.LastAuthorization = err.Error()
			}
			a.paint()
		}
	}
}

func (a *App) handle(ctx context.Context, ev Event) error {
	switch ev.Kind {
	case EventQuit:
		return errQuit
	case EventPaint:
		a.paint()
		return nil
	case EventShowPolicy:
		body := a.Session.Policy
		if body == "" {
			body = "No enrollment policy loaded. Pairing and trust still apply."
		}
		return a.window.ShowPolicy("RMM enrollment policy", body)
	case EventCollectInventory:
		p := Proposal{
			Kind:         intent.KindInventoryCollect,
			TargetNodeID: a.Session.DefaultTarget(),
		}
		if ev.Proposal != nil {
			p = *ev.Proposal
			p.Kind = intent.KindInventoryCollect
		}
		return a.authorizeAndSubmit(ctx, &p)
	case EventConfirmIntent:
		if ev.Proposal == nil {
			return fmt.Errorf("no intent proposal")
		}
		err := a.authorizeAndSubmit(ctx, ev.Proposal)
		ev.Proposal.ZeroElevation()
		return err
	default:
		return fmt.Errorf("unknown GUI event %s", ev.Kind)
	}
}

func (a *App) authorizeAndSubmit(ctx context.Context, p *Proposal) error {
	ok, err := a.window.Confirm(intentPrompt(*p))
	if err != nil {
		return err
	}
	if !ok {
		return fmt.Errorf("operator declined management intent")
	}
	p.OperatorConfirm = true
	_, err = a.Session.Submit(ctx, *p)
	p.ZeroElevation()
	return err
}

func (a *App) paint() {
	if a.window == nil || a.Session == nil {
		return
	}
	st := a.Session.Status()
	a.window.Paint(st)
	if a.StateDir != "" {
		_ = os.MkdirAll(a.StateDir, 0o700)
		raw, _ := json.MarshalIndent(st, "", "  ")
		_ = os.WriteFile(filepath.Join(a.StateDir, "console.gui.json"), raw, 0o600)
	}
}
