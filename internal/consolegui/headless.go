package consolegui

type headlessWindow struct {
	toolkit    string
	status     Status
	policy     string
	lastPrompt string
	deny       bool
	events     chan Event
	closed     bool
}

type Headless struct {
	Window *headlessWindow
}

func NewHeadless() *Headless {
	return &Headless{Window: &headlessWindow{
		toolkit: "headless-native-contract",
		events:  make(chan Event, 16),
	}}
}

func (h *Headless) Name() string { return "headless" }

func (h *Headless) Open(title string) (Window, error) {
	_ = title
	if h.Window.events == nil {
		h.Window.events = make(chan Event, 16)
	}
	return h.Window, nil
}

func (h *Headless) Push(ev Event) {
	h.Window.events <- ev
}

func (h *Headless) CloseEvents() {
	close(h.Window.events)
}

func (w *headlessWindow) Toolkit() string { return w.toolkit }

func (w *headlessWindow) Paint(status Status) { w.status = status }

func (w *headlessWindow) ShowPolicy(title, body string) error {
	_ = title
	w.policy = body
	return nil
}

func (w *headlessWindow) Confirm(prompt string) (bool, error) {
	w.lastPrompt = prompt
	if w.deny {
		return false, nil
	}
	return true, nil
}

func (w *headlessWindow) Events() <-chan Event { return w.events }

func (w *headlessWindow) Close() error {
	if !w.closed {
		w.closed = true
	}
	return nil
}
