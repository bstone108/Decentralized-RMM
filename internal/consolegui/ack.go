package consolegui

func signalPaint(ch chan struct{}) {
	if ch == nil {
		return
	}
	select {
	case ch <- struct{}{}:
	default:
	}
}

func waitPaint(done <-chan struct{}, ch <-chan struct{}) bool {
	if ch == nil {
		return false
	}
	select {
	case <-done:
		return false
	case <-ch:
		return true
	}
}

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
