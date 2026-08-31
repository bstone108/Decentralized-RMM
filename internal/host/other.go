//go:build !linux && !windows && !darwin

package host

func enrich(s *Snapshot) {}
