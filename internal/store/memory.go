package store

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"sync"
)

// Memory is an in-process store for tests. It is not a production backend.
type Memory struct {
	mu   sync.RWMutex
	data map[string][]byte
}

func NewMemory() *Memory {
	return &Memory{data: map[string][]byte{}}
}

func (m *Memory) Get(key []byte) ([]byte, bool, error) {
	if err := AssertAllowedKey(key); err != nil {
		return nil, false, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	v, ok := m.data[string(key)]
	if !ok {
		return nil, false, nil
	}
	out := append([]byte(nil), v...)
	return out, true, nil
}

func (m *Memory) Put(key, value []byte) error {
	if err := AssertAllowedKey(key); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data[string(key)] = append([]byte(nil), value...)
	return nil
}

func (m *Memory) Delete(key []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.data, string(key))
	return nil
}

func (m *Memory) PrefixScan(prefix []byte, fn func(key, value []byte) error) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for k, v := range m.data {
		if prefix != nil && !bytes.HasPrefix([]byte(k), prefix) {
			continue
		}
		if err := fn([]byte(k), append([]byte(nil), v...)); err != nil {
			return err
		}
	}
	return nil
}

func (m *Memory) Export(w io.Writer) error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return json.NewEncoder(w).Encode(m.data)
}

func (m *Memory) Import(r io.Reader) error {
	var data map[string][]byte
	if err := json.NewDecoder(r).Decode(&data); err != nil {
		return err
	}
	for k := range data {
		if err := AssertAllowedKey([]byte(k)); err != nil {
			return err
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.data = data
	return nil
}

func (m *Memory) Close() error    { return nil }
func (m *Memory) Backend() string { return "memory" }
func (m *Memory) Path() string    { return ":memory:" }

func PutJSON(s Store, key []byte, v any) error {
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return s.Put(key, raw)
}

func GetJSON(s Store, key []byte, dest any) (bool, error) {
	raw, ok, err := s.Get(key)
	if err != nil || !ok {
		return ok, err
	}
	if err := json.Unmarshal(raw, dest); err != nil {
		return true, fmt.Errorf("decode %s: %w", key, err)
	}
	return true, nil
}
