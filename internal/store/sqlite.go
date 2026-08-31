package store

import "fmt"

// OpenSQLite exists so the fallback remains a typed seam. It is not selected
// unless a future spike documents material Badger incompatibility.
func OpenSQLite(path string) (Store, error) {
	return nil, fmt.Errorf("sqlite fallback is not selected; BadgerDB remains the baseline (path=%s)", path)
}
