//go:build !windows

package store

import "os"

func restrictKeyFile(path string) error {
	return os.Chmod(path, 0o600)
}
