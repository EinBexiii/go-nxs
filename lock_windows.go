//go:build windows

package nxs

import (
	"os"
	"path/filepath"

	"golang.org/x/sys/windows"
)

func lockDir(dir string) (func() error, error) {
	f, err := os.OpenFile(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	ol := new(windows.Overlapped)
	if err := windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, ol); err != nil {
		_ = f.Close()
		return nil, err
	}
	return f.Close, nil
}

// syncDir is a no-op, as Windows does not support syncing directories.
func syncDir(string) error { return nil }
