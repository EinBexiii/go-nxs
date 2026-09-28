//go:build !unix && !windows

package nxs

func lockDir(string) (func() error, error) { return func() error { return nil }, nil }

func syncDir(string) error { return nil }
