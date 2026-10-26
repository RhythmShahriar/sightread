// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

//go:build windows

package watch

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// TestLockWindows: the lock file is opened with no sharing, so a second
// lockFile (as a second watch process would call it) gets ErrLocked
// while the first handle is open. Once that is closed it succeeds.
func TestLockWindows(t *testing.T) {
	path := filepath.Join(t.TempDir(), LockName)
	f, err := lockFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := lockFile(path); !errors.Is(err, ErrLocked) {
		t.Fatalf("second lockFile: %v, want ErrLocked", err)
	}
	// A plain open, as another program would do it, is refused too.
	if g, err := os.OpenFile(path, os.O_RDWR, 0); err == nil {
		_ = g.Close()
		t.Error("the held lock file opened with sharing")
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	g, err := lockFile(path)
	if err != nil {
		t.Fatalf("after close: %v", err)
	}
	_ = g.Close()
}

// TestLockWindowsBadPath: a path Windows can't create is an error other
// than ErrLocked, so watch says what went wrong instead of "still going".
func TestLockWindowsBadPath(t *testing.T) {
	_, err := lockFile(filepath.Join(t.TempDir(), "missing", LockName))
	if err == nil || errors.Is(err, ErrLocked) {
		t.Fatalf("err %v, want a path error", err)
	}
	var pe *os.PathError
	if !errors.As(err, &pe) {
		t.Errorf("err %T, want *os.PathError", err)
	}
}
