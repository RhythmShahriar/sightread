// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package inventory

import (
	"fmt"
	"io"
	"io/fs"
	"os"
)

// notRegularError is returned when a path that should be a file is a
// FIFO, socket, device or folder. Reading one could block or never end.
type notRegularError struct {
	path string
	kind string
}

func (e *notRegularError) Error() string {
	return fmt.Sprintf("%s is %s, not a regular file", e.path, e.kind)
}

// fileKind names a non-regular file mode for a warning.
func fileKind(m fs.FileMode) string {
	switch {
	case m&fs.ModeNamedPipe != 0:
		return "a FIFO"
	case m&fs.ModeSocket != 0:
		return "a socket"
	case m&fs.ModeDevice != 0, m&fs.ModeCharDevice != 0:
		return "a device"
	case m.IsDir():
		return "a folder"
	case m&fs.ModeSymlink != 0:
		return "a link"
	}
	return "a special file"
}

// openRegular opens path for reading only when it is a regular file, or
// a link to one. Special files are refused before and after the open,
// so a FIFO swapped in between can't block either.
func openRegular(path string) (*os.File, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if fi.Mode()&fs.ModeSymlink != 0 {
		target, err := os.Stat(path)
		if err != nil {
			return nil, err
		}
		if !target.Mode().IsRegular() {
			return nil, &notRegularError{path, "a link to " + fileKind(target.Mode())}
		}
	} else if !fi.Mode().IsRegular() {
		return nil, &notRegularError{path, fileKind(fi.Mode())}
	}
	f, err := openRead(path)
	if err != nil {
		return nil, err
	}
	if fi, err = f.Stat(); err != nil {
		_ = f.Close()
		return nil, err
	} else if !fi.Mode().IsRegular() {
		_ = f.Close()
		return nil, &notRegularError{path, fileKind(fi.Mode())}
	}
	return f, nil
}

// readHead returns at most n bytes from the start of the regular file
// at path. WordPress reads headers from the first 8 KiB the same way.
func readHead(path string, n int64) ([]byte, error) {
	f, err := openRegular(path)
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	return io.ReadAll(io.LimitReader(f, n))
}
