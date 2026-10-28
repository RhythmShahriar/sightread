// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

//go:build !windows

package fetch

import (
	"errors"
	"syscall"
)

// connRefused reports whether err is a refused connection.
func connRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED)
}

// connReset reports whether err is a connection the peer reset.
func connReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET)
}
