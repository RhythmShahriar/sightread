// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

//go:build windows

package fetch

import (
	"errors"
	"syscall"
)

// Winsock reports a refused or reset connection with its own codes,
// which syscall.ECONNREFUSED and syscall.ECONNRESET don't match there.
const (
	wsaeConnReset   syscall.Errno = 10054 // WSAECONNRESET
	wsaeConnRefused syscall.Errno = 10061 // WSAECONNREFUSED
)

// connRefused reports whether err is a refused connection.
func connRefused(err error) bool {
	return errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, wsaeConnRefused)
}

// connReset reports whether err is a connection the peer reset.
func connReset(err error) bool {
	return errors.Is(err, syscall.ECONNRESET) || errors.Is(err, wsaeConnReset)
}
