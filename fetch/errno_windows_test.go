// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

//go:build windows

package fetch

import (
	"net"
	"os"
	"testing"
)

// TestReasonWinsock: the Winsock codes for a refused and a reset
// connection read as they do on other systems.
func TestReasonWinsock(t *testing.T) {
	for errno, want := range map[error]string{wsaeConnRefused: "connection refused", wsaeConnReset: "connection dropped"} {
		err := &net.OpError{Op: "dial", Net: "tcp", Err: os.NewSyscallError("connectex", errno)}
		if got := reason(err); got != want {
			t.Errorf("%v: reason %q, want %q", errno, got, want)
		}
	}
}
