// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package canary

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/RhythmShahriar/sightread/testbed/ports"
)

func TestCanaryCountsConnections(t *testing.T) {
	c, err := New(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Start(); err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if c.Fired() {
		t.Fatal("canary fired before any connection")
	}
	for i := 0; i < 3; i++ {
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", ports.Canary), time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = conn.Close()
	}
	// The listener records asynchronously; wait briefly for the count.
	deadline := time.Now().Add(2 * time.Second)
	for c.Count() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if c.Count() != 3 {
		t.Fatalf("want 3 connections, got %d", c.Count())
	}
	if !c.Fired() {
		t.Fatal("canary should have fired after connections")
	}
}

func TestCanaryDetectsDroppedFile(t *testing.T) {
	dir := t.TempDir()
	c, err := New(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	if err := os.WriteFile(filepath.Join(dir, "canary", "b01"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	files, err := c.Files()
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0] != "b01" {
		t.Fatalf("want [b01], got %v", files)
	}
	if !c.Fired() {
		t.Fatal("a dropped canary file should trip the canary")
	}
}
