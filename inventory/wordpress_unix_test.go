// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

//go:build unix

package inventory

import (
	"context"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// T-38: wp-config.php as a FIFO and an unreadable .env must not stop or
// hang a run. Inventory never opens either; a FIFO plugin file is
// refused without blocking.
func TestWordPressSecretsAndFIFOs(t *testing.T) {
	root := copyTree(t, "testdata/wp/site")
	for _, p := range []string{"wp-config.php", "wp-content/plugins/fifo-plugin/fifo-plugin.php"} {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := syscall.Mkfifo(full, 0o644); err != nil {
			t.Skip("no FIFOs here:", err)
		}
	}
	env := filepath.Join(root, ".env")
	if err := os.WriteFile(env, []byte("DB_PASSWORD=x\n"), 0); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := ReadWordPress(context.Background(), root)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ReadWordPress blocked on a FIFO")
	}
	site, _ := ReadWordPress(context.Background(), root)
	if nc := notCheckedBy(site.NotChecked)["wp-plugin:fifo-plugin"]; nc.Reason != "no-header" {
		t.Errorf("FIFO plugin = %+v, want no-header", nc)
	}
	want := "skipped wp-content/plugins/fifo-plugin/fifo-plugin.php: it is a FIFO, not a regular file"
	found := false
	for _, w := range site.Warnings {
		found = found || w == want
	}
	if !found {
		t.Errorf("warnings = %q, want %q", site.Warnings, want)
	}
}
