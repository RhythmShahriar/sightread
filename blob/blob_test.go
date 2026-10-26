// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package blob

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/RhythmShahriar/sightread/core"
)

func init() {
	// The child half of TestTwoProcesses.
	if dir := os.Getenv("BLOB_TEST_CHILD_DIR"); dir != "" {
		os.Exit(childPut(dir))
	}
}

func readAll(t *testing.T, s core.BlobStore, sum [32]byte) ([]byte, error) {
	t.Helper()
	rc, err := s.Open(sum)
	if err != nil {
		return nil, err
	}
	defer rc.Close()
	return io.ReadAll(rc)
}

// files lists every file under dir, relative.
func files(t *testing.T, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.WalkDir(dir, func(p string, e fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !e.IsDir() {
			r, _ := filepath.Rel(dir, p)
			out = append(out, filepath.ToSlash(r))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestRegistered(t *testing.T) {
	root := t.TempDir()
	s, err := core.OpenBlobs(root)
	if err != nil {
		t.Fatal(err)
	}
	d, ok := s.(*Disk)
	if !ok || d.Dir() != filepath.Join(root, "blobs") {
		t.Fatalf("core.OpenBlobs gave %T at %v", s, d)
	}
}

func stores(t *testing.T) map[string]core.BlobStore {
	d, err := OpenDisk(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return map[string]core.BlobStore{"disk": d, "memory": Memory()}
}

func TestRoundTrip(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			data := []byte("<?php echo 'hi';\n")
			sum, n, err := s.Put(context.Background(), bytes.NewReader(data), int64(len(data)))
			if err != nil {
				t.Fatal(err)
			}
			if sum != sha256.Sum256(data) || n != int64(len(data)) || !s.Has(sum) {
				t.Fatalf("sum %x n %d has %v", sum[:4], n, s.Has(sum))
			}
			got, err := readAll(t, s, sum)
			if err != nil || !bytes.Equal(got, data) {
				t.Fatalf("read %q %v", got, err)
			}
			// The same bytes again are the same blob.
			if again, _, err := s.Put(context.Background(), bytes.NewReader(data), 100); err != nil || again != sum {
				t.Errorf("second Put: %x %v", again[:4], err)
			}
			// Empty content is a blob too.
			if _, n, err := s.Put(context.Background(), strings.NewReader(""), 0); err != nil || n != 0 {
				t.Errorf("empty Put: %d %v", n, err)
			}
			var missing [32]byte
			if s.Has(missing) {
				t.Error("Has reports a blob never stored")
			}
			if _, err := s.Open(missing); err == nil {
				t.Error("Open of a missing blob succeeded")
			}
		})
	}
}

func TestPath(t *testing.T) {
	d, _ := OpenDisk(t.TempDir())
	sum, _, err := d.Put(context.Background(), strings.NewReader("x"), 1)
	if err != nil {
		t.Fatal(err)
	}
	p, ok := d.Path(sum)
	h := fmt.Sprintf("%x", sum)
	if !ok || p != filepath.Join(d.Dir(), h[:2], h) {
		t.Errorf("path %s %v", p, ok)
	}
	if filepath.Ext(p) != "" {
		t.Errorf("blob has an extension: %s", p)
	}
	if _, ok := Memory().Path(sum); ok {
		t.Error("memory blob has a path")
	}
}

func TestLimit(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			_, _, err := s.Put(context.Background(), strings.NewReader("12345"), 4)
			if !errors.Is(err, core.ErrTooLarge) {
				t.Fatalf("err %v, want ErrTooLarge", err)
			}
			if d, ok := s.(*Disk); ok {
				if f := files(t, d.Dir()); len(f) != 0 {
					t.Errorf("files left: %v", f)
				}
			}
			if m, ok := s.(*Mem); ok && m.Len() != 0 {
				t.Errorf("%d blobs stored", m.Len())
			}
			// Exactly at the limit is fine.
			if _, _, err := s.Put(context.Background(), strings.NewReader("1234"), 4); err != nil {
				t.Errorf("at the limit: %v", err)
			}
		})
	}
}

// TestCorruptBlob: a blob changed on disk is caught on read and removed,
// so the next run fetches it again (e06).
func TestCorruptBlob(t *testing.T) {
	d, _ := OpenDisk(t.TempDir())
	sum, _, err := d.Put(context.Background(), strings.NewReader("original contents"), 100)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := d.Path(sum)
	if err := os.WriteFile(p, []byte("tampered contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readAll(t, d, sum); !errors.Is(err, core.ErrBlobCorrupt) {
		t.Fatalf("err %v, want ErrBlobCorrupt", err)
	}
	if d.Has(sum) {
		t.Error("corrupt blob kept")
	}
	// Stored again, it reads fine.
	if _, _, err := d.Put(context.Background(), strings.NewReader("original contents"), 100); err != nil {
		t.Fatal(err)
	}
	if got, err := readAll(t, d, sum); err != nil || string(got) != "original contents" {
		t.Errorf("after refetch: %q %v", got, err)
	}
}

// TestConcurrentPut: two writers of the same content both succeed (e07).
// A blob torn by a crash or changed on disk is replaced when the same
// bytes are stored again, while a sound one is kept as it is.
func TestPutRepairsCorruptBlob(t *testing.T) {
	const body = "original contents"
	for name, bad := range map[string][]byte{
		"flipped byte": []byte("original contentS"),
		"zero length":  {},
		"torn":         []byte("origin"),
	} {
		d, _ := OpenDisk(t.TempDir())
		sum, _, err := d.Put(context.Background(), strings.NewReader(body), 100)
		if err != nil {
			t.Fatal(err)
		}
		p, _ := d.Path(sum)
		if err := os.WriteFile(p, bad, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := d.Put(context.Background(), strings.NewReader(body), 100); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got, err := readAll(t, d, sum); err != nil || string(got) != body {
			t.Errorf("%s: after Put again %q %v", name, got, err)
		}
		if n := len(files(t, d.Dir())); n != 1 {
			t.Errorf("%s: %d files left, want 1", name, n)
		}
	}

	d, _ := OpenDisk(t.TempDir())
	sum, _, err := d.Put(context.Background(), strings.NewReader(body), 100)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := d.Path(sum)
	before, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := d.Put(context.Background(), strings.NewReader(body), 100); err != nil {
		t.Fatal(err)
	}
	after, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Error("a sound blob was replaced")
	}
}

func TestConcurrentPut(t *testing.T) {
	d, _ := OpenDisk(t.TempDir())
	data := bytes.Repeat([]byte("shared plugin file\n"), 4096)
	var wg sync.WaitGroup
	sums := make([][32]byte, 16)
	for i := range sums {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sum, _, err := d.Put(context.Background(), bytes.NewReader(data), 1<<20)
			if err != nil {
				t.Error(err)
			}
			sums[i] = sum
		}()
	}
	wg.Wait()
	for _, s := range sums {
		if s != sha256.Sum256(data) {
			t.Fatal("a writer got another sum")
		}
	}
	if got, err := readAll(t, d, sums[0]); err != nil || !bytes.Equal(got, data) {
		t.Errorf("read back: %v", err)
	}
	if f := files(t, d.Dir()); len(f) != 1 {
		t.Errorf("files %v, want one blob", f)
	}
}

// childContent is what both processes of TestTwoProcesses store.
var childContent = bytes.Repeat([]byte("two runs share one cache\n"), 8192)

func childPut(dir string) int {
	d, err := OpenDisk(dir)
	if err != nil {
		fmt.Println(err)
		return 1
	}
	for range 50 {
		if _, _, err := d.Put(context.Background(), bytes.NewReader(childContent), 1<<20); err != nil {
			fmt.Println(err)
			return 1
		}
	}
	return 0
}

func TestTwoProcesses(t *testing.T) {
	if testing.Short() {
		t.Skip("starts child processes")
	}
	dir := t.TempDir()
	var cmds []*exec.Cmd
	var outs []*bytes.Buffer
	for range 2 {
		cmd := exec.Command(os.Args[0], "-test.run=^$")
		cmd.Env = append(os.Environ(), "BLOB_TEST_CHILD_DIR="+dir)
		var out bytes.Buffer
		cmd.Stdout, cmd.Stderr = &out, &out
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		cmds, outs = append(cmds, cmd), append(outs, &out)
	}
	for i, c := range cmds {
		if err := c.Wait(); err != nil {
			t.Errorf("child %d: %v\n%s", i, err, outs[i])
		}
	}
	d, _ := OpenDisk(dir)
	if got, err := readAll(t, d, sha256.Sum256(childContent)); err != nil || !bytes.Equal(got, childContent) {
		t.Errorf("shared blob: %v", err)
	}
	if f := files(t, d.Dir()); len(f) != 1 {
		t.Errorf("files %v, want one blob", f)
	}
}

// stallReader hands out one chunk, then calls hook before the next.
type stallReader struct {
	n    int
	hook func()
}

func (s *stallReader) Read(p []byte) (int, error) {
	s.n++
	if s.n > 1 && s.hook != nil {
		s.hook()
		s.hook = nil
	}
	return copy(p, bytes.Repeat([]byte("a"), min(len(p), 1024))), nil
}

// TestCancelLeavesNoTemp: Ctrl-C mid-Put leaves no partial file (e08).
func TestCancelLeavesNoTemp(t *testing.T) {
	for name, s := range stores(t) {
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			_, _, err := s.Put(ctx, &stallReader{hook: cancel}, 1<<30)
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("err %v, want Canceled", err)
			}
			if d, ok := s.(*Disk); ok {
				if f := files(t, d.Dir()); len(f) != 0 {
					t.Errorf("files left: %v", f)
				}
			}
			if _, _, err := s.Put(ctx, strings.NewReader("x"), 1); !errors.Is(err, context.Canceled) {
				t.Errorf("Put on a done context: %v", err)
			}
		})
	}
}

func TestModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix modes")
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "blobs"), 0o755); err != nil {
		t.Fatal(err)
	}
	d, err := OpenDisk(root)
	if err != nil {
		t.Fatal(err)
	}
	sum, _, err := d.Put(context.Background(), strings.NewReader("#!/bin/sh\necho hi\n"), 100)
	if err != nil {
		t.Fatal(err)
	}
	p, _ := d.Path(sum)
	for path, want := range map[string]fs.FileMode{d.Dir(): 0o700, filepath.Dir(p): 0o700, p: 0o600} {
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := fi.Mode().Perm(); got != want {
			t.Errorf("%s mode %o, want %o", path, got, want)
		}
	}
}

func TestPrune(t *testing.T) {
	d, _ := OpenDisk(t.TempDir())
	ctx := context.Background()
	keep, _, _ := d.Put(ctx, strings.NewReader("referenced"), 100)
	drop, _, _ := d.Put(ctx, strings.NewReader("unreferenced"), 100)
	fresh, _, _ := d.Put(ctx, strings.NewReader("unreferenced but new"), 100)
	old := time.Now().Add(-48 * time.Hour)
	for _, s := range [][32]byte{keep, drop} {
		p, _ := d.Path(s)
		if err := os.Chtimes(p, old, old); err != nil {
			t.Fatal(err)
		}
	}
	stale := filepath.Join(d.Dir(), tmpPrefix+"crashed")
	if err := os.WriteFile(stale, []byte("partial"), 0o600); err != nil {
		t.Fatal(err)
	}
	_ = os.Chtimes(stale, old, old)
	other := filepath.Join(d.Dir(), "README")
	_ = os.WriteFile(other, []byte("not a blob"), 0o600)
	_ = os.Chtimes(other, old, old)

	n, size, err := d.Prune(map[[32]byte]bool{keep: true}, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || size != int64(len("unreferenced")+len("partial")) {
		t.Errorf("pruned %d files, %d bytes", n, size)
	}
	if !d.Has(keep) || d.Has(drop) || !d.Has(fresh) {
		t.Errorf("keep %v drop %v fresh %v", d.Has(keep), d.Has(drop), d.Has(fresh))
	}
	if _, err := os.Stat(other); err != nil {
		t.Error("Prune removed a file that is not a blob")
	}
	// Storing a blob again makes it new, so a prune right after keeps it.
	p, _ := d.Path(keep)
	_ = os.Chtimes(p, old, old)
	if _, _, err := d.Put(ctx, strings.NewReader("referenced"), 100); err != nil {
		t.Fatal(err)
	}
	if n, _, _ := d.Prune(nil, 24*time.Hour); n != 0 || !d.Has(keep) {
		t.Errorf("pruned a blob stored a moment ago")
	}
}
