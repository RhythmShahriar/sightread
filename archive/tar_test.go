// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package archive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/RhythmShahriar/sightread/blob"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/fetch"
)

// tent is one entry of a test tarball.
type tent struct {
	name   string
	body   string
	typ    byte // tar.TypeReg when zero
	link   string
	size   int64 // header size when it should lie; 0 means len(body)
	format tar.Format
}

// writeTar writes entries with archive/tar into w.
func writeTar(t testing.TB, w io.Writer, entries ...tent) {
	t.Helper()
	tw := tar.NewWriter(w)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Typeflag: e.typ, Linkname: e.link, Mode: 0o644, Format: e.format, ModTime: time.Unix(0, 0)}
		if h.Typeflag == 0 {
			h.Typeflag = tar.TypeReg
		}
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(e.body))
			if e.size != 0 {
				h.Size = e.size
			}
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(tw, e.body); err != nil && e.size == 0 {
			t.Fatal(err)
		}
	}
	// A lying header leaves the writer short; Flush would fail and the
	// archive is meant to be broken then.
	_ = tw.Close()
}

// makeTgz returns entries as a gzip-compressed tarball.
func makeTgz(t testing.TB, entries ...tent) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	writeTar(t, gz, entries...)
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// gzipBytes compresses raw as one gzip member.
func gzipBytes(t testing.TB, raw []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	_, _ = gz.Write(raw)
	_ = gz.Close()
	return buf.Bytes()
}

func readTgz(t testing.TB, data []byte, lim core.Limits, strip StripRule) (*core.Tree, *blob.Mem, error) {
	t.Helper()
	m := blob.Memory()
	tree, err := ReadTarGz(context.Background(), bytes.NewReader(data), m, lim, strip)
	return tree, m, err
}

func mustTgz(t *testing.T, data []byte, strip StripRule) (*core.Tree, *blob.Mem) {
	t.Helper()
	tree, m, err := readTgz(t, data, core.DefaultLimits(), strip)
	if err != nil {
		t.Fatal(err)
	}
	return tree, m
}

func TestReadTarGzPackage(t *testing.T) {
	data := makeTgz(t,
		tent{name: "package/", typ: tar.TypeDir},
		tent{name: "package/package.json", body: `{"name":"left-pad"}`},
		tent{name: "package/index.js", body: "module.exports = 1;"},
		tent{name: "package/lib/inner.tgz", body: "\x1f\x8bnested"},
		tent{name: "package/README.md", body: "# left-pad"},
	)
	tree, m := mustTgz(t, data, StripFolder("package"))
	want := []string{"README.md", "index.js", "lib/inner.tgz", "package.json"}
	if !slices.Equal(paths(tree), want) || tree.Root != "package/" || len(tree.Issues) != 0 {
		t.Fatalf("paths %v root %q issues %v", paths(tree), tree.Root, issues(tree))
	}
	if content(t, tree, "index.js") != "module.exports = 1;" {
		t.Error("content differs")
	}
	// The nested tarball is listed, not opened.
	if f, _ := tree.Lookup("lib/inner.tgz"); f.Kind != core.KindArchive {
		t.Errorf("nested kind %s", f.Kind)
	}
	if f, _ := tree.Lookup("index.js"); f.Kind != core.KindJS || f.Mode != 0o644 {
		t.Errorf("index.js %+v", f)
	}
	if tree.SHA256 != sha256.Sum256(data) || tree.HashKind != core.HashArchive || m.Len() != 4 {
		t.Errorf("hash, kind or blobs (%d) not set", m.Len())
	}
}

func TestReadTarGzPathEscapes(t *testing.T) {
	long := "package/" + strings.Repeat("d/", 60) + "../../../" + strings.Repeat("../", 60) + "evil.js"
	data := makeTgz(t,
		tent{name: "package/ok.js", body: "1"},
		tent{name: "package/../../evil.js", body: "evil"},
		tent{name: "/abs.js", body: "abs"},
		tent{name: `package\..\..\win.js`, body: "win"},
		// Over 100 bytes: the writer puts the name in a PAX record.
		tent{name: long, body: "pax", format: tar.FormatPAX},
		tent{name: "package/café/ü.js", body: "pax unicode", format: tar.FormatPAX},
		tent{name: "package/ctl\x01.js", body: "x"},
	)
	if !bytes.Contains(gunzip(t, data), []byte("path=")) {
		t.Fatal("fixture has no PAX path record")
	}
	tree, m := mustTgz(t, data, StripSingle)
	for _, p := range []string{"package/../../evil.js", "/abs.js", `package\..\..\win.js`, long} {
		if !hasIssue(tree, core.IssuePathEscape, p) {
			t.Errorf("no path-escape for %q in %v", p, issues(tree))
		}
	}
	if !hasIssue(tree, core.IssueMalformed, "package/ctl\x01.js") {
		t.Errorf("control character in the name: %v", issues(tree))
	}
	if !slices.Equal(paths(tree), []string{"café/ü.js", "ok.js"}) || m.Len() != 2 {
		t.Errorf("stored %v (%d blobs)", paths(tree), m.Len())
	}
}

func gunzip(t *testing.T, data []byte) []byte {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		t.Fatal(err)
	}
	out, _ := io.ReadAll(gz)
	return out
}

func TestReadTarGzLinksAndDevices(t *testing.T) {
	data := makeTgz(t,
		tent{name: "package/a.js", body: "1"},
		tent{name: "package/passwd", typ: tar.TypeSymlink, link: "/etc/passwd"},
		tent{name: "package/up", typ: tar.TypeSymlink, link: "../../x"},
		tent{name: "package/in", typ: tar.TypeSymlink, link: "a.js"},
		tent{name: "package/hard", typ: tar.TypeLink, link: "package/a.js"},
		tent{name: "package/hardout", typ: tar.TypeLink, link: "../../etc/shadow"},
		tent{name: "package/tty", typ: tar.TypeChar},
		tent{name: "package/sda", typ: tar.TypeBlock},
		tent{name: "package/fifo", typ: tar.TypeFifo},
		tent{name: "package/odd", typ: 'Z'},
	)
	tree, m := mustTgz(t, data, StripSingle)
	want := map[string]string{
		"package/passwd": "link-escape symlink to outside the package", "package/up": "link-escape symlink to outside the package",
		"package/in": "link symlink", "package/hard": "link hard link", "package/hardout": "link-escape hard link to outside the package",
		"package/tty": "link character device", "package/sda": "link block device", "package/fifo": "link named pipe",
		"package/odd": "link irregular file",
	}
	got := map[string]string{}
	for _, i := range tree.Issues {
		got[i.Path] = string(i.Kind) + " " + i.Detail
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("issues\n%v\nwant\n%v", got, want)
	}
	if f, _ := tree.Lookup("passwd"); f.Link != "/etc/passwd" || f.Mode&fs.ModeSymlink == 0 || f.SHA256 != [32]byte{} {
		t.Errorf("symlink %+v", f)
	}
	if f, _ := tree.Lookup("hard"); f.Link != "package/a.js" || f.Mode.Type() != fs.ModeIrregular || f.SHA256 != [32]byte{} {
		t.Errorf("hard link %+v", f)
	}
	if f, _ := tree.Lookup("fifo"); f.Mode&fs.ModeNamedPipe == 0 {
		t.Errorf("fifo mode %v", f.Mode)
	}
	if m.Len() != 1 {
		t.Errorf("%d blobs, want 1: a link or device was stored", m.Len())
	}
}

func TestReadTarGzDuplicates(t *testing.T) {
	data := makeTgz(t,
		tent{name: "package/index.js", body: "first"},
		tent{name: "package/index.js", body: "second"},
		tent{name: "package/Index.js", body: "case"},
	)
	tree, _ := mustTgz(t, data, StripSingle)
	got := map[string]string{}
	for _, p := range paths(tree) {
		got[p] = content(t, tree, p)
	}
	if fmt.Sprint(got) != fmt.Sprint(map[string]string{"index.js": "first", "index.js#2": "second", "Index.js": "case"}) {
		t.Errorf("kept %v", got)
	}
	if !hasIssue(tree, core.IssueCollision, "package/index.js") || !hasIssue(tree, core.IssueCollision, "package/Index.js") {
		t.Errorf("issues %v", issues(tree))
	}
}

func TestReadTarGzTrailing(t *testing.T) {
	entries := []tent{{name: "package/a.js", body: "1"}}
	good := makeTgz(t, entries...)
	for name, tc := range map[string]struct {
		data   []byte
		detail string
	}{
		"garbage after gzip":   {append(append([]byte{}, good...), "hidden"...), "data after the end of the gzip stream; not read"},
		"second gzip member":   {append(append([]byte{}, good...), makeTgz(t, tent{name: "package/b.js", body: "2"})...), "data after the end of the gzip stream; not read"},
		"data after tar end":   {tarThen(t, entries, "package/evil.js hidden after the end marker"), "data after the end of the tar archive; not read"},
		"truncated":            {good[:len(good)-10], "unreadable"},
		"lying header":         {makeTgz(t, tent{name: "package/a.js", body: "short", size: 4096}), "unreadable"},
		"bad gzip checksum":    {flipCRC(good), "unreadable gzip stream"},
		"zero padding is fine": {append(append([]byte{}, good...), make([]byte, 512)...), ""},
	} {
		t.Run(name, func(t *testing.T) {
			tree, _, err := readTgz(t, tc.data, core.DefaultLimits(), StripSingle)
			if err != nil {
				t.Fatal(err)
			}
			var found []string
			for _, i := range tree.Issues {
				if i.Kind == core.IssueMalformed {
					found = append(found, i.Detail)
				}
			}
			switch {
			case tc.detail == "" && (len(found) != 0 || tree.SHA256 != sha256.Sum256(tc.data)):
				t.Errorf("issues %v, hash set %v", found, tree.SHA256 != [32]byte{})
			case tc.detail != "" && (len(found) == 0 || !strings.HasPrefix(found[0], tc.detail)):
				t.Errorf("malformed %q, want %q", found, tc.detail)
			}
		})
	}
}

// tarThen is a tarball of entries with extra bytes after its end marker,
// all inside one gzip member.
func tarThen(t *testing.T, entries []tent, extra string) []byte {
	t.Helper()
	var raw bytes.Buffer
	writeTar(t, &raw, entries...)
	raw.WriteString(extra)
	return gzipBytes(t, raw.Bytes())
}

// flipCRC breaks the CRC-32 in the gzip trailer.
func flipCRC(data []byte) []byte {
	out := append([]byte{}, data...)
	out[len(out)-8] ^= 0xff
	return out
}

func TestReadTarGzNotGzip(t *testing.T) {
	if _, _, err := readTgz(t, []byte("plain text"), core.DefaultLimits(), StripSingle); err == nil {
		t.Error("text read as a tgz")
	}
	// A gzip that holds no tar is an unreadable archive, not a panic.
	tree, _, err := readTgz(t, gzipBytes(t, []byte("not a tar at all, just text that goes on")), core.DefaultLimits(), StripSingle)
	if err != nil || !hasIssue(tree, core.IssueMalformed, "") {
		t.Errorf("err %v issues %v", err, issues(tree))
	}
}

func TestReadTarGzCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ReadTarGz(ctx, bytes.NewReader(makeTgz(t, tent{name: "a", body: "1"})), blob.Memory(), core.DefaultLimits(), StripSingle); !errors.Is(err, context.Canceled) {
		t.Errorf("err %v", err)
	}
}

// lazyTgz streams a tarball that write produces into a pipe, so a test
// can offer far more than it would ever build in memory. The writer
// stops once the reader is done; written reports the tar bytes it got
// out.
func lazyTgz(t *testing.T, write func(tw *tar.Writer) error) (r io.Reader, written func() int64) {
	t.Helper()
	pr, pw := io.Pipe()
	done := make(chan int64, 1)
	go func() {
		cw := &countWriter{}
		gz, _ := gzip.NewWriterLevel(io.MultiWriter(pw, cw), gzip.BestSpeed)
		tw := tar.NewWriter(gz)
		err := write(tw)
		if err == nil {
			err = tw.Close()
		}
		if err == nil {
			err = gz.Close()
		}
		pw.CloseWithError(err)
		done <- cw.n
	}()
	t.Cleanup(func() { _ = pr.Close() })
	return pr, func() int64 { _ = pr.Close(); return <-done }
}

type countWriter struct{ n int64 }

func (c *countWriter) Write(p []byte) (int, error) { c.n += int64(len(p)); return len(p), nil }

// TestReadTarGzMillionEntries: a stream of 1,000,000 empty entries stops
// at the entry cap without reading the rest.
func TestReadTarGzMillionEntries(t *testing.T) {
	if testing.Short() {
		t.Skip("streams 100,000 entries")
	}
	r, written := lazyTgz(t, func(tw *tar.Writer) error {
		for i := range 1000000 {
			if err := tw.WriteHeader(&tar.Header{Name: fmt.Sprintf("package/%07d", i), Typeflag: tar.TypeReg, Mode: 0o644}); err != nil {
				return err
			}
		}
		return nil
	})
	start := time.Now()
	tree, err := ReadTarGz(context.Background(), r, blob.Memory(), core.DefaultLimits(), StripSingle)
	if err != nil {
		t.Fatal(err)
	}
	took := time.Since(start)
	written()
	if len(tree.Files) != 100000 || !hasIssue(tree, core.IssueLimit, "") || tree.SHA256 != [32]byte{} {
		t.Errorf("%d files, last issues %v", len(tree.Files), tree.Issues[len(tree.Issues)-1:])
	}
	if took > 60*time.Second {
		t.Errorf("took %s to stop at the cap", took)
	}
}

// TestReadTarGzBombMember: a member that would expand to 1 GiB stops at
// the ratio a little past 1 MiB, long before the writer gets far.
func TestReadTarGzBombMember(t *testing.T) {
	r, written := lazyTgz(t, func(tw *tar.Writer) error {
		if err := tw.WriteHeader(&tar.Header{Name: "package/a.js", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1}); err != nil {
			return err
		}
		_, _ = tw.Write([]byte("1"))
		if err := tw.WriteHeader(&tar.Header{Name: "package/bomb.bin", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1 << 30}); err != nil {
			return err
		}
		zeros := make([]byte, 1<<20)
		for range 1024 {
			if _, err := tw.Write(zeros); err != nil {
				return err
			}
		}
		return nil
	})
	runtime.GC()
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	tree, err := ReadTarGz(context.Background(), r, blob.Memory(), core.DefaultLimits(), StripSingle)
	runtime.ReadMemStats(&m1)
	if err != nil {
		t.Fatal(err)
	}
	if n := written(); n > 64<<20 {
		t.Errorf("the writer got %d MiB of gzip out: the reader went on", n>>20)
	}
	if !hasIssue(tree, core.IssueLimit, "package/bomb.bin") || !slices.Equal(paths(tree), []string{"a.js"}) {
		t.Errorf("issues %v paths %v", issues(tree), paths(tree))
	}
	if alloc := m1.TotalAlloc - m0.TotalAlloc; alloc > 64<<20 {
		t.Errorf("allocated %d MiB", alloc>>20)
	}
}

// TestReadTarGzTotalCap: incompressible entries past the uncompressed
// cap give E11. So do the bytes of an entry too big to store, which tar
// would otherwise skip uncounted.
func TestReadTarGzTotalCap(t *testing.T) {
	t.Setenv("RHYTHM_INVOKED_AS", "rhythm sightread")
	noise := make([]byte, 512<<10)
	_, _ = rand.Read(noise)
	lim := core.DefaultLimits()
	lim.Uncompressed = 1 << 20
	data := makeTgz(t, tent{name: "package/1", body: string(noise)}, tent{name: "package/2", body: string(noise)}, tent{name: "package/3", body: string(noise)})
	_, _, err := readTgz(t, data, lim, StripSingle)
	if !errors.Is(err, core.ErrTooLarge) || core.CodeOf(err) != core.ETooLarge {
		t.Fatalf("err %v, want E11", err)
	}
	err = fetch.Package{Command: "npm", Name: "huge-pkg", Version: "1.4.0", Archive: "tarball"}.Wrap(err)
	want := "rhythm sightread npm: the 1.4.0 archive of huge-pkg unpacks to over 1 MiB\n" +
		"  raise --max-size if you expect that; a size jump this big is worth a look on its own"
	if err.Error() != want {
		t.Errorf("err\n%s\nwant\n%s", err, want)
	}

	lim.EntryStored = 256 << 10
	big := makeTgz(t, tent{name: "package/big", body: string(noise) + string(noise) + string(noise)})
	if _, _, err := readTgz(t, big, lim, StripSingle); core.CodeOf(err) != core.ETooLarge {
		t.Errorf("skipped bytes not counted: %v", err)
	}
}

func TestReadTarGzEntryCap(t *testing.T) {
	lim := core.DefaultLimits()
	lim.EntryStored = 1024
	data := makeTgz(t, tent{name: "package/big.txt", body: strings.Repeat("x", 2048)}, tent{name: "package/small.js", body: "1"})
	tree, m, err := readTgz(t, data, lim, StripSingle)
	if err != nil {
		t.Fatal(err)
	}
	// The walk goes on past an entry too big to store.
	if !hasIssue(tree, core.IssueLimit, "package/big.txt") || !slices.Equal(paths(tree), []string{"small.js"}) || m.Len() != 1 {
		t.Errorf("issues %v paths %v", issues(tree), paths(tree))
	}
	if tree.SHA256 != sha256.Sum256(data) {
		t.Error("a walk that read everything has no hash")
	}
}

// TestReadTarGzTricksOnDisk: every trick into a Disk store writes
// nothing outside the blob folder and stays under the memory cap.
func TestReadTarGzTricksOnDisk(t *testing.T) {
	for name, data := range map[string][]byte{
		"package": makeTgz(t, tent{name: "package/a.js", body: "1"}),
		"escape":  makeTgz(t, tent{name: "package/../../evil.js", body: "x"}, tent{name: "/abs.js", body: "x"}),
		"links":   makeTgz(t, tent{name: "package/l", typ: tar.TypeSymlink, link: "/etc/passwd"}, tent{name: "package/h", typ: tar.TypeLink, link: "../../x"}),
		"devices": makeTgz(t, tent{name: "package/c", typ: tar.TypeChar}, tent{name: "package/f", typ: tar.TypeFifo}),
		"dupes":   makeTgz(t, tent{name: "package/x", body: "1"}, tent{name: "package/x", body: "2"}),
	} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			d, err := blob.OpenDisk(filepath.Join(root, "cache"))
			if err != nil {
				t.Fatal(err)
			}
			before := walk(t, root)
			runtime.GC()
			var m0, m1 runtime.MemStats
			runtime.ReadMemStats(&m0)
			if _, err := ReadTarGz(context.Background(), bytes.NewReader(data), d, core.DefaultLimits(), StripSingle); err != nil {
				t.Fatal(err)
			}
			runtime.ReadMemStats(&m1)
			if alloc := m1.TotalAlloc - m0.TotalAlloc; alloc > 16<<20 {
				t.Errorf("allocated %d MiB", alloc>>20)
			}
			for _, p := range walk(t, root) {
				if !slices.Contains(before, p) && !strings.HasPrefix(p, "cache/blobs/") {
					t.Errorf("wrote %s outside the blob folder", p)
				}
			}
		})
	}
}

func FuzzTarIndex(f *testing.F) {
	f.Add(makeTgz(f, tent{name: "package/a.js", body: "1"}, tent{name: "package/b/", typ: tar.TypeDir}))
	f.Add(makeTgz(f, tent{name: "package/../../evil.js", body: "x"}, tent{name: "package/l", typ: tar.TypeSymlink, link: "/etc/passwd"}))
	f.Add(makeTgz(f, tent{name: "package/x", body: "1"}, tent{name: "package/X", body: "2"}, tent{name: "package/x", body: "3"}))
	f.Add(makeTgz(f, tent{name: "package/z", body: strings.Repeat("\x00", 1<<16)}))
	f.Add(makeTgz(f, tent{name: "package/" + strings.Repeat("p", 120), body: "pax", format: tar.FormatPAX}))
	f.Add([]byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 0xff})
	lim := core.DefaultLimits()
	lim.Uncompressed, lim.EntryStored, lim.Entries = 1<<20, 256<<10, 64
	f.Fuzz(func(t *testing.T, data []byte) {
		m := blob.Memory()
		tree, err := ReadTarGz(context.Background(), bytes.NewReader(data), m, lim, StripSingle)
		if err != nil {
			return
		}
		if tree.Bytes > lim.Uncompressed || len(tree.Files) > lim.Entries {
			t.Fatalf("%d bytes, %d files past the limits", tree.Bytes, len(tree.Files))
		}
		if !slices.IsSortedFunc(tree.Files, func(a, b core.File) int { return strings.Compare(a.Path, b.Path) }) {
			t.Fatal("files not sorted")
		}
		for _, file := range tree.Files {
			p := copySuffix.ReplaceAllString(tree.Root+file.Path, "")
			if clean, _, ok := ValidateName(p); !ok || clean != p {
				t.Fatalf("stored path %q fails ValidateName", p)
			}
			if file.Mode.IsRegular() && !m.Has(file.SHA256) {
				t.Fatalf("%s has no blob", file.Path)
			}
			if file.Size > lim.EntryStored {
				t.Fatalf("%s stored %d bytes", file.Path, file.Size)
			}
		}
	})
}
