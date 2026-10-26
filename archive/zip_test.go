// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package archive

import (
	"archive/zip"
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash/crc32"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/blob"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/fetch"
)

// zent is one entry of a test zip.
type zent struct {
	name   string
	body   string
	mode   fs.FileMode // 0 means a regular 0644 file
	method uint16      // zip.Store or zip.Deflate (the default)
	flags  uint16
}

// makeZip writes entries with archive/zip, as an attacker's tool might.
func makeZip(t testing.TB, entries ...zent) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for _, e := range entries {
		h := &zip.FileHeader{Name: e.name, Method: zip.Deflate, Flags: e.flags}
		if e.method != 0 || e.flags != 0 {
			h.Method = e.method
		}
		mode := e.mode
		if mode == 0 {
			mode = 0o644
		}
		h.SetMode(mode)
		fw, err := w.CreateHeader(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := io.WriteString(fw, e.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func readZip(t testing.TB, data []byte, lim core.Limits, strip StripRule) (*core.Tree, *blob.Mem, error) {
	t.Helper()
	m := blob.Memory()
	tree, err := ReadZip(context.Background(), bytes.NewReader(data), int64(len(data)), m, lim, strip)
	return tree, m, err
}

func mustZip(t *testing.T, data []byte, strip StripRule) (*core.Tree, *blob.Mem) {
	t.Helper()
	tree, m, err := readZip(t, data, core.DefaultLimits(), strip)
	if err != nil {
		t.Fatal(err)
	}
	return tree, m
}

func paths(tree *core.Tree) []string {
	var out []string
	for _, f := range tree.Files {
		out = append(out, f.Path)
	}
	return out
}

func content(t *testing.T, tree *core.Tree, p string) string {
	t.Helper()
	f, ok := tree.Lookup(p)
	if !ok {
		t.Fatalf("no %s in %v", p, paths(tree))
	}
	rc, err := tree.Blobs.Open(f.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	b, _ := io.ReadAll(rc)
	return string(b)
}

// issues lists the issues as "kind path" lines.
func issues(tree *core.Tree) []string {
	var out []string
	for _, i := range tree.Issues {
		out = append(out, string(i.Kind)+" "+i.Path)
	}
	return out
}

func hasIssue(tree *core.Tree, kind core.ArchiveIssueKind, path string) bool {
	return slices.Contains(issues(tree), string(kind)+" "+path)
}

func TestReadZipPlugin(t *testing.T) {
	data := makeZip(t,
		zent{name: "akismet/", mode: fs.ModeDir | 0o755},
		zent{name: "akismet/akismet.php", body: "<?php // main"},
		zent{name: "akismet/readme.txt", body: "=== Akismet ==="},
		zent{name: "akismet/_inc/akismet.js", body: "var a = 1;"},
		zent{name: "akismet/_inc/akismet.min.js", body: "var a=1;"},
		zent{name: "akismet/_inc/img/logo.png", body: "\x89PNG"},
		zent{name: "akismet/views/config.json", body: "{}", method: zip.Store},
		zent{name: "akismet/vendor/lib.phar", body: "phar"},
		zent{name: "akismet/LICENSE", body: "GPL"},
	)
	tree, m := mustZip(t, data, StripFolder("akismet"))
	want := []string{"LICENSE", "_inc/akismet.js", "_inc/akismet.min.js", "_inc/img/logo.png", "akismet.php", "readme.txt", "vendor/lib.phar", "views/config.json"}
	if !slices.Equal(paths(tree), want) {
		t.Fatalf("paths %v, want %v", paths(tree), want)
	}
	if tree.Root != "akismet/" || len(tree.Issues) != 0 {
		t.Errorf("root %q issues %v", tree.Root, issues(tree))
	}
	kinds := map[string]core.FileKind{
		"akismet.php": core.KindPHP, "readme.txt": core.KindText, "_inc/akismet.js": core.KindJS,
		"_inc/akismet.min.js": core.KindMinified, "_inc/img/logo.png": core.KindAsset,
		"views/config.json": core.KindJSON, "vendor/lib.phar": core.KindArchive, "LICENSE": core.KindText,
	}
	for p, k := range kinds {
		if f, _ := tree.Lookup(p); f.Kind != k {
			t.Errorf("%s kind %s, want %s", p, f.Kind, k)
		}
	}
	if content(t, tree, "akismet.php") != "<?php // main" {
		t.Error("content differs")
	}
	if tree.SHA256 != sha256.Sum256(data) || tree.HashKind != core.HashArchive || tree.Blobs != core.BlobStore(m) {
		t.Error("archive hash, kind or blobs not set")
	}
	var bytesWant int64
	for _, f := range tree.Files {
		bytesWant += f.Size
	}
	if tree.Bytes != bytesWant || m.Len() != len(want) {
		t.Errorf("bytes %d (want %d), %d blobs", tree.Bytes, bytesWant, m.Len())
	}
}

func TestReadZipStrip(t *testing.T) {
	gh := makeZip(t, zent{name: "acme-billing-abc1234/composer.json", body: "{}"}, zent{name: "acme-billing-abc1234/src/A.php", body: "<?php"})
	if tree, _ := mustZip(t, gh, StripSingle); tree.Root != "acme-billing-abc1234/" || !slices.Equal(paths(tree), []string{"composer.json", "src/A.php"}) {
		t.Errorf("single: root %q paths %v", tree.Root, paths(tree))
	}
	if tree, _ := mustZip(t, gh, StripFolder("other")); tree.Root != "" || len(tree.Files) != 2 || tree.Files[0].Path != "acme-billing-abc1234/composer.json" {
		t.Errorf("other name: root %q paths %v", tree.Root, paths(tree))
	}
	if tree, _ := mustZip(t, gh, StripRule{}); tree.Root != "" {
		t.Errorf("no strip: root %q", tree.Root)
	}
	two := makeZip(t, zent{name: "a/x.php", body: "1"}, zent{name: "b/y.php", body: "2"})
	if tree, _ := mustZip(t, two, StripSingle); tree.Root != "" || !slices.Equal(paths(tree), []string{"a/x.php", "b/y.php"}) {
		t.Errorf("two tops: root %q paths %v", tree.Root, paths(tree))
	}
	flat := makeZip(t, zent{name: "a/x.php", body: "1"}, zent{name: "top.php", body: "2"})
	if tree, _ := mustZip(t, flat, StripSingle); tree.Root != "" {
		t.Errorf("file at top: root %q", tree.Root)
	}
	// A refused entry does not count as a second top folder.
	bad := makeZip(t, zent{name: "p/x.php", body: "1"}, zent{name: "../evil.php", body: "2"})
	if tree, _ := mustZip(t, bad, StripSingle); tree.Root != "p/" {
		t.Errorf("with a refused entry: root %q", tree.Root)
	}
}

func TestReadZipPathEscapes(t *testing.T) {
	data := makeZip(t,
		zent{name: "plugin/ok.php", body: "<?php"},
		zent{name: "../evil.php", body: "evil"},
		zent{name: "/abs.php", body: "abs"},
		zent{name: `plugin\..\..\win.php`, body: "win"},
		zent{name: `C:\x.php`, body: "drive"},
		zent{name: `\\host\share\x`, body: "unc"},
		zent{name: "plugin/../../x.php", body: "x"},
		zent{name: "evil\x00.php", body: "nul"},
		zent{name: `plugin\inc\loader.php`, body: "<?php // backslashes"},
	)
	tree, m := mustZip(t, data, StripSingle)
	for _, p := range []string{"../evil.php", "/abs.php", `plugin\..\..\win.php`, `C:\x.php`, `\\host\share\x`, "plugin/../../x.php"} {
		if !hasIssue(tree, core.IssuePathEscape, p) {
			t.Errorf("no path-escape for %q in %v", p, issues(tree))
		}
	}
	if !hasIssue(tree, core.IssueMalformed, "evil\x00.php") {
		t.Errorf("no malformed issue for NUL name: %v", issues(tree))
	}
	if !slices.Equal(paths(tree), []string{"inc/loader.php", "ok.php"}) || m.Len() != 2 {
		t.Errorf("stored %v (%d blobs)", paths(tree), m.Len())
	}
}

func TestReadZipLinks(t *testing.T) {
	data := makeZip(t,
		zent{name: "p/ok.php", body: "<?php"},
		zent{name: "p/passwd", body: "/etc/passwd", mode: fs.ModeSymlink | 0o777},
		zent{name: "p/up", body: "../../home/user/.ssh/id_rsa", mode: fs.ModeSymlink | 0o777},
		zent{name: "p/inside", body: "ok.php", mode: fs.ModeSymlink | 0o777},
		zent{name: "p/dev", mode: fs.ModeDevice | fs.ModeCharDevice | 0o644},
		zent{name: "p/fifo", mode: fs.ModeNamedPipe | 0o644},
	)
	tree, m := mustZip(t, data, StripSingle)
	for p, kind := range map[string]core.ArchiveIssueKind{
		"p/passwd": core.IssueLinkEscape, "p/up": core.IssueLinkEscape, "p/inside": core.IssueLink,
		"p/dev": core.IssueLink, "p/fifo": core.IssueLink,
	} {
		if !hasIssue(tree, kind, p) {
			t.Errorf("no %s for %s in %v", kind, p, issues(tree))
		}
	}
	f, _ := tree.Lookup("passwd")
	if f.Link != "/etc/passwd" || f.Mode&fs.ModeSymlink == 0 || f.SHA256 != [32]byte{} || f.Size != 0 {
		t.Errorf("link entry %+v", f)
	}
	if f, _ := tree.Lookup("fifo"); f.Mode&fs.ModeNamedPipe == 0 {
		t.Errorf("fifo mode %v", f.Mode)
	}
	// Only ok.php has a blob: no link target or device was stored.
	if m.Len() != 1 {
		t.Errorf("%d blobs, want 1", m.Len())
	}
	for _, i := range tree.Issues {
		if i.Path == "p/fifo" && i.Detail != "named pipe" || i.Path == "p/dev" && i.Detail != "character device" {
			t.Errorf("issue %+v", i)
		}
	}
}

func TestEscapes(t *testing.T) {
	for _, tc := range []struct {
		name, target string
		want         bool
	}{
		{"p/a", "/etc/passwd", true},
		{"p/a", `C:\Windows`, true},
		{"p/a", "../../x", true},
		{"p/a", "../other/x", true},
		{"p/a", `..\..\x`, true},
		{"p/a", "b.php", false},
		{"p/sub/a", "../b.php", false},
		{"p/a", ".", false},
		{"a", "b", false},
		{"a", "../b", true},
		{"p/a", "", false},
	} {
		if got := escapes(tc.name, tc.target); got != tc.want {
			t.Errorf("escapes(%q, %q) = %v", tc.name, tc.target, got)
		}
	}
}

func TestReadZipCollisions(t *testing.T) {
	data := makeZip(t,
		zent{name: "p/x.php", body: "first"},
		zent{name: "p/x.php", body: "second"},
		zent{name: "p/Foo.php", body: "upper"},
		zent{name: "p/foo.php", body: "lower"},
		zent{name: "p/caf\u00e9.php", body: "nfc"},
		zent{name: "p/cafe\u0301.php", body: "nfd"},
		zent{name: "p/x.php#2", body: "a real file with that name"},
	)
	tree, _ := mustZip(t, data, StripSingle)
	got := map[string]string{}
	for _, p := range paths(tree) {
		got[p] = content(t, tree, p)
	}
	want := map[string]string{
		"x.php": "first", "x.php#2": "second", "x.php#2#2": "a real file with that name",
		"Foo.php": "upper", "foo.php": "lower", "caf\u00e9.php": "nfc", "caf\u00e9.php#2": "nfd",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("kept %v\nwant %v", got, want)
	}
	for _, p := range []string{"p/x.php", "p/foo.php", "p/cafe\u0301.php", "p/x.php#2"} {
		if !hasIssue(tree, core.IssueCollision, p) {
			t.Errorf("no collision for %q in %v", p, issues(tree))
		}
	}
}

func TestReadZipNested(t *testing.T) {
	inner := makeZip(t, zent{name: "deep/evil.php", body: "<?php eval($_GET['x']);"})
	data := makeZip(t, zent{name: "p/inner.zip", body: string(inner), method: zip.Store}, zent{name: "p/a.php", body: "<?php"})
	tree, _ := mustZip(t, data, StripSingle)
	if !slices.Equal(paths(tree), []string{"a.php", "inner.zip"}) {
		t.Errorf("paths %v: the nested zip was opened", paths(tree))
	}
	if f, _ := tree.Lookup("inner.zip"); f.Kind != core.KindArchive || f.Size != int64(len(inner)) {
		t.Errorf("nested entry %+v", f)
	}
}

func TestReadZipEncrypted(t *testing.T) {
	data := makeZip(t, zent{name: "p/secret.php", body: "garbled", method: zip.Store, flags: 0x1}, zent{name: "p/a.php", body: "<?php"})
	tree, m := mustZip(t, data, StripSingle)
	if !hasIssue(tree, core.IssueEncrypted, "p/secret.php") || m.Len() != 1 {
		t.Errorf("issues %v, %d blobs", issues(tree), m.Len())
	}
}

// TestReadZipLyingHeader: a header that understates the size is caught
// on the bytes read, not trusted.
func TestReadZipLyingHeader(t *testing.T) {
	body := bytes.Repeat([]byte("A"), 1<<20)
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	fw, err := w.CreateRaw(&zip.FileHeader{
		Name: "p/big.php", Method: zip.Store, CRC32: crc32.ChecksumIEEE(body),
		CompressedSize64: uint64(len(body)), UncompressedSize64: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _ = fw.Write(body)
	fw, _ = w.Create("p/ok.php")
	_, _ = io.WriteString(fw, "<?php")
	_ = w.Close()
	tree, m := mustZip(t, buf.Bytes(), StripSingle)
	if !hasIssue(tree, core.IssueMalformed, "p/big.php") || m.Len() != 1 {
		t.Errorf("issues %v, %d blobs", issues(tree), m.Len())
	}
}

func TestReadZipLocalHeaderMismatch(t *testing.T) {
	data := makeZip(t, zent{name: "p/a.php", body: "<?php"})
	// The local header comes first; rename the entry there only.
	i := bytes.Index(data, []byte("p/a.php"))
	copy(data[i:], "p/b.php")
	tree, _ := mustZip(t, data, StripSingle)
	if !hasIssue(tree, core.IssueMalformed, "p/a.php") {
		t.Fatalf("issues %v", issues(tree))
	}
	if tree.Issues[0].Other != "p/b.php" {
		t.Errorf("other %q", tree.Issues[0].Other)
	}
}

// diskTree reads data into a Disk store under a fresh root and checks
// that nothing outside the blob folder appeared and memory stayed
// within maxAlloc.
func diskTree(t *testing.T, data []byte, lim core.Limits, maxAlloc uint64) (*core.Tree, error) {
	t.Helper()
	root := t.TempDir()
	d, err := blob.OpenDisk(filepath.Join(root, "cache"))
	if err != nil {
		t.Fatal(err)
	}
	before := walk(t, root)
	runtime.GC()
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	tree, err := ReadZip(context.Background(), bytes.NewReader(data), int64(len(data)), d, lim, StripSingle)
	runtime.ReadMemStats(&m1)
	if alloc := m1.TotalAlloc - m0.TotalAlloc; alloc > maxAlloc {
		t.Errorf("allocated %d MiB, cap %d MiB", alloc>>20, maxAlloc>>20)
	}
	for _, p := range walk(t, root) {
		if !slices.Contains(before, p) && !strings.HasPrefix(p, "cache/blobs/") {
			t.Errorf("wrote %s outside the blob folder", p)
		}
	}
	return tree, err
}

func walk(t *testing.T, root string) []string {
	t.Helper()
	var out []string
	_ = filepath.WalkDir(root, func(p string, _ fs.DirEntry, err error) error {
		if err == nil {
			r, _ := filepath.Rel(root, p)
			out = append(out, filepath.ToSlash(r))
		}
		return nil
	})
	return out
}

// TestReadZipDeflateBomb: 1,010:1 deflate stops at the ratio and keeps
// memory low (e04).
func TestReadZipDeflateBomb(t *testing.T) {
	bomb := strings.Repeat("\x00", 10<<20)
	data := makeZip(t, zent{name: "p/a.php", body: "<?php"}, zent{name: "p/bomb.bin", body: bomb}, zent{name: "p/z.php", body: "<?php"})
	if r := len(bomb) / len(data); r < 500 {
		t.Fatalf("fixture ratio %d:1 is no bomb", r)
	}
	tree, err := diskTree(t, data, core.DefaultLimits(), 32<<20)
	if err != nil {
		t.Fatal(err)
	}
	if !hasIssue(tree, core.IssueLimit, "p/bomb.bin") {
		t.Errorf("issues %v", issues(tree))
	}
	if _, ok := tree.Lookup("bomb.bin"); ok {
		t.Error("bomb stored")
	}
	if _, ok := tree.Lookup("z.php"); ok {
		t.Error("read on past the bomb")
	}
}

func TestReadZipTotalCap(t *testing.T) {
	t.Setenv("RHYTHM_INVOKED_AS", "rhythm sightread")
	body := strings.Repeat("abcdefgh", 64<<10) // 512 KiB each, low ratio
	data := makeZip(t, zent{name: "p/1.txt", body: body, method: zip.Store}, zent{name: "p/2.txt", body: body, method: zip.Store}, zent{name: "p/3.txt", body: body, method: zip.Store})
	lim := core.DefaultLimits()
	lim.Uncompressed = 1 << 20
	_, err := diskTree(t, data, lim, 32<<20)
	if !errors.Is(err, core.ErrTooLarge) || core.CodeOf(err) != core.ETooLarge {
		t.Fatalf("err %v, want E11", err)
	}
	err = fetch.Package{Command: "plugin", Name: "big", Version: "1.0", Archive: "zip"}.Wrap(err)
	want := "rhythm sightread plugin: the 1.0 archive of big unpacks to over 1 MiB\n" +
		"  raise --max-size if you expect that; a size jump this big is worth a look on its own"
	if err.Error() != want {
		t.Errorf("err\n%s\nwant\n%s", err, want)
	}
}

func TestReadZipEntryCap(t *testing.T) {
	data := makeZip(t, zent{name: "p/small.php", body: "<?php"}, zent{name: "p/big.txt", body: strings.Repeat("x", 2048), method: zip.Store})
	lim := core.DefaultLimits()
	lim.EntryStored = 1024
	tree, m, err := readZip(t, data, lim, StripSingle)
	if err != nil {
		t.Fatal(err)
	}
	if !hasIssue(tree, core.IssueLimit, "p/big.txt") || !slices.Equal(paths(tree), []string{"small.php"}) || m.Len() != 1 {
		t.Errorf("issues %v paths %v", issues(tree), paths(tree))
	}
}

// TestReadZipManyEntries: 100,001 empty entries stop at the entry cap;
// the writer needs zip64 records for that many, so this reads zip64 too.
func TestReadZipManyEntries(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a 100,001-entry zip")
	}
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for i := range 100001 {
		if _, err := w.CreateHeader(&zip.FileHeader{Name: fmt.Sprintf("p/%06d", i), Method: zip.Store}); err != nil {
			t.Fatal(err)
		}
	}
	_ = w.Close()
	data := buf.Bytes()
	if !bytes.Contains(data, []byte("PK\x06\x06")) {
		t.Fatal("fixture has no zip64 end record")
	}
	tree, _, err := readZip(t, data, core.DefaultLimits(), StripSingle)
	if err != nil {
		t.Fatal(err)
	}
	if len(tree.Files) != 100000 || !hasIssue(tree, core.IssueLimit, "") {
		t.Errorf("%d files, issues %v", len(tree.Files), tree.Issues[len(tree.Issues)-1:])
	}
}

func TestReadZipCancel(t *testing.T) {
	data := makeZip(t, zent{name: "p/a.php", body: "<?php"})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ReadZip(ctx, bytes.NewReader(data), int64(len(data)), blob.Memory(), core.DefaultLimits(), StripSingle); !errors.Is(err, context.Canceled) {
		t.Errorf("err %v", err)
	}
}

func TestReadZipNotZip(t *testing.T) {
	data := []byte("this is not a zip")
	if _, _, err := readZip(t, data, core.DefaultLimits(), StripSingle); err == nil {
		t.Error("text read as a zip")
	}
}

func TestKindOf(t *testing.T) {
	for name, want := range map[string]core.FileKind{
		"a.PHP": core.KindPHP, "x.inc": core.KindPHP, "t.phtml": core.KindPHP,
		"a.ts": core.KindJS, "a.cjs": core.KindJS, "dist/app.min.js": core.KindMinified,
		"composer.json": core.KindJSON, "style.css": core.KindText, ".htaccess": core.KindText,
		"README": core.KindText, "font.woff2": core.KindAsset, "lang/de.mo": core.KindAsset,
		"pkg.tgz": core.KindArchive, "blob.dat": core.KindBinary, "noext": core.KindBinary,
	} {
		if got := KindOf(name); got != want {
			t.Errorf("KindOf(%q) = %s, want %s", name, got, want)
		}
	}
}

func TestReadLocal(t *testing.T) {
	t.Setenv("RHYTHM_INVOKED_AS", "rhythm sightread")
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "premium-plugin.zip")
	data := makeZip(t, zent{name: "premium-plugin/premium.php", body: "<?php"})
	if err := os.WriteFile(zipPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	tree, err := core.ReadLocalArchive(context.Background(), zipPath, blob.Memory(), core.DefaultLimits())
	if err != nil {
		t.Fatal(err)
	}
	if tree.Root != "premium-plugin/" || !slices.Equal(paths(tree), []string{"premium.php"}) || tree.SHA256 != sha256.Sum256(data) {
		t.Errorf("root %q paths %v", tree.Root, paths(tree))
	}

	// The format comes from the bytes, not the name.
	renamed := filepath.Join(dir, "plugin.bin")
	_ = os.WriteFile(renamed, data, 0o600)
	if _, err := ReadLocal(context.Background(), renamed, blob.Memory(), core.DefaultLimits()); err != nil {
		t.Errorf("zip without .zip: %v", err)
	}

	tgz := filepath.Join(dir, "pkg.tgz")
	tgzData := makeTgz(t, tent{name: "package/index.js", body: "1"})
	_ = os.WriteFile(tgz, tgzData, 0o600)
	tree, err = ReadLocal(context.Background(), tgz, blob.Memory(), core.DefaultLimits())
	if err != nil || tree.Root != "package/" || !slices.Equal(paths(tree), []string{"index.js"}) || tree.SHA256 != sha256.Sum256(tgzData) {
		t.Errorf("tgz: %v", err)
	}
	// A tgz a limit stops early still carries the file's hash.
	lim0 := core.DefaultLimits()
	lim0.Entries = 1
	two := filepath.Join(dir, "two.tgz")
	twoData := makeTgz(t, tent{name: "package/a.js", body: "1"}, tent{name: "package/b.js", body: "2"})
	_ = os.WriteFile(two, twoData, 0o600)
	if tree, err := ReadLocal(context.Background(), two, blob.Memory(), lim0); err != nil || tree.SHA256 != sha256.Sum256(twoData) || !hasIssue(tree, core.IssueLimit, "") {
		t.Errorf("stopped tgz: %v", err)
	}

	text := filepath.Join(dir, "notes.zip")
	_ = os.WriteFile(text, []byte("just some notes\n"), 0o600)
	_, err = ReadLocal(context.Background(), text, blob.Memory(), core.DefaultLimits())
	want := "rhythm sightread: " + text + " is not a zip or tgz archive\n  give the plugin, theme or package archive itself (.zip, .tgz or .tar.gz)"
	if err == nil || err.Error() != want || core.CodeOf(err) != core.EBadConfig {
		t.Errorf("text file\n%v\nwant\n%s", err, want)
	}
	if _, err := ReadLocal(context.Background(), dir, blob.Memory(), core.DefaultLimits()); core.CodeOf(err) != core.EBadConfig {
		t.Errorf("folder: %v", err)
	}
	lim := core.DefaultLimits()
	lim.Download = 16
	_, err = ReadLocal(context.Background(), zipPath, blob.Memory(), lim)
	if !errors.Is(err, core.ErrTooLarge) || !strings.Contains(err.Error(), "premium-plugin.zip is over 16 bytes") {
		t.Errorf("over --max-size: %v", err)
	}
	if _, err := ReadLocal(context.Background(), filepath.Join(dir, "missing.zip"), blob.Memory(), lim); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("missing file: %v", err)
	}
}

// copySuffix is the #2 (or #2#2) of a kept duplicate.
var copySuffix = regexp.MustCompile(`(#[0-9]+)+$`)

func FuzzZipIndex(f *testing.F) {
	f.Add(makeZip(f, zent{name: "p/a.php", body: "<?php"}, zent{name: "p/b/", mode: fs.ModeDir | 0o755}))
	f.Add(makeZip(f, zent{name: "../evil.php", body: "x"}, zent{name: "p/l", body: "/etc/passwd", mode: fs.ModeSymlink | 0o777}))
	f.Add(makeZip(f, zent{name: "p/x.php", body: "1"}, zent{name: "p/X.php", body: "2"}, zent{name: "p/x.php", body: "3"}))
	f.Add(makeZip(f, zent{name: "p/z", body: strings.Repeat("\x00", 1<<16)}))
	f.Add([]byte("PK\x05\x06" + strings.Repeat("\x00", 18)))
	lim := core.DefaultLimits()
	lim.Uncompressed, lim.EntryStored, lim.Entries = 1<<20, 256<<10, 64
	f.Fuzz(func(t *testing.T, data []byte) {
		m := blob.Memory()
		tree, err := ReadZip(context.Background(), bytes.NewReader(data), int64(len(data)), m, lim, StripSingle)
		if err != nil {
			return
		}
		if tree.Bytes > lim.Uncompressed || len(tree.Files) > lim.Entries {
			t.Fatalf("%d bytes, %d files past the limits", tree.Bytes, len(tree.Files))
		}
		for _, file := range tree.Files {
			// Drop the #n of a disambiguated duplicate.
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

// TestReadZipTricksOnDisk runs every trick fixture into a Disk store:
// each stays under the memory cap and writes nothing outside the blob
// folder (SR-6, e05).
func TestReadZipTricksOnDisk(t *testing.T) {
	inner := makeZip(t, zent{name: "deep/evil.php", body: "<?php"})
	fixtures := map[string][]byte{
		"plugin":    makeZip(t, zent{name: "p/a.php", body: "<?php"}, zent{name: "p/js/a.js", body: "x"}),
		"escape":    makeZip(t, zent{name: "../evil.php", body: "x"}, zent{name: "/abs.php", body: "x"}, zent{name: `..\win.php`, body: "x"}),
		"links":     makeZip(t, zent{name: "p/l", body: "/etc/passwd", mode: fs.ModeSymlink | 0o777}, zent{name: "p/d", mode: fs.ModeDevice | 0o644}),
		"collision": makeZip(t, zent{name: "p/x.php", body: "1"}, zent{name: "p/x.php", body: "2"}, zent{name: "p/X.php", body: "3"}),
		"nested":    makeZip(t, zent{name: "p/inner.zip", body: string(inner)}),
		"encrypted": makeZip(t, zent{name: "p/s.php", body: "x", method: zip.Store, flags: 1}),
	}
	for name, data := range fixtures {
		t.Run(name, func(t *testing.T) {
			if _, err := diskTree(t, data, core.DefaultLimits(), 16<<20); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestReadZipManyEntriesMemory(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a 100,001-entry zip")
	}
	var buf bytes.Buffer
	w := zip.NewWriter(&buf)
	for i := range 100001 {
		_, _ = w.CreateHeader(&zip.FileHeader{Name: fmt.Sprintf("p/%06d", i), Method: zip.Store})
	}
	_ = w.Close()
	runtime.GC()
	var m0, m1 runtime.MemStats
	runtime.ReadMemStats(&m0)
	if _, _, err := readZip(t, buf.Bytes(), core.DefaultLimits(), StripSingle); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&m1)
	// The tree keeps paths and hashes only: well under the 512 MB RSS
	// target of PRD 17 for 100,000 entries.
	if alloc := m1.TotalAlloc - m0.TotalAlloc; alloc > 256<<20 {
		t.Errorf("allocated %d MiB", alloc>>20)
	}
}
