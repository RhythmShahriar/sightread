// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package diff

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

// numbered returns n lines "<prefix> <i>".
func numbered(prefix string, n int) string {
	var b strings.Builder
	for i := range n {
		fmt.Fprintf(&b, "%s %d\n", prefix, i)
	}
	return b.String()
}

// run diffs two fixture trees.
func run(t *testing.T, old, new map[string]string) *core.Diff {
	t.Helper()
	d, err := Differ{}.Diff(context.Background(), coretest.Tree(old), coretest.Tree(new))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// summary is "kind old->new" per change, for comparing results.
func summary(d *core.Diff) []string {
	var out []string
	for _, c := range d.Changes {
		var o, n string
		if c.Old != nil {
			o = c.Old.Path
		}
		if c.New != nil {
			n = c.New.Path
		}
		s := c.Kind.String() + " " + o + "->" + n
		if c.EOLOnly {
			s += " eol"
		}
		out = append(out, s)
	}
	return out
}

func TestDiffTable(t *testing.T) {
	body := numbered("line", 30)
	edited := strings.Replace(strings.Replace(body, "line 3\n", "line three\n", 1), "line 20\n", "line twenty\n", 1)
	tests := []struct {
		name     string
		old, new map[string]string
		want     []string
		stats    core.DiffStats
	}{
		{
			name: "unchanged",
			old:  map[string]string{"a.php": body},
			new:  map[string]string{"a.php": body},
		},
		{
			name:  "added, removed and modified",
			old:   map[string]string{"a.php": "x\ny\n", "gone.txt": "1\n2\n3\n"},
			new:   map[string]string{"a.php": "x\nz\n", "new.js": "a\nb\n"},
			want:  []string{"modified a.php->a.php", "removed gone.txt->", "added ->new.js"},
			stats: core.DiffStats{FilesChanged: 1, FilesAdded: 1, FilesRemoved: 1, LinesAdded: 3, LinesRemoved: 4},
		},
		{
			name:  "rename by hash",
			old:   map[string]string{"old/a.php": body},
			new:   map[string]string{"new/a.php": body},
			want:  []string{"renamed old/a.php->new/a.php"},
			stats: core.DiffStats{FilesChanged: 1},
		},
		{
			name:  "rename by similarity",
			old:   map[string]string{"inc/a.php": body},
			new:   map[string]string{"src/a.php": edited},
			want:  []string{"renamed inc/a.php->src/a.php"},
			stats: core.DiffStats{FilesChanged: 1, LinesAdded: 2, LinesRemoved: 2},
		},
		{
			name: "dissimilar files are not a rename",
			old:  map[string]string{"inc/a.php": body},
			new:  map[string]string{"src/b.php": numbered("other", 30)},
			want: []string{"removed inc/a.php->", "added ->src/b.php"},
			stats: core.DiffStats{FilesAdded: 1, FilesRemoved: 1,
				LinesAdded: 30, LinesRemoved: 30},
		},
		{
			name: "similar files of another kind are not a rename",
			old:  map[string]string{"inc/a.php": body},
			new:  map[string]string{"src/a.txt": edited},
			want: []string{"removed inc/a.php->", "added ->src/a.txt"},
			stats: core.DiffStats{FilesAdded: 1, FilesRemoved: 1,
				LinesAdded: 30, LinesRemoved: 30},
		},
		{
			name:  "line endings only",
			old:   map[string]string{"a.php": "<?php\necho 1;\n"},
			new:   map[string]string{"a.php": "<?php\r\necho 1;\r\n"},
			want:  []string{"modified a.php->a.php eol"},
			stats: core.DiffStats{FilesChanged: 1},
		},
		{
			name:  "line endings and content",
			old:   map[string]string{"a.php": "<?php\necho 1;\n"},
			new:   map[string]string{"a.php": "<?php\r\necho 2;\r\n"},
			want:  []string{"modified a.php->a.php"},
			stats: core.DiffStats{FilesChanged: 1, LinesAdded: 2, LinesRemoved: 2},
		},
		{
			name:  "binary counts no lines",
			old:   map[string]string{"img.bin": "\x00\x01\n"},
			new:   map[string]string{"img.bin": "\x00\x02\n\n"},
			want:  []string{"modified img.bin->img.bin"},
			stats: core.DiffStats{FilesChanged: 1},
		},
		{
			name:  "two copies renamed by hash pair in path order",
			old:   map[string]string{"a1.txt": "same\n", "a2.txt": "same\n"},
			new:   map[string]string{"b1.txt": "same\n", "b2.txt": "same\n"},
			want:  []string{"renamed a1.txt->b1.txt", "renamed a2.txt->b2.txt"},
			stats: core.DiffStats{FilesChanged: 2},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := run(t, tt.old, tt.new)
			if got := summary(d); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("changes = %q, want %q", got, tt.want)
			}
			st := d.Stats
			st.BytesFrom, st.BytesTo = 0, 0
			if st != tt.stats {
				t.Errorf("stats = %+v, want %+v", st, tt.stats)
			}
			if d.Stats.BytesFrom != d.Old.Bytes || d.Stats.BytesTo != d.New.Bytes {
				t.Errorf("bytes = %d to %d, want the tree totals", d.Stats.BytesFrom, d.Stats.BytesTo)
			}
		})
	}
}

func TestRenameSimilarity(t *testing.T) {
	body := numbered("line", 30)
	d := run(t, map[string]string{"a.php": body}, map[string]string{"b.php": body + "extra\n"})
	if len(d.Changes) != 1 || d.Changes[0].Similarity < minSimilarity || d.Changes[0].Similarity >= 1 {
		t.Fatalf("changes = %+v, want one rename under 1", d.Changes)
	}
	d = run(t, map[string]string{"a.php": body}, map[string]string{"b.php": body})
	if d.Changes[0].Similarity != 1 {
		t.Errorf("rename by hash similarity = %v, want 1", d.Changes[0].Similarity)
	}
}

func TestRenameBestPairWins(t *testing.T) {
	body := numbered("line", 40)
	close1 := strings.Replace(body, "line 5\n", "line five\n", 1)
	close2 := strings.Replace(strings.Replace(strings.Replace(body, "line 5\n", "x\n", 1), "line 6\n", "y\n", 1), "line 7\n", "z\n", 1)
	d := run(t,
		map[string]string{"old.php": body},
		map[string]string{"far.php": close2, "near.php": close1})
	want := []string{"added ->far.php", "renamed old.php->near.php"}
	if got := summary(d); !reflect.DeepEqual(got, want) {
		t.Errorf("changes = %q, want %q", got, want)
	}
}

func TestRenameSearchBounded(t *testing.T) {
	old, new := map[string]string{}, map[string]string{}
	for i := range maxRenameFiles + 1 {
		old[fmt.Sprintf("o/%d.txt", i)] = numbered(fmt.Sprint(i), 5)
		new[fmt.Sprintf("n/%d.txt", i)] = numbered(fmt.Sprint(i), 5) + "x\n"
	}
	d := run(t, old, new)
	if d.Stats.FilesAdded != maxRenameFiles+1 || d.Stats.FilesRemoved != maxRenameFiles+1 {
		t.Errorf("stats = %+v, want no similarity renames over the bound", d.Stats)
	}
}

func TestModeChanged(t *testing.T) {
	old := coretest.Tree(map[string]string{"bin/run.sh": "echo\n"})
	new := coretest.Tree(map[string]string{"bin/run.sh": "echo\n"})
	new.Files[0].Mode = 0o755
	d, err := Differ{}.Diff(context.Background(), old, new)
	if err != nil {
		t.Fatal(err)
	}
	if got := summary(d); !reflect.DeepEqual(got, []string{"mode-changed bin/run.sh->bin/run.sh"}) {
		t.Fatalf("changes = %q", got)
	}
	if h, err := (Differ{}).Hunks(context.Background(), d, "bin/run.sh", 3); err != nil || h != nil {
		t.Errorf("hunks = %v, %v; want none", h, err)
	}
}

func TestNilTrees(t *testing.T) {
	tree := coretest.Tree(map[string]string{"a.txt": "a\n"})
	d, err := Differ{}.Diff(context.Background(), nil, tree)
	if err != nil || !reflect.DeepEqual(summary(d), []string{"added ->a.txt"}) {
		t.Fatalf("nil old: %q, %v", summary(d), err)
	}
	d, err = Differ{}.Diff(context.Background(), tree, nil)
	if err != nil || !reflect.DeepEqual(summary(d), []string{"removed a.txt->"}) {
		t.Fatalf("nil new: %q, %v", summary(d), err)
	}
}

func TestNoBlobStoreCountsFilesOnly(t *testing.T) {
	old := coretest.Tree(map[string]string{"a.txt": "a\n"})
	new := coretest.Tree(map[string]string{"a.txt": "b\n"})
	old.Blobs, new.Blobs = nil, nil
	d, err := Differ{}.Diff(context.Background(), old, new)
	if err != nil {
		t.Fatal(err)
	}
	if d.Stats.FilesChanged != 1 || d.Stats.LinesAdded != 0 {
		t.Errorf("stats = %+v", d.Stats)
	}
}

// failing is a blob store whose every Open finds a corrupt blob.
type failing struct{ core.BlobStore }

func (failing) Open([32]byte) (io.ReadCloser, error) { return nil, core.ErrBlobCorrupt }

func TestCorruptBlobFails(t *testing.T) {
	old := coretest.Tree(map[string]string{"a.txt": "a\n"})
	new := coretest.Tree(map[string]string{"a.txt": "b\n"})
	new.Blobs = failing{new.Blobs}
	_, err := Differ{}.Diff(context.Background(), old, new)
	if !errors.Is(err, core.ErrBlobCorrupt) {
		t.Fatalf("err = %v, want ErrBlobCorrupt", err)
	}
}

func TestCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Differ{}.Diff(ctx, coretest.Tree(map[string]string{"a": "1"}), coretest.Tree(map[string]string{"a": "2"}))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want canceled", err)
	}
}

func TestDeterministicOrder(t *testing.T) {
	old, new := map[string]string{}, map[string]string{}
	r := rand.New(rand.NewPCG(1, 2))
	for i := range 300 {
		p := fmt.Sprintf("d%d/f%d.php", i%7, i)
		body := numbered(p, 10+i%5)
		switch r.IntN(5) {
		case 0: // removed
			old[p] = body
		case 1: // added
			new[p] = body
		case 2: // moved
			old[p] = body
			new["moved/"+p] = body
		case 3: // edited
			old[p] = body
			new[p] = body + "more\n"
		default:
			old[p], new[p] = body, body
		}
	}
	first := summary(run(t, old, new))
	for range 5 {
		if got := summary(run(t, old, new)); !reflect.DeepEqual(got, first) {
			t.Fatal("changes differ between runs")
		}
	}
	for i := 1; i < len(first); i++ {
		if key(first[i-1]) > key(first[i]) {
			t.Fatalf("not sorted: %q before %q", first[i-1], first[i])
		}
	}
}

// key is the sort path of a summary line: the new path, else the old.
func key(s string) string {
	_, paths, _ := strings.Cut(s, " ")
	paths, _, _ = strings.Cut(paths, " ")
	o, n, _ := strings.Cut(paths, "->")
	if n != "" {
		return n
	}
	return o
}

// diff10k returns two trees of 10,000 files where 10 differ.
func diff10k() (old, new *core.Tree) {
	o, n := map[string]string{}, map[string]string{}
	for i := range 10000 {
		p := fmt.Sprintf("src/%02d/file%05d.php", i%50, i)
		body := "<?php\n// " + p + "\nreturn " + fmt.Sprint(i) + ";\n"
		o[p] = body
		if i%1000 == 0 {
			body += "echo 1;\n"
		}
		n[p] = body
	}
	return coretest.Tree(o), coretest.Tree(n)
}

func TestDiff10kFast(t *testing.T) {
	old, new := diff10k()
	start := time.Now()
	d, err := Differ{}.Diff(context.Background(), old, new)
	took := time.Since(start)
	if err != nil {
		t.Fatal(err)
	}
	if d.Stats.FilesChanged != 10 || d.Stats.LinesAdded != 10 {
		t.Fatalf("stats = %+v", d.Stats)
	}
	limit := time.Second
	if raceOn {
		limit *= 10 // the race detector slows everything down
	}
	if took > limit {
		t.Errorf("diff of 10,000 files took %v, want under %v", took, limit)
	}
}

func BenchmarkDiff10k(b *testing.B) {
	old, new := diff10k()
	b.ResetTimer()
	for b.Loop() {
		if _, err := (Differ{}).Diff(context.Background(), old, new); err != nil {
			b.Fatal(err)
		}
	}
}
