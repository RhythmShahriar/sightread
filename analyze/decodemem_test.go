// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package analyze

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

// bombFiles is n small PHP files, each eval(gzuncompress(base64(...)))
// of about 900 KiB of PHP: a few KiB of source each. Dense payloads are
// statements that cost the most to analyse; the others are a call
// after a long comment, quick to analyse.
func bombFiles(n int, dense bool) map[string]string {
	var b strings.Builder
	if !dense {
		b.WriteString("/* " + strings.Repeat("padding ", 900<<7) + "*/ system($_GET['c']);\n")
	}
	for i := 0; b.Len() < 900<<10; i++ {
		fmt.Fprintf(&b, "$v%d = f%d($_GET['k%d'], 'x%d');\n", i, i%50, i, i)
	}
	call := "eval(gzuncompress(base64_decode('" + b64(zlibBytes([]byte(b.String()))) + "')));"
	files := map[string]string{}
	for i := range n {
		files[fmt.Sprintf("f%02d.php", i)] = "<?php\n" + call + "\n"
	}
	return files
}

// decodeLimited lists, in path order, the files cut by the package
// decode budget.
func decodeLimited(set *core.FeatureSet) []string {
	var out []string
	for _, u := range set.Unanalysed {
		if u.Reason == reasonDecodeLimit {
			out = append(out, u.Path)
		}
	}
	return out
}

// Positive: the package decodes at most maxPackageOut however many
// files hold payloads; the files over it are the last in path
// order, on every run.
func TestPackageDecodeBounded(t *testing.T) {
	const n = 32
	files := bombFiles(n, false)
	lim := core.DefaultLimits()
	lim.FileBudget = time.Minute // decoding is under test, not time
	set := analyzeAll(t, coretest.Tree(files), lim)
	limited := decodeLimited(set)
	decoded := n - len(limited)
	if max := maxPackageOut/(900<<10) + 1; decoded > max || decoded == 0 {
		t.Fatalf("%d files decoded, want 1 to %d", decoded, max)
	}
	for i, p := range limited {
		if want := fmt.Sprintf("f%02d.php", decoded+i); p != want {
			t.Fatalf("limited %q, want the last files in path order", limited)
		}
	}
	if len(set.ByKey["flow:request->exec"]) != decoded {
		t.Errorf("payload sinks %d, want one per decoded file\n%s", len(set.ByKey["flow:request->exec"]), dump(set))
	}
	want := dump(set)
	for range 3 {
		if got := dump(analyzeAll(t, coretest.Tree(files), lim)); got != want {
			t.Fatal("the decode budget made runs differ")
		}
	}
}

// Negative: a package whose payloads fit the budget decodes them all.
func TestPackageDecodeUnderBudget(t *testing.T) {
	lim := core.DefaultLimits()
	lim.FileBudget = time.Minute
	set := analyzeAll(t, coretest.Tree(bombFiles(4, false)), lim)
	if l := decodeLimited(set); len(l) != 0 {
		t.Errorf("limited %q under the budget", l)
	}
}

// Decoded payloads take turns on a memory budget of their own, so many
// small files holding large payloads stay near what a few cost.
func TestDecodedMemoryBound(t *testing.T) {
	if testing.Short() || raceSlowdown > 1 {
		t.Skip("decodes and analyses 16 MiB of payloads")
	}
	defer runtime.GOMAXPROCS(runtime.GOMAXPROCS(16))
	tree := coretest.Tree(bombFiles(64, true))
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	var peak atomic.Uint64
	ctx, cancel := context.WithCancel(context.Background())
	sampled := make(chan struct{})
	go func() {
		defer close(sampled)
		var m runtime.MemStats
		for ctx.Err() == nil {
			runtime.ReadMemStats(&m)
			peak.Store(max(peak.Load(), m.HeapInuse))
			time.Sleep(2 * time.Millisecond)
		}
	}()
	lim := core.DefaultLimits()
	lim.FileBudget = time.Minute
	analyzeAll(t, tree, lim)
	cancel()
	<-sampled
	used := peak.Load() - min(peak.Load(), base.HeapInuse)
	t.Logf("peak heap %d MiB", used>>20)
	if used > 1<<30 {
		t.Errorf("peak heap %d MiB, over 1024 MiB", used>>20)
	}
}
