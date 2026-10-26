// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package meta

import (
	"fmt"
	"strings"
	"testing"

	"github.com/RhythmShahriar/rhythm/kit/cli"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

// php returns a PHP file of n bytes.
func php(n int) string { return "<?php\n" + strings.Repeat("$a = 1;\n", (n-6)/8) }

func TestSizeJumpWording(t *testing.T) {
	s := subject(core.WPPlugin)
	s.OldTree = coretest.Tree(map[string]string{"a.php": php(40 << 10)})
	s.NewTree = coretest.Tree(map[string]string{"a.php": php(40 << 10), "b.php": php(150 << 10)})
	f := only(t, run(t, sizeDetector{}, s), SigSizeJump)
	if want := "code grew from 40 KB to 190 KB (+150 KB)"; f.Evidence.String() != want || f.Severity != cli.SeverityMedium {
		t.Errorf("finding = %s %q, want %q", f.Severity, f.Evidence, want)
	}
}

func TestSizeJumpHistory(t *testing.T) {
	s := subject(core.NPM)
	s.OldTree = coretest.Tree(map[string]string{"a.js": php(600 << 10)})
	s.NewTree = coretest.Tree(map[string]string{"a.js": php(600 << 10), "b.js": php(150 << 10)})
	s.New.History = []core.Release{{Size: 1000}, {Size: 1100}, {Size: 900}, {Size: 1000}}
	s.New.Archive.Size = 2000
	f := only(t, run(t, sizeDetector{}, s), SigSizeJump)
	if !strings.HasSuffix(f.Evidence.String(), "; 2 KB is over the usual size of the last 4 releases (median 1 KB)") {
		t.Errorf("evidence = %q", f.Evidence)
	}
	// The same growth inside the usual spread stays quiet.
	s.New.Archive.Size = 1150 // median 1000 plus 3 times the MAD of 50
	for _, f := range run(t, sizeDetector{}, s) {
		t.Errorf("fired inside the usual size: %q", f.Evidence)
	}
}

func TestMedianAndMAD(t *testing.T) {
	if m := median([]int64{5, 1, 3}); m != 3 {
		t.Errorf("median = %d", m)
	}
	if m := median([]int64{4, 1, 3, 2}); m != 2 {
		t.Errorf("median = %d", m)
	}
}

func TestBulkFindingWording(t *testing.T) {
	s := subject(core.NPM)
	s.OldTree = coretest.Tree(map[string]string{"index.js": "1\n"})
	s.NewTree = coretest.Tree(map[string]string{"index.js": "1\n", "lib/x.min.js": "!function(){}();\n", "lib/y.bin": "a\x00b"})
	f := only(t, run(t, sizeDetector{}, s), SigSizeJump)
	if want := "adds 2 minified or binary files to a package that had none: lib/x.min.js, lib/y.bin"; f.Evidence.String() != want || f.File != "lib/x.min.js" {
		t.Errorf("finding = %q @%s", f.Evidence, f.File)
	}
}

func TestFilesRemovedWording(t *testing.T) {
	s := subject(core.WPPlugin)
	s.OldTree = coretest.Tree(map[string]string{
		"a.php":           "<?php check_ajax_referer('x'); echo esc_html($y);\n",
		"up/.htaccess":    "Require all denied\n",
		"inc/index.php":   "<?php\n",
		"keep.php":        "<?php current_user_can('x');\n",
		"docs/notes.txt":  "wp_verify_nonce(",
		"inc/helpers.php": "<?php function a() {}\n",
	})
	s.NewTree = coretest.Tree(map[string]string{"keep.php": "<?php current_user_can('x');\n"})
	var got []string
	for _, f := range run(t, sizeDetector{}, s) {
		if f.ID == SigFilesRemoved {
			got = append(got, f.Evidence.String())
		}
	}
	want := []string{
		"removes a.php, which checked nonces and escaped output",
		"removes inc/index.php, which kept its folder from being listed",
		"removes up/.htaccess, which denied web access to its folder",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("evidence =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestFilesRemovedCapped(t *testing.T) {
	s := subject(core.WPPlugin)
	old := map[string]string{}
	for i := range 25 {
		old[fmt.Sprintf("f%02d.php", i)] = "<?php wp_verify_nonce($n, 'a');\n"
	}
	s.OldTree, s.NewTree = coretest.Tree(old), coretest.Tree(nil)
	fs := run(t, sizeDetector{}, s)
	if len(fs) != maxPerSignal {
		t.Fatalf("%d findings, want %d", len(fs), maxPerSignal)
	}
	if want := "removes f19.php, which checked nonces (and 5 more like it)"; fs[maxPerSignal-1].Evidence.String() != want {
		t.Errorf("last = %q, want %q", fs[maxPerSignal-1].Evidence, want)
	}
}
