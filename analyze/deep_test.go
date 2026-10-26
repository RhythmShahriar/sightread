// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package analyze

import (
	"slices"
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
	"github.com/RhythmShahriar/sightread/lex/php"
)

// deepFiles wraps a webshell call n levels deep in parentheses, nested
// calls, JS array brackets and PHP string interpolation.
func deepFiles(n, interp int) map[string]string {
	in := `${eval($_POST['x'])}`
	for range interp {
		in = `{$a["` + in + `"]}`
	}
	return map[string]string{
		"parens.php": "<?php $q = " + strings.Repeat("(", n) + "system($_GET['c'])" + strings.Repeat(")", n) + ";\n",
		"calls.php":  "<?php $q = " + strings.Repeat("f(", n) + "system($_GET['c'])" + strings.Repeat(")", n) + ";\n",
		"arrays.js":  "var q = " + strings.Repeat("[", n) + "require('child_process').exec(location.hash)" + strings.Repeat("]", n) + ";\n",
		"interp.php": "<?php $s = \"" + in + "\";\n",
	}
}

// Positive: code nested deeper than the walk follows is listed as
// unanalysed (fail closed, SR-30), never passed as clean. This covers
// the evaluator's depth bound and the lexer's interpolation bound.
func TestTooDeepUnanalysed(t *testing.T) {
	for name, files := range map[string]map[string]string{
		"walk":  deepFiles(130, 42),
		"lexer": {"interp.php": deepFiles(1, php.MaxDepth+4)["interp.php"]},
	} {
		t.Run(name, func(t *testing.T) {
			set := analyzeAll(t, coretest.Tree(files), core.DefaultLimits())
			for p := range files {
				if got := reasons(set, p); !slices.Equal(got, []string{reasonTooDeep}) {
					t.Errorf("%s reasons %q, want %q\n%s", p, got, reasonTooDeep, dump(set))
				}
			}
		})
	}
}

// Negative: the same calls at an ordinary depth are analysed in full
// and found.
func TestShallowNestingAnalysed(t *testing.T) {
	files := deepFiles(20, 4)
	set := analyzeAll(t, coretest.Tree(files), core.DefaultLimits())
	if len(set.Unanalysed) != 0 {
		t.Errorf("unanalysed %q", set.Unanalysed)
	}
	for _, key := range []string{"flow:request->exec", "call:child_process.exec"} {
		if len(set.ByKey[key]) == 0 {
			t.Errorf("missing %s\n%s", key, dump(set))
		}
	}
	found := false
	for _, f := range set.ByKey["flow:request->eval"] {
		found = found || f.Ev.Path == "interp.php"
	}
	if !found {
		t.Errorf("interpolated eval not found\n%s", dump(set))
	}
}
