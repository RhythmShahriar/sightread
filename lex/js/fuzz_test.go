// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package js

import (
	"flag"
	"strings"
	"testing"
	"time"
)

func fuzzing() bool {
	f := flag.Lookup("test.fuzz")
	return f != nil && f.Value.String() != ""
}

// linearBudget is how long lexing 1 MiB may take. That is about 20 ms
// on an idle machine, so the budget leaves room for a loaded CI runner
// and still fails at once on quadratic behaviour, which would take
// hours at this size.
const linearBudget = 5 * time.Second * raceSlowdown

func checkLinear(t *testing.T, src string) {
	t.Helper()
	if src == "" {
		return
	}
	big := strings.Repeat(src, (1<<20)/len(src)+1)
	start := time.Now()
	toks := Lex([]byte(big))
	if d := time.Since(start); d > linearBudget {
		t.Fatalf("lexing 1 MiB of %q took %v, budget %v", clip(src), d, linearBudget)
	}
	checkTokens(t, big, toks)
}

func FuzzJSLex(f *testing.F) {
	for _, s := range []string{
		"", "a / b / c", "return /x[/]/g", "`a${`b${c}`}d`", "`open ${", "/* open", "'open\nnext",
		"#!/usr/bin/env node\nx", `eval(1)`, "<p>{a}</p>", "x = {a:1} / 2", "0x1fn 1_0.5e+3",
		"(/[(/[(/[", "}`", "${}", "a?.b?.5:c",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, src []byte) {
		start := time.Now()
		toks := Lex(src)
		if d := time.Since(start); d > linearBudget {
			t.Fatalf("lexing %d bytes took %v", len(src), d)
		}
		checkTokens(t, string(src), toks)
		for _, tk := range toks {
			_, _ = StringValue(tk)
			_, _ = TemplateText(tk)
			_ = IdentName(tk)
			_ = tk.Construct()
		}
		if !fuzzing() {
			checkLinear(t, string(src))
		}
	})
}

func TestLexLinearTime(t *testing.T) {
	for _, s := range []string{"(/[", "`${", "`${`${", "'", "/*", "{", "}", "x/", "a=/", `\u`, "#"} {
		checkLinear(t, s)
	}
}
