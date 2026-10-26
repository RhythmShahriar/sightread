// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package php

import (
	"flag"
	"strings"
	"testing"
	"time"
)

// fuzzing reports whether the test binary runs under -fuzz, where each
// input must stay cheap.
func fuzzing() bool {
	f := flag.Lookup("test.fuzz")
	return f != nil && f.Value.String() != ""
}

// linearBudget is how long lexing 1 MiB may take. That is about 20 ms
// on an idle machine, so the budget leaves room for a loaded CI runner
// and still fails at once on quadratic behaviour, which would take
// hours at this size.
const linearBudget = 5 * time.Second * raceSlowdown

// repeatTo repeats s until it is at least n bytes.
func repeatTo(s string, n int) string {
	if s == "" {
		return ""
	}
	return strings.Repeat(s, n/len(s)+1)
}

func checkLinear(t *testing.T, src string) {
	t.Helper()
	big := repeatTo(src, 1<<20)
	start := time.Now()
	toks := Lex([]byte(big))
	if d := time.Since(start); d > linearBudget {
		t.Fatalf("lexing 1 MiB of %q took %v, budget %v", clip(src), d, linearBudget)
	}
	checkTokens(t, big, toks)
}

var phpSeeds = []string{
	"",
	"<?php echo 1;",
	"<?php $a = \"x {$b->c[\"d\"]} ${e} $f[0] $g->h\";",
	"<?php $s = <<<EOT\n  a $b {$c}\n  EOT;\n",
	"<?php $s = <<<'EOT'\nraw\nEOT;\n",
	"<?php $s = <<<EOT\nunterminated",
	"<?php /* open",
	"<?php #[A(\"]\")] function f(){}",
	"<b><?= $x ?></b><? y(); ?>",
	"<?php eval /* c */ (base64_decode($x)); ?>\n<html>",
	"<?php __halt_compiler();\x00\xff<?php",
	"<?php (int)$a . (string) $b <=> 0x1f;",
	"\"{$\"{$\"{$",
	"<?php `ls`; 'a\\'b'; \"\\\"\";",
	"<?php \"{$a[\"{$b[\"{$c}\"]}\"]}\";",
	"<?php \\Foo\\bar(); $$x; ${'y'};",
}

func FuzzPHPLex(f *testing.F) {
	for _, s := range phpSeeds {
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
			_ = Segments(tk)
			_ = tk.Construct()
		}
		if !fuzzing() {
			// Seed and regression inputs also run at 1 MiB, the
			// linear-time check; while fuzzing that would cost too much
			// per input.
			checkLinear(t, string(src))
		}
	})
}

func TestLexLinearTime(t *testing.T) {
	for _, s := range []string{
		`<?php "{$`, "<?php <<<A\n", "<?php <<<A\n$x {$y}", "/*", "<?php '", `<?php "$a[`, `<?php "$a->`,
		"<?php #[", "<?php ?>", "<?php {$", `<?php "${`, "<?", "<?php $$$$$$", "<?php ((((((", "<?php (int",
	} {
		checkLinear(t, s)
	}
}
