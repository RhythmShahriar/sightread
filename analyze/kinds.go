// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package analyze

import (
	"bytes"
	"path"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/lex/js"
	"github.com/RhythmShahriar/sightread/lex/php"
)

// What kind of file a path really is: minified bundles, Unicode tricks
// in code and code hidden in files that should hold none.

// The minified rule: an average line over minAvgLine bytes, or more
// than longShare of the bytes on lines over longLine bytes.
const (
	minAvgLine = 500
	longLine   = 1000
	longShare  = 0.9
)

// bundleMarkers are what a bundler leaves in its output: webpack's and
// esbuild's runtimes, rollup's helpers.
var bundleMarkers = [][]byte{
	[]byte("__webpack_require__"),
	[]byte("__webpack_modules__"),
	[]byte("webpackChunk"),
	[]byte("__esbuild"),
	[]byte("rollupPluginBabelHelpers"),
	[]byte("/*! rollup"),
}

// sourceMapMarks start a source map comment.
var sourceMapMarks = [][]byte{
	[]byte("//# sourceMappingURL="),
	[]byte("//@ sourceMappingURL="),
	[]byte("/*# sourceMappingURL="),
}

// minified reports whether a JavaScript or CSS file is minified or
// bundled: the archive already named it so (.min.js), its lines are long
// (an average over 500 bytes, or over 90% of its bytes on lines over
// 1,000), or it carries a source map comment or a bundler's runtime.
func minified(p string, kind core.FileKind, src []byte) bool {
	if kind == core.KindMinified {
		return true
	}
	switch strings.ToLower(path.Ext(p)) {
	case ".js", ".mjs", ".cjs", ".jsx", ".css":
	default:
		if kind != core.KindJS {
			return false
		}
	}
	if len(src) == 0 {
		return false
	}
	lines, long := 0, 0
	for rest := src; len(rest) > 0; {
		n := bytes.IndexByte(rest, '\n')
		if n < 0 {
			n = len(rest)
		}
		lines++
		if n > longLine {
			long += n
		}
		rest = rest[min(n+1, len(rest)):]
	}
	if len(src)/lines > minAvgLine || float64(long) > longShare*float64(len(src)) {
		return true
	}
	for _, m := range sourceMapMarks {
		if bytes.Contains(src, m) {
			return true
		}
	}
	for _, m := range bundleMarkers {
		if bytes.Contains(src, m) {
			return true
		}
	}
	return false
}

// The keys of FUnicode.
const (
	uniBidi      = "bidi"
	uniZeroWidth = "zero-width"
	uniHomoglyph = "homoglyph"
)

// Where in the code a Unicode trick sits, the "in" attribute.
const (
	inComment    = "comment"
	inString     = "string"
	inIdentifier = "identifier"
	inCode       = "code"
)

// isBidi reports the bidi controls of Trojan Source: the embeddings and
// overrides U+202A to U+202E and the isolates U+2066 to U+2069.
func isBidi(r rune) bool { return r >= 0x202a && r <= 0x202e || r >= 0x2066 && r <= 0x2069 }

// isZeroWidth reports zero-width space, non-joiner and joiner and the
// byte order mark (U+FEFF, a zero-width no-break space past offset 0).
func isZeroWidth(r rune) bool { return r >= 0x200b && r <= 0x200d || r == 0xfeff }

// rtlScripts are the scripts written right to left: text in them uses
// bidi controls for real.
var rtlScripts = []*unicode.RangeTable{unicode.Arabic, unicode.Hebrew, unicode.Syriac, unicode.Thaana, unicode.Nko}

func hasRTL(s string) bool {
	for _, r := range s {
		if r > 0x7f && unicode.In(r, rtlScripts...) {
			return true
		}
	}
	return false
}

// confusableGreek are the Greek letters that pass for Latin ones. Greek
// names such as π or Δ in maths code are left alone.
const confusableGreek = "\u0391\u0392\u0395\u0396\u0397\u0399\u039a\u039c\u039d\u039f\u03a1\u03a4\u03a5\u03a7\u03b1\u03b9\u03ba\u03bd\u03bf\u03c1\u03c5\u03c7"

// mixedScripts reports whether an identifier mixes Latin letters with
// Cyrillic ones (or with Greek letters that look Latin) and names the
// other script.
func mixedScripts(name string) (string, bool) {
	latin, other := false, ""
	for _, r := range name {
		switch {
		case r < 0x80:
			if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' {
				latin = true
			}
		case unicode.Is(unicode.Cyrillic, r):
			other = "cyrillic"
		case unicode.Is(unicode.Greek, r) && strings.ContainsRune(confusableGreek, r):
			if other == "" {
				other = "greek"
			}
		case unicode.Is(unicode.Latin, r):
			latin = true
		}
	}
	return other, latin && other != ""
}

// uniSpan is one token's text for the Unicode scan.
type uniSpan struct {
	off   int
	line  int
	text  string
	in    string
	ident string // the identifier's name, for the homoglyph check
}

// unicodeFeatures records FUnicode for bidi controls and zero-width
// characters in code tokens and for identifiers that mix scripts. PHP
// inline HTML is page text rather than code; it is skipped. Text in a right to
// left script (bidi), letters joined by a zero-width joiner or
// non-joiner (emoji, Indic and Persian words) and a string that is only
// a byte order mark (the idiom that strips one) are left alone.
func unicodeFeatures(col *collector, src []byte, ptoks []php.Token, jtoks []js.Token, isPHP bool) {
	if !hasHighByte(src) {
		return
	}
	var spans []uniSpan
	if isPHP {
		spans = phpSpans(ptoks, spans)
	} else {
		for _, t := range jtoks {
			if !hasHighByte([]byte(t.Text)) {
				continue
			}
			sp := uniSpan{off: t.Off, line: t.Line, text: t.Text, in: inCode}
			switch t.Kind {
			case js.Comment:
				sp.in = inComment
			case js.String, js.Template, js.RegExp:
				sp.in = inString
			case js.Identifier, js.Keyword:
				sp.in, sp.ident = inIdentifier, js.IdentName(t)
			}
			spans = append(spans, sp)
		}
	}
	for _, sp := range spans {
		unicodeSpan(col, sp)
	}
}

// phpSpans lists the PHP tokens with bytes over 0x7f, string parts one
// by one so a variable inside a string is checked as a name.
func phpSpans(toks []php.Token, out []uniSpan) []uniSpan {
	for _, t := range toks {
		if t.Kind == php.InlineHTML || !hasHighByte([]byte(t.Text)) {
			continue
		}
		if len(t.Parts) > 0 {
			out = phpSpans(t.Parts, out)
			continue
		}
		sp := uniSpan{off: t.Off, line: t.Line, text: t.Text, in: inCode}
		switch t.Kind {
		case php.Comment:
			sp.in = inComment
		case php.String:
			sp.in = inString
		case php.Identifier, php.Keyword:
			sp.in, sp.ident = inIdentifier, strings.TrimPrefix(t.Text, `\`)
		case php.Variable:
			sp.in, sp.ident = inIdentifier, strings.TrimLeft(t.Text, "$")
		}
		out = append(out, sp)
	}
	return out
}

func hasHighByte(b []byte) bool {
	for _, c := range b {
		if c >= 0x80 {
			return true
		}
	}
	return false
}

// unicodeSpan checks one token.
func unicodeSpan(col *collector, sp uniSpan) {
	text := sp.text
	rtl := -1 // unknown until a bidi control asks
	line := sp.line
	var prev rune
	for i, r := range text {
		if r == '\n' {
			line++
		}
		var key string
		switch {
		case isBidi(r):
			if sp.in == inString || sp.in == inComment {
				if rtl < 0 {
					rtl = 0
					if hasRTL(text) {
						rtl = 1
					}
				}
				if rtl == 1 {
					break
				}
			}
			key = uniBidi
		case isZeroWidth(r):
			if r == 0xfeff && sp.off+i == 0 {
				break // a byte order mark
			}
			if r == 0xfeff && sp.in == inString && bomOnly(text) {
				break
			}
			if r != 0xfeff && sp.in != inIdentifier && sp.in != inCode && joins(prev, text[i+utf8.RuneLen(r):]) {
				break
			}
			key = uniZeroWidth
		}
		if key != "" {
			col.addCtxAt(col.ctx, sp.off+i, core.FUnicode, key, line, line, "", map[string]string{
				"char": "U+" + strings.ToUpper(strconv.FormatInt(int64(r), 16)),
				"in":   sp.in,
			})
		}
		prev = r
	}
	if sp.ident != "" {
		if other, ok := mixedScripts(sp.ident); ok {
			col.addCtxAt(col.ctx, sp.off, core.FUnicode, uniHomoglyph, sp.line, sp.line, "", map[string]string{
				"name":    attrText(sp.ident),
				"scripts": "latin," + other,
				"in":      inIdentifier,
			})
		}
	}
}

// joins reports whether a zero-width joiner or non-joiner sits between
// two characters that use one: the characters on both sides are
// outside ASCII and neither is another control.
func joins(prev rune, rest string) bool {
	next, _ := utf8.DecodeRuneInString(rest)
	ok := func(r rune) bool { return r > 0x7f && r != utf8.RuneError && !isBidi(r) && !isZeroWidth(r) }
	return ok(prev) && ok(next)
}

// bomOnly reports whether a string literal holds nothing but a byte
// order mark, written raw in the source to strip one.
func bomOnly(lit string) bool {
	s := strings.Trim(lit, "'\"`")
	return s == "\ufeff"
}

// Code in assets.

// assetCodeExts are the text files that never hold code, so PHP or
// JavaScript in them is hidden code. Templates and markup (.html, .twig,
// .tpl) and documentation hold code for real and are not listed.
var assetCodeExts = map[string]bool{
	".txt": true, ".log": true, ".csv": true, ".tsv": true, ".css": true, ".scss": true, ".sass": true,
	".less": true, ".po": true, ".pot": true, ".map": true, ".ini": true, ".conf": true, ".lock": true,
	".dat": true, ".bin": true, ".db": true, ".data": true, ".cache": true, ".tmp": true, ".bak": true,
}

// imageExts are the image types whose magic bytes are known, for
// JavaScript hidden in or after an image.
var imageExts = map[string][]byte{
	".png":  []byte("\x89PNG\r\n\x1a\n"),
	".jpg":  {0xff, 0xd8, 0xff},
	".jpeg": {0xff, 0xd8, 0xff},
	".gif":  []byte("GIF8"),
	".ico":  {0, 0, 1, 0},
	".webp": []byte("RIFF"),
	".bmp":  []byte("BM"),
}

// assetChecked reports whether a file of kind at p is checked for code:
// every asset and binary file plus the text files of the types in
// assetCodeExts outside documentation (a readme.txt shows PHP samples).
func assetChecked(p string, kind core.FileKind) bool {
	switch kind {
	case core.KindAsset, core.KindBinary:
		return true
	case core.KindText:
		return assetCodeExts[strings.ToLower(path.Ext(p))] && !docName(p)
	}
	return false
}

// docName reports a file that is documentation by its name or folder:
// readme, changelog, license and the docs folders.
func docName(p string) bool {
	l := strings.ToLower(p)
	base := path.Base(l)
	for _, pre := range []string{"readme", "changelog", "license", "licence", "changes", "history", "upgrade", "copying"} { //nolint:misspell // the British file name some packages ship
		if strings.HasPrefix(base, pre) {
			return true
		}
	}
	for _, d := range strings.Split(path.Dir(l), "/") {
		if d == "docs" || d == "doc" {
			return true
		}
	}
	return false
}

// maxTagTries is how many PHP open tag candidates one file is checked
// for: random binary data holds "<?" now and then.
const maxTagTries = 64

// phpInAsset finds a PHP open tag followed by a statement the lexer
// reads: a name, a variable or a keyword, then "(" or ";" (or the
// closing tag after <?=), all in printable text. It returns the tag's
// offset. "<?xml" headers and random bytes that happen to spell "<?"
// do not count.
func phpInAsset(src []byte) (int, bool) {
	tries := 0
	for i := 0; i < len(src) && tries < maxTagTries; {
		k := bytes.Index(src[i:], []byte("<?"))
		if k < 0 {
			return 0, false
		}
		k += i
		i = k + 2
		rest := src[k+2:]
		switch {
		case len(rest) >= 3 && bytes.EqualFold(rest[:3], []byte("php")):
		case len(rest) >= 1 && rest[0] == '=':
		case len(rest) >= 1 && (rest[0] == ' ' || rest[0] == '\t' || rest[0] == '\n' || rest[0] == '\r'):
		default:
			continue
		}
		tries++
		if phpStatement(src[k:min(len(src), k+512)]) {
			return k, true
		}
	}
	return 0, false
}

// minStatement is the fewest bytes a statement after an open tag must
// run, so a few printable bytes in random data do not count.
const minStatement = 8

// phpStatement reports whether text, starting at an open tag, goes on
// with a statement: a name of at least three characters (a function,
// a keyword or a variable) and then "(", ";", "=" or the closing tag, all
// printable ASCII and at least minStatement bytes long.
func phpStatement(text []byte) bool {
	toks := php.Lex(text)
	if len(toks) == 0 || toks[0].Kind != php.OpenTag {
		return false
	}
	start := toks[0].End()
	named := false
	for n, t := range toks[1:] {
		if n > 32 || !asciiText(t.Text) {
			return false
		}
		switch t.Kind {
		case php.Error, php.InlineHTML:
			return false
		case php.Identifier, php.Keyword, php.Variable:
			name := strings.TrimLeft(t.Text, "$\\")
			if len(name) >= 3 && (name[0] == '_' || isLetter(name[0])) {
				named = true
			}
		case php.Punct, php.Operator, php.CloseTag:
			// A short start ("eval(") reads on to the next end.
			if named && (t.Text == "(" || t.Text == ";" || t.Text == "=" || t.Kind == php.CloseTag) && t.End()-start >= minStatement {
				return true
			}
		}
	}
	return false
}

func isLetter(c byte) bool { return c|0x20 >= 'a' && c|0x20 <= 'z' }

// asciiText reports whether s is printable ASCII, tabs and line breaks.
func asciiText(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < 0x20 && c != '\t' && c != '\n' && c != '\r') || c >= 0x7f {
			return false
		}
	}
	return true
}

// textual reports whether s is text: printable ASCII, tabs and line
// breaks, or valid UTF-8 letters. Binary data fails.
func textual(s string) bool {
	for _, r := range s {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
		case r < 0x20 || r == 0x7f || r == utf8.RuneError:
			return false
		}
	}
	return true
}

// imagePayload is the part of an image that may hide a script: the
// whole file when it does not start with its type's magic bytes, else
// what follows the image's end (PNG's IEND chunk, JPEG's last end
// marker). ok is false when there is nothing to check.
func imagePayload(ext string, src []byte) (int, bool) {
	magic, known := imageExts[ext]
	if !known {
		return 0, false
	}
	if !bytes.HasPrefix(src, magic) {
		return 0, true
	}
	switch ext {
	case ".png":
		if k := bytes.LastIndex(src, []byte("IEND")); k >= 0 && k+8 < len(src) {
			return k + 8, true // the chunk type and its CRC
		}
	case ".jpg", ".jpeg":
		if k := bytes.LastIndex(src, []byte{0xff, 0xd9}); k >= 0 && k+2 < len(src) {
			return k + 2, true
		}
	}
	return 0, false
}

// jsWords are words that mark text as JavaScript rather than prose.
var jsWords = map[string]bool{
	"function": true, "var": true, "let": true, "const": true, "return": true, "new": true, "eval": true,
	"require": true, "window": true, "document": true, "import": true, "await": true, "async": true,
}

// jsInImage reports whether text is JavaScript: printable, lexed without
// errors, with a call, a JavaScript word or an arrow plus a statement
// end. Prose fails (no keyword) and so does binary data.
func jsInImage(text []byte) bool {
	if len(bytes.TrimSpace(text)) < 16 || !textual(string(text)) {
		return false
	}
	toks := js.Lex(text)
	call, word, end := false, false, false
	var prev js.Token
	for _, t := range toks {
		switch t.Kind {
		case js.Error:
			return false
		case js.Whitespace, js.Comment:
			continue
		case js.Keyword, js.Identifier:
			if jsWords[t.Text] {
				word = true
			}
		case js.Punct:
			switch t.Text {
			case "(":
				call = call || prev.Kind == js.Identifier || prev.Kind == js.Keyword || prev.Text == ")"
			case "=>":
				word = true
			case ";", "}":
				end = true
			}
		}
		prev = t
	}
	return call && word && end
}

// assetCode finds code in a file that should hold none and reports its
// language and where it starts: PHP after an open tag anywhere, or
// JavaScript making up an image (or following its end).
func assetCode(p string, src []byte) (lang, int, bool) {
	if k, ok := phpInAsset(src); ok {
		return langPHP, k, true
	}
	if k, ok := imagePayload(strings.ToLower(path.Ext(p)), src); ok && jsInImage(src[k:]) {
		return langJS, k, true
	}
	return 0, 0, false
}

// assetFileFeatures returns FCodeInAsset for a non-code file that holds
// code, keyed by the file's path, plus the features of that code (in
// the file's context, at its lines), so what hidden code does counts.
func assetFileFeatures(p string, src []byte, env decodeEnv) ([]core.Feature, []core.Unanalysed) {
	l, k, ok := assetCode(p, src)
	if !ok {
		return nil, nil
	}
	ctx := pathContext(p)
	lines := newLineIndex(src)
	col := newCollector(p, ctx, lines)
	line := bytes.Count(src[:k], []byte("\n")) + 1
	name := "php"
	if l == langJS {
		name = "js"
	}
	col.addAt(k, core.FCodeInAsset, p, line, line, "", map[string]string{
		"lang": name,
		"ext":  strings.ToLower(path.Ext(p)),
	})
	fs, un := analyzeCode(l, p, src[k:], ctx, env)
	// Binary data after the code reads as unterminated strings now and
	// then; only the limits count here.
	un = slices.DeleteFunc(un, func(u core.Unanalysed) bool { return u.Reason != reasonDecodeLimit && u.Reason != reasonTimeLimit })
	for _, f := range fs {
		f.Ev.Line += line - 1
		f.Ev.EndLine += line - 1
		col.out = append(col.out, f)
	}
	sortFeatures(col.out)
	return col.out, un
}
