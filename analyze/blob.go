// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package analyze

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"compress/zlib"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
	"sync/atomic"
	"unicode/utf8"

	"github.com/RhythmShahriar/sightread/core"
)

// Encoded blobs and the bounded decoder. A long literal that looks
// encoded (base64, hex, \x escapes, character codes) is an FBlob. The
// decoder undoes up to maxLayers layers of the encodings and
// compressions PHP and JavaScript payloads use, in pure Go; it never
// runs anything. Decoded text that looks like code is analysed again
// with Context decoded, so a payload's features count like any other.

// Decoder limits (SR-3): what one blob and one package may decode to.
const (
	maxLayers       = 8
	maxBlobOut      = 1 << 20
	maxPackageOut   = 16 << 20
	minBlob         = 512 // a literal shorter than this is not reported as a blob
	minChainLiteral = 8   // a decode chain argument shorter than this is not decoded
)

// reasonDecodeLimit is the Unanalysed reason of a blob the decoder had
// to stop on.
const reasonDecodeLimit = "decode limit reached"

// ctxAsset is the Context of a data URI: an image, font or style
// embedded in a file, not code.
const ctxAsset = "asset"

// The encodings of FBlob's encoding attribute.
const (
	encBase64    = "base64"
	encHex       = "hex"
	encEscape    = "escape"
	encCharCodes = "charcodes"
	encDataURI   = "data-uri"
)

// Values of FBlob's decoded attribute.
const (
	decodedCode = "code"
	decodedData = "data"
	decodedNone = "none"
)

// decodeBudget is what a package may still decode, shared by the
// workers of one analysis.
type decodeBudget struct{ left atomic.Int64 }

func newDecodeBudget() *decodeBudget {
	b := &decodeBudget{}
	b.left.Store(maxPackageOut)
	return b
}

// take reserves n bytes and reports whether the budget had them.
func (b *decodeBudget) take(n int) bool {
	if b == nil {
		return true
	}
	if b.left.Add(-int64(n)) < 0 {
		b.left.Store(-1)
		return false
	}
	return true
}

// errLimit is a decode step that would pass a limit.
var errLimit = errors.New(reasonDecodeLimit)

// decodeEnv is what one file's analysis may decode.
type decodeEnv struct {
	budget *decodeBudget
	layers int    // decode layers left for payloads found in this file
	clk    *clock // the file's time budget, shared with its payloads
	// own names the package's own plugin folders (see ownDirs), so an
	// update filter can tell its own entry from another plugin's.
	own []string
}

// decodeStep undoes one encoding of data, or reports false when it does
// not apply. op is a PHP or JavaScript decoder name.
func decodeStep(op string, data []byte, budget *decodeBudget) ([]byte, bool, error) {
	var out []byte
	var err error
	switch op {
	case "base64_decode", "atob", encBase64:
		out, err = decodeB64(data)
	case "hex2bin", encHex:
		out, err = decodeHex(data)
	case "str_rot13":
		out = []byte(rot13(string(data)))
	case "strrev":
		out = []byte(reverse(string(data)))
	case "gzinflate":
		out, err = inflate(flate.NewReader(bytes.NewReader(data)))
	case "gzuncompress":
		var r io.ReadCloser
		if r, err = zlib.NewReader(bytes.NewReader(data)); err == nil {
			out, err = inflate(r)
		}
	case "gzdecode":
		var r *gzip.Reader
		if r, err = gzip.NewReader(bytes.NewReader(data)); err == nil {
			out, err = inflate(r)
		}
	default:
		return nil, false, nil
	}
	if errors.Is(err, errLimit) {
		return nil, false, err
	}
	if err != nil || len(out) == 0 {
		return nil, false, nil
	}
	if !budget.take(len(out)) {
		return nil, false, errLimit
	}
	return out, true, nil
}

// inflate reads a decompressor to its end, failing past maxBlobOut so
// a small bomb never grows big.
func inflate(r io.ReadCloser) ([]byte, error) {
	defer func() { _ = r.Close() }()
	var buf bytes.Buffer
	n, err := io.Copy(&buf, io.LimitReader(r, maxBlobOut+1))
	if n > maxBlobOut {
		return nil, errLimit
	}
	if err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// decodeB64 decodes base64 the lenient way PHP does: characters outside
// the alphabet are skipped, padding is optional, the URL alphabet
// works too.
func decodeB64(data []byte) ([]byte, error) {
	if len(data)/4*3 > maxBlobOut {
		return nil, errLimit
	}
	clean := make([]byte, 0, len(data))
	for _, c := range data {
		switch {
		case 'A' <= c && c <= 'Z', 'a' <= c && c <= 'z', '0' <= c && c <= '9', c == '+', c == '/':
			clean = append(clean, c)
		case c == '-':
			clean = append(clean, '+')
		case c == '_':
			clean = append(clean, '/')
		case c == '=':
			// Padding inside the text ends PHP's decode; at the end it
			// is optional.
		}
	}
	if len(clean)%4 == 1 {
		clean = clean[:len(clean)-1]
	}
	out := make([]byte, base64.RawStdEncoding.DecodedLen(len(clean)))
	n, err := base64.RawStdEncoding.Decode(out, clean)
	return out[:n], err
}

func decodeHex(data []byte) ([]byte, error) {
	clean := bytes.Map(func(r rune) rune {
		if r == ' ' || r == '\n' || r == '\r' || r == '\t' {
			return -1
		}
		return r
	}, data)
	if len(clean)/2 > maxBlobOut {
		return nil, errLimit
	}
	out := make([]byte, len(clean)/2)
	_, err := hex.Decode(out, clean)
	return out, err
}

// decodeAll undoes the chain of decoders written around a literal
// (innermost first), then keeps undoing whatever the result still looks
// like (base64, hex, gzip, zlib, raw deflate) until it reads as text or
// the layers run out. It returns the result, the layers undone and
// errLimit when a limit stopped it.
func decodeAll(data []byte, chain []string, layers int, budget *decodeBudget) ([]byte, int, error) {
	n := 0
	for _, op := range chain {
		if n >= layers {
			return data, n, errLimit
		}
		out, ok, err := decodeStep(op, data, budget)
		if err != nil {
			return data, n, err
		}
		if !ok {
			return data, n, nil
		}
		data = out
		n++
	}
	for n < layers {
		op := guessDecoder(data)
		if op == "" {
			return data, n, nil
		}
		out, ok, err := decodeStep(op, data, budget)
		if err != nil {
			return data, n, err
		}
		if !ok {
			return data, n, nil
		}
		data = out
		n++
	}
	if guessDecoder(data) != "" {
		return data, n, errLimit // more layers than allowed
	}
	return data, n, nil
}

// guessDecoder names the decoder that fits data, or "" when data reads
// as text that is not itself an encoding.
func guessDecoder(data []byte) string {
	switch {
	case len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b:
		return "gzdecode"
	case len(data) >= 2 && data[0] == 0x78 && (uint16(data[0])<<8|uint16(data[1]))%31 == 0:
		return "gzuncompress"
	}
	if looksText(data) {
		s := strings.TrimSpace(string(data))
		switch {
		case len(s) >= 16 && isHexText(s):
			return encHex
		case len(s) >= 16 && isBase64Text(s):
			return encBase64
		}
		return ""
	}
	// Binary without a header: raw deflate (gzinflate) is the one
	// compression PHP payloads use that has no magic bytes.
	if out, err := inflate(flate.NewReader(bytes.NewReader(data))); errors.Is(err, errLimit) || err == nil && len(out) > 0 {
		return "gzinflate" // a bomb too: the step then stops at the limit
	}
	return ""
}

// looksText reports whether data is mostly printable text.
func looksText(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	if !utf8.Valid(data) {
		return false
	}
	bad := 0
	for _, c := range data {
		if c < 0x20 && c != '\n' && c != '\r' && c != '\t' || c == 0x7f {
			bad++
		}
	}
	return bad*20 <= len(data)
}

func isHexText(s string) bool {
	n := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case '0' <= c && c <= '9', 'a' <= c|0x20 && c|0x20 <= 'f':
			n++
		case c == ' ' || c == '\n' || c == '\r' || c == '\t':
		default:
			return false
		}
	}
	return n%2 == 0 && n > 0
}

// isBase64Text reports whether s is base64: only its alphabet (and
// line breaks), both letter cases or digits mixed in, padding only at
// the end.
func isBase64Text(s string) bool {
	upper, lower, digit, n := false, false, false, 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case 'A' <= c && c <= 'Z':
			upper = true
		case 'a' <= c && c <= 'z':
			lower = true
		case '0' <= c && c <= '9':
			digit = true
		case c == '+' || c == '/' || c == '-' || c == '_':
		case c == '=':
			if strings.Trim(s[i:], "=\r\n") != "" {
				return false
			}
		case c == '\n' || c == '\r':
			continue
		default:
			return false
		}
		n++
	}
	return n >= 16 && upper && lower && (digit || n >= 64)
}

// entropy is the Shannon entropy of s in bits per byte.
func entropy(s []byte) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for _, c := range s {
		counts[c]++
	}
	h := 0.0
	n := float64(len(s))
	for _, c := range counts {
		if c > 0 {
			p := float64(c) / n
			h -= p * math.Log2(p)
		}
	}
	return h
}

// payloadLang says whether decoded text is PHP or JavaScript code.
func payloadLang(text []byte) (lang, bool) {
	if !looksText(text) {
		return 0, false
	}
	s := string(text)
	if strings.Contains(s, "<?php") || strings.Contains(s, "<?=") {
		return langPHP, true
	}
	hasCall := strings.Contains(s, "(") && strings.Contains(s, ")")
	if !hasCall || (!strings.Contains(s, ";") && !strings.Contains(s, "\n")) {
		return 0, false
	}
	// PHP code eval() runs has no open tag: a $variable is the tell.
	for i := 0; i+1 < len(s); i++ {
		if s[i] == '$' && (s[i+1] == '_' || ('a' <= s[i+1]|0x20 && s[i+1]|0x20 <= 'z')) {
			return langPHP, true
		}
	}
	for _, w := range []string{"function", "=>", "var ", "const ", "let ", "require(", "document.", "window.", "console.", "process.", "eval("} {
		if strings.Contains(s, w) {
			return langJS, true
		}
	}
	for _, w := range []string{"eval(", "system(", "exec(", "assert(", "base64_decode("} {
		if strings.Contains(s, w) {
			return langPHP, true
		}
	}
	return 0, false
}

// blobScan finds the blobs of one file's stream, decodes them and
// analyses decoded code.
type blobScan struct {
	col  *collector
	st   *stream
	path string
	env  decodeEnv
	out  []core.Feature // features of decoded payloads
	un   bool           // a decode limit was reached
}

// scan walks the stream once.
func (b *blobScan) scan() {
	toks := b.st.toks
	concat := "."
	if b.st.lang == langJS {
		concat = "+"
	}
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		switch {
		case t.k == tStr && t.known:
			// A run of literals joined by concatenation is one blob.
			j := i
			var val, raw strings.Builder
			for {
				val.WriteString(toks[j].val)
				raw.WriteString(toks[j].text)
				if !at(toks, j+1).punct(concat) || at(toks, j+2).k != tStr || !at(toks, j+2).known {
					break
				}
				j += 2
			}
			b.literal(i, j, val.String(), raw.String())
			i = j
		case t.punct("[") || (t.punct("(") && at(toks, i-1).is(tName, "fromCharCode")) ||
			(t.punct("(") && at(toks, i-1).is(tName, "array")):
			if j, data, ok := b.charCodes(i); ok {
				b.found(i, j, encCharCodes, data, string(data), nil, len(b.textOf(i, j)))
				i = j
			}
		}
	}
}

// textOf is the source text of tokens [i, j], an estimate of size.
func (b *blobScan) textOf(i, j int) string {
	toks := b.st.toks
	if j >= len(toks) {
		j = len(toks) - 1
	}
	start, end := toks[i].off, toks[j].off+len(toks[j].text)
	src := b.col.lines.src
	if start < 0 || end > len(src) || start > end {
		return ""
	}
	return src[start:end]
}

// charCodes reads a bracket of at least 128 numbers from 0 to 255 (or
// 0xFFFF in JavaScript) as the text they spell.
func (b *blobScan) charCodes(i int) (int, []byte, bool) {
	toks := b.st.toks
	e := b.st.close(i)
	if e >= len(toks) || (e-i)/2 < 128 {
		return 0, nil, false
	}
	var out strings.Builder
	for k := i + 1; k < e; k++ {
		t := toks[k]
		if (k-i)%2 == 0 {
			if !t.punct(",") {
				return 0, nil, false
			}
			continue
		}
		if t.k != tNum {
			return 0, nil, false
		}
		v := numLit(t.text)
		if v.kind != vNum || v.n < 0 || v.n > 0xffff {
			return 0, nil, false
		}
		out.WriteRune(rune(v.n))
	}
	return e, []byte(out.String()), true
}

// literal classifies the literal run [i, j] with value val and source
// text raw.
func (b *blobScan) literal(i, j int, val, raw string) {
	chain := b.chain(i, j)
	if strings.HasPrefix(val, "data:") {
		if len(val) >= minBlob {
			b.dataURI(i, j, val)
		}
		return
	}
	enc := ""
	switch {
	case escapeChain(raw):
		enc = encEscape
	case isHexText(strings.TrimSpace(val)) && len(val) >= 32:
		enc = encHex
	case isBase64Text(strings.TrimSpace(val)):
		enc = encBase64
	}
	if len(chain) > 0 && len(val) >= minChainLiteral {
		// Written into a decoder: decode it whatever its size.
		b.found(i, j, enc, []byte(val), val, chain, len(raw))
		return
	}
	if enc == "" || len(val) < minBlob && len(raw) < minBlob {
		return
	}
	b.found(i, j, enc, []byte(val), val, nil, len(raw))
}

// escapeChain reports whether a literal is mostly \x or octal escapes.
func escapeChain(raw string) bool {
	if len(raw) < 32 {
		return false
	}
	n := strings.Count(raw, `\x`) + strings.Count(raw, `\u`)
	for i := 0; i+3 < len(raw); i++ {
		if raw[i] == '\\' && '0' <= raw[i+1] && raw[i+1] <= '7' && '0' <= raw[i+2] && raw[i+2] <= '7' && '0' <= raw[i+3] && raw[i+3] <= '7' {
			n++
		}
	}
	return n*4*2 >= len(raw)
}

// decoderNames are the calls a literal can be wrapped in that decode
// it.
var decoderNames = map[string]bool{
	"base64_decode": true, "gzinflate": true, "gzuncompress": true, "gzdecode": true, "str_rot13": true,
	"hex2bin": true, "strrev": true, "atob": true,
}

// chain reads the decoder calls written around the literal [i, j]:
// eval(gzinflate(base64_decode('...'))) gives base64_decode, gzinflate.
// Buffer.from('...', 'base64') counts as base64.
func (b *blobScan) chain(i, j int) []string {
	toks := b.st.toks
	var out []string
	k := i - 1
	end := j + 1
	for len(out) < maxLayers && at(toks, k).punct("(") && at(toks, k-1).k == tName {
		name := at(toks, k-1).text
		switch {
		case decoderNames[name]:
			out = append(out, name)
		case name == "from" && at(toks, k-2).punct(".") && at(toks, k-3).is(tName, "Buffer") &&
			at(toks, end).punct(",") && at(toks, end+1).k == tStr:
			switch at(toks, end+1).val {
			case "base64":
				out = append(out, encBase64)
			case "hex":
				out = append(out, encHex)
			}
			return out
		default:
			return out
		}
		// Step out to the call around this one.
		end = b.st.close(k) + 1
		k -= 2
	}
	return out
}

// found decodes one blob and records it.
func (b *blobScan) found(i, j int, enc string, data []byte, text string, chain []string, size int) {
	toks := b.st.toks
	line := toks[i].line
	end := toks[min(j, len(toks)-1)].line
	initial := data
	steps := chain
	switch enc {
	case encHex:
		if len(chain) == 0 {
			steps = []string{encHex}
		}
	case encBase64:
		if len(chain) == 0 {
			steps = []string{encBase64}
		}
	}
	out, layers, err := decodeAll(initial, steps, b.env.layers, b.env.budget)
	if errors.Is(err, errLimit) {
		b.un = true
	}
	decoded := decodedNone
	if layers > 0 || enc == encEscape || enc == encCharCodes {
		decoded = decodedData
		if l, ok := payloadLang(out); ok && !errors.Is(err, errLimit) {
			decoded = decodedCode
			b.payload(l, out, line, end, b.env.layers-layers)
		}
	}
	if enc == "" || len(text) < minBlob && size < minBlob {
		return // a short literal in a decode chain: only its payload counts
	}
	ent := entropy([]byte(text))
	if enc == encHex || enc == encEscape || enc == encCharCodes {
		ent = entropy(initial) // the bytes, not the digits that spell them
	}
	sum := sha256.Sum256([]byte(text))
	key := enc + ":" + hex.EncodeToString(sum[:6])
	b.col.addAt(toks[i].off, core.FBlob, key, line, end, "", map[string]string{
		"encoding": enc,
		"size":     strconv.Itoa(size),
		"entropy":  strconv.FormatFloat(ent, 'f', 2, 64),
		"layers":   strconv.Itoa(layers),
		"decoded":  decoded,
	})
}

// payload analyses decoded code as a file of its own in Context
// decoded, then moves its evidence to the blob's lines.
func (b *blobScan) payload(l lang, text []byte, line, end, layers int) {
	if l == langPHP && !bytes.Contains(text, []byte("<?")) {
		text = append([]byte("<?php "), text...)
	}
	fs, un := analyzeCode(l, b.path, text, core.CtxDecoded, decodeEnv{budget: b.env.budget, layers: layers, clk: b.env.clk, own: b.env.own})
	if len(un) > 0 {
		b.un = true
	}
	for _, f := range fs {
		f.Context = core.CtxDecoded
		f.Ev.Line, f.Ev.EndLine = line, end
		b.out = append(b.out, f)
	}
}

// dataURI records a data: URI as a blob in Context asset: an image or
// font embedded in code is not code. A data URI whose type is a script
// is decoded and analysed.
func (b *blobScan) dataURI(i, j int, val string) {
	toks := b.st.toks
	line, end := toks[i].line, toks[min(j, len(toks)-1)].line
	addDataURI(b.col, b.env, b.path, val, toks[i].off, line, end, func(l lang, text []byte, layers int) {
		b.payload(l, text, line, end, layers)
	}, &b.un)
}

// addDataURI records one data URI.
func addDataURI(col *collector, env decodeEnv, p, val string, off, line, end int, payload func(lang, []byte, int), limit *bool) {
	head, body, ok := strings.Cut(val, ",")
	if !ok {
		return
	}
	mime := strings.ToLower(strings.TrimPrefix(head, "data:"))
	b64 := strings.HasSuffix(mime, ";base64")
	mime, _, _ = strings.Cut(mime, ";")
	decoded := decodedData
	layers := 0
	if strings.Contains(mime, "javascript") || strings.Contains(mime, "php") || strings.Contains(mime, "ecmascript") {
		data := []byte(body)
		if b64 {
			out, n, err := decodeAll(data, []string{encBase64}, env.layers, env.budget)
			if errors.Is(err, errLimit) {
				*limit = true
			}
			data, layers = out, n
		}
		if l, ok := payloadLang(data); ok {
			decoded = decodedCode
			payload(l, data, env.layers-layers)
		}
	}
	sum := sha256.Sum256([]byte(val))
	col.addCtxAt(ctxAsset, off, core.FBlob, encDataURI+":"+hex.EncodeToString(sum[:6]), line, end, "", map[string]string{
		"encoding": encDataURI,
		"mime":     attrText(mime),
		"size":     strconv.Itoa(len(val)),
		"entropy":  strconv.FormatFloat(entropy([]byte(body)), 'f', 2, 64),
		"layers":   strconv.Itoa(layers),
		"decoded":  decoded,
	})
}

// assetFeatures returns the data URIs of a style sheet or SVG file as
// FBlob features in Context asset.
func assetFeatures(p string, src []byte, env decodeEnv) ([]core.Feature, []core.Unanalysed) {
	col := newCollector(p, ctxAsset, newLineIndex(src))
	env.layers = maxLayers
	limit := false
	var payloads []core.Feature
	s := string(src)
	for i := 0; i < len(s); {
		k := strings.Index(s[i:], "data:")
		if k < 0 {
			break
		}
		k += i
		e := k
		for e < len(s) && !strings.ContainsRune("\"')> \t\r\n", rune(s[e])) {
			e++
		}
		i = max(e, k+5)
		if e-k < minBlob {
			continue
		}
		line := strings.Count(s[:k], "\n") + 1
		addDataURI(col, env, p, s[k:e], k, line, line, func(l lang, text []byte, layers int) {
			fs, un := analyzeCode(l, p, text, core.CtxDecoded, decodeEnv{budget: env.budget, layers: layers, clk: env.clk, own: env.own})
			limit = limit || len(un) > 0
			for _, f := range fs {
				f.Ev.Line, f.Ev.EndLine = line, line
				payloads = append(payloads, f)
			}
		}, &limit)
	}
	out := append(col.out, payloads...)
	sortFeatures(out)
	var un []core.Unanalysed
	if limit {
		un = append(un, core.Unanalysed{Path: p, Reason: reasonDecodeLimit})
	}
	return out, un
}
