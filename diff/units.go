// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package diff

import "bytes"

// maxLine is the longest line diffed as a whole. A longer line (a
// bundle or a data blob on one line) is cut into tokens so its hunks
// show the part that changed rather than the whole line.
const maxLine = 64 << 10

// maxToken bounds a token when a long stretch has no punctuation to cut
// at, such as base64.
const maxToken = 1024

// units cuts data into the pieces the line diff compares, each with its
// terminator so the pieces join back into data. Text is cut into lines
// and lines over maxLine into tokens; with tokens set every line is cut
// into tokens, which is how minified files are compared.
func units(data []byte, tokens bool) []string {
	var out []string
	for len(data) > 0 {
		end := bytes.IndexByte(data, '\n') + 1
		if end == 0 {
			end = len(data)
		}
		line := data[:end]
		data = data[end:]
		if tokens || len(line) > maxLine {
			out = appendTokens(out, line)
			continue
		}
		out = append(out, string(line))
	}
	return out
}

// appendTokens cuts line after each ";", "{", "}" and "," (the joints of
// minified JavaScript and CSS) and at most every maxToken bytes.
func appendTokens(out []string, line []byte) []string {
	start := 0
	for i, c := range line {
		switch {
		case c == ';' || c == '{' || c == '}' || c == ',' || c == '\n':
		case i+1-start >= maxToken:
		default:
			continue
		}
		out = append(out, string(line[start:i+1]))
		start = i + 1
	}
	if start < len(line) {
		out = append(out, string(line[start:]))
	}
	return out
}

// intern numbers the units of both sides so equal units share a number.
func intern(old, new []string) (a, b []int) {
	ids := make(map[string]int, len(old))
	id := func(s string) int {
		if n, ok := ids[s]; ok {
			return n
		}
		n := len(ids)
		ids[s] = n
		return n
	}
	a = make([]int, len(old))
	for i, s := range old {
		a[i] = id(s)
	}
	b = make([]int, len(new))
	for i, s := range new {
		b[i] = id(s)
	}
	return a, b
}
