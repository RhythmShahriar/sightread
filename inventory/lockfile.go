// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package inventory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"github.com/RhythmShahriar/rhythm/kit/secrets"
	"github.com/RhythmShahriar/sightread/core"
)

// maxLockBytes caps a lockfile or manifest. The biggest real lockfiles
// are a few MiB; past this a file is not a lockfile anyone maintains.
const maxLockBytes = 64 << 20

// errTooBig is readAll's error for a file over its cap.
var errTooBig = errors.New("file is over the size limit")

// readAll returns the whole regular file at path, or errTooBig when it
// holds more than limit bytes. Lockfiles are read this way: a truncated
// lockfile would parse as a different one.
func readAll(path string, limit int64) ([]byte, error) {
	b, err := readHead(path, limit+1)
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s: %w (%d MiB)", path, errTooBig, limit>>20)
	}
	return b, nil
}

// Options are what the lockfile readers take from config.
type Options struct {
	// NPMRegistry is sources.npm.registry; empty means the public npm
	// registry.
	NPMRegistry string
	// NPMScopes is sources.npm.scopes: "@acme" to its registry URL. A
	// scope listed here is private and reviewed from that registry.
	NPMScopes map[string]string
	// ComposerRepos is sources.composer.repositories.
	ComposerRepos []string
	// NPMRC lists the .npmrc files read for @scope:registry= lines. Nil
	// means the project's .npmrc and ~/.npmrc.
	NPMRC []string
}

// Packages is what one lockfile pins.
//
// Installed holds every package the lockfile names, including those
// that are also listed in NotChecked: a Private entry or one whose
// ResolvedKind is not registry is not reviewed; `changes` still
// needs it to see a package move off the registry.
type Packages struct {
	Lockfile   string // path as given, slash separated
	Installed  []core.Installed
	NotChecked []core.NotChecked
	Warnings   []string
}

// warn adds a warning. Values from the lockfile go in with %q, so a
// control character in a hostile file can't reach the terminal raw.
func (p *Packages) warn(format string, a ...any) {
	p.Warnings = append(p.Warnings, fmt.Sprintf(format, a...))
}

// validRef reports whether name and version make a reference ParseRef
// would accept, so a hostile lockfile can't produce one the rest of
// Sightread refuses.
func validRef(eco core.Ecosystem, name, version string) bool {
	s := string(eco) + ":" + name
	if version != "" {
		s += "@" + version
	}
	r, err := core.ParseRef(s)
	return err == nil && r.Name == name && r.Version == version
}

// trimBOM drops a UTF-8 byte order mark. Windows editors write one and
// encoding/json refuses it.
func trimBOM(b []byte) []byte { return bytes.TrimPrefix(b, bom) }

// lineIndex finds the line of a byte offset.
type lineIndex []int // offsets of each '\n'

func newLineIndex(b []byte) lineIndex {
	var idx lineIndex
	for i, c := range b {
		if c == '\n' {
			idx = append(idx, i)
		}
	}
	return idx
}

// line is the 1-based line holding byte offset off.
func (l lineIndex) line(off int) int {
	return sort.SearchInts(l, off) + 1
}

// jsonFrame is one open object or array in scanJSONKeys.
type jsonFrame struct {
	obj     bool
	wantKey bool
	n       int
}

// scanJSONKeys calls fn for every object key in data with the key's
// path (array elements by index) and its 1-based line. It streams the
// tokens, so a key's line comes from the bytes and not from a decoded
// copy. fn must not keep path.
func scanJSONKeys(data []byte, fn func(path []string, line int)) error {
	lines := newLineIndex(data)
	dec := json.NewDecoder(bytes.NewReader(data))
	var stack []jsonFrame
	var path []string
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		if d, ok := tok.(json.Delim); ok && (d == '}' || d == ']') {
			stack = stack[:len(stack)-1]
			path = path[:len(stack)]
			if n := len(stack); n > 0 && stack[n-1].obj {
				stack[n-1].wantKey = true
			}
			continue
		}
		if n := len(stack); n > 0 {
			top := &stack[n-1]
			if top.obj && top.wantKey {
				key, _ := tok.(string)
				path = append(path[:n-1], key)
				// InputOffset is just past the key; a key never spans lines.
				fn(path, lines.line(int(dec.InputOffset())-1))
				top.wantKey = false
				continue
			}
			if !top.obj {
				path = append(path[:n-1], strconv.Itoa(top.n))
				top.n++
			}
		}
		if d, ok := tok.(json.Delim); ok {
			stack = append(stack, jsonFrame{obj: d == '{', wantKey: d == '{'})
			continue
		}
		if n := len(stack); n > 0 && stack[n-1].obj {
			stack[n-1].wantKey = true
		}
	}
}

// urlHost is the lower-case host of a URL, or "" when s is not an
// absolute http(s) URL.
func urlHost(s string) string {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || u.Host == "" || u.Scheme != "https" && u.Scheme != "http" {
		return ""
	}
	return strings.ToLower(u.Hostname())
}

// cleanURL removes a user and password from a URL and masks anything
// that looks like a token, so a credential written into a lockfile URL
// never reaches a report or a log.
func cleanURL(s string) string {
	if u, err := url.Parse(s); err == nil && u.User != nil {
		u.User = nil
		s = u.String()
	}
	return secrets.Redact(s)
}
