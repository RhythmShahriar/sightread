// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package report

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/RhythmShahriar/rhythm/kit/secrets"
	"github.com/RhythmShahriar/rhythm/kit/term"
)

// Every string a writer takes from a report may come from a package:
// names, versions, changelog text, publisher names, file paths, hunks.
// Writers pass each one through text (or lines) before any format's own
// escaping, so all formats agree on what a reader may see.

// email matches an e-mail address. Publisher and maintainer addresses
// are personal data the report has no need to repeat.
var email = regexp.MustCompile(`[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}`)

// text makes package text safe for every output: control characters and
// bytes that are not UTF-8 become visible escapes (\x1b, \xff), bidi
// overrides are dropped, secrets and e-mail addresses are masked.
// Sanitising runs before masking, so a bidi character placed inside a
// key can't hide it from the secret rules and then vanish. It is
// idempotent, which keeps a report read back and written again the same.
func text(s string) string {
	if s == "" {
		return s
	}
	return maskEmails(secrets.Redact(term.Sanitize(s)))
}

// texts applies text to each element, keeping nil as nil.
func texts(in []string) []string {
	if in == nil {
		return nil
	}
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = text(s)
	}
	return out
}

// maskEmails keeps the first character of the local part and the domain:
// "ann@example.com" becomes "a•••••@example.com".
func maskEmails(s string) string {
	if !strings.Contains(s, "@") {
		return s
	}
	return email.ReplaceAllStringFunc(s, func(m string) string {
		local, domain, _ := strings.Cut(m, "@")
		if strings.HasSuffix(local, "•••••") {
			return m
		}
		return secrets.Mask(local, 1) + "@" + domain
	})
}

// paths rewrites absolute paths for WriteOptions.RedactPaths: a path in
// the target becomes relative to it and one under the home folder starts
// with ~. Reports from CI are often public; the runner's folders are
// nobody's business.
type paths struct {
	on   bool
	root string // the target folder, cleaned
	home string
}

func newPaths(target string, on bool) paths {
	p := paths{on: on}
	if !on {
		return p
	}
	if target != "" && filepath.IsAbs(target) {
		p.root = filepath.Clean(target)
	}
	if h, err := os.UserHomeDir(); err == nil && h != "" && filepath.IsAbs(h) {
		p.home = filepath.Clean(h)
	}
	return p
}

// path rewrites one path value.
func (p paths) path(s string) string {
	if !p.on || s == "" {
		return s
	}
	if p.root != "" {
		if s == p.root {
			return "."
		}
		if rel, ok := strings.CutPrefix(s, p.root+string(filepath.Separator)); ok {
			return filepath.ToSlash(rel)
		}
	}
	if p.home != "" {
		if s == p.home {
			return "~"
		}
		if rel, ok := strings.CutPrefix(s, p.home+string(filepath.Separator)); ok {
			return "~/" + filepath.ToSlash(rel)
		}
	}
	return s
}

// text rewrites the paths inside a message, such as a warning that names
// a folder.
func (p paths) text(s string) string {
	if !p.on || s == "" {
		return s
	}
	if p.root != "" && strings.Contains(s, p.root) {
		s = strings.ReplaceAll(s, p.root+string(filepath.Separator), "")
		s = strings.ReplaceAll(s, p.root, ".")
	}
	if p.home != "" && strings.Contains(s, p.home) {
		s = strings.ReplaceAll(s, p.home, "~")
	}
	return s
}

// toolVersion is the version a report names, "dev" when unset.
func toolVersion(v string) string {
	if v == "" {
		return "dev"
	}
	return term.SafeText(v)
}
