// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package core

import (
	"fmt"
	"strings"
	"unicode"
)

// Ecosystem is where a package comes from, as JSON, config, the allow
// file and --only write it.
type Ecosystem string

// The ecosystems Sightread reviews.
const (
	WPPlugin Ecosystem = "wp-plugin"
	WPTheme  Ecosystem = "wp-theme"
	Composer Ecosystem = "composer"
	NPM      Ecosystem = "npm"
)

// Ecosystems lists every ecosystem in the order reports group them.
func Ecosystems() []Ecosystem { return []Ecosystem{WPPlugin, WPTheme, Composer, NPM} }

// ParseEcosystem reads an ecosystem ID. The shorthands "plugin" and
// "theme" are accepted on input and never printed.
func ParseEcosystem(s string) (Ecosystem, error) {
	switch s {
	case "wp-plugin", "plugin":
		return WPPlugin, nil
	case "wp-theme", "theme":
		return WPTheme, nil
	case "composer":
		return Composer, nil
	case "npm":
		return NPM, nil
	}
	return "", fmt.Errorf("unknown ecosystem %q: want wp-plugin, wp-theme, composer or npm", s)
}

// Ref names one package, with or without a version.
type Ref struct {
	Eco     Ecosystem
	Name    string
	Version string
}

// maxRefPart bounds a name or version. Real ones are far shorter (npm
// allows 214 characters); the cap keeps a hostile lockfile from making
// a reference that fills a terminal.
const maxRefPart = 256

// ParseRef reads "<eco>:<name>[@<version>]": "npm:@a/b@1.2.3",
// "wp-plugin:akismet" or "plugin:akismet@5.3.5". An npm scope's leading
// "@" is part of the name, so the version follows the last "@" after it.
func ParseRef(s string) (Ref, error) {
	ecoText, rest, ok := strings.Cut(s, ":")
	if !ok {
		return Ref{}, fmt.Errorf("package %q: want <ecosystem>:<name>[@<version>], e.g. npm:left-pad@1.3.0", s)
	}
	eco, err := ParseEcosystem(ecoText)
	if err != nil {
		return Ref{}, fmt.Errorf("package %q: %w", s, err)
	}
	r := Ref{Eco: eco, Name: rest}
	if i := strings.LastIndexByte(rest, '@'); i > 0 {
		r.Name, r.Version = rest[:i], rest[i+1:]
		if r.Version == "" {
			return Ref{}, fmt.Errorf("package %q: empty version after @", s)
		}
	}
	if err := checkName(eco, r.Name); err != nil {
		return Ref{}, fmt.Errorf("package %q: %w", s, err)
	}
	if err := checkPart("version", r.Version); err != nil {
		return Ref{}, fmt.Errorf("package %q: %w", s, err)
	}
	return r, nil
}

// checkName applies the shape each ecosystem gives its names. It is
// deliberately loose: the registries decide what exists, this only keeps
// out what can't be a name at all.
func checkName(eco Ecosystem, name string) error {
	if name == "" {
		return fmt.Errorf("empty name")
	}
	if err := checkPart("name", name); err != nil {
		return err
	}
	switch eco {
	case WPPlugin, WPTheme:
		if strings.ContainsAny(name, "/@") {
			return fmt.Errorf("a WordPress.org slug has no %q", "/")
		}
	case Composer:
		vendor, pkg, ok := strings.Cut(name, "/")
		if !ok || vendor == "" || pkg == "" || strings.Contains(pkg, "/") {
			return fmt.Errorf("a Composer name is <vendor>/<package>")
		}
	case NPM:
		if strings.HasPrefix(name, "@") {
			scope, pkg, ok := strings.Cut(name[1:], "/")
			if !ok || scope == "" || pkg == "" || strings.Contains(pkg, "/") {
				return fmt.Errorf("a scoped npm name is @<scope>/<name>")
			}
		} else if strings.Contains(name, "/") {
			return fmt.Errorf("an npm name has a / only after an @scope")
		}
	}
	return nil
}

func checkPart(what, s string) error {
	if len(s) > maxRefPart {
		return fmt.Errorf("%s is over %d bytes", what, maxRefPart)
	}
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.IsControl(r) || r == ':' {
			return fmt.Errorf("%s holds %q", what, r)
		}
	}
	return nil
}

// String writes the reference as ParseRef reads it, always with the full
// ecosystem ID: "npm:@a/b@1.2.3", or "npm:@a/b" without a version.
func (r Ref) String() string {
	if r.Version == "" {
		return string(r.Eco) + ":" + r.Name
	}
	return string(r.Eco) + ":" + r.Name + "@" + r.Version
}

// Unversioned returns r without its version, the key for "the same
// package" across versions.
func (r Ref) Unversioned() Ref { return Ref{Eco: r.Eco, Name: r.Name} }
