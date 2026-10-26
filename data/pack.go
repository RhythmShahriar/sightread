// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package data

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"maps"
	"path"
	"regexp"
	"slices"
	"strings"
	"testing/fstest"
	"time"

	"github.com/RhythmShahriar/sightread/core"
)

// The packs and the release assets that carry them. Every Sightread
// release attaches both assets (go run ./data/gen --pack writes them),
// listed in its signed checksums.txt.
const (
	NamesPack    = "sightread-names"
	SignalsPack  = "sightread-signals"
	NamesAsset   = "sightread-names.json"
	SignalsAsset = "sightread-signals.tar.gz"
)

// Size caps for what a release asset may hold. The real packs are a few
// hundred KB; the caps keep a hostile mirror from filling memory.
const (
	maxNamesBytes   = 8 << 20
	maxSignalsBytes = 4 << 20
	maxSignalsTar   = 16 << 20
	maxPackEntry    = 1 << 20
	maxPackEntries  = 512
)

// packVersion is a pack's own version, the date its data was taken.
var packVersion = regexp.MustCompile(`^\d{4}\.\d{2}\.\d{2}$`)

// nameList is one file of data/names: one ecosystem's popular names.
type nameList struct {
	Version string   `json:"version"`
	Names   []string `json:"names"`
}

// namesPack is the sightread-names asset: every list in one file. Its
// version is the newest of its lists.
type namesPack struct {
	Version string                      `json:"version"`
	Lists   map[core.Ecosystem]nameList `json:"lists"`
}

// signalsPack is the sightread-signals asset: the rule files, the
// known-safe hosts and the version marker of data/signals.
type signalsPack struct {
	Version string
	Domains []string
	Rules   fs.FS // the rule files at its root
}

// nameFiles are the embedded lists, by ecosystem.
var nameFiles = map[core.Ecosystem]string{
	core.WPPlugin: "names/wp-plugins.json",
	core.WPTheme:  "names/wp-themes.json",
	core.NPM:      "names/npm.json",
	core.Composer: "names/packagist.json",
}

// decodeList reads one list file and checks it.
func decodeList(file string, b []byte) (nameList, error) {
	var l nameList
	if err := strictJSON(b, &l); err != nil {
		return l, fmt.Errorf("%s: %w", file, err)
	}
	if !packVersion.MatchString(l.Version) {
		return l, fmt.Errorf("%s: version %q: want YYYY.MM.DD", file, l.Version)
	}
	if len(l.Names) == 0 {
		return l, fmt.Errorf("%s: names: empty", file)
	}
	for i, n := range l.Names {
		if strings.TrimSpace(n) == "" || len(n) > 214 {
			return l, fmt.Errorf("%s: names: entry %d: not a package name", file, i+1)
		}
	}
	return l, nil
}

// strictJSON decodes b into v, refusing unknown keys and trailing data.
func strictJSON(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("data after the JSON value")
	}
	return nil
}

// buildNames gathers the list files of fsys into one pack.
func buildNames(fsys fs.FS) (*namesPack, error) {
	p := &namesPack{Lists: map[core.Ecosystem]nameList{}}
	for _, eco := range core.Ecosystems() {
		file, ok := nameFiles[eco]
		if !ok {
			continue
		}
		b, err := fs.ReadFile(fsys, file)
		if err != nil {
			return nil, err
		}
		l, err := decodeList(file, b)
		if err != nil {
			return nil, err
		}
		p.Lists[eco] = l
		p.Version = max(p.Version, l.Version)
	}
	return p, nil
}

// encodeNames writes the sightread-names asset. encoding/json sorts map
// keys, so the same lists always give the same bytes.
func encodeNames(p *namesPack) ([]byte, error) {
	b, err := json.MarshalIndent(p, "", " ")
	if err != nil {
		return nil, err
	}
	return append(b, '\n'), nil
}

// decodeNames reads a sightread-names asset and checks every list.
func decodeNames(b []byte) (*namesPack, error) {
	if len(b) > maxNamesBytes {
		return nil, fmt.Errorf("%s: over %d bytes", NamesAsset, maxNamesBytes)
	}
	var raw struct {
		Version string                     `json:"version"`
		Lists   map[string]json.RawMessage `json:"lists"`
	}
	if err := strictJSON(b, &raw); err != nil {
		return nil, fmt.Errorf("%s: %w", NamesAsset, err)
	}
	if !packVersion.MatchString(raw.Version) {
		return nil, fmt.Errorf("%s: version %q: want YYYY.MM.DD", NamesAsset, raw.Version)
	}
	p := &namesPack{Version: raw.Version, Lists: map[core.Ecosystem]nameList{}}
	for k, v := range raw.Lists {
		eco := core.Ecosystem(k)
		if _, ok := nameFiles[eco]; !ok {
			return nil, fmt.Errorf("%s: lists: unknown ecosystem %q", NamesAsset, k)
		}
		l, err := decodeList(NamesAsset+": lists: "+k, v)
		if err != nil {
			return nil, err
		}
		p.Lists[eco] = l
	}
	if len(p.Lists) == 0 {
		return nil, fmt.Errorf("%s: lists: empty", NamesAsset)
	}
	return p, nil
}

// domainsFile is data/domains-ok.json.
type domainsFile struct {
	Version string   `json:"version"`
	Domains []string `json:"domains"`
}

// markerFile is data/signals/pack.json, the version of the rule pack.
// Bump it whenever detect/code/rules or domains-ok.json changes, so a
// newer pack wins over an older one on every machine.
type markerFile struct {
	Version string `json:"version"`
}

// The entries of the sightread-signals archive.
const (
	entryMarker  = "pack.json"
	entryDomains = "domains-ok.json"
	entryRules   = "rules/"
)

// buildSignals writes the sightread-signals asset: a gzip tar of
// pack.json, domains-ok.json and rules/*.yaml. Entries are sorted and
// carry zero times, root owner and mode 0644; the gzip header holds
// no name or time, so the same files always give the same bytes.
func buildSignals(marker, domains []byte, rules fs.FS) ([]byte, error) {
	files := map[string][]byte{entryMarker: marker, entryDomains: domains}
	names, err := fs.Glob(rules, "*.yaml")
	if err != nil {
		return nil, err
	}
	for _, n := range names {
		b, err := fs.ReadFile(rules, n)
		if err != nil {
			return nil, err
		}
		files[entryRules+n] = b
	}
	var tarBuf bytes.Buffer
	tw := tar.NewWriter(&tarBuf)
	for _, n := range slices.Sorted(maps.Keys(files)) {
		h := &tar.Header{
			Name: n, Mode: 0o644, Size: int64(len(files[n])), ModTime: time.Unix(0, 0).UTC(),
			Typeflag: tar.TypeReg, Format: tar.FormatUSTAR,
		}
		if err := tw.WriteHeader(h); err != nil {
			return nil, err
		}
		if _, err := tw.Write(files[n]); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	zw, err := gzip.NewWriterLevel(&out, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	zw.ModTime = time.Time{}
	if _, err := zw.Write(tarBuf.Bytes()); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// gunzip returns the tar inside a sightread-signals asset, refusing one
// that inflates past maxSignalsTar.
func gunzip(b []byte) ([]byte, error) {
	if len(b) > maxSignalsBytes {
		return nil, fmt.Errorf("%s: over %d bytes", SignalsAsset, maxSignalsBytes)
	}
	zr, err := gzip.NewReader(bytes.NewReader(b))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", SignalsAsset, err)
	}
	t, err := io.ReadAll(io.LimitReader(zr, maxSignalsTar+1))
	if err != nil {
		return nil, fmt.Errorf("%s: %w", SignalsAsset, err)
	}
	if len(t) > maxSignalsTar {
		return nil, fmt.Errorf("%s: unpacks to over %d bytes", SignalsAsset, maxSignalsTar)
	}
	return t, nil
}

// decodeSignals reads a sightread-signals asset. Only the three kinds of
// entry are allowed, as plain files with clean names; anything else (a
// link, a folder entry, ../, a second copy) makes the whole pack invalid.
func decodeSignals(b []byte) (*signalsPack, error) {
	t, err := gunzip(b)
	if err != nil {
		return nil, err
	}
	bad := func(format string, a ...any) error {
		return fmt.Errorf("%s: %s", SignalsAsset, fmt.Sprintf(format, a...))
	}
	tr := tar.NewReader(bytes.NewReader(t))
	rules := fstest.MapFS{}
	var marker, domains []byte
	seen := map[string]bool{}
	for n := 0; ; n++ {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, bad("%v", err)
		}
		if n >= maxPackEntries {
			return nil, bad("over %d entries", maxPackEntries)
		}
		name := h.Name
		if h.Typeflag != tar.TypeReg || path.Clean(name) != name || seen[name] {
			return nil, bad("entry %q is not a plain file or is given twice", name)
		}
		seen[name] = true
		if h.Size > maxPackEntry {
			return nil, bad("entry %q is over %d bytes", name, maxPackEntry)
		}
		body, err := io.ReadAll(io.LimitReader(tr, maxPackEntry))
		if err != nil {
			return nil, bad("%v", err)
		}
		switch {
		case name == entryMarker:
			marker = body
		case name == entryDomains:
			domains = body
		case strings.HasPrefix(name, entryRules) && path.Dir(name) == "rules" && path.Ext(name) == ".yaml":
			rules[strings.TrimPrefix(name, entryRules)] = &fstest.MapFile{Data: body, Mode: 0o644}
		default:
			return nil, bad("unexpected entry %q", name)
		}
	}
	if marker == nil || domains == nil {
		return nil, bad("missing %s or %s", entryMarker, entryDomains)
	}
	return parseSignals(marker, domains, rules)
}

// parseSignals checks the marker and the host list and puts the pack
// together.
func parseSignals(marker, domains []byte, rules fs.FS) (*signalsPack, error) {
	var m markerFile
	if err := strictJSON(marker, &m); err != nil {
		return nil, fmt.Errorf("%s: %w", entryMarker, err)
	}
	if !packVersion.MatchString(m.Version) {
		return nil, fmt.Errorf("%s: version %q: want YYYY.MM.DD", entryMarker, m.Version)
	}
	var d domainsFile
	if err := strictJSON(domains, &d); err != nil {
		return nil, fmt.Errorf("%s: %w", entryDomains, err)
	}
	for i, h := range d.Domains {
		if h == "" || strings.ContainsAny(h, " /:@") {
			return nil, fmt.Errorf("%s: domains: entry %d: %q is not a host pattern", entryDomains, i+1, h)
		}
	}
	return &signalsPack{Version: m.Version, Domains: d.Domains, Rules: rules}, nil
}
