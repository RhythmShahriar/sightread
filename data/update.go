// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package data

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cache"
	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/rhythm/kit/update"
)

// userAgent names Sightread to GitHub.
const userAgent = "rhythm-sightread-data"

// Update fetches the latest Sightread release's packs (`rhythm-sightread
// update`). It checks the Sigstore signature over the release's
// checksums.txt, then downloads both pack assets and checks each against
// it. Only when everything checks out are the files written, each
// atomically, so a failure or an offline machine keeps what is there.
// It reports the packs now in force.
func (p *Packs) Update(ctx context.Context, w io.Writer) ([]cli.DataPack, error) {
	return p.UpdatePinned(ctx, w, nil)
}

// UpdatePinned brings the packs to the versions pins names, pack name to
// version (update --pin, rhythm install --locked). A version is a
// Sightread release such as 1.0.1, or the version already in force (the
// embedded pack's date). Packs pins leaves out are refreshed as Update
// would. A pin that can't be met is an error, so Main exits 3.
func (p *Packs) UpdatePinned(ctx context.Context, w io.Writer, pins map[string]string) ([]cli.DataPack, error) {
	for name := range pins {
		if _, ok := assetOf[name]; !ok {
			return nil, fmt.Errorf("--pin: no pack is called %q (the packs are %s and %s)", name, NamesPack, SignalsPack)
		}
	}
	// Group the packs by the release they come from: "" is the latest.
	want := map[string][]string{}
	current := map[string]string{}
	for _, d := range p.Packs() {
		current[d.Name] = d.Version
	}
	for _, name := range []string{NamesPack, SignalsPack} {
		v, pinned := pins[name]
		switch {
		case !pinned:
			want[""] = append(want[""], name)
		case v == current[name]:
			fmt.Fprintf(w, "%s %s is already in place\n", name, v)
		case !releaseVersion(v):
			return nil, fmt.Errorf("%s %s: not a Sightread release version; this machine has %s", name, v, current[name])
		default:
			want[v] = append(want[v], name)
		}
	}
	p.mu.Lock()
	opts := p.opts
	p.mu.Unlock()
	if len(want) > 0 && opts.Verifier == nil {
		return nil, errNoVerifier
	}
	u := p.updater(opts)
	var got []recordEntry
	for _, tag := range slices.Sorted(maps.Keys(want)) {
		var rel *update.Release
		var err error
		if tag == "" {
			rel, err = u.Latest(ctx)
		} else {
			rel, err = u.ByTag(ctx, tag)
		}
		if err != nil {
			return nil, fmt.Errorf("finding the release: %w", err)
		}
		entries, err := p.fetch(ctx, w, u, opts, rel, want[tag], tag != "")
		if err != nil {
			return nil, err
		}
		got = append(got, entries...)
	}
	if err := p.store(got); err != nil {
		return nil, err
	}
	return p.Packs(), nil
}

// releaseTag matches a release version: 1.0.1, v1.0.1, 1.1.0-rc1.
var releaseTag = regexp.MustCompile(`^v?\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$`)

// releaseVersion reports whether v names a release. A pack's own date
// (2026.10.26) has the same shape and is not one.
func releaseVersion(v string) bool { return releaseTag.MatchString(v) && !packVersion.MatchString(v) }

// updater builds the kit release client for the packs' repository.
func (p *Packs) updater(opts Options) *update.Updater {
	api := opts.API
	if api == "" {
		api = os.Getenv("SIGHTREAD_GITHUB_API")
	}
	if api == "" {
		api = os.Getenv("RHYTHM_GITHUB_API")
	}
	return &update.Updater{
		Repo: Repo, Binary: "rhythm-sightread", UserAgent: userAgent,
		API: api, HTTP: opts.HTTP, Verifier: opts.Verifier,
	}
}

// fetch downloads names' assets from rel and checks them against the
// signed checksums. Nothing is written here.
func (p *Packs) fetch(ctx context.Context, w io.Writer, u *update.Updater, opts Options, rel *update.Release, names []string, pinned bool) ([]recordEntry, error) {
	// Checksums verifies the bundle first (u.Verifier is set) and fails
	// closed when it is missing or doesn't verify.
	sums, err := u.Checksums(ctx, rel)
	if err != nil {
		return nil, fmt.Errorf("release %s: %w", rel.Version, err)
	}
	var out []recordEntry
	for _, name := range names {
		asset := assetOf[name]
		link, ok := rel.Assets[asset]
		if !ok {
			return nil, fmt.Errorf("release %s has no %s", rel.Version, asset)
		}
		want, ok := sums[asset]
		if !ok {
			return nil, fmt.Errorf("release %s: checksums.txt does not list %s", rel.Version, asset)
		}
		b, err := download(ctx, opts.HTTP, link, maxNamesBytes)
		if err != nil {
			return nil, fmt.Errorf("downloading %s: %w", asset, err)
		}
		if got := hexSum(b); got != want {
			return nil, fmt.Errorf("release %s: %s has sha256 %s, checksums.txt says %s", rel.Version, asset, got, want)
		}
		version, err := packVersionOf(name, b)
		if err != nil {
			return nil, fmt.Errorf("release %s: %w", rel.Version, err)
		}
		out = append(out, recordEntry{Name: name, Release: rel.Version, Version: version, SHA256: want, Pinned: pinned, data: b})
		fmt.Fprintf(w, "%s %s (data %s) verified\n", name, rel.Version, version)
	}
	return out, nil
}

// packVersionOf parses a downloaded asset and returns its own version.
func packVersionOf(name string, b []byte) (string, error) {
	if name == NamesPack {
		n, err := decodeNames(b)
		if err != nil {
			return "", err
		}
		return n.Version, nil
	}
	s, err := decodeSignals(b)
	if err != nil {
		return "", err
	}
	return s.Version, nil
}

// store writes the verified assets and then the record, each
// atomically, then makes the packs read the cache again.
func (p *Packs) store(entries []recordEntry) error {
	if len(entries) == 0 {
		return nil
	}
	dir, err := p.dir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	keep := map[string]recordEntry{}
	for _, e := range readRecord(dir) {
		keep[e.Name] = e
	}
	for _, e := range entries {
		if err := cache.WriteFile(filepath.Join(dir, assetOf[e.Name]), e.data); err != nil {
			return err
		}
		keep[e.Name] = e
	}
	var r record
	for _, name := range slices.Sorted(maps.Keys(keep)) {
		r.Packs = append(r.Packs, keep[name])
	}
	b, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		return err
	}
	if err := cache.WriteFile(filepath.Join(dir, recordFile), append(b, '\n')); err != nil {
		return err
	}
	p.mu.Lock()
	p.st = nil
	p.mu.Unlock()
	return nil
}

// download reads link into memory, up to limit bytes. Only https is
// accepted, or http to a loopback host for tests.
func download(ctx context.Context, c *http.Client, link string, limit int64) ([]byte, error) {
	if err := checkLink(link); err != nil {
		return nil, err
	}
	if c == nil {
		c = &http.Client{Timeout: 2 * time.Minute, Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	resp, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("over %d bytes", limit)
	}
	return b, nil
}

// checkLink refuses anything but https, or http to a loopback host.
func checkLink(link string) error {
	u, err := url.Parse(link)
	if err != nil {
		return errors.New("not a valid URL")
	}
	switch {
	case u.Scheme == "https" && u.Host != "":
		return nil
	case u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "::1" || u.Hostname() == "localhost"):
		return nil
	}
	return fmt.Errorf("refusing to download over %q: %s://%s", u.Scheme, u.Scheme, u.Host)
}
