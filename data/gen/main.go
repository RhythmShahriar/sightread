// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Command gen refreshes Sightread's data packs. It is run by hand at
// release prep, never by tests or the build.
//
//	go run ./data/gen          # refresh data/names/*.json from public sources (network)
//	go run ./data/gen --pack   # write data/release/* from the embedded files (no network)
//
// Without --pack it asks WordPress.org for the most installed plugins and
// themes, the npm registry search for the most popular packages and
// Packagist for its most downloaded ones, writes the lists dated today
// and prints each file's sha256. Bump data/signals/pack.json when the
// rules or domains-ok.json change, then run --pack: the cli lane's
// goreleaser attaches data/release/* to every release and
// TestReleasePacksCurrent fails while they are stale.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cache"

	"github.com/RhythmShahriar/sightread/data"
)

// The list sizes (PRD 12.1, engineer.md 4.9).
const (
	wpPlugins = 1500
	wpThemes  = 500
	npmTop    = 5000
	packagist = 2000
)

func main() {
	root := flag.String("root", ".", "the module's folder")
	pack := flag.Bool("pack", false, "write data/release/* from the embedded files; no network")
	flag.Parse()
	var err error
	if *pack {
		err = writePacks(*root)
	} else {
		err = refresh(context.Background(), *root)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "gen:", err)
		os.Exit(1)
	}
}

// writePacks writes the two release assets.
func writePacks(root string) error {
	names, signals, err := data.ReleaseFiles()
	if err != nil {
		return err
	}
	for _, a := range []struct {
		name string
		b    []byte
	}{{data.NamesAsset, names}, {data.SignalsAsset, signals}} {
		name, b := a.name, a.b
		p := filepath.Join(root, "data", "release", name)
		if err := cache.WriteFile(p, b); err != nil {
			return err
		}
		if err := os.Chmod(p, 0o644); err != nil { //nolint:gosec // a release asset, read by everyone
			return err
		}
		fmt.Printf("%s  %s\n", sum(b), p)
	}
	return nil
}

// refresh fetches every list and writes it.
func refresh(ctx context.Context, root string) error {
	c := &http.Client{Timeout: time.Minute}
	version := time.Now().UTC().Format("2006.01.02")
	for _, l := range []struct {
		file  string
		fetch func(context.Context, *http.Client) ([]string, error)
	}{
		{"wp-plugins.json", wordpress("plugins", wpPlugins)},
		{"wp-themes.json", wordpress("themes", wpThemes)},
		{"npm.json", npm},
		{"packagist.json", packagistTop},
	} {
		names, err := l.fetch(ctx, c)
		if err != nil {
			return fmt.Errorf("%s: %w", l.file, err)
		}
		b, err := json.MarshalIndent(struct {
			Version string   `json:"version"`
			Names   []string `json:"names"`
		}{version, names}, "", " ")
		if err != nil {
			return err
		}
		p := filepath.Join(root, "data", "names", l.file)
		if err := cache.WriteFile(p, append(b, '\n')); err != nil {
			return err
		}
		fmt.Printf("%s  %s (%d names)\n", sum(b), p, len(names))
	}
	return nil
}

func sum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// getJSON fetches link into v.
func getJSON(ctx context.Context, c *http.Client, link string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, link, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "rhythm-sightread-gen")
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: HTTP %d", link, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(v)
}

// uniq appends the names of add not yet in out, up to limit.
func uniq(out []string, seen map[string]bool, add []string, limit int) []string {
	for _, n := range add {
		if len(out) == limit {
			break
		}
		if n != "" && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

// wordpress lists the most installed plugins or themes.
func wordpress(kind string, limit int) func(context.Context, *http.Client) ([]string, error) {
	return func(ctx context.Context, c *http.Client) ([]string, error) {
		action := "query_" + kind
		var out []string
		seen := map[string]bool{}
		for page := 1; len(out) < limit; page++ {
			q := url.Values{}
			q.Set("action", action)
			q.Set("request[browse]", "popular")
			q.Set("request[per_page]", "250")
			q.Set("request[page]", strconv.Itoa(page))
			var resp map[string]json.RawMessage
			if err := getJSON(ctx, c, "https://api.wordpress.org/"+kind+"/info/1.2/?"+q.Encode(), &resp); err != nil {
				return nil, err
			}
			var items []struct {
				Slug string `json:"slug"`
			}
			if err := json.Unmarshal(resp[kind], &items); err != nil {
				return nil, err
			}
			if len(items) == 0 {
				break
			}
			var slugs []string
			for _, it := range items {
				slugs = append(slugs, it.Slug)
			}
			out = uniq(out, seen, slugs, limit)
		}
		return out, nil
	}
}

// npm lists the packages the registry search ranks most popular. npm
// has no public "top by downloads" list; the search's popularity score
// is built from downloads.
func npm(ctx context.Context, c *http.Client) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for from := 0; len(out) < npmTop && from < 2*npmTop; from += 250 {
		q := url.Values{}
		q.Set("text", "not:insecure")
		q.Set("popularity", "1.0")
		q.Set("quality", "0.0")
		q.Set("maintenance", "0.0")
		q.Set("size", "250")
		q.Set("from", strconv.Itoa(from))
		var resp struct {
			Objects []struct {
				Package struct {
					Name string `json:"name"`
				} `json:"package"`
			} `json:"objects"`
		}
		if err := getJSON(ctx, c, "https://registry.npmjs.org/-/v1/search?"+q.Encode(), &resp); err != nil {
			return nil, err
		}
		if len(resp.Objects) == 0 {
			break
		}
		var names []string
		for _, o := range resp.Objects {
			names = append(names, o.Package.Name)
		}
		out = uniq(out, seen, names, npmTop)
	}
	return out, nil
}

// packagistTop lists Packagist's most downloaded packages.
func packagistTop(ctx context.Context, c *http.Client) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for page := 1; len(out) < packagist; page++ {
		var resp struct {
			Packages []struct {
				Name string `json:"name"`
			} `json:"packages"`
		}
		link := "https://packagist.org/explore/popular.json?per_page=100&page=" + strconv.Itoa(page)
		if err := getJSON(ctx, c, link, &resp); err != nil {
			return nil, err
		}
		if len(resp.Packages) == 0 {
			break
		}
		var names []string
		for _, p := range resp.Packages {
			names = append(names, p.Name)
		}
		out = uniq(out, seen, names, packagist)
	}
	return out, nil
}
