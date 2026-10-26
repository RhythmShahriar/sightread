// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package run

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
)

// Limits on a sites file, read before it is decoded (SR-16): a YAML
// alias can expand a small file into a huge tree.
const (
	maxSitesFile  = 4 << 20
	maxYAMLNodes  = 100000
	maxYAMLDepth  = 64
	maxAliasNodes = 10000
)

// sitesFile is the shape of sites.yaml (PRD 8.3), shared by watch -l and
// all --sites.
type sitesFile struct {
	Sites []siteEntry `yaml:"sites"`
}

type siteEntry struct {
	Name        string `yaml:"name"`
	Path        string `yaml:"path"`
	WP          string `yaml:"wp"`
	TunerReport string `yaml:"tuner_report"`
	AllowFile   string `yaml:"allow_file"`
}

// LoadSites reads a sites file. Unknown keys, a site without a name or a
// source and a repeated name are E12, naming the file and the site.
// Relative paths are relative to the file's folder and ~ is the home
// folder.
func LoadSites(path string) ([]Site, error) {
	b, err := readCapped(path, maxSitesFile)
	if err != nil {
		return nil, sitesError(path, "can't be read (%v)", errors.Unwrap(err))
	}
	if err := checkYAML(b); err != nil {
		return nil, sitesError(path, "%v", err)
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var f sitesFile
	if err := dec.Decode(&f); err != nil && !errors.Is(err, io.EOF) {
		return nil, sitesError(path, "%s", yamlProblem(err))
	}
	if len(f.Sites) == 0 {
		return nil, sitesError(path, "lists no sites (want a sites: list with name and path, wp or tuner_report)")
	}
	dir := filepath.Dir(path)
	seen := map[string]bool{}
	var out []Site
	for i, e := range f.Sites {
		switch {
		case e.Name == "":
			return nil, sitesError(path, "site %d needs a name", i+1)
		case seen[e.Name]:
			return nil, sitesError(path, "site %s is listed twice", e.Name)
		case e.Path == "" && e.WP == "" && e.TunerReport == "":
			return nil, sitesError(path, "site %s needs a path, wp or tuner_report", e.Name)
		}
		seen[e.Name] = true
		s := Site{Name: e.Name, AllowFile: localPath(dir, e.AllowFile)}
		s.Inventory.Root = localPath(dir, e.Path)
		s.Inventory.TunerReport = localPath(dir, e.TunerReport)
		if e.WP != "" {
			argv, err := SplitCommand(e.WP)
			if err != nil {
				return nil, sitesError(path, "site %s: wp %q: %v", e.Name, e.WP, err)
			}
			s.Inventory.WP = argv
		}
		out = append(out, s)
	}
	return out, nil
}

// yamlProblem words a decode error for a person: the first problem,
// with an unknown key named as such.
func yamlProblem(err error) string {
	var te *yaml.TypeError
	if errors.As(err, &te) && len(te.Errors) > 0 {
		msg := te.Errors[0]
		if before, rest, ok := strings.Cut(msg, "field "); ok {
			if key, _, ok := strings.Cut(rest, " not found"); ok {
				return before + "unknown key " + key + " (want name, path, wp, tuner_report or allow_file)"
			}
		}
		return msg
	}
	return strings.TrimPrefix(err.Error(), "yaml: ")
}

func sitesError(path, format string, a ...any) error {
	return &core.Error{Code: core.EBadConfig, Exit: cli.ExitUsage, What: path + ": " + fmt.Sprintf(format, a...)}
}

// localPath expands ~ and makes p relative to dir; "" stays "".
func localPath(dir, p string) string {
	if p == "" {
		return ""
	}
	p = filepath.FromSlash(p)
	if rest, ok := strings.CutPrefix(p, "~"+string(filepath.Separator)); ok || p == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, rest)
		}
	}
	if !filepath.IsAbs(p) {
		return filepath.Join(dir, p)
	}
	return p
}

// readCapped reads at most limit bytes of path, failing past it.
func readCapped(path string, limit int64) ([]byte, error) {
	f, err := os.Open(path) //nolint:gosec // a file the user named
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("over %d MiB: %w", limit>>20, core.ErrTooLarge)
	}
	return b, nil
}

// checkYAML parses b into nodes and refuses a tree that is too deep, too
// big or whose aliases expand too far, before anything decodes it.
func checkYAML(b []byte) error {
	var root yaml.Node
	if err := yaml.Unmarshal(b, &root); err != nil {
		return errors.New(strings.TrimPrefix(err.Error(), "yaml: "))
	}
	nodes := 0
	var walk func(n *yaml.Node, depth int, budget *int) error
	walk = func(n *yaml.Node, depth int, budget *int) error {
		if depth > maxYAMLDepth {
			return fmt.Errorf("nests deeper than %d levels", maxYAMLDepth)
		}
		nodes++
		if nodes > maxYAMLNodes {
			return fmt.Errorf("has more than %d values", maxYAMLNodes)
		}
		if budget != nil {
			if *budget--; *budget < 0 {
				return fmt.Errorf("has an alias that expands to more than %d values", maxAliasNodes)
			}
		}
		if n.Kind == yaml.AliasNode && n.Alias != nil {
			if budget == nil {
				b := maxAliasNodes
				budget = &b
			}
			return walk(n.Alias, depth+1, budget)
		}
		for _, c := range n.Content {
			if err := walk(c, depth+1, budget); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(&root, 0, nil)
}
