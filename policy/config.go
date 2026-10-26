// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package policy

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/rhythm/kit/secrets"
	"github.com/RhythmShahriar/rhythm/kit/term"
	"github.com/RhythmShahriar/rhythm/kit/update"
	"github.com/RhythmShahriar/sightread/core"
)

// Dir is the folder that holds a project's Sightread files.
const Dir = ".sightread"

// ConfigName is the config file inside Dir.
const ConfigName = "config.yaml"

// AllowName is the default allow file inside Dir.
const AllowName = "allowed.yaml"

// maxConfigBytes caps a config file. A real one is a few hundred bytes.
const maxConfigBytes = 1 << 20

// LoadConfig finds and reads the config (see core.Policy). With none it
// returns an empty config. With explicit it reads that file, which must
// exist. Otherwise it looks for .sightread/config.yaml in start and each
// parent, stopping after a folder that holds .git (the top of the
// repository) or at the filesystem root. It returns an empty config
// when there is none. Expired ignore entries are dropped with a warning
// on s.Stderr.
func (s *Store) LoadConfig(start, explicit string, none bool) (*core.Config, string, error) {
	if none {
		return &core.Config{}, "", nil
	}
	p := explicit
	if p == "" {
		var err error
		if p, err = FindConfig(start); err != nil {
			return nil, "", err
		}
		if p == "" {
			return &core.Config{}, "", nil
		}
	}
	data, err := readCapped(p, maxConfigBytes)
	if err != nil {
		return nil, "", badFile(p, err)
	}
	cfg, err := s.ParseConfig(data, p)
	if err != nil {
		return nil, "", err
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		abs = p
	}
	return cfg, abs, nil
}

// FindConfig returns the nearest .sightread/config.yaml from start up,
// or "" when there is none. The search stops after the folder that holds
// .git, so a config above the repository never applies to it.
func FindConfig(start string) (string, error) {
	if start == "" {
		start = "."
	}
	dir, err := filepath.Abs(start)
	if err != nil {
		return "", err
	}
	for {
		p := filepath.Join(dir, Dir, ConfigName)
		fi, err := os.Stat(p)
		switch {
		case err == nil && fi.IsDir():
			return "", configError(p, "is a folder, not a config file")
		case err == nil:
			return p, nil
		case !errors.Is(err, fs.ErrNotExist):
			return "", badFile(p, err)
		}
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return "", nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", nil
		}
		dir = parent
	}
}

// ParseConfig decodes and validates a config. name is the file it came
// from, for messages. Every problem is an E12 *core.Error naming the
// file and the key.
func (s *Store) ParseConfig(data []byte, name string) (*core.Config, error) {
	var c core.Config
	if err := decodeStrict(data, &c); err != nil {
		return nil, configError(name, err.Error())
	}
	bad := func(format string, a ...any) error {
		return configError(name, fmt.Sprintf(format, a...))
	}

	if c.FailOn != "" {
		sev, err := cli.ParseFailOn(c.FailOn)
		if err != nil {
			// The kit text names the flag; here the key is at fault.
			return nil, bad("%s", strings.Replace(err.Error(), "--fail-on", "fail_on", 1))
		}
		c.FailOn = sev.String()
	}
	if c.MinConfidence != "" {
		conf, ok := core.ParseConfidence(strings.ToLower(strings.TrimSpace(c.MinConfidence)))
		if !ok {
			return nil, bad("min_confidence %s: want confirmed or likely", show(c.MinConfidence))
		}
		c.MinConfidence = string(conf)
	}
	if c.MinAge != "" {
		if _, err := update.ParseAge(c.MinAge); err != nil {
			return nil, bad("min_age: %s", sanitize(err.Error()))
		}
	}
	for i, e := range c.Ecosystems {
		eco, err := core.ParseEcosystem(string(e))
		if err != nil {
			return nil, bad("ecosystems: %s", sanitize(err.Error()))
		}
		c.Ecosystems[i] = eco
	}
	if err := checkSources(&c.Sources); err != nil {
		return nil, bad("%s", err)
	}
	for _, k := range sortedKeys(c.LocalFiles) {
		if _, err := path.Match(k, ""); err != nil {
			return nil, bad("local_files: bad pattern %s", show(k))
		}
		if strings.TrimSpace(c.LocalFiles[k]) == "" {
			return nil, bad("local_files.%s: needs a path such as ~/vendor-zips/%s-{version}.zip", k, k)
		}
	}
	for _, p := range c.AllowFrom {
		if strings.TrimSpace(p) == "" {
			return nil, bad("allow_from: a path is empty")
		}
	}
	for i, k := range c.TrustedKeys {
		k = strings.TrimSpace(k)
		if !trustedKey(k) {
			return nil, bad("trusted_keys %d: %s is not a key such as ed25519:<base64>; %s verify-report prints a report's key", i+1, show(k), cli.Name())
		}
		c.TrustedKeys[i] = k
	}
	if err := checkSignals(&c.Signals); err != nil {
		return nil, bad("%s", err)
	}
	active, err := checkIgnore(c.Ignore, s.now(), func(msg string) {
		fmt.Fprintf(s.stderr(), "%s: %s: %s\n", cli.Name(), display(name), msg)
	})
	if err != nil {
		return nil, bad("%s", err)
	}
	c.Ignore = active
	for i, p := range c.Soundcheck.Production {
		if err := checkSiteURL(p); err != nil {
			return nil, bad("soundcheck.production %d: %s", i+1, err)
		}
	}
	// The Soundcheck change classes (stage.ClassBroke and the others);
	// any other word would never trip the gate.
	switch c.Soundcheck.FailOn {
	case "", "broke", "new", "changed":
	default:
		return nil, bad("soundcheck.fail_on %q: want broke, new or changed", c.Soundcheck.FailOn)
	}
	return &c, nil
}

// checkSources applies the URL rule of PRD 8.1 to every mirror and
// private registry.
func checkSources(src *core.SourcesConfig) error {
	for _, u := range []struct{ key, v string }{
		{"wporg_api", src.WPOrgAPI}, {"wporg_downloads", src.WPOrgDownloads},
		{"wporg_svn", src.WPOrgSVN}, {"wporg_theme_svn", src.WPOrgThemeSVN},
		{"packagist", src.Packagist}, {"packagist_meta", src.PackagistMeta},
		{"github_api", src.GitHubAPI}, {"github_codeload", src.GitHubCodeload},
		{"osv", src.OSV}, {"npm.registry", src.NPM.Registry},
	} {
		if u.v == "" {
			continue
		}
		if err := checkSourceURL(u.v); err != nil {
			return fmt.Errorf("sources.%s: %w", u.key, err)
		}
	}
	for _, scope := range sortedKeys(src.NPM.Scopes) {
		name := strings.TrimPrefix(scope, "@")
		if !strings.HasPrefix(scope, "@") || name == "" || strings.ContainsAny(name, "/: ") {
			return fmt.Errorf("sources.npm.scopes: %s is not an npm scope; write it as \"@acme\"", show(scope))
		}
		if err := checkSourceURL(src.NPM.Scopes[scope]); err != nil {
			return fmt.Errorf("sources.npm.scopes.%s: %w", scope, err)
		}
	}
	for i, r := range src.Composer.Repositories {
		if err := checkSourceURL(r); err != nil {
			return fmt.Errorf("sources.composer.repositories %d: %w", i+1, err)
		}
	}
	return nil
}

// checkSourceURL allows https:// anywhere and http:// only on a loopback
// host, for the testbed and local mirrors. A URL with a user name or
// password is refused without echoing it: credentials come from the
// environment, never from a committed file.
func checkSourceURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || u.Opaque != "" {
		return fmt.Errorf("%s is not a URL such as https://registry.example", show(raw))
	}
	if u.User != nil {
		return errors.New("the URL holds a user name or password; set credentials in the environment instead")
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return nil
	case "http":
		if isLoopback(u.Hostname()) {
			return nil
		}
	}
	return fmt.Errorf("%s: want https://, or http:// on a loopback host (127.0.0.1, ::1, localhost)", show(raw))
}

func isLoopback(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// checkSiteURL checks a production site URL as Soundcheck takes it.
func checkSiteURL(raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("%s is not a site URL such as https://shop.example.com", show(raw))
	}
	if u.User != nil {
		return errors.New("the URL holds a user name or password; leave them out")
	}
	return nil
}

// checkSignals validates signals.severity and signals.domains_ok.
func checkSignals(sig *core.SignalConfig) error {
	for _, id := range sortedKeys(sig.Severity) {
		if err := knownSignal(id); err != nil {
			return fmt.Errorf("signals.severity: %w", err)
		}
		v := strings.ToLower(strings.TrimSpace(sig.Severity[id]))
		sev, err := cli.ParseFailOn(v)
		if err != nil || sev == cli.SeverityNone {
			return fmt.Errorf("signals.severity.%s %s: want info, low, medium, high or critical", id, show(sig.Severity[id]))
		}
		if core.Unignorable(id) && sev < cli.SeverityCritical {
			return fmt.Errorf("signals.severity.%s: %s can't be lowered below critical; it says the bytes are not the ones published or reviewed", id, id)
		}
		sig.Severity[id] = sev.String()
	}
	for _, d := range sig.DomainsOK {
		if strings.TrimSpace(d) == "" {
			return errors.New("signals.domains_ok: a host is empty")
		}
		if _, err := path.Match(d, ""); err != nil {
			return fmt.Errorf("signals.domains_ok: bad pattern %s", show(d))
		}
	}
	return nil
}

// checkIgnore validates the ignore list and returns the entries that
// still apply on now's date. An entry applies through its until day; an
// expired one is reported through warn and dropped.
func checkIgnore(list []core.IgnoreEntry, now time.Time, warn func(string)) ([]core.IgnoreEntry, error) {
	today := now.Format(time.DateOnly)
	var active []core.IgnoreEntry
	for i, ig := range list {
		which := fmt.Sprintf("ignore %d", i+1)
		ig.ID = strings.TrimSpace(ig.ID)
		if ig.ID != "" {
			which += " (" + quoteIfOdd(term.Sanitize(ig.ID)) + ")"
		}
		switch {
		case ig.ID == "":
			return nil, fmt.Errorf("%s: needs an id, the signal it hides, such as outbound-new-domain", which)
		case strings.TrimSpace(ig.Reason) == "":
			return nil, fmt.Errorf("%s: needs a reason, so the next person knows why it is accepted", which)
		}
		if err := knownSignal(ig.ID); err != nil {
			return nil, fmt.Errorf("%s: %w", which, err)
		}
		if core.Unignorable(ig.ID) {
			return nil, fmt.Errorf("%s: %s can't be ignored; it says the bytes are not the ones published or reviewed", which, ig.ID)
		}
		for _, p := range []string{ig.Package, ig.Path} {
			if _, err := path.Match(p, ""); err != nil {
				return nil, fmt.Errorf("%s: bad pattern %s", which, show(p))
			}
		}
		if ig.Until != "" {
			if _, err := time.Parse(time.DateOnly, ig.Until); err != nil {
				return nil, fmt.Errorf("%s: until %s: want a date such as 2027-03-31", which, show(ig.Until))
			}
			if ig.Until < today {
				warn(fmt.Sprintf("%s expired %s and no longer hides anything", which, ig.Until))
				continue
			}
		}
		ig.Reason = strings.TrimSpace(ig.Reason)
		active = append(active, ig)
	}
	return active, nil
}

// knownSignal fails for an ID that is not in the catalogue, suggesting
// the nearest one.
func knownSignal(id string) error {
	if _, ok := core.Signal(id); ok {
		return nil
	}
	msg := "no signal " + show(id)
	if s := cli.Suggest(id, core.SignalIDs()); s != "" {
		msg += " (did you mean " + s + "?)"
	} else {
		msg += " (rhythm sightread signals lists them)"
	}
	return errors.New(msg)
}

// configError is an E12 for a config or allow file.
func configError(file, what string) *core.Error {
	return &core.Error{Code: core.EBadConfig, Exit: cli.ExitUsage, What: display(file) + ": " + what}
}

// badFile turns a read error into an E12 that names the file without
// Go's "open <path>:" prefix.
func badFile(file string, err error) *core.Error {
	var what string
	switch {
	case errors.Is(err, fs.ErrNotExist):
		what = "no such file"
	case errors.Is(err, fs.ErrPermission):
		what = "can't be read (permission denied)"
	case errors.Is(err, errTooBig):
		what = err.Error()
	default:
		var pe *fs.PathError
		if errors.As(err, &pe) {
			err = pe.Err
		}
		what = "can't be read: " + err.Error()
	}
	return &core.Error{Code: core.EBadConfig, Exit: cli.ExitUsage, What: display(file) + ": " + what, Err: err}
}

var errTooBig = errors.New("too big")

// readCapped reads at most limit bytes of a file and fails when it holds
// more.
func readCapped(p string, limit int64) ([]byte, error) {
	f, err := os.Open(p) //nolint:gosec // the user's own config, allow or report file
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	if fi, err := f.Stat(); err == nil && fi.IsDir() {
		return nil, errors.New("is a folder, not a file")
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("is over %d MiB, more than a file of this kind ever needs: %w", limit>>20, errTooBig)
	}
	return data, nil
}

// display shows a path relative to the working folder when it is inside
// it, with forward slashes, so messages read ".sightread/config.yaml".
func display(p string) string {
	if p == "" {
		return p
	}
	if filepath.IsAbs(p) {
		if wd, err := os.Getwd(); err == nil {
			if rel, err := filepath.Rel(wd, p); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
				p = rel
			}
		}
	}
	return filepath.ToSlash(p)
}

// trustedKey reports whether k is a key ID as report/sign.go writes it:
// "ed25519:" and the base64 of a 32-byte public key.
func trustedKey(k string) bool {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(k, "ed25519:"))
	return strings.HasPrefix(k, "ed25519:") && err == nil && len(raw) == ed25519.PublicKeySize
}

// show quotes a value from a file for a message: secrets masked and
// control characters made visible.
func show(v string) string { return fmt.Sprintf("%q", sanitize(v)) }

func sanitize(v string) string { return term.Sanitize(secrets.Redact(v)) }

func sortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	return keys
}
