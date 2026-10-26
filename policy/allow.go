// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package policy

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
	"gopkg.in/yaml.v3"
)

// maxAllowBytes caps an allow file. An agency's shared file with
// thousands of entries is still well under a megabyte.
const maxAllowBytes = 16 << 20

// allowHeader starts an allow file that has no header comment yet.
const allowHeader = `# Versions someone reviewed. An entry matches only this exact archive (sha256).
# rhythm sightread allow writes this file; protect it with CODEOWNERS.
`

// allowFile is the YAML layout of allowed.yaml.
type allowFile struct {
	Allowed []core.AllowEntry `yaml:"allowed"`
}

// allowRecord is one loaded entry with where it came from.
type allowRecord struct {
	entry  core.AllowEntry
	ref    core.Ref // without a version
	source string   // the file, as messages show it
	// inChange marks an entry that the base ref of `changes` doesn't
	// have: the change itself added it, so it doesn't count.
	inChange bool
}

// AllowSet is the loaded allow entries. It implements core.AllowSet.
type AllowSet struct {
	records []allowRecord
	now     func() time.Time
}

// Match implements core.AllowSet. An entry matches when it is for the
// same package and version, has not expired and records the same
// sha256. An entry that the change under review added matches with
// counted false. When nothing matches, an entry that counts and records
// another sha256 for that version is returned as the conflict, which
// the scorer turns into approved-version-changed. A conflicting entry
// added by the change itself is no evidence of anything and is skipped.
// Match compares entries of either hash kind; MatchKind narrows that.
func (a *AllowSet) Match(eco core.Ecosystem, name, version, sha256 string) (*core.AllowEntry, bool, *core.AllowEntry) {
	return a.MatchKind(eco, name, version, sha256, "")
}

// MatchKind is Match for a hash of the given kind (core.HashArchive or
// core.HashManifest). An entry that records the other kind is skipped:
// an archive hash and a manifest hash of the same release always
// differ, so comparing them would raise approved-version-changed for
// bytes that never changed. An empty kind compares every entry.
func (a *AllowSet) MatchKind(eco core.Ecosystem, name, version, sha256, kind string) (*core.AllowEntry, bool, *core.AllowEntry) {
	if a == nil {
		return nil, false, nil
	}
	today := a.today()
	var match, conflict *allowRecord
	for i := range a.records {
		r := &a.records[i]
		if r.ref.Eco != eco || r.ref.Name != name || r.entry.Version != version {
			continue
		}
		if r.entry.Until != "" && r.entry.Until < today {
			continue
		}
		if kind != "" && hashKind(r.entry.Hash) != kind {
			continue
		}
		if strings.EqualFold(r.entry.SHA256, sha256) && sha256 != "" {
			if match == nil || match.inChange && !r.inChange {
				match = r
			}
			continue
		}
		if conflict == nil && !r.inChange {
			conflict = r
		}
	}
	if match != nil {
		return &match.entry, !match.inChange, nil
	}
	if conflict != nil {
		return nil, false, &conflict.entry
	}
	return nil, false, nil
}

// Source returns the file an entry Match returned came from, as
// messages show it, or "".
func (a *AllowSet) Source(e *core.AllowEntry) string {
	if a == nil {
		return ""
	}
	for i := range a.records {
		if &a.records[i].entry == e {
			return a.records[i].source
		}
	}
	return ""
}

// InThisChange reports whether an entry Match returned was added by the
// change under review.
func (a *AllowSet) InThisChange(e *core.AllowEntry) bool {
	if a == nil {
		return false
	}
	for i := range a.records {
		if &a.records[i].entry == e {
			return a.records[i].inChange
		}
	}
	return false
}

// Entries returns a copy of every loaded entry, expired ones included,
// in file order, for `allow list`.
func (a *AllowSet) Entries() []core.AllowEntry {
	if a == nil {
		return nil
	}
	out := make([]core.AllowEntry, len(a.records))
	for i, r := range a.records {
		out[i] = r.entry
	}
	return out
}

func (a *AllowSet) today() string {
	now := time.Now
	if a.now != nil {
		now = a.now
	}
	return now().Format(time.DateOnly)
}

var _ core.AllowSet = (*AllowSet)(nil)

// AllowPath returns the allow file a config names: allow_file, or
// .sightread/allowed.yaml in the project folder. A relative allow_file
// is relative to the project folder, the one holding .sightread.
func AllowPath(cfg *core.Config, configPath string) string {
	root := projectRoot(configPath)
	p := filepath.Join(Dir, AllowName)
	if cfg != nil && cfg.AllowFile != "" {
		p = cfg.AllowFile
	}
	if filepath.IsAbs(p) {
		return p
	}
	return filepath.Join(root, p)
}

// projectRoot is the folder a config's relative paths start from: the
// parent of .sightread for the usual config, the config's own folder for
// one passed with --config, the nearest folder above the working folder
// holding .sightread when there is no config, else the working folder.
func projectRoot(configPath string) string {
	if configPath != "" {
		dir := filepath.Dir(configPath)
		if filepath.Base(dir) == Dir {
			return filepath.Dir(dir)
		}
		return dir
	}
	wd, err := os.Getwd()
	if err != nil {
		return "."
	}
	for dir := wd; ; {
		if fi, err := os.Stat(filepath.Join(dir, Dir)); err == nil && fi.IsDir() {
			return dir
		}
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return wd
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return wd
		}
		dir = parent
	}
}

// LoadAllow reads the allow file and every allow_from file (see
// core.Policy). A missing allow file is an empty one; a missing
// allow_from file is an error, as the config promised it. With baseRef
// set, each file inside the project's git repository is also read at
// that ref through core.GetGitShow; an entry the ref doesn't have is
// marked as added by this change. A file the ref can't show counts as
// empty there, so a change can never approve its own update.
func (s *Store) LoadAllow(cfg *core.Config, configPath, baseRef string) (core.AllowSet, error) {
	set := &AllowSet{now: s.Now}
	main := AllowPath(cfg, configPath)
	files := []struct {
		path     string
		optional bool
	}{{main, true}}
	if cfg != nil {
		root := projectRoot(configPath)
		for _, p := range cfg.AllowFrom {
			if !filepath.IsAbs(p) {
				p = filepath.Join(root, p)
			}
			files = append(files, struct {
				path     string
				optional bool
			}{p, false})
		}
	}
	var repo string
	if baseRef != "" {
		if core.GetGitShow() == nil {
			return nil, fmt.Errorf("reading the allow file at %s: git show %w", baseRef, core.ErrNotLinked)
		}
		repo = gitRoot(projectRoot(configPath))
	}
	for _, f := range files {
		entries, err := readAllowFile(f.path)
		if errors.Is(err, fs.ErrNotExist) && f.optional {
			continue
		}
		if errors.Is(err, fs.ErrNotExist) {
			return nil, badFile(f.path, err)
		}
		if err != nil {
			return nil, err
		}
		var base map[string]bool
		checkBase := baseRef != ""
		if checkBase && repo != "" {
			if rel, ok := inside(repo, f.path); ok {
				base = baseEntries(repo, baseRef, rel)
			} else {
				// Outside the repository the change can't touch it.
				checkBase = false
			}
		}
		for _, e := range entries {
			ref, _ := core.ParseRef(e.Package)
			set.records = append(set.records, allowRecord{
				entry: e, ref: ref, source: display(f.path),
				inChange: checkBase && !base[baseKey(e)],
			})
		}
	}
	return set, nil
}

// readAllowFile reads and validates one allow file. A missing file
// returns an error that wraps fs.ErrNotExist.
func readAllowFile(p string) ([]core.AllowEntry, error) {
	data, err := readCapped(p, maxAllowBytes)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, err
	}
	if err != nil {
		return nil, badFile(p, err)
	}
	entries, err := parseAllow(data)
	if err != nil {
		return nil, configError(p, err.Error())
	}
	return entries, nil
}

// parseAllow decodes and validates allow file bytes.
func parseAllow(data []byte) ([]core.AllowEntry, error) {
	var f allowFile
	if err := decodeStrict(data, &f); err != nil {
		return nil, err
	}
	for i := range f.Allowed {
		if err := checkAllowEntry(&f.Allowed[i], fmt.Sprintf("entry %d", i+1)); err != nil {
			return nil, err
		}
	}
	return f.Allowed, nil
}

// baseEntries returns the keys of the entries the file has at ref. Any
// failure (no such file at the ref, not a repository, a broken file)
// gives none, which fails closed: nothing in the working tree counts.
func baseEntries(repo, ref, rel string) map[string]bool {
	show := core.GetGitShow()
	data, err := show(context.Background(), repo, ref, rel)
	if err != nil {
		return nil
	}
	entries, err := parseAllow(data)
	if err != nil {
		return nil
	}
	keys := make(map[string]bool, len(entries))
	for _, e := range entries {
		keys[baseKey(e)] = true
	}
	return keys
}

// baseKey identifies an entry for the pull request rule: what it allows,
// not why. Widening signals or until in the change makes a new entry.
func baseKey(e core.AllowEntry) string {
	sig := slices.Clone(e.Signals)
	slices.Sort(sig)
	return strings.Join([]string{e.Package, e.Version, strings.ToLower(e.SHA256), hashKind(e.Hash), strings.Join(sig, ","), e.Until}, "|")
}

func hashKind(h string) string {
	if h == "" {
		return core.HashArchive
	}
	return h
}

// gitRoot returns the nearest folder from dir up that holds .git, or "".
func gitRoot(dir string) string {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, ".git")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

// inside returns p relative to root with forward slashes, as git show
// takes it, when p is inside root.
func inside(root, p string) (string, bool) {
	abs, err := filepath.Abs(p)
	if err != nil {
		return "", false
	}
	rel, err := filepath.Rel(root, abs)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return filepath.ToSlash(rel), true
}

// checkAllowEntry validates one entry and normalises its package to the
// full ecosystem ID and its sha256 to lower case. which is "entry 3" or
// "the new entry".
func checkAllowEntry(e *core.AllowEntry, which string) error {
	if strings.TrimSpace(e.Package) == "" {
		return fmt.Errorf("%s needs a package such as npm:left-pad", which)
	}
	ref, err := core.ParseRef(strings.TrimSpace(e.Package))
	if err != nil {
		return fmt.Errorf("%s: %s", which, sanitize(err.Error()))
	}
	if ref.Version != "" {
		return fmt.Errorf("%s: package %s holds a version; put it in version", which, show(e.Package))
	}
	e.Package = ref.String()
	e.Version = strings.TrimSpace(e.Version)
	if e.Version == "" {
		return fmt.Errorf("%s (%s) needs a version", which, e.Package)
	}
	if len(e.Version) > 256 || strings.ContainsFunc(e.Version, func(r rune) bool {
		return r == '@' || r == ':' || unicode.IsSpace(r) || unicode.IsControl(r)
	}) {
		return fmt.Errorf("%s (%s): version %s is not a version", which, e.Package, show(e.Version))
	}
	which += " (" + e.Package + "@" + e.Version + ")"
	switch {
	case !isSHA256(e.SHA256):
		return fmt.Errorf("%s: sha256 must be the 64 hex characters of the reviewed archive's hash", which)
	case e.Hash != "" && e.Hash != core.HashArchive && e.Hash != core.HashManifest:
		return fmt.Errorf("%s: hash %s: want archive or manifest", which, show(e.Hash))
	case strings.TrimSpace(e.Reason) == "":
		return fmt.Errorf("%s needs a reason, so the next person knows why it is allowed", which)
	case strings.TrimSpace(e.By) == "":
		return fmt.Errorf("%s needs by, the person who reviewed it", which)
	case e.Date == "":
		return fmt.Errorf("%s needs a date, the day it was reviewed, such as 2026-10-20", which)
	}
	e.SHA256 = strings.ToLower(e.SHA256)
	if _, err := time.Parse(time.DateOnly, e.Date); err != nil {
		return fmt.Errorf("%s: date %s: want a date such as 2026-10-20", which, show(e.Date))
	}
	if e.Until != "" {
		if _, err := time.Parse(time.DateOnly, e.Until); err != nil {
			return fmt.Errorf("%s: until %s: want a date such as 2027-01-31", which, show(e.Until))
		}
	}
	if len(e.Signals) == 0 {
		e.Signals = nil // "signals: []" means every signal, as no key does
	}
	for _, id := range e.Signals {
		if err := knownSignal(id); err != nil {
			return fmt.Errorf("%s: signals: %w", which, err)
		}
		if core.Unignorable(id) {
			return fmt.Errorf("%s: signals: %s can't be allowed; it says the bytes are not the ones published or reviewed", which, id)
		}
	}
	return nil
}

func isSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
			return false
		}
	}
	return true
}

// AddAllow adds one entry to the allow file at path (see core.Policy),
// creating it with a header comment when it doesn't exist. The entry is
// validated as LoadAllow would; one with the same package, version and
// sha256 as an entry already there is refused. Whether the version may
// be allowed at all (E18) is decided by the allow command before this,
// as only the review knows the integrity result.
func (s *Store) AddAllow(path string, e core.AllowEntry) error {
	if err := checkAllowEntry(&e, "the new entry"); err != nil {
		return configError(path, err.Error())
	}
	return editAllow(path, func(entries []core.AllowEntry) ([]core.AllowEntry, error) {
		if i := findDup(entries, e); i >= 0 {
			return nil, configError(path, fmt.Sprintf("%s@%s with sha256 %s is already allowed (entry %d)", e.Package, e.Version, shortHash(e.SHA256), i+1))
		}
		return append(entries, e), nil
	})
}

// RemoveAllow removes the entries for r from the allow file: every
// version of the package when r has none, else that version.
func (s *Store) RemoveAllow(path string, r core.Ref) error {
	want := r.Unversioned().String()
	return editAllow(path, func(entries []core.AllowEntry) ([]core.AllowEntry, error) {
		kept := slices.DeleteFunc(slices.Clone(entries), func(e core.AllowEntry) bool {
			return e.Package == want && (r.Version == "" || e.Version == r.Version)
		})
		if len(kept) == len(entries) {
			return nil, configError(path, "no entry for "+r.String())
		}
		return kept, nil
	})
}

// ImportAllow adds the entries of the allow file from to the one at
// path, marking each with imported_from. It returns how many it added.
// Entries already there (same package, version and sha256) are skipped.
func (s *Store) ImportAllow(path, from string) (int, error) {
	in, err := readAllowFile(from)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, badFile(from, err)
	}
	if err != nil {
		return 0, err
	}
	added := 0
	err = editAllow(path, func(entries []core.AllowEntry) ([]core.AllowEntry, error) {
		added = 0
		for _, e := range in {
			if findDup(entries, e) >= 0 {
				continue
			}
			e.ImportedFrom = filepath.ToSlash(from)
			entries = append(entries, e)
			added++
		}
		return entries, nil
	})
	if err != nil {
		return 0, err
	}
	return added, nil
}

func findDup(entries []core.AllowEntry, e core.AllowEntry) int {
	for i, x := range entries {
		if x.Package == e.Package && x.Version == e.Version && strings.EqualFold(x.SHA256, e.SHA256) {
			return i
		}
	}
	return -1
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}

// editAllow reads the allow file at path under its lock, applies edit
// and writes the result atomically, sorted by package then version and
// under the file's header comment (or the default one).
func editAllow(path string, edit func([]core.AllowEntry) ([]core.AllowEntry, error)) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return badFile(path, err)
	}
	unlock, err := lockFile(path)
	if err != nil {
		return err
	}
	defer unlock()

	header := allowHeader
	var entries []core.AllowEntry
	data, err := readCapped(path, maxAllowBytes)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return badFile(path, err)
	default:
		if h := leadingComment(data); h != "" {
			header = h
		}
		if entries, err = parseAllow(data); err != nil {
			return configError(path, err.Error())
		}
	}
	if entries, err = edit(entries); err != nil {
		return err
	}
	sortEntries(entries)

	var b bytes.Buffer
	b.WriteString(header)
	enc := yaml.NewEncoder(&b)
	enc.SetIndent(2)
	if err := enc.Encode(allowFile{Allowed: entries}); err != nil {
		return err
	}
	if err := enc.Close(); err != nil {
		return err
	}
	return writeAtomic(path, b.Bytes())
}

// leadingComment returns the comment lines (and blank lines between
// them) at the top of a file.
func leadingComment(data []byte) string {
	var b strings.Builder
	for line := range strings.Lines(string(data)) {
		t := strings.TrimSpace(line)
		if t != "" && !strings.HasPrefix(t, "#") {
			break
		}
		b.WriteString(line)
	}
	s := strings.TrimRight(b.String(), "\n")
	if s == "" {
		return ""
	}
	return s + "\n"
}

// sortEntries orders entries by package, then version with the
// ecosystem's version scheme when one is linked, then sha256, so the
// file diffs cleanly.
func sortEntries(entries []core.AllowEntry) {
	slices.SortStableFunc(entries, func(a, b core.AllowEntry) int {
		if c := strings.Compare(a.Package, b.Package); c != 0 {
			return c
		}
		if a.Version != b.Version {
			ref, _ := core.ParseRef(a.Package)
			if vs := core.Versions(ref.Eco); vs != nil && vs.Valid(a.Version) && vs.Valid(b.Version) {
				if c := vs.Compare(a.Version, b.Version); c != 0 {
					return c
				}
			}
			return strings.Compare(a.Version, b.Version)
		}
		return strings.Compare(a.SHA256, b.SHA256)
	})
}

// writeAtomic writes data to a temp file beside path and renames it over
// path, so a reader never sees half a file. An existing file keeps its
// mode; a new one is 0644, as it is committed.
func writeAtomic(path string, data []byte) error {
	mode := fs.FileMode(0o644)
	if fi, err := os.Stat(path); err == nil {
		mode = fi.Mode().Perm()
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return badFile(path, err)
	}
	name := tmp.Name()
	defer func() { _ = os.Remove(name) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return badFile(path, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return badFile(path, err)
	}
	if err := tmp.Close(); err != nil {
		return badFile(path, err)
	}
	if err := os.Chmod(name, mode); err != nil {
		return badFile(path, err)
	}
	if err := os.Rename(name, path); err != nil {
		return badFile(path, err)
	}
	return nil
}

// Lock timing: how long an edit waits for another and when a lock file
// is old enough to belong to a process that died.
const (
	lockWait  = 15 * time.Second
	lockStale = time.Minute
	lockPoll  = 10 * time.Millisecond
)

// lockFile takes <path>.lock, created exclusively so it works between
// processes on every OS. It returns the function that releases it. A
// lock older than lockStale is taken over.
func lockFile(path string) (func(), error) {
	lp := path + ".lock"
	deadline := time.Now().Add(lockWait)
	for {
		f, err := os.OpenFile(lp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // beside the user's own allow file
		if err == nil {
			_, _ = fmt.Fprintf(f, "%d\n", os.Getpid())
			_ = f.Close()
			return func() { _ = os.Remove(lp) }, nil
		}
		if !errors.Is(err, fs.ErrExist) {
			return nil, badFile(lp, err)
		}
		if fi, err := os.Stat(lp); err == nil && time.Since(fi.ModTime()) > lockStale {
			_ = os.Remove(lp)
			continue
		}
		if time.Now().After(deadline) {
			return nil, &core.Error{Code: core.EBadConfig, Exit: cli.ExitUnavailable,
				What: display(path) + " is being edited by another rhythm sightread allow",
				Hint: []string{"wait for it to finish, or remove " + display(lp) + " if none is running"}}
		}
		time.Sleep(lockPoll)
	}
}
