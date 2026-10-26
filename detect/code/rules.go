// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package code

import (
	"bytes"
	"context"
	"embed"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/rhythm/kit/secrets"
	"gopkg.in/yaml.v3"

	"github.com/RhythmShahriar/sightread/core"
)

// Rules are signal patterns written as data in rules/*.yaml and in the
// folders given with --signals. They supplement the Go detectors, which
// work on the analyzer's features: a rule matches file text with RE2
// regexes and fires only where the Go detector for its signal stayed
// quiet, so a payload the analyzer folds is never reported twice. A rule
// only reads files; nothing it matches is ever run.
//
// A rule file holds one rule:
//
//	id: eval-base64                     # unique, lower case, digits and dashes
//	name: eval() of base64-decoded code # the evidence label
//	signal: decode-exec                 # the catalogue signal it fires
//	side: added                         # added (default): new files and added lines only; any: every file
//	severity: high                      # optional; the signal's default otherwise
//	files: ["**/*.php"]                 # globs, any of them
//	exclude: ["vendor/**"]              # globs, none of them
//	max_size: 16384                     # bytes; larger files are skipped
//	match:                              # every part given must hold
//	  filename: '(?i)\.bak$'            # regex on the file name
//	  regex: ['…', '…']                 # regexes on the content, all of them
//	  words: [FilesMan, b374k]          # words in the content, any of them (any case)
//	  magic: "\x89PNG"                  # the content starts with this
//	  not: ['…']                        # regexes on the content, none of them
//
// Globs use forward slashes and match the path inside the package,
// ignoring case. * and ? stay within one folder, ** matches any number of
// folders (none included); [a-z] classes work as in path.Match.
//
// Derived from tuner/local/rules.go (Rule, ParseRule, compile,
// literalHints, the glob matcher and snippet), with two new fields:
// signal and side.

//go:embed rules/*.yaml
var embeddedRules embed.FS

// Rule is one signal pattern. The fields are the rule file format
// described above.
type Rule struct {
	ID       string    `yaml:"id"`
	Name     string    `yaml:"name"`
	Signal   string    `yaml:"signal"`
	Side     string    `yaml:"side"`
	Severity string    `yaml:"severity"`
	Files    []string  `yaml:"files"`
	Exclude  []string  `yaml:"exclude"`
	MaxSize  int64     `yaml:"max_size"`
	Match    RuleMatch `yaml:"match"`

	// File is where the rule came from, for messages.
	File string `yaml:"-"`

	sev      cli.Severity
	files    []glob
	exclude  []glob
	filename *regexp.Regexp
	regex    []*regexp.Regexp
	hints    [][][][]byte // per regex, sets of lower-case literals; a match holds one of each set
	words    *regexp.Regexp
	lwords   [][]byte
	not      []*regexp.Regexp
}

// RuleMatch is what a rule looks for. Every part that is set must hold.
type RuleMatch struct {
	Filename string   `yaml:"filename"`
	Regex    []string `yaml:"regex"`
	Words    []string `yaml:"words"`
	Magic    string   `yaml:"magic"`
	Not      []string `yaml:"not"`
}

// Sides of Rule.Side.
const (
	SideAdded = "added"
	SideAny   = "any"
)

// ruleSnippet is how many bytes of matched text a finding shows before
// core.NewSnippet makes it safe.
const ruleSnippet = 80

// ruleID is the form of a rule ID.
var ruleID = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)

// RuleError is a rule file that can't be used: the file, the key the
// problem is in and what is wrong.
type RuleError struct{ File, Key, Problem string }

func (e *RuleError) Error() string {
	if e.Key == "" {
		return e.File + ": " + e.Problem
	}
	return e.File + ": " + e.Key + ": " + e.Problem
}

// ParseRule reads and checks one rule file. file names it in errors.
func ParseRule(file string, data []byte) (*Rule, error) {
	fail := func(key, format string, a ...any) error {
		return &RuleError{File: file, Key: key, Problem: fmt.Sprintf(format, a...)}
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, fail("", "%v", err)
	}
	if len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fail("", "a rule is a mapping of keys (id, name, signal, files, match...)")
	}
	if err := knownKeys(doc.Content[0], ruleKeys, ""); err != nil {
		return nil, &RuleError{File: file, Key: err.Key, Problem: err.Problem}
	}
	var r Rule
	if err := doc.Content[0].Decode(&r); err != nil {
		return nil, fail("", "%v", err)
	}
	r.File = file
	if err := r.compile(); err != nil {
		var re *RuleError
		if errors.As(err, &re) {
			re.File = file
		}
		return nil, err
	}
	return &r, nil
}

// ruleKeys are the keys of a rule; a map value lists the keys under it.
var ruleKeys = map[string]map[string]bool{
	"id": nil, "name": nil, "signal": nil, "side": nil, "severity": nil,
	"files": nil, "exclude": nil, "max_size": nil,
	"match": {"filename": true, "regex": true, "words": true, "magic": true, "not": true},
}

// knownKeys checks every key of a rule mapping against ruleKeys, so an
// error names the key and its line before the decoder sees it.
func knownKeys(n *yaml.Node, keys map[string]map[string]bool, parent string) *RuleError {
	seen := map[string]bool{}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		name := k.Value
		if parent != "" {
			name = parent + "." + k.Value
		}
		sub, ok := keys[k.Value]
		if !ok {
			return &RuleError{Key: parent, Problem: fmt.Sprintf("line %d: unknown key %q", k.Line, k.Value)}
		}
		if seen[k.Value] {
			return &RuleError{Key: name, Problem: fmt.Sprintf("line %d: given twice", k.Line)}
		}
		seen[k.Value] = true
		if sub != nil {
			if v.Kind != yaml.MappingNode {
				return &RuleError{Key: name, Problem: fmt.Sprintf("line %d: want a mapping", v.Line)}
			}
			subKeys := map[string]map[string]bool{}
			for s := range sub {
				subKeys[s] = nil
			}
			if err := knownKeys(v, subKeys, name); err != nil {
				return err
			}
		}
	}
	return nil
}

// compile checks a parsed rule and prepares its globs and regexes.
func (r *Rule) compile() error {
	fail := func(key, format string, a ...any) error {
		return &RuleError{File: r.File, Key: key, Problem: fmt.Sprintf(format, a...)}
	}
	info, known := core.Signal(r.Signal)
	switch {
	case !ruleID.MatchString(r.ID):
		return fail("id", "%q: use lower-case letters, digits and dashes", r.ID)
	case r.Name == "":
		return fail("name", "missing; it labels the evidence")
	case r.Signal == "":
		return fail("signal", "missing; name the catalogue signal the rule fires")
	case !known || info.Emitter != core.EmitDetect:
		return fail("signal", "%q is not a signal ID a detector emits (rhythm sightread signals lists them)", r.Signal)
	case len(r.Files) == 0:
		return fail("files", "missing; give at least one glob")
	case r.MaxSize < 0:
		return fail("max_size", "can't be negative")
	}
	switch r.Side {
	case "":
		r.Side = SideAdded
	case SideAdded, SideAny:
	default:
		return fail("side", "%q: want added or any", r.Side)
	}
	r.sev = info.Severity
	if r.Severity != "" {
		sev, err := cli.ParseFailOn(r.Severity)
		if err != nil || sev == cli.SeverityNone {
			return fail("severity", "%q: want info, low, medium, high or critical", r.Severity)
		}
		r.sev = sev
	}
	for _, g := range r.Files {
		if err := checkGlob(g); err != nil {
			return fail("files", "%v", err)
		}
		r.files = append(r.files, newGlob(g))
	}
	for _, g := range r.Exclude {
		if err := checkGlob(g); err != nil {
			return fail("exclude", "%v", err)
		}
		r.exclude = append(r.exclude, newGlob(g))
	}
	var err error
	compile := func(key, src string) *regexp.Regexp {
		re, e := regexp.Compile(src)
		if e != nil && err == nil {
			err = fail(key, "%q: %v", src, e)
		}
		return re
	}
	if r.Match.Filename != "" {
		r.filename = compile("match.filename", r.Match.Filename)
	}
	for _, src := range r.Match.Regex {
		r.regex = append(r.regex, compile("match.regex", src))
		r.hints = append(r.hints, literalHints(src))
	}
	for _, src := range r.Match.Not {
		r.not = append(r.not, compile("match.not", src))
	}
	if len(r.Match.Words) > 0 {
		var alts []string
		for _, w := range r.Match.Words {
			if w == "" {
				return fail("match.words", "can't hold an empty word")
			}
			alts = append(alts, regexp.QuoteMeta(w))
			r.lwords = append(r.lwords, bytes.ToLower([]byte(w)))
		}
		r.words = compile("match.words", `(?i)`+strings.Join(alts, "|"))
	}
	if err == nil && r.filename == nil && len(r.regex) == 0 && r.words == nil && r.Match.Magic == "" {
		return fail("match", "give filename, regex, words or magic; not alone exempts files, it can't match them")
	}
	return err
}

// literalHints returns what a match of the regex must contain, in lower
// case: for each run of top-level parts that are literals or sets of
// literal alternatives, the set (a match holds one of them). Sets with a
// word shorter than 3 bytes aren't worth checking. nil means no hint, so
// the regex always runs.
func literalHints(src string) [][][]byte {
	re, err := syntax.Parse(src, syntax.Perl)
	if err != nil {
		return nil
	}
	re = re.Simplify()
	for re.Op == syntax.OpCapture {
		re = re.Sub[0]
	}
	parts := []*syntax.Regexp{re}
	if re.Op == syntax.OpConcat {
		parts = re.Sub
	}
	// Adjacent literal parts join up: the parser turns
	// gzinflate|gzdecode into gz(?:inflate|decode); "decode" alone
	// would let every file with base64_decode through.
	var out [][][]byte
	var run [][]byte
	flush := func() {
		if run != nil && !slices.ContainsFunc(run, func(a []byte) bool { return len(a) < 3 }) {
			out = append(out, run)
		}
		run = nil
	}
	for _, p := range parts {
		alts := literalAlts(p)
		switch {
		case alts == nil:
			flush()
		case run == nil:
			run = alts
		case len(run)*len(alts) > 64:
			flush()
			run = alts
		default:
			var next [][]byte
			for _, prefix := range run {
				for _, x := range alts {
					next = append(next, append(slices.Clone(prefix), x...))
				}
			}
			run = next
		}
	}
	flush()
	return out
}

// literalAlts returns the lower-case literals one of which re matches,
// or nil when re is anything else.
func literalAlts(re *syntax.Regexp) [][]byte {
	for re.Op == syntax.OpCapture {
		re = re.Sub[0]
	}
	switch re.Op {
	case syntax.OpLiteral:
		return [][]byte{bytes.ToLower([]byte(string(re.Rune)))}
	case syntax.OpAlternate:
		var out [][]byte
		for _, sub := range re.Sub {
			a := literalAlts(sub)
			if a == nil {
				return nil
			}
			out = append(out, a...)
		}
		return out
	case syntax.OpConcat:
		// A factored alternation such as gz(?:inflate|decode).
		out := [][]byte{nil}
		for _, sub := range re.Sub {
			a := literalAlts(sub)
			if a == nil || len(out)*len(a) > 64 {
				return nil
			}
			var next [][]byte
			for _, prefix := range out {
				for _, x := range a {
					next = append(next, append(slices.Clone(prefix), x...))
				}
			}
			out = next
		}
		return out
	}
	return nil
}

// checkGlob reports a malformed glob.
func checkGlob(g string) error {
	if g == "" || strings.HasPrefix(g, "/") || strings.Contains(g, `\`) {
		return fmt.Errorf("glob %q: use a relative path with forward slashes", g)
	}
	for _, seg := range strings.Split(g, "/") {
		if _, err := path.Match(seg, ""); err != nil {
			return fmt.Errorf("glob %q: %w", g, err)
		}
	}
	return nil
}

// glob is a parsed glob (see the rules format).
type glob struct{ segs []string }

func newGlob(g string) glob { return glob{segs: strings.Split(strings.ToLower(g), "/")} }

// match matches a slash path, ignoring case.
func (g glob) match(p string) bool { return matchSegs(g.segs, strings.Split(strings.ToLower(p), "/")) }

// matchSegs reports whether the glob segments g match the path segments
// p, with ** standing for any number of segments.
func matchSegs(g, p []string) bool {
	for len(g) > 0 {
		if g[0] == "**" {
			for i := 0; i <= len(p); i++ {
				if matchSegs(g[1:], p[i:]) {
					return true
				}
			}
			return false
		}
		if len(p) == 0 {
			return false
		}
		if ok, _ := path.Match(g[0], p[0]); !ok {
			return false
		}
		g, p = g[1:], p[1:]
	}
	return len(p) == 0
}

// wants reports whether the rule looks at the file at p by its path.
func (r *Rule) wants(p string) bool {
	match := func(g glob) bool { return g.match(p) }
	if !slices.ContainsFunc(r.files, match) || slices.ContainsFunc(r.exclude, match) {
		return false
	}
	return r.filename == nil || r.filename.MatchString(path.Base(p))
}

// matches returns the offsets in b where the rule matches: the start of
// each match of the first regex (or of the words when there is no
// regex), or -1 alone for a rule that matches by name or magic. whole
// says b is the whole file; a not exemption holds only then, so padding
// can't push a payload past what was read.
func (r *Rule) matches(b []byte, whole bool) []int {
	if r.Match.Magic != "" && !bytes.HasPrefix(b, []byte(r.Match.Magic)) {
		return nil
	}
	lower := bytes.ToLower(b)
	if r.words != nil && !slices.ContainsFunc(r.lwords, func(w []byte) bool { return bytes.Contains(lower, w) }) {
		return nil
	}
	// Most files hold none of a regex's literal words; a lower-case
	// bytes.Contains is far cheaper than running the regex to find out.
	for _, sets := range r.hints {
		for _, set := range sets {
			if !slices.ContainsFunc(set, func(w []byte) bool { return bytes.Contains(lower, w) }) {
				return nil
			}
		}
	}
	for _, re := range r.regex[min(1, len(r.regex)):] {
		if !re.Match(b) {
			return nil
		}
	}
	if whole && slices.ContainsFunc(r.not, func(re *regexp.Regexp) bool { return re.Match(b) }) {
		return nil
	}
	var locs [][]int
	switch {
	case len(r.regex) > 0:
		locs = r.regex[0].FindAllIndex(b, -1)
	case r.words != nil:
		locs = r.words.FindAllIndex(b, -1)
	default:
		return []int{-1}
	}
	out := make([]int, len(locs))
	for i, l := range locs {
		out[i] = l[0]
	}
	return out
}

// ruleSnippetAt is the matched text from at to the end of its line, with
// secrets masked before it is cut to ruleSnippet bytes, so a cut can't
// reveal part of one. core.NewSnippet then makes it safe to print.
func ruleSnippetAt(b []byte, at int) string {
	end := at + 4*ruleSnippet
	if nl := bytes.IndexByte(b[at:], '\n'); nl >= 0 && at+nl < end {
		end = at + nl
	}
	end = min(end, len(b))
	s := secrets.Redact(strings.TrimRight(string(b[at:end]), "\r"))
	if len(s) > ruleSnippet {
		cut := ruleSnippet
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "…"
	}
	return s
}

// lineAt is the 1-based line of offset at in b.
func lineAt(b []byte, at int) int { return bytes.Count(b[:at], []byte("\n")) + 1 }

// LoadRules reads every rule file (*.yaml, not *_test.yaml) at the root
// of fsys. prefix is put before file names in errors. The first bad file
// or a second rule with an ID already taken is an error.
func LoadRules(fsys fs.FS, prefix string) ([]*Rule, error) {
	names, err := fs.Glob(fsys, "*.yaml")
	if err != nil {
		return nil, err
	}
	var out []*Rule
	seen := map[string]string{}
	for _, name := range names {
		if strings.HasSuffix(name, "_test.yaml") {
			continue
		}
		file := name
		if prefix != "" {
			file = filepath.Join(prefix, name)
		}
		data, err := fs.ReadFile(fsys, name)
		if err != nil {
			return nil, &RuleError{File: file, Problem: err.Error()}
		}
		r, err := ParseRule(file, data)
		if err != nil {
			return nil, err
		}
		if other, ok := seen[r.ID]; ok {
			return nil, &RuleError{File: file, Key: "id", Problem: fmt.Sprintf("%q is already used by %s", r.ID, other)}
		}
		seen[r.ID] = file
		out = append(out, r)
	}
	return out, nil
}

// builtinRules are the rules shipped in rules/. A bad one is a bug the
// tests catch, so it panics at start.
var builtinRules = sync.OnceValue(func() []*Rule {
	sub, err := fs.Sub(embeddedRules, "rules")
	if err != nil {
		panic(err)
	}
	rs, err := LoadRules(sub, "rules")
	if err != nil {
		panic("detect/code: " + err.Error())
	}
	return rs
})

// BuiltinRules returns the shipped rules.
func BuiltinRules() []*Rule { return builtinRules() }

// EmbeddedRules returns the shipped rule files (rules/*.yaml) as a file
// system, for package data, which packs them into the sightread-signals
// release asset.
func EmbeddedRules() fs.FS {
	sub, err := fs.Sub(embeddedRules, "rules")
	if err != nil {
		panic(err)
	}
	return sub
}

// RulePack returns the rule files of a newer verified signal pack and
// its version, or a nil fs.FS to use the shipped rules.
type RulePack func() (version string, files fs.FS)

// rulePack is the provider package data registers; nil until it does.
var rulePack struct {
	sync.RWMutex
	f RulePack
}

// packRules caches the parsed rules of each pack version.
var packRules sync.Map // string -> []*Rule

// SetRulePack makes the detector take its rules from f instead of the
// shipped ones whenever f returns files. Package data calls it at init
// so a pack fetched by `update` replaces the rules without a new binary,
// and --no-signal-updates (data.UseEmbedded) brings the shipped ones
// back. A pack whose rules don't parse, such as one written for a newer
// rule format, is ignored; the shipped rules stay.
func SetRulePack(f RulePack) {
	rulePack.Lock()
	defer rulePack.Unlock()
	rulePack.f = f
}

// ActiveRules returns the rules in force: a verified newer pack's, or the
// shipped ones.
func ActiveRules() []*Rule {
	rulePack.RLock()
	f := rulePack.f
	rulePack.RUnlock()
	if f == nil {
		return builtinRules()
	}
	version, files := f()
	if files == nil {
		return builtinRules()
	}
	if v, ok := packRules.Load(version); ok {
		return v.([]*Rule)
	}
	rs, err := LoadRules(files, "sightread-signals")
	if err != nil {
		rs = builtinRules()
	}
	packRules.Store(version, rs)
	return rs
}

// extraRules caches the rules of each --signals folder list.
var extraRules sync.Map // string -> []*Rule

// LoadRuleDirs reads the rule files of the --signals folders. A bad
// file is E12 (exit 2) naming the file and the key, so run calls it
// before any download. Rules of the same folders are read once.
func LoadRuleDirs(dirs []string) ([]*Rule, error) {
	if len(dirs) == 0 {
		return nil, nil
	}
	key := strings.Join(dirs, "\x00")
	if v, ok := extraRules.Load(key); ok {
		return v.([]*Rule), nil
	}
	var out []*Rule
	seen := map[string]string{}
	for _, r := range ActiveRules() {
		seen[r.ID] = r.File
	}
	for _, dir := range dirs {
		rs, err := LoadRules(os.DirFS(dir), dir)
		if err != nil {
			return nil, ruleConfigError(err)
		}
		for _, r := range rs {
			if other, ok := seen[r.ID]; ok {
				return nil, ruleConfigError(&RuleError{File: r.File, Key: "id", Problem: fmt.Sprintf("%q is already used by %s", r.ID, other)})
			}
			seen[r.ID] = r.File
		}
		out = append(out, rs...)
	}
	extraRules.Store(key, out)
	return out, nil
}

// ruleConfigError wraps a rule problem as E12.
func ruleConfigError(err error) error {
	return &core.Error{Code: core.EBadConfig, Exit: cli.ExitUsage, What: err.Error(),
		Hint: []string{"fix the rule file or leave its folder out of --signals"}, Err: err}
}

func init() { core.RegisterDetector(ruleDetector{}) }

// ruleDetector runs the rules on the candidate's files and reports what
// the Go detectors missed.
type ruleDetector struct{}

// ruleSignals are the signals the shipped rules fire. Extra rules may
// fire any detect signal; their findings pass through the same emitter.
var ruleSignals = []string{SigDecodeExec, SigEvalDynamic, SigAdminUserHidden, SigRemoteFetchExec}

func (ruleDetector) Info() core.DetectorInfo {
	return core.DetectorInfo{Name: "code-rules", Signals: ruleSignals}
}

// execSignals are one family for doubling: eval(base64_decode($x)) is
// decode-exec to the Go detector and could be eval-dynamic to a rule.
var execSignals = map[string]bool{SigRemoteFetchExec: true, SigDecodeExec: true, SigEvalDynamic: true}

func (ruleDetector) Detect(ctx context.Context, s *core.Subject, emit func(core.Finding)) {
	if s.NewTree == nil || s.NewTree.Blobs == nil {
		return
	}
	rules := ActiveRules()
	if s.Config != nil {
		// run reads and checks the folders before any download
		// (LoadRuleDirs), so this is a cache hit that reads no file; a
		// folder that fails here was reported there.
		if extra, err := LoadRuleDirs(s.Config.Signals.Dirs); err == nil {
			rules = slices.Concat(rules, extra)
		}
	}
	files := ruleFiles(s)
	if len(files) == 0 {
		return
	}
	goFindings := sync.OnceValue(func() []core.Finding { return goDetectorFindings(ctx, s) })
	out := newEmitter(s, emit)
	for _, p := range files {
		if ctx.Err() != nil {
			return
		}
		var want []*Rule
		for _, r := range rules {
			if (r.Side == SideAny || !p.same) && r.wants(p.path) {
				want = append(want, r)
			}
		}
		if len(want) == 0 {
			continue
		}
		f, _ := s.NewTree.Lookup(p.path)
		b, whole, ok := readBlob(s.NewTree, f)
		if !ok {
			continue
		}
		var oldLines map[string]bool
		if p.old != nil {
			if ob, _, ok := readBlob(s.OldTree, *p.old); ok {
				oldLines = lineSet(ob)
			}
		}
		for _, r := range want {
			if r.MaxSize > 0 && f.Size > r.MaxSize {
				continue
			}
			for _, at := range r.matches(b, whole) {
				fd, ok := r.finding(f, b, at, oldLines)
				if !ok || doubled(fd, goFindings()) {
					continue
				}
				out.send(fd)
			}
		}
	}
}

// ruleFile is a candidate file a rule may look at, with its installed
// copy when the file changed. same marks a file the update left alone:
// it has no added lines, so only side any rules look at it.
type ruleFile struct {
	path string
	old  *core.File
	same bool
}

// ruleFiles lists the candidate's regular files with the old copy of
// changed files.
func ruleFiles(s *core.Subject) []ruleFile {
	changed := map[string]*core.File{}
	added := map[string]bool{}
	if s.Diff != nil {
		for _, c := range s.Diff.Changes {
			switch {
			case c.New == nil || c.EOLOnly:
			case c.Kind == core.Added:
				added[c.New.Path] = true
			case c.Old != nil:
				changed[c.New.Path] = c.Old
			}
		}
	}
	var out []ruleFile
	for _, f := range s.NewTree.Files {
		if !f.Mode.IsRegular() {
			continue
		}
		rf := ruleFile{path: f.Path}
		switch {
		case added[f.Path] || s.OldTree == nil:
		case changed[f.Path] != nil:
			rf.old = changed[f.Path]
		default:
			rf.same = true
		}
		out = append(out, rf)
	}
	return out
}

// finding is the rule's finding for a match at offset at of file f, or
// false when the rule wants added lines and the matched line was there
// before. oldLines is nil for an added file.
func (r *Rule) finding(f core.File, b []byte, at int, oldLines map[string]bool) (core.Finding, bool) {
	line, ev := 1, r.Name
	if at >= 0 {
		if commentLine(lineText(b, at)) {
			return core.Finding{}, false
		}
		line = lineAt(b, at)
		ev = r.Name + ": " + ruleSnippetAt(b, at)
		if r.Side == SideAdded && oldLines != nil && oldLines[lineText(b, at)] {
			return core.Finding{}, false
		}
	} else if r.Side == SideAdded && oldLines != nil {
		// A name or magic match has no line: it is new only when the
		// file is.
		return core.Finding{}, false
	}
	fd := newFinding(r.Signal, core.Feature{Ev: core.Evidence{Path: f.Path, Line: line, EndLine: line}})
	fd.Severity = r.sev
	fd.Evidence = core.NewSnippet(ev)
	return fd, true
}

// commentLine reports whether a whole line is a comment, so nothing on
// it runs: it starts with //, # (not a #[ attribute) or a docblock *.
// A PHP line comment ends at ?>, so a line holding one is code.
func commentLine(l string) bool {
	if strings.Contains(l, "?>") {
		return false
	}
	switch {
	case strings.HasPrefix(l, "//"):
		return true
	case strings.HasPrefix(l, "#"):
		return !strings.HasPrefix(l, "#[")
	case l == "*":
		return true
	case strings.HasPrefix(l, "* "):
		return true
	}
	return false
}

// lineText is the trimmed text of the line holding offset at.
func lineText(b []byte, at int) string {
	start := bytes.LastIndexByte(b[:at], '\n') + 1
	end := len(b)
	if nl := bytes.IndexByte(b[at:], '\n'); nl >= 0 {
		end = at + nl
	}
	return string(bytes.TrimSpace(b[start:end]))
}

// lineSet is the set of trimmed lines of b. A matched line found in the
// installed copy is not added, wherever it moved to.
func lineSet(b []byte) map[string]bool {
	out := map[string]bool{}
	for l := range bytes.SplitSeq(b, []byte("\n")) {
		out[string(bytes.TrimSpace(l))] = true
	}
	return out
}

// readBlob reads up to the analysed size limit of f; whole says nothing
// was left out.
func readBlob(t *core.Tree, f core.File) ([]byte, bool, bool) {
	if t == nil || t.Blobs == nil {
		return nil, false, false
	}
	rc, err := t.Blobs.Open(f.SHA256)
	if err != nil {
		return nil, false, false
	}
	defer func() { _ = rc.Close() }()
	lim := core.DefaultLimits().EntryAnalysed
	b, err := io.ReadAll(io.LimitReader(rc, lim))
	if err != nil {
		return nil, false, false
	}
	return b, int64(len(b)) < lim || f.Size <= lim, true
}

// goDetectorFindings runs the Go code detectors, so a rule match where
// one already fired is dropped.
func goDetectorFindings(ctx context.Context, s *core.Subject) []core.Finding {
	var out []core.Finding
	for _, d := range []core.Detector{execDetector{}, wpDetector{}, netDetector{}} {
		d.Detect(ctx, s, func(f core.Finding) { out = append(out, f) })
	}
	return out
}

// doubled reports whether a Go detector already reported fd's signal (or
// another execution signal for an execution rule) on its file and line.
func doubled(fd core.Finding, goFindings []core.Finding) bool {
	return slices.ContainsFunc(goFindings, func(g core.Finding) bool {
		same := g.ID == fd.ID || execSignals[g.ID] && execSignals[fd.ID]
		return same && covers(g, fd)
	})
}
