// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package data

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sync"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/rhythm/kit/config"
	"github.com/RhythmShahriar/rhythm/kit/update"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/detect/code"
	"github.com/RhythmShahriar/sightread/detect/meta"
)

//go:embed names/*.json domains-ok.json signals/pack.json
var embedded embed.FS

// Repo is the GitHub repository whose releases carry the packs.
const Repo = "RhythmShahriar/sightread"

// recordFile, in the cache folder, lists the packs `update` verified:
// their release, own version and the sha256 the signed checksums.txt
// gave. A cached file whose bytes no longer hash to that is ignored.
const recordFile = "packs.json"

// record is recordFile.
type record struct {
	Packs []recordEntry `json:"packs"`
}

// recordEntry is one verified pack in the cache.
type recordEntry struct {
	Name    string `json:"name"`
	Release string `json:"release"` // the Sightread release it came from
	Version string `json:"version"` // the pack's own YYYY.MM.DD
	SHA256  string `json:"sha256"`
	// Pinned packs came from update --pin and are used even when the
	// embedded copy is newer, so rhythm install --locked gets the data
	// it asked for.
	Pinned bool `json:"pinned,omitempty"`

	data []byte // the asset, between download and store
}

// Options configures a Packs. The zero value is the real setup.
type Options struct {
	// Dir is the cache folder of downloaded packs. Empty means
	// config.CacheDir("sightread")/data.
	Dir string
	// API is the GitHub API base. Empty means SIGHTREAD_GITHUB_API, then
	// RHYTHM_GITHUB_API, then https://api.github.com.
	API string
	// HTTP downloads the assets. Nil means a client with a 2 minute
	// timeout and the proxy from the environment.
	HTTP *http.Client
	// Verifier checks the Sigstore bundle over checksums.txt. Update
	// refuses to run without one.
	Verifier update.Verifier
}

// Packs is the data packs: the embedded ones, replaced by newer verified
// ones `update` put in the cache. It implements core.DataPacks and is
// safe for concurrent use.
type Packs struct {
	opts Options

	mu       sync.Mutex
	embedded bool   // UseEmbedded
	st       *state // nil until loaded, reset by UseEmbedded and Update
}

// state is the packs in force.
type state struct {
	names       *nameIndex
	namesInfo   cli.DataPack
	signals     *signalsPack
	signalsInfo cli.DataPack
	cached      bool // signals came from the cache
}

// New returns packs over opts.
func New(opts Options) *Packs { return &Packs{opts: opts} }

// defaultPacks is the registered instance.
var defaultPacks = New(Options{})

func init() {
	core.SetDataPacks(defaultPacks)
	code.SetRulePack(defaultPacks.rulePack)
}

// Default returns the registered packs.
func Default() *Packs { return defaultPacks }

// SetVerifier gives the registered packs the release signature check.
// The binary's main package calls it with a kit sigverify.Verifier;
// until it does, `update` fails closed.
func SetVerifier(v update.Verifier) {
	defaultPacks.mu.Lock()
	defer defaultPacks.mu.Unlock()
	defaultPacks.opts.Verifier = v
}

// embeddedPacks are the packs built into the binary, parsed once. A bad
// embedded file is a bug the tests catch, so it panics.
var embeddedPacks = sync.OnceValue(func() *state {
	names, err := buildNames(embedded)
	if err != nil {
		panic("data: " + err.Error())
	}
	nb, err := encodeNames(names)
	if err != nil {
		panic("data: " + err.Error())
	}
	sb, err := embeddedSignalsBytes()
	if err != nil {
		panic("data: " + err.Error())
	}
	sig, err := decodeSignals(sb)
	if err != nil {
		panic("data: " + err.Error())
	}
	return &state{
		names:       newNameIndex(names),
		namesInfo:   cli.DataPack{Name: NamesPack, Version: names.Version, SHA256: hexSum(nb)},
		signals:     sig,
		signalsInfo: cli.DataPack{Name: SignalsPack, Version: sig.Version, SHA256: hexSum(sb)},
	}
})

// embeddedSignalsBytes is the sightread-signals asset of the embedded
// files: the marker, the host list and detect/code's shipped rules.
func embeddedSignalsBytes() ([]byte, error) {
	marker, err := fs.ReadFile(embedded, "signals/pack.json")
	if err != nil {
		return nil, err
	}
	domains, err := fs.ReadFile(embedded, "domains-ok.json")
	if err != nil {
		return nil, err
	}
	return buildSignals(marker, domains, code.EmbeddedRules())
}

// ReleaseFiles returns the two release assets built from the embedded
// files, as go run ./data/gen --pack writes them.
func ReleaseFiles() (names, signals []byte, err error) {
	p, err := buildNames(embedded)
	if err != nil {
		return nil, nil, err
	}
	if names, err = encodeNames(p); err != nil {
		return nil, nil, err
	}
	signals, err = embeddedSignalsBytes()
	return names, signals, err
}

func hexSum(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// dir is the cache folder of downloaded packs.
func (p *Packs) dir() (string, error) {
	if p.opts.Dir != "" {
		return p.opts.Dir, nil
	}
	root, err := config.CacheDir("sightread")
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "data"), nil
}

// load returns the packs in force, reading the cache the first time.
func (p *Packs) load() *state {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.st == nil {
		p.st = p.read()
	}
	return p.st
}

// read puts the embedded packs together with any newer verified ones in
// the cache. Anything wrong with a cached pack (missing, edited, bad
// hash, can't be parsed) keeps the embedded one: the cache can only add
// newer data, never take the shipped data away.
func (p *Packs) read() *state {
	base := embeddedPacks()
	st := *base
	if p.embedded {
		return &st
	}
	dir, err := p.dir()
	if err != nil {
		return &st
	}
	for _, e := range readRecord(dir) {
		b, ok := readVerified(dir, e)
		if !ok {
			continue
		}
		switch e.Name {
		case NamesPack:
			names, err := decodeNames(b)
			if err == nil && names.Version == e.Version && (e.Pinned || names.Version > base.namesInfo.Version) {
				st.names = newNameIndex(names)
				st.namesInfo = cli.DataPack{Name: NamesPack, Version: e.Release, SHA256: e.SHA256}
			}
		case SignalsPack:
			sig, err := decodeSignals(b)
			if err == nil && sig.Version == e.Version && (e.Pinned || sig.Version > base.signalsInfo.Version) {
				st.signals, st.cached = sig, true
				st.signalsInfo = cli.DataPack{Name: SignalsPack, Version: e.Release, SHA256: e.SHA256}
			}
		}
	}
	return &st
}

// readRecord reads the cache record; a missing or broken one is empty.
func readRecord(dir string) []recordEntry {
	b, err := os.ReadFile(filepath.Join(dir, recordFile)) //nolint:gosec // our own cache folder
	if err != nil {
		return nil
	}
	var r record
	if json.Unmarshal(b, &r) != nil {
		return nil
	}
	return r.Packs
}

// assetOf maps a pack name to its file in the cache.
var assetOf = map[string]string{NamesPack: NamesAsset, SignalsPack: SignalsAsset}

// readVerified reads e's file from the cache when it still hashes to the
// recorded sha256.
func readVerified(dir string, e recordEntry) ([]byte, bool) {
	asset, ok := assetOf[e.Name]
	if !ok {
		return nil, false
	}
	b, err := os.ReadFile(filepath.Join(dir, asset)) //nolint:gosec // our own cache folder
	if err != nil || len(b) > maxNamesBytes || hexSum(b) != e.SHA256 {
		return nil, false
	}
	return b, true
}

// Names returns the popular names index.
func (p *Packs) Names() core.NameIndex { return p.load().names }

// DomainsOK returns the known-safe hosts of PRD 12.1.
func (p *Packs) DomainsOK() []string { return p.load().signals.Domains }

// Packs reports the packs in force: name, version (the release a
// downloaded pack came from, or the embedded pack's own date) and the
// sha256 of the pack's asset bytes.
func (p *Packs) Packs() []cli.DataPack {
	st := p.load()
	return []cli.DataPack{st.namesInfo, st.signalsInfo}
}

// UseEmbedded makes Names, DomainsOK and the rule pack come from the
// embedded files only (--no-signal-updates), or lets newer cached packs
// back in.
func (p *Packs) UseEmbedded(on bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.embedded, p.st = on, nil
}

// rulePack is what detect/code asks for its rules: the cached signal
// pack's rule files when one is in force, nil for the shipped rules.
func (p *Packs) rulePack() (string, fs.FS) {
	st := p.load()
	if !st.cached {
		return "", nil
	}
	return st.signalsInfo.SHA256, st.signals.Rules
}

// nameIndex answers typosquat questions with one TypoIndex per
// ecosystem.
type nameIndex struct {
	byEco map[core.Ecosystem]*meta.TypoIndex
}

func newNameIndex(p *namesPack) *nameIndex {
	ix := &nameIndex{byEco: map[core.Ecosystem]*meta.TypoIndex{}}
	for eco, l := range p.Lists {
		ix.byEco[eco] = meta.NewTypoIndex(eco, l.Names)
	}
	return ix
}

// Popular reports whether name is on eco's popular list.
func (n *nameIndex) Popular(eco core.Ecosystem, name string) bool {
	return n.byEco[eco].Popular(name)
}

// Near returns the popular names of eco that name is near.
func (n *nameIndex) Near(eco core.Ecosystem, name string) []string {
	return n.byEco[eco].Near(name)
}

// errNoVerifier is Update's answer when no signature check is linked.
var errNoVerifier = fmt.Errorf("the release signature can't be checked: this build has no Sigstore verifier, so no pack was downloaded")
