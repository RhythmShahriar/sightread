// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package data

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"testing/fstest"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/detect/code"
)

// fixturePort is the loopback port of the fixture release server (the
// detect lane's range is 31060-31079).
const fixturePort = "31060"

// newVersion is newer than any embedded pack.
const newVersion = "2099.01.01"

func TestEmbeddedPacksLoad(t *testing.T) {
	p := New(Options{Dir: t.TempDir()})
	n := p.Names()
	for _, c := range []struct {
		eco  core.Ecosystem
		name string
	}{{core.WPPlugin, "akismet"}, {core.WPTheme, "astra"}, {core.NPM, "react"}, {core.NPM, "@types/node"}, {core.Composer, "laravel/framework"}} {
		if !n.Popular(c.eco, c.name) {
			t.Errorf("%s %s is not popular", c.eco, c.name)
		}
	}
	if got := n.Near(core.NPM, "plain-crypto-js"); !slices.Contains(got, "crypto-js") {
		t.Errorf("Near(plain-crypto-js) = %q", got)
	}
	if got := n.Near(core.Composer, "laravell/framework"); !slices.Equal(got, []string{"laravel/framework"}) {
		t.Errorf("Near(laravell/framework) = %q", got)
	}
	for _, neg := range []string{"preact", "react-dom", "lodash.merge", "colors", "color"} {
		if got := n.Near(core.NPM, neg); got != nil {
			t.Errorf("Near(%s) = %q, want none: it is popular itself", neg, got)
		}
	}
	if !slices.Contains(p.DomainsOK(), "wordpress.org") || !slices.Contains(p.DomainsOK(), "fonts.gstatic.com") {
		t.Errorf("DomainsOK = %q", p.DomainsOK())
	}
	packs := p.Packs()
	if len(packs) != 2 || packs[0].Name != NamesPack || packs[1].Name != SignalsPack {
		t.Fatalf("Packs = %+v", packs)
	}
	for _, d := range packs {
		if !packVersion.MatchString(d.Version) || len(d.SHA256) != 64 {
			t.Errorf("pack %+v: want a YYYY.MM.DD version and a sha256", d)
		}
	}
	if v, files := p.rulePack(); files != nil {
		t.Errorf("rule pack %q in force with an empty cache", v)
	}
}

// TestEmbeddedListSizes holds the lists to their documented minimum. The
// seed lists are short of the release sizes; data/gen fills them.
func TestEmbeddedListSizes(t *testing.T) {
	names, err := buildNames(embedded)
	if err != nil {
		t.Fatal(err)
	}
	for eco, least := range map[core.Ecosystem]int{core.WPPlugin: 1500, core.WPTheme: 100, core.NPM: 900, core.Composer: 350} {
		if got := len(names.Lists[eco].Names); got < least {
			t.Errorf("%s list has %d names, want at least %d", eco, got, least)
		}
	}
}

// TestReleasePacksCurrent fails when data/release/* differs from what
// go run ./data/gen --pack writes now. The signals archive is compared
// unpacked, so a change in the Go version's deflate output alone does
// not fail it.
func TestReleasePacksCurrent(t *testing.T) {
	names, signals, err := ReleaseFiles()
	if err != nil {
		t.Fatal(err)
	}
	const hint = "; run go run ./data/gen --pack and commit data/release"
	got, err := os.ReadFile(filepath.Join("release", NamesAsset))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, names) {
		t.Errorf("release/%s is stale%s", NamesAsset, hint)
	}
	got, err = os.ReadFile(filepath.Join("release", SignalsAsset))
	if err != nil {
		t.Fatal(err)
	}
	a, errA := gunzip(got)
	b, errB := gunzip(signals)
	if errA != nil || errB != nil || !bytes.Equal(a, b) {
		t.Errorf("release/%s is stale%s", SignalsAsset, hint)
	}
}

// TestReleaseSignalsMatchRules ties the signals pack to detect/code's
// shipped rules, so a rule change can't ship without a new pack.
func TestReleaseSignalsMatchRules(t *testing.T) {
	_, signals, err := ReleaseFiles()
	if err != nil {
		t.Fatal(err)
	}
	pk, err := decodeSignals(signals)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := fs.Glob(code.EmbeddedRules(), "*.yaml")
	got, _ := fs.Glob(pk.Rules, "*.yaml")
	if !slices.Equal(got, want) {
		t.Errorf("pack rules %q, shipped %q", got, want)
	}
}

// stubVerifier stands in for kit sigverify: it accepts a bundle that
// reads "signed:" plus the checksums for RhythmShahriar/sightread only.
type stubVerifier struct{ calls atomic.Int32 }

func (v *stubVerifier) VerifyChecksums(_ context.Context, repo, version string, checksums, bundle []byte) (string, error) {
	v.calls.Add(1)
	if repo != Repo {
		return "", fmt.Errorf("repository %s is not %s", repo, Repo)
	}
	if string(bundle) != "signed:"+hexSum(checksums) {
		return "", errors.New("signature not valid")
	}
	return "release-go.yml@refs/heads/master v" + version, nil
}

// release is one fixture release.
type release struct {
	names, signals []byte
	sums           string // checksums.txt; computed when empty
	bundle         string // computed when empty
}

// fixtureServer serves GitHub's release API and the assets of rels by
// tag ("1.0.1"); latest is the release /releases/latest answers.
func fixtureServer(t *testing.T, latest string, rels map[string]*release) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	mux := http.NewServeMux()
	srv := httptest.NewUnstartedServer(mux)
	l, err := net.Listen("tcp", "127.0.0.1:"+fixturePort)
	if err != nil {
		t.Fatalf("fixture port: %v", err)
	}
	srv.Listener = l
	for tag, r := range rels {
		if r.sums == "" {
			r.sums = fmt.Sprintf("%s  %s\n%s  %s\n%s  rhythm-sightread_%s_linux_amd64.tar.gz\n",
				hexSum(r.names), NamesAsset, hexSum(r.signals), SignalsAsset, strings.Repeat("0", 64), tag)
		}
		if r.bundle == "" {
			r.bundle = "signed:" + hexSum([]byte(r.sums))
		}
		files := map[string][]byte{
			"checksums.txt": []byte(r.sums), "checksums.txt.sigstore.json": []byte(r.bundle),
			NamesAsset: r.names, SignalsAsset: r.signals,
		}
		for name, b := range files {
			mux.HandleFunc("/dl/v"+tag+"/"+name, func(w http.ResponseWriter, _ *http.Request) {
				hits.Add(1)
				_, _ = w.Write(b)
			})
		}
	}
	releaseJSON := func(tag string) string {
		var assets []string
		for _, name := range []string{"checksums.txt", "checksums.txt.sigstore.json", NamesAsset, SignalsAsset} {
			assets = append(assets, fmt.Sprintf(`{"name":%q,"browser_download_url":"http://127.0.0.1:%s/dl/v%s/%s"}`, name, fixturePort, tag, name))
		}
		return fmt.Sprintf(`{"tag_name":"v%s","published_at":"2026-10-20T00:00:00Z","assets":[%s]}`, tag, strings.Join(assets, ","))
	}
	mux.HandleFunc("/repos/"+Repo+"/releases/", func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		rest := strings.TrimPrefix(r.URL.Path, "/repos/"+Repo+"/releases/")
		tag := latest
		if rest != "latest" {
			tag = strings.TrimPrefix(rest, "tags/v")
		}
		if _, ok := rels[tag]; !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, releaseJSON(tag))
	})
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, &hits
}

// testPacks are a names and a signals asset newer than the embedded
// ones, at version v.
func testPacks(t *testing.T, v string) (names, signals []byte) {
	t.Helper()
	names, err := encodeNames(&namesPack{Version: v, Lists: map[core.Ecosystem]nameList{
		core.NPM: {Version: v, Names: []string{"fresh-pack-name"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	rule, err := fs.ReadFile(code.EmbeddedRules(), "eval-base64.yaml")
	if err != nil {
		t.Fatal(err)
	}
	rule = bytes.Replace(rule, []byte("id: eval-base64"), []byte("id: pack-only-rule"), 1)
	signals, err = buildSignals([]byte(`{"version": "`+v+`"}`), []byte(`{"version": "`+v+`", "domains": ["pack.test"]}`),
		fstest.MapFS{"pack-only-rule.yaml": {Data: rule}})
	if err != nil {
		t.Fatal(err)
	}
	return names, signals
}

func newTestPacks(t *testing.T, srv *httptest.Server, v *stubVerifier) *Packs {
	t.Helper()
	t.Setenv("RHYTHM_OFFLINE", "")
	opts := Options{Dir: filepath.Join(t.TempDir(), "data"), API: srv.URL, HTTP: srv.Client()}
	if v != nil {
		opts.Verifier = v
	}
	return New(opts)
}

func TestUpdateWritesVerifiedPacks(t *testing.T) {
	names, signals := testPacks(t, newVersion)
	srv, _ := fixtureServer(t, "1.0.1", map[string]*release{"1.0.1": {names: names, signals: signals}})
	v := &stubVerifier{}
	p := newTestPacks(t, srv, v)
	var log bytes.Buffer
	got, err := p.Update(t.Context(), &log)
	if err != nil {
		t.Fatal(err)
	}
	if v.calls.Load() != 1 {
		t.Errorf("verifier called %d times, want 1", v.calls.Load())
	}
	want := []string{NamesPack + " 1.0.1 " + hexSum(names), SignalsPack + " 1.0.1 " + hexSum(signals)}
	var have []string
	for _, d := range got {
		have = append(have, d.Name+" "+d.Version+" "+d.SHA256)
	}
	if !slices.Equal(have, want) {
		t.Errorf("Update reported %q, want %q", have, want)
	}
	if !strings.Contains(log.String(), "sightread-names 1.0.1 (data "+newVersion+") verified") {
		t.Errorf("progress = %q", log.String())
	}
	if !p.Names().Popular(core.NPM, "fresh-pack-name") || !slices.Equal(p.DomainsOK(), []string{"pack.test"}) {
		t.Error("the downloaded packs are not in force")
	}
	if _, files := p.rulePack(); files == nil {
		t.Error("the downloaded rule pack is not offered to detect/code")
	} else if _, err := fs.Stat(files, "pack-only-rule.yaml"); err != nil {
		t.Errorf("rule pack: %v", err)
	}

	// A second Packs over the same cache reads them back.
	again := New(Options{Dir: p.opts.Dir})
	if !again.Names().Popular(core.NPM, "fresh-pack-name") {
		t.Error("a new process does not see the cached packs")
	}
	// --no-signal-updates ignores the newer valid cached packs.
	again.UseEmbedded(true)
	if again.Names().Popular(core.NPM, "fresh-pack-name") || slices.Contains(again.DomainsOK(), "pack.test") {
		t.Error("UseEmbedded(true) still uses the cached packs")
	}
	if _, files := again.rulePack(); files != nil {
		t.Error("UseEmbedded(true) still offers the cached rule pack")
	}
	if again.Packs()[0].Version != embeddedPacks().namesInfo.Version {
		t.Errorf("UseEmbedded(true) reports %+v", again.Packs())
	}
	again.UseEmbedded(false)
	if !again.Names().Popular(core.NPM, "fresh-pack-name") {
		t.Error("UseEmbedded(false) does not bring the cached packs back")
	}
}

func TestActiveRulesFollowRulePack(t *testing.T) {
	names, signals := testPacks(t, newVersion)
	srv, _ := fixtureServer(t, "1.0.1", map[string]*release{"1.0.1": {names: names, signals: signals}})
	p := newTestPacks(t, srv, &stubVerifier{})
	if _, err := p.Update(t.Context(), io.Discard); err != nil {
		t.Fatal(err)
	}
	code.SetRulePack(p.rulePack)
	t.Cleanup(func() { code.SetRulePack(defaultPacks.rulePack) })
	ids := func() []string {
		var out []string
		for _, r := range code.ActiveRules() {
			out = append(out, r.ID)
		}
		return out
	}
	if got := ids(); !slices.Equal(got, []string{"pack-only-rule"}) {
		t.Errorf("rules with the pack = %q", got)
	}
	p.UseEmbedded(true)
	if got := ids(); slices.Contains(got, "pack-only-rule") || len(got) != len(code.BuiltinRules()) {
		t.Errorf("rules with UseEmbedded(true) = %q", got)
	}
}

// assertEmpty fails when the cache folder holds anything.
func assertEmpty(t *testing.T, dir string) {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	if len(entries) > 0 {
		t.Errorf("cache was written: %v", entries)
	}
}

func TestUpdateRefusesBadSignature(t *testing.T) {
	names, signals := testPacks(t, newVersion)
	srv, _ := fixtureServer(t, "1.0.1", map[string]*release{"1.0.1": {names: names, signals: signals, bundle: "forged"}})
	p := newTestPacks(t, srv, &stubVerifier{})
	_, err := p.Update(t.Context(), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "signature") {
		t.Fatalf("Update = %v, want a signature error", err)
	}
	assertEmpty(t, p.opts.Dir)
}

func TestUpdateRefusesAssetNotInChecksums(t *testing.T) {
	names, signals := testPacks(t, newVersion)
	sums := fmt.Sprintf("%s  %s\n%s  %s\n", strings.Repeat("a", 64), NamesAsset, hexSum(signals), SignalsAsset)
	srv, _ := fixtureServer(t, "1.0.1", map[string]*release{"1.0.1": {names: names, signals: signals, sums: sums}})
	p := newTestPacks(t, srv, &stubVerifier{})
	_, err := p.Update(t.Context(), io.Discard)
	if err == nil || !strings.Contains(err.Error(), "checksums.txt says") {
		t.Fatalf("Update = %v, want a checksum error", err)
	}
	assertEmpty(t, p.opts.Dir)
}

func TestUpdateWithoutVerifierFailsClosed(t *testing.T) {
	names, signals := testPacks(t, newVersion)
	srv, hits := fixtureServer(t, "1.0.1", map[string]*release{"1.0.1": {names: names, signals: signals}})
	p := newTestPacks(t, srv, nil)
	if _, err := p.Update(t.Context(), io.Discard); !errors.Is(err, errNoVerifier) {
		t.Fatalf("Update = %v, want errNoVerifier", err)
	}
	if hits.Load() != 0 {
		t.Errorf("%d requests made without a verifier", hits.Load())
	}
}

func TestUpdateOfflineKeepsPacks(t *testing.T) {
	names, signals := testPacks(t, newVersion)
	srv, _ := fixtureServer(t, "1.0.1", map[string]*release{"1.0.1": {names: names, signals: signals}})
	p := newTestPacks(t, srv, &stubVerifier{})
	if _, err := p.Update(t.Context(), io.Discard); err != nil {
		t.Fatal(err)
	}
	t.Setenv("RHYTHM_OFFLINE", "1")
	if _, err := p.Update(t.Context(), io.Discard); err == nil || !strings.Contains(err.Error(), "offline") {
		t.Fatalf("Update offline = %v, want an offline error", err)
	}
	if !p.Names().Popular(core.NPM, "fresh-pack-name") {
		t.Error("a failed update dropped the packs already there")
	}
}

func TestCachedPackWithBadHashIgnored(t *testing.T) {
	names, signals := testPacks(t, newVersion)
	srv, _ := fixtureServer(t, "1.0.1", map[string]*release{"1.0.1": {names: names, signals: signals}})
	p := newTestPacks(t, srv, &stubVerifier{})
	if _, err := p.Update(t.Context(), io.Discard); err != nil {
		t.Fatal(err)
	}
	edited := bytes.Replace(names, []byte("fresh-pack-name"), []byte("other-pack-name"), 1)
	if err := os.WriteFile(filepath.Join(p.opts.Dir, NamesAsset), edited, 0o600); err != nil {
		t.Fatal(err)
	}
	q := New(Options{Dir: p.opts.Dir})
	if q.Names().Popular(core.NPM, "other-pack-name") || q.Names().Popular(core.NPM, "fresh-pack-name") {
		t.Error("an edited cached pack was used")
	}
	if got := q.Packs()[0]; got != embeddedPacks().namesInfo {
		t.Errorf("names pack = %+v, want the embedded one", got)
	}
	if !slices.Contains(q.DomainsOK(), "pack.test") {
		t.Error("the intact signals pack was dropped with the bad names pack")
	}
}

func TestOlderCachedPackIgnored(t *testing.T) {
	names, signals := testPacks(t, "2000.01.01")
	srv, _ := fixtureServer(t, "1.0.1", map[string]*release{"1.0.1": {names: names, signals: signals}})
	p := newTestPacks(t, srv, &stubVerifier{})
	got, err := p.Update(t.Context(), io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != embeddedPacks().namesInfo || p.Names().Popular(core.NPM, "fresh-pack-name") {
		t.Errorf("an older release pack replaced the embedded one: %+v", got)
	}
}

func TestUpdatePinned(t *testing.T) {
	names, signals := testPacks(t, "2000.01.01")
	newNames, newSignals := testPacks(t, newVersion)
	srv, _ := fixtureServer(t, "1.0.1", map[string]*release{
		"1.0.0": {names: names, signals: signals},
		"1.0.1": {names: newNames, signals: newSignals},
	})
	p := newTestPacks(t, srv, &stubVerifier{})
	embeddedSignals := p.Packs()[1].Version

	// A pinned older pack is used although the embedded one is newer.
	got, err := p.UpdatePinned(t.Context(), io.Discard, map[string]string{NamesPack: "1.0.0", SignalsPack: embeddedSignals})
	if err != nil {
		t.Fatal(err)
	}
	if got[0].Version != "1.0.0" || got[0].SHA256 != hexSum(names) || got[1].Version != embeddedSignals {
		t.Errorf("pinned packs = %+v", got)
	}
	if !p.Names().Popular(core.NPM, "fresh-pack-name") {
		t.Error("the pinned names pack is not in force")
	}

	// Unmet pins are errors, so cli.Main exits 3.
	for pins, want := range map[string]string{
		NamesPack + "=9.9.9":      "finding the release",
		NamesPack + "=2001.01.01": "not a Sightread release version;",
		"other-pack=1.0.1":        `no pack is called "other-pack"`,
	} {
		name, v, _ := strings.Cut(pins, "=")
		_, err := p.UpdatePinned(t.Context(), io.Discard, map[string]string{name: v})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("pins %s: %v, want %q", pins, err, want)
		}
	}
}

func TestPinsAlreadyInPlaceNeedNoNetwork(t *testing.T) {
	p := New(Options{Dir: t.TempDir()}) // no verifier, no API: any request would fail
	cur := p.Packs()
	var log bytes.Buffer
	got, err := p.UpdatePinned(t.Context(), &log, map[string]string{NamesPack: cur[0].Version, SignalsPack: cur[1].Version})
	if err != nil || !slices.Equal(got, cur) {
		t.Fatalf("UpdatePinned = %+v, %v", got, err)
	}
	if !strings.Contains(log.String(), "is already in place") {
		t.Errorf("progress = %q", log.String())
	}
}

func TestCheckLink(t *testing.T) {
	for link, ok := range map[string]bool{
		"https://github.com/x":        true,
		"http://127.0.0.1:31060/x":    true,
		"http://localhost/x":          true,
		"http://example.test/x":       false,
		"file:///etc/passwd":          false,
		"ftp://example.test/x":        false,
		"https:///no-host":            false,
		"http://127.0.0.1.evil.test/": false,
	} {
		if err := checkLink(link); (err == nil) != ok {
			t.Errorf("checkLink(%q) = %v, want ok=%v", link, err, ok)
		}
	}
}

// tarGz builds a sightread-signals asset from raw entries.
func tarGz(t *testing.T, entries ...*tar.Header) []byte {
	t.Helper()
	var tb bytes.Buffer
	tw := tar.NewWriter(&tb)
	for _, h := range entries {
		body := []byte(`{"version": "2026.10.26", "domains": []}`)
		if h.Typeflag == tar.TypeReg {
			h.Size = int64(len(body))
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if h.Typeflag == tar.TypeReg {
			_, _ = tw.Write(body)
		}
	}
	_ = tw.Close()
	var zb bytes.Buffer
	zw := gzip.NewWriter(&zb)
	_, _ = zw.Write(tb.Bytes())
	_ = zw.Close()
	return zb.Bytes()
}

func TestDecodeSignalsRejects(t *testing.T) {
	reg := func(name string) *tar.Header { return &tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644} }
	for name, b := range map[string][]byte{
		"link":       tarGz(t, reg("pack.json"), reg("domains-ok.json"), &tar.Header{Name: "rules/x.yaml", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"}),
		"escape":     tarGz(t, reg("pack.json"), reg("domains-ok.json"), reg("rules/../../x.yaml")),
		"unexpected": tarGz(t, reg("pack.json"), reg("domains-ok.json"), reg("run.sh")),
		"nested":     tarGz(t, reg("pack.json"), reg("domains-ok.json"), reg("rules/a/x.yaml")),
		"twice":      tarGz(t, reg("pack.json"), reg("pack.json"), reg("domains-ok.json")),
		"no marker":  tarGz(t, reg("domains-ok.json")),
		"not gzip":   []byte("plain text"),
	} {
		if _, err := decodeSignals(b); err == nil {
			t.Errorf("%s: decodeSignals accepted it", name)
		}
	}
}

func TestDecodeNamesRejects(t *testing.T) {
	for name, s := range map[string]string{
		"bad version":   `{"version": "latest", "lists": {"npm": {"version": "2026.10.26", "names": ["a"]}}}`,
		"unknown eco":   `{"version": "2026.10.26", "lists": {"pypi": {"version": "2026.10.26", "names": ["a"]}}}`,
		"empty list":    `{"version": "2026.10.26", "lists": {"npm": {"version": "2026.10.26", "names": []}}}`,
		"blank name":    `{"version": "2026.10.26", "lists": {"npm": {"version": "2026.10.26", "names": [" "]}}}`,
		"unknown key":   `{"version": "2026.10.26", "lists": {}, "run": "x"}`,
		"no lists":      `{"version": "2026.10.26", "lists": {}}`,
		"trailing data": `{"version": "2026.10.26", "lists": {"npm": {"version": "2026.10.26", "names": ["a"]}}} {}`,
	} {
		if _, err := decodeNames([]byte(s)); err == nil {
			t.Errorf("%s: decodeNames accepted it", name)
		}
	}
}

func FuzzDecodeNames(f *testing.F) {
	names, _, err := ReleaseFiles()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(names[:2048])
	f.Add([]byte(`{"version": "2026.10.26", "lists": {"npm": {"version": "2026.10.26", "names": ["a"]}}}`))
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := decodeNames(b)
		if err != nil {
			return
		}
		if !packVersion.MatchString(p.Version) || len(p.Lists) == 0 {
			t.Fatalf("accepted a pack without version or lists: %+v", p)
		}
		_ = newNameIndex(p).Near(core.NPM, "x")
	})
}

func FuzzDecodeSignals(f *testing.F) {
	_, signals, err := ReleaseFiles()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(signals)
	f.Add([]byte{0x1f, 0x8b})
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := decodeSignals(b)
		if err != nil {
			return
		}
		if !packVersion.MatchString(p.Version) {
			t.Fatalf("accepted version %q", p.Version)
		}
		_, _ = code.LoadRules(p.Rules, "fuzz")
	})
}
