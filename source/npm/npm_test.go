// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package npm

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/RhythmShahriar/sightread/core"
)

// fixture is one package on a test registry.
type fixture struct {
	name     string
	tags     map[string]string
	docs     map[string]map[string]any // version to its per-version document
	times    map[string]string
	unpubAll bool
}

// serve writes the abbreviated and full packuments and every version
// document in the shapes registry.npmjs.org serves (fields copied by
// hand, values made up).
func (f *fixture) serve(t *testing.T, r *registry) {
	t.Helper()
	abbrVersions := map[string]any{}
	for v, d := range f.docs {
		abbrVersions[v] = map[string]any{"name": f.name, "version": v, "dist": d["dist"]}
		b, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		r.body["/"+pathName(f.name)+"/"+v] = b
	}
	abbr, _ := json.Marshal(map[string]any{"name": f.name, "modified": "2026-10-20T10:00:00.000Z", "dist-tags": f.tags, "versions": abbrVersions})
	tm := map[string]any{"created": "2016-03-01T00:00:00.000Z", "modified": "2026-10-20T10:00:00.000Z"}
	for v, at := range f.times {
		tm[v] = at
	}
	if f.unpubAll {
		tm["unpublished"] = map[string]any{"time": "2026-10-01T00:00:00.000Z", "versions": []string{"1.0.0"}}
	}
	full, _ := json.Marshal(map[string]any{"name": f.name, "dist-tags": f.tags, "versions": f.docs, "time": tm, "readme": strings.Repeat("x", 100)})
	r.abbr["/"+pathName(f.name)] = string(abbr)
	r.full["/"+pathName(f.name)] = string(full)
}

// leftPad sets up left-pad 1.3.0 and 1.2.0 on r, signed by sg (nil: no
// signature). It returns the fixture and the 1.3.0 tarball.
func leftPad(t *testing.T, r *registry, sg *signer) (*fixture, []byte) {
	t.Helper()
	tgz := makeTgz(t, map[string]string{"package.json": `{"name":"left-pad","version":"1.3.0"}`, "index.js": "module.exports = leftPad;"})
	f := &fixture{name: "left-pad", tags: map[string]string{"latest": "1.3.0"}, docs: map[string]map[string]any{},
		times: map[string]string{"1.2.0": "2017-11-01T00:00:00.000Z", "1.3.0": "2018-04-09T01:31:58.402Z"}}
	for _, v := range []string{"1.2.0", "1.3.0"} {
		dist := map[string]any{"tarball": r.url + "/left-pad/-/left-pad-" + v + ".tgz", "integrity": sri(tgz),
			"shasum": "0000000000000000000000000000000000000000", "fileCount": 2}
		if sg != nil {
			dist["signatures"] = []map[string]string{{"keyid": sg.id, "sig": sg.sign(t, "left-pad@"+v+":"+sri(tgz))}}
		}
		f.docs[v] = map[string]any{
			"name": "left-pad", "version": v, "license": "WTFPL", "main": "index.js",
			"repository":   map[string]any{"type": "git", "url": "git+ssh://git@github.com/stevemao/left-pad.git"},
			"scripts":      map[string]any{"test": "node test"},
			"_npmUser":     map[string]any{"name": "stevemao", "email": "steve@example.com"},
			"maintainers":  []any{map[string]any{"name": "stevemao", "email": "steve@example.com"}, "azer <azer@example.com>"},
			"dist":         dist,
			"dependencies": map[string]any{},
		}
		r.body["/left-pad/-/left-pad-"+v+".tgz"] = tgz
	}
	f.serve(t, r)
	return f, tgz
}

func meta(t *testing.T, s *Source, name, v string) *core.Meta {
	t.Helper()
	m, err := s.Meta(context.Background(), core.Ref{Eco: core.NPM, Name: name, Version: v})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func fetchOne(t *testing.T, s *Source, name, v string) (*core.Meta, *core.Tree, core.Integrity) {
	t.Helper()
	m := meta(t, s, name, v)
	tree, in, err := s.Fetch(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	return m, tree, in
}

func TestSignatureValid(t *testing.T) {
	r := newRegistry(t)
	sg := newSigner(t, "SHA256:test-key-1")
	leftPad(t, r, &sg)
	r.body["/-/npm/v1/keys"] = []byte(keysJSON(t, sg.entry(t, "")))
	pinExtra(t, sg.entry(t, ""))
	m, tree, in := fetchOne(t, New(env(t, r, nil, nil)), "left-pad", "")
	if in.By != core.BySignature || in.Method != MethodSignature {
		t.Fatalf("Integrity = %+v", in)
	}
	if m.Ref.Version != "1.3.0" || m.Publisher.Login != "stevemao" || len(m.Maintainers) != 2 || m.Maintainers[1].Login != "azer" ||
		m.License != "WTFPL" || m.Repository != "git+ssh://git@github.com/stevemao/left-pad.git" || m.HasInstallScript || m.Provenance != "" {
		t.Errorf("Meta = %+v", m)
	}
	if want := time.Date(2018, 4, 9, 1, 31, 58, 402e6, time.UTC); !m.Published.Equal(want) {
		t.Errorf("Published = %v", m.Published)
	}
	if len(m.History) != 1 || m.History[0].Version != "1.2.0" || m.History[0].Published.IsZero() {
		t.Errorf("History = %+v", m.History)
	}
	if tree.Root != "package/" || tree.HashKind != core.HashArchive {
		t.Errorf("tree root %q", tree.Root)
	}
	if _, ok := tree.Lookup("index.js"); !ok {
		t.Error("package/ not stripped")
	}
}

func TestSignatureRefused(t *testing.T) {
	good := newSigner(t, "SHA256:test-key-1")
	other := newSigner(t, "SHA256:test-key-2")
	tests := []struct {
		name   string
		signBy signer
		served []map[string]any
		pinned []map[string]any
		want   string
	}{
		{"wrong signature", other.withID("SHA256:test-key-1"), nil, nil, "the signature does not verify"},
		{"unknown key id", other, nil, nil, "key SHA256:test-key-2 is not both served and pinned"},
		{"served only", other, []map[string]any{good.entry(t, ""), other.entry(t, "")}, nil, "key SHA256:test-key-2 is not both served and pinned"},
		{"pinned only", other, []map[string]any{good.entry(t, "")}, []map[string]any{good.entry(t, ""), other.entry(t, "")}, "not both served and pinned"},
		{"same id other key", other.withID("SHA256:test-key-1"), []map[string]any{other.withID("SHA256:test-key-1").entry(t, "")}, nil, "not both served and pinned"},
		{"expired before publish", good, []map[string]any{good.entry(t, "2018-01-01T00:00:00.000Z")}, []map[string]any{good.entry(t, "")}, "the key expired on 2018-01-01"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := newRegistry(t)
			sg := tt.signBy
			leftPad(t, r, &sg)
			served := tt.served
			if served == nil {
				served = []map[string]any{good.entry(t, "")}
			}
			pinnedKeys := tt.pinned
			if pinnedKeys == nil {
				pinnedKeys = []map[string]any{good.entry(t, "")}
			}
			r.body["/-/npm/v1/keys"] = []byte(keysJSON(t, served...))
			pinExtra(t, pinnedKeys...)
			_, _, in := fetchOne(t, New(env(t, r, nil, nil)), "left-pad", "1.3.0")
			if in.By != core.ByFailed || in.Method != MethodSignatureFailed || !strings.Contains(in.Detail, tt.want) ||
				!slices.Equal(in.Mismatch, []string{"dist.signatures"}) {
				t.Errorf("Integrity = %+v, want failed with %q", in, tt.want)
			}
		})
	}
}

// withID is s under another key id, to sign as a key it is not.
func (s signer) withID(id string) signer { return signer{id: id, priv: s.priv} }

func TestRotatedKey(t *testing.T) {
	old := newSigner(t, "SHA256:old")
	cur := newSigner(t, "SHA256:new")
	r := newRegistry(t)
	leftPad(t, r, &cur)
	both := []map[string]any{old.entry(t, "2017-12-01T00:00:00.000Z"), cur.entry(t, "")}
	r.body["/-/npm/v1/keys"] = []byte(keysJSON(t, both...))
	pinExtra(t, both...)
	s := New(env(t, r, nil, nil))
	if _, _, in := fetchOne(t, s, "left-pad", "1.3.0"); in.By != core.BySignature {
		t.Errorf("signed by the new key: %+v", in)
	}
}

func TestTarballFlippedByte(t *testing.T) {
	r := newRegistry(t)
	sg := newSigner(t, "SHA256:test-key-1")
	_, tgz := leftPad(t, r, &sg)
	bad := append([]byte(nil), tgz...)
	bad[len(bad)/2] ^= 0x01
	r.body["/left-pad/-/left-pad-1.3.0.tgz"] = bad
	r.body["/-/npm/v1/keys"] = []byte(keysJSON(t, sg.entry(t, "")))
	pinExtra(t, sg.entry(t, ""))
	m := meta(t, New(env(t, r, nil, nil)), "left-pad", "1.3.0")
	_, in, err := New(env(t, r, nil, nil)).Fetch(context.Background(), m)
	if err != nil {
		t.Fatal(err)
	}
	if in.By != core.ByFailed || in.Method != MethodIntegrityFailed || !slices.Equal(in.Mismatch, []string{"dist.integrity"}) {
		t.Errorf("Integrity = %+v", in)
	}
}

func TestNoSignature(t *testing.T) {
	r := newRegistry(t)
	leftPad(t, r, nil)
	_, _, in := fetchOne(t, New(env(t, r, nil, nil)), "left-pad", "1.3.0")
	if in.By != core.ByIntegrity || in.Method != MethodIntegrity || in.Detail != "the registry sent no signature for this version" {
		t.Errorf("Integrity = %+v", in)
	}
	for _, q := range r.requests() {
		if strings.Contains(q, "/-/npm/v1/keys") {
			t.Error("keys fetched for an unsigned version")
		}
	}
}

func TestShasumOnly(t *testing.T) {
	r := newRegistry(t)
	f, tgz := leftPad(t, r, nil)
	d := f.docs["1.3.0"]["dist"].(map[string]any)
	delete(d, "integrity")
	d["shasum"] = sha1Hex(tgz)
	f.serve(t, r)
	_, _, in := fetchOne(t, New(env(t, r, nil, nil)), "left-pad", "1.3.0")
	if in.By != core.ByIntegrity || in.Method != "SHA-1 matches the dist.shasum the registry publishes; this version has no SHA-512 integrity" {
		t.Errorf("Integrity = %+v", in)
	}
	d["shasum"] = strings.Repeat("ab", 20)
	f.serve(t, r)
	_, _, in = fetchOne(t, New(env(t, r, nil, nil)), "left-pad", "1.3.0")
	if in.By != core.ByFailed || in.Method != MethodShasumFailed {
		t.Errorf("wrong shasum: %+v", in)
	}
	delete(d, "shasum")
	f.serve(t, r)
	_, _, in = fetchOne(t, New(env(t, r, nil, nil)), "left-pad", "1.3.0")
	if in.By != core.ByNone || in.Method != MethodNone {
		t.Errorf("no hash: %+v", in)
	}
}

func TestPrivateScope(t *testing.T) {
	pub := newRegistry(t)
	priv := newRegistry(t)
	tgz := makeTgz(t, map[string]string{"package.json": `{"name":"@acme/widget"}`, "binding.gyp": "{}"})
	f := &fixture{name: "@acme/widget", tags: map[string]string{"latest": "2.0.0"}, times: map[string]string{"2.0.0": "2026-09-01T00:00:00.000Z"},
		docs: map[string]map[string]any{"2.0.0": {"name": "@acme/widget", "version": "2.0.0",
			"dist": map[string]any{"tarball": priv.url + "/@acme/widget/-/widget-2.0.0.tgz", "integrity": sri(tgz),
				"attestations": map[string]any{"url": priv.url + "/-/npm/v1/attestations/@acme%2fwidget@2.0.0", "provenance": map[string]any{"predicateType": "https://slsa.dev/provenance/v1"}}}}}}
	priv.body["/@acme/widget/-/widget-2.0.0.tgz"] = tgz
	f.serve(t, priv)
	f.serve(t, pub) // a public namesake that must never be asked
	token := "npm_" + "fixture" + strings.Repeat("0", 10)
	s := New(env(t, pub, map[string]*registry{"@acme": priv}, map[string]string{"@acme": token}))
	m, tree, in := fetchOne(t, s, "@acme/widget", "")
	if !m.Private || m.Provenance != "slsa" || !m.HasInstallScript {
		t.Errorf("Meta = %+v", m)
	}
	if in.By != core.ByIntegrity || in.Detail != "the private registry signs nothing" {
		t.Errorf("Integrity = %+v", in)
	}
	if _, ok := tree.Lookup("binding.gyp"); !ok {
		t.Error("tree incomplete")
	}
	if got := pub.requests(); len(got) != 0 {
		t.Errorf("the public registry was asked about a private scope: %v", got)
	}
	if !slices.Contains(priv.requests(), "GET /@acme%2fwidget") || !slices.Contains(priv.requests(), "GET /@acme%2fwidget/2.0.0") {
		t.Errorf("private requests: %v", priv.requests())
	}
	if priv.auth["/@acme%2fwidget"] != "Bearer "+token {
		t.Error("the scope token was not sent to its registry")
	}
}

func TestTrustedPublisher(t *testing.T) {
	r := newRegistry(t)
	f, _ := leftPad(t, r, nil)
	f.docs["1.3.0"]["_npmUser"] = map[string]any{"name": "GitHub Actions", "email": "npm-oidc-no-reply@github.com",
		"trustedPublisher": map[string]any{"id": "github", "oidcConfigId": "oidc:x"}}
	f.serve(t, r)
	if m := meta(t, New(env(t, r, nil, nil)), "left-pad", "1.3.0"); m.Provenance != "trusted-publisher" {
		t.Errorf("Provenance = %q", m.Provenance)
	}
}

func TestTags(t *testing.T) {
	r := newRegistry(t)
	f, _ := leftPad(t, r, nil)
	f.docs["2.0.0-beta.1"] = f.docs["1.3.0"]
	f.docs["1.4.0"] = f.docs["1.3.0"]
	f.tags = map[string]string{"latest": "1.3.0", "next": "2.0.0-beta.1"}
	f.serve(t, r)
	s := New(env(t, r, nil, nil))
	tags, err := s.Tags(context.Background(), "left-pad")
	if err != nil {
		t.Fatal(err)
	}
	if tags["latest"] != "1.3.0" || tags["next"] != "2.0.0-beta.1" || len(tags) != 2 {
		t.Errorf("Tags = %v", tags)
	}
	if m := meta(t, s, "left-pad", ""); m.Ref.Version != "1.3.0" || m.Latest != "1.3.0" {
		t.Errorf("empty version should be dist-tags latest: %+v", m.Ref)
	}
	vs, _ := s.Versions(context.Background(), "left-pad")
	if !slices.Equal(vs, []string{"1.2.0", "1.3.0", "1.4.0", "2.0.0-beta.1"}) {
		t.Errorf("Versions = %v", vs)
	}
}

func TestErrors(t *testing.T) {
	t.Setenv("RHYTHM_INVOKED_AS", "rhythm sightread")
	r := newRegistry(t)
	f, _ := leftPad(t, r, nil)
	f.times["1.4.0"] = "2026-10-01T00:00:00.000Z" // published, then unpublished
	f.serve(t, r)
	s := New(env(t, r, nil, nil))
	ctx := context.Background()
	_, err := s.Meta(ctx, core.Ref{Eco: core.NPM, Name: "left-pad", Version: "1.4.0"})
	wantErr(t, err, core.EVersionMissing, "rhythm sightread npm: left-pad 1.4.0 was unpublished from 127.0.0.1\n"+
		"  newest: 1.3.0 · see them all: rhythm sightread npm left-pad --to list")
	_, err = s.Meta(ctx, core.Ref{Eco: core.NPM, Name: "left-pad", Version: "9.9.9"})
	wantErr(t, err, core.EVersionMissing, "rhythm sightread npm: left-pad has no version 9.9.9 on 127.0.0.1\n"+
		"  newest: 1.3.0 · see them all: rhythm sightread npm left-pad --to list")
	_, err = s.Versions(ctx, "lodahs")
	wantErr(t, err, core.EUnknownPackage, "rhythm sightread npm: 127.0.0.1 has no package \"lodahs\"\n"+
		"  if it is private, set its scope's registry under sources.npm.scopes in .sightread/config.yaml")
	gone := &fixture{name: "gone", tags: map[string]string{}, docs: map[string]map[string]any{}, unpubAll: true}
	gone.serve(t, r)
	_, err = s.Versions(ctx, "gone")
	wantErr(t, err, core.EVersionMissing, "rhythm sightread npm: every version of gone was unpublished from 127.0.0.1\n"+
		"  there is nothing to download; review a copy you trust with --to-file <tgz>")
}

func TestPinnedKeysVerifyRealSignatures(t *testing.T) {
	keys, err := parseKeys(pinnedJSON)
	if err != nil || len(keys) != 2 {
		t.Fatalf("keys.json: %d keys, %v", len(keys), err)
	}
	// Real registry.npmjs.org signatures, one per pinned key.
	for _, c := range []struct{ name, version, integrity, keyID, sig, published string }{
		{"ms", "0.1.0", "sha512-7uwYj3Xip4rOFpe5dDy+C25Ad0nAXkT4yAVMSpuh1UYR2Z7tAswSh4wb/HghRa533wofFUsvg54OQ90Mu1dCJg==",
			"SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA",
			"MEQCICUgMnbu4P+yWGs9zpkWDoZJsS3hgrwmM1OE23QR0d98AiAaQaF6n0DTpxKiluPo/kDhJPZM3eOe4ydmWBn7qdFQvA==", "2011-12-01T00:00:00Z"},
		{"bare-path", "3.0.1", "sha512-ghj2DSK/2e99a1anTVPCV4m4YIYtrbXhfM7V3D7XZLOTsybnYyaJloymGqssQc8l/or0UoDyRtNQkmkEF/ysgQ==",
			"SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U",
			"MEUCIBeiPxiPiajnqWTNG0WKVi6Urx3W0i06otw/B8riq2yPAiEA5HF1+89yE2f2rcazhSK5jlUk+IiAI5t5VW3wrv6vKok=", "2025-06-01T00:00:00Z"},
	} {
		at, _ := time.Parse(time.RFC3339, c.published)
		if err := verifySig(keys[c.keyID], c.name, c.version, c.integrity, c.sig, at); err != nil {
			t.Errorf("%s@%s: %v", c.name, c.version, err)
		}
		if err := verifySig(keys[c.keyID], c.name, "9.9.9", c.integrity, c.sig, at); err == nil {
			t.Errorf("%s: a signature verified for another version", c.name)
		}
	}
	// The expired key with no publish date can't be judged.
	k := keys["SHA256:jl3bwswu80PjjokCgh0o2w5c2U4LhQAE57gj9cz1kzA"]
	if err := verifySig(k, "ms", "0.1.0", "x", "AA==", time.Time{}); !errors.Is(err, errUndated) {
		t.Errorf("undated: %v", err)
	}
}

func TestExtraKeysOnlyOnLoopback(t *testing.T) {
	sg := newSigner(t, "SHA256:extra")
	pinExtra(t, sg.entry(t, ""))
	var notes []string
	note := func(f string, a ...any) { notes = append(notes, f) }
	if _, ok := pinned("https://registry.npmjs.org", note)["SHA256:extra"]; ok {
		t.Error("extra keys added for the public registry")
	}
	if len(notes) != 1 || !strings.Contains(notes[0], "ignored") {
		t.Errorf("notes = %v", notes)
	}
	if _, ok := pinned("http://127.0.0.1:31000", note)["SHA256:extra"]; !ok {
		t.Error("extra keys not added for a loopback mirror")
	}
}

func TestPathName(t *testing.T) {
	if got := pathName("@acme/widget"); got != "@acme%2fwidget" {
		t.Errorf("scoped: %q", got)
	}
	if got := pathName("left-pad"); got != "left-pad" {
		t.Errorf("plain: %q", got)
	}
}
