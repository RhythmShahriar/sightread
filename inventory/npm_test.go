// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package inventory

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

// npmWant is what a test expects of one Installed entry.
type npmWant struct {
	version, kind, constraint, path string
	direct, dev, private            bool
}

// readNPMFixture reads testdata/npm/<dir> with no .npmrc unless given.
func readNPMFixture(t *testing.T, dir string, opt Options) *Packages {
	t.Helper()
	if opt.NPMRC == nil {
		opt.NPMRC = []string{}
	}
	p, err := ReadNPM(filepath.Join("testdata/npm", dir), opt)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// checkNPM compares p's entries, keyed "name@version", with want.
func checkNPM(t *testing.T, p *Packages, want map[string]npmWant) {
	t.Helper()
	got := map[string]core.Installed{}
	for _, in := range p.Installed {
		got[in.Ref.Name+"@"+in.Ref.Version] = in
		if in.LockLine < 1 {
			t.Errorf("%s has no LockLine", in.Ref)
		}
		if in.Lockfile != p.Lockfile {
			t.Errorf("%s Lockfile %q, want %q", in.Ref, in.Lockfile, p.Lockfile)
		}
	}
	for key, w := range want {
		in, ok := got[key]
		if !ok {
			t.Errorf("%s missing; have %v", key, keys(got))
			continue
		}
		g := npmWant{in.Ref.Version, in.ResolvedKind, in.Constraint, in.Path, in.Direct, in.Dev, in.Private}
		if w.kind == "" {
			w.kind = core.ResolvedRegistry
		}
		if g != w {
			t.Errorf("%s:\n got %+v\nwant %+v", key, g, w)
		}
	}
	if len(got) != len(want) {
		t.Errorf("installed = %v, want %d entries", keys(got), len(want))
	}
}

func keys[V any](m map[string]V) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// reasons lists p's Not checked entries as "name reason".
func reasons(p *Packages) string {
	var out []string
	for _, nc := range p.NotChecked {
		out = append(out, nc.Name+" "+string(nc.Reason))
	}
	return strings.Join(out, ", ")
}

func TestPackageLockV1(t *testing.T) {
	p := readNPMFixture(t, "v1", Options{})
	checkNPM(t, p, map[string]npmWant{
		"debug@2.6.9":    {version: "2.6.9", constraint: "^2.6.0", path: "node_modules/debug", direct: true},
		"ms@2.0.0":       {version: "2.0.0", constraint: "2.0.0", path: "node_modules/debug/node_modules/ms"},
		"left-pad@1.3.0": {version: "1.3.0", constraint: "^1.3.0", path: "node_modules/left-pad", direct: true},
		"mocha@5.2.0":    {version: "5.2.0", constraint: "^5.2.0", path: "node_modules/mocha", direct: true, dev: true},
		"ms@2.1.1":       {version: "2.1.1", constraint: "2.1.1", path: "node_modules/mocha/node_modules/ms", dev: true},
		"my-fork@":       {kind: core.ResolvedGit, constraint: "github:acme/my-fork#v1.0.0", path: "node_modules/my-fork", direct: true},
	})
	if got := reasons(p); got != "my-fork vcs" {
		t.Errorf("not checked = %s", got)
	}
	lock, _ := os.ReadFile("testdata/npm/v1/package-lock.json")
	for _, in := range p.Installed {
		if in.Ref.Name == "left-pad" && in.LockLine != lineOf(t, lock, `"left-pad": {`) {
			t.Errorf("left-pad LockLine = %d", in.LockLine)
		}
		if in.Ref.Name == "ms" && in.Ref.Version == "2.1.1" && in.LockLine != lineOf(t, lock, `"ms": {
          "version": "2.1.1"`) {
			t.Errorf("nested ms LockLine = %d", in.LockLine)
		}
		if in.Ref.Name == "debug" && in.Integrity == "" {
			t.Error("debug lost its integrity")
		}
	}
}

func TestPackageLockV2Workspaces(t *testing.T) {
	p := readNPMFixture(t, "v2", Options{})
	checkNPM(t, p, map[string]npmWant{
		"express@4.19.2":     {version: "4.19.2", constraint: "^4.18.0", path: "node_modules/express", direct: true},
		"debug@2.6.9":        {version: "2.6.9", constraint: "2.6.9", path: "node_modules/express/node_modules/debug"},
		"debug@4.3.4":        {version: "4.3.4", path: "node_modules/debug"},
		"string-width@4.2.3": {version: "4.2.3", constraint: "npm:string-width@^4.2.0", path: "node_modules/string-width-cjs", direct: true},
		"typescript@5.4.5":   {version: "5.4.5", constraint: "~5.4.0", path: "node_modules/typescript", direct: true, dev: true},
		"clsx@2.1.1":         {version: "2.1.1", constraint: "^2.1.0", path: "packages/ui/node_modules/clsx", direct: true},
	})
	if len(p.NotChecked) != 0 {
		t.Errorf("not checked = %s; the workspace @app/ui is the project's own", reasons(p))
	}
	lock, _ := os.ReadFile("testdata/npm/v2/package-lock.json")
	for _, in := range p.Installed {
		if in.Ref.Name == "express" && in.LockLine != lineOf(t, lock, `"node_modules/express": {`) {
			t.Errorf("express LockLine = %d", in.LockLine)
		}
	}
}

func TestPackageLockV3SourcesAndScopes(t *testing.T) {
	opt := Options{NPMRC: []string{"testdata/npm/v3/.npmrc"}}
	p := readNPMFixture(t, "v3", opt)
	checkNPM(t, p, map[string]npmWant{
		"@acme/billing@2.3.1": {version: "2.3.1", constraint: "^2.0.0", path: "node_modules/@acme/billing", direct: true, private: true},
		"@acme/ui-kit@3.2.0":  {version: "3.2.0", constraint: "^3.2.0", path: "node_modules/@acme/ui-kit", direct: true, private: true},
		"fsevents@2.3.3":      {version: "2.3.3", constraint: "^2.3.3", path: "node_modules/fsevents", direct: true},
		"js-tokens@4.0.0":     {version: "4.0.0", path: "node_modules/js-tokens"},
		"loose-envify@1.4.0":  {version: "1.4.0", path: "node_modules/loose-envify"},
		"react@18.3.1":        {version: "18.3.1", constraint: "^18.3.1", path: "node_modules/react", direct: true},
		"xlsx@0.20.3": {version: "0.20.3", kind: core.ResolvedTarball, constraint: "https://cdn.sheetjs.com/xlsx-0.20.3/xlsx-0.20.3.tgz",
			path: "node_modules/xlsx", direct: true},
	})
	if got := reasons(p); got != "@acme/billing private, @acme/ui-kit private, xlsx tarball" {
		t.Errorf("not checked = %s", got)
	}
	// With the scope in config it is private but reviewed from there.
	opt.NPMScopes = map[string]string{"@acme": "https://npm.acme.example"}
	p = readNPMFixture(t, "v3", opt)
	if got := reasons(p); got != "xlsx tarball" {
		t.Errorf("configured scope: not checked = %s", got)
	}
	for _, in := range p.Installed {
		if strings.HasPrefix(in.Ref.Name, "@acme/") && !in.Private {
			t.Errorf("%s not private", in.Ref)
		}
	}
	// Negative: no .npmrc, no config: @acme is an ordinary scope and the
	// billing tarball's host is not a registry.
	p = readNPMFixture(t, "v3", Options{})
	if got := reasons(p); got != "@acme/billing tarball, xlsx tarball" {
		t.Errorf("no npmrc: not checked = %s", got)
	}
}

func TestNPMRCTokenNeverLeaks(t *testing.T) {
	token := coretest.FakeKey(coretest.KeyNPM)
	dir := t.TempDir()
	rc := filepath.Join(dir, ".npmrc")
	content := "//npm.acme.example/:_authToken=" + token + "\n" +
		"_auth=" + token + "\n" +
		"@acme:registry=https://user:" + token + "@npm.acme.example/\n" +
		"@other:registry=${PRIVATE_REGISTRY}\n" +
		"email=ann@example.com\n"
	if err := os.WriteFile(rc, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	lock, _ := os.ReadFile("testdata/npm/v3/package-lock.json")
	lock = []byte(strings.Replace(string(lock), "https://npm.acme.example/@acme/billing", "https://npm.acme.example/@acme/billing?token="+token+"&x=", 1))
	p, err := ParseNPMLock("package-lock.json", lock, nil, Options{NPMRC: []string{rc, filepath.Join(dir, "missing")}})
	if err != nil {
		t.Fatal(err)
	}
	if dump := fmt.Sprintf("%+v", p); strings.Contains(dump, token) || strings.Contains(dump, "ann@example.com") {
		t.Errorf("a credential reached the result: %s", dump)
	}
	scopes := readNPMRC([]string{rc}, &Packages{})
	if len(scopes) != 2 || scopes["@acme"] != "https://npm.acme.example/" || scopes["@other"] != "" {
		t.Errorf("scopes = %q", scopes)
	}
	if fmt.Sprint(scopes) != strings.ReplaceAll(fmt.Sprint(scopes), token, "") {
		t.Error("token in scopes")
	}
	// A broken lockfile's error doesn't carry the .npmrc either.
	_, err = ParseNPMLock("package-lock.json", []byte(`{"packages": `+token), nil, Options{NPMRC: []string{rc}})
	if err == nil || strings.Contains(err.Error(), token) {
		t.Errorf("error = %v", err)
	}
}

func TestPnpmLock(t *testing.T) {
	p := readNPMFixture(t, "pnpm9", Options{})
	checkNPM(t, p, map[string]npmWant{
		"js-tokens@4.0.0":    {version: "4.0.0"},
		"loose-envify@1.4.0": {version: "1.4.0"},
		"react@18.3.1":       {version: "18.3.1"},
		"react-dom@18.3.1":   {version: "18.3.1", constraint: "^18.3.1", path: "node_modules/react-dom", direct: true},
		"vitest@2.1.4":       {version: "2.1.4", constraint: "^2.1.0", path: "node_modules/vitest", direct: true, dev: true},
		"xlsx@0.20.3": {version: "0.20.3", kind: core.ResolvedTarball, constraint: "https://cdn.sheetjs.com/xlsx-0.20.3/xlsx-0.20.3.tgz",
			path: "node_modules/xlsx", direct: true},
		"zod@3.23.8": {version: "3.23.8", constraint: "^3.23.0", path: "packages/shared/node_modules/zod", direct: true},
	})
	if got := reasons(p); got != "xlsx tarball" {
		t.Errorf("not checked = %s", got)
	}
	lock, _ := os.ReadFile("testdata/npm/pnpm9/pnpm-lock.yaml")
	for _, in := range p.Installed {
		if in.Ref.Name == "zod" && in.LockLine != lineOf(t, lock, "  zod@3.23.8:\n    resolution") {
			t.Errorf("zod LockLine = %d", in.LockLine)
		}
		if in.Ref.Name == "react" && !strings.HasPrefix(in.Integrity, "sha512-") {
			t.Errorf("react integrity = %q", in.Integrity)
		}
	}

	p = readNPMFixture(t, "pnpm6", Options{})
	checkNPM(t, p, map[string]npmWant{
		"js-tokens@4.0.0":    {version: "4.0.0"},
		"left-pad@1.3.0":     {version: "1.3.0", constraint: "^1.3.0", path: "node_modules/left-pad", direct: true, dev: true},
		"loose-envify@1.4.0": {version: "1.4.0"},
		"my-fork@1.0.0":      {version: "1.0.0", kind: core.ResolvedGit, constraint: "github:acme/my-fork", path: "node_modules/my-fork", direct: true},
		"react@18.2.0":       {version: "18.2.0"},
		"react-dom@18.2.0":   {version: "18.2.0", constraint: "^18.2.0", path: "node_modules/react-dom", direct: true},
	})

	p = readNPMFixture(t, "pnpm5", Options{})
	checkNPM(t, p, map[string]npmWant{
		"@babel/runtime@7.20.13":      {version: "7.20.13", constraint: "^7.20.0", path: "node_modules/@babel/runtime", direct: true},
		"react-dom@17.0.2":            {version: "17.0.2", constraint: "^17.0.2", path: "node_modules/react-dom", direct: true},
		"react@17.0.2":                {version: "17.0.2"},
		"regenerator-runtime@0.13.11": {version: "0.13.11"},
	})
}

// T-32: a billion-laughs pnpm-lock.yaml fails fast with an error.
func TestPnpmBillionLaughs(t *testing.T) {
	var b strings.Builder
	b.WriteString("lockfileVersion: '9.0'\na: &a [\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\",\"lol\"]\n")
	prev := "a"
	for _, n := range []string{"b", "c", "d", "e", "f", "g", "h", "i"} {
		fmt.Fprintf(&b, "%s: &%s [*%s,*%s,*%s,*%s,*%s,*%s,*%s,*%s,*%s]\n", n, n, prev, prev, prev, prev, prev, prev, prev, prev, prev)
		prev = n
	}
	b.WriteString("packages: *i\n")
	start := time.Now()
	_, err := ParseNPMLock("pnpm-lock.yaml", []byte(b.String()), nil, Options{})
	if !errors.Is(err, errYAMLBomb) {
		t.Errorf("err = %v, want the YAML bomb error", err)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("took %s", d)
	}
	deep := "packages:\n  x: " + strings.Repeat("[", 200) + strings.Repeat("]", 200) + "\n"
	if _, err := ParseNPMLock("pnpm-lock.yaml", []byte(deep), nil, Options{}); err == nil {
		t.Error("200 levels of nesting parsed")
	}
	// Negative: ordinary aliases within the caps are fine.
	ok := "lockfileVersion: '9.0'\nx: &x {integrity: sha512-x}\npackages:\n  a@1.0.0:\n    resolution: *x\n"
	p, err := ParseNPMLock("pnpm-lock.yaml", []byte(ok), nil, Options{})
	if err != nil || len(p.Installed) != 1 || p.Installed[0].Integrity != "sha512-x" {
		t.Errorf("small alias: %+v, %v", p, err)
	}
}

func TestYarnClassic(t *testing.T) {
	p := readNPMFixture(t, "yarn1", Options{})
	checkNPM(t, p, map[string]npmWant{
		"@babel/code-frame@7.12.13": {version: "7.12.13", constraint: "^7.10.4", path: "node_modules/@babel/code-frame", direct: true},
		"chalk@2.4.2":               {version: "2.4.2", constraint: "^2.4.2", path: "node_modules/chalk", direct: true},
		"left-pad@1.3.0":            {version: "1.3.0", constraint: "^1.3.0", path: "node_modules/left-pad", direct: true, dev: true},
		"local-lib@1.0.0":           {version: "1.0.0", kind: core.ResolvedFile, constraint: "file:./local-lib", path: "node_modules/local-lib", direct: true},
		"my-fork@1.0.0":             {version: "1.0.0", kind: core.ResolvedGit, constraint: "acme/my-fork#v1.0.0", path: "node_modules/my-fork", direct: true},
		"string-width@4.2.3":        {version: "4.2.3", constraint: "npm:string-width@^4.2.0", path: "node_modules/string-width-cjs", direct: true},
	})
	if got := reasons(p); got != "local-lib vcs, my-fork vcs" {
		t.Errorf("not checked = %s", got)
	}
	lock, _ := os.ReadFile("testdata/npm/yarn1/yarn.lock")
	for _, in := range p.Installed {
		if in.Ref.Name == "chalk" && in.LockLine != lineOf(t, lock, "chalk@^2.0.0") {
			t.Errorf("chalk LockLine = %d", in.LockLine)
		}
	}
	// Transitive ranges are the parents' ranges, joined.
	p, err := ParseNPMLock("yarn.lock", []byte("a@^1.0.0, a@^1.2.0, a@^1.0.0:\n  version \"1.2.3\"\n"), nil, Options{})
	if err != nil || p.Installed[0].Constraint != "^1.0.0 || ^1.2.0" || p.Installed[0].Direct {
		t.Errorf("transitive = %+v, %v", p, err)
	}
	for _, bad := range []string{"  version \"1\"\n", "a:\n", "\"@\":\n", "a@1, b@1:\n", "nocolon\n"} {
		if _, err := ParseNPMLock("yarn.lock", []byte(bad), nil, Options{}); err == nil {
			t.Errorf("%q parsed", bad)
		}
	}
}

func TestYarnBerry(t *testing.T) {
	p := readNPMFixture(t, "berry", Options{})
	got := map[string]int{}
	for _, in := range p.Installed {
		got[in.Ref.Name+"@"+in.Ref.Version+" "+in.ResolvedKind]++
		if in.Integrity != "" {
			t.Errorf("%s: a Berry checksum is not npm SRI: %q", in.Ref, in.Integrity)
		}
		if in.Ref.Name == "typescript" && (!in.Direct || in.Constraint != "^5.6.0") {
			t.Errorf("typescript = %+v", in)
		}
		if in.Ref.Name == "prettier" && (!in.Direct || !in.Dev) {
			t.Errorf("prettier = %+v", in)
		}
	}
	want := map[string]int{"lodash@4.17.21 registry": 1, "patched-lib@1.0.0 registry": 1, "patched-lib@1.0.0 file": 1,
		"prettier@3.3.3 registry": 1, "typescript@5.6.3 registry": 1}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Errorf("installed = %v, want %v", got, want)
	}
	if got := reasons(p); got != "patched-lib vcs" {
		t.Errorf("not checked = %s", got)
	}
}

func TestBunLock(t *testing.T) {
	p := readNPMFixture(t, "bun", Options{})
	checkNPM(t, p, map[string]npmWant{
		"@types/bun@1.1.13":    {version: "1.1.13", constraint: "^1.1.0", path: "node_modules/@types/bun", direct: true, dev: true},
		"bun-types@1.1.34":     {version: "1.1.34", path: "node_modules/bun-types"},
		"@types/node@20.12.14": {version: "20.12.14", path: "node_modules/@types/node"},
		"@types/node@20.12.8":  {version: "20.12.8", constraint: "~20.12.8"},
		"clsx@2.1.1":           {version: "2.1.1", constraint: "^2.1.0", path: "node_modules/clsx", direct: true},
		"js-tokens@4.0.0":      {version: "4.0.0", path: "node_modules/js-tokens"},
		"loose-envify@1.4.0":   {version: "1.4.0", path: "node_modules/loose-envify"},
		"react@18.3.1":         {version: "18.3.1", constraint: "^18.3.1", path: "node_modules/react", direct: true},
		"undici-types@5.26.5":  {version: "5.26.5", path: "node_modules/undici-types"},
		"xlsx@":                {kind: core.ResolvedTarball, constraint: "https://cdn.sheetjs.com/xlsx-0.20.3/xlsx-0.20.3.tgz", path: "node_modules/xlsx", direct: true},
	})
	if got := reasons(p); got != "xlsx tarball" {
		t.Errorf("not checked = %s", got)
	}
	lock, _ := os.ReadFile("testdata/npm/bun/bun.lock")
	for _, in := range p.Installed {
		if in.Ref.Name == "clsx" && in.LockLine != lineOf(t, lock, `"clsx": [`) {
			t.Errorf("clsx LockLine = %d", in.LockLine)
		}
	}
}

func TestStripJSONC(t *testing.T) {
	in := "{\n // c\n \"a\": \"x // not a comment, /* nor this */\", /* b\n */ \"b\": [1, 2,],\n \"c\": \"\\\"\",\n}"
	out := string(stripJSONC([]byte(in)))
	if len(out) != len(in) || strings.Count(out, "\n") != strings.Count(in, "\n") {
		t.Errorf("length or lines changed: %q", out)
	}
	want := "{\n     \n \"a\": \"x // not a comment, /* nor this */\",     \n    \"b\": [1, 2 ],\n \"c\": \"\\\"\" \n}"
	if out != want {
		t.Errorf("stripJSONC =\n%q\nwant\n%q", out, want)
	}
}

func TestFindNPMLock(t *testing.T) {
	dir := t.TempDir()
	if _, err := FindNPMLock(dir); !errors.Is(err, ErrNoLockfile) {
		t.Errorf("empty folder: %v", err)
	}
	for i := len(NPMLockfiles) - 1; i >= 0; i-- {
		writeFiles(t, dir, map[string]string{NPMLockfiles[i]: "{}"})
		if got, err := FindNPMLock(dir); err != nil || got != NPMLockfiles[i] {
			t.Errorf("with %s: %q, %v", NPMLockfiles[i], got, err)
		}
	}
}

func TestBunLockbIsE8(t *testing.T) {
	_, err := ReadNPM("testdata/npm/lockb", Options{NPMRC: []string{}})
	var e *core.Error
	if !errors.As(err, &e) || e.Code != core.EUnsupportedLock || e.ExitCode() != cli.ExitUsage {
		t.Fatalf("err = %v, want E8", err)
	}
	want := cli.Name() + " npm: bun.lockb is Bun's binary lockfile, which Sightread can't read\n" +
		"  run bun install --save-text-lockfile once to write bun.lock"
	if err.Error() != want {
		t.Errorf("E8 text =\n%s\nwant\n%s", err, want)
	}
	// Negative: bun.lockb next to bun.lock reads the text lockfile.
	dir := copyTree(t, "testdata/npm/bun")
	writeFiles(t, dir, map[string]string{"bun.lockb": "\x00binary"})
	if _, err := ReadNPM(dir, Options{NPMRC: []string{}}); err != nil {
		t.Errorf("bun.lock with bun.lockb: %v", err)
	}
}

func TestClassifyNPM(t *testing.T) {
	s := newNPMSources(Options{NPMRegistry: "https://mirror.example/npm/"}, map[string]string{"@acme": "https://npm.acme.example/"})
	for in, want := range map[string]string{
		"": core.ResolvedRegistry, "https://registry.npmjs.org/a/-/a-1.0.0.tgz": core.ResolvedRegistry,
		"https://registry.yarnpkg.com/a/-/a-1.0.0.tgz": core.ResolvedRegistry, "https://mirror.example/npm/a-1.0.0.tgz": core.ResolvedRegistry,
		"https://npm.acme.example/@acme/x/-/x-1.tgz": core.ResolvedRegistry,
		"git+https://github.com/a/b.git#abc":         core.ResolvedGit, "github:a/b": core.ResolvedGit, "git+ssh://git@github.com/a/b.git": core.ResolvedGit,
		"https://codeload.github.com/a/b/tar.gz/abc": core.ResolvedGit, "file:../x": core.ResolvedFile, "link:../x": core.ResolvedFile,
		"../x": core.ResolvedFile, "https://cdn.sheetjs.com/xlsx-0.20.3/xlsx-0.20.3.tgz": core.ResolvedTarball,
		"https://evil.example/a.tar.gz?x=1": core.ResolvedTarball, "https://evil.example/download": core.ResolvedForeign,
		"weird:thing": core.ResolvedForeign,
	} {
		if got := s.classify(in); got != want {
			t.Errorf("classify(%q) = %s, want %s", in, got, want)
		}
	}
}

// fuzzNPM checks the invariants every npm lockfile parser keeps: no
// panic, only valid references, LockLine inside the input.
func fuzzNPM(t *testing.T, name string, data []byte) {
	p, err := ParseNPMLock(name, data, nil, Options{})
	if err != nil {
		return
	}
	// YAML ends a line at a lone CR too, so count lines as lineAt does.
	lines := lineAt(data, len(data))
	for _, in := range p.Installed {
		if !validRef(core.NPM, in.Ref.Name, in.Ref.Version) {
			t.Fatalf("bad ref %+v", in.Ref)
		}
		if in.LockLine < 0 || in.LockLine > lines {
			t.Fatalf("LockLine %d past %d lines", in.LockLine, lines)
		}
	}
}

// The fuzz seeds are small on purpose: the fuzzer shrinks every input
// that finds new coverage. Shrinking a fixture of a few KiB takes the
// whole run.

func FuzzPackageLock(f *testing.F) {
	for _, s := range []string{
		`{"lockfileVersion": 3, "packages": {"": {"dependencies": {"a": "^1"}}, "node_modules/a": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz", "integrity": "sha512-x", "dependencies": {"b": "^2"}}, "node_modules/a/node_modules/b": {"version": "2.0.0", "dev": true}, "node_modules/w": {"link": true}}}`,
		`{"lockfileVersion": 1, "dependencies": {"a": {"version": "1.0.0", "requires": {"b": "^2"}, "dependencies": {"b": {"version": "2.0.0"}}}, "g": {"version": "github:x/y#abc"}}}`,
		`{"packages": {"node_modules/x": {"name": "@s/y", "version": "1.0.0", "resolved": "https://cdn.example/y.tgz"}}}`,
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) { fuzzNPM(t, "package-lock.json", b) })
}

func FuzzPnpmLock(f *testing.F) {
	for _, s := range []string{
		"lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      a:\n        specifier: ^1\n        version: 1.0.0(b@2.0.0)\npackages:\n  a@1.0.0:\n    resolution: {integrity: sha512-x}\n  c@https://x.example/c.tgz:\n    resolution: {tarball: https://x.example/c.tgz}\n    version: 1.0.0\n",
		"lockfileVersion: '6.0'\ndependencies:\n  a:\n    specifier: ^1\n    version: 1.0.0\npackages:\n  /a@1.0.0:\n    resolution: {integrity: sha512-x}\n    dev: false\n",
		"lockfileVersion: 5.4\nspecifiers:\n  a: ^1\ndependencies:\n  a: 1.0.0_b@2.0.0\npackages:\n  /a/1.0.0_b@2.0.0:\n    resolution: {integrity: sha512-x}\n",
		"x: &x {a: 1}\npackages:\n  a@1.0.0: *x\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) { fuzzNPM(t, "pnpm-lock.yaml", b) })
}

func FuzzYarnLock(f *testing.F) {
	for _, s := range []string{
		"# yarn lockfile v1\n\n\"@a/b@^1\", \"@a/b@^1.1\":\n  version \"1.2.0\"\n  resolved \"https://registry.yarnpkg.com/@a/b/-/b-1.2.0.tgz#abc\"\n  integrity sha512-x\n  dependencies:\n    c \"^2\"\n",
		"x@npm:y@^1:\n  version \"1.0.0\"\nl@file:./l:\n  version \"1.0.0\"\n",
		"__metadata:\n  version: 8\n\n\"a@npm:^1\":\n  version: 1.0.0\n  resolution: \"a@npm:1.0.0\"\n\"w@workspace:.\":\n  version: 0.0.0\n  resolution: \"w@workspace:.\"\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) { fuzzNPM(t, "yarn.lock", b) })
}

func FuzzBunLock(f *testing.F) {
	for _, s := range []string{
		`{"lockfileVersion": 1, "workspaces": {"": {"dependencies": {"a": "^1",},},}, "packages": {"a": ["a@1.0.0", "", {"dependencies": {"b": "^2"}}, "sha512-x"], "a/b": ["b@2.0.0", "", {}, "sha512-y"], "w": ["w@workspace:w"],},}`,
		"{\n // c\n \"packages\": {/* x */ \"t\": [\"t@https://x.example/t.tgz\", {}]}}",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if out := stripJSONC(b); len(out) != len(b) {
			t.Fatalf("stripJSONC changed the length")
		}
		fuzzNPM(t, "bun.lock", b)
	})
}
