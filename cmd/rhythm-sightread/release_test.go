// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/core/coretest"
	"gopkg.in/yaml.v3"
)

// repoFile is a file of the repository, from this package's folder.
func repoFile(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(name)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// goreleaser is the part of .goreleaser.yaml the release depends on.
type goreleaser struct {
	ProjectName string `yaml:"project_name"`
	Builds      []struct {
		Main, Binary string
		Env, Goos    []string
		Goarch       []string `yaml:"goarch"`
		Flags        []string
		Ldflags      []string
	}
	Archives []struct {
		Formats         []string `yaml:"formats"`
		NameTemplate    string   `yaml:"name_template"`
		FormatOverrides []struct {
			Goos    string
			Formats []string
		} `yaml:"format_overrides"`
		Files []yaml.Node
	}
	Checksum struct {
		NameTemplate string      `yaml:"name_template"`
		ExtraFiles   []extraFile `yaml:"extra_files"`
	}
	Release struct {
		Prerelease string      `yaml:"prerelease"`
		ExtraFiles []extraFile `yaml:"extra_files"`
	}
	Signs []struct {
		Cmd, Artifacts, Signature string
		Args                      []string
	}
}

type extraFile struct {
	Glob string `yaml:"glob"`
}

// TestGoreleaserConfig holds .goreleaser.yaml to what rhythm update, the
// install script and the Action expect: the archive names, the files in
// each archive, the signed checksums with the data packs and the signs
// block with the master identity.
func TestGoreleaserConfig(t *testing.T) {
	raw := repoFile(t, ".goreleaser.yaml")
	var g goreleaser
	if err := yaml.Unmarshal(raw, &g); err != nil {
		t.Fatal(err)
	}
	if g.ProjectName != "rhythm-sightread" || len(g.Builds) != 1 || len(g.Archives) != 1 || len(g.Signs) != 1 {
		t.Fatalf("config %+v", g)
	}
	b := g.Builds[0]
	if b.Main != "./cmd/rhythm-sightread" || b.Binary != "rhythm-sightread" || !slices.Equal(b.Env, []string{"CGO_ENABLED=0"}) ||
		!slices.Equal(b.Goos, []string{"linux", "darwin", "windows"}) || !slices.Equal(b.Goarch, []string{"amd64", "arm64"}) ||
		!slices.Equal(b.Flags, []string{"-trimpath"}) ||
		!slices.Equal(b.Ldflags, []string{"-s -w -X main.version={{ .Version }} -X main.actionSHA={{ .FullCommit }}"}) {
		t.Errorf("build %+v", b)
	}
	a := g.Archives[0]
	if a.NameTemplate != "{{ .ProjectName }}_{{ .Os }}_{{ .Arch }}" || !slices.Equal(a.Formats, []string{"tar.gz"}) ||
		len(a.FormatOverrides) != 1 || a.FormatOverrides[0].Goos != "windows" || !slices.Equal(a.FormatOverrides[0].Formats, []string{"zip"}) {
		t.Errorf("archive %+v", a)
	}
	// Every file an archive lists exists.
	var files []string
	for _, n := range a.Files {
		var src string
		if n.Kind == yaml.ScalarNode {
			src = n.Value
		} else {
			var f struct{ Src string }
			if err := n.Decode(&f); err != nil {
				t.Fatal(err)
			}
			src = f.Src
		}
		files = append(files, src)
		matches, err := filepath.Glob(filepath.Join("..", "..", filepath.FromSlash(src)))
		if err != nil || len(matches) == 0 {
			t.Errorf("archive file %s matches nothing", src)
		}
	}
	if !slices.Equal(files, []string{"README.md", "LICENSE", "THIRD_PARTY/publicsuffix/*", "THIRD_PARTY/notices/*"}) {
		t.Errorf("archive files %q", files)
	}
	if !strings.Contains(string(repoFile(t, "THIRD_PARTY/publicsuffix/LICENSE")), "Mozilla Public License, version 2.0") {
		t.Error("THIRD_PARTY/publicsuffix/LICENSE is not the MPL-2.0 text")
	}
	if g.Checksum.NameTemplate != "checksums.txt" || g.Release.Prerelease != "auto" {
		t.Errorf("checksum %+v release %+v", g.Checksum, g.Release)
	}
	for _, list := range [][]extraFile{g.Checksum.ExtraFiles, g.Release.ExtraFiles} {
		if len(list) != 1 || list[0].Glob != "./data/release/*" {
			t.Errorf("extra files %+v, want ./data/release/* in the release and in checksums.txt", list)
		}
	}
	s := g.Signs[0]
	if s.Cmd != "cosign" || s.Artifacts != "checksum" || s.Signature != "${artifact}.sigstore.json" ||
		!slices.Equal(s.Args, []string{"sign-blob", "--bundle=${signature}", "${artifact}", "--yes"}) {
		t.Errorf("signs %+v", s)
	}
	for _, want := range []string{
		"--certificate-identity https://github.com/RhythmShahriar/.github/.github/workflows/release-go.yml@refs/heads/master",
		"--certificate-github-workflow-repository RhythmShahriar/sightread checksums.txt",
	} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("the signs comment lacks %q", want)
		}
	}
}

// TestReleasePacks: the data packs the release publishes exist. The
// detect lane commits them. Until then the test skips; it fails under
// SIGHTREAD_REQUIRE_LINKED=1 as the release checklist runs it.
func TestReleasePacks(t *testing.T) {
	dir := filepath.Join("..", "..", "data", "release")
	var missing []string
	for _, name := range []string{"sightread-names.json", "sightread-signals.tar.gz"} {
		if fi, err := os.Stat(filepath.Join(dir, name)); err != nil || fi.Size() == 0 {
			missing = append(missing, name)
		}
	}
	if len(missing) == 0 {
		return
	}
	if os.Getenv(coretest.RequireLinkedEnv) == "1" {
		t.Fatalf("data/release lacks %q (go run ./data/gen --pack writes them)", missing)
	}
	t.Skipf("data/release lacks %q until the detect lane commits them", missing)
}

// TestReleaseWorkflow: the release runs the shared workflow at master
// with the permissions signing and attestations need; Dependabot
// watches the Go modules and the pinned actions.
func TestReleaseWorkflow(t *testing.T) {
	var wf struct {
		On struct {
			Push struct {
				Tags []string
			}
		}
		Jobs map[string]struct {
			Uses        string
			Permissions map[string]string
		}
	}
	if err := yaml.Unmarshal(repoFile(t, ".github/workflows/release.yml"), &wf); err != nil {
		t.Fatal(err)
	}
	j := wf.Jobs["release"]
	if j.Uses != "RhythmShahriar/.github/.github/workflows/release-go.yml@master" || !slices.Equal(wf.On.Push.Tags, []string{"v*"}) ||
		j.Permissions["contents"] != "write" || j.Permissions["id-token"] != "write" || j.Permissions["attestations"] != "write" {
		t.Errorf("release workflow %+v", wf)
	}
	var dep struct {
		Updates []struct {
			Ecosystem string `yaml:"package-ecosystem"`
			Directory string
		}
	}
	if err := yaml.Unmarshal(repoFile(t, ".github/dependabot.yml"), &dep); err != nil {
		t.Fatal(err)
	}
	var ecos []string
	for _, u := range dep.Updates {
		ecos = append(ecos, u.Ecosystem+" "+u.Directory)
	}
	if !slices.Equal(ecos, []string{"github-actions /", "gomod /"}) {
		t.Errorf("dependabot %q", ecos)
	}
}
