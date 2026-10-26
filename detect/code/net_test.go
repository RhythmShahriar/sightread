// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package code

import (
	"slices"
	"strings"
	"testing"

	"github.com/RhythmShahriar/rhythm/kit/cli"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/core/coretest"
)

func TestHostCategory(t *testing.T) {
	for host, want := range map[string]string{
		"203.0.113.7":               CatRawIP,
		"2001:db8::1":               CatRawIP,
		"mainnet.infura.io":         CatBlockchainRPC,
		"rpc.example.test":          CatBlockchainRPC,
		"cloudflare-eth.com":        CatBlockchainRPC,
		"pastebin.com":              CatPaste,
		"bit.ly":                    CatShortener,
		"evil.duckdns.org":          CatDynDNS,
		"raw.githubusercontent.com": CatRawGitHub,
		"github.com":                "",
		"notpastebin.com":           "",
		"api.wordpress.org":         "",
	} {
		if got := hostCategory(host); got != want {
			t.Errorf("hostCategory(%q) = %q, want %q", host, got, want)
		}
	}
}

func TestNormHost(t *testing.T) {
	for in, want := range map[string]string{
		"API.Acme.test":    "api.acme.test",
		"acme.test:8443":   "acme.test",
		"[2001:db8::1]:80": "2001:db8::1",
		"acme.test.":       "acme.test",
		"2001:db8::1":      "2001:db8::1",
		"[2001:db8::2]":    "2001:db8::2",
		"203.0.113.7:8080": "203.0.113.7",
	} {
		if got := normHost(in); got != want {
			t.Errorf("normHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMatchesAny(t *testing.T) {
	pats := []string{"wordpress.org", "*.acme.test", "fonts.g?ogleapis.com", ""}
	for host, want := range map[string]bool{
		"wordpress.org":        true,
		"api.wordpress.org":    true,
		"evilwordpress.org":    false,
		"acme.test":            true,
		"cdn.acme.test":        true,
		"fonts.googleapis.com": true,
		"maps.googleapis.com":  false,
	} {
		if got := matchesAny(host, pats); got != want {
			t.Errorf("matchesAny(%q) = %v, want %v", host, got, want)
		}
	}
}

func TestURLHost(t *testing.T) {
	for in, want := range map[string]string{
		"https://www.acme.test/plugin":         "www.acme.test",
		"git+https://github.com/acme/x.git":    "github.com",
		"git@gitlab.com:acme/x.git":            "gitlab.com",
		"github:acme/x":                        "github.com",
		"acme.test/docs":                       "acme.test",
		"":                                     "",
		"https://user@bitbucket.org/acme/x":    "bitbucket.org",
		"  https://Docs.Acme.Test:8080/x?y=1 ": "docs.acme.test",
	} {
		if got := urlHost(in); got != want {
			t.Errorf("urlHost(%q) = %q, want %q", in, got, want)
		}
	}
}

// The candidate can't vouch for a new host by naming it its homepage:
// own hosts come from the installed version.
func TestOwnHostsFromInstalled(t *testing.T) {
	f := coretest.Feat(core.FDomain, "collect.evil.test", "a.php", 1)
	s := subject(core.WPPlugin, nil, coretest.Features(f))
	s.Old = &core.Meta{Homepage: "https://acme.test"}
	s.New = &core.Meta{Homepage: "https://evil.test"}
	got := detectAll(t, netDetector{}, s)
	if len(got) != 1 || got[0].Severity != cli.SeverityMedium {
		t.Fatalf("got %v", got)
	}
	s.Old = nil // an added package has only its own word
	if got = detectAll(t, netDetector{}, s); got[0].Severity != cli.SeverityInfo || got[0].Demoted != DemotedOwnHost {
		t.Errorf("added package: %s %q", got[0].Severity, got[0].Demoted)
	}
}

func TestKnownDomainsFromDataPacks(t *testing.T) {
	(&coretest.FakeDataPacks{Domains: []string{"gravatar.com"}}).Install(t)
	f := coretest.Feat(core.FDomain, "secure.gravatar.com", "a.php", 1)
	got := detectAll(t, netDetector{}, subject(core.WPPlugin, nil, coretest.Features(f)))
	if len(got) != 1 || got[0].Severity != cli.SeverityInfo || got[0].Demoted != DemotedKnown {
		t.Fatalf("got %+v", got)
	}
	if !slices.Equal(got[0].Domains, []string{"secure.gravatar.com"}) {
		t.Errorf("domains %v", got[0].Domains)
	}
}

// One finding per host, at its worst place, with the host in Domains.
func TestDomainOncePerHost(t *testing.T) {
	doc := coretest.Feat(core.FDomain, "203.0.113.7", "a/readme.txt", 1)
	doc.Context = core.CtxDoc
	code := coretest.Feat(core.FDomain, "203.0.113.7", "b.php", 9)
	again := coretest.Feat(core.FDomain, "203.0.113.7", "c.php", 2)
	got := detectAll(t, netDetector{}, subject(core.WPPlugin, nil, coretest.Features(doc, code, again)))
	if len(got) != 1 {
		t.Fatalf("got %d findings: %s", len(got), ids(got))
	}
	if got[0].File != "b.php" || got[0].Severity != cli.SeverityHigh || !strings.HasPrefix(got[0].Evidence.String(), "raw-ip host 203.0.113.7") {
		t.Errorf("got %s %s %q", got[0].File, got[0].Severity, got[0].Evidence)
	}
}

func TestTokenName(t *testing.T) {
	yes := []string{"*", "NPM_TOKEN", "github_token", "AWS_SECRET_ACCESS_KEY", "STRIPE_SECRET", "DB_PASSWORD", "MAPS_API_KEY", "ACME_TOKEN"}
	no := []string{"NODE_ENV", "HOME", "PATH", "DEBUG", "PORT", "", "TOKENIZER_MODE"}
	for _, n := range yes {
		if !tokenName(n) {
			t.Errorf("%q is a token name", n)
		}
	}
	for _, n := range no {
		if tokenName(n) {
			t.Errorf("%q is not a token name", n)
		}
	}
}

// A doc line added in the same update does not excuse a token read.
func TestDocsFromInstalled(t *testing.T) {
	read := coretest.Feat(core.FEnvRead, "ACME_TOKEN", "lib/a.js", 1)
	s := subject(core.NPM, coretest.Features(), coretest.Features(read))
	s.Old = &core.Meta{}
	s.OldTree = coretest.Tree(map[string]string{"lib/a.js": "x"})
	s.NewTree = coretest.Tree(map[string]string{"README.md": "Set ACME_TOKEN first."})
	if got := ids(detectAll(t, netDetector{}, s)); got != SigCredentialAccess {
		t.Errorf("doc added with the read: %q", got)
	}
	s.OldTree = s.NewTree
	if got := ids(detectAll(t, netDetector{}, s)); got != "" {
		t.Errorf("documented before: %q", got)
	}
}

func TestI18nFile(t *testing.T) {
	for p, want := range map[string]bool{
		"languages/acme-ar.po":       true,
		"languages/acme.pot":         true,
		"languages/acme-he_IL.mo":    true,
		"locales/he.json":            true,
		"src/i18n/ar.json":           true,
		"languages/acme-ar.l10n.php": true,
		"package.json":               false,
		"src/auth.js":                false,
	} {
		if got := i18nFile(p); got != want {
			t.Errorf("i18nFile(%q) = %v, want %v", p, got, want)
		}
	}
}

func TestIncluded(t *testing.T) {
	inc := func(target string) *core.FeatureSet {
		return coretest.Features(coretest.Feat(core.FInclude, "include", "a.php", 1, AttrTarget, target))
	}
	for target, want := range map[string]bool{
		"/assets/icon.png":  true,
		"assets/icon.png":   true,
		"./assets/icon.png": true,
		"/var/www/wp-content/plugins/x/assets/icon.png": true,
		"icon.png":          true,
		"/assets/other.png": false,
		"con.png":           false,
		"":                  false,
	} {
		if got := included(inc(target), "assets/icon.png"); got != want {
			t.Errorf("included(%q) = %v, want %v", target, got, want)
		}
	}
	commented := coretest.Feat(core.FInclude, "include", "a.php", 1, AttrTarget, "assets/icon.png")
	commented.Context = core.CtxComment
	if included(coretest.Features(commented), "assets/icon.png") {
		t.Error("an include in a comment loads nothing")
	}
}

// Secret evidence is masked: a fake key in the snippet or the masked
// attribute never comes back whole.
func TestSecretMasked(t *testing.T) {
	key := coretest.FakeKey(coretest.KeyStripe)
	f := coretest.Feat(core.FSecret, "stripe-key", "inc/config.php", 3)
	f.Ev.Snippet = core.NewSnippet("$k = '" + key + "';")
	got := detectAll(t, netDetector{}, subject(core.WPPlugin, nil, coretest.Features(f)))
	if len(got) != 1 || strings.Contains(got[0].Evidence.String(), key) || got[0].Severity != cli.SeverityMedium {
		t.Fatalf("got %+v", got)
	}
}

// TestSecretExampleByValue: only the analyzer's example mark lowers a
// secret; EXAMPLE or an example host elsewhere on the line does not.
func TestSecretExampleByValue(t *testing.T) {
	key := coretest.FakeKey(coretest.KeyGitHub)
	f := coretest.Feat(core.FSecret, "github-token", "inc/config.php", 3)
	f.Ev.Snippet = core.NewSnippet("$k = '" + key + "'; // for EXAMPLE, see https://api.example.com")
	got := detectAll(t, netDetector{}, subject(core.WPPlugin, nil, coretest.Features(f)))
	if len(got) != 1 || got[0].Severity != cli.SeverityMedium || got[0].Demoted != "" {
		t.Fatalf("a real token next to the word example was lowered: %+v", got)
	}
	f.Attrs = map[string]string{AttrExample: "true"}
	got = detectAll(t, netDetector{}, subject(core.WPPlugin, nil, coretest.Features(f)))
	if len(got) != 1 || got[0].Severity != cli.SeverityInfo || got[0].Demoted != DemotedExample {
		t.Fatalf("an example value stayed: %+v", got)
	}
}

// wp-config.php constants count only when sent out.
func TestWPConfigRead(t *testing.T) {
	read := coretest.Feat(core.FCredRead, "wp-config:DB_PASSWORD", "inc/a.php", 3)
	sendOther := coretest.Feat(core.FSend, "wp_remote_post", "inc/b.php", 3)
	if credRead(read, []core.Feature{read, sendOther}) {
		t.Error("a send in another file does not count")
	}
	sendSame := coretest.Feat(core.FSend, "wp_remote_post", "inc/a.php", 9)
	if !credRead(read, []core.Feature{read, sendSame}) {
		t.Error("a send in the same file counts")
	}
	read.Attrs = map[string]string{AttrSent: "true"}
	if !credRead(read, nil) {
		t.Error("sent=true counts")
	}
	if !credRead(coretest.Feat(core.FCredRead, ".ssh/id_rsa", "a.js", 1), nil) {
		t.Error("an SSH key read always counts")
	}
}

// A repository on a code host vouches for no host: anyone has a
// github.com/attacker repository.
func TestOwnHostsSkipCodeHosts(t *testing.T) {
	s := subject(core.NPM, nil, nil)
	s.Old = &core.Meta{Homepage: "https://www.acme.test/x", Repository: "git+https://github.com/acme/x.git"}
	if got := ownHosts(s); !slices.Equal(got, []string{"acme.test"}) {
		t.Errorf("ownHosts = %q", got)
	}
	s.Old = &core.Meta{Repository: "gitlab:acme/x", Homepage: "https://bitbucket.org/acme/x"}
	if got := ownHosts(s); len(got) != 0 {
		t.Errorf("ownHosts = %q, want none", got)
	}
}

// TestExfilTarget: data-exfil names a literal local address as such and
// says "built at run time" only when no target was written.
func TestExfilTarget(t *testing.T) {
	send := func(attrs map[string]string) core.Feature {
		f := coretest.Feat(core.FSend, "fsockopen", "x.php", 3)
		f.Attrs = attrs
		return f
	}
	for _, c := range []struct {
		name  string
		attrs map[string]string
		want  string
	}{
		{"loopback", map[string]string{AttrReads: "env", AttrLocal: "127.0.0.1"}, "sends env to the local address 127.0.0.1: "},
		{"reserved", map[string]string{AttrReads: "env", AttrLocal: "c2.wpos-cdn.example"}, "sends env to the local or reserved name c2.wpos-cdn.example: "},
		{"dynamic", map[string]string{AttrReads: "env"}, "sends env to a host built at run time: "},
		{"literal host", map[string]string{AttrReads: "env", AttrHost: "evil.test", AttrDomain: "evil.test"}, "sends env to evil.test: "},
	} {
		got, ok := exfilFinding(subject(core.WPPlugin, nil, coretest.Features()), send(c.attrs))
		if !ok || !strings.HasPrefix(got.Evidence.String(), c.want) {
			t.Errorf("%s: %v %q, want prefix %q", c.name, ok, got.Evidence, c.want)
		}
		if c.name != "literal host" && got.Severity != cli.SeverityMedium {
			t.Errorf("%s: severity %s, want medium", c.name, got.Severity)
		}
	}
}
