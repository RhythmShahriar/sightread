// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package run_test

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/core"
	"github.com/RhythmShahriar/sightread/run"
)

func writeSites(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "sites.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadSites(t *testing.T) {
	home, _ := os.UserHomeDir()
	p := writeSites(t, `sites:
  - name: shop
    path: /var/www/shop
  - name: brochure
    wp: "ssh deploy@brochure.example -- wp --path=/srv/www"
  - name: api
    path: code/acme-api
  - name: client-remote
    tuner_report: ~/reports/client.json
    allow_file: ~/agency/allowed.yaml
`)
	got, err := run.LoadSites(p)
	if err != nil {
		t.Fatal(err)
	}
	want := []run.Site{
		{Name: "shop", Inventory: core.InventoryRequest{Root: filepath.FromSlash("/var/www/shop")}},
		{Name: "brochure", Inventory: core.InventoryRequest{WP: []string{"ssh", "deploy@brochure.example", "--", "wp", "--path=/srv/www"}}},
		{Name: "api", Inventory: core.InventoryRequest{Root: filepath.Join(filepath.Dir(p), "code", "acme-api")}},
		{Name: "client-remote", Inventory: core.InventoryRequest{TunerReport: filepath.Join(home, "reports", "client.json")},
			AllowFile: filepath.Join(home, "agency", "allowed.yaml")},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
}

// TestLoadSitesRefuses: every bad file is E12 naming what is wrong,
// including an alias bomb and a deep tree caught before decoding.
func TestLoadSitesRefuses(t *testing.T) {
	bomb := "a: &a [x, x, x, x, x, x, x, x, x, x]\n"
	for i := 'b'; i <= 'h'; i++ {
		prev := string(i - 1)
		bomb += string(i) + ": &" + string(i) + " [*" + prev + ", *" + prev + ", *" + prev + ", *" + prev + ", *" + prev + ", *" + prev + ", *" + prev + ", *" + prev + ", *" + prev + ", *" + prev + "]\n"
	}
	cases := map[string]string{
		"sites: []\n":            "lists no sites",
		"sites:\n  - path: /x\n": "site 1 needs a name",
		"sites:\n  - name: a\n":  "site a needs a path, wp or tuner_report",
		"sites:\n  - {name: a, path: x}\n  - {name: a, path: y}\n": "site a is listed twice",
		"sites:\n  - {name: a, wp: \"wp 'x\"}\n":                   "site a: wp \"wp 'x\": a quote is not closed",
		"sites:\n  - {name: a, path: x, pth: y}\n":                 "unknown key pth",
		bomb + "sites: []\n":                                       "has an alias that expands to more than 10000 values",
		strings.Repeat("[", 70) + strings.Repeat("]", 70) + "\n":   "nests deeper than 64 levels",
	}
	for body, want := range cases {
		p := writeSites(t, body)
		_, err := run.LoadSites(p)
		if err == nil || core.CodeOf(err) != core.EBadConfig || !strings.Contains(err.Error(), p+": ") || !strings.Contains(err.Error(), want) {
			t.Errorf("%.40q: %v, want %q", body, err, want)
		}
	}
	if _, err := run.LoadSites(filepath.Join(t.TempDir(), "none.yaml")); err == nil || !strings.Contains(err.Error(), "can't be read") {
		t.Errorf("missing file: %v", err)
	}
}

func FuzzLoadSites(f *testing.F) {
	f.Add("sites:\n  - name: shop\n    path: /var/www/shop\n")
	f.Add("a: &a [x, *a]\n")
	f.Add("sites: [{name: a, wp: \"wp --path='/a b'\"}]")
	f.Fuzz(func(t *testing.T, body string) {
		p := filepath.Join(t.TempDir(), "sites.yaml")
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		sites, err := run.LoadSites(p)
		if err != nil {
			if core.CodeOf(err) != core.EBadConfig {
				t.Fatalf("error without E12: %v", err)
			}
			return
		}
		for _, s := range sites {
			if s.Name == "" {
				t.Fatalf("a site without a name: %+v", s)
			}
		}
	})
}
