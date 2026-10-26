// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package kitcheck

import (
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// licenses is every module the build or its tests link, with its
// license. A new dependency fails TestLicenses until someone reads its
// license and adds it here. THIRD_PARTY/ carries what a license asks to
// ship with the binary: the MPL-2.0 Public Suffix List and the Apache
// NOTICE files (TestNotices).
var licenses = map[string]string{
	"github.com/RhythmShahriar/sightread":               "MIT",
	"github.com/RhythmShahriar/rhythm":                  "AGPL-3.0-only", // the kit, Rhythm's own
	"github.com/asaskevich/govalidator":                 "MIT",
	"github.com/atotto/clipboard":                       "BSD-3-Clause",
	"github.com/aymanbagabas/go-osc52/v2":               "MIT",
	"github.com/blang/semver":                           "MIT",
	"github.com/catppuccin/go":                          "MIT",
	"github.com/cenkalti/backoff/v5":                    "MIT",
	"github.com/cespare/xxhash/v2":                      "MIT",
	"github.com/charmbracelet/bubbles":                  "MIT",
	"github.com/charmbracelet/bubbletea":                "MIT",
	"github.com/charmbracelet/colorprofile":             "MIT",
	"github.com/charmbracelet/huh":                      "MIT",
	"github.com/charmbracelet/lipgloss":                 "MIT",
	"github.com/charmbracelet/x/ansi":                   "MIT",
	"github.com/charmbracelet/x/cellbuf":                "MIT",
	"github.com/charmbracelet/x/exp/strings":            "MIT",
	"github.com/charmbracelet/x/term":                   "MIT",
	"github.com/cyberphone/json-canonicalization":       "Apache-2.0",
	"github.com/digitorus/pkcs7":                        "MIT",
	"github.com/digitorus/timestamp":                    "BSD-2-Clause",
	"github.com/dustin/go-humanize":                     "MIT",
	"github.com/erikgeiser/coninput":                    "MIT",
	"github.com/go-logr/logr":                           "Apache-2.0",
	"github.com/go-logr/stdr":                           "Apache-2.0",
	"github.com/go-openapi/analysis":                    "Apache-2.0",
	"github.com/go-openapi/errors":                      "Apache-2.0",
	"github.com/go-openapi/jsonpointer":                 "Apache-2.0",
	"github.com/go-openapi/jsonreference":               "Apache-2.0",
	"github.com/go-openapi/loads":                       "Apache-2.0",
	"github.com/go-openapi/runtime":                     "Apache-2.0",
	"github.com/go-openapi/runtime/server-middleware":   "Apache-2.0",
	"github.com/go-openapi/spec":                        "Apache-2.0",
	"github.com/go-openapi/strfmt":                      "Apache-2.0",
	"github.com/go-openapi/swag":                        "Apache-2.0",
	"github.com/go-openapi/swag/cmdutils":               "Apache-2.0",
	"github.com/go-openapi/swag/conv":                   "Apache-2.0",
	"github.com/go-openapi/swag/fileutils":              "Apache-2.0",
	"github.com/go-openapi/swag/jsonname":               "Apache-2.0",
	"github.com/go-openapi/swag/jsonutils":              "Apache-2.0",
	"github.com/go-openapi/swag/loading":                "Apache-2.0",
	"github.com/go-openapi/swag/mangling":               "Apache-2.0",
	"github.com/go-openapi/swag/netutils":               "Apache-2.0",
	"github.com/go-openapi/swag/pools":                  "Apache-2.0",
	"github.com/go-openapi/swag/stringutils":            "Apache-2.0",
	"github.com/go-openapi/swag/typeutils":              "Apache-2.0",
	"github.com/go-openapi/swag/yamlutils":              "Apache-2.0",
	"github.com/go-openapi/validate":                    "Apache-2.0",
	"github.com/go-viper/mapstructure/v2":               "MIT",
	"github.com/google/certificate-transparency-go":     "Apache-2.0",
	"github.com/google/go-containerregistry":            "Apache-2.0",
	"github.com/google/uuid":                            "BSD-3-Clause",
	"github.com/grpc-ecosystem/grpc-gateway/v2":         "BSD-3-Clause",
	"github.com/in-toto/attestation":                    "Apache-2.0",
	"github.com/in-toto/in-toto-golang":                 "Apache-2.0",
	"github.com/lucasb-eyer/go-colorful":                "MIT",
	"github.com/mattn/go-isatty":                        "MIT",
	"github.com/mattn/go-localereader":                  "MIT",
	"github.com/mattn/go-runewidth":                     "MIT",
	"github.com/mitchellh/hashstructure/v2":             "MIT",
	"github.com/muesli/ansi":                            "MIT",
	"github.com/muesli/cancelreader":                    "MIT",
	"github.com/muesli/termenv":                         "MIT",
	"github.com/oklog/ulid/v2":                          "Apache-2.0",
	"github.com/opencontainers/go-digest":               "Apache-2.0",
	"github.com/pkg/errors":                             "BSD-2-Clause",
	"github.com/rivo/uniseg":                            "MIT",
	"github.com/secure-systems-lab/go-securesystemslib": "MIT",
	"github.com/shibumi/go-pathspec":                    "Apache-2.0",
	"github.com/sigstore/protobuf-specs":                "Apache-2.0",
	"github.com/sigstore/rekor":                         "Apache-2.0",
	"github.com/sigstore/rekor-tiles/v2":                "Apache-2.0",
	"github.com/sigstore/sigstore":                      "Apache-2.0",
	"github.com/sigstore/sigstore-go":                   "Apache-2.0",
	"github.com/sigstore/timestamp-authority/v2":        "Apache-2.0",
	"github.com/theupdateframework/go-tuf/v2":           "Apache-2.0",
	"github.com/transparency-dev/formats":               "Apache-2.0",
	"github.com/transparency-dev/merkle":                "Apache-2.0",
	"github.com/xo/terminfo":                            "MIT",
	"github.com/youmark/pkcs8":                          "MIT",
	"go.opentelemetry.io/auto/sdk":                      "Apache-2.0",
	"go.opentelemetry.io/otel":                          "Apache-2.0 and BSD-3-Clause",
	"go.opentelemetry.io/otel/metric":                   "Apache-2.0",
	"go.opentelemetry.io/otel/trace":                    "Apache-2.0",
	"go.yaml.in/yaml/v3":                                "MIT and Apache-2.0",
	"golang.org/x/crypto":                               "BSD-3-Clause",
	"golang.org/x/mod":                                  "BSD-3-Clause",
	"golang.org/x/net":                                  "BSD-3-Clause", // publicsuffix's table is MPL-2.0 data
	"golang.org/x/sync":                                 "BSD-3-Clause",
	"golang.org/x/sys":                                  "BSD-3-Clause",
	"golang.org/x/term":                                 "BSD-3-Clause",
	"golang.org/x/text":                                 "BSD-3-Clause",
	"google.golang.org/genproto/googleapis/api":         "Apache-2.0",
	"google.golang.org/genproto/googleapis/rpc":         "Apache-2.0",
	"google.golang.org/grpc":                            "Apache-2.0",
	"google.golang.org/protobuf":                        "BSD-3-Clause",
	"gopkg.in/yaml.v3":                                  "MIT and Apache-2.0",
	"k8s.io/klog/v2":                                    "Apache-2.0",
}

// TestLicenses lists the modules of every package the module builds,
// tests included, on each OS. It fails on one missing from licenses.
// It reads the build graph rather than go list -m all: the full module
// graph also names modules no Sightread package compiles.
func TestLicenses(t *testing.T) {
	seen := map[string]bool{}
	for _, goos := range []string{"linux", "darwin", "windows"} {
		cmd := exec.Command("go", "list", "-deps", "-test", "-f", "{{with .Module}}{{.Path}}{{end}}", "./...")
		cmd.Dir = "../.."
		cmd.Env = append(os.Environ(), "GOOS="+goos, "GOWORK=off", "CGO_ENABLED=0")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list (%s): %v", goos, err)
		}
		for _, m := range strings.Fields(string(out)) {
			seen[m] = true
		}
	}
	var unknown []string
	for m := range seen {
		if _, ok := licenses[m]; !ok {
			unknown = append(unknown, m)
		}
	}
	sort.Strings(unknown)
	for _, m := range unknown {
		t.Errorf("module %s has no known license: read it and add it to licenses (and THIRD_PARTY/)", m)
	}
	if !seen["github.com/RhythmShahriar/rhythm"] {
		t.Error("the kit isn't in the build graph: is go list reading the right module?")
	}
}

// TestNotices: every module the binary links that has a NOTICE file
// (Apache-2.0 section 4) has it in THIRD_PARTY/notices/NOTICE.
func TestNotices(t *testing.T) {
	notices, err := os.ReadFile("../../THIRD_PARTY/notices/NOTICE")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "list", "-deps", "-f", "{{with .Module}}{{.Path}} {{.Dir}}{{end}}", "./cmd/rhythm-sightread")
	cmd.Dir = "../.."
	cmd.Env = append(os.Environ(), "GOWORK=off", "CGO_ENABLED=0")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go list: %v", err)
	}
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		path, dir, ok := strings.Cut(line, " ")
		if !ok || seen[path] || dir == "" {
			continue
		}
		seen[path] = true
		files, _ := filepath.Glob(filepath.Join(dir, "NOTICE*"))
		if len(files) > 0 && !strings.Contains(string(notices), "== "+path+" ") {
			t.Errorf("module %s has a NOTICE file that THIRD_PARTY/notices/NOTICE doesn't carry", path)
		}
	}
}
