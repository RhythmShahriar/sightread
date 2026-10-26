// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package registry

import (
	"fmt"
	"regexp"
	"strings"
)

// fakeKeyKinds lists the kinds fakeKey makes. It mirrors
// coretest.FakeKeyKinds; TestFakeKeyMatchesCoretest asserts the two
// agree so the testbed's fixtures and the unit tests share one set of
// fake credentials.
func fakeKeyKinds() []string {
	return []string{"npm", "github", "stripe", "aws", "slack"}
}

// fakeKey returns a fake credential of kind, assembled from parts at run
// time so no literal real-format key is ever committed (GitHub push
// protection and secret scanners block literal ones). It is the same
// assembly as core/coretest.FakeKey, checked by TestFakeKeyMatchesCoretest.
// The registry stays stdlib only, so it repeats the parts instead of
// importing a test package.
func fakeKey(kind string) (string, error) {
	j := func(parts ...string) string { return strings.Join(parts, "") }
	switch kind {
	case "npm":
		return j("npm", "_", "Fk3sightreadTEST", "0nly4Fixtures9xQ2wZa"), nil
	case "github":
		return j("gh", "p_", "Fk3sightreadTEST0nly", "4Fixtures9xQ2wZaB"), nil
	case "stripe":
		return j("sk", "_live_", "Fk3sightreadTEST", "0nly4Fixtures"), nil
	case "aws":
		return j("AK", "IA", "FK3SIGHTREAD", "TEST"), nil
	case "slack":
		return j("https://hooks.", "slack.com/services/", "T0FAKE0001/", "B0FAKE0002/", "Fk3sightreadTEST0nly4Fix"), nil
	}
	return "", fmt.Errorf("registry: unknown fake key kind %q", kind)
}

// FakeKeys returns every fake credential a fixture can hold, assembled.
// The benchmark looks for them in what Sightread prints and writes: a
// key found there was not masked.
func FakeKeys() []string {
	out := make([]string, 0, len(fakeKeyKinds()))
	for _, kind := range fakeKeyKinds() {
		k, err := fakeKey(kind)
		if err == nil {
			out = append(out, k)
		}
	}
	return out
}

// fakeKeyRE matches a {{fakekey:<kind>}} placeholder.
var fakeKeyRE = regexp.MustCompile(`\{\{fakekey:([a-z]+)\}\}`)

// expandFakeKeys replaces every {{fakekey:<kind>}} placeholder in b with
// the assembled fake credential. An unknown kind is an error, so a typo
// in a fixture is caught at build time rather than shipping a literal
// placeholder into an archive.
func expandFakeKeys(b []byte) ([]byte, error) {
	var bad string
	out := fakeKeyRE.ReplaceAllFunc(b, func(m []byte) []byte {
		kind := string(fakeKeyRE.FindSubmatch(m)[1])
		k, err := fakeKey(kind)
		if err != nil {
			bad = kind
			return m
		}
		return []byte(k)
	})
	if bad != "" {
		return nil, fmt.Errorf("unknown fake key kind %q", bad)
	}
	return out, nil
}
