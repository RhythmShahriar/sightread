// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package registry

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"io"
	"slices"
	"strings"
	"testing"

	"github.com/RhythmShahriar/sightread/core/coretest"
)

// TestFakeKeyMatchesCoretest keeps the fixtures and the unit tests on
// one set of fake keys: the same kinds and the same assembled strings
// as coretest.FakeKey.
func TestFakeKeyMatchesCoretest(t *testing.T) {
	if !slices.Equal(fakeKeyKinds(), coretest.FakeKeyKinds()) {
		t.Fatalf("kinds %v, coretest has %v", fakeKeyKinds(), coretest.FakeKeyKinds())
	}
	for _, kind := range coretest.FakeKeyKinds() {
		got, err := fakeKey(kind)
		if err != nil {
			t.Fatal(err)
		}
		if want := coretest.FakeKey(kind); got != want {
			t.Errorf("fakeKey(%q) differs from coretest.FakeKey", kind)
		}
	}
	if got := FakeKeys(); len(got) != len(coretest.FakeKeyKinds()) {
		t.Errorf("FakeKeys returned %d keys", len(got))
	}
}

func TestExpandFakeKeys(t *testing.T) {
	b, err := expandFakeKeys([]byte("x {{fakekey:npm}} y"))
	if err != nil || string(b) != "x "+coretest.FakeKey(coretest.KeyNPM)+" y" {
		t.Errorf("expandFakeKeys: %v", err)
	}
	if _, err := expandFakeKeys([]byte("{{fakekey:bogus}}")); err == nil {
		t.Error("expandFakeKeys accepted an unknown kind")
	}
	if b, err := expandFakeKeys([]byte("no placeholder")); err != nil || string(b) != "no placeholder" {
		t.Errorf("text without a placeholder changed: %q %v", b, err)
	}
}

// TestFixtureFakeKeyExpanded builds b11, whose payload carries a
// {{fakekey:npm}} placeholder: the served tarball holds the assembled
// key and no placeholder, while the committed file holds no key.
func TestFixtureFakeKeyExpanded(t *testing.T) {
	reg := scenarioRegistry(t)
	tgz, ok := reg.Archive("b11-colorlib", "2.1.1")
	if !ok {
		t.Fatal("no b11-colorlib 2.1.1 archive")
	}
	zr, err := gzip.NewReader(bytes.NewReader(tgz))
	if err != nil {
		t.Fatal(err)
	}
	tr := tar.NewReader(zr)
	var all bytes.Buffer
	for {
		if _, err := tr.Next(); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(&all, tr); err != nil { //nolint:gosec // a fixture archive built by this test
			t.Fatal(err)
		}
	}
	key := coretest.FakeKey(coretest.KeyNPM)
	if !strings.Contains(all.String(), key) {
		t.Error("the b11 archive does not hold the expanded fake key")
	}
	if strings.Contains(all.String(), "{{fakekey:") {
		t.Error("the b11 archive still holds a placeholder")
	}
}
