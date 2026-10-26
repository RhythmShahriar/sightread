// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package registry

import (
	"archive/zip"
	"bytes"
	"fmt"
	"io/fs"
)

// Hazard archive kinds.
const (
	hazardZipBomb    = "zipbomb"
	hazardBadEntries = "badentries"
)

// buildHazard builds a crafted zip for an environment scenario. These
// archives exist to prove Sightread's archive limits and path checks
// fire; its payloads never run, so there is no canary here.
func buildHazard(top, kind string) ([]byte, error) {
	switch kind {
	case hazardZipBomb:
		return zipBomb(top)
	case hazardBadEntries:
		return badEntries(top)
	}
	return nil, fmt.Errorf("unknown hazard %q", kind)
}

// zipBomb builds a zip that trips the uncompressed ratio and the entry
// count: one highly compressible 8 MiB entry (ratio well over 200:1) and
// 101,000 empty entries (over the 100,000 cap).
func zipBomb(top string) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zipEntry(zw, top+"/bomb.bin")
	if err != nil {
		return nil, err
	}
	zeros := make([]byte, 1<<20)
	for i := 0; i < 8; i++ {
		if _, err := w.Write(zeros); err != nil {
			return nil, err
		}
	}
	for i := 0; i < 101000; i++ {
		if _, err := zipEntry(zw, fmt.Sprintf("%s/pad/%06d", top, i)); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// badEntries builds a zip whose entry names and modes exercise every
// path check: traversal, absolute, backslash, a symlink, a hardlink, a
// duplicate name and a case or NFC collision.
func badEntries(top string) ([]byte, error) {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	write := func(name string, mode fs.FileMode, body string) error {
		hdr := &zip.FileHeader{Name: name, Method: zip.Deflate, Modified: epoch}
		hdr.SetMode(mode)
		w, err := zw.CreateHeader(hdr)
		if err != nil {
			return err
		}
		_, err = w.Write([]byte(body))
		return err
	}
	entries := []struct {
		name string
		mode fs.FileMode
		body string
	}{
		{top + "/ok.php", 0o644, "<?php // benign\n"},
		{"../escape.php", 0o644, "<?php // traversal\n"},
		{"/abs.php", 0o644, "<?php // absolute\n"},
		{top + `/..\win.php`, 0o644, "<?php // backslash traversal\n"},
		{top + "/link", fs.ModeSymlink | 0o777, "/etc/passwd"},
		{top + "/hard", fs.ModeType | 0o644, top + "/ok.php"},
		{top + "/dup.php", 0o644, "<?php // first\n"},
		{top + "/dup.php", 0o644, "<?php // second (duplicate)\n"},
		{top + "/File.php", 0o644, "<?php // upper\n"},
		{top + "/file.php", 0o644, "<?php // lower (case collision)\n"},
	}
	for _, e := range entries {
		if err := write(e.name, e.mode, e.body); err != nil {
			return nil, err
		}
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// zipEntry creates one stored-mode entry with the fixed modtime.
func zipEntry(zw *zip.Writer, name string) (writer interface{ Write([]byte) (int, error) }, err error) {
	hdr := &zip.FileHeader{Name: name, Method: zip.Deflate, Modified: epoch}
	hdr.SetMode(0o644)
	return zw.CreateHeader(hdr)
}
