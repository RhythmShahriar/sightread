// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package large generates p01-large, the performance fixture of PRD 17:
// a WordPress plugin of about 4,000 PHP files and 40 MB in two versions,
// written to disk at the start of a benchmark (never committed). It is
// not a scored scenario; the benchmark reviews the pair with --from-file
// and --to-file and holds the warm run to under 10 s and 512 MB RSS.
//
// The files are plain, benign PHP built from a seeded generator, so the
// same bytes come out on every machine and run.
package large

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
)

// Spec sizes the fixture.
type Spec struct {
	// Files is the number of PHP files in the old version.
	Files int
	// FileBytes is the approximate size of each file.
	FileBytes int
	// Changed is how many files the new version edits.
	Changed int
	// Added is how many files the new version adds.
	Added int
}

// Default is the PRD 17 fixture: 4,000 files of about 10 KB (40 MB), with
// 200 files edited and 20 added in the new version.
var Default = Spec{Files: 4000, FileBytes: 10 * 1024, Changed: 200, Added: 20}

// Slug is the plugin folder name and the name the benchmark reviews.
const Slug = "p01-large"

// marker records the spec a folder was built with, so a second run with
// the same spec reuses it.
const marker = ".p01-spec"

// Generate writes dir/old and dir/new for spec. When dir already holds
// a build of the same spec it is kept as it is.
func Generate(dir string, spec Spec) error {
	stamp := fmt.Sprintf("%+v\n", spec)
	if b, err := os.ReadFile(filepath.Join(dir, marker)); err == nil && string(b) == stamp { //nolint:gosec // the benchmark's own folder
		return nil
	}
	if err := os.RemoveAll(dir); err != nil {
		return err
	}
	for _, side := range []string{"old", "new"} {
		if err := writeSide(filepath.Join(dir, side), spec, side == "new"); err != nil {
			return err
		}
	}
	return os.WriteFile(filepath.Join(dir, marker), []byte(stamp), 0o644) //nolint:gosec // not a secret
}

// writeSide writes one version. The new version edits every n-th file
// and adds spec.Added files; the rest are byte-identical to the old.
func writeSide(root string, spec Spec, isNew bool) error {
	version := "1.0.0"
	if isNew {
		version = "1.1.0"
	}
	main := fmt.Sprintf("<?php\n/*\nPlugin Name: P01 Large\nVersion: %s\n*/\nrequire_once __DIR__ . '/includes/loader.php';\n", version)
	if err := write(filepath.Join(root, Slug+".php"), []byte(main)); err != nil {
		return err
	}
	every := 0
	if spec.Changed > 0 {
		every = spec.Files / spec.Changed
	}
	for i := 0; i < spec.Files; i++ {
		edited := isNew && every > 0 && i%every == 0
		if err := write(filePath(root, i), File(i, spec.FileBytes, edited)); err != nil {
			return err
		}
	}
	if isNew {
		for i := spec.Files; i < spec.Files+spec.Added; i++ {
			if err := write(filePath(root, i), File(i, spec.FileBytes, false)); err != nil {
				return err
			}
		}
	}
	return nil
}

// filePath spreads the files over folders of 40.
func filePath(root string, i int) string {
	return filepath.Join(root, "includes", fmt.Sprintf("mod-%03d", i/40), fmt.Sprintf("file-%05d.php", i))
}

func write(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil { //nolint:gosec // fixture tree
		return err
	}
	return os.WriteFile(path, b, 0o644) //nolint:gosec // fixture file
}

// words feed the generated strings and comments.
var words = strings.Fields("order item total label price stock title summary field option value " +
	"customer address status note shipping tax discount coupon cart product review rating")

// File returns the content of file i of about size bytes. An edited file
// keeps the old functions and adds one, the way a feature release grows.
func File(i, size int, edited bool) []byte {
	r := rand.New(rand.NewPCG(uint64(i), 0x5eed)) //nolint:gosec // deterministic fixture text, not security
	var b bytes.Buffer
	fmt.Fprintf(&b, "<?php\n/**\n * Generated fixture file %d for the p01-large performance check.\n */\n\n", i)
	for k := 0; b.Len() < size; k++ {
		w1, w2 := words[r.IntN(len(words))], words[r.IntN(len(words))]
		fmt.Fprintf(&b, "/**\n * Returns the %s %s for row %d.\n */\n", w1, w2, k)
		fmt.Fprintf(&b, "function p01_fn_%d_%d( $a, $b ) {\n", i, k)
		fmt.Fprintf(&b, "\t$total = $a + $b * %d;\n", r.IntN(1000))
		fmt.Fprintf(&b, "\treturn array( 'id' => %d, 'label' => '%s %s', 'total' => $total );\n}\n\n", k, w1, w2)
	}
	if edited {
		fmt.Fprintf(&b, "function p01_fn_%d_added( $rows ) {\n\treturn count( $rows );\n}\n", i)
	}
	return b.Bytes()
}
