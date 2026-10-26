// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package archive

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"testing"

	"github.com/RhythmShahriar/sightread/blob"
	"github.com/RhythmShahriar/sightread/core"
)

// store puts data into blobs as the Getter would and returns the
// Download it reports.
func store(t *testing.T, blobs core.BlobStore, data []byte) core.Download {
	t.Helper()
	sum, n, err := blobs.Put(context.Background(), bytes.NewReader(data), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	d := core.Download{SHA256: sum, Size: n}
	d.Path, _ = blobs.Path(sum)
	return d
}

func TestReadZipDownload(t *testing.T) {
	data := makeZip(t, zent{name: "akismet/akismet.php", body: "<?php // a"}, zent{name: "akismet/readme.txt", body: "=== A ==="})
	disk, err := blob.OpenDisk(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	for name, blobs := range map[string]core.BlobStore{"memory": blob.Memory(), "disk": disk} {
		d := store(t, blobs, data)
		tree, err := ReadZipDownload(context.Background(), d, blobs, core.Limits{}, StripFolder("akismet"))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if tree.SHA256 != sha256.Sum256(data) || tree.Root != "akismet/" || len(tree.Files) != 2 {
			t.Errorf("%s: tree %+v", name, tree)
		}
	}
}

func TestReadZipDownloadCorrupt(t *testing.T) {
	data := makeZip(t, zent{name: "a.php", body: "<?php"})
	disk, err := blob.OpenDisk(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d := store(t, disk, data)
	// Someone changed the blob after it was downloaded.
	changed := bytes.Replace(data, []byte("<?php"), []byte("<?PHP"), 1)
	if err := os.WriteFile(d.Path, changed, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadZipDownload(context.Background(), d, disk, core.Limits{}, StripSingle); !errors.Is(err, core.ErrBlobCorrupt) {
		t.Errorf("changed blob on disk: %v, want ErrBlobCorrupt", err)
	}

	mem := blob.Memory()
	d = store(t, mem, data)
	d.Size++ // the Download says more than the store holds
	if _, err := ReadZipDownload(context.Background(), d, mem, core.Limits{}, StripSingle); !errors.Is(err, core.ErrBlobCorrupt) {
		t.Errorf("short blob: %v, want ErrBlobCorrupt", err)
	}
	if _, err := ReadZipDownload(context.Background(), core.Download{Size: 1}, mem, core.Limits{}, StripSingle); err == nil {
		t.Error("missing blob read")
	}
}

// A blob that went bad on disk fails one read and is deleted, and the
// next download stores it fresh, so later runs read it again.
func TestReadZipDownloadRepairs(t *testing.T) {
	data := makeZip(t, zent{name: "a.php", body: "<?php"})
	disk, err := blob.OpenDisk(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	d := store(t, disk, data)
	flipped := bytes.Clone(data)
	flipped[0] ^= 0xff
	if err := os.WriteFile(d.Path, flipped, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadZipDownload(context.Background(), d, disk, core.Limits{}, StripSingle); !errors.Is(err, core.ErrBlobCorrupt) {
		t.Fatalf("corrupt blob: %v, want ErrBlobCorrupt", err)
	}
	if disk.Has(d.SHA256) {
		t.Error("corrupt blob kept after a failed read")
	}
	if err := os.WriteFile(d.Path, flipped, 0o600); err != nil {
		t.Fatal(err)
	}
	// The next run downloads the same bytes over the bad blob.
	d = store(t, disk, data)
	for run := range 3 {
		if _, err := ReadZipDownload(context.Background(), d, disk, core.Limits{}, StripSingle); err != nil {
			t.Fatalf("run %d: %v", run, err)
		}
	}
}
