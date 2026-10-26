// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Command stub stands in for rhythm-roadie, rhythm-soundcheck, wp and an
// --apply command in the stage tests: the test builds it once and copies
// it under each name. It appends what it was asked to STUB_LOG, one JSON
// line per call, and answers from the fixture files the test names.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

type call struct {
	Name string   `json:"name"`
	Args []string `json:"args"`
	// ZipSHA256 is the sha256 of the zip handed to "wp ... install".
	ZipSHA256 string `json:"zip_sha256,omitempty"`
}

func main() {
	name := strings.TrimSuffix(filepath.Base(os.Args[0]), ".exe")
	args := os.Args[1:]
	c := call{Name: name, Args: args}
	if i := slices.Index(args, "install"); name == "wp" && i >= 0 && i+1 < len(args) {
		if b, err := os.ReadFile(args[i+1]); err == nil {
			sum := sha256.Sum256(b)
			c.ZipSHA256 = hex.EncodeToString(sum[:])
		}
	}
	if f, err := os.OpenFile(os.Getenv("STUB_LOG"), os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0o600); err == nil {
		b, _ := json.Marshal(c)
		_, _ = f.Write(append(b, '\n'))
		_ = f.Close()
	}
	key := strings.ToUpper(strings.ReplaceAll(strings.TrimPrefix(name, "rhythm-"), "-", "_"))
	if len(args) > 0 && name == "rhythm-soundcheck" {
		key += "_" + strings.ToUpper(args[0])
	}
	if out := os.Getenv("STUB_" + key + "_OUT"); out != "" {
		if b, err := os.ReadFile(out); err == nil {
			_, _ = os.Stdout.Write(b)
		}
	}
	os.Stderr.WriteString(name + " stub ran\n")
	code, _ := strconv.Atoi(os.Getenv("STUB_" + key + "_EXIT"))
	os.Exit(code)
}
