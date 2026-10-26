// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package exectest

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const module = "github.com/RhythmShahriar/sightread"

type pkg struct {
	ImportPath string
	Dir        string
	Imports    []string
	GoFiles    []string
	Module     *struct{ Path string }
	Standard   bool
}

// root returns the module's folder.
func root(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("go", "env", "GOMOD").Output()
	if err != nil {
		t.Fatalf("go env GOMOD: %v", err)
	}
	gomod := strings.TrimSpace(string(out))
	if gomod == "" || gomod == os.DevNull {
		t.Fatal("not inside the module")
	}
	return filepath.Dir(gomod)
}

// list runs go list -deps -json ./... over every OS the module builds
// for, so a Windows- or Unix-only file can't hide an import.
func list(t *testing.T) []pkg {
	t.Helper()
	dir := root(t)
	seen := map[string]bool{}
	var all []pkg
	for _, goos := range []string{"linux", "darwin", "windows"} {
		cmd := exec.Command("go", "list", "-deps", "-json", "./...")
		cmd.Dir = dir
		cmd.Env = append(os.Environ(), "GOOS="+goos, "GOWORK=off", "CGO_ENABLED=0")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("go list (%s): %v\n%s", goos, err, stderr.String())
		}
		dec := json.NewDecoder(bytes.NewReader(out))
		for {
			var p pkg
			if err := dec.Decode(&p); errors.Is(err, io.EOF) {
				break
			} else if err != nil {
				t.Fatal(err)
			}
			key := goos + " " + p.ImportPath
			if !seen[key] {
				seen[key] = true
				all = append(all, p)
			}
		}
	}
	return all
}

func ours(p pkg) bool { return p.Module != nil && p.Module.Path == module }

func rel(p pkg) string {
	if p.ImportPath == module {
		return "."
	}
	return strings.TrimPrefix(p.ImportPath, module+"/")
}

// mayRunPrograms are the packages allowed to import internal/proc: they
// start git, the user's wp command, Soundcheck and Roadie, the watch
// child run or the opener.
var mayRunPrograms = map[string]bool{
	"inventory/wpcli":      true,
	"inventory/gitref":     true,
	"stage":                true,
	"watch":                true,
	"cmd/rhythm-sightread": true,
}

// readsPackageText are the trees that handle fetched package text. They
// must not import the network: a detector or lexer never resolves or
// contacts a domain it finds.
var readsPackageText = []string{"analyze", "lex", "detect"}

// netPackages are the standard packages that open connections. net/url,
// net/netip and net/mail only parse text and are fine.
func netPackage(imp string) bool {
	switch {
	case imp == "net", imp == "net/rpc", imp == "net/smtp", imp == "crypto/tls":
		return true
	case imp == "net/http" || strings.HasPrefix(imp, "net/http/"):
		return true
	}
	return false
}

// engines are module paths of code engines and git libraries Sightread
// must never link: running JavaScript, WASM or PHP is out. git is
// only ever the user's git binary through internal/proc.
var engines = []string{"go-git", "goja", "v8go", "wazero", "/otto", "quickjs"}

func TestOnlyProcStartsPrograms(t *testing.T) {
	for _, p := range list(t) {
		if !ours(p) {
			continue
		}
		name := rel(p)
		for _, imp := range p.Imports {
			if (imp == "os/exec" || imp == "plugin") && name != "internal/proc" {
				t.Errorf("%s imports %s: start programs through internal/proc", name, imp)
			}
			if imp == module+"/internal/proc" && !mayRunPrograms[name] {
				t.Errorf("%s imports internal/proc but has no program to start (allowed: inventory/wpcli, inventory/gitref, stage, watch, cmd/rhythm-sightread)", name)
			}
		}
	}
}

func TestNoCodeEngines(t *testing.T) {
	for _, p := range list(t) {
		if p.Module == nil {
			continue
		}
		path := strings.ToLower(p.Module.Path)
		for _, e := range engines {
			if strings.Contains(path, e) {
				t.Errorf("module %s (via %s) is a code engine or git library", p.Module.Path, p.ImportPath)
			}
		}
	}
}

func TestPackageTextStaysOffline(t *testing.T) {
	for _, p := range list(t) {
		if !ours(p) {
			continue
		}
		name := rel(p)
		for _, top := range readsPackageText {
			if name != top && !strings.HasPrefix(name, top+"/") {
				continue
			}
			for _, imp := range p.Imports {
				if netPackage(imp) {
					t.Errorf("%s imports %s: code that reads package text never touches the network", name, imp)
				}
			}
		}
	}
}

// TestNoSyscallExecOrInsecureTLS reads every Go file: syscall.Exec
// replaces the process with another program. Turning off TLS
// verification lets anyone in the middle swap a package.
func TestNoSyscallExecOrInsecureTLS(t *testing.T) {
	dir := root(t)
	self, _ := filepath.Abs("exec_test.go")
	insecure := "Insecure" + "SkipVerify" // split so this file doesn't match itself
	sysExec := "syscall." + "Exec"
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "node_modules", "vendor", "dist", "bin":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || path == self {
			return nil
		}
		b, err := os.ReadFile(path) //nolint:gosec // the module's own sources
		if err != nil {
			return err
		}
		r, _ := filepath.Rel(dir, path)
		if bytes.Contains(b, []byte(insecure)) {
			t.Errorf("%s mentions %s: TLS is always verified", filepath.ToSlash(r), insecure)
		}
		if bytes.Contains(b, []byte(sysExec)) {
			t.Errorf("%s calls %s", filepath.ToSlash(r), sysExec)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
