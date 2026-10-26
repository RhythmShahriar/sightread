// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package ports

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"strconv"
	"testing"
)

// constants reads every integer constant of ports.go by name, so the
// test sees what the file says rather than what was compiled in.
func constants(t *testing.T) map[string]int {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "ports.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]int{}
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		for i, name := range vs.Names {
			if i >= len(vs.Values) {
				continue
			}
			lit, ok := vs.Values[i].(*ast.BasicLit)
			if !ok || lit.Kind != token.INT {
				continue
			}
			v, err := strconv.Atoi(lit.Value)
			if err != nil {
				t.Fatal(err)
			}
			out[name.Name] = v
		}
		return true
	})
	return out
}

// readmeRows returns the first cell of every ports table row of the
// testbed README: a port or a range such as 23300-23339.
func readmeRows(t *testing.T) map[string]bool {
	t.Helper()
	b, err := os.ReadFile("../README.md")
	if err != nil {
		t.Fatal(err)
	}
	rows := map[string]bool{}
	for _, m := range regexp.MustCompile(`(?m)^\| (\d{5}(?:-\d{5})?) \|`).FindAllStringSubmatch(string(b), -1) {
		rows[m[1]] = true
	}
	return rows
}

// TestREADMEPortsMatchCode keeps the README ports table and this
// package in step, both ways.
func TestREADMEPortsMatchCode(t *testing.T) {
	consts := constants(t)
	if len(consts) < 15 {
		t.Fatalf("read only %d constants from ports.go", len(consts))
	}
	rows := readmeRows(t)
	want := map[string]string{}
	for name, v := range consts {
		switch name {
		case "ProbeBase", "ProbeTop":
			continue
		}
		want[strconv.Itoa(v)] = name
	}
	want[fmt.Sprintf("%d-%d", consts["ProbeBase"], consts["ProbeTop"])] = "ProbeBase-ProbeTop"

	for port, name := range want {
		if !rows[port] {
			t.Errorf("README ports table has no row for %s (%s)", port, name)
		}
	}
	for port := range rows {
		if _, ok := want[port]; !ok {
			t.Errorf("README ports table lists %s, which ports.go does not define", port)
		}
	}
	// The compiled values agree with the parsed ones.
	if consts["WPOrg"] != WPOrg || consts["ClosedProxy"] != ClosedProxy || consts["FrontStall"] != FrontStall {
		t.Error("ports.go parsed differently from the compiled constants")
	}
}

// TestProbesInRange keeps every probe and front inside the reserved
// range.
func TestProbesInRange(t *testing.T) {
	for _, p := range []int{ProbeStall, ProbeEndless, ProbeRetry, ProbeSSRF, ProbeSelfTLS, ProbeRedirectLoopback, ProbeUnconfigured, FrontRetry, FrontStall} {
		if p < ProbeBase || p > ProbeTop {
			t.Errorf("port %d is outside %d-%d", p, ProbeBase, ProbeTop)
		}
	}
}
