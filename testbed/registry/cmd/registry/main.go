// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Command registry starts the testbed's fixture registry on loopback so
// a person can point Sightread at it by hand. The benchmark starts the
// same library (testbed/registry) in process; this command is for
// `make -C testbed up` and for the demo.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"

	"github.com/RhythmShahriar/sightread/testbed/ports"
	"github.com/RhythmShahriar/sightread/testbed/registry"
)

// envPortBase is PORT_BASE when it is a number, else the documented
// WordPress.org port.
func envPortBase() int {
	if n, err := strconv.Atoi(os.Getenv("PORT_BASE")); err == nil {
		return n
	}
	return ports.WPOrg
}

func main() {
	packages := flag.String("packages", "packages", "the scenario folders")
	state := flag.String("state", "state", "the state, CA and request log folder")
	plain := flag.Bool("plain-http", false, "serve plain HTTP instead of TLS (loopback mirror tests)")
	base := flag.Int("port-base", envPortBase(), "the WordPress.org port; the others follow it (Packagist +1, GitHub +2, npm +3, OSV +4, codeload +8). Also PORT_BASE")
	flag.Parse()
	if *base < 1024 || *base > 65535-8 {
		fmt.Fprintf(os.Stderr, "registry: -port-base %d: want a port from 1024 to %d\n", *base, 65535-8)
		os.Exit(2)
	}

	reg, err := registry.New(registry.Options{PackagesDir: *packages, StateDir: *state, PlainHTTP: *plain, PortBase: *base})
	if err != nil {
		fmt.Fprintln(os.Stderr, "registry:", err)
		os.Exit(1)
	}
	if err := reg.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "registry:", err)
		os.Exit(1)
	}
	// env.sh reads where the registry is from here.
	if err := os.WriteFile(filepath.Join(*state, "port-base"), []byte(strconv.Itoa(*base)+"\n"), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, "registry:", err)
		os.Exit(1)
	}
	scheme := "https"
	if *plain {
		scheme = "http"
	}
	fmt.Printf("fixture registry up (%s) on 127.0.0.1:%d-%d and localhost:%d. CA in %s/ca.pem, keys in %s/npm-keys.json.\n",
		scheme, *base, *base+4, *base+8, *state, *state)
	fmt.Println("Ctrl-C to stop.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	if err := reg.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "registry:", err)
		os.Exit(1)
	}
}
