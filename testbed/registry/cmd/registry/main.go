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
	"syscall"

	"github.com/RhythmShahriar/sightread/testbed/registry"
)

func main() {
	packages := flag.String("packages", "packages", "the scenario folders")
	state := flag.String("state", "state", "the state, CA and request log folder")
	plain := flag.Bool("plain-http", false, "serve plain HTTP instead of TLS (loopback mirror tests)")
	flag.Parse()

	reg, err := registry.New(registry.Options{PackagesDir: *packages, StateDir: *state, PlainHTTP: *plain})
	if err != nil {
		fmt.Fprintln(os.Stderr, "registry:", err)
		os.Exit(1)
	}
	if err := reg.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "registry:", err)
		os.Exit(1)
	}
	scheme := "https"
	if *plain {
		scheme = "http"
	}
	fmt.Printf("fixture registry up (%s). CA in %s/ca.pem, keys in %s/npm-keys.json.\n", scheme, *state, *state)
	fmt.Println("Ctrl-C to stop.")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	if err := reg.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "registry:", err)
		os.Exit(1)
	}
}
