// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Command canary runs the testbed tripwire on loopback for `make up`.
package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/RhythmShahriar/sightread/testbed/canary"
)

func main() {
	state := flag.String("state", "state", "the state folder")
	flag.Parse()
	c, err := canary.New(*state)
	if err != nil {
		fmt.Fprintln(os.Stderr, "canary:", err)
		os.Exit(1)
	}
	if err := c.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "canary:", err)
		os.Exit(1)
	}
	fmt.Println("canary up; Ctrl-C to stop.")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	if err := c.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "canary:", err)
	}
	fmt.Printf("canary saw %d connections\n", c.Count())
}
