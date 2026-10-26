// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Command webhook runs the testbed notification receiver for `make up`.
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/RhythmShahriar/sightread/testbed/webhook"
)

func main() {
	r, err := webhook.New()
	if err != nil {
		fmt.Fprintln(os.Stderr, "webhook:", err)
		os.Exit(1)
	}
	r.Start()
	fmt.Println("webhook receiver up; Ctrl-C to stop.")
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	<-sig
	if err := r.Close(); err != nil {
		fmt.Fprintln(os.Stderr, "webhook:", err)
	}
}
