// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

// Package canary is the testbed's tripwire. Every malicious fixture
// payload, if its code ever ran, would open a connection to the canary
// port and write a file into the canary folder. The listener counts and
// logs every connection and the watcher reads the folder, so a test can
// assert that across a whole benchmark the canary never fired, which is
// how the testbed proves Sightread never executes what it downloads.
package canary

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/RhythmShahriar/sightread/testbed/ports"
)

// Canary is the running tripwire: a TCP listener and the folder a
// payload would write into.
type Canary struct {
	stateDir string
	ln       net.Listener
	logFile  *os.File
	mu       sync.Mutex
	count    int
	closed   chan struct{}
}

// hit is one connection as the log records it.
type hit struct {
	Time   string `json:"time"`
	Remote string `json:"remote"`
}

// canaryDir is the folder a payload would drop a file into.
func canaryDir(stateDir string) string { return filepath.Join(stateDir, "canary") }

// New opens the connection log and creates the canary folder. The
// listener is bound by Start.
func New(stateDir string) (*Canary, error) {
	if err := os.MkdirAll(canaryDir(stateDir), 0o755); err != nil { //nolint:gosec // testbed state
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(stateDir, "canary.log"), os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644) //nolint:gosec // testbed log
	if err != nil {
		return nil, err
	}
	return &Canary{stateDir: stateDir, logFile: f, closed: make(chan struct{})}, nil
}

// Start binds the canary port and accepts connections in the background.
func (c *Canary) Start() error { return c.StartOn(ports.Canary) }

// StartOn binds 127.0.0.1:port instead; 0 picks a free port (see Port),
// so unit tests run beside make up or a bench. The fixtures' payloads
// target ports.Canary, so the benchmark always uses Start.
func (c *Canary) StartOn(port int) error {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return fmt.Errorf("canary listen: %w", err)
	}
	c.ln = ln
	go c.accept()
	return nil
}

// accept logs and counts every connection, then closes it at once.
func (c *Canary) accept() {
	for {
		conn, err := c.ln.Accept()
		if err != nil {
			select {
			case <-c.closed:
				return
			default:
				return
			}
		}
		c.record(conn.RemoteAddr().String())
		_ = conn.Close()
	}
}

// record logs one connection and bumps the count.
func (c *Canary) record(remote string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.count++
	if b, err := json.Marshal(hit{Time: time.Now().UTC().Format(time.RFC3339Nano), Remote: remote}); err == nil {
		_, _ = c.logFile.Write(append(b, '\n'))
	}
}

// Count returns how many connections the canary has seen.
func (c *Canary) Count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.count
}

// Files lists the files a payload dropped into the canary folder.
func (c *Canary) Files() ([]string, error) {
	entries, err := os.ReadDir(canaryDir(c.stateDir))
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() {
			names = append(names, e.Name())
		}
	}
	return names, nil
}

// Fired reports whether the canary tripped at all: any connection or any
// dropped file. A clean benchmark leaves it false.
func (c *Canary) Fired() bool {
	if c.Count() > 0 {
		return true
	}
	files, err := c.Files()
	return err == nil && len(files) > 0
}

// Close stops the listener and closes the log.
func (c *Canary) Close() error {
	close(c.closed)
	var err error
	if c.ln != nil {
		err = c.ln.Close()
	}
	if c.logFile != nil {
		if e := c.logFile.Close(); e != nil && err == nil {
			err = e
		}
	}
	return err
}

// Port returns the port the canary listens on, once started.
func (c *Canary) Port() int { return c.ln.Addr().(*net.TCPAddr).Port }
