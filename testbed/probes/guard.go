// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package probes

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// Guard listens on the port HTTPS_PROXY and HTTP_PROXY point at and
// closes every connection after reading its first line, so nothing sent
// through the proxy goes anywhere. Each connection is an egress attempt:
// a request Sightread (or a compared tool) tried to send to a host that
// is not a configured loopback base. The first line names the host
// (CONNECT api.wordpress.org:443 HTTP/1.1), which the benchmark lists.
type Guard struct {
	ln       net.Listener
	mu       sync.Mutex
	attempts []string
	done     chan struct{}
}

// StartGuard listens on 127.0.0.1:port.
func StartGuard(port int) (*Guard, error) {
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, fmt.Errorf("guard listen %d: %w", port, err)
	}
	g := &Guard{ln: ln, done: make(chan struct{})}
	go g.accept()
	return g, nil
}

// accept records and closes connections until the listener closes.
func (g *Guard) accept() {
	defer close(g.done)
	for {
		c, err := g.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			continue
		}
		go g.record(c)
	}
}

// record reads the request line (briefly) and closes the connection.
func (g *Guard) record(c net.Conn) {
	defer func() { _ = c.Close() }()
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	line, _ := bufio.NewReaderSize(c, 4096).ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		line = "(no request line)"
	}
	g.mu.Lock()
	g.attempts = append(g.attempts, line)
	g.mu.Unlock()
}

// Attempts returns the request lines seen so far, oldest first.
func (g *Guard) Attempts() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.attempts...)
}

// Count returns how many connections reached the guard.
func (g *Guard) Count() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.attempts)
}

// Close stops listening.
func (g *Guard) Close() error {
	err := g.ln.Close()
	<-g.done
	return err
}
