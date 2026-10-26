// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package registry

import (
	"encoding/json"
	"os"
	"sync"
	"time"
)

// reqLog appends one JSON line per request to testbed/state/requests.log
// so the privacy and egress tests can read back exactly which host and
// path Sightread asked for. It records the host, path and raw query, not
// headers or bodies.
type reqLog struct {
	mu sync.Mutex
	f  *os.File
}

// logLine is one request as the log records it.
type logLine struct {
	Time   string `json:"time"`
	Host   string `json:"host"`
	Method string `json:"method"`
	Path   string `json:"path"`
	Query  string `json:"query,omitempty"`
}

// openReqLog truncates and opens the request log at path.
func openReqLog(path string) (*reqLog, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644) //nolint:gosec // testbed log
	if err != nil {
		return nil, err
	}
	return &reqLog{f: f}, nil
}

// record writes one line.
func (l *reqLog) record(host, method, path, query string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	b, err := json.Marshal(logLine{
		Time:   time.Now().UTC().Format(time.RFC3339Nano),
		Host:   host,
		Method: method,
		Path:   path,
		Query:  query,
	})
	if err != nil {
		return
	}
	_, _ = l.f.Write(append(b, '\n'))
}

// Close closes the log file.
func (l *reqLog) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.f.Close()
}
