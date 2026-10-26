// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package blob

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"sync"

	"github.com/RhythmShahriar/sightread/core"
)

// Mem is a blob store in memory, for tests and the demo. Path always
// reports false, so --soundcheck can't hand off a memory blob.
type Mem struct {
	mu sync.Mutex
	m  map[[32]byte][]byte
}

// Memory returns an empty memory store.
func Memory() *Mem { return &Mem{m: map[[32]byte][]byte{}} }

// Put stores up to limit bytes of r; more is core.ErrTooLarge and stores
// nothing.
func (s *Mem) Put(ctx context.Context, r io.Reader, limit int64) ([32]byte, int64, error) {
	if err := ctx.Err(); err != nil {
		return [32]byte{}, 0, err
	}
	data, err := io.ReadAll(io.LimitReader(ctxReader{ctx: ctx, r: r}, limit+1))
	if err != nil {
		return [32]byte{}, 0, err
	}
	if int64(len(data)) > limit {
		return [32]byte{}, 0, core.ErrTooLarge
	}
	sum := sha256.Sum256(data)
	s.mu.Lock()
	s.m[sum] = data
	s.mu.Unlock()
	return sum, int64(len(data)), nil
}

// Open reads a blob back, re-hashing it first.
func (s *Mem) Open(sum [32]byte) (io.ReadCloser, error) {
	s.mu.Lock()
	data, ok := s.m[sum]
	s.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("blob %x: not stored", sum[:4])
	}
	if sha256.Sum256(data) != sum {
		return nil, core.ErrBlobCorrupt
	}
	return io.NopCloser(bytes.NewReader(data)), nil
}

// Has reports whether sum is stored.
func (s *Mem) Has(sum [32]byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.m[sum]
	return ok
}

// Path reports false: memory blobs have no file.
func (s *Mem) Path([32]byte) (string, bool) { return "", false }

// Len is how many blobs are stored.
func (s *Mem) Len() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.m)
}
