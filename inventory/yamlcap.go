// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package inventory

import (
	"errors"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// YAML lockfiles are decoded into yaml.Node, which keeps an alias as a
// pointer, then copied into ynode with a cap on how far each alias may
// expand and how deep the tree may go (SR-32). A billion-laughs file is
// small as a yaml.Node and fails here, fast, before anything grows.
const (
	maxAliasNodes = 10000   // nodes one alias may expand to
	maxYAMLNodes  = 2000000 // nodes in the whole document
	maxYAMLDepth  = 64
)

// errYAMLBomb is the error for a document past those caps.
var errYAMLBomb = errors.New("YAML expands too far (aliases over 10,000 nodes, over 64 levels deep or over 2,000,000 nodes)")

// ynode is a YAML node with aliases expanded, keys in order and lines.
type ynode struct {
	kind  yaml.Kind // ScalarNode, MappingNode or SequenceNode
	value string
	line  int
	keys  []string
	lines []int // the line of each key
	vals  []*ynode
	items []*ynode
}

// get returns the value of key in a mapping, or nil.
func (n *ynode) get(key string) *ynode {
	if n == nil || n.kind != yaml.MappingNode {
		return nil
	}
	for i, k := range n.keys {
		if k == key {
			return n.vals[i]
		}
	}
	return nil
}

// str returns a scalar's text, or "".
func (n *ynode) str() string {
	if n == nil || n.kind != yaml.ScalarNode {
		return ""
	}
	return n.value
}

// parseYAML decodes data into a ynode tree within the caps.
func parseYAML(data []byte) (*ynode, error) {
	if yamlNodeFloor(data) > maxYAMLNodes {
		return nil, errYAMLBomb
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if doc.Kind == 0 {
		return &ynode{kind: yaml.MappingNode}, nil // empty document
	}
	c := &yamlCopier{budget: maxYAMLNodes}
	return c.copy(&doc, 0)
}

// yamlNodeFloor counts, in one pass and without decoding, the marks
// that each start at least one node: a block entry "- ", a mapping
// colon ": " or ":" at the end of a line; a flow "," "[" or "{".
// Quoted text and comments are skipped; a quote opens only where a
// token starts, so a stray one cannot hide the marks after it.
// yaml.Unmarshal builds the whole tree before the copier can count it,
// at a few hundred bytes a node, so a flat 32 MiB "- a" list costs
// gigabytes; this count turns such a file away first. On a real
// lockfile it stays near the true count and so never refuses one the
// copier would take.
func yamlNodeFloor(data []byte) int {
	n := 0
	var quote byte // the open quote on this line, or 0
	lineStart := true
	for i := 0; i < len(data); i++ {
		c := data[i]
		if c == '\n' {
			quote, lineStart = 0, true
			continue
		}
		if quote != 0 {
			if c == quote {
				quote = 0
			}
			continue
		}
		next := byte('\n')
		if i+1 < len(data) {
			next = data[i+1]
		}
		spaceAfter := next == ' ' || next == '\n' || next == '\r' || next == '\t'
		switch c {
		case ' ', '\t', '\r':
			continue
		case '#':
			if i == 0 || isYAMLSpace(data[i-1]) {
				for i+1 < len(data) && data[i+1] != '\n' {
					i++
				}
				continue
			}
		case '\'', '"':
			// A quote opens a scalar only at the start of a token; in
			// "a'b" it is part of a plain word and hides nothing.
			if i == 0 || isYAMLSpace(data[i-1]) || strings.IndexByte("[{,:-?", data[i-1]) >= 0 {
				quote = c
			}
		case '-':
			// Only at the start of a line or after another "- ", so a
			// hyphen inside a plain word is not counted.
			if lineStart && spaceAfter {
				n++
				continue // the next mark on this line may be "- " too
			}
		case ':':
			if spaceAfter {
				n++
			}
		case ',', '[', '{':
			n++
		}
		lineStart = false
	}
	return n
}

// isYAMLSpace reports whether c separates YAML tokens.
func isYAMLSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}

// yamlCopier copies a yaml.Node tree, counting nodes.
type yamlCopier struct {
	budget int
	alias  []int // remaining nodes for each alias being expanded
}

// spend counts one node against the document and every open alias.
func (c *yamlCopier) spend() error {
	c.budget--
	if c.budget < 0 {
		return errYAMLBomb
	}
	for i := range c.alias {
		c.alias[i]--
		if c.alias[i] < 0 {
			return errYAMLBomb
		}
	}
	return nil
}

func (c *yamlCopier) copy(n *yaml.Node, depth int) (*ynode, error) {
	if depth > maxYAMLDepth {
		return nil, errYAMLBomb
	}
	if err := c.spend(); err != nil {
		return nil, err
	}
	switch n.Kind {
	case yaml.DocumentNode:
		if len(n.Content) == 0 {
			return &ynode{kind: yaml.MappingNode}, nil
		}
		return c.copy(n.Content[0], depth)
	case yaml.AliasNode:
		if n.Alias == nil {
			return nil, fmt.Errorf("line %d: alias to nothing", n.Line)
		}
		c.alias = append(c.alias, maxAliasNodes)
		out, err := c.copy(n.Alias, depth+1)
		c.alias = c.alias[:len(c.alias)-1]
		return out, err
	case yaml.ScalarNode:
		return &ynode{kind: yaml.ScalarNode, value: n.Value, line: n.Line}, nil
	case yaml.SequenceNode:
		out := &ynode{kind: yaml.SequenceNode, line: n.Line}
		for _, item := range n.Content {
			v, err := c.copy(item, depth+1)
			if err != nil {
				return nil, err
			}
			out.items = append(out.items, v)
		}
		return out, nil
	case yaml.MappingNode:
		out := &ynode{kind: yaml.MappingNode, line: n.Line}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, err := c.copy(n.Content[i], depth+1)
			if err != nil {
				return nil, err
			}
			v, err := c.copy(n.Content[i+1], depth+1)
			if err != nil {
				return nil, err
			}
			out.keys = append(out.keys, k.value)
			out.lines = append(out.lines, n.Content[i].Line)
			out.vals = append(out.vals, v)
		}
		return out, nil
	}
	return nil, fmt.Errorf("line %d: unexpected YAML node", n.Line)
}
