// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package policy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"

	"github.com/RhythmShahriar/rhythm/kit/cli"
	"gopkg.in/yaml.v3"
)

// The caps of the node walk that runs before any YAML is decoded. A
// config or allow file is a few hundred values; these only stop a file
// built to expand (the "billion laughs" shape) or to recurse.
const (
	maxAliasNodes = 10_000  // values one alias may stand for
	maxExtraNodes = 100_000 // values all aliases together may add
	maxDepth      = 64      // nesting, aliases expanded
)

// decodeStrict decodes one YAML document into v, a pointer to a struct.
// It first walks the parsed nodes: it caps alias expansion and depth,
// and checks every mapping key against v's yaml tags so an unknown key
// is named with the nearest valid one. Only then does yaml.v3 decode
// with KnownFields as a backstop. Errors are plain text without the
// file name; the caller adds it.
func decodeStrict(data []byte, v any) error {
	var doc yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil // an empty file sets nothing
		}
		return cleanYAMLError(err)
	}
	var more yaml.Node
	if err := dec.Decode(&more); err == nil {
		return errors.New("holds more than one YAML document; keep the settings in one")
	} else if !errors.Is(err, io.EOF) {
		return cleanYAMLError(err)
	}

	w := &walker{memo: map[*yaml.Node]shape{}, open: map[*yaml.Node]bool{}}
	if _, err := w.measure(&doc); err != nil {
		return err
	}
	if err := w.check(&doc, reflect.TypeOf(v).Elem(), nil); err != nil {
		return err
	}

	strict := yaml.NewDecoder(bytes.NewReader(data))
	strict.KnownFields(true)
	if err := strict.Decode(v); err != nil && !errors.Is(err, io.EOF) {
		return cleanYAMLError(err)
	}
	return nil
}

// shape is a node's size and height with every alias expanded.
type shape struct{ nodes, height int }

type walker struct {
	memo  map[*yaml.Node]shape
	open  map[*yaml.Node]bool // on the current path, to refuse a cycle
	extra int                 // values aliases added so far
}

// measure returns n's expanded shape, failing as soon as an alias
// stands for too many values, all aliases together add too many or the
// nesting goes too deep. Shapes are memoised, so a file is measured in
// time linear in its real size however far it would expand.
func (w *walker) measure(n *yaml.Node) (shape, error) {
	if s, ok := w.memo[n]; ok {
		return s, nil
	}
	if w.open[n] {
		return shape{}, fmt.Errorf("line %d: an alias refers to itself", n.Line)
	}
	w.open[n] = true
	defer delete(w.open, n)

	var s shape
	if n.Kind == yaml.AliasNode {
		if n.Alias == nil {
			return shape{}, fmt.Errorf("line %d: an alias has no anchor", n.Line)
		}
		t, err := w.measure(n.Alias)
		if err != nil {
			return shape{}, err
		}
		if t.nodes > maxAliasNodes {
			return shape{}, fmt.Errorf("line %d: alias *%s stands for over %d values; write the values out", n.Line, n.Value, maxAliasNodes)
		}
		if w.extra += t.nodes; w.extra > maxExtraNodes {
			return shape{}, fmt.Errorf("line %d: aliases expand to over %d values; write the values out", n.Line, maxExtraNodes)
		}
		s = t
	} else {
		s = shape{nodes: 1, height: 1}
		for _, c := range n.Content {
			cs, err := w.measure(c)
			if err != nil {
				return shape{}, err
			}
			s.nodes += cs.nodes
			s.height = max(s.height, cs.height+1)
		}
	}
	if s.height > maxDepth {
		return shape{}, fmt.Errorf("line %d: nests deeper than %d levels", n.Line, maxDepth)
	}
	w.memo[n] = s
	return s, nil
}

// check matches the node tree against Go type t, naming the first
// unknown key or wrong kind of value. at is the path of keys so far.
func (w *walker) check(n *yaml.Node, t reflect.Type, at []string) error {
	for n.Kind == yaml.DocumentNode || n.Kind == yaml.AliasNode {
		if n.Kind == yaml.DocumentNode {
			if len(n.Content) == 0 {
				return nil
			}
			n = n.Content[0]
		} else {
			n = n.Alias
		}
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if n.Kind == yaml.ScalarNode && n.Tag == "!!null" {
		return nil // "key:" or "key: ~" leaves the value unset
	}
	where := strings.Join(at, ".")
	switch t.Kind() {
	case reflect.Struct:
		if n.Kind != yaml.MappingNode {
			return kindError(n, where, "keys and values")
		}
		fields := yamlFields(t)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, val := n.Content[i], n.Content[i+1]
			if k.Value == "<<" {
				if err := w.check(val, t, at); err != nil {
					return err
				}
				continue
			}
			ft, ok := fields[k.Value]
			if !ok {
				return unknownKey(k, at, fields)
			}
			if err := w.check(val, ft, append(slices.Clip(at), k.Value)); err != nil {
				return err
			}
		}
	case reflect.Map:
		if n.Kind != yaml.MappingNode {
			return kindError(n, where, "keys and values")
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			if err := w.check(n.Content[i+1], t.Elem(), append(slices.Clip(at), n.Content[i].Value)); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if n.Kind != yaml.SequenceNode {
			return kindError(n, where, "a list")
		}
		for i, c := range n.Content {
			if err := w.check(c, t.Elem(), append(slices.Clip(at), fmt.Sprintf("%d", i+1))); err != nil {
				return err
			}
		}
	default:
		if n.Kind != yaml.ScalarNode {
			return kindError(n, where, "a single value")
		}
	}
	return nil
}

// yamlFields maps each yaml key of struct t to its field type.
func yamlFields(t reflect.Type) map[string]reflect.Type {
	m := map[string]reflect.Type{}
	for i := range t.NumField() {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if name == "-" {
			continue
		}
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		m[name] = f.Type
	}
	return m
}

// unknownKey names the unknown key, where it is and the nearest valid key
// at that level: "unknown key fial_on (did you mean fail_on?)" or
// "unknown key regstry in sources.npm (did you mean registry?)".
func unknownKey(k *yaml.Node, at []string, fields map[string]reflect.Type) error {
	msg := "unknown key " + quoteIfOdd(k.Value)
	if len(at) > 0 {
		msg += " in " + describe(at)
	}
	keys := make([]string, 0, len(fields))
	for f := range fields {
		keys = append(keys, f)
	}
	slices.Sort(keys)
	if s := cli.Suggest(k.Value, keys); s != "" {
		msg += " (did you mean " + s + "?)"
	} else {
		msg += fmt.Sprintf(" (line %d)", k.Line)
	}
	return errors.New(msg)
}

// kindError says a key holds the wrong kind of value.
func kindError(n *yaml.Node, where, want string) error {
	if where == "" {
		return fmt.Errorf("line %d: the file must hold keys and values", n.Line)
	}
	return fmt.Errorf("line %d: %s wants %s", n.Line, where, want)
}

// describe writes a key path for a message. List positions are 1-based
// and read "ignore 2" rather than "ignore.2".
func describe(at []string) string {
	var b strings.Builder
	for i, p := range at {
		switch {
		case i == 0:
			b.WriteString(p)
		case isIndex(p):
			b.WriteString(" " + p)
		default:
			b.WriteString("." + p)
		}
	}
	return b.String()
}

func isIndex(s string) bool {
	return s != "" && strings.Trim(s, "0123456789") == ""
}

// quoteIfOdd quotes a key that holds anything beyond the characters keys
// are made of, so a key with a space or control character is visible.
func quoteIfOdd(s string) string {
	if s != "" && strings.Trim(s, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-@.*/") == "" {
		return s
	}
	return fmt.Sprintf("%q", s)
}

// cleanYAMLError drops yaml.v3's "yaml: " prefix and joins a multi-line
// unmarshal error into one line.
func cleanYAMLError(err error) error {
	s := strings.TrimPrefix(err.Error(), "yaml: ")
	s = strings.TrimPrefix(s, "unmarshal errors:\n")
	lines := strings.Split(s, "\n")
	for i := range lines {
		lines[i] = strings.TrimSpace(lines[i])
	}
	return errors.New(strings.Join(lines, "; "))
}
