// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package pairs

import (
	"fmt"
	"reflect"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// yaml.v3 has no strict mode for yaml.Node.Decode while core's types
// carry no yaml tags (yaml.v3 would want "requiresphp" for RequiresPHP).
// decodeStrict walks the node against the Go type first: it refuses
// unknown keys with their line and renames snake_case keys
// ("requires_php") to the lower-case field names yaml.v3 matches. Map
// keys are left alone, since a dependency may well be called a_b.

var (
	timeType        = reflect.TypeFor[time.Time]()
	unmarshalerType = reflect.TypeFor[yaml.Unmarshaler]()
)

// decodeStrict checks n against dst's type and decodes it into dst.
func decodeStrict(n *yaml.Node, dst any) error {
	if err := normalise(n, reflect.TypeOf(dst)); err != nil {
		return err
	}
	return n.Decode(dst)
}

// fieldNames maps each key a struct accepts to the name yaml.v3 decodes
// it under: the yaml tag when there is one, else the lower-case field
// name, reachable also as snake_case.
func fieldNames(t reflect.Type) map[string]string {
	names := map[string]string{}
	for f := range t.Fields() {
		if !f.IsExported() {
			continue
		}
		if tag, ok := f.Tag.Lookup("yaml"); ok {
			name, _, _ := strings.Cut(tag, ",")
			if name == "-" {
				continue
			}
			if name != "" {
				names[name] = name
				continue
			}
		}
		lower := strings.ToLower(f.Name)
		names[lower] = lower
		names[snake(f.Name)] = lower
	}
	return names
}

// snake turns a Go field name into snake_case: RequiresPHP is
// requires_php, EndLine is end_line, OldIntegrity is old_integrity.
func snake(name string) string {
	var b strings.Builder
	rs := []rune(name)
	for i, r := range rs {
		upper := r >= 'A' && r <= 'Z'
		if upper && i > 0 {
			prevLower := rs[i-1] >= 'a' && rs[i-1] <= 'z'
			nextLower := i+1 < len(rs) && rs[i+1] >= 'a' && rs[i+1] <= 'z'
			prevUpper := rs[i-1] >= 'A' && rs[i-1] <= 'Z'
			if prevLower || prevUpper && nextLower {
				b.WriteByte('_')
			}
		}
		b.WriteRune(r)
	}
	return strings.ToLower(b.String())
}

func normalise(n *yaml.Node, t reflect.Type) error {
	if n.Kind == yaml.AliasNode && n.Alias != nil {
		n = n.Alias
	}
	if t.Implements(unmarshalerType) {
		return nil // it checks itself
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
		if t.Implements(unmarshalerType) || reflect.PointerTo(t).Implements(unmarshalerType) {
			return nil
		}
	}
	if t == timeType {
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		if n.Kind != yaml.MappingNode {
			return nil // Decode reports the type error with its line
		}
		names := fieldNames(t)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			name, ok := names[k.Value]
			if !ok {
				return fmt.Errorf("line %d: unknown key %q", k.Line, k.Value)
			}
			k.Value = name
			f, _ := fieldByYAMLName(t, name)
			if err := normalise(n.Content[i+1], f.Type); err != nil {
				return fmt.Errorf("%s: %w", name, err)
			}
		}
	case reflect.Map:
		if n.Kind != yaml.MappingNode {
			return nil
		}
		for i := 1; i < len(n.Content); i += 2 {
			if err := normalise(n.Content[i], t.Elem()); err != nil {
				return err
			}
		}
	case reflect.Slice, reflect.Array:
		if n.Kind != yaml.SequenceNode {
			return nil
		}
		for i, item := range n.Content {
			if err := normalise(item, t.Elem()); err != nil {
				return fmt.Errorf("entry %d: %w", i+1, err)
			}
		}
	}
	return nil
}

// fieldByYAMLName finds the field yaml.v3 decodes name into.
func fieldByYAMLName(t reflect.Type, name string) (reflect.StructField, bool) {
	for f := range t.Fields() {
		if tag, ok := f.Tag.Lookup("yaml"); ok {
			if n, _, _ := strings.Cut(tag, ","); n == name {
				return f, true
			}
		}
		if strings.ToLower(f.Name) == name {
			return f, true
		}
	}
	return reflect.StructField{}, false
}

// yamlFields maps each top-level key of raw to a pointer to its field.
func yamlFields(raw *rawCase) map[string]any {
	v := reflect.ValueOf(raw).Elem()
	out := map[string]any{}
	for i := range v.NumField() {
		f := v.Type().Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		out[name] = v.Field(i).Addr().Interface()
	}
	return out
}
