// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package detect

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/RhythmShahriar/sightread/core"
)

// The explain text of every signal, one YAML file per catalogue ID.
//
//go:embed explain/*.yaml
var explainFS embed.FS

// Incident is a named real-world case a signal would have caught.
type Incident struct {
	Name string `yaml:"name"`
	Line string `yaml:"line"`
}

// Text is one signal's explain text as written in explain/<id>.yaml.
// core.Explain carries it flattened; signalsdoc and tests read it here.
type Text struct {
	ID          string     `yaml:"-"`
	Why         string     `yaml:"why"`
	HowToReview []string   `yaml:"how_to_review"`
	FalseAlarms string     `yaml:"false_alarms"`
	Incidents   []Incident `yaml:"incidents"`
	Advice      string     `yaml:"advice"`
	More        string     `yaml:"more"`
}

// WikiBase is where the signal reference lives; More is WikiBase#<id>.
const WikiBase = "https://github.com/RhythmShahriar/rhythm/wiki/Sightread-Signal-Reference"

// Explain flattens t for core: review steps numbered one per line,
// incidents as "<name>: <line>" one per line.
func (t Text) Explain() core.Explain {
	var steps, incidents []string
	for i, s := range t.HowToReview {
		steps = append(steps, strconv.Itoa(i+1)+". "+s)
	}
	for _, in := range t.Incidents {
		incidents = append(incidents, in.Name+": "+in.Line)
	}
	return core.Explain{
		Why:         t.Why,
		HowToReview: strings.Join(steps, "\n"),
		FalseAlarms: t.FalseAlarms,
		Incidents:   strings.Join(incidents, "\n"),
		Advice:      t.Advice,
		More:        t.More,
	}
}

// LoadTexts reads every <id>.yaml at the top of fsys strictly: unknown
// keys, missing fields, an ID outside the catalogue and a catalogue ID
// without a file are all errors.
func LoadTexts(fsys fs.FS) (map[string]Text, error) {
	names, err := fs.Glob(fsys, "*.yaml")
	if err != nil {
		return nil, err
	}
	out := map[string]Text{}
	var errs []error
	for _, name := range names {
		id := strings.TrimSuffix(path.Base(name), ".yaml")
		t, err := loadText(fsys, name, id)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", name, err))
			continue
		}
		out[id] = t
	}
	for _, id := range core.SignalIDs() {
		if _, ok := out[id]; !ok && !hasErr(errs, id+".yaml") {
			errs = append(errs, fmt.Errorf("%s.yaml: missing: every catalogue signal needs explain text", id))
		}
	}
	return out, errors.Join(errs...)
}

func hasErr(errs []error, prefix string) bool {
	for _, e := range errs {
		if strings.HasPrefix(e.Error(), prefix+":") {
			return true
		}
	}
	return false
}

func loadText(fsys fs.FS, name, id string) (Text, error) {
	if _, ok := core.Signal(id); !ok {
		return Text{}, fmt.Errorf("%q is not a signal ID of the catalogue", id)
	}
	b, err := fs.ReadFile(fsys, name)
	if err != nil {
		return Text{}, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	var t Text
	if err := dec.Decode(&t); err != nil {
		return Text{}, err
	}
	t.ID = id
	switch {
	case strings.TrimSpace(t.Why) == "":
		return Text{}, errors.New("why: missing")
	case len(t.HowToReview) == 0:
		return Text{}, errors.New("how_to_review: missing")
	case strings.TrimSpace(t.FalseAlarms) == "":
		return Text{}, errors.New("false_alarms: missing (write None. when there are none)")
	case strings.TrimSpace(t.Advice) == "" || strings.Contains(t.Advice, "\n"):
		return Text{}, errors.New("advice: want one line")
	case t.More != WikiBase+"#"+id:
		return Text{}, fmt.Errorf("more: want %s#%s", WikiBase, id)
	}
	for i, in := range t.Incidents {
		if in.Name == "" || in.Line == "" {
			return Text{}, fmt.Errorf("incidents: entry %d: needs name and line", i+1)
		}
	}
	return t, nil
}

// texts is the embedded explain text, loaded once at init.
var texts map[string]Text

// Texts returns the explain text of every signal by ID.
func Texts() map[string]Text { return texts }

func init() {
	sub, err := fs.Sub(explainFS, "explain")
	if err != nil {
		panic("detect: " + err.Error())
	}
	// A bad embedded file is a build mistake the tests catch; failing at
	// start beats a signal that prints no advice.
	if texts, err = LoadTexts(sub); err != nil {
		panic("detect: explain text: " + err.Error())
	}
	for id, t := range texts {
		core.RegisterExplain(id, t.Explain())
	}
}
