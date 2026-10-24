package detector

import (
	"bytes"
	"regexp"
	"strconv"

	"github.com/SteerMesh/axon/internal/domain"
	"github.com/SteerMesh/axon/internal/target"
)

type OSC133 struct{}

var exitPattern = regexp.MustCompile(`\x1b\]133;D;([0-9]+)(?:\x07|\x1b\\)`)

func (OSC133) Detect(recent []byte) (target.StateObservation, bool) {
	if bytes.Contains(recent, []byte("\x1b]133;C")) {
		return target.StateObservation{State: domain.StateRunning, Confidence: 1, Source: "osc133.command-start"}, true
	}
	if match := exitPattern.FindSubmatch(recent); match != nil {
		exit, _ := strconv.Atoi(string(match[1]))
		state := domain.StateIdle
		if exit != 0 {
			state = domain.StateError
		}
		return target.StateObservation{State: state, Confidence: 1, Source: "osc133.command-finished"}, true
	}
	if bytes.Contains(recent, []byte("\x1b]133;A")) {
		return target.StateObservation{State: domain.StateIdle, Confidence: 1, Source: "osc133.prompt"}, true
	}
	return target.StateObservation{}, false
}

type PromptHeuristic struct {
	source   string
	patterns []*regexp.Regexp
}

type Multi []target.StateDetector

func (m Multi) Detect(recent []byte) (target.StateObservation, bool) {
	var best target.StateObservation
	found := false
	for _, candidate := range m {
		if observation, ok := candidate.Detect(recent); ok && (!found || observation.Confidence > best.Confidence) {
			best, found = observation, true
		}
	}
	return best, found
}

func NewPromptHeuristic(source string, patterns ...string) *PromptHeuristic {
	detector := &PromptHeuristic{source: source}
	for _, pattern := range patterns {
		detector.patterns = append(detector.patterns, regexp.MustCompile(`(?i)`+pattern))
	}
	return detector
}

func (d *PromptHeuristic) Detect(recent []byte) (target.StateObservation, bool) {
	for _, pattern := range d.patterns {
		if pattern.Match(recent) {
			return target.StateObservation{State: domain.StateWaitingForInput, Confidence: 0.7, Source: d.source}, true
		}
	}
	return target.StateObservation{}, false
}
