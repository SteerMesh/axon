package detector

import (
	"testing"

	"github.com/SteerMesh/axon/internal/domain"
	"github.com/SteerMesh/axon/internal/target"
)

func TestOSC133AndPromptDetection(t *testing.T) {
	observation, ok := (OSC133{}).Detect([]byte("\x1b]133;D;1\x07"))
	if !ok || observation.State != domain.StateError || observation.Confidence != 1 {
		t.Fatalf("unexpected OSC observation: %+v", observation)
	}
	prompt := NewPromptHeuristic("claude.permission", `allow this action`, `proceed\?`)
	observation, ok = prompt.Detect([]byte("Allow this action?"))
	if !ok || observation.State != domain.StateWaitingForInput || observation.Confidence >= 1 {
		t.Fatalf("unexpected prompt observation: %+v", observation)
	}
}

func TestDetectorVariantsAndMultiSelection(t *testing.T) {
	for _, test := range []struct {
		input string
		state domain.SessionState
		found bool
	}{
		{"\x1b]133;C", domain.StateRunning, true},
		{"\x1b]133;D;0\x1b\\", domain.StateIdle, true},
		{"\x1b]133;A", domain.StateIdle, true},
		{"plain output", "", false},
	} {
		observation, found := (OSC133{}).Detect([]byte(test.input))
		if found != test.found || observation.State != test.state {
			t.Fatalf("input=%q observation=%+v found=%v", test.input, observation, found)
		}
	}
	low := NewPromptHeuristic("low", "continue")
	high := fixedDetector{target.StateObservation{State: domain.StateError, Confidence: 0.95, Source: "high"}, true}
	observation, found := (Multi{low, high}).Detect([]byte("continue"))
	if !found || observation.Source != "high" {
		t.Fatalf("multi selected %+v", observation)
	}
	if _, found := (Multi{NewPromptHeuristic("none", "never")}).Detect([]byte("continue")); found {
		t.Fatal("multi reported a false match")
	}
}

type fixedDetector struct {
	observation target.StateObservation
	found       bool
}

func (d fixedDetector) Detect([]byte) (target.StateObservation, bool) {
	return d.observation, d.found
}
