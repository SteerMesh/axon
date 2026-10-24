package session

import "testing"

func TestRingReportsReplayGap(t *testing.T) {
	ring := NewRing(5)
	ring.Add([]byte("abc"))
	ring.Add([]byte("def"))

	replay := ring.ReplayFrom(1)
	if !replay.Gap || replay.MinSeq != 2 || replay.MaxSeq != 2 {
		t.Fatalf("unexpected replay: %+v", replay)
	}
}

func TestRingCopiesInputAndOutput(t *testing.T) {
	ring := NewRing(100)
	input := []byte("hello")
	ring.Add(input)
	input[0] = 'x'

	replay := ring.ReplayFrom(0)
	if got := string(replay.Chunks[0].Data); got != "hello" {
		t.Fatalf("stored data mutated: %q", got)
	}
	replay.Chunks[0].Data[0] = 'y'
	if got := string(ring.ReplayFrom(0).Chunks[0].Data); got != "hello" {
		t.Fatalf("replay exposed internal data: %q", got)
	}
}

func TestRingNormalizesNonPositiveCapacity(t *testing.T) {
	ring := NewRing(0)
	ring.Add([]byte("a"))
	ring.Add([]byte("b"))
	replay := ring.ReplayFrom(0)
	if len(replay.Chunks) != 1 || string(replay.Chunks[0].Data) != "b" {
		t.Fatalf("replay=%+v", replay)
	}
}
