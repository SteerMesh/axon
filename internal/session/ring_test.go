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

// TestRingCapsReplaySizeRegardlessOfRetention covers the case that killed
// the relay connection in production: a session.subscribe from sequence 0
// on a session with real scrollback tried to return the entire retained
// history (up to NewRing's maxBytes, far larger than one relay frame can
// carry) in a single Replay. ReplayFrom must cap what it returns to
// MaxReplayBytes independently of how much the ring is allowed to retain.
func TestRingCapsReplaySizeRegardlessOfRetention(t *testing.T) {
	ring := NewRing(4 * MaxReplayBytes) // retention is generous; one reply must not be
	chunkSize := 1024
	chunk := make([]byte, chunkSize)
	for i := range chunk {
		chunk[i] = 'x'
	}
	count := (3 * MaxReplayBytes) / chunkSize // well over the per-reply cap
	for i := 0; i < count; i++ {
		ring.Add(chunk)
	}

	replay := ring.ReplayFrom(0)
	if replay.Gap {
		t.Fatal("a capped reply must not be reported as a retention gap")
	}
	total := 0
	for _, c := range replay.Chunks {
		total += len(c.Data)
	}
	if total > MaxReplayBytes {
		t.Fatalf("replay exceeded MaxReplayBytes: %d bytes in %d chunks", total, len(replay.Chunks))
	}
	if total == 0 {
		t.Fatal("replay was empty")
	}
	// It must keep the most recent chunks, not the oldest.
	if replay.Chunks[len(replay.Chunks)-1].Sequence != replay.MaxSeq {
		t.Fatalf("replay dropped the newest chunks: last=%+v maxSeq=%d", replay.Chunks[len(replay.Chunks)-1], replay.MaxSeq)
	}
	if replay.MinSeq != replay.Chunks[0].Sequence {
		t.Fatalf("MinSeq %d does not match the first returned chunk %+v", replay.MinSeq, replay.Chunks[0])
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
