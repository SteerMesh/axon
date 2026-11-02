package session

import "sync"

type Chunk struct {
	Sequence uint64 `json:"seq"`
	Data     []byte `json:"data"`
}

type Replay struct {
	Chunks []Chunk `json:"chunks"`
	MinSeq uint64  `json:"min_seq"`
	MaxSeq uint64  `json:"max_seq"`
	Gap    bool    `json:"gap"`
}

// MaxReplayBytes bounds how much raw output a single ReplayFrom call
// returns. A reply must fit in one relay frame (internal/relay.MaxFrameBytes,
// 128KiB) — the relay enforces that as a hard per-connection read limit and
// simply drops the connection on anything larger, there is no graceful
// partial-frame fallback. Scrollback retention (NewRing's maxBytes) can be
// far larger than that, so a subscribe from sequence 0 on a session with
// real history must not try to return the whole thing in one response.
const MaxReplayBytes = 32 << 10

type Ring struct {
	mu       sync.RWMutex
	maxBytes int
	bytes    int
	next     uint64
	chunks   []Chunk
}

func NewRing(maxBytes int) *Ring {
	if maxBytes < 1 {
		maxBytes = 1
	}
	return &Ring{maxBytes: maxBytes, next: 1}
}

func (r *Ring) Add(data []byte) Chunk {
	r.mu.Lock()
	defer r.mu.Unlock()

	copyData := append([]byte(nil), data...)
	chunk := Chunk{Sequence: r.next, Data: copyData}
	r.next++
	r.chunks = append(r.chunks, chunk)
	r.bytes += len(copyData)

	for len(r.chunks) > 1 && r.bytes > r.maxBytes {
		r.bytes -= len(r.chunks[0].Data)
		r.chunks = r.chunks[1:]
	}
	return chunk
}

func (r *Ring) ReplayFrom(from uint64) Replay {
	r.mu.RLock()
	defer r.mu.RUnlock()

	result := Replay{}
	if len(r.chunks) == 0 {
		return result
	}
	result.MinSeq = r.chunks[0].Sequence
	result.MaxSeq = r.chunks[len(r.chunks)-1].Sequence
	if from != 0 && from < result.MinSeq {
		result.Gap = true
		return result
	}

	var matched []Chunk
	for _, chunk := range r.chunks {
		if from == 0 || chunk.Sequence >= from {
			matched = append(matched, chunk)
		}
	}
	if len(matched) == 0 {
		return result
	}

	// Keep only the most recent chunks that fit under MaxReplayBytes. A
	// fresh attach should show "what's happening now" rather than force
	// the entire retained scrollback through a single frame the relay
	// will just reject.
	total, keepFrom := 0, 0
	for i := len(matched) - 1; i >= 0; i-- {
		total += len(matched[i].Data)
		if total > MaxReplayBytes {
			keepFrom = i + 1
			break
		}
	}
	matched = matched[keepFrom:]
	result.MinSeq = matched[0].Sequence
	for _, chunk := range matched {
		result.Chunks = append(result.Chunks, Chunk{
			Sequence: chunk.Sequence,
			Data:     append([]byte(nil), chunk.Data...),
		})
	}
	return result
}
