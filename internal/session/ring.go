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
	for _, chunk := range r.chunks {
		if from == 0 || chunk.Sequence >= from {
			result.Chunks = append(result.Chunks, Chunk{
				Sequence: chunk.Sequence,
				Data:     append([]byte(nil), chunk.Data...),
			})
		}
	}
	return result
}
