package session

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/SteerMesh/axon/internal/domain"
	"github.com/SteerMesh/axon/internal/target"
	"github.com/oklog/ulid/v2"
)

const (
	DefaultScrollbackBytes = 2 << 20
	DefaultSubscriberQueue = 128
	MaxInputBytes          = 64 << 10
)

var (
	ErrNotFound  = errors.New("session not found")
	ErrReadOnly  = errors.New("session is read-only")
	ErrDuplicate = errors.New("session name already exists")
)

type Manager struct {
	mu         sync.RWMutex
	adapters   map[string]target.Adapter
	detectors  map[string]target.StateDetector
	sessions   map[string]*runtimeSession
	names      map[string]string
	scrollback int
}

type runtimeSession struct {
	mu          sync.Mutex
	meta        domain.Session
	process     target.Process
	ring        *Ring
	subscribers map[uint64]chan Chunk
	nextSubID   uint64
	dedupe      map[string]struct{}
	dedupeOrder []string
	inputMu     sync.Mutex
	detector    target.StateDetector
	recent      []byte
}

func NewManager(scrollbackBytes int, adapters ...target.Adapter) *Manager {
	if scrollbackBytes <= 0 {
		scrollbackBytes = DefaultScrollbackBytes
	}
	m := &Manager{
		adapters:   make(map[string]target.Adapter),
		detectors:  make(map[string]target.StateDetector),
		sessions:   make(map[string]*runtimeSession),
		names:      make(map[string]string),
		scrollback: scrollbackBytes,
	}
	for _, adapter := range adapters {
		m.adapters[adapter.Kind()] = adapter
	}
	return m
}

func (m *Manager) RegisterDetector(kind string, detector target.StateDetector) {
	m.mu.Lock()
	m.detectors[kind] = detector
	m.mu.Unlock()
}

func (m *Manager) Create(ctx context.Context, name string, spec domain.TargetSpec, permission domain.Permission) (domain.Session, error) {
	m.mu.Lock()
	if name == "" {
		name = spec.Kind + "-" + ulid.Make().String()[20:]
	}
	if _, exists := m.names[name]; exists {
		m.mu.Unlock()
		return domain.Session{}, ErrDuplicate
	}
	adapter, ok := m.adapters[spec.Kind]
	detector := m.detectors[spec.Kind]
	if !ok {
		m.mu.Unlock()
		return domain.Session{}, fmt.Errorf("unknown target kind %q", spec.Kind)
	}
	// Reserve the name while process creation is in progress.
	m.names[name] = ""
	m.mu.Unlock()

	process, err := adapter.Spawn(ctx, spec)
	if err != nil {
		m.mu.Lock()
		delete(m.names, name)
		m.mu.Unlock()
		return domain.Session{}, err
	}

	now := time.Now().UTC()
	meta := domain.Session{
		ID:             ulid.Make().String(),
		Name:           name,
		Target:         spec,
		State:          domain.StateRunning,
		DefaultPerm:    permission,
		DevicePerms:    make(map[string]domain.Permission),
		StreamEpoch:    ulid.Make().String(),
		CreatedAt:      now,
		LastActivityAt: now,
	}
	rs := &runtimeSession{
		meta:        meta,
		process:     process,
		ring:        NewRing(m.scrollback),
		subscribers: make(map[uint64]chan Chunk),
		dedupe:      make(map[string]struct{}),
		detector:    detector,
	}
	m.mu.Lock()
	m.sessions[meta.ID] = rs
	m.names[name] = meta.ID
	m.mu.Unlock()

	go m.readOutput(rs)
	go m.wait(rs)
	return cloneSession(meta), nil
}

func (m *Manager) readOutput(rs *runtimeSession) {
	buffer := make([]byte, 32<<10)
	for {
		n, err := rs.process.Output().Read(buffer)
		if n > 0 {
			rs.mu.Lock()
			// Ring insertion and subscriber publication share the session lock so
			// Subscribe cannot miss output between its replay snapshot and live
			// registration.
			chunk := rs.ring.Add(buffer[:n])
			if rs.detector != nil {
				rs.recent = append(rs.recent, buffer[:n]...)
				if len(rs.recent) > 8<<10 {
					rs.recent = append([]byte(nil), rs.recent[len(rs.recent)-(8<<10):]...)
				}
				if observation, detected := rs.detector.Detect(rs.recent); detected && observation.Confidence >= 0.7 {
					rs.meta.State = observation.State
				}
			}
			rs.meta.LastActivityAt = time.Now().UTC()
			for id, subscriber := range rs.subscribers {
				select {
				case subscriber <- chunk:
				default:
					close(subscriber)
					delete(rs.subscribers, id)
				}
			}
			rs.mu.Unlock()
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				rs.mu.Lock()
				rs.meta.State = domain.StateError
				rs.mu.Unlock()
			}
			return
		}
	}
}

func (m *Manager) wait(rs *runtimeSession) {
	exitCode, err := rs.process.Wait()
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.meta.ExitCode = &exitCode
	if err != nil && exitCode < 0 {
		rs.meta.State = domain.StateError
	} else {
		rs.meta.State = domain.StateFinished
	}
	rs.meta.LastActivityAt = time.Now().UTC()
	for id, subscriber := range rs.subscribers {
		close(subscriber)
		delete(rs.subscribers, id)
	}
}

func (m *Manager) List() []domain.Session {
	m.mu.RLock()
	runtimes := make([]*runtimeSession, 0, len(m.sessions))
	for _, rs := range m.sessions {
		runtimes = append(runtimes, rs)
	}
	m.mu.RUnlock()

	result := make([]domain.Session, 0, len(runtimes))
	for _, rs := range runtimes {
		rs.mu.Lock()
		result = append(result, cloneSession(rs.meta))
		rs.mu.Unlock()
	}
	return result
}

func (m *Manager) Resolve(idOrName string) (*runtimeSession, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if rs, ok := m.sessions[idOrName]; ok {
		return rs, nil
	}
	if id, ok := m.names[idOrName]; ok {
		if rs := m.sessions[id]; rs != nil {
			return rs, nil
		}
	}
	return nil, ErrNotFound
}

func (m *Manager) Get(idOrName string) (domain.Session, error) {
	rs, err := m.Resolve(idOrName)
	if err != nil {
		return domain.Session{}, err
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return cloneSession(rs.meta), nil
}

func (m *Manager) Input(idOrName, deviceID, idempotencyKey string, data []byte) error {
	if idempotencyKey == "" {
		return fmt.Errorf("idempotency key is required")
	}
	if len(data) == 0 || len(data) > MaxInputBytes {
		return fmt.Errorf("input must contain 1 to %d bytes", MaxInputBytes)
	}
	rs, err := m.Resolve(idOrName)
	if err != nil {
		return err
	}
	rs.inputMu.Lock()
	defer rs.inputMu.Unlock()

	rs.mu.Lock()
	if rs.meta.PermissionFor(deviceID) == domain.PermissionReadOnly {
		rs.mu.Unlock()
		return ErrReadOnly
	}
	dedupeKey := deviceID + ":" + idempotencyKey
	if _, exists := rs.dedupe[dedupeKey]; exists {
		rs.mu.Unlock()
		return nil
	}
	rs.mu.Unlock()

	for written := 0; written < len(data); {
		n, writeErr := rs.process.Write(data[written:])
		written += n
		if writeErr != nil {
			return writeErr
		}
		if n == 0 {
			return io.ErrShortWrite
		}
	}
	rs.mu.Lock()
	rs.dedupe[dedupeKey] = struct{}{}
	rs.dedupeOrder = append(rs.dedupeOrder, dedupeKey)
	if len(rs.dedupeOrder) > 1024 {
		delete(rs.dedupe, rs.dedupeOrder[0])
		rs.dedupeOrder = rs.dedupeOrder[1:]
	}
	rs.meta.LastActivityAt = time.Now().UTC()
	rs.mu.Unlock()
	return nil
}

func (m *Manager) Resize(idOrName string, cols, rows uint16) error {
	rs, err := m.Resolve(idOrName)
	if err != nil {
		return err
	}
	return rs.process.Resize(cols, rows)
}

func (m *Manager) Signal(idOrName string, signal target.Signal) error {
	rs, err := m.Resolve(idOrName)
	if err != nil {
		return err
	}
	return rs.process.Signal(signal)
}

func (m *Manager) Replay(idOrName string, from uint64) (Replay, error) {
	rs, err := m.Resolve(idOrName)
	if err != nil {
		return Replay{}, err
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	return rs.ring.ReplayFrom(from), nil
}

func (m *Manager) Subscribe(idOrName string, from uint64) (Replay, <-chan Chunk, func(), error) {
	rs, err := m.Resolve(idOrName)
	if err != nil {
		return Replay{}, nil, nil, err
	}
	rs.mu.Lock()
	replay := rs.ring.ReplayFrom(from)
	if replay.Gap {
		rs.mu.Unlock()
		return replay, nil, nil, nil
	}
	id := rs.nextSubID
	rs.nextSubID++
	ch := make(chan Chunk, DefaultSubscriberQueue)
	rs.subscribers[id] = ch
	rs.mu.Unlock()
	cancel := func() {
		rs.mu.Lock()
		if existing, ok := rs.subscribers[id]; ok {
			close(existing)
			delete(rs.subscribers, id)
		}
		rs.mu.Unlock()
	}
	return replay, ch, cancel, nil
}

func cloneSession(session domain.Session) domain.Session {
	copySession := session
	copySession.Target.Args = append([]string(nil), session.Target.Args...)
	copySession.Target.Env = nil
	copySession.DevicePerms = make(map[string]domain.Permission, len(session.DevicePerms))
	for id, permission := range session.DevicePerms {
		copySession.DevicePerms[id] = permission
	}
	return copySession
}
