package ipc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/SteerMesh/axon/internal/security"
	"github.com/SteerMesh/axon/internal/session"
	"github.com/SteerMesh/axon/internal/store"
	"github.com/SteerMesh/axon/internal/target"
)

type Server struct {
	manager  *session.Manager
	listener net.Listener
	path     string
	closed   chan struct{}
	once     sync.Once
	wg       sync.WaitGroup
	connMu   sync.Mutex
	conns    map[net.Conn]struct{}
	pairing  *security.PairingManager
	store    *store.Store
}

type Options struct {
	Pairing *security.PairingManager
	Store   *store.Store
}

func DefaultSocketPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".mesh", "axon", "agent.sock"), nil
}

func Listen(manager *session.Manager, socketPath string) (*Server, error) {
	return ListenWithOptions(manager, socketPath, Options{})
}

func ListenWithOptions(manager *session.Manager, socketPath string, options Options) (*Server, error) {
	if err := prepareSocket(socketPath); err != nil {
		return nil, err
	}
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", socketPath, err)
	}
	if err := os.Chmod(socketPath, 0o600); err != nil {
		listener.Close()
		return nil, fmt.Errorf("secure socket permissions: %w", err)
	}
	server := &Server{
		manager:  manager,
		listener: listener,
		path:     socketPath,
		closed:   make(chan struct{}),
		conns:    make(map[net.Conn]struct{}),
		pairing:  options.Pairing,
		store:    options.Store,
	}
	server.wg.Add(1)
	go server.accept()
	return server, nil
}

func prepareSocket(socketPath string) error {
	dir := filepath.Dir(socketPath)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create socket directory: %w", err)
	}
	dirInfo, err := os.Stat(dir)
	if err != nil {
		return fmt.Errorf("inspect socket directory: %w", err)
	}
	if dirInfo.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("socket directory %s must not be accessible by group or others", dir)
	}
	info, err := os.Lstat(socketPath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("refusing to replace non-socket path %s", socketPath)
	}
	return os.Remove(socketPath)
}

func (s *Server) accept() {
	defer s.wg.Done()
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
				continue
			}
		}
		s.connMu.Lock()
		s.conns[conn] = struct{}{}
		s.connMu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(conn)
		}()
	}
}

func (s *Server) handle(conn net.Conn) {
	defer func() {
		s.connMu.Lock()
		delete(s.conns, conn)
		s.connMu.Unlock()
		_ = conn.Close()
	}()
	reader := bufio.NewReader(conn)
	encoder := json.NewEncoder(conn)
	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			return
		}
		var request Request
		if err := json.Unmarshal(line, &request); err != nil {
			_ = encoder.Encode(errorResponse("", "invalid_message", err.Error()))
			continue
		}
		if request.Method == "session.attach" {
			s.handleAttach(conn, encoder, request)
			return
		}
		_ = encoder.Encode(s.dispatch(request))
	}
}

func (s *Server) dispatch(request Request) Response {
	switch request.Method {
	case "health":
		return resultResponse(request.ID, map[string]string{"status": "ok"})
	case "sessions.list":
		return resultResponse(request.ID, s.manager.List())
	case "session.create":
		var params CreateParams
		if err := decodeParams(request, &params); err != nil {
			return errorResponse(request.ID, "invalid_message", err.Error())
		}
		created, err := s.manager.Create(context.Background(), params.Name, params.Target, params.Permission)
		if err != nil {
			return mapError(request.ID, err)
		}
		return resultResponse(request.ID, created)
	case "session.input":
		var params InputParams
		if err := decodeParams(request, &params); err != nil {
			return errorResponse(request.ID, "invalid_message", err.Error())
		}
		if err := s.manager.Input(params.SessionID, params.DeviceID, params.IdempotencyKey, params.Data); err != nil {
			return mapError(request.ID, err)
		}
		return resultResponse(request.ID, map[string]bool{"accepted": true})
	case "session.resize":
		var params ResizeParams
		if err := decodeParams(request, &params); err != nil {
			return errorResponse(request.ID, "invalid_message", err.Error())
		}
		if err := s.manager.Resize(params.SessionID, params.Cols, params.Rows); err != nil {
			return mapError(request.ID, err)
		}
		return resultResponse(request.ID, map[string]bool{"resized": true})
	case "session.signal":
		var params SignalParams
		if err := decodeParams(request, &params); err != nil {
			return errorResponse(request.ID, "invalid_message", err.Error())
		}
		if err := s.manager.Signal(params.SessionID, target.Signal(params.Signal)); err != nil {
			return mapError(request.ID, err)
		}
		return resultResponse(request.ID, map[string]bool{"signaled": true})
	case "pairing.issue":
		if s.pairing == nil {
			return errorResponse(request.ID, "not_configured", "pairing is not configured")
		}
		var params PairingIssueParams
		if err := decodeParams(request, &params); err != nil || params.TTLSeconds < 1 || params.TTLSeconds > 3600 {
			return errorResponse(request.ID, "invalid_message", "ttl_seconds must be between 1 and 3600")
		}
		bundle, err := s.pairing.Issue(time.Duration(params.TTLSeconds) * time.Second)
		if err != nil {
			return mapError(request.ID, err)
		}
		return resultResponse(request.ID, bundle)
	case "devices.list":
		if s.store == nil {
			return errorResponse(request.ID, "not_configured", "device storage is not configured")
		}
		devices, err := s.store.Devices(context.Background())
		if err != nil {
			return mapError(request.ID, err)
		}
		return resultResponse(request.ID, DeviceListResult{Devices: devices})
	case "devices.revoke":
		if s.store == nil {
			return errorResponse(request.ID, "not_configured", "device storage is not configured")
		}
		var params DeviceRevokeParams
		if err := decodeParams(request, &params); err != nil || params.DeviceID == "" {
			return errorResponse(request.ID, "invalid_message", "device_id is required")
		}
		if err := s.store.RevokeDevice(context.Background(), params.DeviceID, time.Now()); err != nil {
			return mapError(request.ID, err)
		}
		return resultResponse(request.ID, map[string]bool{"revoked": true})
	default:
		return errorResponse(request.ID, "not_found", "unknown method "+request.Method)
	}
}

func (s *Server) handleAttach(conn net.Conn, encoder *json.Encoder, request Request) {
	var params AttachParams
	if err := decodeParams(request, &params); err != nil {
		_ = encoder.Encode(errorResponse(request.ID, "invalid_message", err.Error()))
		return
	}
	replay, stream, cancel, err := s.manager.Subscribe(params.SessionID, params.FromSeq)
	if err != nil {
		_ = encoder.Encode(mapError(request.ID, err))
		return
	}
	if replay.Gap {
		_ = encoder.Encode(errorResponseDetails(request.ID, "replay_gap", "requested output is no longer retained", replay))
		return
	}
	defer cancel()
	if err := encoder.Encode(resultResponse(request.ID, AttachResult{Replay: replay})); err != nil {
		return
	}
	for {
		select {
		case <-s.closed:
			return
		case chunk, ok := <-stream:
			if !ok {
				return
			}
			if err := encoder.Encode(Event{Type: "session.output", Chunk: chunk}); err != nil {
				return
			}
		}
	}
}

func decodeParams(request Request, dst any) error {
	if len(request.Params) == 0 {
		return errors.New("params are required")
	}
	return json.Unmarshal(request.Params, dst)
}

func resultResponse(id string, value any) Response {
	data, err := json.Marshal(value)
	if err != nil {
		return errorResponse(id, "internal", err.Error())
	}
	return Response{ID: id, OK: true, Result: data}
}

func errorResponse(id, code, message string) Response {
	return Response{ID: id, OK: false, Error: &RPCError{Code: code, Message: message}}
}

func errorResponseDetails(id, code, message string, details any) Response {
	data, _ := json.Marshal(details)
	return Response{ID: id, OK: false, Result: data, Error: &RPCError{Code: code, Message: message}}
}

func mapError(id string, err error) Response {
	switch {
	case errors.Is(err, session.ErrNotFound):
		return errorResponse(id, "not_found", err.Error())
	case errors.Is(err, session.ErrReadOnly):
		return errorResponse(id, "read_only", err.Error())
	case errors.Is(err, session.ErrDuplicate):
		return errorResponse(id, "conflict", err.Error())
	default:
		return errorResponse(id, "internal", err.Error())
	}
}

func (s *Server) Close() error {
	var closeErr error
	s.once.Do(func() {
		close(s.closed)
		closeErr = s.listener.Close()
		s.connMu.Lock()
		for conn := range s.conns {
			_ = conn.Close()
		}
		s.connMu.Unlock()
		s.wg.Wait()
		_ = os.Remove(s.path)
	})
	return closeErr
}
