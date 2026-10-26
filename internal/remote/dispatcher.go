package remote

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/SteerMesh/axon/internal/authz"
	"github.com/SteerMesh/axon/internal/domain"
	"github.com/SteerMesh/axon/internal/meshcli"
	"github.com/SteerMesh/axon/internal/session"
	"github.com/SteerMesh/axon/internal/store"
	"github.com/SteerMesh/axon/internal/target"
	"github.com/SteerMesh/axon/internal/templates"
	"github.com/SteerMesh/axon/pkg/protocol"
	"github.com/oklog/ulid/v2"
)

type DeviceContext struct {
	ID   string
	Role authz.Role
}

type Dispatcher struct {
	manager   *session.Manager
	store     *store.Store
	templates *templates.Catalog
	mesh      meshcli.Options
}

type Subscription struct {
	SessionID string
	Epoch     string
	Replay    session.Replay
	Chunks    <-chan session.Chunk
	State     func() domain.SessionState
	Cancel    func()
}

func (d *Dispatcher) WithMeshOptions(options meshcli.Options) *Dispatcher {
	d.mesh = options
	return d
}

func (d *Dispatcher) WithTemplates(catalog templates.Catalog) *Dispatcher {
	d.templates = &catalog
	return d
}

func NewDispatcher(manager *session.Manager, persistent *store.Store) *Dispatcher {
	return &Dispatcher{manager: manager, store: persistent}
}

// Subscribe atomically captures retained output and registers for future
// chunks. It is separate from Handle because its live channel is an in-process
// capability and must never be serialized into the wire response.
func (d *Dispatcher) Subscribe(ctx context.Context, device DeviceContext, request protocol.Envelope) (protocol.Envelope, *Subscription) {
	response := protocol.Envelope{
		Version: protocol.Version, ID: ulid.Make().String(), ReplyTo: request.ID,
		Type: request.Type + ".response", SessionID: request.SessionID, Timestamp: time.Now().UTC(),
	}
	var operationErr error
	var params struct {
		FromSeq uint64 `json:"from_seq"`
	}
	if operationErr = request.Validate(); operationErr == nil {
		operationErr = json.Unmarshal(request.Data, &params)
	}
	if operationErr == nil {
		operationErr = d.authorizeSession(device, request.SessionID, authz.OperationAttach, false)
	}
	var subscription *Subscription
	if operationErr == nil {
		managed, err := d.manager.Get(request.SessionID)
		if err != nil {
			operationErr = err
		} else {
			replay, chunks, cancel, err := d.manager.Subscribe(request.SessionID, params.FromSeq)
			operationErr = err
			if err == nil {
				sessionID := managed.ID
				subscription = &Subscription{
					SessionID: managed.ID, Epoch: managed.StreamEpoch,
					Replay: replay, Chunks: chunks, Cancel: cancel,
					State: func() domain.SessionState {
						current, getErr := d.manager.Get(sessionID)
						if getErr != nil {
							return domain.StateError
						}
						return current.State
					},
				}
			}
		}
	}
	outcome := "accepted"
	if operationErr != nil {
		outcome = errorCode(operationErr)
	}
	if d.store != nil {
		_ = d.store.Audit(ctx, store.AuditEntry{
			OccurredAt: time.Now(), DeviceID: device.ID, SessionID: request.SessionID,
			Action: request.Type, Outcome: outcome,
		}, nil)
	}
	if operationErr != nil {
		return withError(response, outcome, operationErr.Error()), nil
	}
	data, err := json.Marshal(subscription.Replay)
	if err != nil {
		if subscription.Cancel != nil {
			subscription.Cancel()
		}
		return withError(response, "internal", err.Error()), nil
	}
	response.Epoch = subscription.Epoch
	response.Data = data
	return response, subscription
}

func (d *Dispatcher) Handle(ctx context.Context, device DeviceContext, request protocol.Envelope) protocol.Envelope {
	response := protocol.Envelope{
		Version: protocol.Version, ID: ulid.Make().String(), ReplyTo: request.ID,
		Type: request.Type + ".response", SessionID: request.SessionID, Timestamp: time.Now().UTC(),
	}
	if err := request.Validate(); err != nil {
		return withError(response, "invalid_message", err.Error())
	}

	var result any
	var input []byte
	var operationErr error
	switch request.Type {
	case string(authz.OperationList):
		operationErr = authz.Authorize(device.Role, "", authz.OperationList, false)
		result = d.manager.List()
	case "mesh.options":
		operationErr = authz.Authorize(device.Role, "", authz.OperationList, false)
		result = d.mesh
	case string(authz.OperationInput):
		var params struct {
			Bytes     []byte `json:"bytes"`
			Confirmed bool   `json:"confirmed"`
		}
		operationErr = json.Unmarshal(request.Data, &params)
		input = params.Bytes
		if operationErr == nil {
			operationErr = d.authorizeSession(device, request.SessionID, authz.OperationInput, params.Confirmed)
		}
		if operationErr == nil {
			operationErr = d.manager.Input(request.SessionID, device.ID, request.IdempotencyKey, params.Bytes)
		}
		result = map[string]bool{"accepted": operationErr == nil}
	case string(authz.OperationResize):
		var params struct {
			Cols uint16 `json:"cols"`
			Rows uint16 `json:"rows"`
		}
		operationErr = json.Unmarshal(request.Data, &params)
		if operationErr == nil {
			operationErr = d.authorizeSession(device, request.SessionID, authz.OperationResize, false)
		}
		if operationErr == nil {
			operationErr = d.manager.Resize(request.SessionID, params.Cols, params.Rows)
		}
		result = map[string]bool{"resized": operationErr == nil}
	case string(authz.OperationSignal):
		var params struct {
			Signal target.Signal `json:"signal"`
		}
		operationErr = json.Unmarshal(request.Data, &params)
		if operationErr == nil {
			operationErr = d.authorizeSession(device, request.SessionID, authz.OperationSignal, false)
		}
		if operationErr == nil {
			operationErr = d.manager.Signal(request.SessionID, params.Signal)
		}
		result = map[string]bool{"signaled": operationErr == nil}
	case string(authz.OperationRemove):
		operationErr = d.authorizeSession(device, request.SessionID, authz.OperationRemove, false)
		if operationErr == nil {
			operationErr = d.manager.Remove(request.SessionID)
		}
		result = map[string]bool{"removed": operationErr == nil}
	case string(authz.OperationCreate):
		var params struct {
			Template  string `json:"template"`
			Name      string `json:"name"`
			Workspace string `json:"workspace"`
			Target    string `json:"target"`
		}
		operationErr = json.Unmarshal(request.Data, &params)
		if operationErr == nil {
			operationErr = authz.Authorize(device.Role, "", authz.OperationCreate, false)
		}
		if operationErr == nil && d.templates == nil {
			operationErr = errors.New("mobile session templates are not configured")
		}
		if operationErr == nil {
			spec, permission, err := d.templates.Resolve(params.Template)
			if err != nil {
				operationErr = err
			} else {
				if params.Workspace != "" || params.Target != "" {
					if params.Template != "mesh" {
						operationErr = errors.New("launch parameters are only supported by the Mesh template")
					} else {
						var args []string
						args, operationErr = d.mesh.BuildArgs(params.Workspace, params.Target)
						spec.Args = append(spec.Args, args...)
					}
				}
				if operationErr == nil {
					result, operationErr = d.manager.Create(context.Background(), params.Name, spec, permission)
				}
			}
		}
	case "session.replay":
		var params struct {
			FromSeq uint64 `json:"from_seq"`
		}
		operationErr = json.Unmarshal(request.Data, &params)
		if operationErr == nil {
			operationErr = d.authorizeSession(device, request.SessionID, authz.OperationAttach, false)
		}
		if operationErr == nil {
			result, operationErr = d.manager.Replay(request.SessionID, params.FromSeq)
		}
	default:
		operationErr = fmt.Errorf("unsupported remote command %q", request.Type)
	}

	outcome := "accepted"
	if operationErr != nil {
		outcome = errorCode(operationErr)
	}
	if d.store != nil {
		_ = d.store.Audit(ctx, store.AuditEntry{
			OccurredAt: time.Now(), DeviceID: device.ID, SessionID: request.SessionID,
			Action: request.Type, Outcome: outcome,
		}, input)
	}
	if operationErr != nil {
		return withError(response, outcome, operationErr.Error())
	}
	data, err := json.Marshal(result)
	if err != nil {
		return withError(response, "internal", err.Error())
	}
	response.Data = data
	return response
}

func (d *Dispatcher) authorizeSession(device DeviceContext, sessionID string, operation authz.Operation, confirmed bool) error {
	managed, err := d.manager.Get(sessionID)
	if err != nil {
		return err
	}
	return authz.Authorize(device.Role, managed.PermissionFor(device.ID), operation, confirmed)
}

func withError(response protocol.Envelope, code, message string) protocol.Envelope {
	response.Type = "error"
	response.Data, _ = json.Marshal(protocol.Error{Code: code, Message: message})
	return response
}

func errorCode(err error) string {
	switch {
	case errors.Is(err, authz.ErrUnauthorized):
		return "unauthorized"
	case errors.Is(err, authz.ErrReadOnly), errors.Is(err, session.ErrReadOnly):
		return "read_only"
	case errors.Is(err, authz.ErrConfirmationNeeded):
		return "confirmation_required"
	case errors.Is(err, session.ErrNotFound):
		return "not_found"
	case errors.Is(err, session.ErrSessionActive):
		return "session_active"
	default:
		return "invalid_message"
	}
}
