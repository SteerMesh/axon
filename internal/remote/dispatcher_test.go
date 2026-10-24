package remote

import (
	"context"
	"encoding/json"
	"io"
	"reflect"
	"testing"
	"time"

	"github.com/SteerMesh/axon/internal/authz"
	"github.com/SteerMesh/axon/internal/domain"
	"github.com/SteerMesh/axon/internal/meshcli"
	"github.com/SteerMesh/axon/internal/session"
	"github.com/SteerMesh/axon/internal/templates"
	"github.com/SteerMesh/axon/pkg/protocol"
)

func TestDispatcherCommandMatrix(t *testing.T) {
	r, w := io.Pipe()
	manager := session.NewManager(1024, endpointAdapter{process: &endpointProcess{r: r}})
	catalog := templates.Catalog{Templates: map[string]templates.Template{
		"safe": {Target: "test", Permission: domain.PermissionInteractive},
	}}
	dispatcher := NewDispatcher(manager, nil).WithTemplates(catalog)
	owner := DeviceContext{ID: "owner", Role: authz.RoleOwner}
	viewer := DeviceContext{ID: "viewer", Role: authz.RoleViewer}

	created := dispatcher.Handle(context.Background(), owner, requestEnvelope(string(authz.OperationCreate), "", "create-1", map[string]any{"template": "safe", "name": "remote"}))
	if created.Type == "error" {
		t.Fatalf("create failed: %s", created.Data)
	}
	var createdSession domain.Session
	if err := json.Unmarshal(created.Data, &createdSession); err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name      string
		device    DeviceContext
		req       protocol.Envelope
		wantError string
	}{
		{"list", viewer, requestEnvelope(string(authz.OperationList), "", "list", nil), ""},
		{"viewer input", viewer, requestEnvelope(string(authz.OperationInput), createdSession.ID, "viewer-input", map[string]any{"bytes": []byte("x"), "confirmed": true}), "unauthorized"},
		{"owner input", owner, requestEnvelope(string(authz.OperationInput), createdSession.ID, "owner-input", map[string]any{"bytes": []byte("x"), "confirmed": true}), ""},
		{"resize", viewer, requestEnvelope(string(authz.OperationResize), createdSession.ID, "resize", map[string]any{"cols": 90, "rows": 30}), ""},
		{"signal", owner, requestEnvelope(string(authz.OperationSignal), createdSession.ID, "signal", map[string]any{"signal": "interrupt"}), ""},
		{"replay", viewer, requestEnvelope("session.replay", createdSession.ID, "replay", map[string]any{"from_seq": 0}), ""},
		{"missing session", owner, requestEnvelope(string(authz.OperationSignal), "missing", "missing", map[string]any{"signal": "kill"}), "not_found"},
		{"invalid json", owner, protocol.Envelope{Version: 1, ID: "bad-json", Type: string(authz.OperationInput), SessionID: createdSession.ID, Timestamp: time.Now(), IdempotencyKey: "bad", Data: json.RawMessage("{")}, "invalid_message"},
		{"invalid envelope", owner, protocol.Envelope{Version: 0, ID: "bad", Type: string(authz.OperationList), Timestamp: time.Now()}, "invalid_message"},
		{"unsupported", owner, requestEnvelope("session.erase", createdSession.ID, "unknown", nil), "invalid_message"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := dispatcher.Handle(context.Background(), test.device, test.req)
			if test.wantError == "" {
				if response.Type == "error" {
					t.Fatalf("unexpected error: %s", response.Data)
				}
				return
			}
			var protocolError protocol.Error
			if response.Type != "error" || json.Unmarshal(response.Data, &protocolError) != nil || protocolError.Code != test.wantError {
				t.Fatalf("response = %+v, error = %+v", response, protocolError)
			}
		})
	}
	_ = w.Close()
}

func TestDispatcherTemplateAndConfirmationFailures(t *testing.T) {
	manager := session.NewManager(1024, endpointAdapter{process: &endpointProcess{r: mustPipeReader(t)}})
	owner := DeviceContext{ID: "owner", Role: authz.RoleOwner}
	viewer := DeviceContext{ID: "viewer", Role: authz.RoleViewer}
	dispatcher := NewDispatcher(manager, nil)
	for _, test := range []struct {
		name   string
		device DeviceContext
		req    protocol.Envelope
		code   string
	}{
		{"viewer create", viewer, requestEnvelope(string(authz.OperationCreate), "", "viewer-create", map[string]any{"template": "x"}), "unauthorized"},
		{"templates absent", owner, requestEnvelope(string(authz.OperationCreate), "", "no-template", map[string]any{"template": "x"}), "invalid_message"},
	} {
		t.Run(test.name, func(t *testing.T) {
			response := dispatcher.Handle(context.Background(), test.device, test.req)
			var got protocol.Error
			_ = json.Unmarshal(response.Data, &got)
			if got.Code != test.code {
				t.Fatalf("got %q, want %q", got.Code, test.code)
			}
		})
	}

	r, _ := io.Pipe()
	manager = session.NewManager(1024, endpointAdapter{process: &endpointProcess{r: r}})
	created, err := manager.Create(context.Background(), "confirm", domain.TargetSpec{Kind: "test"}, domain.PermissionConfirmInput)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher = NewDispatcher(manager, nil)
	response := dispatcher.Handle(context.Background(), owner, requestEnvelope(string(authz.OperationInput), created.ID, "confirm", map[string]any{"bytes": []byte("yes"), "confirmed": false}))
	var got protocol.Error
	_ = json.Unmarshal(response.Data, &got)
	if got.Code != "confirmation_required" {
		t.Fatalf("got %+v", got)
	}
}

func TestDispatcherListsMeshOptionsAndCreatesConfiguredMeshSession(t *testing.T) {
	r, _ := io.Pipe()
	manager := session.NewManager(1024, endpointAdapter{process: &endpointProcess{r: r}})
	catalog := templates.Catalog{Templates: map[string]templates.Template{
		"mesh": {Target: "test", Permission: domain.PermissionInteractive},
	}}
	options := meshcli.Options{
		Workspaces: []string{"steermesh-team"},
		Targets:    []string{"kiro", "codex"},
	}
	dispatcher := NewDispatcher(manager, nil).WithTemplates(catalog).WithMeshOptions(options)
	owner := DeviceContext{ID: "owner", Role: authz.RoleOwner}

	response := dispatcher.Handle(context.Background(), owner, requestEnvelope("mesh.options", "", "options", nil))
	if response.Type == "error" {
		t.Fatalf("options failed: %s", response.Data)
	}
	var gotOptions meshcli.Options
	if err := json.Unmarshal(response.Data, &gotOptions); err != nil || len(gotOptions.Workspaces) != 1 {
		t.Fatalf("options = %+v, err = %v", gotOptions, err)
	}

	response = dispatcher.Handle(context.Background(), owner, requestEnvelope(string(authz.OperationCreate), "", "create", map[string]any{
		"template": "mesh", "name": "remote", "workspace": "steermesh-team", "target": "codex",
	}))
	if response.Type == "error" {
		t.Fatalf("create failed: %s", response.Data)
	}
	var created domain.Session
	if err := json.Unmarshal(response.Data, &created); err != nil {
		t.Fatal(err)
	}
	if got, want := created.Target.Args, []string{"--ws", "steermesh-team", "--target", "codex"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("args = %v, want %v", got, want)
	}

	response = dispatcher.Handle(context.Background(), owner, requestEnvelope(string(authz.OperationCreate), "", "invalid", map[string]any{
		"template": "mesh", "name": "invalid", "workspace": "missing", "target": "codex",
	}))
	if response.Type != "error" {
		t.Fatal("unknown workspace was accepted")
	}
}

func requestEnvelope(kind, sessionID, id string, body any) protocol.Envelope {
	data, _ := json.Marshal(body)
	request := protocol.Envelope{Version: 1, ID: id, Type: kind, SessionID: sessionID, Timestamp: time.Now(), Data: data}
	if kind == string(authz.OperationInput) {
		request.IdempotencyKey = id
	}
	return request
}

func mustPipeReader(t *testing.T) *io.PipeReader {
	t.Helper()
	r, _ := io.Pipe()
	return r
}
