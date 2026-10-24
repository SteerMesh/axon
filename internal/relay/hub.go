package relay

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
)

const MaxFrameBytes = 128 << 10

type RouteFrame struct {
	Version int    `json:"v"`
	MateID  string `json:"mate_id"`
	From    string `json:"from"`
	To      string `json:"to"`
	Payload []byte `json:"payload"`
}

type Hub struct {
	mu      sync.RWMutex
	token   string
	mates   map[string]*peer
	devices map[string]map[string]*peer
	origins []string
}

type peer struct {
	conn     *websocket.Conn
	writeMu  sync.Mutex
	mateID   string
	deviceID string
	role     string
}

func NewHub(token string, origins ...string) *Hub {
	return &Hub{token: token, mates: make(map[string]*peer), devices: make(map[string]map[string]*peer), origins: origins}
}

func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
		return
	}
	if r.URL.Path != "/v1/connect" {
		http.NotFound(w, r)
		return
	}
	if !h.authorized(r) {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	mateID, role, deviceID := r.URL.Query().Get("mate_id"), r.URL.Query().Get("role"), r.URL.Query().Get("device_id")
	if mateID == "" || (role != "mate" && role != "device") || (role == "device" && deviceID == "") {
		http.Error(w, "invalid routing identity", http.StatusBadRequest)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: h.origins, Subprotocols: []string{"axon.v1"}})
	if err != nil {
		return
	}
	p := &peer{conn: conn, mateID: mateID, role: role, deviceID: deviceID}
	if err := h.register(p); err != nil {
		_ = conn.Close(websocket.StatusPolicyViolation, err.Error())
		return
	}
	defer h.unregister(p)
	defer conn.CloseNow()
	h.readLoop(r.Context(), p)
}

func (h *Hub) authorized(r *http.Request) bool {
	header := r.Header.Get("Authorization")
	want := "Bearer " + h.token
	if h.token != "" && len(header) == len(want) && subtle.ConstantTimeCompare([]byte(header), []byte(want)) == 1 {
		return true
	}
	encoded := "bearer." + base64.RawURLEncoding.EncodeToString([]byte(h.token))
	for _, protocol := range strings.Split(r.Header.Get("Sec-WebSocket-Protocol"), ",") {
		candidate := strings.TrimSpace(protocol)
		if len(candidate) == len(encoded) && subtle.ConstantTimeCompare([]byte(candidate), []byte(encoded)) == 1 {
			return true
		}
	}
	return false
}

func (h *Hub) register(p *peer) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if p.role == "mate" {
		if _, exists := h.mates[p.mateID]; exists {
			return errors.New("mate is already connected")
		}
		h.mates[p.mateID] = p
		return nil
	}
	if h.devices[p.mateID] == nil {
		h.devices[p.mateID] = make(map[string]*peer)
	}
	if _, exists := h.devices[p.mateID][p.deviceID]; exists {
		return errors.New("device is already connected")
	}
	h.devices[p.mateID][p.deviceID] = p
	return nil
}

func (h *Hub) unregister(p *peer) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if p.role == "mate" {
		if h.mates[p.mateID] == p {
			delete(h.mates, p.mateID)
		}
		return
	}
	if devices := h.devices[p.mateID]; devices != nil && devices[p.deviceID] == p {
		delete(devices, p.deviceID)
		if len(devices) == 0 {
			delete(h.devices, p.mateID)
		}
	}
}

func (h *Hub) readLoop(ctx context.Context, source *peer) {
	for {
		messageType, data, err := source.conn.Read(ctx)
		if err != nil {
			return
		}
		if messageType != websocket.MessageBinary || len(data) > MaxFrameBytes {
			_ = source.conn.Close(websocket.StatusUnsupportedData, "binary frame required or frame too large")
			return
		}
		var frame RouteFrame
		if err := json.Unmarshal(data, &frame); err != nil || frame.Version != 1 || frame.MateID != source.mateID {
			_ = source.conn.Close(websocket.StatusPolicyViolation, "invalid routing frame")
			return
		}
		if source.role == "device" {
			frame.From = source.deviceID
			frame.To = "mate"
		} else {
			frame.From = "mate"
			if frame.To == "" || frame.To == "mate" {
				_ = source.conn.Close(websocket.StatusPolicyViolation, "mate frame requires device destination")
				return
			}
		}
		target := h.target(frame)
		if target == nil {
			continue
		}
		forwarded, _ := json.Marshal(frame)
		writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = target.write(writeCtx, forwarded)
		cancel()
		if err != nil {
			return
		}
	}
}

func (h *Hub) target(frame RouteFrame) *peer {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if frame.To == "mate" {
		return h.mates[frame.MateID]
	}
	return h.devices[frame.MateID][frame.To]
}

func (h *Hub) MateConnected(mateID string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.mates[mateID] != nil
}

func (p *peer) write(ctx context.Context, data []byte) error {
	p.writeMu.Lock()
	defer p.writeMu.Unlock()
	if err := p.conn.Write(ctx, websocket.MessageBinary, data); err != nil {
		return fmt.Errorf("forward route frame: %w", err)
	}
	return nil
}
