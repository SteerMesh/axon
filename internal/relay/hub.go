package relay

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	webpush "github.com/SherClockHolmes/webpush-go"
	"github.com/SteerMesh/axon/internal/security"
	"github.com/coder/websocket"
)

const MaxFrameBytes = 128 << 10

// vapidSubscriber is the "aud"/"sub" contact embedded in the VAPID JWT, as
// required by RFC 8292. It identifies the relay operator to push services,
// not any end user.
const vapidSubscriber = "mailto:axon-relay@steermesh.dev"

// pushSender matches webpush.SendNotificationWithContext so tests can
// substitute a mock without making real network calls.
type pushSender func(ctx context.Context, message []byte, s *webpush.Subscription, options *webpush.Options) (*http.Response, error)

type RouteFrame struct {
	Version int    `json:"v"`
	MateID  string `json:"mate_id"`
	From    string `json:"from"`
	To      string `json:"to"`
	Payload []byte `json:"payload"`
}

type Hub struct {
	mu       sync.RWMutex
	mateKeys map[string]ed25519.PublicKey
	mates    map[string]*peer
	devices  map[string]map[string]*peer
	origins  []string
	push     *pushConfig
}

// pushConfig holds everything needed to wake a backgrounded device over Web
// Push. It is nil until EnablePush is called, which keeps the relay fully
// functional (just without wake notifications) when VAPID keys aren't set.
type pushConfig struct {
	store      *SubscriptionStore
	publicKey  string
	privateKey string
	send       pushSender
}

type peer struct {
	conn     *websocket.Conn
	writeMu  sync.Mutex
	mateID   string
	deviceID string
	role     string
}

// NewHub builds a relay hub that authenticates connections against
// mateKeys, a registry of each mate's Ed25519 identity public key (see
// cmd/axon-relay/main.go, AXON_RELAY_MATE_KEYS). The relay never stores or
// issues credentials itself -- it only verifies Relay Access Tokens (see
// internal/security/relaytoken.go) that a mate signed with the private
// half of one of these keys.
func NewHub(mateKeys map[string]ed25519.PublicKey, origins ...string) *Hub {
	return &Hub{mateKeys: mateKeys, mates: make(map[string]*peer), devices: make(map[string]map[string]*peer), origins: origins}
}

// EnablePush turns on Web Push wake notifications. Until this is called the
// relay behaves exactly as before: a frame with no connected target peer is
// silently dropped.
func (h *Hub) EnablePush(store *SubscriptionStore, publicKey, privateKey string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.push = &pushConfig{store: store, publicKey: publicKey, privateKey: privateKey, send: webpush.SendNotificationWithContext}
}

func (h *Hub) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/healthz" {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
		return
	}
	if r.URL.Path == "/v1/vapid-key" {
		h.handleVAPIDKey(w, r)
		return
	}
	if r.URL.Path == "/v1/push/subscribe" {
		h.handlePushSubscribe(w, r)
		return
	}
	if r.URL.Path != "/v1/connect" {
		http.NotFound(w, r)
		return
	}
	mateID, role, deviceID := r.URL.Query().Get("mate_id"), r.URL.Query().Get("role"), r.URL.Query().Get("device_id")
	if mateID == "" || (role != "mate" && role != "device") || (role == "device" && deviceID == "") {
		http.Error(w, "invalid routing identity", http.StatusBadRequest)
		return
	}
	if !h.authorizedConnect(r, mateID, role, deviceID) {
		slog.Warn("Relay connection unauthorized", "mate_id", mateID, "role", role, "device_id", deviceID)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{OriginPatterns: h.origins, Subprotocols: []string{"axon.v1"}})
	if err != nil {
		slog.Warn("Relay WebSocket acceptance failed", "mate_id", mateID, "role", role, "error", err)
		return
	}
	// coder/websocket defaults to a 32768-byte read limit, well under
	// MaxFrameBytes. Without raising it here, any frame between 32KB and
	// MaxFrameBytes never reaches the size check in readLoop below — the
	// library kills the connection first with StatusMessageTooBig.
	conn.SetReadLimit(MaxFrameBytes)
	p := &peer{conn: conn, mateID: mateID, role: role, deviceID: deviceID}
	if err := h.register(p); err != nil {
		slog.Warn("Relay peer registration rejected", "mate_id", mateID, "role", role, "device_id", deviceID, "error", err)
		_ = conn.Close(websocket.StatusPolicyViolation, err.Error())
		return
	}
	defer h.unregister(p)
	defer conn.CloseNow()
	h.readLoop(r.Context(), p)
}

// pushSubscribeRequest mirrors the PushSubscription JSON shape the browser
// produces from PushManager.subscribe(), plus the routing identity needed to
// address it later.
type pushSubscribeRequest struct {
	MateID   string `json:"mate_id"`
	DeviceID string `json:"device_id"`
	Endpoint string `json:"endpoint"`
	Keys     struct {
		P256dh string `json:"p256dh"`
		Auth   string `json:"auth"`
	} `json:"keys"`
}

// handleVAPIDKey serves the relay's public VAPID key. It is intentionally
// unauthenticated: the key is public by definition, and serving it over HTTP
// (rather than baking it into the PWA build) lets the relay rotate it.
func (h *Hub) handleVAPIDKey(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	publicKey := ""
	if h.push != nil {
		publicKey = h.push.publicKey
	}
	h.mu.RUnlock()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"publicKey": publicKey})
}

// handlePushSubscribe requires a device-scope Relay Access Token bound to
// the exact (mate_id, device_id) being subscribed or unsubscribed (see
// authorizedDevice). That identity has to be parsed out of this request's
// own body/query first -- unlike /v1/connect, there's no URL query
// parameter carrying it uniformly across methods -- so each method below
// resolves its identity before authorizing, never after.
func (h *Hub) handlePushSubscribe(w http.ResponseWriter, r *http.Request) {
	h.mu.RLock()
	push := h.push
	h.mu.RUnlock()
	if push == nil {
		http.Error(w, "push notifications are not configured", http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodPost:
		var req pushSubscribeRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid request body", http.StatusBadRequest)
			return
		}
		if req.MateID == "" || req.DeviceID == "" || req.Endpoint == "" || req.Keys.P256dh == "" || req.Keys.Auth == "" {
			http.Error(w, "mate_id, device_id, endpoint, and keys are required", http.StatusBadRequest)
			return
		}
		if !h.authorizedDevice(r, req.MateID, req.DeviceID) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		sub := Subscription{
			MateID: req.MateID, DeviceID: req.DeviceID, Endpoint: req.Endpoint,
			P256dh: req.Keys.P256dh, Auth: req.Keys.Auth, CreatedAt: time.Now().UTC(),
		}
		if err := push.store.Upsert(r.Context(), sub); err != nil {
			http.Error(w, "store subscription: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case http.MethodDelete:
		mateID, deviceID := r.URL.Query().Get("mate_id"), r.URL.Query().Get("device_id")
		if mateID == "" || deviceID == "" {
			var req pushSubscribeRequest
			if err := json.NewDecoder(r.Body).Decode(&req); err == nil {
				if mateID == "" {
					mateID = req.MateID
				}
				if deviceID == "" {
					deviceID = req.DeviceID
				}
			}
		}
		if mateID == "" || deviceID == "" {
			http.Error(w, "mate_id and device_id are required", http.StatusBadRequest)
			return
		}
		if !h.authorizedDevice(r, mateID, deviceID) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if err := push.store.Delete(r.Context(), mateID, deviceID); err != nil {
			http.Error(w, "delete subscription: "+err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// authorizedConnect binds a Relay Access Token to the exact identity a
// /v1/connect request claims: mate_id/role/device_id are parsed before
// this runs (see ServeHTTP) specifically so the check below can verify
// the token was issued for *this* mate_id and is of a scope *this* role
// is allowed to use -- a token can't be replayed by a different mate or
// across roles it wasn't minted for.
func (h *Hub) authorizedConnect(r *http.Request, mateID, role, deviceID string) bool {
	allowedScopes := []security.RelayTokenScope{security.RelayScopePairing, security.RelayScopeDevice}
	if role == "mate" {
		allowedScopes = []security.RelayTokenScope{security.RelayScopeMate}
	}
	return h.verifyRelayAccessToken(r, mateID, allowedScopes, deviceID)
}

// authorizedDevice binds a Relay Access Token to a REST request (push
// subscribe/unsubscribe) that identifies its own mate_id/device_id in its
// body or query params rather than in the URL the way /v1/connect does.
// Callers must resolve those identity fields themselves and pass them in
// here -- before this runs -- so the scope-and-identity check below is
// always against the caller's own claimed identity, never an empty or
// partially-parsed one. Only device-scope tokens are accepted: by the
// time a device calls this, pairing has already completed and it holds a
// real device-scope token (see security.PairingResult), so there is no
// legitimate wildcard/pairing-scope use case here.
func (h *Hub) authorizedDevice(r *http.Request, mateID, deviceID string) bool {
	return h.verifyRelayAccessToken(r, mateID, []security.RelayTokenScope{security.RelayScopeDevice}, deviceID)
}

func (h *Hub) verifyRelayAccessToken(r *http.Request, mateID string, allowedScopes []security.RelayTokenScope, deviceID string) bool {
	h.mu.RLock()
	mateKey, known := h.mateKeys[mateID]
	h.mu.RUnlock()
	if !known {
		authFailures.WithLabelValues("unknown_mate").Inc()
		return false
	}
	token := bearerToken(r)
	if token == "" {
		authFailures.WithLabelValues("bad_signature").Inc()
		return false
	}
	_, err := security.VerifyRelayToken(token, mateKey, mateID, allowedScopes, deviceID, time.Now())
	if err != nil {
		authFailures.WithLabelValues(authFailureReason(err)).Inc()
		return false
	}
	return true
}

// authFailureReason maps a security.VerifyRelayToken error to the metric
// label for axon_relay_auth_failures_total. It mirrors that function's own
// branches exactly (see relaytoken.go) via errors.Is against its exported
// sentinels, rather than inventing categories the code can't actually
// produce.
func authFailureReason(err error) string {
	switch {
	case errors.Is(err, security.ErrRelayTokenWrongScope):
		return "wrong_scope"
	case errors.Is(err, security.ErrRelayTokenDeviceMismatch):
		return "device_id_mismatch"
	case errors.Is(err, security.ErrRelayTokenExpired):
		return "expired"
	default:
		// security.ErrRelayTokenInvalid, or anything else unrecognized --
		// the token's own encoding/signature/identity didn't check out.
		return "bad_signature"
	}
}

// bearerToken reads the RAT from the Authorization header (used by the
// mate, and by any non-browser client) or, failing that, from the
// `bearer.<base64url(token)>` WebSocket subprotocol (used by the browser
// PWA, which cannot set arbitrary headers on a WebSocket handshake).
func bearerToken(r *http.Request) string {
	if header := r.Header.Get("Authorization"); strings.HasPrefix(header, "Bearer ") {
		return strings.TrimPrefix(header, "Bearer ")
	}
	for _, candidate := range strings.Split(r.Header.Get("Sec-WebSocket-Protocol"), ",") {
		candidate = strings.TrimSpace(candidate)
		if encoded, ok := strings.CutPrefix(candidate, "bearer."); ok {
			decoded, err := base64.RawURLEncoding.DecodeString(encoded)
			if err == nil {
				return string(decoded)
			}
		}
	}
	return ""
}

func (h *Hub) register(p *peer) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if p.role == "mate" {
		if _, exists := h.mates[p.mateID]; exists {
			return errors.New("mate is already connected")
		}
		h.mates[p.mateID] = p
		connectionsActive.WithLabelValues(p.role).Inc()
		return nil
	}
	if h.devices[p.mateID] == nil {
		h.devices[p.mateID] = make(map[string]*peer)
	}
	if _, exists := h.devices[p.mateID][p.deviceID]; exists {
		return errors.New("device is already connected")
	}
	h.devices[p.mateID][p.deviceID] = p
	connectionsActive.WithLabelValues(p.role).Inc()
	return nil
}

func (h *Hub) unregister(p *peer) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if p.role == "mate" {
		if h.mates[p.mateID] == p {
			delete(h.mates, p.mateID)
			connectionsActive.WithLabelValues(p.role).Dec()
		}
		return
	}
	if devices := h.devices[p.mateID]; devices != nil && devices[p.deviceID] == p {
		delete(devices, p.deviceID)
		if len(devices) == 0 {
			delete(h.devices, p.mateID)
		}
		connectionsActive.WithLabelValues(p.role).Dec()
	}
}

func (h *Hub) readLoop(ctx context.Context, source *peer) {
	for {
		messageType, data, err := source.conn.Read(ctx)
		if err != nil {
			slog.Info("Relay peer disconnected",
				"mate_id", source.mateID,
				"role", source.role,
				"device_id", source.deviceID,
				"status", websocket.CloseStatus(err),
				"error", err,
			)
			return
		}
		if messageType != websocket.MessageBinary || len(data) > MaxFrameBytes {
			slog.Warn("Relay rejected message",
				"mate_id", source.mateID,
				"role", source.role,
				"device_id", source.deviceID,
				"message_type", messageType,
				"size", len(data),
			)
			_ = source.conn.Close(websocket.StatusUnsupportedData, "binary frame required or frame too large")
			return
		}
		var frame RouteFrame
		if err := json.Unmarshal(data, &frame); err != nil || frame.Version != 1 || frame.MateID != source.mateID {
			slog.Warn("Relay rejected route frame",
				"mate_id", source.mateID,
				"role", source.role,
				"device_id", source.deviceID,
				"frame_version", frame.Version,
				"frame_mate_id", frame.MateID,
				"error", err,
			)
			_ = source.conn.Close(websocket.StatusPolicyViolation, "invalid routing frame")
			return
		}
		frameBytes.Observe(float64(len(data)))
		if source.role == "device" {
			frame.From = source.deviceID
			frame.To = "mate"
		} else {
			frame.From = "mate"
			if frame.To == "" || frame.To == "mate" {
				slog.Warn("Relay rejected mate route without device destination", "mate_id", source.mateID, "to", frame.To)
				_ = source.conn.Close(websocket.StatusPolicyViolation, "mate frame requires device destination")
				return
			}
		}
		target := h.target(frame)
		if target == nil {
			if source.role == "device" {
				framesTotal.WithLabelValues("dropped_no_peer").Inc()
				_ = source.conn.Close(websocket.StatusTryAgainLater, "mate unavailable")
				return
			}
			framesTotal.WithLabelValues("woken_via_push").Inc()
			h.triggerPush(frame)
			continue
		}
		forwarded, _ := json.Marshal(frame)
		writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		err = target.write(writeCtx, forwarded)
		cancel()
		if err == nil {
			framesTotal.WithLabelValues("delivered").Inc()
		} else {
			slog.Warn("Relay target delivery failed",
				"source_role", source.role,
				"mate_id", source.mateID,
				"device_id", target.deviceID,
				"error", err,
			)
			h.unregister(target)
			target.conn.CloseNow()
			if source.role == "device" {
				_ = source.conn.Close(websocket.StatusTryAgainLater, "mate unavailable")
				return
			}
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

// triggerPush fires a content-free Web Push wake notification when a frame
// could not be delivered to a connected device peer. It is called from the
// exact point that already detects "no connected peer for this device" with
// zero content awareness, so it adds no new information flow: the relay
// still never learns anything about the frame beyond its routing identity.
// Mate targets never have a push subscription (the host agent isn't a
// browser), so only device targets are considered.
func (h *Hub) triggerPush(frame RouteFrame) {
	if frame.To == "" || frame.To == "mate" {
		return
	}
	h.mu.RLock()
	push := h.push
	h.mu.RUnlock()
	if push == nil {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		push.notify(ctx, frame.MateID, frame.To)
	}()
}

// notify looks up the subscription for (mateID, deviceID) and, if present,
// sends a wake notification. The push payload is fixed and content-free: it
// never carries sid, data, or anything content-derived. A 404/410 response
// means the push service considers the subscription dead, so it is removed.
func (p *pushConfig) notify(ctx context.Context, mateID, deviceID string) {
	sub, err := p.store.Get(ctx, mateID, deviceID)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			slog.Warn("Axon Relay failed to look up push subscription", "error", err)
		}
		return
	}
	payload := []byte(`{"type":"wake"}`)
	resp, err := p.send(ctx, payload, &webpush.Subscription{
		Endpoint: sub.Endpoint,
		Keys:     webpush.Keys{P256dh: sub.P256dh, Auth: sub.Auth},
	}, &webpush.Options{
		Subscriber:      vapidSubscriber,
		VAPIDPublicKey:  p.publicKey,
		VAPIDPrivateKey: p.privateKey,
		TTL:             60,
	})
	if err != nil {
		pushTotal.WithLabelValues("failed").Inc()
		slog.Warn("Axon Relay failed to send push notification", "error", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone {
		pushTotal.WithLabelValues("pruned").Inc()
		if err := p.store.Delete(ctx, mateID, deviceID); err != nil {
			slog.Warn("Axon Relay failed to delete dead push subscription", "error", err)
		}
		return
	}
	pushTotal.WithLabelValues("sent").Inc()
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
