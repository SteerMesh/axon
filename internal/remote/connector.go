package remote

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/SteerMesh/axon/internal/relay"
	"github.com/SteerMesh/axon/pkg/protocol"
	"github.com/coder/websocket"
)

type Connector struct {
	relayURL string
	token    string
	mateID   string
	endpoint *Endpoint

	writeMu sync.Mutex
	conn    *websocket.Conn
}

func NewConnector(relayURL, token, mateID string, endpoint *Endpoint) *Connector {
	return &Connector{relayURL: relayURL, token: token, mateID: mateID, endpoint: endpoint}
}

// healthyConnectionWindow is how long a relay connection must stay up before
// a subsequent failure is treated as a fresh problem rather than a
// continuation of a prior outage, so backoff can reset to its floor instead
// of staying stretched out from an earlier, unrelated run of failures.
const healthyConnectionWindow = 10 * time.Second

// resetsBackoff reports whether a connection that stayed up for connectedFor
// counts as healthy enough to reset backoff to its floor on disconnect.
func resetsBackoff(connectedFor time.Duration) bool {
	return connectedFor >= healthyConnectionWindow
}

func (c *Connector) Run(ctx context.Context) error {
	backoff := time.Second
	for {
		connectedAt := time.Now()
		err := c.runOnce(ctx)
		if resetsBackoff(time.Since(connectedAt)) {
			backoff = time.Second
		}
		if err != nil && ctx.Err() == nil {
			slog.Warn("Axon relay connection ended", "error", err, "retry_in", backoff)
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
		if backoff < 30*time.Second {
			backoff *= 2
		}
	}
}

func (c *Connector) runOnce(ctx context.Context) error {
	endpointURL, err := url.Parse(c.relayURL)
	if err != nil {
		return err
	}
	switch endpointURL.Scheme {
	case "https":
		endpointURL.Scheme = "wss"
	case "http":
		endpointURL.Scheme = "ws"
	case "ws", "wss":
	default:
		return fmt.Errorf("unsupported relay URL scheme %q", endpointURL.Scheme)
	}
	endpointURL.Path = "/v1/connect"
	query := endpointURL.Query()
	query.Set("mate_id", c.mateID)
	query.Set("role", "mate")
	endpointURL.RawQuery = query.Encode()
	header := make(http.Header)
	header.Set("Authorization", "Bearer "+c.token)
	conn, _, err := websocket.Dial(ctx, endpointURL.String(), &websocket.DialOptions{HTTPHeader: header, Subprotocols: []string{"axon.v1"}})
	if err != nil {
		return err
	}
	c.writeMu.Lock()
	c.conn = conn
	c.writeMu.Unlock()
	defer func() {
		c.writeMu.Lock()
		c.conn = nil
		c.writeMu.Unlock()
		conn.CloseNow()
	}()

	for {
		messageType, data, err := conn.Read(ctx)
		if err != nil {
			return err
		}
		if messageType != websocket.MessageBinary {
			continue
		}
		var frame relay.RouteFrame
		if err := json.Unmarshal(data, &frame); err != nil || frame.From == "" {
			continue
		}
		outbound, err := c.endpoint.Handle(ctx, frame.From, frame.Payload)
		if err != nil {
			slog.Warn("Rejected remote frame", "device_id", frame.From, "error", err)
			// A device waiting on this request must never hang indefinitely:
			// always send back a reply, even when the Mate could not satisfy
			// it, so the device's pending promise settles.
			if sendErr := c.Send(ctx, frame.From, errorPacket(err)); sendErr != nil {
				return sendErr
			}
			continue
		}
		if outbound.Envelope != nil {
			if err := c.sendEnvelope(ctx, frame.From, *outbound.Envelope); err != nil {
				return err
			}
			if outbound.Subscription != nil {
				c.endpoint.Activate(ctx, frame.From, outbound.Subscription, func(event protocol.Envelope) error {
					return c.sendEnvelope(ctx, frame.From, event)
				})
			}
		} else if err := c.Send(ctx, frame.From, outbound.Packet); err != nil {
			return err
		}
	}
}

func (c *Connector) Send(ctx context.Context, deviceID string, payload []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	return c.sendLocked(ctx, deviceID, payload)
}

func (c *Connector) sendEnvelope(ctx context.Context, deviceID string, envelope protocol.Envelope) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	payload, err := c.endpoint.Encrypt(deviceID, envelope)
	if err != nil {
		return err
	}
	return c.sendLocked(ctx, deviceID, payload)
}

func (c *Connector) sendLocked(ctx context.Context, deviceID string, payload []byte) error {
	frame, err := json.Marshal(relay.RouteFrame{Version: 1, MateID: c.mateID, From: "mate", To: deviceID, Payload: payload})
	if err != nil {
		return err
	}
	if c.conn == nil {
		return fmt.Errorf("relay is not connected")
	}
	writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return c.conn.Write(writeCtx, websocket.MessageBinary, frame)
}
