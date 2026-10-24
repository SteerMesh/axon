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

func (c *Connector) Run(ctx context.Context) error {
	backoff := time.Second
	for {
		if err := c.runOnce(ctx); err != nil && ctx.Err() == nil {
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
		response, err := c.endpoint.Process(ctx, frame.From, frame.Payload)
		if err != nil {
			slog.Warn("Rejected remote frame", "device_id", frame.From, "error", err)
			continue
		}
		if err := c.Send(ctx, frame.From, response); err != nil {
			return err
		}
	}
}

func (c *Connector) Send(ctx context.Context, deviceID string, payload []byte) error {
	frame, err := json.Marshal(relay.RouteFrame{Version: 1, MateID: c.mateID, From: "mate", To: deviceID, Payload: payload})
	if err != nil {
		return err
	}
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	if c.conn == nil {
		return fmt.Errorf("relay is not connected")
	}
	writeCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	return c.conn.Write(writeCtx, websocket.MessageBinary, frame)
}
