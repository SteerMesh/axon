package ipc

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/SteerMesh/axon/internal/session"
)

type Client struct {
	path string
	seq  atomic.Uint64
}

func NewClient(socketPath string) *Client { return &Client{path: socketPath} }

func (c *Client) Call(method string, params, result any) error {
	conn, err := net.DialTimeout("unix", c.path, 5*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	request, err := c.request(method, params)
	if err != nil {
		return err
	}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return err
	}
	var response Response
	if err := json.NewDecoder(conn).Decode(&response); err != nil {
		return err
	}
	if !response.OK {
		return fmt.Errorf("%s: %s", response.Error.Code, response.Error.Message)
	}
	if result != nil {
		return json.Unmarshal(response.Result, result)
	}
	return nil
}

func (c *Client) Subscribe(params AttachParams) (session.Replay, <-chan Event, func(), error) {
	conn, err := net.DialTimeout("unix", c.path, 5*time.Second)
	if err != nil {
		return session.Replay{}, nil, nil, err
	}
	request, err := c.request("session.attach", params)
	if err != nil {
		conn.Close()
		return session.Replay{}, nil, nil, err
	}
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		conn.Close()
		return session.Replay{}, nil, nil, err
	}
	decoder := json.NewDecoder(bufio.NewReader(conn))
	var response Response
	if err := decoder.Decode(&response); err != nil {
		conn.Close()
		return session.Replay{}, nil, nil, err
	}
	if !response.OK {
		conn.Close()
		return session.Replay{}, nil, nil, fmt.Errorf("%s: %s", response.Error.Code, response.Error.Message)
	}
	var attached AttachResult
	if err := json.Unmarshal(response.Result, &attached); err != nil {
		conn.Close()
		return session.Replay{}, nil, nil, err
	}
	events := make(chan Event, 32)
	go func() {
		defer close(events)
		defer conn.Close()
		for {
			var event Event
			if err := decoder.Decode(&event); err != nil {
				return
			}
			events <- event
		}
	}()
	return attached.Replay, events, func() { _ = conn.Close() }, nil
}

func (c *Client) request(method string, params any) (Request, error) {
	data, err := json.Marshal(params)
	if err != nil {
		return Request{}, err
	}
	return Request{
		ID:     fmt.Sprintf("local-%d", c.seq.Add(1)),
		Method: method,
		Params: data,
	}, nil
}
