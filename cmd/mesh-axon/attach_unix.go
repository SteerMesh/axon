//go:build unix

package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/SteerMesh/axon/internal/ipc"
	"golang.org/x/term"
)

func attach(socketPath, sessionID string, from uint64) error {
	client := ipc.NewClient(socketPath)
	replay, events, cancel, err := client.Subscribe(ipc.AttachParams{SessionID: sessionID, FromSeq: from})
	if err != nil {
		return agentUnavailable(err)
	}
	defer cancel()
	for _, chunk := range replay.Chunks {
		if _, err := os.Stdout.Write(chunk.Data); err != nil {
			return err
		}
	}

	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		return fmt.Errorf("attach requires a terminal")
	}
	oldState, err := term.MakeRaw(fd)
	if err != nil {
		return err
	}
	defer term.Restore(fd, oldState)

	resize := func() {
		cols, rows, err := term.GetSize(fd)
		if err == nil {
			_ = client.Call("session.resize", ipc.ResizeParams{SessionID: sessionID, Cols: uint16(cols), Rows: uint16(rows)}, nil)
		}
	}
	resize()
	windows := make(chan os.Signal, 1)
	signal.Notify(windows, syscall.SIGWINCH)
	defer signal.Stop(windows)
	go func() {
		for range windows {
			resize()
		}
	}()

	inputDone := make(chan struct{})
	go func() {
		defer close(inputDone)
		buffer := make([]byte, 4096)
		var detachPrefix bool
		for {
			n, readErr := os.Stdin.Read(buffer)
			if n > 0 {
				data := buffer[:n]
				if detachPrefix && data[0] == 'd' {
					cancel()
					return
				}
				detachPrefix = data[n-1] == 0x1c // Ctrl-\\
				if detachPrefix {
					data = data[:n-1]
				}
				if len(data) > 0 {
					_ = client.Call("session.input", ipc.InputParams{
						SessionID:      sessionID,
						DeviceID:       "local",
						IdempotencyKey: inputKey(),
						Data:           data,
					}, nil)
				}
			}
			if readErr != nil {
				return
			}
		}
	}()

	for event := range events {
		if _, err := os.Stdout.Write(event.Chunk.Data); err != nil {
			return err
		}
	}
	return nil
}
