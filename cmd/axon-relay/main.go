package main

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/SteerMesh/axon/internal/relay"
)

func main() {
	addr := envOr("AXON_RELAY_ADDR", ":8080")
	token := os.Getenv("AXON_RELAY_TOKEN")
	origins := splitNonEmpty(os.Getenv("AXON_RELAY_ORIGINS"))
	if token == "" {
		fmt.Fprintln(os.Stderr, "AXON_RELAY_TOKEN is required")
		os.Exit(1)
	}
	server := &http.Server{
		Addr: addr, Handler: relay.NewHub(token, origins...),
		ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 70 * time.Second,
	}
	slog.Info("Axon Relay listening", "address", addr)
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("Axon Relay stopped", "error", err)
		os.Exit(1)
	}
}

func splitNonEmpty(value string) []string {
	var result []string
	for _, item := range strings.Split(value, ",") {
		if item = strings.TrimSpace(item); item != "" {
			result = append(result, item)
		}
	}
	return result
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
