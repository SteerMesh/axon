package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/SteerMesh/axon/internal/relay"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

func main() {
	addr := envOr("AXON_RELAY_ADDR", ":8080")
	origins := splitNonEmpty(os.Getenv("AXON_RELAY_ORIGINS"))
	vapidPublicKey := os.Getenv("AXON_RELAY_VAPID_PUBLIC_KEY")
	vapidPrivateKey := os.Getenv("AXON_RELAY_VAPID_PRIVATE_KEY")
	mateKeys, err := parseMateKeys(os.Getenv("AXON_RELAY_MATE_KEYS"))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if len(mateKeys) == 0 {
		fmt.Fprintln(os.Stderr, "AXON_RELAY_MATE_KEYS is required (comma-separated mate_id=base64url-ed25519-public-key pairs)")
		os.Exit(1)
	}
	hub := relay.NewHub(mateKeys, origins...)
	switch {
	case vapidPublicKey != "" && vapidPrivateKey != "":
		subscriptions, err := relay.OpenSubscriptionStore(envOr("AXON_RELAY_DB_PATH", "axon-relay.db"))
		if err != nil {
			slog.Error("Axon Relay failed to open push subscription store", "error", err)
			os.Exit(1)
		}
		defer subscriptions.Close()
		hub.EnablePush(subscriptions, vapidPublicKey, vapidPrivateKey)
	case vapidPublicKey != "" || vapidPrivateKey != "":
		slog.Warn("AXON_RELAY_VAPID_PUBLIC_KEY and AXON_RELAY_VAPID_PRIVATE_KEY must both be set; push notifications disabled")
	}
	metricsAddr := envOr("AXON_RELAY_METRICS_ADDR", "127.0.0.1:9090")
	metricsServer := &http.Server{
		Addr: metricsAddr, Handler: promhttp.Handler(),
		ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 70 * time.Second,
	}
	go func() {
		slog.Info("Axon Relay metrics listening", "address", metricsAddr)
		if err := metricsServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("Axon Relay metrics server stopped", "error", err)
		}
	}()

	server := &http.Server{
		Addr: addr, Handler: hub,
		ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 70 * time.Second,
	}
	slog.Info("Axon Relay listening", "address", addr, "mates", len(mateKeys))
	if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		slog.Error("Axon Relay stopped", "error", err)
		os.Exit(1)
	}
}

// parseMateKeys reads AXON_RELAY_MATE_KEYS, formatted as comma-separated
// "mate_id=base64url-ed25519-public-key" pairs (the same base64url
// encoding mesh-axon prints for its identity -- see
// security.PublicKeyString). The relay has no other way to learn a
// mate's public key: it never stores credentials itself, so every mate
// that will connect must be provisioned here by an operator. This is a
// required step when upgrading to scoped relay tokens -- see
// docs/IMPLEMENTATION_STATUS.md.
func parseMateKeys(value string) (map[string]ed25519.PublicKey, error) {
	keys := make(map[string]ed25519.PublicKey)
	for _, pair := range splitNonEmpty(value) {
		mateID, encoded, found := strings.Cut(pair, "=")
		if !found || mateID == "" || encoded == "" {
			return nil, fmt.Errorf("invalid AXON_RELAY_MATE_KEYS entry %q, want mate_id=base64url-key", pair)
		}
		decoded, err := base64.RawURLEncoding.DecodeString(encoded)
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("invalid public key for mate %q in AXON_RELAY_MATE_KEYS", mateID)
		}
		keys[mateID] = ed25519.PublicKey(decoded)
	}
	return keys, nil
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
