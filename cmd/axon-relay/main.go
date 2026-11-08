package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/SteerMesh/axon/internal/relay"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"golang.org/x/time/rate"
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

	rateLimitConfig := rateLimitConfigFromEnv()
	server := &http.Server{
		Addr: addr, Handler: relay.WithRateLimit(hub, rateLimitConfig),
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

// rateLimitConfigFromEnv reads the four rate-limiting tunables, falling
// back to relay.DefaultRateLimitConfig()'s provisional defaults (burst 5 /
// 10 per minute on /v1/connect, burst 10 / 20 per minute on
// /v1/push/subscribe) for any unset or invalid value. The *_RATE_LIMIT vars
// are expressed as sustained requests per minute (not raw rate.Limit, which
// is per second) because that is the unit the design doc and this file's
// own defaults are specified in -- easier for an operator tuning these
// against axon_relay_rate_limited_total to reason about.
func rateLimitConfigFromEnv() relay.RateLimitConfig {
	cfg := relay.DefaultRateLimitConfig()
	if perMinute, ok := envPositiveInt("AXON_RELAY_CONNECT_RATE_LIMIT"); ok {
		cfg.ConnectLimit = rate.Limit(float64(perMinute) / 60.0)
	}
	if burst, ok := envPositiveInt("AXON_RELAY_CONNECT_RATE_BURST"); ok {
		cfg.ConnectBurst = burst
	}
	if perMinute, ok := envPositiveInt("AXON_RELAY_PUSH_RATE_LIMIT"); ok {
		cfg.PushSubscribeLimit = rate.Limit(float64(perMinute) / 60.0)
	}
	if burst, ok := envPositiveInt("AXON_RELAY_PUSH_RATE_BURST"); ok {
		cfg.PushSubscribeBurst = burst
	}
	return cfg
}

// envPositiveInt reads key as a positive integer. It reports ok=false (and
// logs a warning) for an unset, non-numeric, or non-positive value, so
// callers can fall back to their own default without needing their own
// validation.
func envPositiveInt(key string) (int, bool) {
	raw := os.Getenv(key)
	if raw == "" {
		return 0, false
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value <= 0 {
		slog.Warn("Axon Relay ignoring invalid env var, using default", "key", key, "value", raw)
		return 0, false
	}
	return value, true
}
