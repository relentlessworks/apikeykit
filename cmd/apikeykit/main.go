package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"

	"github.com/relentlessworks/apikeykit/internal/api"
	"github.com/relentlessworks/apikeykit/internal/auth"
	"github.com/relentlessworks/apikeykit/internal/config"
	"github.com/relentlessworks/apikeykit/internal/store"
)

func main() {
	cfg := config.Load()

	// Auto-generate secret if not provided
	secret := cfg.Secret
	if secret == "" {
		b := make([]byte, 32)
		rand.Read(b)
		secret = hex.EncodeToString(b)
		log.Println("[INFO] No secret provided, generated random one for this session")
	}

	// Initialize store
	s, err := store.New(cfg.DB)
	if err != nil {
		log.Fatalf("Failed to initialize store: %v", err)
	}

	// Initialize auth
	a := auth.New(s, secret, cfg.SMTP)

	// Initialize handlers
	h := api.NewHandlers(s, a)

	// Start server
	log.Printf("[INFO] apikeykit listening on %s", cfg.Addr)
	log.Printf("[INFO] database: %s", cfg.DB)
	log.Printf("[INFO] SMTP: %s", smtpStatus(cfg.SMTP))

	srv := &http.Server{
		Addr:    cfg.Addr,
		Handler: h.Routes(),
	}
	if err := srv.ListenAndServe(); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func smtpStatus(smtp string) string {
	if smtp == "" {
		return "not configured (OTP logged to stderr)"
	}
	return fmt.Sprintf("configured (%s)", smtp)
}
