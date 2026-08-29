package model

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
)

// Workspace represents a tenant in the system.
type Workspace struct {
	Handle    string    `json:"handle"`
	Name      string    `json:"name"`
	Plan      string    `json:"plan"`
	CreatedAt time.Time `json:"created_at"`
}

// APIKey represents an API key record.
type APIKey struct {
	Handle        string     `json:"handle"`
	WorkspaceHdl  string     `json:"workspace_handle"`
	Name          string     `json:"name"`
	Prefix        string     `json:"prefix"`
	SecretHash    string     `json:"secret_hash"`
	Scopes        []string   `json:"scopes"`
	Status        string     `json:"status"` // active, revoked
	CreatedAt     time.Time  `json:"created_at"`
	ExpiresAt     *time.Time `json:"expires_at,omitempty"`
	LastUsedAt    *time.Time `json:"last_used_at,omitempty"`
	RotatedAt     *time.Time `json:"rotated_at,omitempty"`
}

// AuditEntry represents an audit log entry.
type AuditEntry struct {
	ID             string    `json:"id"`
	WorkspaceHdl   string    `json:"workspace_handle"`
	Action         string    `json:"action"`
	Actor          string    `json:"actor"`
	Target         string    `json:"target"`
	Timestamp      time.Time `json:"timestamp"`
	Metadata       string    `json:"metadata,omitempty"`
}

// OTP represents a one-time password entry.
type OTP struct {
	Email     string    `json:"email"`
	Code      string    `json:"code"`
	ExpiresAt time.Time `json:"expires_at"`
}

// Token represents an auth bearer token.
type Token struct {
	Token     string    `json:"token"`
	Email     string    `json:"email"`
	Workspace string    `json:"workspace"`
	ExpiresAt time.Time `json:"expires_at"`
}

const (
	StatusActive  = "active"
	StatusRevoked = "revoked"
	PlanFree      = "free"
	PlanPro       = "pro"
)

const maxKeysPerWorkspace = 100

// GenerateHandle creates a short stable handle like "key_a1b2c".
func GenerateHandle(prefix string) string {
	b := make([]byte, 3)
	rand.Read(b)
	return fmt.Sprintf("%s_%s", prefix, hex.EncodeToString(b))
}

// GenerateSecret generates a random API key secret.
// Format: prefix + "_" + 32 hex chars (e.g. "ak_live_a1b2c3d4e5f6a7b8")
func GenerateSecret(prefix string) string {
	b := make([]byte, 16)
	rand.Read(b)
	return fmt.Sprintf("ak_%s_%s", prefix, hex.EncodeToString(b))
}

// GenerateToken generates a random bearer token.
func GenerateToken() string {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// GenerateOTPCode generates a 6-digit OTP code.
func GenerateOTPCode() string {
	b := make([]byte, 4)
	rand.Read(b)
	return fmt.Sprintf("%06d", int(b[0])<<8|int(b[1])%1000000)
}

// MaxKeysPerWorkspace returns the max keys allowed per workspace.
func MaxKeysPerWorkspace() int {
	return maxKeysPerWorkspace
}
