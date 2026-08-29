package api

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/relentlessworks/apikeykit/internal/auth"
	"github.com/relentlessworks/apikeykit/internal/model"
	"github.com/relentlessworks/apikeykit/internal/store"
)

// Handlers holds all HTTP handlers.
type Handlers struct {
	store *store.Store
	auth  *auth.Auth
	mw    *Middleware
	mcp   *MCPHandler
}

// NewHandlers creates a new handlers instance.
func NewHandlers(s *store.Store, a *auth.Auth) *Handlers {
	h := &Handlers{
		store: s,
		auth:  a,
	}
	h.mw = NewMiddleware(a)
	h.mcp = NewMCPHandler(s, a)
	return h
}

// Routes returns the HTTP mux with all routes registered.
func (h *Handlers) Routes() http.Handler {
	mux := http.NewServeMux()

	// Public endpoints
	mux.HandleFunc("/help", h.handleHelp)
	mux.HandleFunc("/.well-known/agent.md", h.handleHelp)
	mux.HandleFunc("/mcp", h.mcp.handleMCP)

	// Auth endpoints
	mux.HandleFunc("/auth/request", h.handleAuthRequest)
	mux.HandleFunc("/auth/verify", h.handleAuthVerify)

	// Protected endpoints
	mux.HandleFunc("/keys", h.mw.RequireAuth(h.handleKeys))
	mux.HandleFunc("/keys/", h.mw.RequireAuth(h.handleKeyDetail))
	mux.HandleFunc("/workspaces", h.mw.RequireAuth(h.handleWorkspaces))
	mux.HandleFunc("/audit", h.mw.RequireAuth(h.handleAudit))

	return mux
}

// --- Help / Self-documenting ---

func (h *Handlers) handleHelp(w http.ResponseWriter, r *http.Request) {
	writeText(w, helpText)
}

const helpText = `apikeykit — Agentic-first API key management service

AUTH:
  POST /auth/request    email=<email>              Request an OTP code (logged to stderr in dev mode)
  POST /auth/verify     email=<email> code=<code>  Verify OTP, get bearer token

KEYS (require Authorization: Bearer <token>):
  POST   /keys          name=<name> scopes=<a,b,c> ttl=<seconds>  Create a new API key (returns secret once)
  GET    /keys          List all keys in your workspace
  GET    /keys/<handle> Get key details
  DELETE /keys/<handle> Revoke and delete a key
  POST   /keys/<handle>/rotate    Rotate key secret (returns new secret once)
  POST   /keys/<handle>/verify    secret=<secret>  Verify a key secret is valid

WORKSPACES (require Authorization: Bearer <token>):
  GET /workspaces   List your workspaces

AUDIT (require Authorization: Bearer <token>):
  GET /audit?limit=20   View audit log (last N entries)

RESPONSES:
  Plain text by default (key=value pairs, one record per line)
  JSON via Accept: application/json or ?format=json

ERRORS:
  error: <message> | hint: <what to do next>

MCP:
  POST /mcp  JSON-RPC 2.0 endpoint for Model Context Protocol

EXAMPLES:
  curl -X POST http://localhost:7700/auth/request -d 'email=agent@example.com'
  curl -X POST http://localhost:7700/auth/verify -d 'email=agent@example.com&code=123456'
  curl -H "Authorization: Bearer <token>" -X POST http://localhost:7700/keys -d 'name=my-api-key&scopes=read,write'
  curl -H "Authorization: Bearer <token>" http://localhost:7700/keys
  curl -H "Authorization: Bearer <token>" -X DELETE http://localhost:7700/keys/key_abc12
  curl -H "Authorization: Bearer <token>" -X POST http://localhost:7700/keys/key_abc12/rotate
  curl -H "Authorization: Bearer <token>" -X POST http://localhost:7700/keys/key_abc12/verify -d 'secret=ak_live_xxx'
`

// --- Auth ---

func (h *Handlers) handleAuthRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed", "use POST")
		return
	}
	email := r.FormValue("email")
	if email == "" {
		writeError(w, r, http.StatusBadRequest, "missing email", "provide email=<your-email> in the request body")
		return
	}
	if err := h.auth.RequestOTP(email); err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to send OTP: "+err.Error(), "check if SMTP is configured, or check stderr for the code in dev mode")
		return
	}
	writeText(w, "ok otp sent to "+email+" | check stderr for the code in dev mode\n")
}

func (h *Handlers) handleAuthVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed", "use POST")
		return
	}
	email := r.FormValue("email")
	code := r.FormValue("code")
	if email == "" || code == "" {
		writeError(w, r, http.StatusBadRequest, "missing email or code", "provide email=<your-email> and code=<6-digit-code> in the request body")
		return
	}
	token, err := h.auth.VerifyOTP(email, code)
	if err != nil {
		writeError(w, r, http.StatusUnauthorized, "invalid or expired OTP", "request a new OTP via POST /auth/request with email=<your-email>")
		return
	}
	writeRecord(w, r, map[string]interface{}{
		"token":     token,
		"hint":      "use this as Authorization: Bearer <token> for all subsequent requests",
	})
}

// --- Keys ---

func (h *Handlers) handleKeys(w http.ResponseWriter, r *http.Request, tok *model.Token) {
	switch r.Method {
	case http.MethodPost:
		h.createKey(w, r, tok)
	case http.MethodGet:
		h.listKeys(w, r, tok)
	default:
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed", "use POST to create or GET to list keys")
	}
}

func (h *Handlers) createKey(w http.ResponseWriter, r *http.Request, tok *model.Token) {
	name := r.FormValue("name")
	if name == "" {
		writeError(w, r, http.StatusBadRequest, "missing name", "provide name=<key-name> in the request body")
		return
	}
	scopes := parseScopes(r.FormValue("scopes"))

	var expiresAt *time.Time
	ttlStr := r.FormValue("ttl")
	if ttlStr != "" {
		ttl, err := strconv.Atoi(ttlStr)
		if err != nil || ttl <= 0 {
			writeError(w, r, http.StatusBadRequest, "invalid ttl", "ttl must be a positive integer (seconds)")
			return
		}
		t := time.Now().Add(time.Duration(ttl) * time.Second)
		expiresAt = &t
	}

	// Check workspace key limit
	if h.store.CountKeys(tok.Workspace) >= model.MaxKeysPerWorkspace() {
		writeError(w, r, http.StatusForbidden, "key limit reached", fmt.Sprintf("free plan allows %d keys per workspace; delete unused keys first", model.MaxKeysPerWorkspace()))
		return
	}

	// Generate key
	prefix := "live"
	secret := model.GenerateSecret(prefix)
	handle := model.GenerateHandle("key")

	key := model.APIKey{
		Handle:       handle,
		WorkspaceHdl: tok.Workspace,
		Name:         name,
		Prefix:       prefix,
		SecretHash:   auth.HashSecret(secret),
		Scopes:       scopes,
		Status:       model.StatusActive,
		CreatedAt:    time.Now(),
		ExpiresAt:    expiresAt,
	}

	if err := h.store.CreateKey(key); err != nil {
		writeError(w, r, http.StatusInternalServerError, "failed to create key", err.Error())
		return
	}

	// Audit log
	h.store.AddAudit(model.AuditEntry{
		ID:           model.GenerateHandle("aud"),
		WorkspaceHdl: tok.Workspace,
		Action:       "key.create",
		Actor:        tok.Email,
		Target:       handle,
		Timestamp:    time.Now(),
	})

	// Return key with secret (only time secret is shown)
	writeRecord(w, r, map[string]interface{}{
		"handle":  handle,
		"secret":  secret,
		"name":    name,
		"scopes":  scopes,
		"status":  model.StatusActive,
		"warning": "save the secret now — it will not be shown again",
	})
}

func (h *Handlers) listKeys(w http.ResponseWriter, r *http.Request, tok *model.Token) {
	keys := h.store.ListKeys(tok.Workspace)
	var records []map[string]interface{}
	for _, k := range keys {
		records = append(records, map[string]interface{}{
			"handle": k.Handle,
			"name":   k.Name,
			"prefix": k.Prefix,
			"scopes": k.Scopes,
			"status": k.Status,
		})
	}
	if len(records) == 0 {
		writeText(w, "no keys found | hint: create one with POST /keys name=<name> scopes=<a,b>\n")
		return
	}
	writeRecords(w, r, records)
}

func (h *Handlers) handleKeyDetail(w http.ResponseWriter, r *http.Request, tok *model.Token) {
	// Parse path: /keys/<handle> or /keys/<handle>/rotate or /keys/<handle>/verify
	path := strings.TrimPrefix(r.URL.Path, "/keys/")
	parts := strings.Split(path, "/")
	if len(parts) == 0 || parts[0] == "" {
		writeError(w, r, http.StatusBadRequest, "missing key handle", "use /keys/<handle> to get key details")
		return
	}
	handle := parts[0]

	key, ok := h.store.GetKey(handle)
	if !ok {
		writeError(w, r, http.StatusNotFound, "key not found", "call GET /keys to list all keys in your workspace")
		return
	}

	if key.WorkspaceHdl != tok.Workspace {
		writeError(w, r, http.StatusNotFound, "key not found", "this key does not belong to your workspace")
		return
	}

	if len(parts) == 1 {
		// GET /keys/<handle> or DELETE /keys/<handle>
		switch r.Method {
		case http.MethodGet:
			record := map[string]interface{}{
				"handle":  key.Handle,
				"name":     key.Name,
				"prefix":   key.Prefix,
				"scopes":   key.Scopes,
				"status":   key.Status,
				"created":  key.CreatedAt.Format(time.RFC3339),
			}
			if key.ExpiresAt != nil {
				record["expires"] = key.ExpiresAt.Format(time.RFC3339)
			}
			if key.LastUsedAt != nil {
				record["last_used"] = key.LastUsedAt.Format(time.RFC3339)
			}
			if key.RotatedAt != nil {
				record["rotated"] = key.RotatedAt.Format(time.RFC3339)
			}
			writeRecord(w, r, record)
		case http.MethodDelete:
			h.store.DeleteKey(handle)
			h.store.AddAudit(model.AuditEntry{
				ID:           model.GenerateHandle("aud"),
				WorkspaceHdl: tok.Workspace,
				Action:       "key.delete",
				Actor:        tok.Email,
				Target:       handle,
				Timestamp:    time.Now(),
			})
			writeText(w, "ok key "+handle+" deleted\n")
		default:
			writeError(w, r, http.StatusMethodNotAllowed, "method not allowed", "use GET for details or DELETE to revoke")
		}
		return
	}

	// /keys/<handle>/rotate or /keys/<handle>/verify
	action := parts[1]
	switch action {
	case "rotate":
		if r.Method != http.MethodPost {
			writeError(w, r, http.StatusMethodNotAllowed, "method not allowed", "use POST /keys/<handle>/rotate")
			return
		}
		if key.Status != model.StatusActive {
			writeError(w, r, http.StatusBadRequest, "key is not active", "only active keys can be rotated")
			return
		}
		newSecret := model.GenerateSecret(key.Prefix)
		key.SecretHash = auth.HashSecret(newSecret)
		now := time.Now()
		key.RotatedAt = &now
		h.store.UpdateKey(*key)

		h.store.AddAudit(model.AuditEntry{
			ID:           model.GenerateHandle("aud"),
			WorkspaceHdl: tok.Workspace,
			Action:       "key.rotate",
			Actor:        tok.Email,
			Target:       handle,
			Timestamp:    now,
		})

		writeRecord(w, r, map[string]interface{}{
			"handle":  handle,
			"secret":  newSecret,
			"warning": "save the new secret now — the old one is invalidated",
		})

	case "verify":
		if r.Method != http.MethodPost {
			writeError(w, r, http.StatusMethodNotAllowed, "method not allowed", "use POST /keys/<handle>/verify with secret=<secret>")
			return
		}
		secret := r.FormValue("secret")
		if secret == "" {
			writeError(w, r, http.StatusBadRequest, "missing secret", "provide secret=<your-api-key-secret> in the request body")
			return
		}

		valid := auth.VerifySecret(secret, key.SecretHash)
		result := map[string]interface{}{
			"handle":  key.Handle,
			"valid":   valid,
		}

		if valid {
			result["name"] = key.Name
			result["scopes"] = key.Scopes
			result["status"] = key.Status

			// Check expiry
			if key.ExpiresAt != nil && time.Now().After(*key.ExpiresAt) {
				result["valid"] = false
				result["reason"] = "expired"
			} else {
				// Update last used
				now := time.Now()
				key.LastUsedAt = &now
				h.store.UpdateKey(*key)
			}
		}

		h.store.AddAudit(model.AuditEntry{
			ID:           model.GenerateHandle("aud"),
			WorkspaceHdl: tok.Workspace,
			Action:       "key.verify",
			Actor:        tok.Email,
			Target:       handle,
			Timestamp:    time.Now(),
			Metadata:     fmt.Sprintf("valid=%v", valid),
		})

		writeRecord(w, r, result)

	default:
		writeError(w, r, http.StatusBadRequest, "unknown action", "use /keys/<handle>/rotate or /keys/<handle>/verify")
	}
}

// --- Workspaces ---

func (h *Handlers) handleWorkspaces(w http.ResponseWriter, r *http.Request, tok *model.Token) {
	if r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed", "use GET /workspaces")
		return
	}
	workspaces := h.store.ListWorkspaces()
	var records []map[string]interface{}
	for _, ws := range workspaces {
		if ws.Handle == tok.Workspace {
			records = append(records, map[string]interface{}{
				"handle": ws.Handle,
				"name":   ws.Name,
				"plan":   ws.Plan,
				"keys":   h.store.CountKeys(ws.Handle),
			})
		}
	}
	if len(records) == 0 {
		writeText(w, "no workspaces found\n")
		return
	}
	writeRecords(w, r, records)
}

// --- Audit ---

func (h *Handlers) handleAudit(w http.ResponseWriter, r *http.Request, tok *model.Token) {
	if r.Method != http.MethodGet {
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed", "use GET /audit?limit=20")
		return
	}
	limit := 20
	if l := r.URL.Query().Get("limit"); l != "" {
		if v, err := strconv.Atoi(l); err == nil && v > 0 {
			limit = v
		}
	}
	entries := h.store.ListAudit(tok.Workspace, limit)
	var records []map[string]interface{}
	for _, e := range entries {
		rec := map[string]interface{}{
			"id":        e.ID,
			"action":    e.Action,
			"actor":     e.Actor,
			"target":    e.Target,
			"timestamp": e.Timestamp.Format(time.RFC3339),
		}
		if e.Metadata != "" {
			rec["meta"] = e.Metadata
		}
		records = append(records, rec)
	}
	if len(records) == 0 {
		writeText(w, "no audit entries found\n")
		return
	}
	writeRecords(w, r, records)
}
