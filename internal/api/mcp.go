package api

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/relentlessworks/apikeykit/internal/auth"
	"github.com/relentlessworks/apikeykit/internal/model"
	"github.com/relentlessworks/apikeykit/internal/store"
)

// MCPHandler handles Model Context Protocol JSON-RPC 2.0 requests.
type MCPHandler struct {
	store *store.Store
	auth  *auth.Auth
}

// NewMCPHandler creates a new MCP handler.
func NewMCPHandler(s *store.Store, a *auth.Auth) *MCPHandler {
	return &MCPHandler{store: s, auth: a}
}

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *rpcError   `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

func (h *MCPHandler) handleMCP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, r, http.StatusMethodNotAllowed, "method not allowed", "use POST /mcp with JSON-RPC 2.0 body")
		return
	}

	var req jsonRPCRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSONRPCError(w, req.ID, -32700, "parse error")
		return
	}

	switch req.Method {
	case "initialize":
		writeJSONRPCResult(w, req.ID, map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"serverInfo": map[string]string{
				"name":    "apikeykit",
				"version": "0.1.0",
			},
			"capabilities": map[string]interface{}{
				"tools": map[string]interface{}{},
			},
		})

	case "tools/list":
		writeJSONRPCResult(w, req.ID, map[string]interface{}{
			"tools": mcpTools(),
		})

	case "tools/call":
		h.handleToolCall(w, req)

	default:
		writeJSONRPCError(w, req.ID, -32601, "method not found: "+req.Method)
	}
}

func mcpTools() []map[string]interface{} {
	return []map[string]interface{}{
		{
			"name":        "request_otp",
			"description": "Request an OTP code for authentication. The code is logged to stderr in dev mode.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"email": map[string]interface{}{"type": "string", "description": "Email address to send OTP to"},
				},
				"required": []string{"email"},
			},
		},
		{
			"name":        "verify_otp",
			"description": "Verify an OTP code and get a bearer token.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"email": map[string]interface{}{"type": "string"},
					"code":  map[string]interface{}{"type": "string", "description": "6-digit OTP code"},
				},
				"required": []string{"email", "code"},
			},
		},
		{
			"name":        "create_key",
			"description": "Create a new API key. Returns the secret once — save it immediately.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"token":  map[string]interface{}{"type": "string", "description": "Bearer token from verify_otp"},
					"name":   map[string]interface{}{"type": "string"},
					"scopes": map[string]interface{}{"type": "string", "description": "Comma-separated scopes (e.g. read,write)"},
					"ttl":    map[string]interface{}{"type": "integer", "description": "TTL in seconds (optional)"},
				},
				"required": []string{"token", "name"},
			},
		},
		{
			"name":        "list_keys",
			"description": "List all API keys in your workspace.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"token": map[string]interface{}{"type": "string", "description": "Bearer token"},
				},
				"required": []string{"token"},
			},
		},
		{
			"name":        "get_key",
			"description": "Get details of a specific API key.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"token":  map[string]interface{}{"type": "string"},
					"handle": map[string]interface{}{"type": "string", "description": "Key handle (e.g. key_abc12)"},
				},
				"required": []string{"token", "handle"},
			},
		},
		{
			"name":        "delete_key",
			"description": "Revoke and delete an API key.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"token":  map[string]interface{}{"type": "string"},
					"handle": map[string]interface{}{"type": "string"},
				},
				"required": []string{"token", "handle"},
			},
		},
		{
			"name":        "rotate_key",
			"description": "Rotate an API key's secret. Returns the new secret once.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"token":  map[string]interface{}{"type": "string"},
					"handle": map[string]interface{}{"type": "string"},
				},
				"required": []string{"token", "handle"},
			},
		},
		{
			"name":        "verify_key",
			"description": "Verify an API key secret is valid. Checks status, expiry, and hash.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"token":   map[string]interface{}{"type": "string"},
					"handle":  map[string]interface{}{"type": "string"},
					"secret":  map[string]interface{}{"type": "string", "description": "The API key secret to verify"},
				},
				"required": []string{"token", "handle", "secret"},
			},
		},
		{
			"name":        "list_audit",
			"description": "View the audit log for your workspace.",
			"inputSchema": map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"token": map[string]interface{}{"type": "string"},
					"limit": map[string]interface{}{"type": "integer", "description": "Number of entries (default 20)"},
				},
				"required": []string{"token"},
			},
		},
	}
}

func (h *MCPHandler) handleToolCall(w http.ResponseWriter, req jsonRPCRequest) {
	var params struct {
		Name      string            `json:"name"`
		Arguments map[string]string `json:"arguments"`
	}
	if err := json.Unmarshal(req.Params, &params); err != nil {
		writeJSONRPCError(w, req.ID, -32602, "invalid params")
		return
	}

	switch params.Name {
	case "request_otp":
		email := params.Arguments["email"]
		if email == "" {
			writeJSONRPCError(w, req.ID, -32602, "missing email")
			return
		}
		if err := h.auth.RequestOTP(email); err != nil {
			writeJSONRPCError(w, req.ID, -32603, err.Error())
			return
		}
		writeJSONRPCResult(w, req.ID, map[string]string{"status": "ok", "message": "OTP sent (check stderr in dev mode)"})

	case "verify_otp":
		email := params.Arguments["email"]
		code := params.Arguments["code"]
		token, err := h.auth.VerifyOTP(email, code)
		if err != nil {
			writeJSONRPCError(w, req.ID, -32603, err.Error())
			return
		}
		writeJSONRPCResult(w, req.ID, map[string]string{"token": token})

	case "create_key":
		tok, ok := h.validateToken(params.Arguments["token"])
		if !ok {
			writeJSONRPCError(w, req.ID, -32603, "invalid or expired token")
			return
		}
		name := params.Arguments["name"]
		if name == "" {
			writeJSONRPCError(w, req.ID, -32602, "missing name")
			return
		}
		scopes := parseScopes(params.Arguments["scopes"])
		secret := model.GenerateSecret("live")
		handle := model.GenerateHandle("key")
		key := model.APIKey{
			Handle:       handle,
			WorkspaceHdl: tok.Workspace,
			Name:         name,
			Prefix:       "live",
			SecretHash:   auth.HashSecret(secret),
			Scopes:       scopes,
			Status:       model.StatusActive,
			CreatedAt:    time.Now(),
		}
		h.store.CreateKey(key)
		h.store.AddAudit(model.AuditEntry{
			ID:           model.GenerateHandle("aud"),
			WorkspaceHdl: tok.Workspace,
			Action:       "key.create",
			Actor:        tok.Email,
			Target:       handle,
			Timestamp:    time.Now(),
		})
		writeJSONRPCResult(w, req.ID, map[string]string{"handle": handle, "secret": secret, "warning": "save the secret now"})

	case "list_keys":
		tok, ok := h.validateToken(params.Arguments["token"])
		if !ok {
			writeJSONRPCError(w, req.ID, -32603, "invalid or expired token")
			return
		}
		keys := h.store.ListKeys(tok.Workspace)
		var out []map[string]string
		for _, k := range keys {
			out = append(out, map[string]string{
				"handle": k.Handle,
				"name":   k.Name,
				"prefix": k.Prefix,
				"status": k.Status,
			})
		}
		writeJSONRPCResult(w, req.ID, map[string]interface{}{"keys": out})

	case "get_key":
		tok, ok := h.validateToken(params.Arguments["token"])
		if !ok {
			writeJSONRPCError(w, req.ID, -32603, "invalid or expired token")
			return
		}
		key, exists := h.store.GetKey(params.Arguments["handle"])
		if !exists || key.WorkspaceHdl != tok.Workspace {
			writeJSONRPCError(w, req.ID, -32603, "key not found")
			return
		}
		writeJSONRPCResult(w, req.ID, map[string]string{
			"handle":  key.Handle,
			"name":    key.Name,
			"prefix":  key.Prefix,
			"status":  key.Status,
		})

	case "delete_key":
		tok, ok := h.validateToken(params.Arguments["token"])
		if !ok {
			writeJSONRPCError(w, req.ID, -32603, "invalid or expired token")
			return
		}
		handle := params.Arguments["handle"]
		key, exists := h.store.GetKey(handle)
		if !exists || key.WorkspaceHdl != tok.Workspace {
			writeJSONRPCError(w, req.ID, -32603, "key not found")
			return
		}
		h.store.DeleteKey(handle)
		h.store.AddAudit(model.AuditEntry{
			ID:           model.GenerateHandle("aud"),
			WorkspaceHdl: tok.Workspace,
			Action:       "key.delete",
			Actor:        tok.Email,
			Target:       handle,
			Timestamp:    time.Now(),
		})
		writeJSONRPCResult(w, req.ID, map[string]string{"status": "deleted", "handle": handle})

	case "rotate_key":
		tok, ok := h.validateToken(params.Arguments["token"])
		if !ok {
			writeJSONRPCError(w, req.ID, -32603, "invalid or expired token")
			return
		}
		handle := params.Arguments["handle"]
		key, exists := h.store.GetKey(handle)
		if !exists || key.WorkspaceHdl != tok.Workspace {
			writeJSONRPCError(w, req.ID, -32603, "key not found")
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
		writeJSONRPCResult(w, req.ID, map[string]string{"handle": handle, "secret": newSecret, "warning": "save the new secret now"})

	case "verify_key":
		tok, ok := h.validateToken(params.Arguments["token"])
		if !ok {
			writeJSONRPCError(w, req.ID, -32603, "invalid or expired token")
			return
		}
		handle := params.Arguments["handle"]
		secret := params.Arguments["secret"]
		key, exists := h.store.GetKey(handle)
		if !exists || key.WorkspaceHdl != tok.Workspace {
			writeJSONRPCError(w, req.ID, -32603, "key not found")
			return
		}
		valid := auth.VerifySecret(secret, key.SecretHash)
		writeJSONRPCResult(w, req.ID, map[string]interface{}{"valid": valid, "handle": handle})

	case "list_audit":
		tok, ok := h.validateToken(params.Arguments["token"])
		if !ok {
			writeJSONRPCError(w, req.ID, -32603, "invalid or expired token")
			return
		}
		limit := 20
		if l := params.Arguments["limit"]; l != "" {
			if v, err := strconv.Atoi(l); err == nil && v > 0 {
				limit = v
			}
		}
		entries := h.store.ListAudit(tok.Workspace, limit)
		var out []map[string]string
		for _, e := range entries {
			out = append(out, map[string]string{
				"action":    e.Action,
				"actor":     e.Actor,
				"target":    e.Target,
				"timestamp": e.Timestamp.Format("2006-01-02T15:04:05Z07:00"),
			})
		}
		writeJSONRPCResult(w, req.ID, map[string]interface{}{"entries": out})

	default:
		writeJSONRPCError(w, req.ID, -32601, "unknown tool: "+params.Name)
	}
}

func (h *MCPHandler) validateToken(token string) (*model.Token, bool) {
	return h.auth.ValidateToken(token)
}

func writeJSONRPCResult(w http.ResponseWriter, id interface{}, result interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	})
}

func writeJSONRPCError(w http.ResponseWriter, id interface{}, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error: &rpcError{
			Code:    code,
			Message: msg,
		},
	})
}
