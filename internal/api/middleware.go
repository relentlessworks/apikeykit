package api

import (
	"net/http"

	"github.com/relentlessworks/apikeykit/internal/auth"
	"github.com/relentlessworks/apikeykit/internal/model"
)

// Middleware provides auth middleware.
type Middleware struct {
	auth *auth.Auth
}

// NewMiddleware creates a new middleware handler.
func NewMiddleware(a *auth.Auth) *Middleware {
	return &Middleware{auth: a}
}

// RequireAuth wraps a handler that requires authentication.
func (m *Middleware) RequireAuth(next func(w http.ResponseWriter, r *http.Request, tok *model.Token)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr := getBearer(r)
		if tokenStr == "" {
			writeError(w, r, http.StatusUnauthorized, "missing auth token", "call POST /auth/request with email to get an OTP, then POST /auth/verify to get a bearer token")
			return
		}
		tok, ok := m.auth.ValidateToken(tokenStr)
		if !ok {
			writeError(w, r, http.StatusUnauthorized, "invalid or expired token", "call POST /auth/request with email to get a new OTP, then POST /auth/verify")
			return
		}
		next(w, r, tok)
	}
}
