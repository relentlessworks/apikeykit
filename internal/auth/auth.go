package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/smtp"
	"strings"
	"time"

	"github.com/relentlessworks/apikeykit/internal/model"
	"github.com/relentlessworks/apikeykit/internal/store"
)

// Auth handles OTP-based authentication.
type Auth struct {
	store  *store.Store
	secret string
	smtp   string
}

// New creates a new auth handler.
func New(s *store.Store, secret, smtpHost string) *Auth {
	return &Auth{
		store:  s,
		secret: secret,
		smtp:   smtpHost,
	}
}

// RequestOTP generates and sends an OTP to the given email.
func (a *Auth) RequestOTP(email string) error {
	code := model.GenerateOTPCode()
	otp := model.OTP{
		Email:     email,
		Code:      code,
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}
	if err := a.store.SaveOTP(otp); err != nil {
		return err
	}

	if a.smtp == "" {
		log.Printf("[DEV] OTP for %s: %s", email, code)
		return nil
	}

	return a.sendEmail(email, fmt.Sprintf("Your APIKeyKit verification code is: %s\n\nThis code expires in 10 minutes.", code))
}

// VerifyOTP validates the OTP and returns a bearer token.
func (a *Auth) VerifyOTP(email, code string) (string, error) {
	otp, ok := a.store.GetOTP(email, code)
	if !ok {
		return "", fmt.Errorf("invalid or expired OTP code")
	}

	// Create or find workspace for this email
	wsHandle := generateWorkspaceHandle(email)
	ws, ok := a.store.GetWorkspace(wsHandle)
	if !ok {
		newWs := model.Workspace{
			Handle:    wsHandle,
			Name:      email,
			Plan:      model.PlanFree,
			CreatedAt: time.Now(),
		}
		a.store.CreateWorkspace(newWs)
		ws = &newWs
	}

	token := model.GenerateToken()
	t := model.Token{
		Token:     token,
		Email:     email,
		Workspace: ws.Handle,
		ExpiresAt: time.Now().Add(365 * 24 * time.Hour),
	}
	if err := a.store.SaveToken(t); err != nil {
		return "", err
	}

	a.store.DeleteOTP(otp.Email)

	return token, nil
}

// ValidateToken checks if a bearer token is valid and returns the associated token info.
func (a *Auth) ValidateToken(token string) (*model.Token, bool) {
	return a.store.GetToken(token)
}

// HashSecret hashes a key secret using SHA-256.
func HashSecret(secret string) string {
	h := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(h[:])
}

// VerifySecret checks if a plaintext secret matches a hash.
func VerifySecret(secret, hash string) bool {
	return HashSecret(secret) == hash
}

func (a *Auth) sendEmail(to, body string) error {
	from := "noreply@apikeykit.local"
	msg := fmt.Sprintf("From: %s\r\nTo: %s\r\nSubject: APIKeyKit Verification Code\r\n\r\n%s", from, to, body)
	return smtp.SendMail(a.smtp, nil, from, []string{to}, []byte(msg))
}

// generateWorkspaceHandle creates a workspace handle from an email.
func generateWorkspaceHandle(email string) string {
	// Use first 5 chars of the local part, sanitized
	local := email
	if idx := strings.Index(email, "@"); idx > 0 {
		local = email[:idx]
	}
	local = strings.ToLower(local)
	// Keep only alphanumeric
	var b strings.Builder
	for _, c := range local {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') {
			b.WriteRune(c)
		}
	}
	s := b.String()
	if len(s) > 5 {
		s = s[:5]
	}
	for len(s) < 3 {
		s += "x"
	}
	return "ws_" + s
}
