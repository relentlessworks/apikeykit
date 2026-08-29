package store

import (
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/relentlessworks/apikeykit/internal/model"
)

// Store is a JSON file-backed data store.
type Store struct {
	mu   sync.RWMutex
	path string
	data *dbData
}

type dbData struct {
	Workspaces []model.Workspace `json:"workspaces"`
	Keys       []model.APIKey    `json:"keys"`
	Audit      []model.AuditEntry `json:"audit"`
	OTPs       []model.OTP       `json:"otps"`
	Tokens     []model.Token     `json:"tokens"`
}

// New creates a new store backed by a JSON file.
func New(path string) (*Store, error) {
	s := &Store{
		path: path,
		data: &dbData{
			Workspaces: []model.Workspace{},
			Keys:       []model.APIKey{},
			Audit:      []model.AuditEntry{},
			OTPs:       []model.OTP{},
			Tokens:     []model.Token{},
		},
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Store) load() error {
	b, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return s.save()
		}
		return err
	}
	if len(b) == 0 {
		return s.save()
	}
	return json.Unmarshal(b, s.data)
}

func (s *Store) save() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	b, err := json.MarshalIndent(s.data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(s.path, b, 0644)
}

// --- Workspace operations ---

func (s *Store) CreateWorkspace(w model.Workspace) error {
	s.mu.Lock()
	s.data.Workspaces = append(s.data.Workspaces, w)
	s.mu.Unlock()
	return s.save()
}

func (s *Store) GetWorkspace(handle string) (*model.Workspace, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.data.Workspaces {
		if s.data.Workspaces[i].Handle == handle {
			return &s.data.Workspaces[i], true
		}
	}
	return nil, false
}

func (s *Store) ListWorkspaces() []model.Workspace {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]model.Workspace, len(s.data.Workspaces))
	copy(out, s.data.Workspaces)
	return out
}

// --- API Key operations ---

func (s *Store) CreateKey(k model.APIKey) error {
	s.mu.Lock()
	s.data.Keys = append(s.data.Keys, k)
	s.mu.Unlock()
	return s.save()
}

func (s *Store) GetKey(handle string) (*model.APIKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.data.Keys {
		if s.data.Keys[i].Handle == handle {
			return &s.data.Keys[i], true
		}
	}
	return nil, false
}

func (s *Store) ListKeys(workspace string) []model.APIKey {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []model.APIKey
	for _, k := range s.data.Keys {
		if k.WorkspaceHdl == workspace {
			out = append(out, k)
		}
	}
	return out
}

func (s *Store) CountKeys(workspace string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	count := 0
	for _, k := range s.data.Keys {
		if k.WorkspaceHdl == workspace {
			count++
		}
	}
	return count
}

func (s *Store) UpdateKey(k model.APIKey) error {
	s.mu.Lock()
	for i := range s.data.Keys {
		if s.data.Keys[i].Handle == k.Handle {
			s.data.Keys[i] = k
			break
		}
	}
	s.mu.Unlock()
	return s.save()
}

func (s *Store) DeleteKey(handle string) error {
	s.mu.Lock()
	for i, k := range s.data.Keys {
		if k.Handle == handle {
			s.data.Keys = append(s.data.Keys[:i], s.data.Keys[i+1:]...)
			break
		}
	}
	s.mu.Unlock()
	return s.save()
}

// --- OTP operations ---

func (s *Store) SaveOTP(otp model.OTP) error {
	s.mu.Lock()
	// Remove any existing OTP for this email
	var filtered []model.OTP
	for _, o := range s.data.OTPs {
		if o.Email != otp.Email {
			filtered = append(filtered, o)
		}
	}
	filtered = append(filtered, otp)
	s.data.OTPs = filtered
	s.mu.Unlock()
	return s.save()
}

func (s *Store) GetOTP(email, code string) (*model.OTP, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.data.OTPs {
		if s.data.OTPs[i].Email == email && s.data.OTPs[i].Code == code {
			if time.Now().Before(s.data.OTPs[i].ExpiresAt) {
				return &s.data.OTPs[i], true
			}
		}
	}
	return nil, false
}

func (s *Store) DeleteOTP(email string) {
	s.mu.Lock()
	var filtered []model.OTP
	for _, o := range s.data.OTPs {
		if o.Email != email {
			filtered = append(filtered, o)
		}
	}
	s.data.OTPs = filtered
	s.mu.Unlock()
	s.save()
}

// --- Token operations ---

func (s *Store) SaveToken(t model.Token) error {
	s.mu.Lock()
	s.data.Tokens = append(s.data.Tokens, t)
	s.mu.Unlock()
	return s.save()
}

func (s *Store) GetToken(token string) (*model.Token, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for i := range s.data.Tokens {
		if s.data.Tokens[i].Token == token {
			if time.Now().Before(s.data.Tokens[i].ExpiresAt) {
				return &s.data.Tokens[i], true
			}
		}
	}
	return nil, false
}

// --- Audit operations ---

func (s *Store) AddAudit(entry model.AuditEntry) error {
	s.mu.Lock()
	s.data.Audit = append(s.data.Audit, entry)
	// Keep last 1000 entries
	if len(s.data.Audit) > 1000 {
		s.data.Audit = s.data.Audit[len(s.data.Audit)-1000:]
	}
	s.mu.Unlock()
	return s.save()
}

func (s *Store) ListAudit(workspace string, limit int) []model.AuditEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []model.AuditEntry
	for _, a := range s.data.Audit {
		if a.WorkspaceHdl == workspace {
			out = append(out, a)
		}
	}
	// Return last N entries in reverse
	if len(out) > limit {
		out = out[len(out)-limit:]
	}
	// Reverse
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}
