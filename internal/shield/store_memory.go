package shield

import (
	"context"
	"sync"
	"time"
)

// MemoryStore is a thread-safe in-memory Store for unit tests and for
// callers that don't need durability. Not for production use; sessions
// vanish on restart.
type MemoryStore struct {
	mu       sync.Mutex
	sessions map[string]time.Time           // id -> expiresAt
	tokens   map[string]memoryToken         // token -> row
	bySess   map[string]map[string]struct{} // sessionID -> set of tokens
}

type memoryToken struct {
	sessionID  string
	kind       string
	hint       string
	ciphertext string
}

// NewMemoryStore returns an empty MemoryStore.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		sessions: make(map[string]time.Time),
		tokens:   make(map[string]memoryToken),
		bySess:   make(map[string]map[string]struct{}),
	}
}

func (m *MemoryStore) InsertSession(_ context.Context, id string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.sessions[id] = expiresAt
	return nil
}

func (m *MemoryStore) GetSession(_ context.Context, id string) (time.Time, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.sessions[id]
	return t, ok, nil
}

func (m *MemoryStore) UpdateSessionExpiry(_ context.Context, id string, expiresAt time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.sessions[id]; ok {
		m.sessions[id] = expiresAt
	}
	return nil
}

func (m *MemoryStore) SweepExpiredSessions(_ context.Context, before time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, exp := range m.sessions {
		if exp.Before(before) {
			delete(m.sessions, id)
			for tok := range m.bySess[id] {
				delete(m.tokens, tok)
			}
			delete(m.bySess, id)
		}
	}
	return nil
}

func (m *MemoryStore) InsertToken(_ context.Context, sessionID, token, kind, hint, ciphertext string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	// Idempotent on (token, session_id): a repeat tokenize of the
	// same value (deterministic id) returns the existing row.
	if existing, ok := m.tokens[token]; ok && existing.sessionID == sessionID {
		return nil
	}
	m.tokens[token] = memoryToken{sessionID: sessionID, kind: kind, hint: hint, ciphertext: ciphertext}
	if m.bySess[sessionID] == nil {
		m.bySess[sessionID] = make(map[string]struct{})
	}
	m.bySess[sessionID][token] = struct{}{}
	return nil
}

func (m *MemoryStore) GetTokenCiphertext(_ context.Context, sessionID, token string) (string, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	row, ok := m.tokens[token]
	if !ok || row.sessionID != sessionID {
		return "", false, nil
	}
	return row.ciphertext, true, nil
}
