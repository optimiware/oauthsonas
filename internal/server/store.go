package server

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"

	"github.com/ory/fosite"
)

// ttlStore is a small in-memory map whose entries expire after a fixed TTL.
// Entries are checked lazily on access and removed by sweep.
type ttlStore[V any] struct {
	mu  sync.Mutex
	ttl time.Duration
	now func() time.Time
	m   map[string]ttlEntry[V]
}

type ttlEntry[V any] struct {
	value   V
	expires time.Time
}

func newTTLStore[V any](ttl time.Duration) *ttlStore[V] {
	return &ttlStore[V]{ttl: ttl, now: time.Now, m: map[string]ttlEntry[V]{}}
}

// put stores value under a fresh random id.
func (s *ttlStore[V]) put(value V) (string, error) {
	id, err := randomString(32)
	if err != nil {
		return "", err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[id] = ttlEntry[V]{value: value, expires: s.now().Add(s.ttl)}
	return id, nil
}

// get returns the unexpired value for id.
func (s *ttlStore[V]) get(id string) (V, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.lookup(id)
}

// take removes and returns the unexpired value for id, but only when accept
// approves it; a rejected attempt leaves the entry in place.
func (s *ttlStore[V]) take(id string, accept func(V) bool) (V, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	value, ok := s.lookup(id)
	if !ok || !accept(value) {
		var zero V
		return zero, false
	}
	delete(s.m, id)
	return value, true
}

// sweep removes expired entries.
func (s *ttlStore[V]) sweep() {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now()
	for id, entry := range s.m {
		if now.After(entry.expires) {
			delete(s.m, id)
		}
	}
}

func (s *ttlStore[V]) lookup(id string) (V, bool) {
	entry, ok := s.m[id]
	if !ok || !s.now().Before(entry.expires) {
		var zero V
		return zero, false
	}
	return entry.value, true
}

func randomString(bytes int) (string, error) {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// startCleanup periodically drops expired protocol state until Close.
func (s *Server) startCleanup() {
	go func() {
		ticker := time.NewTicker(cleanupInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				s.cleanupStore()
			case <-s.cleanupDone:
				return
			}
		}
	}()
}

// cleanupStore removes expired state. fosite's MemoryStore guards each map
// with unexported locks, so every caller that touches it must hold storeMu.
func (s *Server) cleanupStore() {
	s.interactions.sweep()
	s.gate.sweep()

	s.storeMu.Lock()
	defer s.storeMu.Unlock()
	now := time.Now()
	codeTTL, accessTTL, refreshTTL := s.config.AuthorizationCodeTTL.D(), s.config.TokenTTL.D(), s.config.RefreshTokenTTL.D()
	for id, req := range s.store.AuthorizeCodes {
		if expired(req, fosite.AuthorizeCode, codeTTL, now) {
			delete(s.store.AuthorizeCodes, id)
		}
	}
	for id, req := range s.store.PKCES {
		if expired(req, fosite.AuthorizeCode, codeTTL, now) {
			delete(s.store.PKCES, id)
		}
	}
	for id, req := range s.store.IDSessions {
		if expired(req, fosite.AuthorizeCode, codeTTL, now) {
			delete(s.store.IDSessions, id)
		}
	}
	for id, req := range s.store.AccessTokens {
		if expired(req, fosite.AccessToken, accessTTL, now) {
			delete(s.store.AccessTokens, id)
		}
	}
	for id, req := range s.store.RefreshTokens {
		if expired(req, fosite.RefreshToken, refreshTTL, now) {
			delete(s.store.RefreshTokens, id)
		}
	}
	for requestID, signature := range s.store.AccessTokenRequestIDs {
		if _, ok := s.store.AccessTokens[signature]; !ok {
			delete(s.store.AccessTokenRequestIDs, requestID)
		}
	}
	for requestID, signature := range s.store.RefreshTokenRequestIDs {
		if _, ok := s.store.RefreshTokens[signature]; !ok {
			delete(s.store.RefreshTokenRequestIDs, requestID)
		}
	}
}

// expired reports whether a stored request is past its token's expiry. It
// prefers the session's own expiry, which fosite refreshes on rotation, and
// falls back to the request time plus ttl.
func expired(req fosite.Requester, kind fosite.TokenType, ttl time.Duration, now time.Time) bool {
	if sess := req.GetSession(); sess != nil {
		if at := sess.GetExpiresAt(kind); !at.IsZero() {
			return at.Before(now)
		}
	}
	return req.GetRequestedAt().Add(ttl).Before(now)
}
