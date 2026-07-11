package session

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"time"
)

// minKeyLen is the minimum signing-key length (256-bit) for HMAC-SHA256.
const minKeyLen = 32

// Manager signs, reads and writes session cookies. The MVP is cookie-only: the
// whole session lives in a signed cookie. It is safe for concurrent use.
type Manager struct {
	keys   [][]byte // first signs, all verify (rotation)
	cookie cookieConfig
	ttl    time.Duration
	now    func() time.Time
}

// New creates a Manager with the given signing secret and options. The Secure
// cookie attribute defaults to true; disable it with WithSecure(false) only for
// local HTTP development. New panics if any signing key is shorter than 32
// bytes: a weak key is a configuration error that must fail at startup.
func New(secret []byte, opts ...Option) *Manager {
	m := &Manager{
		keys: [][]byte{secret},
		cookie: cookieConfig{
			name:     defaultName,
			path:     defaultPath,
			secure:   true,
			sameSite: http.SameSiteLaxMode,
		},
		ttl: defaultTTL,
		now: time.Now,
	}
	for _, o := range opts {
		o(m)
	}
	for _, k := range m.keys {
		if len(k) < minKeyLen {
			panic("session: signing key must be at least 32 bytes")
		}
	}
	return m
}

// Load reads and verifies the session cookie from the request.
func (m *Manager) Load(r *http.Request) (*Session, error) {
	c, err := r.Cookie(m.cookie.name)
	if err != nil || c.Value == "" {
		return nil, ErrNoSession
	}
	// Reject an oversized cookie before doing any work on it.
	if len(c.Value)+len(m.cookie.name) > maxCookieSize {
		return nil, ErrInvalid
	}
	payload, err := m.unsign(c.Value)
	if err != nil {
		return nil, err
	}
	var s Session
	if err := json.Unmarshal(payload, &s); err != nil {
		return nil, ErrInvalid
	}
	if !s.ExpiresAt.IsZero() && m.now().After(s.ExpiresAt) {
		return nil, ErrExpired
	}
	return &s, nil
}

// Save writes the session as a signed cookie. It assigns an ID and timestamps
// when missing and refreshes the expiry to now+TTL.
func (m *Manager) Save(w http.ResponseWriter, s *Session) error {
	now := m.now()
	if s.ID == "" {
		id, err := newID()
		if err != nil {
			return err
		}
		s.ID = id
	}
	if s.CreatedAt.IsZero() {
		s.CreatedAt = now
	}
	s.ExpiresAt = now.Add(m.ttl)

	payload, err := json.Marshal(s)
	if err != nil {
		return err
	}
	value := m.sign(payload)
	if len(value)+len(m.cookie.name) > maxCookieSize {
		return ErrTooLarge
	}

	http.SetCookie(w, &http.Cookie{
		Name:     m.cookie.name,
		Value:    value,
		Path:     m.cookie.path,
		Domain:   m.cookie.domain,
		Expires:  s.ExpiresAt,
		MaxAge:   int(m.ttl.Seconds()),
		Secure:   m.cookie.secure,
		HttpOnly: true,
		SameSite: m.cookie.sameSite,
	})
	return nil
}

// Destroy clears the session cookie.
func (m *Manager) Destroy(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     m.cookie.name,
		Value:    "",
		Path:     m.cookie.path,
		Domain:   m.cookie.domain,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
		Secure:   m.cookie.secure,
		HttpOnly: true,
		SameSite: m.cookie.sameSite,
	})
}

// sessionKey is the private context key for the loaded session.
type sessionKey struct{}

// Middleware loads the session into the request context, creating a fresh empty
// session when there is none or it is invalid. Handlers read it with From and
// persist changes with Save.
func (m *Manager) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, err := m.Load(r)
		if err != nil {
			s = &Session{}
		}
		ctx := context.WithValue(r.Context(), sessionKey{}, s)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// From returns the session stored in the context by Middleware.
func From(ctx context.Context) (*Session, bool) {
	s, ok := ctx.Value(sessionKey{}).(*Session)
	return s, ok
}

// newID returns a random session ID.
func newID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// RegenerateID assigns a fresh session ID. Call it right after a privilege
// change (for example a successful login), then Save, to avoid session
// fixation.
func (s *Session) RegenerateID() error {
	id, err := newID()
	if err != nil {
		return err
	}
	s.ID = id
	return nil
}
