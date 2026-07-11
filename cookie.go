package session

import (
	"net/http"
	"time"
)

// defaults for the session cookie and lifetime.
const (
	defaultName = "session"
	defaultPath = "/"
	defaultTTL  = 24 * time.Hour
	// maxCookieSize is the conservative per-cookie byte budget (browsers cap
	// around 4 KB including name and attributes).
	maxCookieSize = 4000
)

// cookieConfig holds the cookie attributes. HttpOnly is always set.
type cookieConfig struct {
	name     string
	domain   string
	path     string
	secure   bool
	sameSite http.SameSite
}

// Option configures a Manager.
type Option func(*Manager)

// WithName sets the cookie name (default "session").
func WithName(name string) Option {
	return func(m *Manager) {
		if name != "" {
			m.cookie.name = name
		}
	}
}

// WithDomain sets the cookie Domain attribute.
func WithDomain(domain string) Option {
	return func(m *Manager) { m.cookie.domain = domain }
}

// WithPath sets the cookie Path attribute (default "/").
func WithPath(path string) Option {
	return func(m *Manager) {
		if path != "" {
			m.cookie.path = path
		}
	}
}

// WithSecure sets the Secure attribute (send only over HTTPS). It defaults to
// true; pass false only for local HTTP development.
func WithSecure(secure bool) Option {
	return func(m *Manager) { m.cookie.secure = secure }
}

// WithSameSite sets the SameSite attribute (default Lax).
func WithSameSite(mode http.SameSite) Option {
	return func(m *Manager) { m.cookie.sameSite = mode }
}

// WithTTL sets the session lifetime (default 24h).
func WithTTL(d time.Duration) Option {
	return func(m *Manager) {
		if d > 0 {
			m.ttl = d
		}
	}
}

// WithKey adds another key for verification, enabling key rotation: the primary
// key (passed to New) signs, any configured key verifies.
func WithKey(key []byte) Option {
	return func(m *Manager) {
		if len(key) > 0 {
			m.keys = append(m.keys, key)
		}
	}
}

// WithClock overrides the time source (for testing).
func WithClock(now func() time.Time) Option {
	return func(m *Manager) { m.now = now }
}
