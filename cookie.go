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
	// cookieAttrOverhead is a fixed byte allowance for the Set-Cookie
	// attributes whose text is not otherwise counted (Expires, Max-Age,
	// Secure, HttpOnly, SameSite and their "; key=" separators), so the size
	// check reflects the real on-the-wire header, not just value+name+path.
	cookieAttrOverhead = 110
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

// WithName sets the cookie name (default "session"). It panics on a name that
// is not a valid cookie token (RFC 6265): an invalid name makes net/http emit
// an empty Set-Cookie header, silently dropping the session, so it must fail at
// startup like a weak key.
func WithName(name string) Option {
	return func(m *Manager) {
		if name == "" {
			return
		}
		if !isValidCookieName(name) {
			panic("session: invalid cookie name " + name)
		}
		m.cookie.name = name
	}
}

// isValidCookieName reports whether name is a valid RFC 6265 cookie token: a
// non-empty string of printable ASCII with no separators or control bytes.
func isValidCookieName(name string) bool {
	for i := 0; i < len(name); i++ {
		c := name[i]
		if c <= ' ' || c >= 0x7f {
			return false
		}
		switch c {
		case '(', ')', '<', '>', '@', ',', ';', ':', '\\', '"',
			'/', '[', ']', '?', '=', '{', '}':
			return false
		}
	}
	return name != ""
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

// WithAbsoluteTTL caps the total lifetime of a session from its creation,
// independent of activity. The default TTL slides forward on every Save, so an
// active session can live indefinitely; with an absolute TTL a session older
// than CreatedAt+d is rejected on Load even if it was refreshed recently. A
// non-positive duration disables the cap (the default).
func WithAbsoluteTTL(d time.Duration) Option {
	return func(m *Manager) {
		if d > 0 {
			m.absoluteTTL = d
		}
	}
}

// WithKey adds another key for verification, enabling key rotation: the primary
// key (passed to New) signs, any configured key verifies.
func WithKey(key []byte) Option {
	return func(m *Manager) {
		if len(key) > 0 {
			// Copy so the Manager never shares a slice with the caller.
			m.keys = append(m.keys, append([]byte(nil), key...))
		}
	}
}

// WithClock overrides the time source (for testing). A nil function is ignored.
func WithClock(now func() time.Time) Option {
	return func(m *Manager) {
		if now != nil {
			m.now = now
		}
	}
}
