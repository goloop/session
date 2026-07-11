package session

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

var secret = []byte("0123456789abcdef0123456789abcdef")

// roundTrip saves a session on a recorder and loads it back through a request.
func roundTrip(t *testing.T, m *Manager, s *Session) (*Session, error) {
	t.Helper()
	rec := httptest.NewRecorder()
	if err := m.Save(rec, s); err != nil {
		t.Fatalf("save: %v", err)
	}
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	return m.Load(req)
}

func TestSaveLoadRoundTrip(t *testing.T) {
	m := New(secret, WithSecure(true))
	s := &Session{Subject: "user-1"}
	s.Set("theme", "dark")

	got, err := roundTrip(t, m, s)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if got.Subject != "user-1" || got.Get("theme") != "dark" {
		t.Fatalf("session: %+v", got)
	}
	if got.ID == "" {
		t.Fatal("id not assigned")
	}
}

func TestCookieAttributes(t *testing.T) {
	m := New(secret, WithName("sid"), WithSecure(true), WithSameSite(http.SameSiteStrictMode))
	rec := httptest.NewRecorder()
	if err := m.Save(rec, &Session{}); err != nil {
		t.Fatalf("save: %v", err)
	}
	c := rec.Result().Cookies()[0]
	if c.Name != "sid" || !c.HttpOnly || !c.Secure || c.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie attrs: %+v", c)
	}
}

func TestTamperRejected(t *testing.T) {
	m := New(secret)
	rec := httptest.NewRecorder()
	_ = m.Save(rec, &Session{Subject: "user-1"})
	c := rec.Result().Cookies()[0]

	// Flip a character in the payload segment.
	parts := strings.Split(c.Value, ".")
	parts[1] = parts[1][:len(parts[1])-1] + "A"
	c.Value = strings.Join(parts, ".")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(c)
	if _, err := m.Load(req); err != ErrInvalid {
		t.Fatalf("expected ErrInvalid, got %v", err)
	}
}

func TestExpired(t *testing.T) {
	past := func() time.Time { return time.Now().Add(-48 * time.Hour) }
	m := New(secret, WithTTL(time.Hour), WithClock(past))
	rec := httptest.NewRecorder()
	_ = m.Save(rec, &Session{Subject: "user-1"})
	c := rec.Result().Cookies()[0]

	// Load with the real clock: the cookie is long expired.
	m2 := New(secret, WithTTL(time.Hour))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(c)
	if _, err := m2.Load(req); err != ErrExpired {
		t.Fatalf("expected ErrExpired, got %v", err)
	}
}

func TestKeyRotation(t *testing.T) {
	oldKey := []byte("old-key-old-key-old-key-old-key0")
	signer := New(oldKey, WithTTL(time.Hour))
	rec := httptest.NewRecorder()
	_ = signer.Save(rec, &Session{Subject: "user-1"})
	c := rec.Result().Cookies()[0]

	// New primary key; old key still accepted for verification.
	verifier := New(secret, WithKey(oldKey), WithTTL(time.Hour))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(c)
	got, err := verifier.Load(req)
	if err != nil || got.Subject != "user-1" {
		t.Fatalf("rotation load: %+v err=%v", got, err)
	}
}

func TestNoCookie(t *testing.T) {
	m := New(secret)
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if _, err := m.Load(req); err != ErrNoSession {
		t.Fatalf("expected ErrNoSession, got %v", err)
	}
}

func TestDestroy(t *testing.T) {
	m := New(secret, WithName("sid"))
	rec := httptest.NewRecorder()
	m.Destroy(rec)
	c := rec.Result().Cookies()[0]
	if c.Name != "sid" || c.MaxAge != -1 {
		t.Fatalf("destroy cookie: %+v", c)
	}
}

func TestMiddleware(t *testing.T) {
	m := New(secret)
	var loaded bool
	h := m.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, ok := From(r.Context())
		loaded = ok && s != nil
		s.Set("k", "v")
		_ = m.Save(w, s)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if !loaded {
		t.Fatal("middleware did not provide a session")
	}
	if len(rec.Result().Cookies()) == 0 {
		t.Fatal("save did not set a cookie")
	}
}

func TestWeakKeyPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic on short signing key")
		}
	}()
	New([]byte("too-short"))
}

func TestSecureDefault(t *testing.T) {
	m := New(secret)
	rec := httptest.NewRecorder()
	_ = m.Save(rec, &Session{})
	if !rec.Result().Cookies()[0].Secure {
		t.Fatal("Secure should default to true")
	}
}

func TestInboundSizeCapRejected(t *testing.T) {
	m := New(secret, WithName("sid"))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "sid", Value: "v1." + strings.Repeat("A", 5000) + ".x"})
	if _, err := m.Load(req); err != ErrInvalid {
		t.Fatalf("expected ErrInvalid for oversized cookie, got %v", err)
	}
}

func TestRegenerateID(t *testing.T) {
	s := &Session{ID: "old"}
	if err := s.RegenerateID(); err != nil {
		t.Fatalf("regenerate: %v", err)
	}
	if s.ID == "old" || s.ID == "" {
		t.Fatalf("id not regenerated: %q", s.ID)
	}
}

func TestTooLarge(t *testing.T) {
	m := New(secret)
	s := &Session{}
	s.Set("blob", strings.Repeat("x", 5000))
	rec := httptest.NewRecorder()
	if err := m.Save(rec, s); err != ErrTooLarge {
		t.Fatalf("expected ErrTooLarge, got %v", err)
	}
}

func TestLoadOrNew(t *testing.T) {
	m := New(secret)
	// No cookie: a fresh, usable session.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	s := m.LoadOrNew(req)
	if s == nil {
		t.Fatal("LoadOrNew returned nil")
	}
	s.Set("k", "v") // must not panic on the lazily-initialised map
	rec := httptest.NewRecorder()
	if err := m.Save(rec, s); err != nil {
		t.Fatalf("save: %v", err)
	}
	// Round-trip: the saved cookie loads back.
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.Header.Set("Cookie", rec.Result().Cookies()[0].String())
	got := m.LoadOrNew(req2)
	if got.Get("k") != "v" {
		t.Fatalf("round-trip lost value: %q", got.Get("k"))
	}
}

func TestExpiryBoundaryExclusive(t *testing.T) {
	exp := time.Now().Add(time.Hour)
	m := New(secret, WithClock(func() time.Time { return exp.Add(-time.Hour) }))
	rec := httptest.NewRecorder()
	s := &Session{}
	if err := m.Save(rec, s); err != nil {
		t.Fatalf("save: %v", err)
	}
	cookie := rec.Result().Cookies()[0]
	// Advance the clock to exactly the cookie's expiry: must be rejected.
	m2 := New(secret, WithClock(func() time.Time { return s.ExpiresAt }))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Cookie", cookie.String())
	if _, err := m2.Load(req); err != ErrExpired {
		t.Fatalf("at expiry = %v, want ErrExpired", err)
	}
}
