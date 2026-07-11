// Package session provides secure, signed cookie sessions for browser apps,
// standard library only.
//
// The MVP is cookie-only: the whole session lives in an HMAC-SHA256 signed
// cookie, so there is no server-side store to run. It is thin and
// cryptographically conservative, and is a companion to token-based auth, not a
// replacement: session owns cookie and browser state, while an auth package
// owns subjects, passwords and tokens.
//
// # Manager
//
//	m := session.New(secret,
//	    session.WithName("sid"),
//	    session.WithSecure(true),                 // HTTPS only in production
//	    session.WithSameSite(http.SameSiteLaxMode),
//	    session.WithTTL(24*time.Hour),
//	)
//
// # Reading and writing
//
//	s := m.LoadOrNew(r)          // existing session, or a fresh one
//	s.Set("theme", "dark")
//	err := m.Save(w, s)          // sign and set the cookie
//	m.Destroy(w)                 // clear the cookie on logout
//
// Load returns ErrNoSession when there is no cookie; LoadOrNew handles that for
// the common "start a session in this handler" case. With the middleware,
// handlers read the session from the context and persist changes explicitly:
//
//	http.Handle("/", m.Middleware(handler))
//	// inside handler:
//	s, _ := session.From(r.Context())
//	s.Set("seen", "1")
//	_ = m.Save(w, s)
//
// # Security
//
// The cookie is HttpOnly, SameSite=Lax and signed with HMAC-SHA256. Enable
// Secure in production. The payload is versioned so the format can evolve
// without breaking old cookies. Key rotation is built in: the primary key signs
// and any configured key (WithKey) verifies, so you can roll keys without
// invalidating live sessions.
//
// # Scope
//
// The MVP does not include a server-side store, encrypted payloads or CSRF;
// those are planned. It does not do user management, password hashing or OAuth.
//
// See DOC.md (English) and DOC.UK.md (Ukrainian) for the full reference.
package session
