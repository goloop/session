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
// The payload is SIGNED, NOT ENCRYPTED. Subject and every value are stored as
// base64(JSON): the client cannot forge them, but can read them. Do not put
// secrets in a session. Encrypted payloads are planned (WithEncryption).
//
// Logout is stateless: Destroy clears the cookie in this response, but a copy
// the client already captured stays valid until its ExpiresAt, because there is
// no server-side store to revoke it. Keep the TTL short, consider
// WithAbsoluteTTL for a hard lifetime cap, and for immediate revocation pair
// this with a server-side denylist of session IDs.
//
// A loaded session is not proof of authentication. Middleware and LoadOrNew
// return a fresh empty session when the cookie is missing or invalid, so a
// successful From does not mean the request is authenticated: check Subject (or
// your own flag) before granting access, or a protected route can fail open.
//
// # Scope
//
// The MVP does not include a server-side store, encrypted payloads or CSRF;
// those are planned. It does not do user management, password hashing or OAuth.
//
// See DOC.md (English) and DOC.UK.md (Ukrainian) for the full reference.
package session
