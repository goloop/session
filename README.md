[![Go Reference](https://img.shields.io/badge/godoc-reference-blue)](https://pkg.go.dev/github.com/goloop/session) [![License](https://img.shields.io/badge/license-MIT-brightgreen)](https://github.com/goloop/session/blob/master/LICENSE) [![Stay with Ukraine](https://img.shields.io/static/v1?label=Stay%20with&message=Ukraine%20♥&color=ffD700&labelColor=0057B8&style=flat)](https://u24.gov.ua/)

# session

`session` provides secure, signed cookie sessions for browser apps. The MVP is
cookie-only: the whole session lives in an HMAC-SHA256 signed cookie, so there
is no server-side store to run. Zero dependencies, standard library only.

It complements token-based auth rather than replacing it: `session` owns cookie
and browser state; an auth package owns subjects, passwords and tokens.

## Install

```bash
go get github.com/goloop/session
```

## Quick start

```go
m := session.New(secret,
	session.WithName("sid"),
	session.WithSecure(true),                 // HTTPS only in production
	session.WithSameSite(http.SameSiteLaxMode),
	session.WithTTL(24*time.Hour),
)

// Read (or start), mutate, persist.
s := m.LoadOrNew(r)
s.Set("theme", "dark")
err := m.Save(w, s)

// Log out.
m.Destroy(w)
```

With the middleware:

```go
http.Handle("/", m.Middleware(handler))

// inside handler:
s, _ := session.From(r.Context())
s.Set("seen", "1")
_ = m.Save(w, s)
```

## Security

- Cookie is `HttpOnly`, `SameSite=Lax` and `Secure` by default; pass
  `WithSecure(false)` only for local HTTP development.
- `New` panics on a signing key shorter than 32 bytes; call
  `Session.RegenerateID` after login (then `Save`) to avoid session fixation.
- Payload is signed with HMAC-SHA256 and versioned, so the format can evolve
  without breaking old cookies.
- **Key rotation** is built in: the primary key signs, any key added with
  `WithKey` verifies, so you can roll keys without invalidating live sessions.

## Scope

The MVP does not yet include a server-side store, encrypted payloads or CSRF
(planned). It does not do user management, password hashing or OAuth.

## Documentation

- English reference: [DOC.md](DOC.md)
- Ukrainian reference: [DOC.UK.md](DOC.UK.md)

## License

MIT - see [LICENSE](LICENSE).
