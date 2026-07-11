# session - reference

`session` provides signed cookie sessions. Full English reference; Ukrainian in
[DOC.UK.md](DOC.UK.md).

## Contents

- [Model](#model)
- [Session](#session)
- [Manager and options](#manager-and-options)
- [Load, Save, Destroy](#load-save-destroy)
- [Middleware](#middleware)
- [Cookie format and security](#cookie-format-and-security)
- [Key rotation](#key-rotation)
- [Scope](#scope)

## Model

The MVP stores the whole session in a signed cookie (cookie-only): there is no
server-side store. The cookie is signed with HMAC-SHA256; nothing in it is
secret (it is signed, not encrypted), so do not put confidential data in a
session value. Encrypted payloads are a planned addition.

## Session

```go
type Session struct {
	ID        string
	Subject   string
	Values    map[string]string
	CreatedAt time.Time
	ExpiresAt time.Time
}
```

`Get`, `Set` and `Delete` manage `Values`. `Subject` is a convenience field for
the authenticated principal and may be empty.

## Manager and options

```go
m := session.New(secret, opts...)
```

| Option | Effect | Default |
|--------|--------|---------|
| `WithName(s)` | cookie name | "session" |
| `WithDomain(s)` | cookie Domain | "" |
| `WithPath(s)` | cookie Path | "/" |
| `WithSecure(b)` | Secure attribute (HTTPS only) | true |
| `WithSameSite(m)` | SameSite attribute | Lax |
| `WithTTL(d)` | session lifetime | 24h |
| `WithKey(k)` | extra verification key (rotation) | - |
| `WithClock(fn)` | time source (testing) | time.Now |

`HttpOnly` is always set.

## Load, Save, Destroy

```go
s, err := m.Load(r)   // ErrNoSession, ErrInvalid or ErrExpired on failure
err = m.Save(w, s)    // assigns ID/timestamps, refreshes expiry, sets cookie
m.Destroy(w)          // clears the cookie
```

`Save` assigns a random `ID` and `CreatedAt` when missing, sets `ExpiresAt` to
now+TTL, and returns `ErrTooLarge` if the encoded cookie would exceed the ~4 KB
browser limit.

## Middleware

```go
http.Handle("/", m.Middleware(handler))
s, ok := session.From(r.Context())
```

`Middleware` loads the session into the request context, substituting a fresh
empty session when there is none or it is invalid. Because a cookie-only session
is written in the response header, handlers persist changes explicitly with
`Save`.

## Cookie format and security

The cookie value is `version.payload.signature`, each segment base64url. The
version prefix lets the format evolve; an unknown version is rejected. The
signature is verified in constant time before the payload is decoded, so a
tampered cookie never reaches your session. Defaults are `HttpOnly`,
`SameSite=Lax` and `Secure=true`; pass `WithSecure(false)` only for local HTTP
development. `New` panics if a signing key is shorter than 32 bytes. After a
successful login call `Session.RegenerateID` before `Save` to avoid session
fixation.

## Key rotation

`New` takes the primary (signing) key; add older keys with `WithKey`. All
configured keys are tried on verification, so you can introduce a new key and
retire an old one without invalidating live sessions:

```go
m := session.New(newKey, session.WithKey(oldKey))
```

## Scope

The MVP does not include a server-side store, encrypted payloads or CSRF
(planned), and does not do user management, password hashing or OAuth.
