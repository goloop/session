# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-07-12

### Added
- `WithAbsoluteTTL(d)` caps the total lifetime of a session from its creation,
  independent of activity, so a continually refreshed session cannot live
  forever.

### Fixed
- `Save` returns `ErrNilSession` instead of panicking when given a nil session.
- `WithName` panics on a name that is not a valid cookie token: an invalid name
  made `net/http` emit an empty `Set-Cookie`, silently dropping the session.
- The `Save` size check now includes a fixed allowance for the cookie
  attributes (`Expires`, `Max-Age`, `Secure`, `HttpOnly`, `SameSite`), so a
  cookie that passes the check also fits under the browser limit.
- `anyKeyVerifies` checks every rotation key without an early return, so the
  time taken does not reveal which key matched.

### Documentation
- The package doc now states plainly that the payload is signed, not encrypted
  (readable by the client), that logout is stateless (a captured cookie stays
  valid until expiry), and that a loaded session is not proof of authentication
  (check `Subject`).

## [0.1.0]

First release: signed, cookie-only sessions on the standard library, with key
rotation, safe cookie defaults and session-fixation protection.
