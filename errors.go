package session

import "errors"

var (
	// ErrNoSession is returned when a request carries no session cookie.
	ErrNoSession = errors.New("session: no session cookie")

	// ErrInvalid is returned when a session cookie is malformed or fails its
	// signature check (tampering).
	ErrInvalid = errors.New("session: invalid session cookie")

	// ErrExpired is returned when a session is past its expiry.
	ErrExpired = errors.New("session: session expired")

	// ErrTooLarge is returned when an encoded session exceeds the cookie size
	// limit (about 4 KB).
	ErrTooLarge = errors.New("session: encoded session too large for a cookie")

	// ErrNilSession is returned by Save when given a nil session.
	ErrNilSession = errors.New("session: nil session")
)
