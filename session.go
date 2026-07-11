package session

import "time"

// Session is the state carried in a signed cookie. Values holds arbitrary
// string key/value pairs; Subject is a convenience field for the authenticated
// principal (it may be empty for anonymous sessions).
type Session struct {
	ID        string            `json:"id"`
	Subject   string            `json:"sub,omitempty"`
	Values    map[string]string `json:"val,omitempty"`
	CreatedAt time.Time         `json:"iat"`
	ExpiresAt time.Time         `json:"exp"`
}

// Get returns the value for key, or "" if absent.
func (s *Session) Get(key string) string {
	if s == nil || s.Values == nil {
		return ""
	}
	return s.Values[key]
}

// Set stores a value under key.
func (s *Session) Set(key, value string) {
	if s.Values == nil {
		s.Values = make(map[string]string)
	}
	s.Values[key] = value
}

// Delete removes a key.
func (s *Session) Delete(key string) {
	delete(s.Values, key)
}
