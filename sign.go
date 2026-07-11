package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// version prefixes every cookie payload so the format can evolve without
// breaking old cookies (an unknown version is simply rejected).
const version = "v1"

// sign encodes and signs the payload as "version.payload.signature", each
// segment base64url. The first key signs.
func (m *Manager) sign(payload []byte) string {
	p := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := version + "." + p
	sig := mac(m.keys[0], signingInput)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
}

// unsign verifies the cookie value against every key (constant time) and
// returns the decoded payload.
func (m *Manager) unsign(value string) ([]byte, error) {
	parts := strings.Split(value, ".")
	if len(parts) != 3 || parts[0] != version {
		return nil, ErrInvalid
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, ErrInvalid
	}
	signingInput := parts[0] + "." + parts[1]
	if !anyKeyVerifies(m.keys, signingInput, sig) {
		return nil, ErrInvalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, ErrInvalid
	}
	return payload, nil
}

// mac returns the HMAC-SHA256 of signingInput under key.
func mac(key []byte, signingInput string) []byte {
	h := hmac.New(sha256.New, key)
	h.Write([]byte(signingInput))
	return h.Sum(nil)
}

// anyKeyVerifies reports whether the signature matches under any key, using a
// constant-time comparison. This supports key rotation: the first key signs,
// any key verifies. It checks every key without an early return, so the time
// taken does not reveal which key (primary or a rotated one) matched.
func anyKeyVerifies(keys [][]byte, signingInput string, sig []byte) bool {
	matched := false
	for _, k := range keys {
		if len(k) == 0 {
			continue
		}
		if hmac.Equal(mac(k, signingInput), sig) {
			matched = true
		}
	}
	return matched
}
