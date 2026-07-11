package session_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"time"

	"github.com/goloop/session"
)

func ExampleManager() {
	m := session.New([]byte("0123456789abcdef0123456789abcdef"),
		session.WithName("sid"),
		session.WithSecure(true),
		session.WithTTL(24*time.Hour),
	)

	// Save a session.
	rec := httptest.NewRecorder()
	s := &session.Session{Subject: "user-1"}
	s.Set("theme", "dark")
	_ = m.Save(rec, s)

	// Load it back on the next request.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	for _, c := range rec.Result().Cookies() {
		req.AddCookie(c)
	}
	loaded, _ := m.Load(req)
	fmt.Println(loaded.Subject, loaded.Get("theme"))
	// Output: user-1 dark
}
