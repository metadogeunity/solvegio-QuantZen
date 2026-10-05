package auth

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLoginAndCSRF(t *testing.T) {
	m := New("admin", "password", strings.Repeat("s", 32), time.Hour)
	req := httptest.NewRequest("POST", "/api/auth/login", nil)
	rec := httptest.NewRecorder()

	if !m.Login(rec, req, "admin", "password") {
		t.Fatal("expected login success")
	}

	cookies := rec.Result().Cookies()
	var session, csrf *http.Cookie
	for _, cookie := range cookies {
		switch cookie.Name {
		case SessionCookie:
			session = cookie
		case CSRFCookie:
			csrf = cookie
		}
	}
	if session == nil || !session.HttpOnly {
		t.Fatal("expected HttpOnly session cookie")
	}
	if csrf == nil || csrf.HttpOnly {
		t.Fatal("expected readable CSRF cookie")
	}

	authReq := httptest.NewRequest("GET", "/api/dashboard", nil)
	authReq.AddCookie(session)
	if !m.Authenticate(authReq) {
		t.Fatal("expected authenticated session")
	}

	postReq := httptest.NewRequest("POST", "/api/simulator", nil)
	postReq.AddCookie(session)
	postReq.AddCookie(csrf)
	postReq.Header.Set("X-QZ-CSRF", csrf.Value)
	if !m.ValidateCSRF(postReq) {
		t.Fatal("expected valid CSRF token")
	}
}

func TestLoginThrottlesFailures(t *testing.T) {
	m := New("admin", "password", strings.Repeat("s", 32), time.Hour)
	for i := 0; i < 10; i++ {
		req := httptest.NewRequest("POST", "/", nil)
		rec := httptest.NewRecorder()
		if m.Login(rec, req, "admin", "wrong") {
			t.Fatal("unexpected successful login")
		}
	}
	req := httptest.NewRequest("POST", "/", nil)
	rec := httptest.NewRecorder()
	if m.Login(rec, req, "admin", "password") {
		t.Fatal("expected throttle after repeated failures")
	}
}
