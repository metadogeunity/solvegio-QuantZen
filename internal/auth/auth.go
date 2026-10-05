package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	SessionCookie = "qz_session"
	CSRFCookie   = "qz_csrf"
)

type Manager struct {
	username string
	password string
	secret   []byte
	ttl      time.Duration
	mu       sync.Mutex
	failed   map[string]loginWindow
}

type loginWindow struct {
	started time.Time
	count   int
}

func New(username, password, secret string, ttl time.Duration) *Manager {
	return &Manager{
		username: username,
		password: password,
		secret:   []byte(secret),
		ttl:      ttl,
		failed:   make(map[string]loginWindow),
	}
}

func (m *Manager) Configured() bool {
	return m.username != "" && m.password != "" && len(m.secret) >= 32 && m.ttl > 0
}

func (m *Manager) Authenticate(r *http.Request) bool {
	if !m.Configured() {
		return false
	}

	cookie, err := r.Cookie(SessionCookie)
	if err != nil || cookie.Value == "" {
		return false
	}

	payload, signature, ok := strings.Cut(cookie.Value, ".")
	if !ok {
		return false
	}

	mac := hmac.New(sha256.New, m.secret)
	_, _ = mac.Write([]byte(payload))
	if !hmac.Equal([]byte(signature), []byte(base64.RawURLEncoding.EncodeToString(mac.Sum(nil)))) {
		return false
	}

	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return false
	}

	parts := strings.Split(string(raw), "|")
	if len(parts) != 3 || parts[0] != m.username {
		return false
	}

	exp, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil || time.Now().Unix() >= exp {
		return false
	}
	return true
}

func (m *Manager) Login(w http.ResponseWriter, r *http.Request, username, password string) bool {
	if !m.Configured() || !m.allowLogin(username) {
		return false
	}
	if !secureEqual(username, m.username) || !secureEqual(password, m.password) {
		m.recordFailure(username)
		return false
	}

	csrfBytes := make([]byte, 32)
	if _, err := rand.Read(csrfBytes); err != nil {
		return false
	}
	csrf := base64.RawURLEncoding.EncodeToString(csrfBytes)
	exp := time.Now().Add(m.ttl).Unix()
	payload := base64.RawURLEncoding.EncodeToString([]byte(username + "|" + strconv.FormatInt(exp, 10) + "|" + csrf))

	mac := hmac.New(sha256.New, m.secret)
	_, _ = mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	token := payload + "." + sig

	secure := strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") || r.TLS != nil
	http.SetCookie(w, &http.Cookie{
		Name: SessionCookie, Value: token, Path: "/", HttpOnly: true,
		Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: int(m.ttl.Seconds()),
	})
	http.SetCookie(w, &http.Cookie{
		Name: CSRFCookie, Value: csrf, Path: "/", HttpOnly: false,
		Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: int(m.ttl.Seconds()),
	})

	m.mu.Lock()
	delete(m.failed, username)
	m.mu.Unlock()
	return true
}

func (m *Manager) allowLogin(username string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	window, ok := m.failed[username]
	if !ok || time.Since(window.started) >= time.Minute {
		return true
	}
	return window.count < 10
}

func (m *Manager) recordFailure(username string) {
	m.mu.Lock()
	defer m.mu.Unlock()

	window, ok := m.failed[username]
	if !ok || time.Since(window.started) >= time.Minute {
		m.failed[username] = loginWindow{started: time.Now(), count: 1}
		return
	}
	window.count++
	m.failed[username] = window
}

func (m *Manager) Logout(w http.ResponseWriter, r *http.Request) {
	secure := strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") || r.TLS != nil
	for _, name := range []string{SessionCookie, CSRFCookie} {
		http.SetCookie(w, &http.Cookie{
			Name: name, Value: "", Path: "/", MaxAge: -1,
			HttpOnly: name == SessionCookie, Secure: secure, SameSite: http.SameSiteLaxMode,
		})
	}
}

func (m *Manager) ValidateCSRF(r *http.Request) bool {
	cookie, err := r.Cookie(CSRFCookie)
	if err != nil || cookie.Value == "" {
		return false
	}
	return secureEqual(cookie.Value, r.Header.Get("X-QZ-CSRF"))
}

func secureEqual(a, b string) bool {
	ha := sha256.Sum256([]byte(a))
	hb := sha256.Sum256([]byte(b))
	return hmac.Equal(ha[:], hb[:])
}
