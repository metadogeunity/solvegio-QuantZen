package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"path"
	"sort"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/metadogeunity/solvegio-QuantZen/internal/audit"
	"github.com/metadogeunity/solvegio-QuantZen/internal/auth"
	"github.com/metadogeunity/solvegio-QuantZen/internal/httpsecurity"
	"github.com/metadogeunity/solvegio-QuantZen/internal/canonical"
	"github.com/metadogeunity/solvegio-QuantZen/internal/config"
	qzcrypto "github.com/metadogeunity/solvegio-QuantZen/internal/crypto"
	"github.com/metadogeunity/solvegio-QuantZen/internal/httpx"
	"github.com/metadogeunity/solvegio-QuantZen/internal/protocol"
	"github.com/metadogeunity/solvegio-QuantZen/internal/replay"
	"github.com/metadogeunity/solvegio-QuantZen/internal/solvegio"
	"github.com/metadogeunity/solvegio-QuantZen/internal/store"
	"github.com/metadogeunity/solvegio-QuantZen/internal/trust"
	"github.com/metadogeunity/solvegio-QuantZen/internal/webhook"
)

type App struct {
	cfg      config.Config
	auth     *auth.Manager
	audit    *audit.Log
	trust    *trust.Registry
	keys     *qzcrypto.KeyStore
	replay   replay.Store
	solvegio *solvegio.Client
	db       *store.Store

	requests atomic.Int64
	verified atomic.Int64
	blocked  atomic.Int64
	replays  atomic.Int64
	invalid  atomic.Int64
	unknown  atomic.Int64
	webhooks atomic.Int64
}

func main() {
	cfg := config.Load()

	id, err := qzcrypto.GenerateIdentity("qz-key-001")
	if err != nil {
		log.Fatal(err)
	}

	now := time.Now().UTC()
	reg := trust.NewRegistry()
	reg.Put(trust.Key{
		Issuer:      "SolveGio-Partner-Demo",
		KID:         id.KeyID,
		Algorithm:   "Ed25519 + ML-DSA-65",
		Status:      "ACTIVE",
		Fingerprint: id.Fingerprint,
		ValidFrom:   now,
		ValidUntil:  now.AddDate(1, 0, 0),
		EdPublic:   id.EdPublic,
		PQPublic:   id.PQPublic,
	})

	var replayStore replay.Store = replay.NewMemory()
	if cfg.RedisURL != "" {
		if r, e := replay.NewRedis(cfg.RedisURL); e == nil && r.Ping(context.Background()) == nil {
			replayStore = r
		}
	}

	db, err := store.New(context.Background(), cfg.DatabaseURL)
	if err != nil {
		log.Printf("database disabled: %v", err)
		db, _ = store.New(context.Background(), "")
	}

	app := &App{
		cfg:      cfg,
		auth:     auth.New(cfg.DashboardUsername, cfg.DashboardPassword, cfg.DashboardSessionSecret, cfg.DashboardSessionTTL),
		audit:    audit.New(),
		trust:    reg,
		keys:     qzcrypto.NewKeyStore(id),
		replay:   replayStore,
		solvegio: solvegio.New(cfg.SolveGioBaseURL, cfg.SolveGioAPIKey, cfg.SolveGioTimeout),
		db:       db,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", app.health)
	mux.HandleFunc("/readyz", app.ready)
	mux.HandleFunc("/api/auth/login", app.login)
	mux.Handle("/api/auth/session", app.requireAdmin(http.HandlerFunc(app.session)))
	mux.Handle("/api/auth/logout", app.requireCSRF(http.HandlerFunc(app.logout)))
	mux.Handle("/api/dashboard", app.requireAdmin(http.HandlerFunc(app.dashboard)))
	mux.Handle("/api/trust-registry", app.requireAdmin(http.HandlerFunc(app.registry)))
	mux.Handle("/api/audit-log", app.requireAdmin(http.HandlerFunc(app.auditLog)))
	mux.Handle("/api/solvegio", app.requireAdmin(http.HandlerFunc(app.solvegioStatus)))
	mux.Handle("/api/simulator", app.requireCSRF(http.HandlerFunc(app.simulator)))
	mux.Handle("/api/demo/identity", app.requireAdmin(http.HandlerFunc(app.demoIdentity)))
	mux.HandleFunc("/gateway/forward", app.forward)
	mux.HandleFunc("/webhooks/solvegio", app.solvegioWebhook)
	mux.Handle("/", http.FileServer(http.Dir("./web")))

	srv := &http.Server{
		Addr:              ":" + cfg.Port,
		Handler:           httpsecurity.Middleware(mux),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       20 * time.Second,
		WriteTimeout:      20 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	log.Printf("QuantZen gateway listening on :%s", cfg.Port)
	log.Fatal(srv.ListenAndServe())
}

func (a *App) recentEvents(ctx context.Context) []audit.Event {
	live := a.audit.List()
	persisted, err := a.db.List(ctx, 500)
	if err != nil || len(persisted) == 0 {
		sort.Slice(live, func(i, j int) bool { return live[i].Time.After(live[j].Time) })
		return live
	}

	seen := make(map[string]struct{}, len(live)+len(persisted))
	out := make([]audit.Event, 0, len(live)+len(persisted))
	for _, e := range append(live, persisted...) {
		if _, ok := seen[e.ID]; ok {
			continue
		}
		seen[e.ID] = struct{}{}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	if len(out) > 500 {
		out = out[:500]
	}
	return out
}

func (a *App) persistEvent(ctx context.Context, e audit.Event) {
	if a.db != nil {
		_ = a.db.Insert(ctx, e)
	}
}

func (a *App) ready(w http.ResponseWriter, _ *http.Request) {
	if !a.auth.Configured() {
		httpx.JSON(w, http.StatusServiceUnavailable, map[string]any{"status": "not_ready", "reason": "dashboard authentication is not configured"})
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"status": "ready"})
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpx.Error(w, http.StatusMethodNotAllowed, "POST required")
		return
	}
	var in struct {
		Username string
		Password string
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&in); err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if !a.auth.Login(w, r, in.Username, in.Password) {
		httpx.Error(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	httpx.JSON(w, http.StatusOK, map[string]any{"authenticated": true})
}

func (a *App) session(w http.ResponseWriter, _ *http.Request) {
	httpx.JSON(w, http.StatusOK, map[string]any{"authenticated": true})
}

func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	a.auth.Logout(w, r)
	httpx.JSON(w, http.StatusOK, map[string]any{"authenticated": false})
}

func (a *App) requireAdmin(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.auth.Configured() || !a.auth.Authenticate(r) {
			httpx.Error(w, http.StatusUnauthorized, "authentication required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) requireCSRF(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !a.auth.Configured() || !a.auth.Authenticate(r) {
			httpx.Error(w, http.StatusUnauthorized, "authentication required")
			return
		}
		if r.Method == http.MethodPost && !a.auth.ValidateCSRF(r) {
			httpx.Error(w, http.StatusForbidden, "CSRF validation failed")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *App) health(w http.ResponseWriter, _ *http.Request) {
	httpx.JSON(w, http.StatusOK, map[string]any{"status": "ok", "version": "0.1.0-mvp"})
}

func (a *App) dashboard(w http.ResponseWriter, r *http.Request) {
	events := a.recentEvents(r.Context())
	now := time.Now().UTC()

	var protected, verified, blocked, replays, invalid, unknown, webhookEvents int
	endpointCounts := make(map[string]int)
	activity := make([]int, 24)

	for _, e := range events {
		if strings.HasPrefix(e.Endpoint, "/v1/") {
			protected++
			endpointCounts[e.Endpoint]++
			if e.Decision == "ALLOW" {
				verified++
			} else if e.Decision == "BLOCK" {
				blocked++
			}
			switch e.Type {
			case "REPLAY_DETECTED":
				replays++
			case "INVALID_SIGNATURE":
				invalid++
			case "UNKNOWN_KEY":
				unknown++
			}

			age := now.Sub(e.Time)
			if age >= 0 && age < 24*time.Hour {
				index := 23 - int(age/time.Hour)
				if index >= 0 && index < len(activity) {
					activity[index]++
				}
			}
		}

		if e.Endpoint == "/webhooks/solvegio" {
			webhookEvents++
		}
	}

	endpointStats := make([]map[string]any, 0, len(endpointCounts))
	for endpoint, count := range endpointCounts {
		endpointStats = append(endpointStats, map[string]any{
			"endpoint": endpoint,
			"count":    count,
		})
	}
	sort.Slice(endpointStats, func(i, j int) bool {
		return endpointStats[i]["count"].(int) > endpointStats[j]["count"].(int)
	})

	httpx.JSON(w, http.StatusOK, map[string]any{
		"protected_requests":    protected,
		"verified":              verified,
		"blocked":               blocked,
		"replay_attacks":        replays,
		"invalid_signatures":    invalid,
		"unknown_keys":          unknown,
		"webhook_events":        webhookEvents,
		"endpoint_distribution": endpointStats,
		"activity":              activity,
		"events":                events,
	})
}

func (a *App) registry(w http.ResponseWriter, _ *http.Request) {
	httpx.JSON(w, http.StatusOK, a.trust.List())
}

func (a *App) auditLog(w http.ResponseWriter, r *http.Request) {
	httpx.JSON(w, http.StatusOK, a.recentEvents(r.Context()))
}

func (a *App) solvegioStatus(w http.ResponseWriter, r *http.Request) {
	events := a.recentEvents(r.Context())
	lastEvent := "Never"
	if len(events) > 0 {
		lastEvent = events[0].Time.Format("15:04:05 UTC")
	}

	httpx.JSON(w, http.StatusOK, map[string]any{
		"environment":        map[bool]string{true: "CONFIGURED", false: "NOT CONFIGURED"}[a.solvegio.Configured()],
		"api_connection":     a.solvegio.Configured(),
		"webhook_status":     a.cfg.WebhookSecret != "",
		"last_event":         lastEvent,
		"api_key_configured": a.solvegio.Configured(),
	})
}

func (a *App) demoIdentity(w http.ResponseWriter, _ *http.Request) {
	id, _ := a.keys.Get("qz-key-001")
	httpx.JSON(w, http.StatusOK, map[string]any{
		"kid":            id.KeyID,
		"ed25519_public": base64.RawURLEncoding.EncodeToString(id.EdPublic),
		"mldsa65_public": base64.RawURLEncoding.EncodeToString(id.PQPublic.Bytes()),
		"fingerprint":    id.Fingerprint,
	})
}

func (a *App) signDemo(method, p string, body []byte) map[string]string {
	canon, err := canonical.JSON(body)
	if err != nil {
		return nil
	}

	timestamp := fmt.Sprint(time.Now().Unix())
	nonceBytes := make([]byte, 16)
	_, _ = rand.Read(nonceBytes)
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	digest := protocol.Digest(canon)
	msg := protocol.SigningString(method, p, timestamp, nonce, digest)

	id, _ := a.keys.Get("qz-key-001")
	ed, pq, err := qzcrypto.Sign(id, []byte(msg))
	if err != nil {
		return nil
	}

	return map[string]string{
		"X-QZ-Version":           protocol.Version,
		"X-QZ-Key-Id":            id.KeyID,
		"X-QZ-Timestamp":         timestamp,
		"X-QZ-Nonce":             nonce,
		"X-QZ-Content-Digest":    digest,
		"X-QZ-Signature-Ed25519": ed,
		"X-QZ-Signature-MLDSA65":  pq,
	}
}

func (a *App) verifyRequest(tenant string, h http.Header, body []byte, method, p string) (string, string, string) {
	env, err := protocol.FromHeaders(h)
	if err != nil {
		return "400", "BLOCK", "INVALID_SIGNATURE"
	}
	if env.Version != protocol.Version {
		return "400", "BLOCK", "INVALID_SIGNATURE"
	}

	canon, err := canonical.JSON(body)
	if err != nil {
		return "400", "BLOCK", "INVALID_JSON"
	}
	digest := protocol.Digest(canon)
	if !strings.EqualFold(digest, env.ContentDigest) {
		return "400", "BLOCK", "PAYLOAD_TAMPERED"
	}

	if time.Since(time.Unix(env.Timestamp, 0)).Abs() > a.cfg.TimestampTolerance {
		return "401", "BLOCK", "EXPIRED_TIMESTAMP"
	}

	key, ok := a.trust.Get(env.KeyID)
	if !ok {
		a.unknown.Add(1)
		return "401", "BLOCK", "UNKNOWN_KEY"
	}
	if key.Status != "ACTIVE" {
		return "401", "BLOCK", "REVOKED_KEY"
	}

	now := time.Now().UTC()
	if now.Before(key.ValidFrom) || now.After(key.ValidUntil) {
		return "401", "BLOCK", "KEY_OUTSIDE_VALIDITY"
	}

	msg := protocol.SigningString(method, p, fmt.Sprint(env.Timestamp), env.Nonce, env.ContentDigest)
	edOK, pqOK, err := qzcrypto.Verify(key.EdPublic, key.PQPublic, []byte(msg), env.Ed25519Signature, env.MLDSASignature)
	if err != nil || !edOK || !pqOK {
		a.invalid.Add(1)
		return "401", "BLOCK", "INVALID_SIGNATURE"
	}

	claimed, err := a.replay.Claim(context.Background(), "qz:"+tenant+":"+env.Nonce, 5*time.Minute)
	if err != nil || !claimed {
		a.replays.Add(1)
		return "409", "BLOCK", "REPLAY_DETECTED"
	}

	return "200", "ALLOW", "VERIFIED"
}

func (a *App) forward(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpx.Error(w, http.StatusMethodNotAllowed, "POST required")
		return
	}

	target := path.Clean(r.URL.Query().Get("path"))
	if !strings.HasPrefix(target, "/v1/") {
		httpx.Error(w, http.StatusBadRequest, "only /v1/* paths are allowed")
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "invalid body")
		return
	}

	method := strings.ToUpper(r.URL.Query().Get("method"))
	if method == "" {
		method = http.MethodPost
	}

	statusText, decision, detail := a.verifyRequest(r.Header.Get("X-Tenant"), r.Header, body, method, target)
	a.requests.Add(1)

	if decision == "ALLOW" {
		a.verified.Add(1)
	} else {
		a.blocked.Add(1)
	}

	if decision != "ALLOW" {
		status, _ := strconv.Atoi(statusText)
		if status == 0 {
			status = http.StatusUnauthorized
		}

		e := a.audit.Add(audit.Event{
			Method:   method,
			Type:     detail,
			Endpoint: target,
			Tenant:   r.Header.Get("X-Tenant"),
			KeyID:    r.Header.Get("X-QZ-Key-Id"),
			Decision: decision,
			Details:  statusText,
		})
		a.persistEvent(r.Context(), e)
		httpx.Error(w, status, detail)
		return
	}

	start := time.Now()
	code, headers, resp, err := a.solvegio.Do(r.Context(), method, target, bytes.NewReader(body))
	if err != nil {
		e := a.audit.Add(audit.Event{
			Method:   method,
			Type:     "UPSTREAM_ERROR",
			Endpoint: target,
			Tenant:   r.Header.Get("X-Tenant"),
			KeyID:    r.Header.Get("X-QZ-Key-Id"),
			Decision: "BLOCK",
			Details:  err.Error(),
		})
		a.persistEvent(r.Context(), e)
		httpx.Error(w, http.StatusBadGateway, "SolveGio upstream unavailable")
		return
	}

	for k, v := range headers {
		if strings.EqualFold(k, "Content-Type") && len(v) > 0 {
			w.Header().Set(k, v[0])
		}
	}

	latency := time.Since(start).Milliseconds()
	e := a.audit.Add(audit.Event{
		Method:    method,
		Type:      detail,
		Endpoint:  target,
		Tenant:    r.Header.Get("X-Tenant"),
		KeyID:     r.Header.Get("X-QZ-Key-Id"),
		Decision:  "ALLOW",
		LatencyMs: latency,
		Details:   fmt.Sprintf("upstream=%d", code),
	})
	a.persistEvent(r.Context(), e)

	w.Header().Set("X-QuantZen-Decision", "ALLOW")
	w.Header().Set("X-QuantZen-Audit-Hash", e.Hash)
	w.WriteHeader(code)
	_, _ = w.Write(resp)
}

func (a *App) simulator(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		httpx.Error(w, http.StatusMethodNotAllowed, "POST required")
		return
	}

	var in struct {
		Scenario string `json:"Scenario"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	if in.Scenario == "" {
		in.Scenario = "valid"
	}

	body, _ := json.Marshal(map[string]any{
		"pricing_id": "demo-pricing",
		"buyer":      map[string]string{"email": "demo@example.com"},
	})
	headers := make(http.Header)
	for k, v := range a.signDemo(http.MethodPost, "/v1/payments", body) {
		headers.Set(k, v)
	}

	switch in.Scenario {
	case "invalid_signature":
		headers.Set("X-QZ-Signature-MLDSA65", "bad")
	case "tampered_payload":
		body, _ = json.Marshal(map[string]any{
			"pricing_id": "tampered",
			"buyer":      map[string]string{"email": "demo@example.com"},
		})
	case "expired_timestamp":
		headers.Set("X-QZ-Timestamp", fmt.Sprint(time.Now().Add(-10*time.Minute).Unix()))
	case "reused_nonce":
		_, _ = a.replay.Claim(context.Background(), "qz:partner-demo:"+headers.Get("X-QZ-Nonce"), 5*time.Minute)
	case "revoked_key":
		a.trust.Revoke("qz-key-001")
	case "unknown_key":
		headers.Set("X-QZ-Key-Id", "unknown-key")
	case "duplicate_webhook":
		a.webhooks.Add(1)
		eventID := "evt_demo_" + fmt.Sprint(time.Now().UnixNano())
		_, _ = a.replay.Claim(context.Background(), "webhook:"+eventID, 24*time.Hour)
		claimed, _ := a.replay.Claim(context.Background(), "webhook:"+eventID, 24*time.Hour)

		detail := "DUPLICATE_WEBHOOK"
		decision := "BLOCK"
		if claimed {
			decision = "ALLOW"
			detail = "WEBHOOK_ACCEPTED"
		}

		e := a.audit.Add(audit.Event{
			Method:   http.MethodPost,
			Type:     detail,
			Endpoint: "/webhooks/solvegio",
			Tenant:   "partner-demo",
			Decision: decision,
			Details:  "event_id=" + eventID,
		})
		a.persistEvent(r.Context(), e)

		httpx.JSON(w, http.StatusOK, map[string]any{
			"scenario": in.Scenario,
			"decision": decision,
			"status":   "409",
			"details":  detail,
		})
		return
	}

	status, decision, detail := a.verifyRequest("partner-demo", headers, body, http.MethodPost, "/v1/payments")
	a.requests.Add(1)
	if decision == "ALLOW" {
		a.verified.Add(1)
	} else {
		a.blocked.Add(1)
	}

	if in.Scenario == "revoked_key" {
		a.trust.Activate("qz-key-001")
	}

	e := a.audit.Add(audit.Event{
		Method:   http.MethodPost,
		Type:     detail,
		Endpoint: "/v1/payments",
		Tenant:   "partner-demo",
		KeyID:    headers.Get("X-QZ-Key-Id"),
		Decision: decision,
		Details:  status,
	})
	a.persistEvent(r.Context(), e)

	httpx.JSON(w, http.StatusOK, map[string]any{
		"scenario": in.Scenario,
		"decision": decision,
		"status":   status,
		"details":  detail,
	})
}

func (a *App) solvegioWebhook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
	if err != nil {
		httpx.Error(w, http.StatusBadRequest, "read error")
		return
	}

	a.webhooks.Add(1)

	if err = webhook.Verify(r, body, a.cfg.WebhookSecret, a.cfg.TimestampTolerance); err != nil {
		e := a.audit.Add(audit.Event{
			Method:   http.MethodPost,
			Type:     "INVALID_WEBHOOK_SIGNATURE",
			Endpoint: "/webhooks/solvegio",
			Decision: "BLOCK",
			Details:  err.Error(),
		})
		a.persistEvent(r.Context(), e)
		httpx.Error(w, http.StatusUnauthorized, err.Error())
		return
	}

	var event struct {
		ID string `json:"id"`
	}
	_ = json.Unmarshal(body, &event)

	if event.ID != "" {
		claimed, claimErr := a.replay.Claim(r.Context(), "webhook:"+event.ID, 24*time.Hour)
		if claimErr != nil || !claimed {
			e := a.audit.Add(audit.Event{
				Method:   http.MethodPost,
				Type:     "DUPLICATE_WEBHOOK",
				Endpoint: "/webhooks/solvegio",
				Decision: "BLOCK",
				Details:  "event_id=" + event.ID,
			})
			a.persistEvent(r.Context(), e)
			httpx.Error(w, http.StatusConflict, "DUPLICATE_WEBHOOK")
			return
		}
	}

	e := a.audit.Add(audit.Event{
		Method:   http.MethodPost,
		Type:     "WEBHOOK_VERIFIED",
		Endpoint: "/webhooks/solvegio",
		Decision: "ALLOW",
		Details:  "SolveGio HMAC verified",
	})
	a.persistEvent(r.Context(), e)

	httpx.JSON(w, http.StatusOK, map[string]any{"ok": true, "audit_hash": e.Hash})
}
