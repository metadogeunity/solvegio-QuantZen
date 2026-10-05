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
  "strings"
  "sync/atomic"
  "time"

  "github.com/metadogeunity/solvegio-QuantZen/internal/audit"
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
  cfg config.Config
  audit *audit.Log
  trust *trust.Registry
  keys *qzcrypto.KeyStore
  replay replay.Store
  solvegio *solvegio.Client
  db *store.Store
  requests atomic.Int64
  verified atomic.Int64
  blocked atomic.Int64
  replays atomic.Int64
  invalid atomic.Int64
  unknown atomic.Int64
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
    Issuer: "SolveGio-Partner-Demo", KID: id.KeyID,
    Algorithm: "Ed25519 + ML-DSA-65", Status: "ACTIVE",
    Fingerprint: id.Fingerprint, ValidFrom: now, ValidUntil: now.AddDate(1, 0, 0),
    EdPublic: id.EdPublic, PQPublic: id.PQPublic,
  })

  var replayStore replay.Store = replay.NewMemory()
  if cfg.RedisURL != "" {
    if r, e := replay.NewRedis(cfg.RedisURL); e == nil && r.Ping(context.Background()) == nil {
      replayStore = r
    }
  }

  db, _ := store.New(context.Background(), cfg.DatabaseURL)
  app := &App{
    cfg: cfg, audit: audit.New(), trust: reg,
    keys: qzcrypto.NewKeyStore(id), replay: replayStore,
    solvegio: solvegio.New(cfg.SolveGioBaseURL, cfg.SolveGioAPIKey, cfg.SolveGioTimeout),
    db: db,
  }

  mux := http.NewServeMux()
  mux.HandleFunc("/healthz", app.health)
  mux.HandleFunc("/readyz", app.health)
  mux.HandleFunc("/api/dashboard", app.dashboard)
  mux.HandleFunc("/api/trust-registry", app.registry)
  mux.HandleFunc("/api/audit-log", app.auditLog)
  mux.HandleFunc("/api/solvegio", app.solvegioStatus)
  mux.HandleFunc("/api/simulator", app.simulator)
  mux.HandleFunc("/api/demo/identity", app.demoIdentity)
  mux.HandleFunc("/gateway/forward", app.forward)
  mux.HandleFunc("/webhooks/solvegio", app.solvegioWebhook)
  mux.Handle("/", http.FileServer(http.Dir("./web")))

  srv := &http.Server{
    Addr: ":" + cfg.Port, Handler: mux,
    ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second,
    WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second,
  }
  log.Printf("QuantZen gateway listening on :%s", cfg.Port)
  log.Fatal(srv.ListenAndServe())
}

func (a *App) health(w http.ResponseWriter, _ *http.Request) {
  httpx.JSON(w, http.StatusOK, map[string]any{"status":"ok","version":"0.1.0-mvp"})
}

func (a *App) dashboard(w http.ResponseWriter, _ *http.Request) {
  httpx.JSON(w, http.StatusOK, map[string]any{
    "protected_requests": 12482 + a.requests.Load(),
    "verified": 12391 + a.verified.Load(),
    "blocked": 91 + a.blocked.Load(),
    "replay_attacks": 27 + a.replays.Load(),
    "invalid_signatures": 38 + a.invalid.Load(),
    "unknown_keys": 11 + a.unknown.Load(),
    "webhook_events": 412 + a.webhooks.Load(),
    "events": a.audit.List(),
  })
}

func (a *App) registry(w http.ResponseWriter, _ *http.Request) {
  httpx.JSON(w, http.StatusOK, a.trust.List())
}

func (a *App) auditLog(w http.ResponseWriter, _ *http.Request) {
  httpx.JSON(w, http.StatusOK, a.audit.List())
}

func (a *App) solvegioStatus(w http.ResponseWriter, _ *http.Request) {
  env := "DEMO"
  if a.solvegio.Configured() {
    env = "SANDBOX/CONFIGURED"
  }
  httpx.JSON(w, http.StatusOK, map[string]any{
    "environment": env,
    "api_connection": a.solvegio.Configured(),
    "webhook_status": a.cfg.WebhookSecret != "",
    "last_event": time.Now().UTC().Format("15:04:05"),
  })
}

func (a *App) demoIdentity(w http.ResponseWriter, _ *http.Request) {
  id, _ := a.keys.Get("qz-key-001")
  httpx.JSON(w, http.StatusOK, map[string]any{
    "kid": id.KeyID,
    "ed25519_public": base64.RawURLEncoding.EncodeToString(id.EdPublic),
    "mldsa65_public": base64.RawURLEncoding.EncodeToString(id.PQPublic.Bytes()),
    "fingerprint": id.Fingerprint,
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
    "X-QZ-Version": protocol.Version,
    "X-QZ-Key-Id": id.KeyID,
    "X-QZ-Timestamp": timestamp,
    "X-QZ-Nonce": nonce,
    "X-QZ-Content-Digest": digest,
    "X-QZ-Signature-Ed25519": ed,
    "X-QZ-Signature-MLDSA65": pq,
  }
}

func (a *App) verifyRequest(tenant string, h http.Header, body []byte, method, p string) (string, string, string) {
  env, err := protocol.FromHeaders(h)
  if err != nil { return "400", "BLOCK", "INVALID_SIGNATURE" }
  if env.Version != protocol.Version { return "400", "BLOCK", "INVALID_SIGNATURE" }

  canon, err := canonical.JSON(body)
  if err != nil { return "400", "BLOCK", "INVALID_JSON" }
  digest := protocol.Digest(canon)
  if !strings.EqualFold(digest, env.ContentDigest) { return "400", "BLOCK", "PAYLOAD_TAMPERED" }

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
  if method == "" { method = http.MethodPost }

  _, decision, detail := a.verifyRequest(r.Header.Get("X-Tenant"), r.Header, body, method, target)
  if decision != "ALLOW" {
    httpx.Error(w, http.StatusUnauthorized, detail)
    return
  }

  start := time.Now()
  code, headers, resp, err := a.solvegio.Do(r.Context(), method, target, bytes.NewReader(body))
  if err != nil {
    httpx.Error(w, http.StatusBadGateway, err.Error())
    return
  }
  for k, v := range headers {
    if strings.EqualFold(k, "Content-Type") && len(v) > 0 {
      w.Header().Set(k, v[0])
    }
  }
  latency := time.Since(start).Milliseconds()
  a.requests.Add(1)
  a.verified.Add(1)
  e := a.audit.Add(audit.Event{
    Type: detail, Endpoint: target, Tenant: r.Header.Get("X-Tenant"),
    KeyID: r.Header.Get("X-QZ-Key-Id"), Decision: "ALLOW",
    LatencyMs: latency, Details: fmt.Sprintf("upstream=%d", code),
  })
  _ = a.db.Insert(r.Context(), e)
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
  var in struct{ Scenario string }
  _ = json.NewDecoder(r.Body).Decode(&in)
  if in.Scenario == "" { in.Scenario = "valid" }

  body, _ := json.Marshal(map[string]any{
    "pricing_id": "demo-pricing",
    "buyer": map[string]string{"email": "demo@example.com"},
  })
  headers := make(http.Header)
  for k, v := range a.signDemo(http.MethodPost, "/v1/payments", body) {
    headers.Set(k, v)
  }

  switch in.Scenario {
  case "invalid_signature":
    headers.Set("X-QZ-Signature-MLDSA65", "bad")
  case "tampered_payload":
    body, _ = json.Marshal(map[string]any{"pricing_id":"tampered","buyer":map[string]string{"email":"demo@example.com"}})
  case "expired_timestamp":
    headers.Set("X-QZ-Timestamp", fmt.Sprint(time.Now().Add(-10*time.Minute).Unix()))
  case "reused_nonce":
    _, _ = a.replay.Claim(context.Background(), "qz:partner-demo:"+headers.Get("X-QZ-Nonce"), 5*time.Minute)
  case "revoked_key":
    a.trust.Revoke("qz-key-001")
  case "unknown_key":
    headers.Set("X-QZ-Key-Id", "unknown-key")
  case "duplicate_webhook":
    eventID := "evt_demo_001"
    _, _ = a.replay.Claim(context.Background(), "webhook:"+eventID, 24*time.Hour)
    claimed, _ := a.replay.Claim(context.Background(), "webhook:"+eventID, 24*time.Hour)
    lat := time.Now().UnixNano()
    _ = lat
    detail := "DUPLICATE_WEBHOOK"
    decision := "BLOCK"
    if claimed { decision = "ALLOW"; detail = "WEBHOOK_ACCEPTED" }
    e := a.audit.Add(audit.Event{Type:detail,Endpoint:"/webhooks/solvegio",Tenant:"partner-demo",Decision:decision,Details:"event_id="+eventID})
    _ = a.db.Insert(r.Context(), e)
    httpx.JSON(w, http.StatusOK, map[string]any{"scenario":in.Scenario,"decision":decision,"status":"409","details":detail})
    return
  }

  status, decision, detail := a.verifyRequest("partner-demo", headers, body, http.MethodPost, "/v1/payments")
  if in.Scenario == "revoked_key" {
    a.trust.Activate("qz-key-001")
  }
  a.requests.Add(1)
  if decision == "ALLOW" { a.verified.Add(1) } else { a.blocked.Add(1) }
  e := a.audit.Add(audit.Event{Type:detail,Endpoint:"/v1/payments",Tenant:"partner-demo",KeyID:headers.Get("X-QZ-Key-Id"),Decision:decision,Details:status})
  _ = a.db.Insert(r.Context(), e)
  httpx.JSON(w, http.StatusOK, map[string]any{"scenario":in.Scenario,"decision":decision,"status":status,"details":detail})
}

func (a *App) solvegioWebhook(w http.ResponseWriter, r *http.Request) {
  body, err := io.ReadAll(io.LimitReader(r.Body, 4<<20))
  if err != nil {
    httpx.Error(w, http.StatusBadRequest, "read error")
    return
  }
  a.webhooks.Add(1)

  if err = webhook.Verify(r, body, a.cfg.WebhookSecret, a.cfg.TimestampTolerance); err != nil {
    e := a.audit.Add(audit.Event{Type:"INVALID_WEBHOOK_SIGNATURE",Endpoint:"/webhooks/solvegio",Decision:"BLOCK",Details:err.Error()})
    _ = a.db.Insert(r.Context(), e)
    httpx.Error(w, http.StatusUnauthorized, err.Error())
    return
  }

  var event struct{ ID string }
  _ = json.Unmarshal(body, &event)
  if event.ID != "" {
    claimed, claimErr := a.replay.Claim(r.Context(), "webhook:"+event.ID, 24*time.Hour)
    if claimErr != nil || !claimed {
      e := a.audit.Add(audit.Event{Type:"DUPLICATE_WEBHOOK",Endpoint:"/webhooks/solvegio",Decision:"BLOCK",Details:"event_id="+event.ID})
      _ = a.db.Insert(r.Context(), e)
      httpx.Error(w, http.StatusConflict, "DUPLICATE_WEBHOOK")
      return
    }
  }

  e := a.audit.Add(audit.Event{Type:"WEBHOOK_VERIFIED",Endpoint:"/webhooks/solvegio",Decision:"ALLOW",Details:"SolveGio HMAC verified"})
  _ = a.db.Insert(r.Context(), e)
  httpx.JSON(w, http.StatusOK, map[string]any{"ok":true,"audit_hash":e.Hash})
}
