package protocol

import (
  "crypto/sha256"
  "encoding/base64"
  "fmt"
  "net/http"
  "strconv"
  "strings"
)

const Version = "QZ-HYBRID-1"

func Digest(body []byte) string {
  sum := sha256.Sum256(body)
  return base64.RawURLEncoding.EncodeToString(sum[:])
}

func SigningString(method, p, timestamp, nonce, digest string) string {
  return strings.Join([]string{Version, strings.ToUpper(method), p, timestamp, nonce, "sha256=" + digest}, "
")
}

type Envelope struct {
  Version string
  KeyID string
  Timestamp int64
  Nonce string
  ContentDigest string
  Ed25519Signature string
  MLDSASignature string
}

func FromHeaders(h http.Header) (Envelope, error) {
  v := h.Get("X-QZ-Version")
  t, err := strconv.ParseInt(h.Get("X-QZ-Timestamp"), 10, 64)
  if err != nil { return Envelope{}, fmt.Errorf("invalid timestamp") }
  e := Envelope{Version:v, KeyID:h.Get("X-QZ-Key-Id"), Timestamp:t, Nonce:h.Get("X-QZ-Nonce"), ContentDigest:strings.TrimPrefix(h.Get("X-QZ-Content-Digest"),"sha256="), Ed25519Signature:h.Get("X-QZ-Signature-Ed25519"), MLDSASignature:h.Get("X-QZ-Signature-MLDSA65")}
  if e.Version=="" || e.KeyID=="" || e.Nonce=="" || e.ContentDigest=="" || e.Ed25519Signature=="" || e.MLDSASignature=="" { return Envelope{}, fmt.Errorf("missing QuantZen signature headers") }
  return e,nil
}
