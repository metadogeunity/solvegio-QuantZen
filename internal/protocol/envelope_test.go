package protocol

import (
	"net/http"
	"strings"
	"testing"
)

func TestSigningStringBindsTenant(t *testing.T) {
	a := SigningString("tenant-a", "POST", "/v1/payments", "1", "n", "d")
	b := SigningString("tenant-b", "POST", "/v1/payments", "1", "n", "d")
	if a == b {
		t.Fatal("tenant must be included in signature target")
	}
}

func TestFromHeadersRejectsOversizedSignatures(t *testing.T) {
	h := make(http.Header)
	h.Set("X-QZ-Version", Version)
	h.Set("X-QZ-Key-Id", "kid")
	h.Set("X-QZ-Timestamp", "1")
	h.Set("X-QZ-Nonce", "nonce")
	h.Set("X-QZ-Content-Digest", "digest")
	h.Set("X-QZ-Signature-Ed25519", strings.Repeat("a", 257))
	h.Set("X-QZ-Signature-MLDSA65", strings.Repeat("a", 10))
	if _, err := FromHeaders(h); err == nil {
		t.Fatal("expected oversized signature rejection")
	}
}
