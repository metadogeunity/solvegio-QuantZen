package trust

import (
  "crypto/ed25519"
  "sync"
  "time"
  mldsa65 "github.com/trailofbits/ml-dsa/mldsa65"
)

type Key struct {
  Issuer string
  KID string
  Algorithm string
  Status string
  Fingerprint string
  ValidFrom time.Time
  ValidUntil time.Time
  EdPublic ed25519.PublicKey
  PQPublic *mldsa65.PublicKey
}
type Registry struct{mu sync.RWMutex; keys map[string]Key}
func NewRegistry()*Registry{return &Registry{keys:map[string]Key{}}}
func (r *Registry)Put(k Key){r.mu.Lock();defer r.mu.Unlock();r.keys[k.KID]=k}
func (r *Registry)Get(kid string)(Key,bool){r.mu.RLock();defer r.mu.RUnlock();k,ok:=r.keys[kid];return k,ok}
func (r *Registry)List()[]Key{r.mu.RLock();defer r.mu.RUnlock();out:=make([]Key,0,len(r.keys));for _,k:=range r.keys{out=append(out,k)};return out}
func (r *Registry)Revoke(kid string)bool{r.mu.Lock();defer r.mu.Unlock();k,ok:=r.keys[kid];if !ok{return false};k.Status="REVOKED";r.keys[kid]=k;return true}
func (r *Registry)Activate(kid string)bool{r.mu.Lock();defer r.mu.Unlock();k,ok:=r.keys[kid];if !ok{return false};k.Status="ACTIVE";r.keys[kid]=k;return true}
