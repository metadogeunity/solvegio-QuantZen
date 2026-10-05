package hybrid

import (
  "crypto/ed25519"
  "crypto/rand"
  "crypto/sha256"
  "encoding/base64"
  "fmt"
  "sync"
  mldsa65 "github.com/trailofbits/ml-dsa/mldsa65"
)

type Identity struct {
  KeyID string
  EdPrivate ed25519.PrivateKey
  EdPublic ed25519.PublicKey
  PQPrivate *mldsa65.PrivateKey
  PQPublic *mldsa65.PublicKey
  Fingerprint string
}

func GenerateIdentity(keyID string) (*Identity,error) {
  pub,priv,err:=ed25519.GenerateKey(rand.Reader); if err!=nil{return nil,err}
  pqPub,pqPriv,err:=mldsa65.GenerateKeyPair(rand.Reader); if err!=nil{return nil,err}
  h:=sha256.New(); _,_=h.Write(pub); _,_=h.Write(pqPub.Bytes())
  return &Identity{KeyID:keyID,EdPrivate:priv,EdPublic:pub,PQPrivate:pqPriv,PQPublic:pqPub,Fingerprint:fmt.Sprintf("sha256:%x",h.Sum(nil)[:12])},nil
}

func Sign(id *Identity,msg []byte)(string,string,error){
  ed:=ed25519.Sign(id.EdPrivate,msg); pq,err:=id.PQPrivate.Sign(rand.Reader,msg,nil); if err!=nil{return "","",err}
  return base64.RawURLEncoding.EncodeToString(ed),base64.RawURLEncoding.EncodeToString(pq),nil
}

func Verify(edPub ed25519.PublicKey,pqPub *mldsa65.PublicKey,msg []byte,edSig,pqSig string)(bool,bool,error){
  ed,err:=base64.RawURLEncoding.DecodeString(edSig);if err!=nil{return false,false,err}
  pq,err:=base64.RawURLEncoding.DecodeString(pqSig);if err!=nil{return false,false,err}
  return ed25519.Verify(edPub,msg,ed),pqPub.Verify(msg,pq),nil
}

type KeyStore struct{mu sync.RWMutex; keys map[string]*Identity}
func NewKeyStore(id *Identity)*KeyStore{return &KeyStore{keys:map[string]*Identity{id.KeyID:id}}}
func (k *KeyStore)Get(id string)(*Identity,bool){k.mu.RLock();defer k.mu.RUnlock();v,ok:=k.keys[id];return v,ok}
