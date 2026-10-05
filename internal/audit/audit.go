package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"
)

type Event struct {
	ID        string    \`json:"id"\`
	Time      time.Time \`json:"time"\`
	Method    string    \`json:"method,omitempty"\`
	Type      string    \`json:"type"\`
	Endpoint  string    \`json:"endpoint"\`
	Tenant    string    \`json:"tenant,omitempty"\`
	KeyID     string    \`json:"key_id,omitempty"\`
	Decision  string    \`json:"decision"\`
	LatencyMs int64     \`json:"latency_ms,omitempty"\`
	Details   string    \`json:"details,omitempty"\`
	PrevHash  string    \`json:"prev_hash,omitempty"\`
	Hash      string    \`json:"hash"\`
}

type Log struct {
	mu       sync.RWMutex
	events   []Event
	lastHash string
}

func New() *Log {
	return &Log{events: make([]Event, 0, 256)}
}

func (l *Log) Add(e Event) Event {
	l.mu.Lock()
	defer l.mu.Unlock()

	if e.ID == "" {
		e.ID = fmt.Sprintf("evt-%d", time.Now().UnixNano())
	}
	e.Time = time.Now().UTC()
	e.PrevHash = l.lastHash

	b, _ := json.Marshal(e)
	s := sha256.Sum256(append([]byte(l.lastHash), b...))
	e.Hash = hex.EncodeToString(s[:])

	l.lastHash = e.Hash
	l.events = append([]Event{e}, l.events...)
	if len(l.events) > 500 {
		l.events = l.events[:500]
	}
	return e
}

func (l *Log) List() []Event {
	l.mu.RLock()
	defer l.mu.RUnlock()

	out := make([]Event, len(l.events))
	copy(out, l.events)
	return out
}
