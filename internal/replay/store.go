package replay

import (
  "context"
  "sync"
  "time"
  "github.com/redis/go-redis/v9"
)

type Store interface{Claim(context.Context,string,time.Duration)(bool,error)}
type Memory struct{mu sync.Mutex; items map[string]time.Time}
func NewMemory()*Memory{return &Memory{items:map[string]time.Time{}}}
func(m *Memory)Claim(_ context.Context,key string,ttl time.Duration)(bool,error){m.mu.Lock();defer m.mu.Unlock();now:=time.Now();for k,e:=range m.items{if now.After(e){delete(m.items,k)}};if _,ok:=m.items[key];ok{return false,nil};m.items[key]=now.Add(ttl);return true,nil}
type Redis struct{client *redis.Client}
func NewRedis(raw string)(*Redis,error){o,err:=redis.ParseURL(raw);if err!=nil{return nil,err};return &Redis{client:redis.NewClient(o)},nil}
func(r *Redis)Ping(ctx context.Context)error{return r.client.Ping(ctx).Err()}
func(r *Redis)Claim(ctx context.Context,key string,ttl time.Duration)(bool,error){return r.client.SetNX(ctx,key,"1",ttl).Result()}
