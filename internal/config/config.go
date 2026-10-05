package config

import("os";"strconv";"time")
type Config struct{Port string;SolveGioBaseURL string;SolveGioAPIKey string;SolveGioTimeout time.Duration;WebhookSecret string;RedisURL string;DatabaseURL string;TimestampTolerance time.Duration}
func Load()Config{return Config{Port:env("PORT","8080"),SolveGioBaseURL:os.Getenv("SOLVEGIO_BASE_URL"),SolveGioAPIKey:os.Getenv("SOLVEGIO_API_KEY"),SolveGioTimeout:time.Duration(envInt("SOLVEGIO_TIMEOUT_SECONDS",15))*time.Second,WebhookSecret:os.Getenv("WEBHOOK_SECRET"),RedisURL:os.Getenv("REDIS_URL"),DatabaseURL:os.Getenv("DATABASE_URL"),TimestampTolerance:time.Duration(envInt("QZ_TIMESTAMP_TOLERANCE_SECONDS",300))*time.Second}}
func env(k,f string)string{if v:=os.Getenv(k);v!=""{return v};return f}
func envInt(k string,f int)int{v,e:=strconv.Atoi(os.Getenv(k));if e!=nil||v<=0{return f};return v}
