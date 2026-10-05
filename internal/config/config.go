package config

import (
	"os"
	"strconv"
	"time"
)

type Config struct {
	Port                 string
	SolveGioBaseURL      string
	SolveGioAPIKey       string
	SolveGioTimeout      time.Duration
	WebhookSecret        string
	RedisURL             string
	DatabaseURL          string
	TimestampTolerance   time.Duration
	DashboardUsername    string
	DashboardPassword    string
	DashboardSessionSecret string
	DashboardSessionTTL  time.Duration
}

func Load() Config {
	return Config{
		Port:                   env("PORT", "8080"),
		SolveGioBaseURL:        os.Getenv("SOLVEGIO_BASE_URL"),
		SolveGioAPIKey:         os.Getenv("SOLVEGIO_API_KEY"),
		SolveGioTimeout:        time.Duration(envInt("SOLVEGIO_TIMEOUT_SECONDS", 15)) * time.Second,
		WebhookSecret:          os.Getenv("WEBHOOK_SECRET"),
		RedisURL:               os.Getenv("REDIS_URL"),
		DatabaseURL:            os.Getenv("DATABASE_URL"),
		TimestampTolerance:     time.Duration(envInt("QZ_TIMESTAMP_TOLERANCE_SECONDS", 300)) * time.Second,
		DashboardUsername:      os.Getenv("DASHBOARD_USERNAME"),
		DashboardPassword:      os.Getenv("DASHBOARD_PASSWORD"),
		DashboardSessionSecret: os.Getenv("DASHBOARD_SESSION_SECRET"),
		DashboardSessionTTL:    time.Duration(envInt("DASHBOARD_SESSION_TTL_SECONDS", 28800)) * time.Second,
	}
}

func env(k, fallback string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return fallback
}

func envInt(k string, fallback int) int {
	v, err := strconv.Atoi(os.Getenv(k))
	if err != nil || v <= 0 {
		return fallback
	}
	return v
}
