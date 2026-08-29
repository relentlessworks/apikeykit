package config

import (
	"flag"
	"os"
)

// Config holds all service configuration.
type Config struct {
	Addr   string
	DB     string
	Secret string
	SMTP   string
}

// Load reads configuration from defaults, env vars, and CLI flags.
func Load() *Config {
	c := &Config{
		Addr:   ":7700",
		DB:     "./apikeykit.json",
		Secret: "",
		SMTP:   "",
	}

	// Env vars
	if v := os.Getenv("APIKEYKIT_ADDR"); v != "" {
		c.Addr = v
	}
	if v := os.Getenv("APIKEYKIT_DB"); v != "" {
		c.DB = v
	}
	if v := os.Getenv("APIKEYKIT_SECRET"); v != "" {
		c.Secret = v
	}
	if v := os.Getenv("APIKEYKIT_SMTP"); v != "" {
		c.SMTP = v
	}

	// Flags (override env)
	flag.StringVar(&c.Addr, "addr", c.Addr, "listen address")
	flag.StringVar(&c.DB, "db", c.DB, "database file path")
	flag.StringVar(&c.Secret, "secret", c.Secret, "token signing secret (auto-generated if empty)")
	flag.StringVar(&c.SMTP, "smtp", c.SMTP, "SMTP server for OTP email (empty = log to stderr)")
	flag.Parse()

	return c
}
