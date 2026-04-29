package routeradmin

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"time"
)

type Client interface {
	Collect(ctx context.Context) (Inventory, error)
}

func NewClient(cfg Config) (Client, error) {
	normalized, err := normalizeConfig(cfg)
	if err != nil {
		return nil, err
	}
	switch detectProvider(normalized) {
	case ProviderXfinity:
		return NewXfinityClient(normalized)
	default:
		return nil, fmt.Errorf("unsupported router admin provider %q", normalized.Provider)
	}
}

func normalizeConfig(cfg Config) (Config, error) {
	cfg.Provider = strings.ToLower(strings.TrimSpace(cfg.Provider))
	if cfg.Provider == "" {
		cfg.Provider = ProviderAuto
	}
	cfg.BaseURL = strings.TrimSpace(cfg.BaseURL)
	cfg.Username = strings.TrimSpace(cfg.Username)
	cfg.Password = strings.TrimSpace(cfg.Password)
	cfg.UserAgent = strings.TrimSpace(cfg.UserAgent)
	if cfg.UserAgent == "" {
		cfg.UserAgent = "netwise-router-admin/1.0"
	}
	if cfg.Timeout <= 0 {
		cfg.Timeout = 4 * time.Second
	}
	if cfg.BaseURL == "" || cfg.Username == "" || cfg.Password == "" {
		return cfg, fmt.Errorf("router admin config requires base_url, username, and password")
	}
	parsed, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return cfg, fmt.Errorf("parse router admin url: %w", err)
	}
	if parsed.Scheme == "" || parsed.Host == "" {
		return cfg, fmt.Errorf("router admin url must include scheme and host")
	}
	parsed.Path = strings.TrimRight(parsed.Path, "/")
	parsed.RawPath = parsed.Path
	parsed.RawQuery = ""
	parsed.Fragment = ""
	parsed.User = nil
	cfg.BaseURL = strings.TrimRight(parsed.String(), "/")
	return cfg, nil
}

func detectProvider(cfg Config) string {
	if cfg.Provider != "" && cfg.Provider != ProviderAuto {
		return cfg.Provider
	}
	parsed, err := url.Parse(cfg.BaseURL)
	if err != nil {
		return cfg.Provider
	}
	host := strings.ToLower(parsed.Hostname())
	if host == "10.0.0.1" {
		return ProviderXfinity
	}
	return cfg.Provider
}
