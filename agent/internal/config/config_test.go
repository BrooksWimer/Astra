package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRouterAdminEnvOverridesDefault(t *testing.T) {
	t.Setenv("NETWISE_ROUTER_ADMIN_PROVIDER", "xfinity")
	t.Setenv("NETWISE_ROUTER_ADMIN_URL", " http://10.0.0.1 ")
	t.Setenv("NETWISE_ROUTER_ADMIN_USERNAME", " admin ")
	t.Setenv("NETWISE_ROUTER_ADMIN_PASSWORD", "secret")
	t.Setenv("NETWISE_ROUTER_ADMIN_TIMEOUT_MS", "7500")

	cfg := Default()
	if cfg.RouterAdminProvider != "xfinity" {
		t.Fatalf("provider override failed: %q", cfg.RouterAdminProvider)
	}
	if cfg.RouterAdminURL != "http://10.0.0.1" {
		t.Fatalf("url override failed: %q", cfg.RouterAdminURL)
	}
	if cfg.RouterAdminUsername != "admin" {
		t.Fatalf("username override failed: %q", cfg.RouterAdminUsername)
	}
	if cfg.RouterAdminPassword != "secret" {
		t.Fatal("password override failed")
	}
	if cfg.RouterAdminTimeoutMs != 7500 {
		t.Fatalf("timeout override failed: %d", cfg.RouterAdminTimeoutMs)
	}
}

func TestRouterAdminEnvOverridesLoadedConfig(t *testing.T) {
	t.Setenv("NETWISE_ROUTER_ADMIN_PROVIDER", "xfinity")
	t.Setenv("NETWISE_ROUTER_ADMIN_URL", "http://env-router.local")
	t.Setenv("NETWISE_ROUTER_ADMIN_USERNAME", "env-admin")
	t.Setenv("NETWISE_ROUTER_ADMIN_PASSWORD", "env-secret")
	t.Setenv("NETWISE_ROUTER_ADMIN_TIMEOUT_MS", "9000")

	path := filepath.Join(t.TempDir(), "config.json")
	payload := []byte(`{
		"router_admin_provider": "auto",
		"router_admin_url": "http://file-router.local",
		"router_admin_username": "file-admin",
		"router_admin_password": "file-secret",
		"router_admin_timeout_ms": 2500
	}`)
	if err := os.WriteFile(path, payload, 0o600); err != nil {
		t.Fatalf("write temp config: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.RouterAdminProvider != "xfinity" ||
		cfg.RouterAdminURL != "http://env-router.local" ||
		cfg.RouterAdminUsername != "env-admin" ||
		cfg.RouterAdminPassword != "env-secret" ||
		cfg.RouterAdminTimeoutMs != 9000 {
		t.Fatalf("env overrides not applied to loaded config: %#v", cfg)
	}
}

func TestRouterAdminInvalidProviderAndTimeoutNormalize(t *testing.T) {
	cfg := &Config{
		RouterAdminProvider:  "unknown",
		RouterAdminTimeoutMs: -1,
	}
	ApplyEnvOverrides(cfg)
	if cfg.RouterAdminProvider != "auto" {
		t.Fatalf("expected unknown provider to normalize to auto, got %q", cfg.RouterAdminProvider)
	}
	if cfg.RouterAdminTimeoutMs != 4000 {
		t.Fatalf("expected timeout default, got %d", cfg.RouterAdminTimeoutMs)
	}
}
