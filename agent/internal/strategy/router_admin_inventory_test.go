package strategy

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/netwise/agent/internal/config"
)

func TestRouterAdminInventoryIsExplicitOnly(t *testing.T) {
	metadata, ok := StrategyMetadataForName("router_admin_inventory")
	if !ok {
		t.Fatal("router_admin_inventory metadata missing")
	}
	if !metadata.ExplicitOnly {
		t.Fatal("router_admin_inventory must be explicit-only")
	}
	if !strategyListContains(ResolveStrategies([]string{"router_admin_inventory"}), "router_admin_inventory") {
		t.Fatal("router_admin_inventory should resolve when requested by name")
	}
	if strategyListContains(ResolveStrategies(nil), "router_admin_inventory") {
		t.Fatal("router_admin_inventory should not be in default strategy resolution")
	}
	for _, profile := range []string{"fast", "medium", "full"} {
		if stringListContains(ProfileStrategyNames(profile), "router_admin_inventory") {
			t.Fatalf("router_admin_inventory should not be in %s profile", profile)
		}
	}
}

func TestRouterAdminInventoryEmitsListObservations(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/index.jst":
			_, _ = io.WriteString(w, `<form id="pageForm" action="check.jst"><input id="username"><input id="password"></form>`)
		case "/check.jst":
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "ok", Path: "/"})
			http.Redirect(w, r, "/connected_devices_computers.jst", http.StatusFound)
		case "/connected_devices_computers.jst":
			cookie, err := r.Cookie("sid")
			if err != nil || cookie.Value != "ok" {
				_, _ = io.WriteString(w, `<script>alert("Please Login First!"); location.href="home_loggedout.jst";</script>`)
				return
			}
			_, _ = io.WriteString(w, `<html><head><title>Connected Devices</title></head><body><a href="javascript:void(0)" onclick="showDetail('device_detail.jst?id=1')">Laptop</a></body></html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	SetRuntimeConfig(&config.Config{
		RouterAdminProvider:  "xfinity",
		RouterAdminURL:       server.URL,
		RouterAdminUsername:  "admin",
		RouterAdminPassword:  "secret",
		RouterAdminTimeoutMs: 2000,
	})
	defer SetRuntimeConfig(nil)

	targets := []Target{
		{IP: "10.0.0.1", Tags: map[string]string{"gateway": "10.0.0.1"}},
		{IP: "10.0.0.44", Hostname: "Laptop"},
	}
	var observations []Observation
	(&RouterAdminInventory{}).Collect(targets, func(obs Observation) {
		observations = append(observations, obs)
	})

	assertObservation(t, observations, "router_admin_inventory_status", "page_fetched")
	assertObservation(t, observations, "router_admin_connected_devices_path", "/connected_devices_computers.jst")
	assertObservation(t, observations, "router_admin_device_count", "1")
	assertObservation(t, observations, "router_admin_display_name", "Laptop")
	assertObservation(t, observations, "router_admin_detail_path_status", "resolved")
}

func TestRouterAdminInventoryMissingConfigEmitsUnavailable(t *testing.T) {
	SetRuntimeConfig(&config.Config{})
	defer SetRuntimeConfig(nil)

	var observations []Observation
	(&RouterAdminInventory{}).Collect([]Target{
		{IP: "10.0.0.1", Tags: map[string]string{"gateway": "10.0.0.1"}},
	}, func(obs Observation) {
		observations = append(observations, obs)
	})
	assertObservation(t, observations, "router_admin_inventory_status", ObservationStatusNotAvailable)
}

func assertObservation(t *testing.T, observations []Observation, key, value string) {
	t.Helper()
	for _, observation := range observations {
		if observation.Key == key && observation.Value == value {
			return
		}
	}
	t.Fatalf("missing observation key=%q value=%q in %#v", key, value, observations)
}

func strategyListContains(strategies []Strategy, name string) bool {
	for _, strategy := range strategies {
		if strategy.Name() == name {
			return true
		}
	}
	return false
}

func stringListContains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
