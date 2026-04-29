package routeradmin

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestXfinityClientCollectsConnectedDevicesPage(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case xfinityLoginPath:
			_, _ = io.WriteString(w, `<!doctype html><html><body><form id="pageForm" action="check.jst" method="post"><input id="username" name="username"><input id="password" name="password"><input id="locale" name="locale" value="false"></form></body></html>`)
		case xfinityLoginSubmitPath:
			if err := r.ParseForm(); err != nil {
				t.Fatalf("parse form: %v", err)
			}
			if got := r.Form.Get("username"); got != "adminuser" {
				t.Fatalf("expected lowercased username, got %q", got)
			}
			if got := r.Form.Get("password"); got != "secret" {
				t.Fatalf("expected password, got %q", got)
			}
			if got := r.Form.Get("locale"); got != "false" {
				t.Fatalf("expected locale=false, got %q", got)
			}
			http.SetCookie(w, &http.Cookie{Name: "sid", Value: "ok", Path: "/"})
			http.Redirect(w, r, xfinityConnectedDevicesPath, http.StatusFound)
		case xfinityConnectedDevicesPath:
			cookie, err := r.Cookie("sid")
			if err != nil || cookie.Value != "ok" {
				_, _ = io.WriteString(w, `<script>alert("Please Login First!"); location.href="home_loggedout.jst";</script>`)
				return
			}
			_, _ = io.WriteString(w, `
				<!doctype html>
				<html>
				<head><title>Connected Devices</title></head>
				<body>
					<div class="device-card">
						<a href="javascript:void(0)" onclick="showDetail('device_detail.jst?id=1')">Brooks</a>
					</div>
					<div class="device-card">
						<a href="javascript:void(0)" onclick="showDetail('device_detail.jst?id=2')">iPhone-83</a>
					</div>
				</body>
				</html>`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Provider: ProviderXfinity,
		BaseURL:  server.URL,
		Username: "AdminUser",
		Password: "secret",
		Timeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}

	inventory, err := client.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if inventory.Status != StatusPageFetched {
		t.Fatalf("expected status %q, got %q", StatusPageFetched, inventory.Status)
	}
	if inventory.DetailPath != "device_detail.jst" {
		t.Fatalf("expected resolved detail candidate, got %q", inventory.DetailPath)
	}
	if len(inventory.Devices) != 2 {
		t.Fatalf("expected 2 devices, got %d", len(inventory.Devices))
	}
	names := []string{inventory.Devices[0].Name, inventory.Devices[1].Name}
	if strings.Join(names, ",") != "Brooks,iPhone-83" {
		t.Fatalf("unexpected device names: %v", names)
	}
}

func TestXfinityClientReportsRejectedSession(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case xfinityLoginPath:
			_, _ = io.WriteString(w, `<form id="pageForm" action="check.jst"><input id="username"><input id="password"></form>`)
		case xfinityLoginSubmitPath:
			http.Redirect(w, r, xfinityConnectedDevicesPath, http.StatusFound)
		case xfinityConnectedDevicesPath:
			_, _ = io.WriteString(w, `<script>alert("Please Login First!"); location.href="home_loggedout.jst";</script>`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	client, err := NewClient(Config{
		Provider: ProviderXfinity,
		BaseURL:  server.URL,
		Username: "admin",
		Password: "secret",
		Timeout:  2 * time.Second,
	})
	if err != nil {
		t.Fatalf("new client: %v", err)
	}
	inventory, err := client.Collect(context.Background())
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if inventory.Status != StatusAuthRejected {
		t.Fatalf("expected auth rejection, got %q", inventory.Status)
	}
}

func TestNewClientNormalizesAndValidatesConfig(t *testing.T) {
	_, err := NewClient(Config{
		BaseURL:  "http://10.0.0.1",
		Username: "admin",
		Password: "secret",
	})
	if err != nil {
		t.Fatalf("unexpected config error: %v", err)
	}

	_, err = NewClient(Config{
		BaseURL: "10.0.0.1",
	})
	if err == nil {
		t.Fatal("expected config validation error")
	}
}

func TestDiscoverDetailPathReturnsUnresolvedOnMultipleCandidates(t *testing.T) {
	body := `
		<a href="javascript:void(0)" onclick="go('device_detail.jst?id=1')">one</a>
		<a href="javascript:void(0)" onclick="go('device_status.jst?id=2')">two</a>
		<script>var next = 'connected_devices_computers.jst';</script>
	`
	path, candidates := discoverDetailPath([]byte(body))
	if path != "" {
		t.Fatalf("expected unresolved path, got %q", path)
	}
	if len(candidates) != 2 {
		t.Fatalf("expected 2 detail candidates, got %d", len(candidates))
	}
}

func TestNormalizeConfigRejectsMissingScheme(t *testing.T) {
	_, err := normalizeConfig(Config{
		BaseURL:  (&url.URL{Host: "10.0.0.1"}).String(),
		Username: "admin",
		Password: "secret",
	})
	if err == nil {
		t.Fatal("expected invalid url error")
	}
}

func TestXfinityLiveCollect(t *testing.T) {
	if os.Getenv("NETWISE_ROUTER_ADMIN_LIVE") != "1" {
		t.Skip("set NETWISE_ROUTER_ADMIN_LIVE=1 and router-admin env vars to run the live gateway check")
	}
	cfg := Config{
		Provider: os.Getenv("NETWISE_ROUTER_ADMIN_PROVIDER"),
		BaseURL:  os.Getenv("NETWISE_ROUTER_ADMIN_URL"),
		Username: os.Getenv("NETWISE_ROUTER_ADMIN_USERNAME"),
		Password: os.Getenv("NETWISE_ROUTER_ADMIN_PASSWORD"),
		Timeout:  liveTimeoutFromEnv(),
	}
	if strings.TrimSpace(cfg.BaseURL) == "" || strings.TrimSpace(cfg.Username) == "" || cfg.Password == "" {
		t.Fatal("live router-admin check requires NETWISE_ROUTER_ADMIN_URL, NETWISE_ROUTER_ADMIN_USERNAME, and NETWISE_ROUTER_ADMIN_PASSWORD")
	}
	client, err := NewClient(cfg)
	if err != nil {
		t.Fatalf("new live client: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout+2*time.Second)
	defer cancel()
	inventory, err := client.Collect(ctx)
	if err != nil {
		t.Fatalf("live collect: %v", err)
	}
	if inventory.Status != StatusPageFetched {
		t.Fatalf("expected live status %q, got %q reason=%q", StatusPageFetched, inventory.Status, inventory.StatusReason)
	}
	if inventory.ConnectedDevicesPath == "" || inventory.ListPageBytes == 0 || inventory.ListPageSHA1 == "" {
		t.Fatalf("expected connected-device list metadata, got path=%q bytes=%d sha1=%q", inventory.ConnectedDevicesPath, inventory.ListPageBytes, inventory.ListPageSHA1)
	}
	if len(inventory.Devices) == 0 {
		t.Fatalf("expected at least one visible device label from live gateway")
	}
	t.Logf("live router-admin status=%s devices=%d list_sha1=%s detail_resolved=%t detail_candidates=%d", inventory.Status, len(inventory.Devices), inventory.ListPageSHA1, inventory.DetailPathResolved, len(inventory.DetailCandidates))
}

func liveTimeoutFromEnv() time.Duration {
	value := strings.TrimSpace(os.Getenv("NETWISE_ROUTER_ADMIN_TIMEOUT_MS"))
	if value == "" {
		return 4 * time.Second
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed <= 0 {
		return 4 * time.Second
	}
	return time.Duration(parsed) * time.Millisecond
}
