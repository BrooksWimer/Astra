package strategy

import (
	"context"
	"strconv"
	"strings"
	"time"

	"github.com/netwise/agent/internal/config"
	"github.com/netwise/agent/internal/routeradmin"
)

type RouterAdminInventory struct{}

func (s *RouterAdminInventory) Name() string {
	return "router_admin_inventory"
}

func (s *RouterAdminInventory) Collect(targets []Target, emit ObservationSink) {
	gateway, ok := routerAdminGatewayTarget(targets)
	if !ok {
		return
	}

	cfg := CurrentConfig()
	if cfg == nil {
		emitObservation(emit, s.Name(), gateway, "router_admin_inventory_status", ObservationStatusNotAvailable, map[string]string{
			"reason": "strategy_runtime_config_unavailable",
		})
		return
	}

	missing := routerAdminMissingConfigFields(cfg)
	if len(missing) > 0 {
		emitObservation(emit, s.Name(), gateway, "router_admin_inventory_status", ObservationStatusNotAvailable, map[string]string{
			"reason":         "router_admin_config_incomplete",
			"missing_fields": strings.Join(missing, ","),
		})
		return
	}

	timeout := time.Duration(cfg.RouterAdminTimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 4 * time.Second
	}
	client, err := routeradmin.NewClient(routeradmin.Config{
		Provider:  cfg.RouterAdminProvider,
		BaseURL:   cfg.RouterAdminURL,
		Username:  cfg.RouterAdminUsername,
		Password:  cfg.RouterAdminPassword,
		Timeout:   timeout,
		UserAgent: "netwise-router-admin/1.0",
	})
	if err != nil {
		emitObservation(emit, s.Name(), gateway, "router_admin_inventory_status", ObservationStatusNotAvailable, map[string]string{
			"reason": routerAdminErrorReason(err),
		})
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout+(1500*time.Millisecond))
	defer cancel()

	inventory, err := client.Collect(ctx)
	if err != nil {
		emitObservation(emit, s.Name(), gateway, "router_admin_inventory_status", "error", map[string]string{
			"reason": routerAdminErrorReason(err),
		})
		return
	}

	baseDetails := map[string]string{
		"provider": inventory.Provider,
	}
	if inventory.BaseURL != "" {
		baseDetails["base_url"] = inventory.BaseURL
	}
	emitObservation(emit, s.Name(), gateway, "router_admin_inventory_status", inventory.Status, cloneStringMap(baseDetails))
	if inventory.StatusReason != "" {
		emitObservation(emit, s.Name(), gateway, "router_admin_inventory_reason", inventory.StatusReason, cloneStringMap(baseDetails))
	}
	if inventory.ConnectedDevicesPath != "" {
		emitObservation(emit, s.Name(), gateway, "router_admin_connected_devices_path", inventory.ConnectedDevicesPath, cloneStringMap(baseDetails))
	}
	if inventory.ListPageTitle != "" {
		emitObservation(emit, s.Name(), gateway, "router_admin_list_page_title", inventory.ListPageTitle, cloneStringMap(baseDetails))
	}
	if inventory.ListPageSHA1 != "" {
		emitObservation(emit, s.Name(), gateway, "router_admin_list_page_sha1", inventory.ListPageSHA1, cloneStringMap(baseDetails))
	}
	if inventory.ListPageBytes > 0 {
		emitObservation(emit, s.Name(), gateway, "router_admin_list_page_bytes", strconv.Itoa(inventory.ListPageBytes), cloneStringMap(baseDetails))
	}

	detailStatus := "unresolved"
	if inventory.DetailPathResolved {
		detailStatus = "resolved"
	}
	emitObservation(emit, s.Name(), gateway, "router_admin_detail_path_status", detailStatus, cloneStringMap(baseDetails))
	if inventory.DetailPath != "" {
		emitObservation(emit, s.Name(), gateway, "router_admin_detail_path", inventory.DetailPath, cloneStringMap(baseDetails))
	}
	for _, candidate := range inventory.DetailCandidates {
		emitObservation(emit, s.Name(), gateway, "router_admin_detail_path_candidate", candidate, cloneStringMap(baseDetails))
	}

	emitObservation(emit, s.Name(), gateway, "router_admin_device_count", strconv.Itoa(len(inventory.Devices)), cloneStringMap(baseDetails))
	for _, device := range inventory.Devices {
		target, matched := matchRouterAdminTarget(targets, device.Name)
		details := cloneStringMap(baseDetails)
		if matched {
			emitObservation(emit, s.Name(), target, "router_admin_display_name", device.Name, details)
			continue
		}
		emitObservation(emit, s.Name(), gateway, "router_admin_device_name", device.Name, details)
	}
}

func routerAdminGatewayTarget(targets []Target) (Target, bool) {
	for _, target := range targets {
		gatewayIP := strings.TrimSpace(target.Tags["gateway"])
		if gatewayIP != "" && target.IP == gatewayIP {
			return target, true
		}
	}
	return Target{}, false
}

func routerAdminMissingConfigFields(cfg *config.Config) []string {
	if cfg == nil {
		return []string{"router_admin_url", "router_admin_username", "router_admin_password"}
	}
	missing := []string{}
	if strings.TrimSpace(cfg.RouterAdminURL) == "" {
		missing = append(missing, "router_admin_url")
	}
	if strings.TrimSpace(cfg.RouterAdminUsername) == "" {
		missing = append(missing, "router_admin_username")
	}
	if strings.TrimSpace(cfg.RouterAdminPassword) == "" {
		missing = append(missing, "router_admin_password")
	}
	return missing
}

func routerAdminErrorReason(err error) string {
	if err == nil {
		return ""
	}
	lower := strings.ToLower(err.Error())
	switch {
	case strings.Contains(lower, "requires base_url"):
		return "router_admin_config_incomplete"
	case strings.Contains(lower, "must include scheme and host"):
		return "router_admin_url_invalid"
	case strings.Contains(lower, "unsupported router admin provider"):
		return "router_admin_provider_unsupported"
	default:
		return "router_admin_request_failed"
	}
}

func matchRouterAdminTarget(targets []Target, displayName string) (Target, bool) {
	name := normalizeTargetHost(displayName)
	if name == "" {
		return Target{}, false
	}
	for _, target := range targets {
		if normalizeTargetHost(target.Hostname) == name {
			return target, true
		}
	}
	return Target{}, false
}
