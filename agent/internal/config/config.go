package config

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
)

// ScanMode: quick 2-5s, standard 10-20s, deep 30-60s
const (
	ScanModeQuick    = "quick"
	ScanModeStandard = "standard"
	ScanModeDeep     = "deep"
)

type Config struct {
	EnablePortScan              bool               `json:"enable_port_scan"`
	PortsToCheck                []int              `json:"ports_to_check"`
	ScanTimeoutSeconds          int                `json:"scan_timeout_seconds"`
	ScanMode                    string             `json:"scan_mode"`
	StrategyProfile             string             `json:"strategy_profile"`
	MaxProbeIPs                 int                `json:"max_probe_ips"`         // 0 = no limit; used when subnet is large
	LargeSubnetThrottle         bool               `json:"large_subnet_throttle"` // if true, cap probes on /16 or larger
	StrategyProbeTimeoutMs      int                `json:"strategy_probe_timeout_ms"`
	StrategyCommandTimeoutMs    int                `json:"strategy_command_timeout_ms"`
	PassiveCaptureEnabled       bool               `json:"passive_capture_enabled"`
	PassiveCaptureWindowSeconds int                `json:"passive_capture_window_seconds,omitempty"`
	PassiveCaptureInterface     string             `json:"passive_capture_interface,omitempty"`
	PassiveCapturePromiscuous   bool               `json:"passive_capture_promiscuous,omitempty"`
	PassiveCaptureSnaplen       int                `json:"passive_capture_snaplen,omitempty"`
	PassiveCaptureBufferPackets int                `json:"passive_capture_buffer_packets,omitempty"`
	PassiveInfraEnabled         bool               `json:"passive_infra_enabled,omitempty"`
	PassiveSyslogListenAddr     string             `json:"passive_syslog_listen_addr,omitempty"`
	PassiveResolverLogPath      string             `json:"passive_resolver_log_path,omitempty"`
	PassiveDHCPLogPath          string             `json:"passive_dhcp_log_path,omitempty"`
	PassiveSessionSource        string             `json:"passive_session_source,omitempty"`
	PassiveSessionCommand       string             `json:"passive_session_command,omitempty"`
	SNMPCommunities             []string           `json:"snmp_communities,omitempty"`
	SNMPVersions                []string           `json:"snmp_versions,omitempty"`
	SNMPV3Username              string             `json:"snmp_v3_username,omitempty"`
	SNMPV3AuthPassword          string             `json:"snmp_v3_auth_password,omitempty"`
	SNMPV3PrivPassword          string             `json:"snmp_v3_priv_password,omitempty"`
	HTTPAPIUsername             string             `json:"http_api_username,omitempty"`
	HTTPAPIPassword             string             `json:"http_api_password,omitempty"`
	APIBearerToken              string             `json:"api_bearer_token,omitempty"`
	RouterAdminProvider         string             `json:"router_admin_provider,omitempty"`
	RouterAdminURL              string             `json:"router_admin_url,omitempty"`
	RouterAdminUsername         string             `json:"router_admin_username,omitempty"`
	RouterAdminPassword         string             `json:"router_admin_password,omitempty"`
	RouterAdminTimeoutMs        int                `json:"router_admin_timeout_ms,omitempty"`
	SMBUsername                 string             `json:"smb_username,omitempty"`
	SMBPassword                 string             `json:"smb_password,omitempty"`
	SMBDomain                   string             `json:"smb_domain,omitempty"`
	ControllerEndpoints         []string           `json:"controller_endpoints,omitempty"`
	AutoActionThreshold         float64            `json:"auto_action_threshold"`
	AutoLabelThreshold          float64            `json:"auto_label_threshold"`
	ConfirmThreshold            float64            `json:"confirm_threshold"`
	UnknownThreshold            float64            `json:"unknown_threshold"`
	DNSPrivacyMode              string             `json:"dns_privacy_mode"` // full | hashed-domain | category-only
	LabelingMode                string             `json:"labeling_mode"`    // hybrid | rules-only | fusion-only
	CalibrationMode             string             `json:"calibration_mode"` // isotonic | sigmoid
	CategoryThresholdOverrides  map[string]float64 `json:"category_threshold_overrides,omitempty"`
	AutoPolicyEnabled           bool               `json:"auto_policy_enabled"`
	QualityGateEnabled          bool               `json:"quality_gate_enabled"`
	QualityGateMinDevices       int                `json:"quality_gate_min_devices"`
	QualityGateMinMacroF1       float64            `json:"quality_gate_min_macro_f1"`
	QualityGateMaxECE           float64            `json:"quality_gate_max_ece"`
	SNMPCredentialedCollection  bool               `json:"snmp_credentialed_collection"`
}

func Default() *Config {
	cfg := &Config{
		EnablePortScan:              false,
		PortsToCheck:                []int{22, 80, 443, 445, 554, 631, 3389, 8009, 1900},
		ScanTimeoutSeconds:          20,
		ScanMode:                    ScanModeStandard,
		StrategyProfile:             "full",
		MaxProbeIPs:                 0,
		LargeSubnetThrottle:         true,
		StrategyProbeTimeoutMs:      900,
		StrategyCommandTimeoutMs:    1800,
		PassiveCaptureEnabled:       false,
		PassiveCaptureWindowSeconds: 120,
		PassiveCaptureInterface:     "primary",
		PassiveCapturePromiscuous:   false,
		PassiveCaptureSnaplen:       262144,
		PassiveCaptureBufferPackets: 4096,
		PassiveInfraEnabled:         false,
		SNMPCommunities:             []string{"public"},
		SNMPVersions:                []string{"2c"},
		RouterAdminProvider:         "auto",
		RouterAdminTimeoutMs:        4000,
		AutoActionThreshold:         0.95,
		AutoLabelThreshold:          0.75,
		ConfirmThreshold:            0.50,
		UnknownThreshold:            0.50,
		DNSPrivacyMode:              "full",
		LabelingMode:                "hybrid",
		CalibrationMode:             "isotonic",
		CategoryThresholdOverrides: map[string]float64{
			"printer": 0.80,
			"router":  0.80,
			"camera":  0.80,
		},
		AutoPolicyEnabled:          false,
		QualityGateEnabled:         true,
		QualityGateMinDevices:      25,
		QualityGateMinMacroF1:      0.80,
		QualityGateMaxECE:          0.10,
		SNMPCredentialedCollection: false,
	}
	ApplyEnvOverrides(cfg)
	return cfg
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, err
	}
	if c.ScanTimeoutSeconds <= 0 {
		c.ScanTimeoutSeconds = 20
	}
	if c.StrategyProbeTimeoutMs <= 0 {
		c.StrategyProbeTimeoutMs = 900
	}
	if c.StrategyCommandTimeoutMs <= 0 {
		c.StrategyCommandTimeoutMs = 1800
	}
	if c.PassiveCaptureWindowSeconds <= 0 {
		c.PassiveCaptureWindowSeconds = 120
	}
	if c.PassiveCaptureSnaplen <= 0 {
		c.PassiveCaptureSnaplen = 262144
	}
	if c.PassiveCaptureBufferPackets <= 0 {
		c.PassiveCaptureBufferPackets = 4096
	}
	if len(c.PortsToCheck) == 0 {
		c.PortsToCheck = []int{22, 80, 443, 445, 554, 631, 3389, 8009, 1900}
	}
	if c.ScanMode == "" {
		c.ScanMode = ScanModeStandard
	}
	c.StrategyProfile = strings.ToLower(strings.TrimSpace(c.StrategyProfile))
	if c.StrategyProfile == "" {
		c.StrategyProfile = "full"
	}
	// Apply scan mode defaults
	switch c.ScanMode {
	case ScanModeQuick:
		if c.ScanTimeoutSeconds > 5 {
			c.ScanTimeoutSeconds = 5
		}
	case ScanModeDeep:
		if c.ScanTimeoutSeconds < 30 {
			c.ScanTimeoutSeconds = 45
		}
	}
	if c.LargeSubnetThrottle && c.MaxProbeIPs <= 0 {
		c.MaxProbeIPs = 512 // cap for /16 or larger
	}
	if c.AutoActionThreshold <= 0 || c.AutoActionThreshold > 1 {
		c.AutoActionThreshold = 0.95
	}
	if c.AutoLabelThreshold <= 0 || c.AutoLabelThreshold > 1 {
		c.AutoLabelThreshold = 0.75
	}
	if c.ConfirmThreshold <= 0 || c.ConfirmThreshold > 1 {
		c.ConfirmThreshold = 0.50
	}
	if c.UnknownThreshold <= 0 || c.UnknownThreshold > 1 {
		c.UnknownThreshold = 0.50
	}
	switch strings.ToLower(strings.TrimSpace(c.LabelingMode)) {
	case "", "hybrid", "rules-only", "fusion-only":
		// keep
	default:
		c.LabelingMode = "hybrid"
	}
	if c.LabelingMode == "" {
		c.LabelingMode = "hybrid"
	}
	switch strings.ToLower(strings.TrimSpace(c.CalibrationMode)) {
	case "", "isotonic", "sigmoid":
		// keep
	default:
		c.CalibrationMode = "isotonic"
	}
	if c.CalibrationMode == "" {
		c.CalibrationMode = "isotonic"
	}
	m := strings.ToLower(strings.TrimSpace(c.DNSPrivacyMode))
	switch m {
	case "", "full", "hashed-domain", "category-only":
		// keep
	default:
		c.DNSPrivacyMode = "full"
	}
	if c.DNSPrivacyMode == "" {
		c.DNSPrivacyMode = "full"
	}
	if c.CategoryThresholdOverrides == nil {
		c.CategoryThresholdOverrides = map[string]float64{
			"printer": 0.80,
			"router":  0.80,
			"camera":  0.80,
		}
	}
	for key, threshold := range c.CategoryThresholdOverrides {
		normalizedKey := strings.ToLower(strings.TrimSpace(key))
		if normalizedKey == "" || threshold <= 0 || threshold > 1 {
			delete(c.CategoryThresholdOverrides, key)
			continue
		}
		if normalizedKey != key {
			delete(c.CategoryThresholdOverrides, key)
			c.CategoryThresholdOverrides[normalizedKey] = threshold
		}
	}
	if c.QualityGateMinDevices <= 0 {
		c.QualityGateMinDevices = 25
	}
	if c.QualityGateMinMacroF1 <= 0 || c.QualityGateMinMacroF1 > 1 {
		c.QualityGateMinMacroF1 = 0.80
	}
	if c.QualityGateMaxECE <= 0 || c.QualityGateMaxECE > 1 {
		c.QualityGateMaxECE = 0.10
	}
	c.PassiveCaptureInterface = strings.TrimSpace(c.PassiveCaptureInterface)
	if c.PassiveCaptureInterface == "" {
		c.PassiveCaptureInterface = "primary"
	}
	c.PassiveSyslogListenAddr = strings.TrimSpace(c.PassiveSyslogListenAddr)
	c.PassiveResolverLogPath = strings.TrimSpace(c.PassiveResolverLogPath)
	c.PassiveDHCPLogPath = strings.TrimSpace(c.PassiveDHCPLogPath)
	c.PassiveSessionSource = strings.TrimSpace(c.PassiveSessionSource)
	c.PassiveSessionCommand = strings.TrimSpace(c.PassiveSessionCommand)
	if !c.PassiveInfraEnabled && hasPassiveInfraSources(&c) {
		c.PassiveInfraEnabled = true
	}
	if len(c.SNMPCommunities) == 0 {
		c.SNMPCommunities = []string{"public"}
	}
	if len(c.SNMPVersions) == 0 {
		c.SNMPVersions = []string{"2c"}
	}
	c.SNMPCommunities = normalizeStringList(c.SNMPCommunities)
	c.SNMPVersions = normalizeStringList(c.SNMPVersions)
	c.ControllerEndpoints = normalizeStringList(c.ControllerEndpoints)
	normalizeRouterAdminConfig(&c)
	ApplyEnvOverrides(&c)
	c.SNMPV3Username = strings.TrimSpace(c.SNMPV3Username)
	c.SNMPV3AuthPassword = strings.TrimSpace(c.SNMPV3AuthPassword)
	c.SNMPV3PrivPassword = strings.TrimSpace(c.SNMPV3PrivPassword)
	c.HTTPAPIUsername = strings.TrimSpace(c.HTTPAPIUsername)
	c.HTTPAPIPassword = strings.TrimSpace(c.HTTPAPIPassword)
	c.APIBearerToken = strings.TrimSpace(c.APIBearerToken)
	c.SMBUsername = strings.TrimSpace(c.SMBUsername)
	c.SMBPassword = strings.TrimSpace(c.SMBPassword)
	c.SMBDomain = strings.TrimSpace(c.SMBDomain)
	return &c, nil
}

func ApplyEnvOverrides(c *Config) {
	if c == nil {
		return
	}
	if value, ok := lookupTrimmedEnv("NETWISE_ROUTER_ADMIN_PROVIDER"); ok {
		c.RouterAdminProvider = value
	}
	if value, ok := lookupTrimmedEnv("NETWISE_ROUTER_ADMIN_URL"); ok {
		c.RouterAdminURL = value
	}
	if value, ok := lookupTrimmedEnv("NETWISE_ROUTER_ADMIN_USERNAME"); ok {
		c.RouterAdminUsername = value
	}
	if value, ok := os.LookupEnv("NETWISE_ROUTER_ADMIN_PASSWORD"); ok && value != "" {
		c.RouterAdminPassword = value
	}
	if value, ok := lookupTrimmedEnv("NETWISE_ROUTER_ADMIN_TIMEOUT_MS"); ok {
		if parsed, err := strconv.Atoi(value); err == nil && parsed > 0 {
			c.RouterAdminTimeoutMs = parsed
		}
	}
	normalizeRouterAdminConfig(c)
}

func lookupTrimmedEnv(name string) (string, bool) {
	value, ok := os.LookupEnv(name)
	if !ok {
		return "", false
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", false
	}
	return value, true
}

func normalizeRouterAdminConfig(c *Config) {
	if c == nil {
		return
	}
	c.RouterAdminProvider = normalizeRouterAdminProvider(c.RouterAdminProvider)
	c.RouterAdminURL = strings.TrimSpace(c.RouterAdminURL)
	c.RouterAdminUsername = strings.TrimSpace(c.RouterAdminUsername)
	if c.RouterAdminTimeoutMs <= 0 {
		c.RouterAdminTimeoutMs = 4000
	}
}

func normalizeRouterAdminProvider(provider string) string {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "", "auto":
		return "auto"
	case "xfinity":
		return "xfinity"
	default:
		return "auto"
	}
}

func normalizeStringList(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		key := strings.ToLower(value)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, value)
	}
	return out
}

func hasPassiveInfraSources(c *Config) bool {
	if c == nil {
		return false
	}
	return c.PassiveSyslogListenAddr != "" ||
		c.PassiveResolverLogPath != "" ||
		c.PassiveDHCPLogPath != "" ||
		c.PassiveSessionSource != "" ||
		c.PassiveSessionCommand != ""
}
