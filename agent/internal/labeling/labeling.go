package labeling

import (
	"math"
	"os"
	"sort"
	"strings"

	"github.com/netwise/agent/internal/classify"
	"github.com/netwise/agent/internal/config"
	"github.com/netwise/agent/internal/evidence"
	"github.com/netwise/agent/internal/labeling/model"
	"github.com/netwise/agent/internal/store"
)

type ConfidenceBand string

const (
	BandAutoAction  ConfidenceBand = "auto_action"
	BandAutoLabel   ConfidenceBand = "auto_label"
	BandNeedConfirm ConfidenceBand = "confirm"
	BandUnknown     ConfidenceBand = "unknown"
)

type ObservationStatus string

const (
	ObservationStatusRealData      ObservationStatus = "real_data"
	ObservationStatusNoResponse    ObservationStatus = "no_response"
	ObservationStatusUnsupported   ObservationStatus = "unsupported"
	ObservationStatusNotApplicable ObservationStatus = "not_applicable"
)

type Mode string

const (
	ModeHybrid     Mode = "hybrid"
	ModeRulesOnly  Mode = "rules_only"
	ModeFusionOnly Mode = "fusion_only"
)

type ConfidenceThresholds struct {
	AutoAction float64
	AutoLabel  float64
	Confirm    float64
	Unknown    float64
}

type Options struct {
	Mode                       Mode
	Thresholds                 ConfidenceThresholds
	CategoryThresholdOverrides map[string]float64
	Calibrator                 *model.Calibrator
	RulesEngine                RulesEngine
	FusionEngine               FusionEngine
	ModelBackend               model.Backend
}

type Option func(*Options)

type CandidateLabel struct {
	Label        string         `json:"label"`
	Score        float64        `json:"score"`
	Confidence   float64        `json:"confidence"`
	Evidence     []string       `json:"evidence"`
	SupportTiers map[string]int `json:"support_tiers,omitempty"`
}

type LabelResult struct {
	DeviceCategory            string           `json:"device_category"`
	DeviceSubType             string           `json:"device_subtype,omitempty"`
	LabelConfidence           float64          `json:"label_confidence"`
	LabelConfidenceCalibrated float64          `json:"label_confidence_calibrated"`
	EvidenceSummary           []string         `json:"evidence_summary"`
	CandidateLabels           []CandidateLabel `json:"candidate_labels"`
	ReasonChain               []string         `json:"reason_chain"`
	ConflictFlags             []string         `json:"conflict_flags"`
	ConfidenceBand            ConfidenceBand   `json:"confidence_band"`
}

type RulesEngine interface {
	Score(d store.Device, profile evidence.Profile) map[string]CandidateLabel
}

type FusionEngine interface {
	Score(profile evidence.Profile, d store.Device) map[string]CandidateLabel
}

type ruleEngineV1 struct{}
type fusionEngineWeighted struct{}

func ClassifyDevice(d store.Device, cfg *config.Config) LabelResult {
	return ClassifyDeviceWithPrivacyAndConfig(d, privacyConfigFromApp(cfg), cfg)
}

func ClassifyDeviceWithPrivacy(d store.Device, privacyCfg evidence.PrivacyConfig) LabelResult {
	return ClassifyDeviceWithOptions(d, privacyCfg)
}

func ClassifyDeviceWithPrivacyAndConfig(d store.Device, privacyCfg evidence.PrivacyConfig, cfg *config.Config) LabelResult {
	return ClassifyDeviceWithOptions(d, privacyCfg, WithConfig(cfg))
}

func ClassifyDeviceWithOptions(d store.Device, privacyCfg evidence.PrivacyConfig, opts ...Option) LabelResult {
	options := defaultOptions()
	for _, opt := range opts {
		if opt != nil {
			opt(&options)
		}
	}
	if options.Calibrator == nil {
		options.Calibrator = model.DefaultCalibrator()
	}
	if options.RulesEngine == nil {
		options.RulesEngine = ruleEngineV1{}
	}
	if options.FusionEngine == nil {
		options.FusionEngine = fusionEngineWeighted{}
	}

	filteredObservations := ActionableObservations(d.Observations)
	d.Observations = filteredObservations
	deviceID := evidence.DeviceKeyFrom(&d)
	profile := evidence.BuildProfile(deviceID, d.Observations, privacyCfg)

	ruleCandidates := map[string]CandidateLabel{}
	fusionCandidates := map[string]CandidateLabel{}

	switch options.Mode {
	case ModeRulesOnly:
		ruleCandidates = options.RulesEngine.Score(d, profile)
	case ModeFusionOnly:
		fusionCandidates = options.FusionEngine.Score(profile, d)
		fusionCandidates = mergeBackendCandidates(fusionCandidates, options.ModelBackend, profile, d)
	default:
		ruleCandidates = options.RulesEngine.Score(d, profile)
		fusionCandidates = options.FusionEngine.Score(profile, d)
		fusionCandidates = mergeBackendCandidates(fusionCandidates, options.ModelBackend, profile, d)
	}

	combined := map[string]*CandidateLabel{}
	for label, c := range ruleCandidates {
		cp := c
		combined[label] = &cp
	}
	for _, c := range fusionCandidates {
		if existing, ok := combined[c.Label]; ok {
			existing.Score += c.Score
			existing.Evidence = append(existing.Evidence, c.Evidence...)
			existing.SupportTiers = mergeSupport(existing.SupportTiers, c.SupportTiers)
			continue
		}
		cp := c
		combined[c.Label] = &cp
	}

	candidates := make([]CandidateLabel, 0, len(combined))
	for _, c := range combined {
		c.SupportTiers = normalizeSupport(c.SupportTiers)
		c.Confidence = scoreToConfidence(c.Score, c.SupportTiers)
		candidates = append(candidates, *c)
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Confidence != candidates[j].Confidence {
			return candidates[i].Confidence > candidates[j].Confidence
		}
		if candidates[i].Score != candidates[j].Score {
			return candidates[i].Score > candidates[j].Score
		}
		return candidates[i].Label < candidates[j].Label
	})

	conflictFlags := detectConflicts(candidates)
	legacy := "unknown"
	evidenceSummary := []string{}
	reasonChain := []string{}
	subtype := ""
	rawConfidence := 0.0
	calibrated := 0.0
	topEvidence := []CandidateLabel{}

	if len(candidates) > 0 {
		top := candidates[0]
		if hasLabel(top.Label) {
			legacy = top.Label
		}
		rawConfidence = top.Confidence
		calibrated = options.Calibrator.Calibrate(rawConfidence)
		evidenceSummary = dedupeFirst(top.Evidence, 6)
		reasonChain = append(reasonChain, string(options.Mode)+" top candidate: "+top.Label)
		if top.SupportTiers["strong"] > 0 && top.SupportTiers["medium"] > 0 {
			subtype = inferSubType(top, profile, d)
		}
		topEvidence = append(topEvidence, top)
	}

	if calibrated < options.Thresholds.Unknown || len(candidates) == 0 {
		conflictFlags = append(conflictFlags, "low_confidence")
		legacy = "unknown"
		calibrated = math.Min(calibrated, 0.499)
	}
	if len(conflictFlags) > 0 && calibrated >= options.Thresholds.Confirm {
		reasonChain = append(reasonChain, "conflicts_detected: "+strings.Join(conflictFlags, ","))
	}

	effectiveThresholds := applyCategoryThresholds(options.Thresholds, options.CategoryThresholdOverrides, legacy)
	band := chooseBand(calibrated, effectiveThresholds, len(conflictFlags) > 0)
	out := LabelResult{
		DeviceCategory:            legacy,
		DeviceSubType:             subtype,
		LabelConfidence:           rawConfidence,
		LabelConfidenceCalibrated: calibrated,
		EvidenceSummary:           evidenceSummary,
		ReasonChain:               append(reasonChain, topToReasons(topEvidence, confidenceToLevel(calibrated))...),
		ConflictFlags:             conflictFlags,
		ConfidenceBand:            band,
	}
	out.CandidateLabels = pruneCandidates(candidates, band)
	return out
}

func WithMode(mode Mode) Option {
	return func(o *Options) {
		if mode == "" {
			return
		}
		o.Mode = mode
	}
}

func WithConfig(cfg *config.Config) Option {
	return func(o *Options) {
		o.Thresholds = thresholdsFromConfig(cfg)
		o.Mode = modeFromConfig(cfg)
		o.CategoryThresholdOverrides = categoryThresholdOverridesFromConfig(cfg)
		o.Calibrator = calibratorFromConfig(cfg)
	}
}

func WithThresholds(thresholds ConfidenceThresholds) Option {
	return func(o *Options) {
		o.Thresholds = normalizeThresholds(thresholds)
	}
}

func WithCalibrator(cal *model.Calibrator) Option {
	return func(o *Options) {
		o.Calibrator = cal
	}
}

func WithRulesEngine(engine RulesEngine) Option {
	return func(o *Options) {
		o.RulesEngine = engine
	}
}

func WithFusionEngine(engine FusionEngine) Option {
	return func(o *Options) {
		o.FusionEngine = engine
	}
}

func WithModelBackend(backend model.Backend) Option {
	return func(o *Options) {
		o.ModelBackend = backend
	}
}

func defaultOptions() Options {
	return Options{
		Mode:                       modeFromEnv(),
		Thresholds:                 normalizeThresholds(DefaultThresholds()),
		CategoryThresholdOverrides: map[string]float64{},
		Calibrator:                 model.DefaultCalibrator(),
	}
}

func DefaultThresholds() ConfidenceThresholds {
	return ConfidenceThresholds{
		AutoAction: 0.95,
		AutoLabel:  0.75,
		Confirm:    0.50,
		Unknown:    0.50,
	}
}

func normalizeThresholds(in ConfidenceThresholds) ConfidenceThresholds {
	def := DefaultThresholds()
	if in.AutoAction > 0 && in.AutoAction <= 1 {
		def.AutoAction = in.AutoAction
	}
	if in.AutoLabel > 0 && in.AutoLabel <= 1 {
		def.AutoLabel = in.AutoLabel
	}
	if in.Confirm > 0 && in.Confirm <= 1 {
		def.Confirm = in.Confirm
	}
	if in.Unknown > 0 && in.Unknown <= 1 {
		def.Unknown = in.Unknown
	}
	if def.AutoAction < def.AutoLabel {
		def.AutoAction = def.AutoLabel
	}
	if def.AutoLabel < def.Confirm {
		def.AutoLabel = def.Confirm
	}
	if def.Unknown > def.Confirm {
		def.Unknown = def.Confirm
	}
	return def
}

func thresholdsFromConfig(cfg *config.Config) ConfidenceThresholds {
	if cfg == nil {
		return DefaultThresholds()
	}
	return normalizeThresholds(ConfidenceThresholds{
		AutoAction: cfg.AutoActionThreshold,
		AutoLabel:  cfg.AutoLabelThreshold,
		Confirm:    cfg.ConfirmThreshold,
		Unknown:    cfg.UnknownThreshold,
	})
}

func modeFromEnv() Mode {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("NETWISE_LABELING_MODE"))) {
	case string(ModeRulesOnly):
		return ModeRulesOnly
	case string(ModeFusionOnly):
		return ModeFusionOnly
	case "rules-only":
		return ModeRulesOnly
	case "fusion-only":
		return ModeFusionOnly
	default:
		return ModeHybrid
	}
}

func modeFromConfig(cfg *config.Config) Mode {
	if cfg == nil {
		return modeFromEnv()
	}
	switch strings.ToLower(strings.TrimSpace(cfg.LabelingMode)) {
	case string(ModeRulesOnly), "rules-only":
		return ModeRulesOnly
	case string(ModeFusionOnly), "fusion-only":
		return ModeFusionOnly
	default:
		return ModeHybrid
	}
}

func categoryThresholdOverridesFromConfig(cfg *config.Config) map[string]float64 {
	if cfg == nil || len(cfg.CategoryThresholdOverrides) == 0 {
		return map[string]float64{}
	}
	out := make(map[string]float64, len(cfg.CategoryThresholdOverrides))
	for key, value := range cfg.CategoryThresholdOverrides {
		normalized := normalizeLabel(key)
		if normalized == "" || value <= 0 || value > 1 {
			continue
		}
		out[normalized] = value
	}
	return out
}

func calibratorFromConfig(cfg *config.Config) *model.Calibrator {
	if cfg == nil {
		return model.DefaultCalibrator()
	}
	switch strings.ToLower(strings.TrimSpace(cfg.CalibrationMode)) {
	case "sigmoid":
		return model.NewCalibrator(sigmoidCalibrationPoints()...)
	default:
		return model.DefaultCalibrator()
	}
}

func sigmoidCalibrationPoints() []model.Point {
	return []model.Point{
		{Raw: 0.00, Calibrated: 0.01},
		{Raw: 0.10, Calibrated: 0.03},
		{Raw: 0.20, Calibrated: 0.08},
		{Raw: 0.35, Calibrated: 0.20},
		{Raw: 0.50, Calibrated: 0.50},
		{Raw: 0.65, Calibrated: 0.78},
		{Raw: 0.80, Calibrated: 0.91},
		{Raw: 0.92, Calibrated: 0.97},
		{Raw: 1.00, Calibrated: 0.99},
	}
}

func privacyConfigFromApp(cfg *config.Config) evidence.PrivacyConfig {
	if cfg == nil {
		return evidence.PrivacyConfig{DNSPrivacyMode: evidence.PrivacyModeFull}
	}
	switch strings.ToLower(strings.TrimSpace(cfg.DNSPrivacyMode)) {
	case "hashed-domain":
		return evidence.PrivacyConfig{DNSPrivacyMode: evidence.PrivacyModeHashedDomain}
	case "category-only":
		return evidence.PrivacyConfig{DNSPrivacyMode: evidence.PrivacyModeCategoryOnly}
	default:
		return evidence.PrivacyConfig{DNSPrivacyMode: evidence.PrivacyModeFull}
	}
}

func mergeBackendCandidates(existing map[string]CandidateLabel, backend model.Backend, profile evidence.Profile, d store.Device) map[string]CandidateLabel {
	if backend == nil {
		return existing
	}
	if existing == nil {
		existing = map[string]CandidateLabel{}
	}
	for _, pred := range backend.Predict(profile, d) {
		label := normalizeLabel(pred.Label)
		if !hasLabel(label) {
			continue
		}
		c, ok := existing[label]
		if !ok {
			c = CandidateLabel{Label: label, SupportTiers: map[string]int{}}
		}
		c.Score += pred.Score
		c.Evidence = append(c.Evidence, pred.Evidence...)
		c.SupportTiers = mergeSupport(c.SupportTiers, pred.SupportTiers)
		c.Confidence = scoreToConfidence(c.Score, c.SupportTiers)
		existing[label] = c
	}
	return existing
}

// Score implementation for deterministic rules.
func (ruleEngineV1) Score(d store.Device, profile evidence.Profile) map[string]CandidateLabel {
	_ = profile
	hostname := ""
	if d.Hostname != nil {
		hostname = *d.Hostname
	}
	mdns := mergeNonEmpty(
		d.ProtocolsSeen.MDNS,
		collectEvidenceValues(d, "mdns_active", "mdns_service"),
		collectEvidenceValues(d, "mdns_passive", "mdns_service"),
	)
	ssdp := mergeNonEmpty(
		d.ProtocolsSeen.SSDP,
		collectEvidenceValues(d, "ssdp_active", "ssdp_st"),
		collectEvidenceValues(d, "ssdp_passive", "ssdp_st"),
	)
	netbios := mergeNonEmpty(
		d.ProtocolsSeen.NetBIOS,
		collectEvidenceValues(d, "netbios_llmnr_passive", "netbios"),
	)
	rule := classify.Classify(
		d.Vendor,
		hostname,
		mdns,
		ssdp,
		netbios,
		d.PortsOpen,
		d.HTTPServer,
		d.TLSSubject,
		d.TLSIssuer,
		d.TLSSANS,
		d.SSHBanner,
		d.SSDPServer,
		d.MACIsLocallyAdmin,
	)

	candidates := map[string]CandidateLabel{}
	ruleLabel := normalizeLabel(rule.DeviceType)
	if hasLabel(ruleLabel) {
		candidates[ruleLabel] = CandidateLabel{
			Label:    ruleLabel,
			Score:    math.Min(1.0, rule.Confidence*2.0),
			Evidence: append([]string{}, rule.Reasons...),
			SupportTiers: map[string]int{
				"strong": 1,
				"medium": 1,
			},
		}
	}

	manual := collectEvidenceValues(d, "manual_operator_label_fallback", "manual_label")
	if len(manual) > 0 {
		m := normalizeLabel(manual[0])
		if hasLabel(m) {
			candidates[m] = CandidateLabel{
				Label:    m,
				Score:    1.15,
				Evidence: []string{"manual override"},
				SupportTiers: map[string]int{
					"strong": 1,
				},
			}
		}
	}

	return candidates
}

func (fusionEngineWeighted) Score(profile evidence.Profile, d store.Device) map[string]CandidateLabel {
	candidates := map[string]*CandidateLabel{}
	add := func(label string, score float64, evidenceText string, tier evidence.EvidenceTier) {
		label = normalizeLabel(label)
		if !hasLabel(label) {
			return
		}
		c, ok := candidates[label]
		if !ok {
			c = &CandidateLabel{
				Label:        label,
				SupportTiers: map[string]int{},
			}
			candidates[label] = c
		}
		c.Score += score
		c.Evidence = append(c.Evidence, evidenceText)
		c.SupportTiers[string(tier)]++
	}

	for _, sig := range profile.Signals {
		lowerV := strings.ToLower(sig.CanonicalValue)
		lowerK := strings.ToLower(sig.Key)
		lowerS := strings.ToLower(sig.Strategy)

		switch {
		case lowerS == "mdns_active" || lowerS == "mdns_passive":
			if containsAny(lowerV, "_ipp", "_printer", "printer", "pdl-datastream", "ipps") {
				add("printer", 1.1, "mdns_service:"+lowerV, sig.Tier)
			}
			if containsAny(lowerV, "_airplay", "raop", "googlecast", "chromecast", "airplay", "sonos", "dlna", "mediarenderer", "rendering") {
				add("tv", 0.95, "mdns_service:"+lowerV, sig.Tier)
			}
			if containsAny(lowerV, "camera", "ipcam", "webcam", "nvr", "rtsp") {
				add("camera", 0.9, "mdns_service:"+lowerV, sig.Tier)
			}
			if containsAny(lowerV, "hap", "homekit", "home-assistant", "hass") {
				add("iot", 0.5, "mdns_service:"+lowerV, sig.Tier)
			}
		case lowerS == "ssdp_active" || lowerS == "ssdp_passive":
			if containsAny(lowerV, "internetgatewaydevice", "wan", "gateway", "router") {
				add("router", 1.0, "ssdp:"+lowerV, sig.Tier)
			}
			if containsAny(lowerV, "upnp:rootdevice") && likelyGatewayIP(d.IP) {
				add("router", 0.95, "ssdp_rootdevice_gateway_ip:"+d.IP, sig.Tier)
			}
			if containsAny(lowerV, "mediarenderer", "renderingcontrol", "basicdevice", "dlna") {
				add("tv", 0.85, "ssdp:"+lowerV, sig.Tier)
			}
			if containsAny(lowerV, "printer", "ipp", "pdl") {
				add("printer", 0.9, "ssdp:"+lowerV, sig.Tier)
			}
		case strings.HasPrefix(lowerS, "upnp"):
			if containsAny(lowerV, "camera", "cam", "ipcam", "nvr") {
				add("camera", 1.0, "upnp:"+lowerV, sig.Tier)
			}
			if containsAny(lowerV, "internetgatewaydevice", "gateway", "router") {
				add("router", 0.9, "upnp:"+lowerV, sig.Tier)
			}
			if containsAny(lowerV, "printer", "ipps", "airprint") {
				add("printer", 0.9, "upnp:"+lowerV, sig.Tier)
			}
		case lowerS == "http_header_probe" || lowerS == "passive_http_metadata" || lowerS == "http_api_probe" || lowerS == "home_api_probe":
			if containsAny(lowerV, "server", "cisco", "printer", "ipps") {
				add("printer", 0.45, "http:"+lowerV, sig.Tier)
			}
			if containsAny(lowerV, "airplay", "chromecast", "plex", "sonos", "homekit") {
				add("tv", 0.4, "http:"+lowerV, sig.Tier)
			}
			if containsAny(lowerV, "hikvision", "axis", "cctv") {
				add("camera", 0.35, "http:"+lowerV, sig.Tier)
			}
		case lowerS == "media_device_probe" || lowerS == "media_device_quick_probe":
			if lowerK == "ports" {
				for _, p := range splitCSV(lowerV) {
					switch p {
					case "554":
						add("camera", 0.55, "port:"+p, sig.Tier)
					case "7000":
						add("tv", 1.45, "port:"+p, sig.Tier)
					case "8008", "8009":
						add("tv", 1.45, "port:"+p, sig.Tier)
					case "8096":
						add("tv", 0.55, "port:"+p, sig.Tier)
					}
				}
				break
			}
			if lowerK == "udp_candidate_port" {
				for _, p := range splitCSV(lowerV) {
					switch p {
					case "1900", "5000":
						add("tv", 0.25, "port:"+p, sig.Tier)
					}
				}
				break
			}
			if containsAny(lowerV, "chromecast", "google cast", "google tv", "android tv", "google home", "nest hub", "nest mini", "bravia", "roku", "airplay", "airtunes", "appletv", "apple tv", "homepod", "raop", "jellyfin", "emby", "plex") {
				add("tv", 1.0, "media:"+lowerV, sig.Tier)
			}
			if containsAny(lowerV, "camera", "nvr", "ipcam") {
				add("camera", 0.55, "media:"+lowerV, sig.Tier)
			}
		case lowerS == "tls_cert_probe" || lowerS == "passive_tls_handshake" || lowerK == "tls_subject" || lowerK == "tls_issuer" || lowerK == "tls_sans":
			if containsAny(lowerV, "camera", "cctv", "hikvision", "axis") {
				add("camera", 0.6, "tls:"+lowerV, sig.Tier)
			}
			if containsAny(lowerV, "apple", "iphone", "ipad", "macbook", "workstation") {
				add("phone", 0.35, "tls:"+lowerV, sig.Tier)
			}
		case lowerS == "snmp_system_identity":
			if lowerK == "udp_161" || lowerK == "snmp_system" || lowerV == "responsive" || lowerV == "none" || lowerV == "no_response" {
				break
			}
			if containsAny(lowerV, "printer", "laserjet", "officejet", "deskjet", "epson", "canon", "brother", "xerox", "ricoh") {
				add("printer", 1.0, "snmp:"+lowerV, sig.Tier)
			}
			if containsAny(lowerV, "camera", "hikvision", "reolink", "axis", "cctv", "nvr", "ipcam", "swann") {
				add("camera", 1.0, "snmp:"+lowerV, sig.Tier)
			}
			if containsAny(lowerV, "router", "gateway", "firewall", "eero", "netgear", "mikrotik", "tp-link", "tplink", "ubiquiti", "unifi", "arris", "cisco", "asus") {
				add("router", 0.95, "snmp:"+lowerV, sig.Tier)
			}
			if containsAny(lowerV, "chromecast", "google cast", "google tv", "apple tv", "appletv", "airplay", "sonos", "roku", "homepod", "smart tv") {
				add("tv", 0.95, "snmp:"+lowerV, sig.Tier)
			}
			if containsAny(lowerV, "iphone", "ipad", "pixel", "galaxy", "android") {
				add("phone", 0.6, "snmp:"+lowerV, sig.Tier)
			}
			if containsAny(lowerV, "macbook", "thinkpad", "latitude", "surface", "ubuntu", "debian", "windows", "workstation") {
				add("laptop", 0.45, "snmp:"+lowerV, sig.Tier)
			}
		case lowerS == "passive_ssh_banner" || lowerS == "ssh_banner_probe":
			if containsAny(lowerV, "openssh") {
				add("laptop", 0.3, "ssh:"+lowerV, sig.Tier)
			}
		case lowerS == "port_service_correlation" || lowerS == "tcp_connect_microset" || lowerK == "ports" || (lowerS == "media_device_quick_probe" && lowerK == "udp_candidate_port"):
			mediaProbe := lowerS == "media_device_probe"
			for _, p := range splitCSV(lowerV) {
				switch p {
				case "554":
					add("camera", 0.55, "port:"+p, sig.Tier)
				case "631", "9100", "80", "443":
					add("printer", 0.35, "port:"+p, sig.Tier)
				case "22", "3389":
					add("laptop", 0.35, "port:"+p, sig.Tier)
				case "1900", "5000":
					add("tv", 0.25, "port:"+p, sig.Tier)
				case "7000":
					score := 0.25
					if mediaProbe {
						score = 1.45
					}
					add("tv", score, "port:"+p, sig.Tier)
				case "8008", "8009":
					score := 0.35
					if mediaProbe {
						score = 1.45
					}
					add("tv", score, "port:"+p, sig.Tier)
				}
			}
		case lowerS == "packet_ttl_os_fingerprint":
			add("iot", 0.1, "ttl:"+sig.CanonicalValue, evidence.TierWeak)
		case lowerS == "icmp_reachability":
			add("iot", 0.05, "icmp_like:"+sig.CanonicalValue, evidence.TierContextual)
		case lowerS == "manual_operator_label_fallback" && lowerK == "manual_label":
			if lowerV == "unlabeled" {
				break
			}
			add(sig.CanonicalValue, 0.95, "manual_label:"+sig.CanonicalValue, evidence.TierStrong)
		case lowerS == "passive_dhcp_fingerprint":
			if containsAny(lowerV, "iphone", "ipad", "ios", "apple", "android", "pixel", "galaxy") {
				add("phone", 0.75, "dhcp:"+lowerV, sig.Tier)
			}
			if containsAny(lowerV, "macbook", "thinkpad", "latitude", "surface", "windows", "ubuntu", "debian") {
				add("laptop", 0.65, "dhcp:"+lowerV, sig.Tier)
			}
		case lowerS == "passive_dns_client_profile" || lowerS == "resolver_client_profile":
			if lowerK == "dns_query_category" || lowerK == "resolver_query_category" {
				switch lowerV {
				case "apple":
					add("phone", 0.22, lowerS+":"+lowerV, sig.Tier)
				case "google":
					add("phone", 0.16, lowerS+":"+lowerV, sig.Tier)
				case "microsoft":
					add("laptop", 0.22, lowerS+":"+lowerV, sig.Tier)
				case "media":
					add("tv", 0.18, lowerS+":"+lowerV, sig.Tier)
				}
			}
		case lowerS == "passive_tls_client_fingerprint":
			if lowerK == "tls_client_sni_category" {
				switch lowerV {
				case "apple":
					add("phone", 0.28, "tls_client:"+lowerV, sig.Tier)
				case "microsoft":
					add("laptop", 0.22, "tls_client:"+lowerV, sig.Tier)
				case "media":
					add("tv", 0.22, "tls_client:"+lowerV, sig.Tier)
				}
			}
		case lowerS == "passive_quic_fingerprint":
			if lowerK == "quic_sni_category" && lowerV == "apple" {
				add("phone", 0.18, "quic:"+lowerV, sig.Tier)
			}
		case lowerS == "wifi_client_association_telemetry":
			if lowerK == "wifi_roam_count" && lowerV != "" && lowerV != "0" {
				add("phone", 0.14, "wifi_roam:"+lowerV, sig.Tier)
			}
		case lowerS == "radius_8021x_identity":
			if containsAny(lowerV, "iphone", "ipad", "ios", "android", "pixel", "galaxy") {
				add("phone", 0.8, "radius:"+lowerV, sig.Tier)
			}
			if containsAny(lowerV, "macbook", "thinkpad", "latitude", "surface") {
				add("laptop", 0.7, "radius:"+lowerV, sig.Tier)
			}
		case strings.HasPrefix(lowerS, "dhcp"):
			if strings.Contains(lowerV, "ios") || strings.Contains(lowerV, "cisco") || strings.Contains(lowerV, "ubiquiti") {
				add("router", 0.3, "dhcp:"+lowerV, sig.Tier)
			}
			if strings.Contains(lowerV, "printer") {
				add("printer", 0.25, "dhcp:"+lowerV, sig.Tier)
			}
		}

		if sig.Family == evidence.FamilyIdentity {
			if lowerK == "vendor" {
				if containsAny(lowerV, "apple", "iphone", "ipad", "macbook") {
					add("phone", 0.25, "vendor:"+sig.CanonicalValue, evidence.TierWeak)
				}
				if containsAny(lowerV, "cisco", "ubiquiti", "netgear", "tplink", "huawei", "asustek", "mikrotik") {
					add("router", 0.22, "vendor:"+sig.CanonicalValue, evidence.TierWeak)
				}
			}
			if lowerK == "hostname" {
				if containsAny(lowerV, "printer", "ipp", "lp", "scan", "hplj", "canon", "epson") {
					add("printer", 0.15, "hostname:"+lowerV, evidence.TierWeak)
				}
				if containsAny(lowerV, "camera", "cam", "nvr") {
					add("camera", 0.12, "hostname:"+lowerV, evidence.TierWeak)
				}
				if containsAny(lowerV, "router", "gateway", "wan", "wifi", "ap-") {
					add("router", 0.15, "hostname:"+lowerV, evidence.TierWeak)
				}
			}
		}
	}

	out := map[string]CandidateLabel{}
	for _, c := range candidates {
		c.Confidence = scoreToConfidence(c.Score, c.SupportTiers)
		out[c.Label] = *c
	}
	return out
}

func chooseBand(calibrated float64, thresholds ConfidenceThresholds, hasConflict bool) ConfidenceBand {
	switch {
	case hasConflict && calibrated >= thresholds.Confirm:
		return BandNeedConfirm
	case calibrated >= thresholds.AutoAction:
		return BandAutoAction
	case calibrated >= thresholds.AutoLabel:
		return BandAutoLabel
	case calibrated >= thresholds.Confirm:
		return BandNeedConfirm
	default:
		return BandUnknown
	}
}

func applyCategoryThresholds(base ConfidenceThresholds, overrides map[string]float64, label string) ConfidenceThresholds {
	if len(overrides) == 0 {
		return base
	}
	override, ok := overrides[normalizeLabel(label)]
	if !ok || override <= 0 || override > 1 {
		return base
	}
	base.AutoLabel = math.Max(base.AutoLabel, override)
	return normalizeThresholds(base)
}

func detectConflicts(candidates []CandidateLabel) []string {
	if len(candidates) == 0 {
		return []string{"no_signal"}
	}
	top := candidates[0]
	if !hasLabel(top.Label) {
		return []string{"no_primary_label"}
	}

	flags := []string{}
	if top.Confidence < 0.30 || top.SupportTiers["strong"] == 0 {
		flags = append(flags, "weak_signal")
	}
	if len(candidates) > 1 {
		second := candidates[1]
		if second.SupportTiers["strong"] > 0 && top.SupportTiers["strong"] > 0 && second.Confidence >= (top.Confidence*0.75) {
			flags = append(flags, "conflicting_strong")
		}
		if !hasLabel(second.Label) {
			return flags
		}
		if second.Confidence >= (top.Confidence * 0.70) {
			flags = append(flags, "candidate_competition")
		}
	}
	return flags
}

func inferSubType(top CandidateLabel, profile evidence.Profile, d store.Device) string {
	if top.SupportTiers["strong"] == 0 {
		return ""
	}
	label := top.Label
	for _, sig := range profile.Signals {
		lowerV := strings.ToLower(sig.CanonicalValue)
		lowerS := strings.ToLower(sig.Strategy)
		switch label {
		case "printer":
			if containsAny(lowerV, "ipp", "pdl", "printer") {
				return "ipp"
			}
			if strings.Contains(lowerS, "upnp") {
				return "upnp_printer"
			}
		case "router":
			if strings.Contains(lowerV, "gateway") || strings.Contains(lowerV, "wan") {
				return "internet_gateway"
			}
		case "camera":
			if strings.Contains(lowerV, "rtsp") {
				return "rtsp"
			}
		case "tv":
			if strings.Contains(lowerV, "airplay") || strings.Contains(lowerV, "chromecast") {
				return "streaming"
			}
		}
		if strings.Contains(lowerS, "smb_") {
			if d.Vendor != "" {
				return strings.ToLower(d.Vendor)
			}
		}
	}
	return ""
}

func pruneCandidates(candidates []CandidateLabel, band ConfidenceBand) []CandidateLabel {
	if len(candidates) == 0 {
		return nil
	}
	limit := 4
	switch band {
	case BandAutoAction:
		limit = 3
	case BandAutoLabel:
		limit = 4
	case BandNeedConfirm:
		limit = 5
	case BandUnknown:
		limit = 3
	}
	out := make([]CandidateLabel, 0, min(len(candidates), limit))
	for _, c := range candidates {
		if c.Confidence < 0.02 && c.Score <= 0 {
			continue
		}
		out = append(out, c)
		if len(out) >= limit {
			break
		}
	}
	return out
}

func topToReasons(topEvidence []CandidateLabel, level confidenceLevel) []string {
	if len(topEvidence) == 0 {
		return nil
	}
	out := []string{}
	for _, c := range topEvidence {
		out = append(out, "level="+string(level))
		for _, e := range c.Evidence {
			out = append(out, c.Label+": "+e)
			if len(out) >= 4 {
				break
			}
		}
	}
	if len(out) > 4 {
		return out[:4]
	}
	return out
}

func scoreToConfidence(score float64, support map[string]int) float64 {
	if score <= 0 {
		return 0
	}
	base := math.Min(1.0, score/2.8)
	strong := support["strong"]
	medium := support["medium"]
	if strong > 0 {
		base = math.Min(1.0, base+0.15*float64(strong))
	}
	if medium > 0 {
		base = math.Min(1.0, base+0.05*float64(medium))
	}
	return math.Max(0.02, math.Min(1.0, base))
}

type confidenceLevel string

const (
	levelLow   confidenceLevel = "low"
	levelMid   confidenceLevel = "mid"
	levelHigh  confidenceLevel = "high"
	levelPrime confidenceLevel = "prime"
)

func confidenceToLevel(conf float64) confidenceLevel {
	switch {
	case conf >= 0.9:
		return levelPrime
	case conf >= 0.7:
		return levelHigh
	case conf >= 0.4:
		return levelMid
	default:
		return levelLow
	}
}

func normalizeSupport(in map[string]int) map[string]int {
	if len(in) == 0 {
		return map[string]int{}
	}
	out := map[string]int{}
	for k, v := range in {
		if v > 0 {
			out[k] = v
		}
	}
	return out
}

func mergeSupport(dst, src map[string]int) map[string]int {
	if dst == nil {
		dst = map[string]int{}
	}
	for k, v := range src {
		dst[k] += v
	}
	return dst
}

func mergeNonEmpty(base []string, extra ...[]string) []string {
	m := map[string]struct{}{}
	out := []string{}
	for _, list := range append([][]string{base}, extra...) {
		for _, v := range list {
			n := normalizeLabel(v)
			if n == "" {
				continue
			}
			if _, ok := m[n]; ok {
				continue
			}
			m[n] = struct{}{}
			out = append(out, n)
		}
	}
	return out
}

func collectEvidenceValues(d store.Device, strategy, key string) []string {
	out := []string{}
	for _, o := range d.Observations {
		if !observationEligibleForLabeling(o) {
			continue
		}
		if o.Strategy == strategy && o.Key == key {
			out = append(out, o.Value)
		}
	}
	return out
}

func ClassifyObservationStatus(obs store.Observation) ObservationStatus {
	key := strings.ToLower(strings.TrimSpace(obs.Key))
	value := strings.ToLower(strings.TrimSpace(obs.Value))
	reason := ""
	if obs.Details != nil {
		reason = strings.ToLower(strings.TrimSpace(obs.Details["reason"]))
	}
	if value == "" {
		return ObservationStatusNoResponse
	}
	if containsAny(value, "unsupported", "not_supported", "unavailable", "not_available") || containsAny(reason, "unsupported", "not_supported", "unavailable") {
		return ObservationStatusUnsupported
	}
	if containsAny(value, "not_applicable", "n/a", "na", "windows_only", "linux_only", "macos_only", "not_ipv6") || containsAny(reason, "not_applicable", "not applicable") {
		return ObservationStatusNotApplicable
	}
	if isObservationStatusMarker(key, value) {
		return ObservationStatusNoResponse
	}
	return ObservationStatusRealData
}

func ActionableObservations(observations []store.Observation) []store.Observation {
	if len(observations) == 0 {
		return nil
	}
	out := make([]store.Observation, 0, len(observations))
	for _, obs := range observations {
		if !observationEligibleForLabeling(obs) {
			continue
		}
		out = append(out, obs)
	}
	return out
}

func CountObservationStatuses(observations []store.Observation) map[string]int {
	counts := map[string]int{
		string(ObservationStatusRealData):      0,
		string(ObservationStatusNoResponse):    0,
		string(ObservationStatusUnsupported):   0,
		string(ObservationStatusNotApplicable): 0,
	}
	for _, obs := range observations {
		counts[string(ClassifyObservationStatus(obs))]++
	}
	for key, value := range counts {
		if value == 0 {
			delete(counts, key)
		}
	}
	return counts
}

func isObservationStatusMarker(key, value string) bool {
	if key == "manual_label" && value != "unlabeled" {
		return false
	}
	switch key {
	case "ports", "http_api", "http", "https", "tls", "ssh_banner", "icmp_like", "ssdp", "mdns", "neighbor", "llmnr", "snmp_system", "udp_161", "udp_162", "udp_1812", "udp_3702", "udp_137", "tcp_139", "tcp_445", "tcp_3389", "gateway", "wireless_beacons", "status", "passive_flow_status", "passive_tls_status", "passive_http_status", "passive_ssh_status", "dhcp_fingerprint_status", "dns_client_profile_status", "tls_client_fingerprint_status", "quic_client_status", "ipv6_client_profile_status", "wifi_client_profile_status", "resolver_profile_status", "session_profile_status":
		switch value {
		case "none", "no_response", "not_seen", "not_found", "no_data", "no_response_received", "not_observed", "lookup_error", "not_available", "unavailable", "unsupported", "not_applicable", "closed", "open", "responsive", "likely", "windows_only", "linux_only", "macos_only", "no_tcp_probe", "n/a", "na", "no_target_match":
			return true
		}
	}
	switch value {
	case "none", "no_response", "not_seen", "not_found", "no_data", "not_observed", "no_response_received", "lookup_error", "closed", "open", "responsive", "likely", "unavailable", "unsupported", "not_available", "windows_only", "linux_only", "macos_only", "not_applicable", "n/a", "na", "no_tcp_probe", "no_target_match":
		return true
	}
	return false
}

func observationEligibleForLabeling(obs store.Observation) bool {
	if ClassifyObservationStatus(obs) != ObservationStatusRealData {
		return false
	}
	matchQuality := ""
	sourceScope := ""
	if obs.Details != nil {
		matchQuality = strings.ToLower(strings.TrimSpace(obs.Details["match_quality"]))
		sourceScope = strings.ToLower(strings.TrimSpace(obs.Details["source_scope"]))
	}
	if matchQuality == "ambient_context" || matchQuality == "unmatched" {
		return false
	}
	if requiresPassiveAttribution(obs.Strategy, sourceScope) {
		return matchQuality == "direct_match" || matchQuality == "strong_inferred_match"
	}
	return true
}

func requiresPassiveAttribution(strategyName, sourceScope string) bool {
	switch strings.ToLower(strings.TrimSpace(strategyName)) {
	case "mdns_passive", "ssdp_passive", "passive_service_fingerprint_pcap", "passive_tls_handshake", "passive_ssh_banner", "passive_http_metadata", "flow_netflow_ipfix", "radius_8021x_identity", "passive_dhcp_fingerprint", "passive_dns_client_profile", "passive_tls_client_fingerprint", "passive_quic_fingerprint", "passive_ipv6_client_profile", "wifi_client_association_telemetry", "resolver_client_profile", "passive_session_profile", "host_event_log_pull", "wireless_11_beacon":
		return true
	}
	return strings.Contains(sourceScope, "passive")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func dedupeFirst(values []string, n int) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, min(len(values), n))
	for _, v := range values {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
		if len(out) >= n {
			break
		}
	}
	return out
}

func containsAny(value string, terms ...string) bool {
	for _, t := range terms {
		if strings.Contains(value, t) {
			return true
		}
	}
	return false
}

func splitCSV(v string) []string {
	parts := strings.Split(v, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(strings.TrimPrefix(strings.TrimSuffix(p, "\n"), " "))
		if p == "" {
			continue
		}
		out = append(out, p)
	}
	return out
}

func likelyGatewayIP(ip string) bool {
	ip = strings.TrimSpace(ip)
	if ip == "" {
		return false
	}
	return strings.HasSuffix(ip, ".1") || strings.HasSuffix(ip, ".254")
}

func normalizeLabel(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	switch v {
	case "wireless printer", "ipp":
		return "printer"
	case "television", "smart tv":
		return "tv"
	case "speaker", "smart speaker":
		return "iot"
	case "phone", "mobile", "smartphone":
		return "phone"
	default:
		if v == "" {
			return ""
		}
		return v
	}
}

func hasLabel(v string) bool {
	v = normalizeLabel(v)
	switch v {
	case "", "unknown", "unlabeled":
		return false
	default:
		return true
	}
}
