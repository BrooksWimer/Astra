package eval

import (
	"fmt"
	"hash/fnv"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/netwise/agent/internal/config"
	"github.com/netwise/agent/internal/evidence"
	"github.com/netwise/agent/internal/labeling"
	"github.com/netwise/agent/internal/store"
)

type DeviceSnapshot struct {
	ID                       string            `json:"id"`
	IP                       string            `json:"ip"`
	MAC                      string            `json:"mac"`
	Hostname                 string            `json:"hostname,omitempty"`
	DeviceType               string            `json:"device_type,omitempty"`
	LabelState               *store.LabelState `json:"label_state,omitempty"`
	ObservationCount         int               `json:"observation_count"`
	ObservationStatusCounts  map[string]int    `json:"observation_status_counts,omitempty"`
	RealDataObservationCount int               `json:"real_data_observation_count,omitempty"`
	SourceCount              int               `json:"source_count"`
	Confidence               float64           `json:"confidence,omitempty"`
	CalibratedConfidence     float64           `json:"calibrated_confidence,omitempty"`
	Conflict                 bool              `json:"conflict,omitempty"`
	Unknown                  bool              `json:"unknown,omitempty"`
}

type LabelCount struct {
	Label string `json:"label"`
	Count int    `json:"count"`
}

type LabelSummary struct {
	DeviceCount                 int            `json:"device_count"`
	LabeledCount                int            `json:"labeled_count"`
	UnknownCount                int            `json:"unknown_count"`
	ConflictCount               int            `json:"conflict_count"`
	ObservationStatusCounts     map[string]int `json:"observation_status_counts,omitempty"`
	BandCounts                  map[string]int `json:"band_counts,omitempty"`
	TopLabels                   []LabelCount   `json:"top_labels,omitempty"`
	TopCandidateLabels          []LabelCount   `json:"top_candidate_labels,omitempty"`
	AverageConfidence           float64        `json:"average_confidence,omitempty"`
	AverageCalibratedConfidence float64        `json:"average_calibrated_confidence,omitempty"`
}

type EvidenceGraphSummary struct {
	BuiltAt             string `json:"built_at"`
	DeviceCount         int    `json:"device_count"`
	TotalSignals        int    `json:"total_signals"`
	ObservedDevices     int    `json:"observed_devices"`
	DevicesWithEvidence int    `json:"devices_with_evidence"`
}

type EvaluationReport struct {
	Name          string                `json:"name"`
	Source        string                `json:"source,omitempty"`
	GeneratedAt   time.Time             `json:"generated_at"`
	SampleCount   int                   `json:"sample_count"`
	Devices       []DeviceSnapshot      `json:"devices,omitempty"`
	LabelSummary  LabelSummary          `json:"label_summary"`
	EvidenceGraph *EvidenceGraphSummary `json:"evidence_graph,omitempty"`
	Metrics       ClassificationMetrics `json:"metrics,omitempty"`
	Confusion     ConfusionMatrix       `json:"confusion,omitempty"`
	Calibration   CalibrationCurve      `json:"calibration,omitempty"`
	QualityGate   *QualityGateResult    `json:"quality_gate,omitempty"`
	Splits        []DatasetSplit        `json:"splits,omitempty"`
	Ablations     []AblationResult      `json:"ablations,omitempty"`
	Notes         []string              `json:"notes,omitempty"`
}

type DatasetSplit struct {
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	IDs         []string `json:"ids,omitempty"`
	Size        int      `json:"size"`
}

type AblationScenario struct {
	Name               string   `json:"name"`
	Description        string   `json:"description,omitempty"`
	DisabledStrategies []string `json:"disabled_strategies,omitempty"`
	DisabledFamilies   []string `json:"disabled_families,omitempty"`
	Notes              string   `json:"notes,omitempty"`
}

type AblationResult struct {
	Scenario    AblationScenario      `json:"scenario"`
	SampleCount int                   `json:"sample_count"`
	Metrics     ClassificationMetrics `json:"metrics"`
	Confusion   ConfusionMatrix       `json:"confusion"`
	Calibration CalibrationCurve      `json:"calibration"`
	Notes       []string              `json:"notes,omitempty"`
}

func BuildEvaluationReportFromDevices(name string, devices []store.Device) EvaluationReport {
	return BuildEvaluationReportFromDevicesWithConfig(name, devices, nil)
}

func BuildEvaluationReportFromDevicesWithConfig(name string, devices []store.Device, cfg *config.Config) EvaluationReport {
	return buildEvaluationReport(name, "devices", devices, evidence.PrivacyConfig{DNSPrivacyMode: evidence.PrivacyModeFull}, cfg)
}

func BuildEvaluationReportFromCorpusPath(name, corpusPath string) (EvaluationReport, error) {
	return BuildEvaluationReportFromCorpusInputs(name, []string{corpusPath})
}

func BuildEvaluationReportFromCorpusInputs(name string, inputs []string) (EvaluationReport, error) {
	return BuildEvaluationReportFromCorpusInputsWithConfig(name, inputs, nil)
}

func BuildEvaluationReportFromCorpusInputsWithConfig(name string, inputs []string, cfg *config.Config) (EvaluationReport, error) {
	devices, resolved, err := loadEvaluationCorpus(inputs)
	if err != nil {
		return EvaluationReport{}, err
	}
	report := buildEvaluationReport(name, "corpus", devices, evidence.PrivacyConfig{DNSPrivacyMode: evidence.PrivacyModeFull}, cfg)
	report.Notes = append(report.Notes, fmt.Sprintf("corpus_inputs=%d", len(resolved)))
	return report, nil
}

func buildEvaluationReport(name, source string, devices []store.Device, privacyCfg evidence.PrivacyConfig, cfg *config.Config) EvaluationReport {
	report := EvaluationReport{
		Name:        name,
		Source:      source,
		GeneratedAt: time.Now().UTC(),
		SampleCount: len(devices),
	}
	if len(devices) == 0 {
		report.LabelSummary = LabelSummary{
			BandCounts:              map[string]int{},
			ObservationStatusCounts: map[string]int{},
		}
		return report
	}

	labeled := make([]store.Device, 0, len(devices))
	for _, d := range devices {
		labeled = append(labeled, ensureEvaluationLabelState(d, privacyCfg))
	}

	snapshots := make([]DeviceSnapshot, 0, len(labeled))
	labelCounts := map[string]int{}
	candidateCounts := map[string]int{}
	bandCounts := map[string]int{}
	statusTotals := map[string]int{}
	var totalConfidence float64
	var totalCalibrated float64
	for _, d := range labeled {
		hostname := ""
		if d.Hostname != nil {
			hostname = *d.Hostname
		}
		conflict := len(d.LabelState.ConflictFlags) > 0
		unknown := isUnknownLabel(d)
		label := normalizedDeviceLabel(d)
		statusCounts := labeling.CountObservationStatuses(d.Observations)
		for status, count := range statusCounts {
			statusTotals[status] += count
		}
		realDataCount := statusCounts[string(labeling.ObservationStatusRealData)]
		if unknown {
			label = "unknown"
		}
		labelCounts[label]++
		if band := strings.TrimSpace(d.LabelState.ConfidenceBand); band != "" {
			bandCounts[band]++
		}
		for _, candidate := range d.LabelState.CandidateLabels {
			if strings.TrimSpace(candidate.Label) == "" {
				continue
			}
			candidateCounts[strings.ToLower(strings.TrimSpace(candidate.Label))]++
		}
		totalConfidence += d.LabelState.LabelConfidence
		totalCalibrated += d.LabelState.LabelConfidenceCalibrated
		snapshots = append(snapshots, DeviceSnapshot{
			ID:                       d.ID,
			IP:                       d.IP,
			MAC:                      d.MAC,
			Hostname:                 hostname,
			DeviceType:               d.DeviceType,
			LabelState:               labelStateSnapshotPtr(d.LabelState),
			ObservationCount:         len(d.Observations),
			ObservationStatusCounts:  statusCounts,
			RealDataObservationCount: realDataCount,
			SourceCount:              len(d.SourcesSeen),
			Confidence:               d.LabelState.LabelConfidence,
			CalibratedConfidence:     d.LabelState.LabelConfidenceCalibrated,
			Conflict:                 conflict,
			Unknown:                  unknown,
		})
	}

	graph := evidence.BuildEvidenceGraph(labeled, privacyCfg)
	report.Devices = snapshots
	report.LabelSummary = LabelSummary{
		DeviceCount:                 len(labeled),
		LabeledCount:                len(labeled) - labelCounts["unknown"],
		UnknownCount:                labelCounts["unknown"],
		ConflictCount:               countConflicts(labeled),
		ObservationStatusCounts:     statusTotals,
		BandCounts:                  bandCounts,
		TopLabels:                   topLabelCounts(labelCounts, 5),
		TopCandidateLabels:          topLabelCounts(candidateCounts, 5),
		AverageConfidence:           totalConfidence / float64(len(labeled)),
		AverageCalibratedConfidence: totalCalibrated / float64(len(labeled)),
	}
	report.EvidenceGraph = &EvidenceGraphSummary{
		BuiltAt:             graph.BuiltAt.UTC().Format(time.RFC3339),
		DeviceCount:         graph.Counters.DeviceCount,
		TotalSignals:        graph.Counters.TotalSignals,
		ObservedDevices:     graph.Counters.ObservedDevices,
		DevicesWithEvidence: graph.Counters.DevicesWithEvidence,
	}
	report.Splits = blindIdentitySplits(labeled, 3)
	report.Ablations = buildAblationResults(labeled, privacyCfg)
	predictions := buildGroundTruthPredictions(labeled)
	if len(predictions) > 0 {
		report.Metrics = SummarizePredictions(predictions)
		report.Confusion = NewConfusionMatrix(predictions)
		report.Calibration = CalibrationECE(predictions, 10)
		report.Notes = append(report.Notes, fmt.Sprintf("manual_ground_truth_samples=%d", len(predictions)))
	} else {
		report.Notes = append(report.Notes, "no manual-label ground truth available for metrics")
	}
	qualityGate := EvaluateQualityGate(report, cfg)
	report.QualityGate = &qualityGate
	return report
}

func ensureEvaluationLabelState(d store.Device, privacyCfg evidence.PrivacyConfig) store.Device {
	if hasEvaluationLabelState(d) {
		if strings.TrimSpace(d.DeviceType) == "" && strings.TrimSpace(d.LabelState.DeviceCategory) != "" {
			d.DeviceType = d.LabelState.DeviceCategory
		}
		if d.Confidence == 0 && d.LabelState.LabelConfidence > 0 {
			d.Confidence = d.LabelState.LabelConfidence
		}
		return d
	}
	res := labeling.ClassifyDeviceWithPrivacy(d, privacyCfg)
	d.DeviceType = res.DeviceCategory
	d.Confidence = res.LabelConfidence
	d.LabelState = toStoreLabelState(res)
	return d
}

func hasEvaluationLabelState(d store.Device) bool {
	if label := strings.TrimSpace(strings.ToLower(d.DeviceType)); label != "" && label != "unknown" && label != "unlabeled" {
		return true
	}
	if hasLabelStateValue(d.LabelState) {
		if label := strings.TrimSpace(strings.ToLower(d.LabelState.DeviceCategory)); label == "unknown" || label == "unlabeled" {
			return false
		}
		return true
	}
	if d.Confidence > 0 {
		return true
	}
	return false
}

func normalizedDeviceLabel(d store.Device) string {
	label := strings.ToLower(strings.TrimSpace(d.DeviceType))
	if label == "" {
		label = strings.ToLower(strings.TrimSpace(d.LabelState.DeviceCategory))
	}
	if label == "" {
		label = "unknown"
	}
	return label
}

func isUnknownLabel(d store.Device) bool {
	label := strings.ToLower(strings.TrimSpace(d.DeviceType))
	if label == "" || label == "unknown" || label == "unlabeled" {
		label = strings.ToLower(strings.TrimSpace(d.LabelState.DeviceCategory))
	}
	return label == "" || label == "unknown" || label == "unlabeled"
}

func labelStateSnapshotPtr(state store.LabelState) *store.LabelState {
	if !hasLabelStateValue(state) {
		return nil
	}
	cp := state
	return &cp
}

func countConflicts(devices []store.Device) int {
	total := 0
	for _, d := range devices {
		if len(d.LabelState.ConflictFlags) > 0 {
			total++
		}
	}
	return total
}

func buildGroundTruthPredictions(devices []store.Device) []Prediction {
	predictions := make([]Prediction, 0, len(devices))
	for _, d := range devices {
		actual := strings.TrimSpace(manualGroundTruthLabel(d))
		if actual == "" {
			continue
		}
		predictions = append(predictions, Prediction{
			Actual:     strings.ToLower(actual),
			Predicted:  normalizedDeviceLabel(d),
			Confidence: d.LabelState.LabelConfidenceCalibrated,
		})
	}
	return predictions
}

func manualGroundTruthLabel(d store.Device) string {
	if strings.EqualFold(strings.TrimSpace(d.ManualLabelState), "set") && strings.TrimSpace(d.ManualLabel) != "" {
		return d.ManualLabel
	}
	for _, obs := range d.Observations {
		if obs.Strategy != "manual_operator_label_fallback" || obs.Key != "manual_label" {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(obs.Value), "unlabeled") {
			continue
		}
		return obs.Value
	}
	return ""
}

func blindIdentitySplits(devices []store.Device, segments int) []DatasetSplit {
	if segments <= 0 {
		segments = 3
	}
	buckets := make([][]string, segments)
	for _, d := range devices {
		key := evidence.StableDeviceKey(&d)
		if key == "" {
			key = evaluationDeviceKey(d)
		}
		idx := stableSplitIndex(key, segments)
		buckets[idx] = append(buckets[idx], key)
	}
	out := make([]DatasetSplit, 0, segments)
	for idx, ids := range buckets {
		sort.Strings(ids)
		out = append(out, DatasetSplit{
			Name:        fmt.Sprintf("segment_%d", idx+1),
			Description: "blind split by stable device identity",
			IDs:         ids,
			Size:        len(ids),
		})
	}
	return out
}

func stableSplitIndex(key string, segments int) int {
	if segments <= 1 {
		return 0
	}
	hasher := fnv.New32a()
	_, _ = hasher.Write([]byte(strings.ToLower(strings.TrimSpace(key))))
	return int(hasher.Sum32() % uint32(segments))
}

func buildAblationResults(devices []store.Device, privacyCfg evidence.PrivacyConfig) []AblationResult {
	scenarios := []AblationScenario{
		{
			Name:               "drop_mdns",
			Description:        "remove mDNS discovery signals",
			DisabledStrategies: []string{"mdns_active", "mdns_passive"},
		},
		{
			Name:               "drop_ssdp_upnp",
			Description:        "remove SSDP and UPnP description signals",
			DisabledStrategies: []string{"ssdp_active", "ssdp_passive", "upnp_description_fetch", "upnp_service_control"},
		},
		{
			Name:             "drop_snmp",
			Description:      "remove SNMP identity signals",
			DisabledFamilies: []string{string(evidence.FamilySNMP)},
		},
		{
			Name:               "drop_http_tls",
			Description:        "remove HTTP, TLS, and SSH fingerprinting signals",
			DisabledStrategies: []string{"http_header_probe", "passive_http_metadata", "http_favicon_fingerprint", "http_api_probe", "home_api_probe", "credentialed_api", "tls_cert_probe", "passive_tls_handshake", "passive_ssh_banner", "ssh_banner_probe"},
		},
		{
			Name:        "ports_only",
			Description: "keep only ports-derived evidence",
			Notes:       "useful for measuring how much ports alone can tell us",
		},
	}

	results := make([]AblationResult, 0, len(scenarios))
	for _, scenario := range scenarios {
		ablated := ablateDevices(devices, scenario, privacyCfg)
		predictions := buildGroundTruthPredictions(ablated)
		result := AblationResult{
			Scenario:    scenario,
			SampleCount: len(ablated),
		}
		if len(predictions) > 0 {
			result.Metrics = SummarizePredictions(predictions)
			result.Confusion = NewConfusionMatrix(predictions)
			result.Calibration = CalibrationECE(predictions, 10)
			result.Notes = append(result.Notes, fmt.Sprintf("manual_ground_truth_samples=%d", len(predictions)))
		} else {
			result.Notes = append(result.Notes, "no manual-label ground truth available for this ablation")
		}
		results = append(results, result)
	}
	return results
}

func ablateDevices(devices []store.Device, scenario AblationScenario, privacyCfg evidence.PrivacyConfig) []store.Device {
	out := make([]store.Device, 0, len(devices))
	disabledStrategies := make(map[string]struct{}, len(scenario.DisabledStrategies))
	disabledFamilies := make(map[string]struct{}, len(scenario.DisabledFamilies))
	for _, strategy := range scenario.DisabledStrategies {
		disabledStrategies[strings.ToLower(strings.TrimSpace(strategy))] = struct{}{}
	}
	for _, family := range scenario.DisabledFamilies {
		disabledFamilies[strings.ToLower(strings.TrimSpace(family))] = struct{}{}
	}

	for _, src := range devices {
		d := src
		d.DeviceType = ""
		d.Confidence = 0
		d.LabelState = store.LabelState{}
		filtered := make([]store.Observation, 0, len(d.Observations))
		for _, obs := range d.Observations {
			if shouldDropObservationForAblation(obs, scenario, disabledStrategies, disabledFamilies, privacyCfg) {
				continue
			}
			filtered = append(filtered, obs)
		}
		d.Observations = filtered
		applyDeviceFieldAblation(&d, scenario)
		out = append(out, ensureEvaluationLabelState(d, privacyCfg))
	}
	return out
}

func shouldDropObservationForAblation(obs store.Observation, scenario AblationScenario, disabledStrategies, disabledFamilies map[string]struct{}, privacyCfg evidence.PrivacyConfig) bool {
	strategyName := strings.ToLower(strings.TrimSpace(obs.Strategy))
	if _, ok := disabledStrategies[strategyName]; ok {
		return true
	}
	family := evidence.FromObservation(obs, privacyCfg).Family
	if _, ok := disabledFamilies[strings.ToLower(string(family))]; ok {
		return true
	}
	if scenario.Name == "ports_only" {
		return family != evidence.FamilyPorts
	}
	return false
}

func applyDeviceFieldAblation(d *store.Device, scenario AblationScenario) {
	if d == nil {
		return
	}
	switch scenario.Name {
	case "drop_mdns":
		d.ProtocolsSeen.MDNS = nil
	case "drop_ssdp_upnp":
		d.ProtocolsSeen.SSDP = nil
		d.SSDPServer = ""
	case "drop_http_tls":
		d.HTTPServer = ""
		d.TLSSubject = ""
		d.TLSIssuer = ""
		d.TLSSANS = ""
		d.SSHBanner = ""
	case "ports_only":
		d.ProtocolsSeen = store.ProtocolsSeen{}
		d.HTTPServer = ""
		d.SSDPServer = ""
		d.TLSSubject = ""
		d.TLSIssuer = ""
		d.TLSSANS = ""
		d.SSHBanner = ""
	}
}

func topLabelCounts(counts map[string]int, limit int) []LabelCount {
	if len(counts) == 0 || limit <= 0 {
		return nil
	}
	out := make([]LabelCount, 0, len(counts))
	for label, count := range counts {
		out = append(out, LabelCount{Label: label, Count: count})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Label < out[j].Label
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

func loadEvaluationCorpus(inputs []string) ([]store.Device, []string, error) {
	if len(inputs) == 0 {
		return nil, nil, fmt.Errorf("no corpus inputs provided")
	}
	expanded, err := expandEvaluationInputs(inputs)
	if err != nil {
		return nil, nil, err
	}
	if len(expanded) == 0 {
		return nil, nil, fmt.Errorf("no corpus files found")
	}

	merged := make([]store.Device, 0)
	for _, path := range expanded {
		devices, err := evidence.LoadCorpus(path)
		if err != nil {
			continue
		}
		merged = append(merged, devices...)
	}
	if len(merged) == 0 {
		return nil, expanded, fmt.Errorf("no corpus devices could be loaded")
	}
	return mergeEvaluationDevices(merged), expanded, nil
}

func expandEvaluationInputs(inputs []string) ([]string, error) {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(inputs))
	for _, raw := range inputs {
		raw = strings.TrimSpace(raw)
		if raw == "" {
			continue
		}
		info, err := os.Stat(raw)
		if err != nil {
			return nil, err
		}
		if !info.IsDir() {
			abs, err := filepath.Abs(raw)
			if err != nil {
				return nil, err
			}
			if _, ok := seen[abs]; !ok {
				seen[abs] = struct{}{}
				out = append(out, abs)
			}
			continue
		}
		err = filepath.WalkDir(raw, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() {
				return nil
			}
			if !strings.EqualFold(filepath.Ext(entry.Name()), ".json") {
				return nil
			}
			abs, err := filepath.Abs(path)
			if err != nil {
				return err
			}
			if _, ok := seen[abs]; ok {
				return nil
			}
			seen[abs] = struct{}{}
			out = append(out, abs)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(out)
	return out, nil
}

func mergeEvaluationDevices(devices []store.Device) []store.Device {
	if len(devices) == 0 {
		return nil
	}
	byKey := map[string]store.Device{}
	order := make([]string, 0, len(devices))
	for _, d := range devices {
		key := evaluationDeviceKey(d)
		if existing, ok := byKey[key]; ok {
			byKey[key] = mergeEvaluationDevice(existing, d)
			continue
		}
		byKey[key] = d
		order = append(order, key)
	}
	out := make([]store.Device, 0, len(order))
	for _, key := range order {
		out = append(out, byKey[key])
	}
	return out
}

func mergeEvaluationDevice(dst, src store.Device) store.Device {
	if dst.ID == "" {
		dst.ID = src.ID
	}
	if dst.IP == "" {
		dst.IP = src.IP
	}
	if dst.MAC == "" {
		dst.MAC = src.MAC
	}
	if dst.Vendor == "" {
		dst.Vendor = src.Vendor
	}
	if dst.Hostname == nil && src.Hostname != nil {
		dst.Hostname = src.Hostname
	}
	dst.PortsOpen = mergeIntSlices(dst.PortsOpen, src.PortsOpen)
	dst.Flags = mergeStringSlices(dst.Flags, src.Flags)
	dst.SourcesSeen = mergeStringSlices(dst.SourcesSeen, src.SourcesSeen)
	dst.ProtocolsSeen.MDNS = mergeStringSlices(dst.ProtocolsSeen.MDNS, src.ProtocolsSeen.MDNS)
	dst.ProtocolsSeen.SSDP = mergeStringSlices(dst.ProtocolsSeen.SSDP, src.ProtocolsSeen.SSDP)
	dst.ProtocolsSeen.NetBIOS = mergeStringSlices(dst.ProtocolsSeen.NetBIOS, src.ProtocolsSeen.NetBIOS)
	dst.Observations = mergeObservationSlices(dst.Observations, src.Observations)
	if dst.DeviceType == "" {
		dst.DeviceType = src.DeviceType
	}
	if dst.Confidence == 0 {
		dst.Confidence = src.Confidence
	}
	if !hasLabelStateValue(dst.LabelState) && hasLabelStateValue(src.LabelState) {
		dst.LabelState = src.LabelState
	}
	if dst.HTTPServer == "" {
		dst.HTTPServer = src.HTTPServer
	}
	if dst.SSDPServer == "" {
		dst.SSDPServer = src.SSDPServer
	}
	if dst.TLSSubject == "" {
		dst.TLSSubject = src.TLSSubject
	}
	if dst.TLSIssuer == "" {
		dst.TLSIssuer = src.TLSIssuer
	}
	if dst.TLSSANS == "" {
		dst.TLSSANS = src.TLSSANS
	}
	if dst.SSHBanner == "" {
		dst.SSHBanner = src.SSHBanner
	}
	if dst.FirstSeen == "" || (src.FirstSeen != "" && src.FirstSeen < dst.FirstSeen) {
		dst.FirstSeen = src.FirstSeen
	}
	if src.LastSeen != "" && (dst.LastSeen == "" || src.LastSeen > dst.LastSeen) {
		dst.LastSeen = src.LastSeen
	}
	return dst
}

func evaluationDeviceKey(d store.Device) string {
	if strings.TrimSpace(d.ID) != "" {
		return strings.ToLower(strings.TrimSpace(d.ID))
	}
	if strings.TrimSpace(d.MAC) != "" {
		return strings.ToLower(strings.TrimSpace(d.MAC))
	}
	if strings.TrimSpace(d.IP) != "" {
		return "ip:" + strings.TrimSpace(d.IP)
	}
	return strings.ToLower(strings.TrimSpace(d.DeviceType + "|" + d.FirstSeen + "|" + d.LastSeen))
}

func hasLabelStateValue(state store.LabelState) bool {
	if strings.TrimSpace(state.DeviceCategory) != "" {
		return true
	}
	if strings.TrimSpace(state.DeviceSubType) != "" {
		return true
	}
	if state.LabelConfidence != 0 || state.LabelConfidenceCalibrated != 0 {
		return true
	}
	if len(state.EvidenceSummary) > 0 || len(state.CandidateLabels) > 0 || len(state.ReasonChain) > 0 || len(state.ConflictFlags) > 0 {
		return true
	}
	if strings.TrimSpace(state.ConfidenceBand) != "" {
		return true
	}
	return false
}

func mergeIntSlices(a, b []int) []int {
	seen := make(map[int]struct{})
	for _, v := range a {
		seen[v] = struct{}{}
	}
	for _, v := range b {
		seen[v] = struct{}{}
	}
	out := make([]int, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}

func mergeStringSlices(a, b []string) []string {
	seen := make(map[string]struct{})
	for _, s := range a {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		seen[s] = struct{}{}
	}
	for _, s := range b {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		seen[s] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for s := range seen {
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

func mergeObservationSlices(a, b []store.Observation) []store.Observation {
	type key struct {
		strategy string
		key      string
		value    string
		ip       string
	}
	seen := make(map[key]struct{})
	out := make([]store.Observation, 0, len(a)+len(b))
	for _, obs := range a {
		k := key{strategy: obs.Strategy, key: obs.Key, value: obs.Value, ip: obs.IP}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, obs)
	}
	for _, obs := range b {
		k := key{strategy: obs.Strategy, key: obs.Key, value: obs.Value, ip: obs.IP}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, obs)
	}
	return out
}

func toStoreLabelState(res labeling.LabelResult) store.LabelState {
	candidates := make([]store.LabelCandidate, 0, len(res.CandidateLabels))
	for _, c := range res.CandidateLabels {
		candidates = append(candidates, store.LabelCandidate{
			Label:        c.Label,
			Score:        c.Score,
			Confidence:   c.Confidence,
			Evidence:     c.Evidence,
			SupportTiers: c.SupportTiers,
		})
	}
	return store.LabelState{
		DeviceCategory:            res.DeviceCategory,
		DeviceSubType:             res.DeviceSubType,
		LabelConfidence:           res.LabelConfidence,
		LabelConfidenceCalibrated: res.LabelConfidenceCalibrated,
		EvidenceSummary:           res.EvidenceSummary,
		CandidateLabels:           candidates,
		ReasonChain:               res.ReasonChain,
		ConflictFlags:             res.ConflictFlags,
		ConfidenceBand:            string(res.ConfidenceBand),
	}
}
