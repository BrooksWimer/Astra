package optimize

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/netwise/agent/internal/config"
	"github.com/netwise/agent/internal/evidence"
	"github.com/netwise/agent/internal/labeling"
	"github.com/netwise/agent/internal/scanner"
	"github.com/netwise/agent/internal/store"
	"github.com/netwise/agent/internal/strategy"
)

type Report struct {
	GeneratedAt                time.Time         `json:"generated_at"`
	SourceInputs               []string          `json:"source_inputs"`
	ExperimentReportPath       string            `json:"experiment_report_path,omitempty"`
	MeasuredFullScanDurationMs int64             `json:"measured_full_scan_duration_ms,omitempty"`
	StrategyRankings           []StrategyRanking `json:"strategy_rankings"`
	Baseline                   ProfileSummary    `json:"baseline"`
	Profiles                   []ProfileSummary  `json:"profiles"`
	Notes                      []string          `json:"notes,omitempty"`
}

type StrategyRanking struct {
	Name                  string                  `json:"name"`
	Mode                  string                  `json:"mode"`
	ExecutionClass        strategy.ExecutionClass `json:"execution_class"`
	SpeedCost             strategy.SpeedCost      `json:"speed_cost"`
	RealDataLikelihood    string                  `json:"real_data_likelihood"`
	DiscoveryValue        int                     `json:"discovery_value"`
	LabelingValue         int                     `json:"labeling_value"`
	Recommendation        strategy.StrategyTier   `json:"recommendation"`
	TargetsHit            int                     `json:"targets_hit"`
	TotalObservations     int                     `json:"total_observations"`
	RealDataObservations  int                     `json:"real_data_observations"`
	RealDataRate          float64                 `json:"real_data_rate"`
	NoResponseCount       int                     `json:"no_response_count,omitempty"`
	UnsupportedCount      int                     `json:"unsupported_count,omitempty"`
	NotApplicableCount    int                     `json:"not_applicable_count,omitempty"`
	TimeCost              float64                 `json:"time_cost"`
	TimeSource            string                  `json:"time_source"`
	LabelAgreementLoss    float64                 `json:"label_agreement_loss"`
	UnknownIncrease       int                     `json:"unknown_increase"`
	AverageConfidenceLoss float64                 `json:"average_confidence_loss"`
	ValueScore            float64                 `json:"value_score"`
	ValuePerUnitTime      float64                 `json:"value_per_unit_time"`
	Notes                 string                  `json:"notes,omitempty"`
}

type ProfileSummary struct {
	Name                         string              `json:"name"`
	Description                  string              `json:"description"`
	StrategyCount                int                 `json:"strategy_count"`
	Strategies                   []string            `json:"strategies"`
	EstimatedStrategyPhaseMs     int64               `json:"estimated_strategy_phase_ms"`
	EstimatedStrategyPhaseSource string              `json:"estimated_strategy_phase_source"`
	ObservationCount             int                 `json:"observation_count"`
	RealDataObservationCount     int                 `json:"real_data_observation_count"`
	DevicesWithRealData          int                 `json:"devices_with_real_data"`
	LabeledCount                 int                 `json:"labeled_count"`
	UnknownCount                 int                 `json:"unknown_count"`
	AverageCalibratedConfidence  float64             `json:"average_calibrated_confidence"`
	LabelAgreementWithFull       float64             `json:"label_agreement_with_full,omitempty"`
	DevicesChanged               int                 `json:"devices_changed,omitempty"`
	ObservationDelta             int                 `json:"observation_delta,omitempty"`
	RealDataObservationDelta     int                 `json:"real_data_observation_delta,omitempty"`
	LabeledDelta                 int                 `json:"labeled_delta,omitempty"`
	UnknownDelta                 int                 `json:"unknown_delta,omitempty"`
	ConfidenceDelta              float64             `json:"confidence_delta,omitempty"`
	PreservedDeviceTypes         []LabelPreservation `json:"preserved_device_types,omitempty"`
	DegradedDeviceTypes          []LabelChange       `json:"degraded_device_types,omitempty"`
}

type LabelPreservation struct {
	Label         string  `json:"label"`
	BaselineCount int     `json:"baseline_count"`
	SameCount     int     `json:"same_count"`
	Agreement     float64 `json:"agreement"`
}

type LabelChange struct {
	BaselineLabel string `json:"baseline_label"`
	NewLabel      string `json:"new_label"`
	Count         int    `json:"count"`
}

type profileDevice struct {
	Key                      string
	Label                    string
	CalibratedConfidence     float64
	ObservationCount         int
	RealDataObservationCount int
}

type profileEvaluation struct {
	Name                        string
	Description                 string
	Strategies                  []string
	ObservationCount            int
	RealDataObservationCount    int
	DevicesWithRealData         int
	LabeledCount                int
	UnknownCount                int
	AverageCalibratedConfidence float64
	Devices                     []profileDevice
	DeviceMap                   map[string]profileDevice
}

type experimentStats struct {
	ScanDurationMs int64
	TargetCount    int
	ByStrategy     map[string]strategyStats
}

type strategyStats struct {
	TargetsHit           int
	TotalObservations    int
	RealDataObservations int
	NoResponse           int
	Unsupported          int
	NotApplicable        int
	DurationMs           int64
}

type experimentEnvelope struct {
	ScanDurationMs  int64 `json:"scan_duration_ms"`
	TargetCount     int   `json:"target_count"`
	StrategyReports []struct {
		Strategy                string         `json:"strategy"`
		TargetsHit              int            `json:"targets_hit"`
		TotalObservations       int            `json:"total_observations"`
		RealDataObservations    int            `json:"real_data_observations"`
		DurationMs              int64          `json:"duration_ms"`
		ObservationStatusCounts map[string]int `json:"observation_status_counts"`
	} `json:"strategy_reports"`
}

func BuildReport(inputs []string, experimentReportPath string, cfg *config.Config, profileNames []string) (Report, error) {
	devices, err := loadOptimizationDevices(inputs)
	if err != nil {
		return Report{}, err
	}
	if len(devices) == 0 {
		return Report{}, fmt.Errorf("no devices could be loaded from optimization inputs")
	}

	stats, statsNotes := loadExperimentStats(experimentReportPath, inputs)
	report := Report{
		GeneratedAt:          time.Now().UTC(),
		SourceInputs:         append([]string{}, inputs...),
		ExperimentReportPath: strings.TrimSpace(experimentReportPath),
		Notes:                append([]string{}, statsNotes...),
	}
	if stats != nil {
		report.MeasuredFullScanDurationMs = stats.ScanDurationMs
	}

	fullProfile, ok := strategy.ResolveProfile("full")
	if !ok {
		return Report{}, fmt.Errorf("full strategy profile is not registered")
	}
	baselineEval := evaluateProfile(fullProfile.Name, fullProfile.Description, devices, cfg, fullProfile.StrategyNames)
	report.Baseline = summarizeProfile(fullProfile, baselineEval, baselineEval, stats)

	requestedProfiles := normalizeProfileNames(profileNames)
	if len(requestedProfiles) == 0 {
		requestedProfiles = []string{"fast", "medium"}
	}
	for _, name := range requestedProfiles {
		if name == "full" {
			continue
		}
		profile, ok := strategy.ResolveProfile(name)
		if !ok {
			return Report{}, fmt.Errorf("unknown strategy profile %q", name)
		}
		currentEval := evaluateProfile(profile.Name, profile.Description, devices, cfg, profile.StrategyNames)
		report.Profiles = append(report.Profiles, summarizeProfile(profile, currentEval, baselineEval, stats))
	}

	rankings := make([]StrategyRanking, 0, len(strategy.StrategyAuditCatalog()))
	fullStrategyNames := fullProfile.StrategyNames
	for _, audit := range strategy.StrategyAuditCatalog() {
		ablatedNames := withoutStrategy(fullStrategyNames, audit.Name)
		ablatedEval := evaluateProfile("without_"+audit.Name, "ablation", devices, cfg, ablatedNames)
		statsForStrategy := strategyStats{}
		if stats != nil {
			statsForStrategy = stats.ByStrategy[audit.Name]
		}
		rankings = append(rankings, buildStrategyRanking(audit, statsForStrategy, ablatedEval, baselineEval))
	}
	sort.Slice(rankings, func(i, j int) bool {
		if rankings[i].ValuePerUnitTime != rankings[j].ValuePerUnitTime {
			return rankings[i].ValuePerUnitTime > rankings[j].ValuePerUnitTime
		}
		if rankings[i].ValueScore != rankings[j].ValueScore {
			return rankings[i].ValueScore > rankings[j].ValueScore
		}
		return rankings[i].Name < rankings[j].Name
	})
	report.StrategyRankings = rankings
	if stats == nil {
		report.Notes = append(report.Notes, "strategy timing unavailable; time-based ranking used static speed-cost weights")
	}
	return report, nil
}

func summarizeProfile(profile strategy.StrategyProfile, current profileEvaluation, baseline profileEvaluation, stats *experimentStats) ProfileSummary {
	estimatedDuration, durationSource := estimateProfileDuration(profile.StrategyNames, stats)
	summary := ProfileSummary{
		Name:                         profile.Name,
		Description:                  profile.Description,
		StrategyCount:                len(profile.StrategyNames),
		Strategies:                   append([]string{}, profile.StrategyNames...),
		EstimatedStrategyPhaseMs:     estimatedDuration,
		EstimatedStrategyPhaseSource: durationSource,
		ObservationCount:             current.ObservationCount,
		RealDataObservationCount:     current.RealDataObservationCount,
		DevicesWithRealData:          current.DevicesWithRealData,
		LabeledCount:                 current.LabeledCount,
		UnknownCount:                 current.UnknownCount,
		AverageCalibratedConfidence:  current.AverageCalibratedConfidence,
	}
	if profile.Name == "full" {
		return summary
	}

	preserved, degraded, agreement, changed := compareProfileLabels(baseline, current)
	summary.LabelAgreementWithFull = agreement
	summary.DevicesChanged = changed
	summary.ObservationDelta = current.ObservationCount - baseline.ObservationCount
	summary.RealDataObservationDelta = current.RealDataObservationCount - baseline.RealDataObservationCount
	summary.LabeledDelta = current.LabeledCount - baseline.LabeledCount
	summary.UnknownDelta = current.UnknownCount - baseline.UnknownCount
	summary.ConfidenceDelta = current.AverageCalibratedConfidence - baseline.AverageCalibratedConfidence
	summary.PreservedDeviceTypes = preserved
	summary.DegradedDeviceTypes = degraded
	return summary
}

func evaluateProfile(name, description string, devices []store.Device, cfg *config.Config, strategyNames []string) profileEvaluation {
	prepared := scanner.FilterDevicesForStrategySubset(devices, strategyNames)
	results := make([]profileDevice, 0, len(prepared))
	deviceMap := make(map[string]profileDevice, len(prepared))
	observationCount := 0
	realDataObservationCount := 0
	devicesWithRealData := 0
	labeledCount := 0
	unknownCount := 0
	totalCalibrated := 0.0

	for _, d := range prepared {
		result := labeling.ClassifyDevice(d, cfg)
		statusCounts := labeling.CountObservationStatuses(d.Observations)
		realCount := statusCounts[string(labeling.ObservationStatusRealData)]
		label := normalizeLabel(result.DeviceCategory)
		if label == "" {
			label = "unknown"
		}
		if label == "unknown" {
			unknownCount++
		} else {
			labeledCount++
		}
		if realCount > 0 {
			devicesWithRealData++
		}
		observationCount += len(d.Observations)
		realDataObservationCount += realCount
		totalCalibrated += result.LabelConfidenceCalibrated

		key := stableDeviceKey(d)
		snapshot := profileDevice{
			Key:                      key,
			Label:                    label,
			CalibratedConfidence:     result.LabelConfidenceCalibrated,
			ObservationCount:         len(d.Observations),
			RealDataObservationCount: realCount,
		}
		results = append(results, snapshot)
		deviceMap[key] = snapshot
	}

	averageCalibrated := 0.0
	if len(prepared) > 0 {
		averageCalibrated = totalCalibrated / float64(len(prepared))
	}

	sort.Slice(results, func(i, j int) bool {
		if results[i].Label != results[j].Label {
			return results[i].Label < results[j].Label
		}
		return results[i].Key < results[j].Key
	})

	return profileEvaluation{
		Name:                        name,
		Description:                 description,
		Strategies:                  append([]string{}, strategyNames...),
		ObservationCount:            observationCount,
		RealDataObservationCount:    realDataObservationCount,
		DevicesWithRealData:         devicesWithRealData,
		LabeledCount:                labeledCount,
		UnknownCount:                unknownCount,
		AverageCalibratedConfidence: averageCalibrated,
		Devices:                     results,
		DeviceMap:                   deviceMap,
	}
}

func buildStrategyRanking(audit strategy.StrategyAudit, stats strategyStats, ablated, baseline profileEvaluation) StrategyRanking {
	deviceCount := len(baseline.Devices)
	hitCoverage := ratio(stats.TargetsHit, maxInt(deviceCount, stats.TargetCount()))
	realDataRate := ratio(stats.RealDataObservations, stats.TotalObservations)
	realDataLikelihood := likelihoodBand(realDataRate)
	agreementLoss, unknownIncrease, confidenceLoss := ablationLosses(ablated, baseline)
	dynamicLabelImpact := clamp01((agreementLoss * 0.65) + (ratio(maxInt(unknownIncrease, 0), maxInt(deviceCount, 1)) * 0.20) + (confidenceLoss * 0.15))
	discoveryScore := float64(audit.DiscoveryValue) / 5.0
	labelingScore := float64(audit.LabelingValue) / 5.0
	observabilityFactor := maxFloat(0.2, maxFloat(hitCoverage, maxFloat(realDataRate, dynamicLabelImpact)))
	valueScore := ((hitCoverage * 0.10) + (realDataRate * 0.10) + (discoveryScore * 0.20) + (labelingScore * 0.25) + (dynamicLabelImpact * 0.35)) * strategySignalFactor(audit) * observabilityFactor
	timeCost, timeSource := strategyTimeCost(stats, audit)

	return StrategyRanking{
		Name:                  audit.Name,
		Mode:                  audit.Mode,
		ExecutionClass:        audit.ExecutionClass,
		SpeedCost:             audit.SpeedCost,
		RealDataLikelihood:    realDataLikelihood,
		DiscoveryValue:        audit.DiscoveryValue,
		LabelingValue:         audit.LabelingValue,
		Recommendation:        audit.Recommendation,
		TargetsHit:            stats.TargetsHit,
		TotalObservations:     stats.TotalObservations,
		RealDataObservations:  stats.RealDataObservations,
		RealDataRate:          realDataRate,
		NoResponseCount:       stats.NoResponse,
		UnsupportedCount:      stats.Unsupported,
		NotApplicableCount:    stats.NotApplicable,
		TimeCost:              timeCost,
		TimeSource:            timeSource,
		LabelAgreementLoss:    agreementLoss,
		UnknownIncrease:       unknownIncrease,
		AverageConfidenceLoss: confidenceLoss,
		ValueScore:            valueScore,
		ValuePerUnitTime:      valueScore / maxFloat(timeCost, 0.1),
		Notes:                 audit.Notes,
	}
}

func strategySignalFactor(audit strategy.StrategyAudit) float64 {
	recommendationFactor := 1.0
	switch audit.Recommendation {
	case strategy.TierFastPath:
		recommendationFactor = 1.0
	case strategy.TierSecondWave:
		recommendationFactor = 0.9
	case strategy.TierExpensive:
		recommendationFactor = 0.75
	case strategy.TierContextual:
		recommendationFactor = 0.5
	case strategy.TierNoise:
		recommendationFactor = 0.25
	}

	executionFactor := 1.0
	switch audit.ExecutionClass {
	case strategy.ExecutionActive, strategy.ExecutionPassive:
		executionFactor = 1.0
	case strategy.ExecutionContextual:
		executionFactor = 0.85
	case strategy.ExecutionAmbient:
		executionFactor = 0.7
	}
	return recommendationFactor * executionFactor
}

func compareProfileLabels(baseline, current profileEvaluation) ([]LabelPreservation, []LabelChange, float64, int) {
	typeCounts := map[string]int{}
	typeSame := map[string]int{}
	changes := map[string]int{}
	same := 0
	total := 0
	changed := 0

	for key, base := range baseline.DeviceMap {
		cur, ok := current.DeviceMap[key]
		if !ok {
			cur = profileDevice{Key: key, Label: "unknown"}
		}
		total++
		if base.Label == cur.Label {
			same++
		} else {
			changed++
			changeKey := base.Label + "->" + cur.Label
			changes[changeKey]++
		}
		if base.Label == "unknown" {
			continue
		}
		typeCounts[base.Label]++
		if base.Label == cur.Label {
			typeSame[base.Label]++
		}
	}

	preserved := make([]LabelPreservation, 0, len(typeCounts))
	for label, count := range typeCounts {
		preserved = append(preserved, LabelPreservation{
			Label:         label,
			BaselineCount: count,
			SameCount:     typeSame[label],
			Agreement:     ratio(typeSame[label], count),
		})
	}
	sort.Slice(preserved, func(i, j int) bool {
		if preserved[i].Agreement != preserved[j].Agreement {
			return preserved[i].Agreement > preserved[j].Agreement
		}
		return preserved[i].Label < preserved[j].Label
	})

	degraded := make([]LabelChange, 0, len(changes))
	for key, count := range changes {
		parts := strings.SplitN(key, "->", 2)
		if len(parts) != 2 {
			continue
		}
		if parts[0] == "unknown" {
			continue
		}
		degraded = append(degraded, LabelChange{
			BaselineLabel: parts[0],
			NewLabel:      parts[1],
			Count:         count,
		})
	}
	sort.Slice(degraded, func(i, j int) bool {
		if degraded[i].Count != degraded[j].Count {
			return degraded[i].Count > degraded[j].Count
		}
		if degraded[i].BaselineLabel != degraded[j].BaselineLabel {
			return degraded[i].BaselineLabel < degraded[j].BaselineLabel
		}
		return degraded[i].NewLabel < degraded[j].NewLabel
	})
	if len(degraded) > 8 {
		degraded = degraded[:8]
	}
	return preserved, degraded, ratio(same, total), changed
}

func ablationLosses(ablated, baseline profileEvaluation) (float64, int, float64) {
	agreement := 0
	total := 0
	for key, base := range baseline.DeviceMap {
		cur, ok := ablated.DeviceMap[key]
		if !ok {
			cur = profileDevice{Key: key, Label: "unknown"}
		}
		total++
		if base.Label == cur.Label {
			agreement++
		}
	}
	agreementLoss := 1 - ratio(agreement, total)
	unknownIncrease := ablated.UnknownCount - baseline.UnknownCount
	confidenceLoss := baseline.AverageCalibratedConfidence - ablated.AverageCalibratedConfidence
	if confidenceLoss < 0 {
		confidenceLoss = 0
	}
	return agreementLoss, unknownIncrease, confidenceLoss
}

func strategyTimeCost(stats strategyStats, audit strategy.StrategyAudit) (float64, string) {
	if stats.DurationMs > 0 {
		return float64(stats.DurationMs) / 1000.0, "measured_seconds"
	}
	return audit.SpeedCost.Weight(), "speed_cost_weight"
}

func estimateProfileDuration(strategyNames []string, stats *experimentStats) (int64, string) {
	if len(strategyNames) == 0 {
		return 0, "none"
	}
	if stats != nil {
		var total int64
		measured := true
		for _, name := range strategyNames {
			item, ok := stats.ByStrategy[name]
			if !ok || item.DurationMs == 0 {
				measured = false
				break
			}
			total += item.DurationMs
		}
		if measured {
			return total, "measured"
		}
	}

	total := 0.0
	for _, name := range strategyNames {
		audit, ok := strategy.StrategyAuditForName(name)
		if !ok {
			continue
		}
		total += audit.SpeedCost.Weight() * 1000
	}
	return int64(total), "speed_cost_weight"
}

func loadExperimentStats(explicitPath string, inputs []string) (*experimentStats, []string) {
	candidates := []string{}
	if strings.TrimSpace(explicitPath) != "" {
		candidates = append(candidates, strings.TrimSpace(explicitPath))
	}
	for _, input := range inputs {
		candidates = append(candidates, strings.TrimSpace(input))
	}
	seen := map[string]struct{}{}
	for _, candidate := range candidates {
		if candidate == "" {
			continue
		}
		if _, ok := seen[candidate]; ok {
			continue
		}
		seen[candidate] = struct{}{}
		stats, err := readExperimentStats(candidate)
		if err == nil {
			return stats, nil
		}
	}
	return nil, []string{"no experiment-style strategy report found in provided inputs"}
}

func readExperimentStats(path string) (*experimentStats, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var envelope experimentEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, err
	}
	if len(envelope.StrategyReports) == 0 {
		return nil, fmt.Errorf("no strategy reports found")
	}
	out := &experimentStats{
		ScanDurationMs: envelope.ScanDurationMs,
		TargetCount:    envelope.TargetCount,
		ByStrategy:     make(map[string]strategyStats, len(envelope.StrategyReports)),
	}
	for _, item := range envelope.StrategyReports {
		out.ByStrategy[item.Strategy] = strategyStats{
			TargetsHit:           item.TargetsHit,
			TotalObservations:    item.TotalObservations,
			RealDataObservations: item.RealDataObservations,
			NoResponse:           item.ObservationStatusCounts[string(labeling.ObservationStatusNoResponse)],
			Unsupported:          item.ObservationStatusCounts[string(labeling.ObservationStatusUnsupported)],
			NotApplicable:        item.ObservationStatusCounts[string(labeling.ObservationStatusNotApplicable)],
			DurationMs:           item.DurationMs,
		}
	}
	return out, nil
}

func loadOptimizationDevices(inputs []string) ([]store.Device, error) {
	if len(inputs) == 0 {
		return nil, fmt.Errorf("no optimization inputs provided")
	}
	devices := make([]store.Device, 0)
	for _, input := range inputs {
		input = strings.TrimSpace(input)
		if input == "" {
			continue
		}
		loaded, err := evidence.LoadCorpus(input)
		if err != nil {
			continue
		}
		devices = append(devices, loaded...)
	}
	if len(devices) == 0 {
		return nil, fmt.Errorf("no corpus devices could be loaded")
	}
	return mergeOptimizationDevices(devices), nil
}

func mergeOptimizationDevices(devices []store.Device) []store.Device {
	if len(devices) == 0 {
		return nil
	}
	byKey := map[string]store.Device{}
	order := make([]string, 0, len(devices))
	for _, d := range devices {
		key := stableDeviceKey(d)
		if existing, ok := byKey[key]; ok {
			byKey[key] = mergeOptimizationDevice(existing, d)
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

func mergeOptimizationDevice(dst, src store.Device) store.Device {
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
		host := *src.Hostname
		dst.Hostname = &host
	}
	dst.PortsOpen = mergeInts(dst.PortsOpen, src.PortsOpen)
	dst.Flags = mergeStrings(dst.Flags, src.Flags)
	dst.SourcesSeen = mergeStrings(dst.SourcesSeen, src.SourcesSeen)
	dst.ProtocolsSeen = store.ProtocolsSeen{
		MDNS:    mergeStrings(dst.ProtocolsSeen.MDNS, src.ProtocolsSeen.MDNS),
		SSDP:    mergeStrings(dst.ProtocolsSeen.SSDP, src.ProtocolsSeen.SSDP),
		NetBIOS: mergeStrings(dst.ProtocolsSeen.NetBIOS, src.ProtocolsSeen.NetBIOS),
	}
	dst.Observations = mergeObservations(dst.Observations, src.Observations)
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
	return dst
}

func mergeInts(a, b []int) []int {
	seen := map[int]struct{}{}
	out := make([]int, 0, len(a)+len(b))
	for _, value := range append(append([]int{}, a...), b...) {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Ints(out)
	return out
}

func mergeStrings(a, b []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(a)+len(b))
	for _, value := range append(append([]string{}, a...), b...) {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func mergeObservations(a, b []store.Observation) []store.Observation {
	type key struct {
		Strategy string
		Key      string
		Value    string
		IP       string
	}
	seen := map[key]struct{}{}
	out := make([]store.Observation, 0, len(a)+len(b))
	for _, observation := range append(append([]store.Observation{}, a...), b...) {
		k := key{Strategy: observation.Strategy, Key: observation.Key, Value: observation.Value, IP: observation.IP}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, observation)
	}
	return out
}

func stableDeviceKey(d store.Device) string {
	if key := evidence.StableDeviceKey(&d); strings.TrimSpace(key) != "" && key != "unknown" {
		return key
	}
	if strings.TrimSpace(d.ID) != "" {
		return strings.ToLower(strings.TrimSpace(d.ID))
	}
	if strings.TrimSpace(d.MAC) != "" {
		return strings.ToLower(strings.TrimSpace(d.MAC))
	}
	if strings.TrimSpace(d.IP) != "" {
		return "ip:" + strings.TrimSpace(d.IP)
	}
	return "unknown"
}

func normalizeLabel(label string) string {
	label = strings.ToLower(strings.TrimSpace(label))
	if label == "" || label == "unlabeled" {
		return "unknown"
	}
	return label
}

func normalizeProfileNames(names []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(names))
	for _, name := range names {
		name = strings.ToLower(strings.TrimSpace(name))
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

func withoutStrategy(names []string, removed string) []string {
	out := make([]string, 0, len(names))
	for _, name := range names {
		if strings.EqualFold(strings.TrimSpace(name), strings.TrimSpace(removed)) {
			continue
		}
		out = append(out, name)
	}
	return out
}

func likelihoodBand(rate float64) string {
	switch {
	case rate >= 0.80:
		return "very_high"
	case rate >= 0.55:
		return "high"
	case rate >= 0.30:
		return "medium"
	case rate > 0:
		return "low"
	default:
		return "very_low"
	}
}

func ratio(num, den int) float64 {
	if den == 0 {
		return 0
	}
	return float64(num) / float64(den)
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func maxFloat(a, b float64) float64 {
	if a > b {
		return a
	}
	return b
}

func (s strategyStats) TargetCount() int {
	if s.TargetsHit > 0 {
		return s.TargetsHit
	}
	return 0
}
