package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/netwise/agent/internal/config"
	"github.com/netwise/agent/internal/evidence"
	"github.com/netwise/agent/internal/labeling"
	"github.com/netwise/agent/internal/network"
	"github.com/netwise/agent/internal/store"
	"github.com/netwise/agent/internal/strategy"
)

type StrategyExperimentReport struct {
	ScanID               string                  `json:"scan_id"`
	Source               string                  `json:"source,omitempty"`
	StrategyProfile      string                  `json:"strategy_profile,omitempty"`
	CorpusInputs         []string                `json:"corpus_inputs,omitempty"`
	Network              store.NetworkInfo       `json:"network"`
	Devices              []store.Device          `json:"devices,omitempty"`
	StartedAt            string                  `json:"started_at"`
	FinishedAt           string                  `json:"finished_at"`
	ScanDurationMs       int64                   `json:"scan_duration_ms"`
	TargetCount          int                     `json:"target_count"`
	TargetsWithEvidence  int                     `json:"targets_with_evidence"`
	StrategyReports      []StrategyYield         `json:"strategy_reports"`
	TargetSummaries      []TargetSummary         `json:"target_summaries"`
	LabelSummary         *LabelExperimentSummary `json:"label_summary,omitempty"`
	EvidenceGraph        *EvidenceGraphSummary   `json:"evidence_graph,omitempty"`
	NoDataTargetIPs      []string                `json:"no_data_target_ips,omitempty"`
	StrategyAvailability map[string]int          `json:"strategy_availability,omitempty"`
}

type StrategyYield struct {
	Strategy                string         `json:"strategy"`
	DurationMs              int64          `json:"duration_ms,omitempty"`
	TargetsHit              int            `json:"targets_hit"`
	TargetsNoData           int            `json:"targets_no_data"`
	TotalObservations       int            `json:"total_observations"`
	RealDataObservations    int            `json:"real_data_observations,omitempty"`
	DirectMatchObservations int            `json:"direct_match_observations,omitempty"`
	StrongInferredObservations int         `json:"strong_inferred_observations,omitempty"`
	AmbientContextObservations int         `json:"ambient_context_observations,omitempty"`
	ObservationStatusCounts map[string]int `json:"observation_status_counts,omitempty"`
}

type TargetSummary struct {
	IP                      string            `json:"ip"`
	MAC                     string            `json:"mac"`
	Hostname                string            `json:"hostname,omitempty"`
	DeviceType              string            `json:"device_type,omitempty"`
	Confidence              float64           `json:"confidence,omitempty"`
	LabelState              *store.LabelState `json:"label_state,omitempty"`
	StrategiesWithAny       int               `json:"strategies_with_any"`
	Observations            int               `json:"observations"`
	RealDataObservations    int               `json:"real_data_observations,omitempty"`
	ObservationStatusCounts map[string]int    `json:"observation_status_counts,omitempty"`
	TopSignals              []SignalBucket    `json:"top_signals,omitempty"`
}

type SignalBucket struct {
	Key        string `json:"key"`
	Count      int    `json:"count"`
	FirstValue string `json:"first_value,omitempty"`
}

type LabelCount struct {
	Label string `json:"label"`
	Count int    `json:"count"`
}

type LabelExperimentSummary struct {
	DeviceCount                 int            `json:"device_count"`
	LabeledCount                int            `json:"labeled_count"`
	UnknownCount                int            `json:"unknown_count"`
	ConflictCount               int            `json:"conflict_count"`
	ObservationStatusCounts     map[string]int `json:"observation_status_counts,omitempty"`
	BandCounts                  map[string]int `json:"band_counts,omitempty"`
	AverageConfidence           float64        `json:"average_confidence,omitempty"`
	AverageCalibratedConfidence float64        `json:"average_calibrated_confidence,omitempty"`
	TopLabels                   []LabelCount   `json:"top_labels,omitempty"`
	TopCandidateLabels          []LabelCount   `json:"top_candidate_labels,omitempty"`
}

type EvidenceGraphSummary struct {
	BuiltAt             string `json:"built_at"`
	DeviceCount         int    `json:"device_count"`
	TotalSignals        int    `json:"total_signals"`
	ObservedDevices     int    `json:"observed_devices"`
	DevicesWithEvidence int    `json:"devices_with_evidence"`
}

func RunStrategyExperiment(netInfo *network.Info, cfg *config.Config, strategyNames []string) (*StrategyExperimentReport, error) {
	if netInfo == nil {
		return nil, fmt.Errorf("missing network info")
	}
	if cfg == nil {
		cfg = config.Default()
	}

	st := store.New()
	scanID := store.NewScanID()
	st.StartScan(scanID, netInfo)
	sc := NewWithStrategyFilter(netInfo, cfg, st, scanID, strategyNames)

	started := time.Now().UTC()
	sc.Run()
	st.FinishScan(scanID)
	result := st.GetScanResult(scanID)
	if result == nil {
		return nil, fmt.Errorf("scan result missing for %s", scanID)
	}
	finishedAt := time.Now().UTC()
	if result.ScanFinishedAt != nil && *result.ScanFinishedAt != "" {
		finishedAt, _ = time.Parse(time.RFC3339, *result.ScanFinishedAt)
	}

	report := buildStrategyExperimentReport(result, sc.StrategyNames(), cfg)
	report.ScanID = scanID
	report.Network = result.Network
	report.StartedAt = result.ScanStartedAt
	report.FinishedAt = finishedAt.Format(time.RFC3339)
	report.StrategyProfile = resolveStrategyProfile(cfg, strategyNames)
	if report.FinishedAt == "" && len(result.Devices) == 0 {
		report.FinishedAt = started.Format(time.RFC3339)
	}
	report.ScanDurationMs = finishedAt.Sub(started).Milliseconds()
	applyStrategyRunStats(report, sc.StrategyRunStats())
	return report, nil
}

func RunCorpusExperiment(inputs []string, cfg *config.Config, strategyNames []string) (*StrategyExperimentReport, error) {
	if cfg == nil {
		cfg = config.Default()
	}
	devices, corpusInputs, err := loadCorpusDevices(inputs)
	if err != nil {
		return nil, err
	}
	selected := effectiveStrategyNames(cfg, strategyNames)
	devices = FilterDevicesForStrategySubset(devices, selected)
	now := time.Now().UTC().Format(time.RFC3339)
	networkInfo := store.NetworkInfo{}
	report := buildStrategyExperimentReportFromDevices(devices, networkInfo, "corpus", now, now, selected, cfg, "corpus", corpusInputs)
	report.StrategyProfile = resolveStrategyProfile(cfg, strategyNames)
	return report, nil
}

func buildStrategyExperimentReport(result *store.ScanResult, strategyNames []string, cfg *config.Config) *StrategyExperimentReport {
	finishedAt := ""
	if result != nil && result.ScanFinishedAt != nil {
		finishedAt = *result.ScanFinishedAt
	}
	devices := FilterDevicesForStrategySubset(result.Devices, effectiveStrategyNames(cfg, strategyNames))
	report := buildStrategyExperimentReportFromDevices(devices, result.Network, result.ScanID, result.ScanStartedAt, finishedAt, effectiveStrategyNames(cfg, strategyNames), cfg, "live", nil)
	report.StrategyProfile = resolveStrategyProfile(cfg, strategyNames)
	return report
}

func buildStrategyExperimentReportFromDevices(devices []store.Device, networkInfo store.NetworkInfo, scanID, startedAt, finishedAt string, strategyNames []string, cfg *config.Config, source string, corpusInputs []string) *StrategyExperimentReport {
	totalTargets := len(devices)
	strategyToTargets := map[string]map[string]struct{}{}
	strategyCounts := map[string]int{}
	strategyRealCounts := map[string]int{}
	strategyDirectCounts := map[string]int{}
	strategyStrongCounts := map[string]int{}
	strategyAmbientCounts := map[string]int{}
	strategyStatusCounts := map[string]map[string]int{}
	targetNoData := []string{}
	targetSummaries := make([]TargetSummary, 0, totalTargets)
	if cfg == nil {
		cfg = config.Default()
	}
	privacyCfg := privacyModeFromConfig(cfg)
	labeledDevices := make([]store.Device, 0, len(devices))
	for _, d := range devices {
		labeledDevices = append(labeledDevices, ensureExperimentLabelState(d, cfg, privacyCfg))
	}

	for _, d := range labeledDevices {
		statusCounts := labeling.CountObservationStatuses(d.Observations)
		realDataCount := statusCounts[string(labeling.ObservationStatusRealData)]
		hasData := realDataCount > 0
		if !hasData {
			targetNoData = append(targetNoData, d.IP)
		}

		perStrategy := map[string]int{}
		signalCounts := map[string]int{}
		signalExamples := map[string]string{}
		for _, o := range d.Observations {
			strategyCounts[o.Strategy]++
			status := string(labeling.ClassifyObservationStatus(o))
			if strategyStatusCounts[o.Strategy] == nil {
				strategyStatusCounts[o.Strategy] = map[string]int{}
			}
			strategyStatusCounts[o.Strategy][status]++
			if status != string(labeling.ObservationStatusRealData) {
				continue
			}
			strategyRealCounts[o.Strategy]++
			switch strings.ToLower(strings.TrimSpace(o.Details["match_quality"])) {
			case "direct_match":
				strategyDirectCounts[o.Strategy]++
			case "strong_inferred_match":
				strategyStrongCounts[o.Strategy]++
			case "ambient_context":
				strategyAmbientCounts[o.Strategy]++
			}
			perStrategy[o.Strategy] = 1
			key := o.Strategy + "|" + o.Key
			signalCounts[key]++
			if _, ok := signalExamples[key]; !ok {
				signalExamples[key] = o.Value
			}
		}
		for strat := range perStrategy {
			if strategyToTargets[strat] == nil {
				strategyToTargets[strat] = map[string]struct{}{}
			}
			strategyToTargets[strat][d.IP] = struct{}{}
		}

		topSignals := make([]SignalBucket, 0, len(signalCounts))
		for k, c := range signalCounts {
			topSignals = append(topSignals, SignalBucket{
				Key:        k,
				Count:      c,
				FirstValue: signalExamples[k],
			})
		}
		sort.Slice(topSignals, func(i, j int) bool {
			if topSignals[i].Count != topSignals[j].Count {
				return topSignals[i].Count > topSignals[j].Count
			}
			return topSignals[i].Key < topSignals[j].Key
		})
		if len(topSignals) > 6 {
			topSignals = topSignals[:6]
		}

		hostname := ""
		if d.Hostname != nil {
			hostname = *d.Hostname
		}
		targetSummaries = append(targetSummaries, TargetSummary{
			DeviceType:              d.DeviceType,
			Confidence:              d.Confidence,
			LabelState:              labelStatePtr(d.LabelState),
			IP:                      d.IP,
			MAC:                     d.MAC,
			Hostname:                hostname,
			StrategiesWithAny:       len(perStrategy),
			Observations:            len(d.Observations),
			RealDataObservations:    realDataCount,
			ObservationStatusCounts: statusCounts,
			TopSignals:              topSignals,
		})
	}

	strategiesForReport := strategy.ResolveStrategies(strategyNames)
	strategyReports := make([]StrategyYield, 0, len(strategiesForReport))
	availability := map[string]int{}
	for _, strat := range strategiesForReport {
		name := strat.Name()
		hitTargets := len(strategyToTargets[name])
		obsCount := strategyCounts[name]
		statusCounts := strategyStatusCounts[name]
		if statusCounts == nil {
			statusCounts = map[string]int{}
		}
		availability[name] = hitTargets
		strategyReports = append(strategyReports, StrategyYield{
			Strategy:                name,
			TargetsHit:              hitTargets,
			TargetsNoData:           totalTargets - hitTargets,
			TotalObservations:       obsCount,
			RealDataObservations:    strategyRealCounts[name],
			DirectMatchObservations: strategyDirectCounts[name],
			StrongInferredObservations: strategyStrongCounts[name],
			AmbientContextObservations: strategyAmbientCounts[name],
			ObservationStatusCounts: copyStringIntMap(statusCounts),
		})
	}

	sort.Slice(strategyReports, func(i, j int) bool {
		if strategyReports[i].TotalObservations != strategyReports[j].TotalObservations {
			return strategyReports[i].TotalObservations > strategyReports[j].TotalObservations
		}
		return strategyReports[i].Strategy < strategyReports[j].Strategy
	})
	sort.Slice(targetSummaries, func(i, j int) bool {
		if targetSummaries[i].Observations != targetSummaries[j].Observations {
			return targetSummaries[i].Observations > targetSummaries[j].Observations
		}
		return targetSummaries[i].IP < targetSummaries[j].IP
	})

	labelSummary := buildLabelExperimentSummary(labeledDevices)
	graph := evidence.BuildEvidenceGraph(labeledDevices, privacyCfg)

	return &StrategyExperimentReport{
		ScanID:               scanID,
		Source:               source,
		CorpusInputs:         corpusInputs,
		Network:              networkInfo,
		Devices:              labeledDevices,
		StartedAt:            startedAt,
		FinishedAt:           finishedAt,
		ScanDurationMs:       computeDurationMs(startedAt, finishedAt),
		TargetCount:          totalTargets,
		TargetsWithEvidence:  totalTargets - len(targetNoData),
		StrategyReports:      strategyReports,
		TargetSummaries:      targetSummaries,
		LabelSummary:         labelSummary,
		EvidenceGraph:        toEvidenceGraphSummary(graph),
		NoDataTargetIPs:      targetNoData,
		StrategyAvailability: availability,
	}
}

func applyStrategyRunStats(report *StrategyExperimentReport, runStats []StrategyRunStat) {
	if report == nil || len(report.StrategyReports) == 0 || len(runStats) == 0 {
		return
	}
	byStrategy := make(map[string]StrategyRunStat, len(runStats))
	for _, stat := range runStats {
		byStrategy[stat.Strategy] = stat
	}
	for i := range report.StrategyReports {
		if stat, ok := byStrategy[report.StrategyReports[i].Strategy]; ok {
			report.StrategyReports[i].DurationMs = stat.DurationMs
		}
	}
}

func buildLabelExperimentSummary(devices []store.Device) *LabelExperimentSummary {
	if len(devices) == 0 {
		return &LabelExperimentSummary{
			BandCounts:              map[string]int{},
			ObservationStatusCounts: map[string]int{},
		}
	}

	summary := &LabelExperimentSummary{
		DeviceCount:             len(devices),
		BandCounts:              map[string]int{},
		ObservationStatusCounts: map[string]int{},
	}
	labelCounts := map[string]int{}
	candidateCounts := map[string]int{}
	var totalConfidence float64
	var totalCalibrated float64

	for _, d := range devices {
		for status, count := range labeling.CountObservationStatuses(d.Observations) {
			summary.ObservationStatusCounts[status] += count
		}
		label := strings.TrimSpace(strings.ToLower(d.DeviceType))
		if label == "" {
			label = strings.TrimSpace(strings.ToLower(d.LabelState.DeviceCategory))
		}
		if label == "" || label == "unknown" || label == "unlabeled" {
			summary.UnknownCount++
		} else {
			summary.LabeledCount++
			labelCounts[label]++
		}

		if len(d.LabelState.ConflictFlags) > 0 {
			summary.ConflictCount++
		}
		if band := strings.TrimSpace(d.LabelState.ConfidenceBand); band != "" {
			summary.BandCounts[band]++
		}
		totalConfidence += d.LabelState.LabelConfidence
		totalCalibrated += d.LabelState.LabelConfidenceCalibrated
		for _, c := range d.LabelState.CandidateLabels {
			if strings.TrimSpace(c.Label) == "" {
				continue
			}
			candidateCounts[strings.ToLower(strings.TrimSpace(c.Label))]++
		}
	}

	summary.AverageConfidence = totalConfidence / float64(len(devices))
	summary.AverageCalibratedConfidence = totalCalibrated / float64(len(devices))
	summary.TopLabels = topLabelCounts(labelCounts, 5)
	summary.TopCandidateLabels = topLabelCounts(candidateCounts, 5)
	return summary
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

func toEvidenceGraphSummary(graph evidence.EvidenceGraph) *EvidenceGraphSummary {
	return &EvidenceGraphSummary{
		BuiltAt:             graph.BuiltAt.UTC().Format(time.RFC3339),
		DeviceCount:         graph.Counters.DeviceCount,
		TotalSignals:        graph.Counters.TotalSignals,
		ObservedDevices:     graph.Counters.ObservedDevices,
		DevicesWithEvidence: graph.Counters.DevicesWithEvidence,
	}
}

func ensureExperimentLabelState(d store.Device, cfg *config.Config, privacyCfg evidence.PrivacyConfig) store.Device {
	if hasExperimentLabelState(d) {
		return d
	}
	res := labeling.ClassifyDevice(d, cfg)
	if cfg == nil {
		res = labeling.ClassifyDeviceWithPrivacy(d, privacyCfg)
	}
	d.DeviceType = res.DeviceCategory
	d.Confidence = res.LabelConfidence
	d.LabelState = toStoreLabelState(res)
	if len(d.ClassificationReasons) == 0 {
		d.ClassificationReasons = append([]string{}, res.ReasonChain...)
	}
	return d
}

func hasExperimentLabelState(d store.Device) bool {
	if label := strings.TrimSpace(strings.ToLower(d.DeviceType)); label != "" && label != "unknown" && label != "unlabeled" {
		return true
	}
	if label := strings.TrimSpace(strings.ToLower(d.LabelState.DeviceCategory)); label != "" && label != "unknown" && label != "unlabeled" {
		return true
	}
	if strings.TrimSpace(d.LabelState.DeviceSubType) != "" {
		return true
	}
	if d.LabelState.LabelConfidence > 0 || d.LabelState.LabelConfidenceCalibrated > 0 {
		return true
	}
	if len(d.LabelState.EvidenceSummary) > 0 || len(d.LabelState.CandidateLabels) > 0 || len(d.LabelState.ReasonChain) > 0 {
		return true
	}
	return false
}

func labelStatePtr(state store.LabelState) *store.LabelState {
	if !hasLabelStateValue(state) {
		return nil
	}
	cp := state
	return &cp
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

func computeDurationMs(startedAt, finishedAt string) int64 {
	start, err := time.Parse(time.RFC3339, strings.TrimSpace(startedAt))
	if err != nil {
		return 0
	}
	finish, err := time.Parse(time.RFC3339, strings.TrimSpace(finishedAt))
	if err != nil {
		return 0
	}
	if finish.Before(start) {
		return 0
	}
	return finish.Sub(start).Milliseconds()
}

func loadCorpusDevices(inputs []string) ([]store.Device, []string, error) {
	if len(inputs) == 0 {
		return nil, nil, fmt.Errorf("no corpus inputs provided")
	}

	expanded, err := expandCorpusInputs(inputs)
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
	return mergeExperimentDevices(merged), expanded, nil
}

func expandCorpusInputs(inputs []string) ([]string, error) {
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

func mergeExperimentDevices(devices []store.Device) []store.Device {
	if len(devices) == 0 {
		return nil
	}
	byID := map[string]store.Device{}
	order := make([]string, 0, len(devices))
	for _, d := range devices {
		key := experimentDeviceKey(d)
		if existing, ok := byID[key]; ok {
			byID[key] = mergeExperimentDevice(existing, d)
			continue
		}
		byID[key] = d
		order = append(order, key)
	}
	out := make([]store.Device, 0, len(order))
	for _, key := range order {
		out = append(out, byID[key])
	}
	return out
}

func mergeExperimentDevice(dst, src store.Device) store.Device {
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
	if len(dst.PortsOpen) == 0 {
		dst.PortsOpen = append([]int{}, src.PortsOpen...)
	} else {
		dst.PortsOpen = mergeIntSlices(dst.PortsOpen, src.PortsOpen)
	}
	dst.Flags = mergeStringSlices(dst.Flags, src.Flags)
	dst.SourcesSeen = mergeStringSlices(dst.SourcesSeen, src.SourcesSeen)
	dst.ProtocolsSeen.MDNS = mergeStringSlices(dst.ProtocolsSeen.MDNS, src.ProtocolsSeen.MDNS)
	dst.ProtocolsSeen.SSDP = mergeStringSlices(dst.ProtocolsSeen.SSDP, src.ProtocolsSeen.SSDP)
	dst.ProtocolsSeen.NetBIOS = mergeStringSlices(dst.ProtocolsSeen.NetBIOS, src.ProtocolsSeen.NetBIOS)
	dst.Observations = mergeObservationSlices(dst.Observations, src.Observations)
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
	if !hasExperimentLabelState(dst) && hasExperimentLabelState(src) {
		dst.DeviceType = src.DeviceType
		dst.Confidence = src.Confidence
		dst.LabelState = src.LabelState
	}
	if dst.FirstSeen == "" {
		dst.FirstSeen = src.FirstSeen
	}
	if src.FirstSeen != "" && (dst.FirstSeen == "" || src.FirstSeen < dst.FirstSeen) {
		dst.FirstSeen = src.FirstSeen
	}
	if src.LastSeen != "" && (dst.LastSeen == "" || src.LastSeen > dst.LastSeen) {
		dst.LastSeen = src.LastSeen
	}
	return dst
}

func experimentDeviceKey(d store.Device) string {
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

func privacyModeFromConfig(cfg *config.Config) evidence.PrivacyConfig {
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

func copyStringIntMap(in map[string]int) map[string]int {
	if len(in) == 0 {
		return map[string]int{}
	}
	out := make(map[string]int, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func FilterDevicesForStrategySubset(devices []store.Device, strategyNames []string) []store.Device {
	if len(devices) == 0 {
		return nil
	}
	allowed := make(map[string]struct{}, len(strategyNames))
	for _, name := range strategyNames {
		normalized := normalizeExperimentStrategyName(name)
		if normalized == "" {
			continue
		}
		allowed[normalized] = struct{}{}
	}

	out := make([]store.Device, 0, len(devices))
	for _, src := range devices {
		d := cloneExperimentDevice(src)
		d.DeviceType = ""
		d.Confidence = 0
		d.LabelState = store.LabelState{}
		d.ClassificationReasons = nil
		if len(allowed) > 0 {
			filtered := make([]store.Observation, 0, len(d.Observations))
			for _, obs := range d.Observations {
				if _, ok := allowed[normalizeExperimentStrategyName(obs.Strategy)]; !ok {
					continue
				}
				filtered = append(filtered, obs)
			}
			d.Observations = filtered
		}
		out = append(out, d)
	}
	return out
}

func normalizeExperimentStrategyName(name string) string {
	return strings.ToLower(strings.TrimSpace(name))
}

func cloneExperimentDevice(src store.Device) store.Device {
	dst := src
	if src.Hostname != nil {
		hostname := *src.Hostname
		dst.Hostname = &hostname
	}
	dst.PortsOpen = append([]int{}, src.PortsOpen...)
	dst.Flags = append([]string{}, src.Flags...)
	dst.SourcesSeen = append([]string{}, src.SourcesSeen...)
	dst.ProtocolsSeen = store.ProtocolsSeen{
		MDNS:    append([]string{}, src.ProtocolsSeen.MDNS...),
		SSDP:    append([]string{}, src.ProtocolsSeen.SSDP...),
		NetBIOS: append([]string{}, src.ProtocolsSeen.NetBIOS...),
	}
	dst.Observations = append([]store.Observation{}, src.Observations...)
	return dst
}

func effectiveStrategyNames(cfg *config.Config, strategyNames []string) []string {
	if len(strategyNames) > 0 {
		return append([]string{}, strategyNames...)
	}
	if cfg == nil {
		return nil
	}
	if names := strategy.ProfileStrategyNames(cfg.StrategyProfile); len(names) > 0 {
		return names
	}
	return nil
}

func resolveStrategyProfile(cfg *config.Config, strategyNames []string) string {
	if len(strategyNames) > 0 {
		return "custom"
	}
	if cfg == nil || strings.TrimSpace(cfg.StrategyProfile) == "" {
		return "full"
	}
	if _, ok := strategy.ResolveProfile(cfg.StrategyProfile); ok {
		return strings.ToLower(strings.TrimSpace(cfg.StrategyProfile))
	}
	return "full"
}
