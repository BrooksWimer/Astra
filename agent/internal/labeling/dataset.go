package labeling

import (
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/netwise/agent/internal/config"
	"github.com/netwise/agent/internal/evidence"
	"github.com/netwise/agent/internal/store"
)

type Dataset struct {
	GeneratedAt             time.Time                 `json:"generated_at"`
	Source                  string                    `json:"source"`
	CorpusInputs            []string                  `json:"corpus_inputs,omitempty"`
	DeviceCount             int                       `json:"device_count"`
	ObservationStatusCounts map[string]int            `json:"observation_status_counts,omitempty"`
	FeatureVectors          []FeatureVector           `json:"feature_vectors"`
	ActiveLearning          []ActiveLearningCandidate `json:"active_learning,omitempty"`
}

type FeatureVector struct {
	DeviceKey                string                 `json:"device_key"`
	DeviceID                 string                 `json:"device_id"`
	IP                       string                 `json:"ip"`
	MAC                      string                 `json:"mac"`
	Hostname                 string                 `json:"hostname,omitempty"`
	ManualLabel              string                 `json:"manual_label,omitempty"`
	SeedLabel                string                 `json:"seed_label,omitempty"`
	ResolvedLabel            string                 `json:"resolved_label"`
	Confidence               float64                `json:"confidence"`
	CalibratedConfidence     float64                `json:"calibrated_confidence"`
	ConfidenceBand           string                 `json:"confidence_band,omitempty"`
	ConflictFlags            []string               `json:"conflict_flags,omitempty"`
	CandidateLabels          []store.LabelCandidate `json:"candidate_labels,omitempty"`
	ObservationCount         int                    `json:"observation_count"`
	ObservationStatusCounts  map[string]int         `json:"observation_status_counts,omitempty"`
	RealDataObservationCount int                    `json:"real_data_observation_count,omitempty"`
	SourcesSeen              []string               `json:"sources_seen,omitempty"`
	PortsOpen                []int                  `json:"ports_open,omitempty"`
	EvidenceFamilyCounts     map[string]int         `json:"evidence_family_counts,omitempty"`
	StrategyCounts           map[string]int         `json:"strategy_counts,omitempty"`
	SignalCounts             map[string]int         `json:"signal_counts,omitempty"`
	TemporalBins             map[string]int         `json:"temporal_bins,omitempty"`
	HitFrequency             float64                `json:"hit_frequency,omitempty"`
	RepeatedObservations     int                    `json:"repeated_observations,omitempty"`
	StaleSignalScore         float64                `json:"stale_signal_score,omitempty"`
}

type ActiveLearningCandidate struct {
	DeviceKey       string                 `json:"device_key"`
	DeviceID        string                 `json:"device_id"`
	ResolvedLabel   string                 `json:"resolved_label"`
	Entropy         float64                `json:"entropy"`
	ConflictCount   int                    `json:"conflict_count"`
	ExpectedGain    float64                `json:"expected_gain"`
	Unknown         bool                   `json:"unknown"`
	CandidateLabels []store.LabelCandidate `json:"candidate_labels,omitempty"`
	ReasonChain     []string               `json:"reason_chain,omitempty"`
}

func BuildDatasetFromDevices(devices []store.Device, cfg *config.Config) Dataset {
	devices = mergeDatasetDevices(devices)
	privacyCfg := datasetPrivacyConfig(cfg)
	featureVectors := make([]FeatureVector, 0, len(devices))
	activeLearning := make([]ActiveLearningCandidate, 0, len(devices))
	statusTotals := map[string]int{}

	for _, raw := range devices {
		d := ensureDatasetLabelState(raw, cfg)
		statusCounts := CountObservationStatuses(d.Observations)
		for status, count := range statusCounts {
			statusTotals[status] += count
		}
		key := evidence.StableDeviceKey(&d)
		profile := evidence.BuildProfile(key, ActionableObservations(d.Observations), privacyCfg)
		vector := FeatureVector{
			DeviceKey:                key,
			DeviceID:                 d.ID,
			IP:                       d.IP,
			MAC:                      d.MAC,
			Hostname:                 datasetHostname(d.Hostname),
			ManualLabel:              optionalDatasetLabel(manualLabelForDataset(d)),
			SeedLabel:                datasetSeedLabel(d),
			ResolvedLabel:            normalizedDatasetLabel(datasetResolvedLabel(d)),
			Confidence:               d.LabelState.LabelConfidence,
			CalibratedConfidence:     d.LabelState.LabelConfidenceCalibrated,
			ConfidenceBand:           strings.TrimSpace(d.LabelState.ConfidenceBand),
			ConflictFlags:            append([]string{}, d.LabelState.ConflictFlags...),
			CandidateLabels:          append([]store.LabelCandidate{}, d.LabelState.CandidateLabels...),
			ObservationCount:         len(d.Observations),
			ObservationStatusCounts:  statusCounts,
			RealDataObservationCount: statusCounts[string(ObservationStatusRealData)],
			SourcesSeen:              append([]string{}, d.SourcesSeen...),
			PortsOpen:                append([]int{}, d.PortsOpen...),
			EvidenceFamilyCounts:     profileFamilyCounts(profile),
			StrategyCounts:           copyStringIntMap(profile.StrategyCounts),
			SignalCounts:             copyStringIntMap(profile.SignalCounts),
			TemporalBins:             copyStringIntMap(profile.TemporalBins),
			HitFrequency:             profile.HitFrequency,
			RepeatedObservations:     profile.RepeatedObservations,
			StaleSignalScore:         profile.StaleSignalScore,
		}
		featureVectors = append(featureVectors, vector)
		activeLearning = append(activeLearning, ActiveLearningCandidate{
			DeviceKey:       key,
			DeviceID:        d.ID,
			ResolvedLabel:   vector.ResolvedLabel,
			Entropy:         candidateEntropy(d.LabelState.CandidateLabels),
			ConflictCount:   len(d.LabelState.ConflictFlags),
			ExpectedGain:    expectedLearningGain(d),
			Unknown:         vector.ResolvedLabel == "unknown",
			CandidateLabels: append([]store.LabelCandidate{}, d.LabelState.CandidateLabels...),
			ReasonChain:     append([]string{}, d.LabelState.ReasonChain...),
		})
	}

	sort.Slice(featureVectors, func(i, j int) bool {
		if featureVectors[i].ResolvedLabel != featureVectors[j].ResolvedLabel {
			return featureVectors[i].ResolvedLabel < featureVectors[j].ResolvedLabel
		}
		return featureVectors[i].DeviceKey < featureVectors[j].DeviceKey
	})
	sort.Slice(activeLearning, func(i, j int) bool {
		if activeLearning[i].ExpectedGain != activeLearning[j].ExpectedGain {
			return activeLearning[i].ExpectedGain > activeLearning[j].ExpectedGain
		}
		if activeLearning[i].Entropy != activeLearning[j].Entropy {
			return activeLearning[i].Entropy > activeLearning[j].Entropy
		}
		return activeLearning[i].DeviceKey < activeLearning[j].DeviceKey
	})
	if len(activeLearning) > 25 {
		activeLearning = activeLearning[:25]
	}

	return Dataset{
		GeneratedAt:             time.Now().UTC(),
		Source:                  "devices",
		DeviceCount:             len(featureVectors),
		ObservationStatusCounts: statusTotals,
		FeatureVectors:          featureVectors,
		ActiveLearning:          activeLearning,
	}
}

func BuildDatasetFromCorpusPath(path string, cfg *config.Config) (Dataset, error) {
	return BuildDatasetFromCorpusInputs([]string{path}, cfg)
}

func BuildDatasetFromCorpusInputs(inputs []string, cfg *config.Config) (Dataset, error) {
	devices := make([]store.Device, 0)
	resolved, err := expandDatasetInputs(inputs)
	if err != nil {
		return Dataset{}, err
	}
	if len(resolved) == 0 {
		return Dataset{}, os.ErrNotExist
	}
	for _, input := range resolved {
		corpusDevices, err := evidence.LoadCorpus(input)
		if err != nil {
			continue
		}
		devices = append(devices, corpusDevices...)
	}
	if len(devices) == 0 {
		return Dataset{}, os.ErrNotExist
	}
	dataset := BuildDatasetFromDevices(devices, cfg)
	dataset.Source = "corpus"
	dataset.CorpusInputs = resolved
	return dataset, nil
}

func ensureDatasetLabelState(d store.Device, cfg *config.Config) store.Device {
	if label := strings.TrimSpace(strings.ToLower(d.LabelState.DeviceCategory)); label != "" && label != "unknown" && label != "unlabeled" {
		if strings.TrimSpace(d.DeviceType) == "" {
			d.DeviceType = d.LabelState.DeviceCategory
		}
		if d.Confidence == 0 {
			d.Confidence = d.LabelState.LabelConfidence
		}
		return d
	}
	res := ClassifyDevice(d, cfg)
	d.DeviceType = res.DeviceCategory
	d.Confidence = res.LabelConfidence
	d.LabelState = store.LabelState{
		DeviceCategory:            res.DeviceCategory,
		DeviceSubType:             res.DeviceSubType,
		LabelConfidence:           res.LabelConfidence,
		LabelConfidenceCalibrated: res.LabelConfidenceCalibrated,
		EvidenceSummary:           append([]string{}, res.EvidenceSummary...),
		ReasonChain:               append([]string{}, res.ReasonChain...),
		ConflictFlags:             append([]string{}, res.ConflictFlags...),
		ConfidenceBand:            string(res.ConfidenceBand),
	}
	if len(res.CandidateLabels) > 0 {
		d.LabelState.CandidateLabels = make([]store.LabelCandidate, 0, len(res.CandidateLabels))
		for _, c := range res.CandidateLabels {
			d.LabelState.CandidateLabels = append(d.LabelState.CandidateLabels, store.LabelCandidate{
				Label:        c.Label,
				Score:        c.Score,
				Confidence:   c.Confidence,
				Evidence:     append([]string{}, c.Evidence...),
				SupportTiers: copyStringIntMap(c.SupportTiers),
			})
		}
	}
	return d
}

func datasetPrivacyConfig(cfg *config.Config) evidence.PrivacyConfig {
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

func profileFamilyCounts(profile evidence.Profile) map[string]int {
	out := make(map[string]int, len(profile.FamilyCounts))
	for key, value := range profile.FamilyCounts {
		out[string(key)] = value
	}
	return out
}

func copyStringIntMap(in map[string]int) map[string]int {
	if len(in) == 0 {
		return map[string]int{}
	}
	out := make(map[string]int, len(in))
	for key, value := range in {
		out[key] = value
	}
	return out
}

func candidateEntropy(candidates []store.LabelCandidate) float64 {
	if len(candidates) == 0 {
		return 0
	}
	total := 0.0
	for _, candidate := range candidates {
		if candidate.Confidence > 0 {
			total += candidate.Confidence
		}
	}
	if total == 0 {
		return 0
	}
	entropy := 0.0
	for _, candidate := range candidates {
		if candidate.Confidence <= 0 {
			continue
		}
		p := candidate.Confidence / total
		entropy += -p * math.Log2(p)
	}
	return entropy
}

func expectedLearningGain(d store.Device) float64 {
	entropy := candidateEntropy(d.LabelState.CandidateLabels)
	conflicts := float64(len(d.LabelState.ConflictFlags)) * 0.20
	bandBonus := 0.0
	switch strings.TrimSpace(d.LabelState.ConfidenceBand) {
	case string(BandNeedConfirm):
		bandBonus = 0.25
	case string(BandUnknown):
		bandBonus = 0.35
	}
	unknownBonus := 0.0
	if normalizedDatasetLabel(datasetResolvedLabel(d)) == "unknown" {
		unknownBonus = 0.20
	}
	return entropy + conflicts + bandBonus + unknownBonus
}

func datasetResolvedLabel(d store.Device) string {
	if manual := manualLabelForDataset(d); manual != "" {
		return manual
	}
	if strings.TrimSpace(d.LabelState.DeviceCategory) != "" {
		return d.LabelState.DeviceCategory
	}
	return d.DeviceType
}

func datasetSeedLabel(d store.Device) string {
	if manual := manualLabelForDataset(d); manual != "" {
		return normalizedDatasetLabel(manual)
	}
	if strings.EqualFold(strings.TrimSpace(d.LabelState.ConfidenceBand), string(BandAutoAction)) {
		return normalizedDatasetLabel(d.LabelState.DeviceCategory)
	}
	return ""
}

func manualLabelForDataset(d store.Device) string {
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

func normalizedDatasetLabel(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" {
		return "unknown"
	}
	return normalizeLabel(v)
}

func optionalDatasetLabel(v string) string {
	v = strings.TrimSpace(strings.ToLower(v))
	if v == "" {
		return ""
	}
	return normalizeLabel(v)
}

func datasetHostname(hostname *string) string {
	if hostname == nil {
		return ""
	}
	return strings.TrimSpace(*hostname)
}

func mergeDatasetDevices(devices []store.Device) []store.Device {
	if len(devices) == 0 {
		return nil
	}
	byKey := make(map[string]store.Device, len(devices))
	order := make([]string, 0, len(devices))
	for _, d := range devices {
		key := evidence.StableDeviceKey(&d)
		if strings.TrimSpace(key) == "" || key == "unknown" {
			key = datasetFallbackKey(d)
		}
		if existing, ok := byKey[key]; ok {
			byKey[key] = mergeDatasetDevice(existing, d)
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

func mergeDatasetDevice(dst, src store.Device) store.Device {
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
	dst.PortsOpen = mergeDatasetInts(dst.PortsOpen, src.PortsOpen)
	dst.Flags = mergeDatasetStrings(dst.Flags, src.Flags)
	dst.SourcesSeen = mergeDatasetStrings(dst.SourcesSeen, src.SourcesSeen)
	dst.ProtocolsSeen.MDNS = mergeDatasetStrings(dst.ProtocolsSeen.MDNS, src.ProtocolsSeen.MDNS)
	dst.ProtocolsSeen.SSDP = mergeDatasetStrings(dst.ProtocolsSeen.SSDP, src.ProtocolsSeen.SSDP)
	dst.ProtocolsSeen.NetBIOS = mergeDatasetStrings(dst.ProtocolsSeen.NetBIOS, src.ProtocolsSeen.NetBIOS)
	dst.Observations = mergeDatasetObservations(dst.Observations, src.Observations)
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
	if strings.TrimSpace(dst.ManualLabel) == "" {
		dst.ManualLabel = src.ManualLabel
	}
	if strings.TrimSpace(dst.ManualLabelState) == "" {
		dst.ManualLabelState = src.ManualLabelState
	}
	if strings.TrimSpace(dst.ManualLabelSource) == "" {
		dst.ManualLabelSource = src.ManualLabelSource
	}
	if strings.TrimSpace(dst.ManualLabelUpdatedAt) == "" {
		dst.ManualLabelUpdatedAt = src.ManualLabelUpdatedAt
	}
	if dst.FirstSeen == "" || (src.FirstSeen != "" && src.FirstSeen < dst.FirstSeen) {
		dst.FirstSeen = src.FirstSeen
	}
	if src.LastSeen != "" && (dst.LastSeen == "" || src.LastSeen > dst.LastSeen) {
		dst.LastSeen = src.LastSeen
	}
	if strings.TrimSpace(dst.LabelState.DeviceCategory) == "" && strings.TrimSpace(src.LabelState.DeviceCategory) != "" {
		dst.LabelState = src.LabelState
	}
	if strings.TrimSpace(dst.DeviceType) == "" {
		dst.DeviceType = src.DeviceType
	}
	if dst.Confidence == 0 {
		dst.Confidence = src.Confidence
	}
	return dst
}

func mergeDatasetInts(a, b []int) []int {
	seen := map[int]struct{}{}
	out := make([]int, 0, len(a)+len(b))
	for _, v := range append(append([]int{}, a...), b...) {
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Ints(out)
	return out
}

func mergeDatasetStrings(a, b []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(a)+len(b))
	for _, v := range append(append([]string{}, a...), b...) {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		if _, ok := seen[v]; ok {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

func mergeDatasetObservations(a, b []store.Observation) []store.Observation {
	type key struct {
		strategy string
		key      string
		value    string
		ip       string
	}
	seen := map[key]struct{}{}
	out := make([]store.Observation, 0, len(a)+len(b))
	for _, obs := range append(append([]store.Observation{}, a...), b...) {
		k := key{strategy: obs.Strategy, key: obs.Key, value: obs.Value, ip: obs.IP}
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		out = append(out, obs)
	}
	return out
}

func datasetFallbackKey(d store.Device) string {
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

func expandDatasetInputs(inputs []string) ([]string, error) {
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
			if _, ok := seen[abs]; ok {
				continue
			}
			seen[abs] = struct{}{}
			out = append(out, abs)
			continue
		}
		err = filepath.WalkDir(raw, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".json") {
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
