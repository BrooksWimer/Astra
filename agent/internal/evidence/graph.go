package evidence

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"github.com/netwise/agent/internal/store"
)

type EvidenceGraph struct {
	BuiltAt    time.Time                     `json:"built_at"`
	DeviceKeys []string                      `json:"device_keys"`
	Profiles   map[string]Profile            `json:"profiles"`
	Identities map[string]IdentityResolution `json:"identities,omitempty"`
	Counters   ProfileCounters               `json:"counters"`
}

type ProfileCounters struct {
	DeviceCount          int `json:"device_count"`
	TotalSignals         int `json:"total_signals"`
	ObservedDevices      int `json:"observed_devices"`
	DevicesWithEvidence  int `json:"devices_with_evidence"`
	UniqueDeviceKeys     int `json:"unique_device_keys"`
	MergedDeviceCount    int `json:"merged_device_count"`
	RepeatedObservations int `json:"repeated_observations"`
}

func BuildEvidenceGraph(devices []store.Device, cfg PrivacyConfig) EvidenceGraph {
	profiles := map[string]Profile{}
	identities := map[string]IdentityResolution{}
	counters := ProfileCounters{
		DeviceCount: len(devices),
	}

	for _, d := range devices {
		resolution := ResolveDeviceIdentity(&d)
		key := resolution.Key
		profile := BuildProfile(key, d.Observations, cfg)
		if profile.Identity.Key == "" {
			profile.Identity = resolution
		}
		if existing, ok := identities[key]; ok {
			identities[key] = mergeIdentityResolution(existing, resolution)
		} else {
			identities[key] = resolution
		}
		counters.TotalSignals += profile.SignalVolume
		counters.RepeatedObservations += profile.RepeatedObservations
		if profile.SignalVolume > 0 {
			counters.DevicesWithEvidence++
		}

		if existing, ok := profiles[key]; ok {
			profiles[key] = mergeProfiles(existing, profile)
			continue
		}
		profiles[key] = profile
	}

	keys := make([]string, 0, len(profiles))
	for key := range profiles {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	counters.ObservedDevices = len(profiles)
	counters.UniqueDeviceKeys = len(profiles)
	if counters.DeviceCount >= len(profiles) {
		counters.MergedDeviceCount = counters.DeviceCount - len(profiles)
	}

	return EvidenceGraph{
		BuiltAt:    time.Now().UTC(),
		DeviceKeys: keys,
		Profiles:   profiles,
		Identities: identities,
		Counters:   counters,
	}
}

// BuildGraphFromDevices is a compatibility-friendly wrapper around
// BuildEvidenceGraph for callers that prefer a more explicit name.
func BuildGraphFromDevices(devices []store.Device, cfg PrivacyConfig) EvidenceGraph {
	return BuildEvidenceGraph(devices, cfg)
}

func mergeProfiles(dst, src Profile) Profile {
	if src.DeviceID != "" && dst.DeviceID == "" {
		dst.DeviceID = src.DeviceID
	}
	if dst.Identity.Key == "" {
		dst.Identity = src.Identity
	} else {
		dst.Identity = mergeIdentityResolution(dst.Identity, src.Identity)
	}
	if dst.FirstSeen.IsZero() || (!src.FirstSeen.IsZero() && src.FirstSeen.Before(dst.FirstSeen)) {
		dst.FirstSeen = src.FirstSeen
	}
	if dst.LastSeen.IsZero() || (!src.LastSeen.IsZero() && src.LastSeen.After(dst.LastSeen)) {
		dst.LastSeen = src.LastSeen
	}

	dst.ObservationCount += src.ObservationCount
	dst.RepeatedObservations += src.RepeatedObservations
	oldSignalVolume := dst.SignalVolume
	oldStaleSignalScore := dst.StaleSignalScore

	seen := map[string]struct{}{}
	merged := make([]Evidence, 0, len(dst.Signals)+len(src.Signals))
	for _, sig := range dst.Signals {
		s := signalKey(sig)
		seen[s] = struct{}{}
		merged = append(merged, sig)
	}
	for _, sig := range src.Signals {
		k := signalKey(sig)
		if _, ok := seen[k]; ok {
			continue
		}
		seen[k] = struct{}{}
		merged = append(merged, sig)
	}
	dst.Signals = merged
	dst.SignalVolume = len(merged)
	dst.UniqueSignals = len(merged)

	dst.StrategyCounts = addCounts(dst.StrategyCounts, src.StrategyCounts)
	dst.FamilyCounts = addCountsFamily(dst.FamilyCounts, src.FamilyCounts)
	dst.TierCounts = addCountsTier(dst.TierCounts, src.TierCounts)
	dst.SignalCounts = addCounts(dst.SignalCounts, src.SignalCounts)
	dst.TopSignals = addCounts(dst.TopSignals, src.TopSignals)
	dst.TemporalBins = addCounts(dst.TemporalBins, src.TemporalBins)

	keySeen := map[string]struct{}{}
	for _, k := range dst.RepeatedObservationKeys {
		keySeen[k] = struct{}{}
	}
	for _, k := range src.RepeatedObservationKeys {
		if _, ok := keySeen[k]; ok {
			continue
		}
		keySeen[k] = struct{}{}
		dst.RepeatedObservationKeys = append(dst.RepeatedObservationKeys, k)
	}
	sort.Strings(dst.RepeatedObservationKeys)

	dur := time.Duration(0)
	if !dst.FirstSeen.IsZero() && !dst.LastSeen.IsZero() && dst.FirstSeen.Before(dst.LastSeen) {
		dur = dst.LastSeen.Sub(dst.FirstSeen)
	}
	dst.ObservedDuration = dur
	if dst.SignalVolume > 0 {
		dst.StaleSignalScore = (oldStaleSignalScore*float64(maxInt(oldSignalVolume, 1)) + src.StaleSignalScore*float64(maxInt(src.SignalVolume, 1))) / float64(maxInt(dst.SignalVolume, 1))
		dst.HitFrequency = float64(dst.ObservationCount) / math.Max(dst.ObservedDuration.Seconds(), 1)
	}
	dst.UniqueSignals = len(merged)
	return dst
}

func mergeIdentityResolution(dst, src IdentityResolution) IdentityResolution {
	if dst.Key == "" {
		return src
	}
	if src.Key == "" {
		return dst
	}
	if dst.Source == IdentitySourceUnknown || dst.Volatile {
		if !src.Volatile || src.Source != IdentitySourceUnknown {
			dst.Source = src.Source
			dst.PrimaryValue = choosePrimaryValue(dst.PrimaryValue, src.PrimaryValue)
			if src.FallbackValue != "" {
				dst.FallbackValue = src.FallbackValue
			}
			dst.Volatile = src.Volatile
			dst.VolatilityReason = src.VolatilityReason
			dst.VolatilityScore = src.VolatilityScore
		}
	}
	dst.Evidence = mergeStringList(dst.Evidence, src.Evidence)
	if src.VolatilityScore < dst.VolatilityScore || dst.VolatilityScore == 0 {
		dst.VolatilityScore = src.VolatilityScore
	}
	return dst
}

func mergeStringList(a, b []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(a)+len(b))
	for _, v := range a {
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
	for _, v := range b {
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
	return out
}

func choosePrimaryValue(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}

func addCounts(dst, src map[string]int) map[string]int {
	if dst == nil && len(src) == 0 {
		return map[string]int{}
	}
	if dst == nil {
		dst = make(map[string]int)
	}
	for key, value := range src {
		dst[key] += value
	}
	return dst
}

func addCountsFamily(dst, src map[EvidenceFamily]int) map[EvidenceFamily]int {
	if dst == nil && len(src) == 0 {
		return map[EvidenceFamily]int{}
	}
	if dst == nil {
		dst = make(map[EvidenceFamily]int)
	}
	for key, value := range src {
		dst[key] += value
	}
	return dst
}

func addCountsTier(dst, src map[EvidenceTier]int) map[EvidenceTier]int {
	if dst == nil && len(src) == 0 {
		return map[EvidenceTier]int{}
	}
	if dst == nil {
		dst = make(map[EvidenceTier]int)
	}
	for key, value := range src {
		dst[key] += value
	}
	return dst
}

func mergeProfileSignals(a, b []Evidence) []Evidence {
	keys := map[string]struct{}{}
	out := make([]Evidence, 0, len(a)+len(b))
	for _, sig := range a {
		k := signalKey(sig)
		keys[k] = struct{}{}
		out = append(out, sig)
	}
	for _, sig := range b {
		k := signalKey(sig)
		if _, ok := keys[k]; ok {
			continue
		}
		keys[k] = struct{}{}
		out = append(out, sig)
	}
	return out
}

func (g EvidenceGraph) Validate() error {
	if g.Profiles == nil {
		return fmt.Errorf("no profiles")
	}
	return nil
}

func MergeEvidenceGraphs(graphs ...EvidenceGraph) EvidenceGraph {
	merged := EvidenceGraph{
		BuiltAt:    time.Now().UTC(),
		Profiles:   map[string]Profile{},
		Identities: map[string]IdentityResolution{},
	}
	for _, g := range graphs {
		if len(g.Profiles) == 0 {
			continue
		}
		merged.Counters.DeviceCount += g.Counters.DeviceCount
		merged.Counters.TotalSignals += g.Counters.TotalSignals
		merged.Counters.RepeatedObservations += g.Counters.RepeatedObservations
		for key, profile := range g.Profiles {
			if existing, ok := merged.Profiles[key]; ok {
				merged.Profiles[key] = mergeProfiles(existing, profile)
				continue
			}
			merged.Profiles[key] = profile
		}
		for key, identity := range g.Identities {
			if existing, ok := merged.Identities[key]; ok {
				merged.Identities[key] = mergeIdentityResolution(existing, identity)
				continue
			}
			merged.Identities[key] = identity
		}
	}
	merged.DeviceKeys = make([]string, 0, len(merged.Profiles))
	for key := range merged.Profiles {
		merged.DeviceKeys = append(merged.DeviceKeys, key)
	}
	sort.Strings(merged.DeviceKeys)
	merged.Counters.ObservedDevices = len(merged.Profiles)
	merged.Counters.UniqueDeviceKeys = len(merged.Profiles)
	merged.Counters.DevicesWithEvidence = 0
	for _, profile := range merged.Profiles {
		if profile.SignalVolume > 0 {
			merged.Counters.DevicesWithEvidence++
		}
	}
	if merged.Counters.DeviceCount < len(merged.Profiles) {
		merged.Counters.DeviceCount = len(merged.Profiles)
	}
	if merged.Counters.DeviceCount >= len(merged.Profiles) {
		merged.Counters.MergedDeviceCount = merged.Counters.DeviceCount - len(merged.Profiles)
	}
	return merged
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
