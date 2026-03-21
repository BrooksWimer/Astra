package evidence

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/netwise/agent/internal/store"
)

type reportTargetSummary struct {
	IP                string               `json:"ip"`
	MAC               string               `json:"mac"`
	Hostname          string               `json:"hostname"`
	Observations      int                  `json:"observations"`
	StrategiesWithAny int                  `json:"strategies_with_any"`
	TopSignals        []reportSignalBucket `json:"top_signals"`
}

type reportSignalBucket struct {
	Key        string `json:"key"`
	Count      int    `json:"count"`
	FirstValue string `json:"first_value"`
}

type strategyReportEnvelope struct {
	Devices          []store.Device        `json:"devices"`
	Items            []store.Device        `json:"items"`
	TargetSummaries  []reportTargetSummary `json:"target_summaries"`
	Targets          []reportTargetSummary `json:"targets"`
	ScanID           string                `json:"scan_id"`
	StartedAt        string                `json:"started_at"`
	FinishedAt       string                `json:"finished_at"`
	ChunkFiles       []string              `json:"chunk_files"`
	ScanDevices      []store.Device        `json:"scan_devices"`
	ResultDevices    []store.Device        `json:"results"`
	TargetSummaries2 []reportTargetSummary `json:"target_summaries_v2"`
}

// LoadCorpus parses known exported artifacts (live scan JSON and chunk/summary JSON variants)
// into a shared slice of Device values.
func LoadCorpus(path string) ([]store.Device, error) {
	return loadCorpus(path, map[string]struct{}{})
}

// LoadCorpusDevices is a compatibility-friendly alias for LoadCorpus.
func LoadCorpusDevices(path string) ([]store.Device, error) {
	return LoadCorpus(path)
}

// LoadCorpusGraph loads a corpus and immediately builds an evidence graph from it.
// This keeps corpus imports and live scan output on the same evidence pathway.
func LoadCorpusGraph(path string, cfg PrivacyConfig) (EvidenceGraph, error) {
	devices, err := LoadCorpus(path)
	if err != nil {
		return EvidenceGraph{}, err
	}
	return BuildEvidenceGraph(devices, cfg), nil
}

func loadCorpus(path string, visited map[string]struct{}) ([]store.Device, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if _, ok := visited[abs]; ok {
		return nil, nil
	}
	visited[abs] = struct{}{}

	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, err
	}

	var raw []store.Device
	if err := json.Unmarshal(data, &raw); err == nil && len(raw) > 0 {
		return dedupeByIdentity(raw), nil
	}

	var envelope strategyReportEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("unsupported corpus format for %s", path)
	}

	devices := make([]store.Device, 0)
	devices = append(devices, envelope.Devices...)
	devices = append(devices, envelope.Items...)
	devices = append(devices, envelope.ScanDevices...)
	devices = append(devices, envelope.ResultDevices...)

	for _, t := range collectTargetSummaries(envelope) {
		if strings.TrimSpace(t.IP) == "" {
			continue
		}
		h := t.Hostname
		var hostname *string
		if strings.TrimSpace(h) != "" {
			tmp := h
			hostname = &tmp
		}
		now := time.Now().Format(time.RFC3339)
		device := store.Device{
			ID:        fallbackID(t.MAC, t.IP),
			IP:        t.IP,
			MAC:       t.MAC,
			Hostname:  hostname,
			FirstSeen: now,
			LastSeen:  now,
			PortsOpen: nil,
		}
		device.Observations = synthesizeObservationsFromSummary(t)
		device.SourcesSeen = synthesizeSourcesFromSummary(t)
		devices = append(devices, device)
	}

	for _, chunkPath := range envelope.ChunkFiles {
		ref := resolveChunkPath(abs, chunkPath)
		if strings.TrimSpace(ref) == "" {
			continue
		}
		chunkDevices, err := loadCorpus(ref, visited)
		if err != nil {
			continue
		}
		devices = append(devices, chunkDevices...)
	}

	return dedupeByIdentity(devices), nil
}

func collectTargetSummaries(envelope strategyReportEnvelope) []reportTargetSummary {
	out := make([]reportTargetSummary, 0, len(envelope.TargetSummaries)+len(envelope.Targets)+len(envelope.TargetSummaries2))
	out = append(out, envelope.TargetSummaries...)
	out = append(out, envelope.Targets...)
	out = append(out, envelope.TargetSummaries2...)
	return out
}

func resolveChunkPath(parent string, raw string) string {
	v := strings.TrimSpace(raw)
	if v == "" {
		return ""
	}
	if filepath.IsAbs(v) {
		return v
	}
	return filepath.Join(filepath.Dir(parent), v)
}

func dedupeByIdentity(inputs []store.Device) []store.Device {
	seen := map[string]struct{}{}
	out := make([]store.Device, 0, len(inputs))
	for _, d := range inputs {
		key := fallbackID(d.MAC, d.IP)
		if strings.TrimSpace(d.ID) != "" && !strings.EqualFold(d.ID, "unknown") {
			key = d.ID
		}
		key = strings.ToLower(key)
		if key == "" {
			key = fmt.Sprintf("unknown:%d", len(out))
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, d)
	}
	return out
}

func fallbackID(mac, ip string) string {
	m := strings.TrimSpace(strings.ToLower(mac))
	if m != "" {
		return m
	}
	i := strings.TrimSpace(ip)
	if i != "" {
		return "ip_" + i
	}
	return "unknown"
}

func synthesizeObservationsFromSummary(summary reportTargetSummary) []store.Observation {
	if len(summary.TopSignals) == 0 {
		return nil
	}
	out := make([]store.Observation, 0, len(summary.TopSignals))
	ts := time.Now().UTC().UnixMilli()
	for _, bucket := range summary.TopSignals {
		strategyName, keyName := parseSignalBucketKey(bucket.Key)
		if strategyName == "" || keyName == "" {
			continue
		}
		value := strings.TrimSpace(bucket.FirstValue)
		details := map[string]string{}
		if bucket.Count > 0 {
			details["count"] = fmt.Sprintf("%d", bucket.Count)
		}
		if summary.StrategiesWithAny > 0 {
			details["strategies_with_any"] = fmt.Sprintf("%d", summary.StrategiesWithAny)
		}
		if summary.Observations > 0 {
			details["summary_observations"] = fmt.Sprintf("%d", summary.Observations)
		}
		if len(details) == 0 {
			details = nil
		}
		out = append(out, store.Observation{
			Timestamp: ts,
			Strategy:  strategyName,
			IP:        summary.IP,
			MAC:       summary.MAC,
			Hostname:  summary.Hostname,
			Key:       keyName,
			Value:     value,
			Details:   details,
		})
	}
	return out
}

func synthesizeSourcesFromSummary(summary reportTargetSummary) []string {
	if len(summary.TopSignals) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(summary.TopSignals))
	for _, bucket := range summary.TopSignals {
		strategyName, _ := parseSignalBucketKey(bucket.Key)
		source := sourceNameFromStrategy(strategyName)
		if source == "" {
			continue
		}
		if _, ok := seen[source]; ok {
			continue
		}
		seen[source] = struct{}{}
		out = append(out, source)
	}
	return out
}

func parseSignalBucketKey(raw string) (string, string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	parts := strings.SplitN(raw, "|", 2)
	if len(parts) != 2 {
		return "", ""
	}
	return strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])
}

func sourceNameFromStrategy(strategyName string) string {
	name := strings.ToLower(strings.TrimSpace(strategyName))
	switch {
	case strings.HasPrefix(name, "arp_"):
		return "arp"
	case strings.HasPrefix(name, "mdns_"):
		return "mdns"
	case strings.HasPrefix(name, "ssdp_"), strings.HasPrefix(name, "upnp_"):
		return "ssdp"
	case strings.HasPrefix(name, "dns_"):
		return "dns"
	case strings.HasPrefix(name, "dhcp"):
		return "dhcp"
	case strings.Contains(name, "http"):
		return "http"
	case strings.Contains(name, "tls"):
		return "tls"
	case strings.Contains(name, "ssh"):
		return "ssh"
	case strings.Contains(name, "netbios"):
		return "netbios"
	default:
		return name
	}
}
