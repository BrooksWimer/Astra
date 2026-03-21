package strategy

import (
	"net/url"
	"strings"

	"github.com/netwise/agent/internal/ssdp"
)

type SsdpActive struct{}

func (s *SsdpActive) Name() string {
	return "ssdp_active"
}

func (s *SsdpActive) Collect(targets []Target, emit ObservationSink) {
	collectSSDP("ssdp_active", "active_discovery", targets, emit)
}

func collectSSDP(strategyName, mode string, targets []Target, emit ObservationSink) {
	entries := ssdpEntries()
	if len(entries) == 0 {
		for _, t := range targets {
			if t.IP == "" && t.Hostname == "" {
				continue
			}
			emitObservation(emit, strategyName, t, "ssdp_status", "not_seen", map[string]string{
				"mode":            mode,
				"target_ip":       t.IP,
				"target_hostname": t.Hostname,
			})
			emitObservation(emit, strategyName, t, "ssdp_observation_mode", mode, map[string]string{
				"status": "not_seen",
			})
		}
		return
	}

	for _, t := range targets {
		if t.IP == "" && t.Hostname == "" {
			continue
		}
		matchedEntries := make([]ssdp.Entry, 0, len(entries))
		for _, entry := range entries {
			matched, _, _ := ssdpEntryMatchesTarget(entry, t)
			if !matched {
				continue
			}
			matchedEntries = append(matchedEntries, entry)
		}
		if len(matchedEntries) == 0 {
			emitObservation(emit, strategyName, t, "ssdp_status", "not_seen", map[string]string{
				"mode":            mode,
				"target_ip":       t.IP,
				"target_hostname": t.Hostname,
			})
			continue
		}
		for _, entry := range matchedEntries {
			family := ssdpServiceFamily(entry.ST, entry.Server)
			_, matchReason, locationHost := ssdpEntryMatchesTarget(entry, t)
			emitObservation(emit, strategyName, t, "ssdp_status", "observed", map[string]string{
				"mode":            mode,
				"target_ip":       t.IP,
				"target_hostname": t.Hostname,
				"entry_ip":        entry.IP,
				"match_reason":    matchReason,
			})
			emitObservation(emit, strategyName, t, "ssdp_observation_mode", mode, map[string]string{
				"st":           entry.ST,
				"usn":          entry.USN,
				"match_reason": matchReason,
			})
			emitObservation(emit, strategyName, t, "ssdp_st", entry.ST, map[string]string{
				"usn":      entry.USN,
				"server":   entry.Server,
				"location": entry.Location,
				"match_reason": matchReason,
			})
			emitObservation(emit, strategyName, t, "ssdp_usn", entry.USN, map[string]string{
				"st":       entry.ST,
				"server":   entry.Server,
				"location": entry.Location,
				"match_reason": matchReason,
			})
			emitObservation(emit, strategyName, t, "ssdp_location", entry.Location, map[string]string{
				"st":           entry.ST,
				"usn":          entry.USN,
				"server":       entry.Server,
				"match_reason": matchReason,
			})
			emitObservation(emit, strategyName, t, "ssdp_server", entry.Server, map[string]string{
				"st":       entry.ST,
				"usn":      entry.USN,
				"location": entry.Location,
				"match_reason": matchReason,
			})
			emitObservation(emit, strategyName, t, "ssdp_location_host", locationHost, map[string]string{
				"location":     entry.Location,
				"entry_ip":     entry.IP,
				"match_reason": matchReason,
			})
			emitObservation(emit, strategyName, t, "ssdp_service_family", family, map[string]string{
				"st":           entry.ST,
				"server":       entry.Server,
				"match_reason": matchReason,
			})
			emitObservation(emit, strategyName, t, "ssdp_target_match", "true", map[string]string{
				"st":           entry.ST,
				"usn":          entry.USN,
				"server":       entry.Server,
				"match_reason": matchReason,
			})
		}
	}
}

func ssdpEntryMatchesTarget(entry ssdp.Entry, target Target) (bool, string, string) {
	locationHost := ssdpLocationHost(entry)
	targetIP := strings.ToLower(strings.TrimSpace(target.IP))
	entryIP := strings.ToLower(strings.TrimSpace(entry.IP))
	locationHost = strings.ToLower(strings.TrimSpace(locationHost))
	if targetIP != "" {
		if entryIP != "" && entryIP == targetIP {
			return true, "entry_ip", locationHost
		}
		if locationHost != "" && locationHost == targetIP {
			return true, "location_host", locationHost
		}
	}
	targetHostname := strings.ToLower(strings.TrimSpace(target.Hostname))
	if targetHostname != "" {
		haystack := strings.ToLower(entry.USN + " " + entry.Server + " " + entry.ST + " " + entry.Location)
		if strings.Contains(haystack, targetHostname) {
			return true, "hostname_token", locationHost
		}
	}
	return false, "", locationHost
}

func ssdpLocationHost(entry ssdp.Entry) string {
	u, err := url.Parse(entry.Location)
	if err != nil || u == nil {
		return ""
	}
	return strings.TrimSpace(u.Hostname())
}

func ssdpServiceFamily(st, server string) string {
	text := strings.ToLower(st + " " + server)
	switch {
	case strings.Contains(text, "internetgatewaydevice") || strings.Contains(text, "wandevice") || strings.Contains(text, "router"):
		return "router"
	case strings.Contains(text, "mediarenderer") || strings.Contains(text, "mediacenter") || strings.Contains(text, "cast"):
		return "media"
	case strings.Contains(text, "printer") || strings.Contains(text, "print"):
		return "printer"
	case strings.Contains(text, "avtransport") || strings.Contains(text, "renderer"):
		return "audio_video"
	case strings.Contains(text, "xbox") || strings.Contains(text, "playstation") || strings.Contains(text, "nintendo"):
		return "console"
	default:
		return "device"
	}
}
