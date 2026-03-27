package strategy

import (
	"strings"

	"github.com/netwise/agent/internal/mdns"
)

type MdnsActive struct{}

func (s *MdnsActive) Name() string {
	return "mdns_active"
}

func (s *MdnsActive) Collect(targets []Target, emit ObservationSink) {
	collectMDNS("mdns_active", "active_browse", targets, emit)
}

func collectMDNS(strategyName, mode string, targets []Target, emit ObservationSink) {
	entries := mdnsEntries()
	if len(entries) == 0 {
		for _, t := range targets {
			if t.IP == "" && t.Hostname == "" {
				continue
			}
			emitObservation(emit, strategyName, t, "mdns_status", "not_seen", map[string]string{
				"mode":            mode,
				"target_ip":       t.IP,
				"target_hostname": t.Hostname,
			})
			emitObservation(emit, strategyName, t, "mdns_observation_mode", mode, map[string]string{
				"status": "not_seen",
			})
		}
		return
	}

	for _, t := range targets {
		if t.IP == "" && t.Hostname == "" {
			continue
		}
		matchedEntries := make([]mdnsObservation, 0, len(entries))
		for _, entry := range entries {
			matched, matchReason := mdnsEntryMatchesTarget(entry, t)
			if !matched {
				continue
			}
			matchedEntries = append(matchedEntries, mdnsObservation{entry: entry, matchReason: matchReason})
		}
		if len(matchedEntries) == 0 {
			emitObservation(emit, strategyName, t, "mdns_status", "not_seen", map[string]string{
				"mode":            mode,
				"target_ip":       t.IP,
				"target_hostname": t.Hostname,
			})
			continue
		}
		for _, observed := range matchedEntries {
			entry := observed.entry
			family := mdnsServiceFamily(entry.Service, entry.Instance)
			emitObservation(emit, strategyName, t, "mdns_status", "observed", map[string]string{
				"mode":            mode,
				"target_ip":       t.IP,
				"target_hostname": t.Hostname,
				"entry_ip":        entry.IP,
				"match_reason":    observed.matchReason,
			})
			emitObservation(emit, strategyName, t, "mdns_observation_mode", mode, map[string]string{
				"service":      entry.Service,
				"instance":     entry.Instance,
				"match_reason": observed.matchReason,
			})
			emitObservation(emit, strategyName, t, "mdns_service", entry.Service, map[string]string{
				"instance":     entry.Instance,
				"hostname":     entry.Hostname,
				"ip":           entry.IP,
				"match_reason": observed.matchReason,
			})
			emitObservation(emit, strategyName, t, "mdns_service_family", family, map[string]string{
				"service":      entry.Service,
				"instance":     entry.Instance,
				"match_reason": observed.matchReason,
			})
			emitObservation(emit, strategyName, t, "mdns_instance", entry.Instance, map[string]string{
				"service":      entry.Service,
				"hostname":     entry.Hostname,
				"ip":           entry.IP,
				"match_reason": observed.matchReason,
			})
			emitObservation(emit, strategyName, t, "mdns_hostname", entry.Hostname, map[string]string{
				"service":      entry.Service,
				"instance":     entry.Instance,
				"ip":           entry.IP,
				"match_reason": observed.matchReason,
			})
			emitObservation(emit, strategyName, t, "mdns_ip", entry.IP, map[string]string{
				"service":      entry.Service,
				"instance":     entry.Instance,
				"hostname":     entry.Hostname,
				"match_reason": observed.matchReason,
			})
			emitObservation(emit, strategyName, t, "mdns_target_match", "true", map[string]string{
				"service":      entry.Service,
				"instance":     entry.Instance,
				"hostname":     entry.Hostname,
				"match_reason": observed.matchReason,
			})
		}
	}
}

type mdnsObservation struct {
	entry       mdns.Entry
	matchReason string
}

func mdnsEntryMatchesTarget(entry mdns.Entry, target Target) (bool, string) {
	targetIP := strings.TrimSpace(strings.ToLower(target.IP))
	entryIP := strings.TrimSpace(strings.ToLower(entry.IP))
	if targetIP != "" && entryIP != "" && targetIP == entryIP {
		return true, "entry_ip"
	}
	targetHostname := normalizeTargetHost(target.Hostname)
	entryHostname := normalizeTargetHost(entry.Hostname)
	if targetHostname != "" && entryHostname != "" && targetHostname == entryHostname {
		return true, "hostname"
	}
	return false, ""
}

func mdnsServiceFamily(service, instance string) string {
	text := strings.ToLower(service + " " + instance)
	switch {
	case strings.Contains(text, "googlecast") || strings.Contains(text, "cast"):
		return "cast"
	case strings.Contains(text, "raop") || strings.Contains(text, "airplay"):
		return "airplay"
	case strings.Contains(text, "printer") || strings.Contains(text, "ipp"):
		return "printer"
	case strings.Contains(text, "spotify"):
		return "audio"
	case strings.Contains(text, "hap") || strings.Contains(text, "homekit"):
		return "homekit"
	case strings.Contains(text, "smb") || strings.Contains(text, "afp"):
		return "file_sharing"
	case strings.Contains(text, "http"):
		return "http"
	default:
		return "service"
	}
}
