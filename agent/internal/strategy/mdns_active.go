package strategy

import "strings"

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
				"mode":           mode,
				"target_ip":      t.IP,
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
		matched := false
		for _, entry := range entries {
			family := mdnsServiceFamily(entry.Service, entry.Instance)
			match := "false"
			if t.IP != "" && strings.EqualFold(entry.IP, t.IP) {
				match = "true"
			}
			if t.Hostname != "" && strings.EqualFold(entry.Hostname, t.Hostname) {
				match = "true"
			}
			if match == "true" {
				matched = true
			}
			emitObservation(emit, strategyName, t, "mdns_status", "observed", map[string]string{
				"mode":            mode,
				"target_ip":       t.IP,
				"target_hostname": t.Hostname,
				"entry_ip":        entry.IP,
			})
			emitObservation(emit, strategyName, t, "mdns_observation_mode", mode, map[string]string{
				"service": entry.Service,
				"instance": entry.Instance,
			})
			emitObservation(emit, strategyName, t, "mdns_service", entry.Service, map[string]string{
				"instance": entry.Instance,
				"hostname": entry.Hostname,
				"ip":       entry.IP,
			})
			emitObservation(emit, strategyName, t, "mdns_service_family", family, map[string]string{
				"service":  entry.Service,
				"instance": entry.Instance,
			})
			emitObservation(emit, strategyName, t, "mdns_instance", entry.Instance, map[string]string{
				"service":  entry.Service,
				"hostname": entry.Hostname,
				"ip":       entry.IP,
			})
			emitObservation(emit, strategyName, t, "mdns_hostname", entry.Hostname, map[string]string{
				"service":  entry.Service,
				"instance": entry.Instance,
				"ip":       entry.IP,
			})
			emitObservation(emit, strategyName, t, "mdns_ip", entry.IP, map[string]string{
				"service":  entry.Service,
				"instance": entry.Instance,
				"hostname": entry.Hostname,
			})
			emitObservation(emit, strategyName, t, "mdns_target_match", match, map[string]string{
				"service":  entry.Service,
				"instance": entry.Instance,
				"hostname": entry.Hostname,
			})
		}
		if !matched {
			emitObservation(emit, strategyName, t, "mdns_status", "not_seen", map[string]string{
				"mode":           mode,
				"target_ip":      t.IP,
				"target_hostname": t.Hostname,
			})
		}
	}
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
