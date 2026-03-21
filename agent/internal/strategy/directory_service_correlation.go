package strategy

import (
	"strconv"
	"strings"
)

type DirectoryServiceCorrelation struct{}

func (s *DirectoryServiceCorrelation) Name() string {
	return "directory_service_correlation"
}

func (s *DirectoryServiceCorrelation) Collect(targets []Target, emit ObservationSink) {
	for _, t := range targets {
		hostname := strings.TrimSpace(t.Hostname)
		if hostname == "" {
			emitObservation(emit, s.Name(), t, "directory_hint", "unavailable", map[string]string{
				"reason": "no_hostname",
			})
			continue
		}
		lower := strings.ToLower(hostname)
		parts := strings.Split(lower, ".")
		emitObservation(emit, s.Name(), t, "hostname_labels", strconv.Itoa(len(parts)), map[string]string{
			"hostname": hostname,
		})
		if len(parts) < 2 {
			emitObservation(emit, s.Name(), t, "directory_hint", "unavailable", map[string]string{
				"reason": "not_fqdn",
			})
			continue
		}
		domain := strings.Join(parts[1:], ".")
		emitObservation(emit, s.Name(), t, "domain", domain, map[string]string{
			"hostname": hostname,
		})
		emitObservation(emit, s.Name(), t, "fqdn_depth", strconv.Itoa(len(parts)), map[string]string{
			"hostname": hostname,
		})
		if strings.Contains(domain, ".local") {
			emitObservation(emit, s.Name(), t, "directory_hint", "local_only", map[string]string{
				"hostname": hostname,
			})
			continue
		}
		hint := "possible_directory"
		if strings.Contains(domain, "corp") || strings.Contains(domain, "ad") || strings.Contains(domain, "domain") || strings.Contains(domain, "internal") {
			hint = "ad_like"
		}
		emitObservation(emit, s.Name(), t, "directory_hint", hint, map[string]string{
			"domain":   domain,
			"hostname": hostname,
		})
	}
}
