package strategy

import (
	"runtime"
	"strconv"
	"strings"
)

type HostEventLogPull struct{}

func (s *HostEventLogPull) Name() string {
	return "host_event_log_pull"
}

func (s *HostEventLogPull) Collect(targets []Target, emit ObservationSink) {
	cmds := [][]string{}
	source := "local_host"
	switch runtime.GOOS {
	case "windows":
		cmds = [][]string{
			{"powershell", "-NoProfile", "-Command", "Get-EventLog -LogName System -Newest 5 | Select-Object -ExpandProperty Message"},
			{"wevtutil", "qe", "System", "/c:5", "/f:Text"},
		}
	case "darwin":
		cmds = [][]string{
			{"log", "show", "--last", "5m", "--style", "syslog"},
		}
	default:
		cmds = [][]string{
			{"journalctl", "-p", "warning", "-n", "10", "--no-pager"},
			{"tail", "-n", "20", "/var/log/syslog"},
			{"tail", "-n", "20", "/var/log/messages"},
		}
	}
	events := []string{}
	for _, cmd := range cmds {
		out, err := runCommandOutput(cmd...)
		if err != nil || strings.TrimSpace(out) == "" {
			continue
		}
		lines := dedupeStrings(strings.Split(strings.TrimSpace(out), "\n"))
		if len(lines) == 0 {
			continue
		}
		if len(lines) > 12 {
			lines = lines[:12]
		}
		for _, line := range lines {
			l := strings.TrimSpace(line)
			if l != "" {
				events = append(events, l)
			}
		}
		if len(events) > 0 {
			break
		}
	}
	if len(events) == 0 {
		for _, t := range targets {
			emitObservation(emit, s.Name(), t, "host_event", "unavailable", map[string]string{
				"source": source,
				"reason": "no_local_events",
			})
		}
		return
	}
	for _, t := range targets {
		matchedEvents := filterHostEventsForTarget(events, t)
		emitObservation(emit, s.Name(), t, "host_event_source", source, map[string]string{
			"event_count": strconv.Itoa(len(matchedEvents)),
		})
		if len(matchedEvents) == 0 {
			emitObservation(emit, s.Name(), t, "host_event", "no_target_match", map[string]string{
				"source": source,
			})
			continue
		}
		for _, e := range matchedEvents {
			emitObservation(emit, s.Name(), t, "host_event", e, map[string]string{"source": source})
		}
	}
}

func filterHostEventsForTarget(events []string, target Target) []string {
	if len(events) == 0 {
		return nil
	}
	out := make([]string, 0, len(events))
	for _, event := range events {
		if hostEventMatchesTarget(event, target) {
			out = append(out, event)
		}
	}
	return out
}

func hostEventMatchesTarget(event string, target Target) bool {
	text := strings.ToLower(strings.TrimSpace(event))
	if text == "" {
		return false
	}
	if target.IP != "" && strings.Contains(text, strings.ToLower(strings.TrimSpace(target.IP))) {
		return true
	}
	if target.Hostname != "" && strings.Contains(text, strings.ToLower(strings.TrimSpace(target.Hostname))) {
		return true
	}
	mac := normalizeARPNeighborMAC(target.MAC)
	if mac != "" {
		compactMAC := strings.ReplaceAll(mac, ":", "")
		textCompact := strings.NewReplacer("-", "", ":", "", ".", "", " ", "").Replace(text)
		if strings.Contains(textCompact, compactMAC) {
			return true
		}
	}
	return false
}
