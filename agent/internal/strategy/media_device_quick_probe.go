package strategy

import (
	"strconv"
	"strings"
)

// MediaDeviceQuickProbe keeps the label-critical TV/camera checks from the
// broader media probe, but avoids the long-tail fan-out across many ports and
// HTTP endpoints.
type MediaDeviceQuickProbe struct{}

func (s *MediaDeviceQuickProbe) Name() string { return "media_device_quick_probe" }

func (s *MediaDeviceQuickProbe) Collect(targets []Target, emit ObservationSink) {
	for _, t := range targets {
		mediaDeviceQuickProbeCollectTarget(t, emit)
	}
}

func mediaDeviceQuickProbeCollectTarget(t Target, emit ObservationSink) {
	candidatePorts := []int{554, 7000, 8008, 8009}
	openPorts := make([]int, 0, len(candidatePorts))
	openLabels := make([]string, 0, len(candidatePorts))
	for _, port := range candidatePorts {
		if isTCPPortOpen(t.IP, port, strategyProbeTimeout) {
			openPorts = append(openPorts, port)
			openLabels = append(openLabels, strconv.Itoa(port))
		}
	}

	details := map[string]string{
		"probe_mode": "quick",
	}
	if len(openLabels) == 0 {
		emitObservation(emit, "media_device_quick_probe", t, "ports", "none", details)
		return
	}
	emitObservation(emit, "media_device_quick_probe", t, "ports", strings.Join(openLabels, ","), details)
	if containsPort(openPorts, 7000) || containsPort(openPorts, 8008) || containsPort(openPorts, 8009) {
		emitObservation(emit, "media_device_quick_probe", t, "udp_candidate_port", "1900", map[string]string{
			"probe_mode": "quick",
			"reason":     "media_port_correlated",
			"state":      "candidate",
		})
	}

	if containsPort(openPorts, 7000) {
		for _, o := range mediaDeviceProbeAirPlay(t.IP) {
			emitObservation(emit, "media_device_quick_probe", t, o.key, o.value, mergeQuickProbeDetails(o.details))
		}
	}
	if containsPort(openPorts, 8008) || containsPort(openPorts, 8009) {
		for _, o := range mediaDeviceProbeCast(t.IP) {
			emitObservation(emit, "media_device_quick_probe", t, o.key, o.value, mergeQuickProbeDetails(o.details))
		}
	}
	if containsPort(openPorts, 554) {
		for _, o := range mediaDeviceProbeRTSP(t.IP) {
			emitObservation(emit, "media_device_quick_probe", t, o.key, o.value, mergeQuickProbeDetails(o.details))
		}
	}
}

func containsPort(ports []int, needle int) bool {
	for _, port := range ports {
		if port == needle {
			return true
		}
	}
	return false
}

func mergeQuickProbeDetails(in map[string]string) map[string]string {
	out := map[string]string{
		"probe_mode": "quick",
	}
	for k, v := range in {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		out[k] = v
	}
	return out
}
