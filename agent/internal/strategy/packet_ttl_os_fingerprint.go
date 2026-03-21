package strategy

import (
	"runtime"
	"strconv"
)

type PacketTtlOsFingerprint struct{}

func (s *PacketTtlOsFingerprint) Name() string {
	return "packet_ttl_os_fingerprint"
}

func (s *PacketTtlOsFingerprint) Collect(targets []Target, emit ObservationSink) {
	for _, t := range targets {
		if t.IP == "" {
			continue
		}
		var cmd []string
		source := "ping"
		if runtime.GOOS == "windows" {
			cmd = []string{"ping", "-n", "1", "-w", "900", t.IP}
		} else if runtime.GOOS == "darwin" {
			cmd = []string{"ping", "-c", "1", "-W", "1", t.IP}
		} else {
			cmd = []string{"ping", "-c", "1", "-W", "1", t.IP}
		}
		out, err := runCommandOutput(cmd...)
		if err != nil {
			source = "ping_exec_error"
		}
		m := ttlRegex.FindStringSubmatch(out)
		if len(m) < 2 {
			emitObservation(emit, s.Name(), t, "ttl", "not_observed", map[string]string{
				"source": source,
				"state":  "unavailable",
			})
			continue
		}
		ttl, err := strconv.Atoi(m[1])
		if err != nil {
			emitObservation(emit, s.Name(), t, "ttl", "not_observed", map[string]string{
				"source": source,
				"state":  "unavailable",
			})
			continue
		}
		if ttl == 0 {
			emitObservation(emit, s.Name(), t, "ttl", "not_observed", map[string]string{
				"source": source,
				"state":  "unavailable",
			})
			continue
		}
		emitObservation(emit, s.Name(), t, "ttl", strconv.Itoa(ttl), map[string]string{
			"source":       source,
			"os_hint":      estimateOSFromTTL(ttl),
			"ttl_bucket":   ttlBucket(ttl),
			"hop_estimate": strconv.Itoa(ttlHopEstimate(ttl)),
		})
	}
}

func ttlBucket(ttl int) string {
	switch {
	case ttl <= 32:
		return "low"
	case ttl <= 64:
		return "mid"
	case ttl <= 128:
		return "high"
	default:
		return "very_high"
	}
}

func ttlHopEstimate(ttl int) int {
	switch {
	case ttl <= 32:
		return 32 - ttl
	case ttl <= 64:
		return 64 - ttl
	case ttl <= 128:
		return 128 - ttl
	default:
		return 255 - ttl
	}
}
