package strategy

import (
	"strconv"
	"strings"
	"sync"
	"time"
)

type CrossScanTimeCorrelation struct{}

type crossScanState struct {
	FirstSeen    string
	LastSeen     string
	SeenCount    int
	LastIP       string
	LastHostname string
	LastMAC      string
}

var crossScanTimeMu sync.Mutex
var crossScanTimeState = map[string]*crossScanState{}

func (s *CrossScanTimeCorrelation) Name() string {
	return "cross_scan_time_correlation"
}

func (s *CrossScanTimeCorrelation) Collect(targets []Target, emit ObservationSink) {
	now := time.Now().UTC().Format(time.RFC3339)
	for _, t := range targets {
		key := crossScanIdentityKey(t)
		crossScanTimeMu.Lock()
		st, ok := crossScanTimeState[key]
		if !ok {
			st = &crossScanState{FirstSeen: now}
			crossScanTimeState[key] = st
		}
		prevIP := st.LastIP
		prevHostname := st.LastHostname
		prevMAC := st.LastMAC
		st.LastSeen = now
		st.SeenCount++
		st.LastIP = t.IP
		if t.Hostname != "" {
			st.LastHostname = t.Hostname
		}
		st.LastMAC = strings.ToLower(strings.TrimSpace(t.MAC))
		firstSeen := st.FirstSeen
		lastSeen := st.LastSeen
		seenCount := st.SeenCount
		churn := "stable"
		if seenCount == 1 {
			churn = "new"
		}
		driftParts := []string{}
		if prevIP != "" && prevIP != t.IP {
			driftParts = append(driftParts, "ip_changed")
		}
		if prevHostname != "" && t.Hostname != "" && prevHostname != t.Hostname {
			driftParts = append(driftParts, "hostname_changed")
		}
		if prevMAC != "" && st.LastMAC != "" && prevMAC != st.LastMAC {
			driftParts = append(driftParts, "mac_changed")
		}
		crossScanTimeMu.Unlock()

		emitObservation(emit, s.Name(), t, "first_seen", firstSeen, map[string]string{
			"batch": strconv.Itoa(len(targets)),
		})
		emitObservation(emit, s.Name(), t, "last_seen", lastSeen, map[string]string{
			"batch": strconv.Itoa(len(targets)),
		})
		emitObservation(emit, s.Name(), t, "seen_count", strconv.Itoa(seenCount), map[string]string{
			"batch": strconv.Itoa(len(targets)),
		})
		emitObservation(emit, s.Name(), t, "recurrence", churn, map[string]string{
			"batch": strconv.Itoa(len(targets)),
		})
		if len(driftParts) == 0 {
			emitObservation(emit, s.Name(), t, "drift", "none", map[string]string{
				"batch": strconv.Itoa(len(targets)),
			})
			continue
		}
		emitObservation(emit, s.Name(), t, "drift", strings.Join(driftParts, ","), map[string]string{
			"batch": strconv.Itoa(len(targets)),
		})
	}
}

func crossScanIdentityKey(t Target) string {
	if t.MAC != "" {
		return "mac:" + strings.ToLower(strings.TrimSpace(t.MAC))
	}
	if t.IP != "" {
		return "ip:" + strings.TrimSpace(t.IP)
	}
	if t.Hostname != "" {
		return "host:" + strings.ToLower(strings.TrimSpace(t.Hostname))
	}
	return "unknown"
}
