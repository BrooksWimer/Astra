package strategy

import (
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

type EvidenceGraphMerger struct{}

type evidenceGraphEdgeState struct {
	FirstSeen string
	LastSeen  string
	Count     int
}

var evidenceGraphMu sync.Mutex
var evidenceGraphState = map[string]*evidenceGraphEdgeState{}

func (s *EvidenceGraphMerger) Name() string {
	return "evidence_graph_merger"
}

func (s *EvidenceGraphMerger) Collect(targets []Target, emit ObservationSink) {
	macIndex := map[string][]string{}
	hostIndex := map[string][]string{}
	for _, t := range targets {
		if t.MAC != "" {
			macKey := strings.ToLower(strings.ReplaceAll(t.MAC, "-", ":"))
			macIndex[macKey] = append(macIndex[macKey], t.IP)
		}
		if t.Hostname != "" {
			h := strings.ToLower(strings.TrimSpace(t.Hostname))
			hostIndex[h] = append(hostIndex[h], t.IP)
		}
	}
	now := time.Now().UTC().Format(time.RFC3339)
	for _, t := range targets {
		edges := []string{}
		if t.MAC != "" {
			key := strings.ToLower(strings.ReplaceAll(t.MAC, "-", ":"))
			for _, ip := range macIndex[key] {
				if ip != t.IP {
					edges = append(edges, "same_mac_peer:"+ip)
				}
			}
		}
		if t.Hostname != "" {
			key := strings.ToLower(strings.TrimSpace(t.Hostname))
			for _, ip := range hostIndex[key] {
				if ip != t.IP {
					edges = append(edges, "same_hostname_peer:"+ip)
				}
			}
		}
		if len(edges) == 0 {
			emitObservation(emit, s.Name(), t, "evidence_graph", "orphan", map[string]string{
				"state": "isolated",
			})
			continue
		}
		sort.Strings(edges)
		for _, edge := range edges {
			evidenceGraphMu.Lock()
			st, ok := evidenceGraphState[edge]
			if !ok {
				st = &evidenceGraphEdgeState{FirstSeen: now}
				evidenceGraphState[edge] = st
			}
			st.Count++
			st.LastSeen = now
			firstSeen := st.FirstSeen
			lastSeen := st.LastSeen
			support := st.Count
			evidenceGraphMu.Unlock()

			emitObservation(emit, s.Name(), t, "evidence_graph", edge, map[string]string{
				"first_seen": firstSeen,
				"last_seen":  lastSeen,
				"support":    strconv.Itoa(support),
				"relation":   edgeRelation(edge),
				"state":      "linked",
			})
		}
	}
}

func edgeRelation(edge string) string {
	switch {
	case strings.HasPrefix(edge, "same_mac_peer:"):
		return "same_mac"
	case strings.HasPrefix(edge, "same_hostname_peer:"):
		return "same_hostname"
	default:
		return "peer"
	}
}
