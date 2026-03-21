package strategy

import (
	"regexp"
	"strconv"
	"strings"
)

type LldpNeighbors struct{}

func (s *LldpNeighbors) Name() string {
	return "lldp_neighbors"
}

func (s *LldpNeighbors) Collect(targets []Target, emit ObservationSink) {
	outputs := collectL2NeighborOutputs()
	for _, t := range targets {
		collectNeighborObservations("lldp_neighbors", "lldp", t, emit, outputs)
	}
}

var neighborFieldPatterns = map[string]*regexp.Regexp{
	"chassis_id":         regexp.MustCompile(`(?i)^(?:chassis(?:\s+id)?|chassis id)\s*[:=]\s*(.+)$`),
	"port_id":            regexp.MustCompile(`(?i)^(?:port(?:\s+id)?|port id)\s*[:=]\s*(.+)$`),
	"system_name":        regexp.MustCompile(`(?i)^system\s+name\s*[:=]\s*(.+)$`),
	"system_description": regexp.MustCompile(`(?i)^system\s+description\s*[:=]\s*(.+)$`),
	"capabilities":       regexp.MustCompile(`(?i)^(?:enabled\s+capabilities|capabilities)\s*[:=]\s*(.+)$`),
	"management_address": regexp.MustCompile(`(?i)^(?:management(?:\s+address|\s+ip)|mgmt(?:\s+address|\s+ip))\s*[:=]\s*(.+)$`),
	"platform":           regexp.MustCompile(`(?i)^platform\s*[:=]\s*(.+)$`),
	"software_version":   regexp.MustCompile(`(?i)^(?:software(?:\s+version)?|firmware(?:\s+version)?)\s*[:=]\s*(.+)$`),
	"vlan":               regexp.MustCompile(`(?i)^(?:native\s+vlan|vlan(?:\s+id)?)\s*[:=]\s*(.+)$`),
	"mac":                regexp.MustCompile(`(?i)^(?:mac(?:\s+address)?|address)\s*[:=]\s*([0-9A-Fa-f:-]+)$`),
}

func collectNeighborObservations(strategyName, prefix string, target Target, emit ObservationSink, outputs []string) {
	if len(outputs) == 0 {
		emitObservation(emit, strategyName, target, prefix+"_status", "no_neighbor", map[string]string{
			"target_ip":       target.IP,
			"target_hostname": target.Hostname,
		})
		return
	}
	emitted := false
	for idx, raw := range outputs {
		for _, line := range strings.Split(raw, "\n") {
			line = strings.TrimSpace(line)
			if line == "" {
				continue
			}
			for field, pattern := range neighborFieldPatterns {
				m := pattern.FindStringSubmatch(line)
				if len(m) != 2 {
					continue
				}
				emitObservation(emit, strategyName, target, prefix+"_"+field, strings.TrimSpace(m[1]), map[string]string{
					"target_ip":   target.IP,
					"source_index": strconv.Itoa(idx),
					"raw_line":    line,
				})
				emitted = true
			}
		}
		if emitted {
			emitObservation(emit, strategyName, target, prefix+"_status", "observed", map[string]string{
				"target_ip":   target.IP,
				"source_index": strconv.Itoa(idx),
			})
		}
	}
	if !emitted {
		emitObservation(emit, strategyName, target, prefix+"_status", "no_parse", map[string]string{
			"target_ip":       target.IP,
			"target_hostname": target.Hostname,
		})
	}
}
