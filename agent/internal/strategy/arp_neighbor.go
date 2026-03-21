package strategy

import (
	"bufio"
	"context"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"time"
)

type ArpNeighbor struct{}

func (s *ArpNeighbor) Name() string {
	return "arp_neighbor"
}

func (s *ArpNeighbor) Collect(targets []Target, emit ObservationSink) {
	collectARPNeighbors(s.Name(), targets, emit, false)
}

type arpNeighborRecord struct {
	IP         string
	MAC        string
	Interface  string
	State      string
	Type       string
	Flags      string
	Age        string
	Source     string
}

func collectARPNeighbors(strategyName string, targets []Target, emit ObservationSink, refresh bool) {
	if refresh {
		for _, t := range targets {
			if t.IP == "" {
				continue
			}
			refreshDetails := map[string]string{"transport": "ping"}
			if err := triggerNeighborRefresh(t.IP); err != nil {
				refreshDetails["error"] = err.Error()
				emitObservation(emit, strategyName, t, "neighbor_refresh", "failed", refreshDetails)
			} else {
				emitObservation(emit, strategyName, t, "neighbor_refresh", "probe_sent", refreshDetails)
			}
		}
	}

	neighbors := readARPNeighbors()
	if len(neighbors) == 0 {
		for _, t := range targets {
			if t.IP == "" {
				continue
			}
			emitObservation(emit, strategyName, t, "neighbor_state", "table_unavailable", map[string]string{
				"source": "neighbor_table",
			})
		}
		return
	}

	byIP := map[string]arpNeighborRecord{}
	byMAC := map[string]arpNeighborRecord{}
	for _, n := range neighbors {
		if n.IP != "" {
			byIP[strings.ToLower(strings.TrimSpace(n.IP))] = n
		}
		if normalized := normalizeARPNeighborMAC(n.MAC); normalized != "" {
			byMAC[normalized] = n
		}
	}

	for _, t := range targets {
		if t.IP == "" {
			continue
		}
		ipKey := strings.ToLower(strings.TrimSpace(t.IP))
		if record, ok := byIP[ipKey]; ok {
			emitARPNeighborRecord(strategyName, t, record, "ip", emit)
			continue
		}
		if normalized := normalizeARPNeighborMAC(t.MAC); normalized != "" {
			if record, ok := byMAC[normalized]; ok {
				emitARPNeighborRecord(strategyName, t, record, "mac", emit)
				continue
			}
		}
		emitObservation(emit, strategyName, t, "neighbor_state", "not_found", map[string]string{
			"source": "neighbor_table",
		})
	}
}

func emitARPNeighborRecord(strategyName string, t Target, record arpNeighborRecord, matchKey string, emit ObservationSink) {
	details := map[string]string{
		"source":      valueOrUnknown(record.Source),
		"match":       matchKey,
		"neighbor_ip": valueOrUnknown(record.IP),
	}
	if record.Interface != "" {
		details["interface"] = record.Interface
	}
	if record.Age != "" {
		details["age"] = record.Age
	}
	if record.Flags != "" {
		details["flags"] = record.Flags
	}

	emitObservation(emit, strategyName, t, "neighbor_state", valueOrUnknown(record.State), details)
	emitObservation(emit, strategyName, t, "neighbor_interface", valueOrUnknown(record.Interface), details)
	emitObservation(emit, strategyName, t, "neighbor_type", valueOrUnknown(record.Type), details)
	emitObservation(emit, strategyName, t, "neighbor_mac", valueOrUnknown(record.MAC), details)
	emitObservation(emit, strategyName, t, "neighbor_flags", valueOrUnknown(record.Flags), details)
	emitObservation(emit, strategyName, t, "neighbor_age", valueOrUnknown(record.Age), details)
}

func triggerNeighborRefresh(ip string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 1200*time.Millisecond)
	defer cancel()
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "ping", "-n", "1", "-w", "500", ip)
	} else {
		cmd = exec.CommandContext(ctx, "ping", "-c", "1", "-W", "1", ip)
	}
	_ = cmd.Run()
	return ctx.Err()
}

func readARPNeighbors() []arpNeighborRecord {
	switch runtime.GOOS {
	case "windows":
		if out, err := exec.Command("arp", "-a").CombinedOutput(); err == nil {
			if records := parseWindowsARPOutput(string(out)); len(records) > 0 {
				return records
			}
		}
	case "linux":
		if out, err := exec.Command("ip", "neigh", "show").CombinedOutput(); err == nil {
			if records := parseIPNeighOutput(string(out)); len(records) > 0 {
				return records
			}
		}
	}
	if out, err := exec.Command("arp", "-an").CombinedOutput(); err == nil {
		if records := parseGenericARPOutput(string(out)); len(records) > 0 {
			return records
		}
	}
	return nil
}

func parseWindowsARPOutput(output string) []arpNeighborRecord {
	records := []arpNeighborRecord{}
	scanner := bufio.NewScanner(strings.NewReader(output))
	currentInterface := ""
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(strings.ToLower(line), "internet address") {
			continue
		}
		if strings.HasPrefix(strings.ToLower(line), "interface:") {
			currentInterface = strings.TrimSpace(line)
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		ip := fields[0]
		if net.ParseIP(ip) == nil {
			continue
		}
		mac := fields[1]
		state := strings.ToLower(fields[2])
		records = append(records, arpNeighborRecord{
			IP:        ip,
			MAC:       mac,
			Interface: currentInterface,
			State:     state,
			Type:      "arp",
			Flags:     state,
			Source:    "arp -a",
		})
	}
	return records
}

func parseIPNeighOutput(output string) []arpNeighborRecord {
	records := []arpNeighborRecord{}
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 3 || net.ParseIP(fields[0]) == nil {
			continue
		}
		rec := arpNeighborRecord{
			IP:      fields[0],
			State:   fields[len(fields)-1],
			Type:    "arp",
			Source:  "ip neigh show",
		}
		for i := 0; i < len(fields); i++ {
			switch fields[i] {
			case "dev":
				if i+1 < len(fields) {
					rec.Interface = fields[i+1]
				}
			case "lladdr":
				if i+1 < len(fields) {
					rec.MAC = fields[i+1]
				}
			}
		}
		if strings.Contains(line, "router") {
			rec.Flags = appendFlag(rec.Flags, "router")
		}
		if strings.Contains(line, "permanent") {
			rec.Flags = appendFlag(rec.Flags, "permanent")
		}
		records = append(records, rec)
	}
	return records
}

func parseGenericARPOutput(output string) []arpNeighborRecord {
	records := []arpNeighborRecord{}
	re := regexp.MustCompile(`(?i)\(([^)]+)\)\s+at\s+([0-9a-f:\-.]+)\s+on\s+([^\s]+)(?:\s+ifscope\s+\[([^\]]+)\])?`)
	for _, match := range re.FindAllStringSubmatch(output, -1) {
		if len(match) < 4 || net.ParseIP(match[1]) == nil {
			continue
		}
		state := "dynamic"
		if strings.Contains(strings.ToLower(match[0]), "permanent") {
			state = "permanent"
		}
		records = append(records, arpNeighborRecord{
			IP:        match[1],
			MAC:       match[2],
			Interface: match[3],
			State:     state,
			Type:      "arp",
			Flags:     valueOrUnknown(matchValue(match, 4)),
			Source:    "arp -an",
		})
	}
	return records
}

func appendFlag(existing, flag string) string {
	if existing == "" {
		return flag
	}
	if strings.Contains(existing, flag) {
		return existing
	}
	return existing + "," + flag
}

func normalizeARPNeighborMAC(mac string) string {
	mac = strings.ToLower(strings.TrimSpace(mac))
	mac = strings.ReplaceAll(mac, "-", ":")
	mac = strings.ReplaceAll(mac, ".", ":")
	mac = strings.ReplaceAll(mac, " ", "")
	return mac
}

func valueOrUnknown(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return "unknown"
	}
	return value
}

func matchValue(values []string, index int) string {
	if index < 0 || index >= len(values) {
		return ""
	}
	return values[index]
}
